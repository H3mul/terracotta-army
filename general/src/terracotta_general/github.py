"""Minimal GitHub App client: App JWT, installations, installation tokens, revoke."""

from __future__ import annotations

import calendar
import itertools
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import jwt

from terracotta_general.audit import AuditLog

API = "https://api.github.com"
HEADERS = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}


class GitHubError(Exception):
    """Fixed-word reasons only: nothing from GitHub's body, nothing about keys."""


@dataclass
class Token:
    value: str = field(repr=False)
    expires_at: float
    repos: frozenset[str]  # lower-case names it covers ("" set for unrestricted listing tokens)


@dataclass(frozen=True)
class Installation:
    id: int
    login: str


class App:
    def __init__(
        self,
        client_id: str,
        private_key_pem: str,
        http: httpx.AsyncClient,
        base: str = API,
        clock: Callable[[], float] = time.time,
        audit: AuditLog | None = None,
    ):
        self.client_id, self._key, self._http, self._base, self._clock = (
            client_id, private_key_pem, http, base, clock)
        self._audit, self._ops = audit, itertools.count(1)

    def _log(self, event: str, op: str, state: str, **fields: str | int) -> None:
        """Write-ahead: `started` is logged before the call, `done` or `failed` after."""
        if self._audit:
            self._audit.write(event, op=op, state=state, **fields)

    def _app_jwt(self) -> str:
        now = int(self._clock())
        payload = {"iat": now - 60, "exp": now + 300, "iss": self.client_id}
        return jwt.encode(payload, self._key, algorithm="RS256")

    async def _call(self, method: str, path: str, bearer: str, **kw) -> httpx.Response:
        try:
            return await self._http.request(
                method, self._base + path, headers={**HEADERS, "Authorization": f"Bearer {bearer}"}, **kw)
        except httpx.HTTPError:
            raise GitHubError("github-unreachable") from None

    async def installations(self) -> list[Installation]:
        out, page = [], 1
        while True:
            r = await self._call("GET", f"/app/installations?per_page=100&page={page}", self._app_jwt())
            if r.status_code != 200:
                raise GitHubError("github-refused")
            items = r.json()
            out += [Installation(i["id"], i["account"]["login"]) for i in items]
            if len(items) < 100:
                return out
            page += 1

    async def installation_for_repo(self, repo: str) -> int:
        r = await self._call("GET", f"/repos/{repo}/installation", self._app_jwt())
        if r.status_code == 404:
            raise GitHubError("github-not-installed")
        if r.status_code != 200:
            raise GitHubError("github-refused")
        return r.json()["id"]

    async def installation_token(
        self, installation_id: int, repositories: list[str] | None, permissions: dict[str, str]
    ) -> Token:
        op = f"m{next(self._ops)}"
        what = f"{len(repositories)} repos" if repositories is not None else "listing"
        self._log("mint", op, "started", installation=installation_id, reason=what)
        try:
            token = await self._mint(installation_id, repositories, permissions)
        except GitHubError as e:
            self._log("mint", op, "failed", installation=installation_id, reason=str(e))
            raise
        self._log("mint", op, "done", installation=installation_id, reason=what)
        return token

    async def _mint(
        self, installation_id: int, repositories: list[str] | None, permissions: dict[str, str]
    ) -> Token:
        body: dict = {"permissions": permissions}
        if repositories is not None:
            body["repositories"] = repositories
        r = await self._call(
            "POST", f"/app/installations/{installation_id}/access_tokens", self._app_jwt(), json=body)
        if r.status_code != 201:
            raise GitHubError("github-refused")
        a = r.json()
        try:
            expires = _parse_ts(a["expires_at"])
            token = Token(a["token"], expires, frozenset(x["name"].lower() for x in a.get("repositories", [])))
            granted = a.get("permissions", {})
            selection = a.get("repository_selection")
        except (KeyError, ValueError):
            raise GitHubError("github-bad-answer") from None
        narrow = _perms_within(granted, permissions)
        if repositories is not None:
            narrow = (narrow and selection == "selected"
                      and token.repos == frozenset(r.lower() for r in repositories))
        if not narrow:
            await self.revoke(token)  # the token exists at GitHub whether or not we keep it
            raise GitHubError("github-token-too-broad")
        return token

    async def list_repos(self, token: Token) -> list[str]:
        names, page = [], 1
        while True:
            r = await self._call("GET", f"/installation/repositories?per_page=100&page={page}", token.value)
            if r.status_code != 200:
                raise GitHubError("github-refused")
            items = r.json()["repositories"]
            names += [x["name"] for x in items]
            if len(items) < 100:
                return names
            page += 1

    async def default_branch_protection(self, token: Token, repo: str) -> tuple[str, bool]:
        """(default branch name, whether branch protection or a ruleset applies to it)."""
        r = await self._call("GET", f"/repos/{repo}", token.value)
        if r.status_code != 200:
            raise GitHubError("github-refused")
        branch = r.json().get("default_branch")
        if not isinstance(branch, str):
            raise GitHubError("github-bad-answer")
        r = await self._call("GET", f"/repos/{repo}/branches/{branch}", token.value)
        if r.status_code != 200:
            raise GitHubError("github-refused")
        return branch, bool(r.json().get("protected"))

    async def set_suspended(self, installation_id: int, suspended: bool) -> None:
        """Suspending an installation makes GitHub reject its tokens and refuse new ones."""
        r = await self._call("PUT" if suspended else "DELETE",
                             f"/app/installations/{installation_id}/suspended", self._app_jwt())
        if r.status_code != 204:
            raise GitHubError("github-refused")

    async def revoke(self, token: Token) -> None:
        op = f"r{next(self._ops)}"
        self._log("revoke_token", op, "started")
        try:
            r = await self._call("DELETE", "/installation/token", token.value)
        except GitHubError as e:
            self._log("revoke_token", op, "failed", reason=str(e))
            raise
        self._log("revoke_token", op, "done" if r.status_code == 204 else "failed", status=r.status_code)


_RANK = {"read": 1, "write": 2, "admin": 3}
_IMPLICIT = {"metadata": "read"}  # GitHub adds this to every installation token


def _perms_within(granted: dict[str, str], requested: dict[str, str]) -> bool:
    """Every granted permission was requested (or is implicit) at no higher level."""
    allowed = {**_IMPLICIT, **requested}
    return all(
        k in allowed and _RANK.get(v, 99) <= _RANK.get(allowed[k], 0) for k, v in granted.items())


def _parse_ts(s: str) -> float:
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
