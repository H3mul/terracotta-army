"""Minimal GitHub App client: App JWT, installations, installation tokens, revoke."""

from __future__ import annotations

import calendar
import time
from collections.abc import Callable
from dataclasses import dataclass, field

import httpx
import jwt

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
    ):
        self.client_id, self._key, self._http, self._base, self._clock = (
            client_id, private_key_pem, http, base, clock)

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

    async def revoke(self, token: Token) -> None:
        await self._call("DELETE", "/installation/token", token.value)


_RANK = {"read": 1, "write": 2, "admin": 3}
_IMPLICIT = {"metadata": "read"}  # GitHub adds this to every installation token


def _perms_within(granted: dict[str, str], requested: dict[str, str]) -> bool:
    """Every granted permission was requested (or is implicit) at no higher level."""
    allowed = {**_IMPLICIT, **requested}
    return all(
        k in allowed and _RANK.get(v, 99) <= _RANK.get(allowed[k], 0) for k, v in granted.items())


def _parse_ts(s: str) -> float:
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
