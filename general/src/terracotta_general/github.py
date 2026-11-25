"""Minimal GitHub App client: App JWT, installations, installation tokens, revoke."""

from __future__ import annotations

import asyncio
import calendar
import itertools
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import httpx
import jwt

from terracotta_general.audit import AuditLog

API = "https://api.github.com"
WEB = "https://github.com"  # the device flow lives here, not on the API host
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
        if repositories is None and set(permissions) - {"metadata"}:
            # No list means every repo of the installation (129 on an "all" install): only a
            # metadata-only listing token may be minted that way.
            raise GitHubError("github-unscoped-refused")
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


@dataclass(frozen=True)
class DeviceCode:
    device_code: str = field(repr=False)
    user_code: str
    verification_uri: str
    expires_in: int
    interval: int


_DEVICE_ERRORS = {  # GitHub's device flow error codes -> our fixed reasons
    "expired_token": "device-expired",
    "access_denied": "device-denied",
    "incorrect_device_code": "device-code-invalid",
    "incorrect_client_credentials": "github-client-invalid",
    "device_flow_disabled": "github-device-flow-disabled",
}


class Writer:
    """The writer App: no private key, only a client id and secret.

    Write access starts as a device-flow user token the operator approves on a phone. The secret
    narrows that token to one repo (`scoped`) and revokes tokens (`revoke_user`); it cannot create
    one. The refresh token GitHub returns with the user token is dropped here, never returned.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        http: httpx.AsyncClient,
        base: str = API,
        web: str = WEB,
        clock: Callable[[], float] = time.time,
        audit: AuditLog | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ):
        self.client_id, self._secret, self._http, self._base, self._web = (
            client_id, client_secret, http, base, web)
        self._clock, self._audit, self._sleep, self._ops = clock, audit, sleep, itertools.count(1)

    def _log(self, event: str, op: str, state: str, **fields: str | int) -> None:
        if self._audit:
            self._audit.write(event, op=op, state=state, **fields)

    async def _send(self, method: str, url: str, **kw) -> httpx.Response:
        try:
            return await self._http.request(method, url, headers={**HEADERS, "Accept": "application/json"}, **kw)
        except httpx.HTTPError:
            raise GitHubError("github-unreachable") from None

    async def device_start(self) -> DeviceCode:
        r = await self._send("POST", f"{self._web}/login/device/code", data={"client_id": self.client_id})
        try:
            a = r.json()
            if r.status_code != 200 or "error" in a:
                raise GitHubError(_DEVICE_ERRORS.get(a.get("error"), "github-refused"))
            return DeviceCode(a["device_code"], a["user_code"], a["verification_uri"],
                              int(a["expires_in"]), int(a["interval"]))
        except (ValueError, KeyError, TypeError, AttributeError):
            raise GitHubError("github-bad-answer") from None

    async def device_poll(self, dc: DeviceCode, timeout: float | None = None) -> str:
        """Wait for the phone approval and return the user token (and nothing else GitHub sent)."""
        end = self._clock() + min(dc.expires_in, timeout if timeout is not None else dc.expires_in)
        interval = dc.interval
        while True:
            await self._sleep(interval)  # never faster than the interval GitHub last gave
            if self._clock() >= end:
                raise GitHubError("device-expired")
            r = await self._send("POST", f"{self._web}/login/oauth/access_token", data={
                "client_id": self.client_id, "device_code": dc.device_code,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code"})
            try:
                a = r.json()
                if "access_token" in a:
                    return str(a["access_token"])
                err = a.get("error")
                if err == "authorization_pending":
                    continue
                if err == "slow_down":
                    interval = int(a.get("interval", interval + 5))
                    continue
            except (ValueError, TypeError, AttributeError):
                raise GitHubError("github-bad-answer") from None
            raise GitHubError(_DEVICE_ERRORS.get(err, "github-refused"))

    async def scoped(self, user_token: str, target: str, repo: str, permissions: dict[str, str]) -> Token:
        """A new user token limited to exactly one repo of `target` and to `permissions`.

        Leaving out `repositories` would widen the token to the whole installation, so a call
        without exactly one plain repo name is refused before anything is sent. GitHub shows the
        narrowed permissions but not the repo set, so only the permissions can be checked here.
        """
        if not permissions or not repo or "/" in repo or not target:
            raise GitHubError("github-unscoped-refused")
        op = f"s{next(self._ops)}"
        self._log("mint_scoped", op, "started", repo=f"{target}/{repo}".lower())
        try:
            token = await self._scoped(user_token, target, repo, permissions)
        except GitHubError as e:
            self._log("mint_scoped", op, "failed", repo=f"{target}/{repo}".lower(), reason=str(e))
            raise
        self._log("mint_scoped", op, "done", repo=f"{target}/{repo}".lower())
        return token

    async def _scoped(self, user_token: str, target: str, repo: str, permissions: dict[str, str]) -> Token:
        r = await self._send(
            "POST", f"{self._base}/applications/{self.client_id}/token/scoped",
            auth=(self.client_id, self._secret),
            json={"access_token": user_token, "target": target, "repositories": [repo], "permissions": permissions})
        if r.status_code != 200:
            raise GitHubError("github-refused")
        try:
            a = r.json()
            tok, granted = str(a["token"]), a["installation"]["permissions"]
            raw = a.get("expires_at")
            expires = _parse_ts(raw) if raw else self._clock() + 8 * 3600  # GitHub's stated life
        except (KeyError, ValueError, TypeError, AttributeError):
            raise GitHubError("github-bad-answer") from None
        token = Token(tok, expires, frozenset({repo.lower()}))
        if not _perms_within(granted, permissions):
            await self.revoke_user(token)  # it exists at GitHub whether or not we keep it
            raise GitHubError("github-token-too-broad")
        return token

    async def revoke_user(self, token: Token | str) -> None:
        """Revoke a user token (immediate; a revoked or unknown token counts as revoked)."""
        op = f"r{next(self._ops)}"
        value = token if isinstance(token, str) else token.value
        self._log("revoke_token", op, "started", level="write")
        try:
            r = await self._send("DELETE", f"{self._base}/applications/{self.client_id}/token",
                                 auth=(self.client_id, self._secret), json={"access_token": value})
        except GitHubError as e:
            self._log("revoke_token", op, "failed", level="write", reason=str(e))
            raise
        ok = r.status_code in (204, 404)
        self._log("revoke_token", op, "done" if ok else "failed", level="write", status=r.status_code)
        if not ok:
            raise GitHubError("github-revoke-failed")


_RANK = {"read": 1, "write": 2, "admin": 3}
_IMPLICIT = {"metadata": "read"}  # GitHub adds this to every installation token


def _perms_within(granted: dict[str, str], requested: dict[str, str]) -> bool:
    """Every granted permission was requested (or is implicit) at no higher level."""
    allowed = {**_IMPLICIT, **requested}
    return all(
        k in allowed and _RANK.get(v, 99) <= _RANK.get(allowed[k], 0) for k, v in granted.items())


def _parse_ts(s: str) -> float:
    return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
