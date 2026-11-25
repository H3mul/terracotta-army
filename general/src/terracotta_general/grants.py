"""Ad hoc read grants: time-boxed access to one private repo outside the standing allowlist."""

from __future__ import annotations

import asyncio
import time
from collections import deque
from collections.abc import Callable

from terracotta_general.audit import AuditLog
from terracotta_general.github import App, GitHubError, Token
from terracotta_general.policy import Policy
from terracotta_general.requests import Request, RequestStore, TransitionError
from terracotta_general.standing import READ_PERMS

DAY = 86400
REMINT_BEFORE = 300  # a grant outlives its 1h token; re-mint when this close to expiry


class Grants:
    def __init__(self, app: App, store: RequestStore, policy: Callable[[], Policy],
                 audit: AuditLog, clock: Callable[[], float] = time.time):
        self._app, self._store, self._policy, self._audit, self._clock = app, store, policy, audit, clock
        self._tokens: dict[str, tuple[Token, int]] = {}  # request id -> (token, installation id)
        # ponytail: in memory, so a restart resets the count; persist if restarts become routine
        self._spent: dict[str, deque[float]] = {"grants": deque(), "mints": deque()}

    def usage(self) -> dict[str, str]:
        lim = self._policy().limits
        caps = {"grants": lim.grants_per_day, "mints": lim.mints_per_day}
        return {k: f"{self._recent(k)}/{caps[k]} in the last 24h" for k in caps}

    def _recent(self, kind: str) -> int:
        q = self._spent[kind]
        while q and q[0] <= self._clock() - DAY:
            q.popleft()
        return len(q)

    def _spend(self, kind: str) -> None:
        lim = self._policy().limits
        cap = lim.grants_per_day if kind == "grants" else lim.mints_per_day
        if self._recent(kind) >= cap:
            self._audit.write("refused", level="read", reason=f"daily limit of {cap} {kind} reached")
            raise PermissionError(f"daily limit of {cap} ad hoc {kind} reached; try again later or raise limits in the policy")
        self._spent[kind].append(self._clock())

    async def grant_read(self, repo: str, ttl: str | None, caller: str) -> Request:
        """Authorized by the caller's SSH login (the admin socket is only reachable that way)."""
        repo = repo.lower()
        pol = self._policy()
        d = pol.decide(repo, "read")
        if not d.allowed:
            raise PermissionError(d.reason)
        if self._store.active(repo, "read"):
            raise TransitionError(f"{repo} already has an active read grant; revoke it first")
        ttl_s = pol.clamp_ttl("read", ttl, repo)
        self._spend("grants")  # before any GitHub call, so probing unknown repos counts too
        self._spend("mints")
        inst = await self._app.installation_for_repo(repo)  # raises GitHubError if not installed
        token = await self._app.installation_token(inst, [repo.split("/", 1)[1]], READ_PERMS)
        req = self._store.create(repo, "read", ttl_s)
        self._store.approve(req.id)
        self._tokens[req.id] = (token, inst)
        self._audit.write("grant", request=req.id, repo=repo, level="read", ttl=ttl_s, caller=caller)
        return req

    async def token_for(self, repo: str) -> Token | None:
        active = self._store.active(repo, "read")
        if not active:
            return None
        rid = active[0].id
        token, inst = self._tokens[rid]
        if token.expires_at - self._clock() < REMINT_BEFORE:
            try:
                self._spend("mints")
                fresh = await self._app.installation_token(inst, [repo.split("/", 1)[1]], READ_PERMS)
            except (GitHubError, PermissionError):
                return token if token.expires_at > self._clock() else None
            await self._app.revoke(token)
            self._tokens[rid] = (token := fresh, inst)
        return token

    async def revoke(self, repo: str, level: str | None = None, caller: str = "operator") -> int:
        n = 0
        for r in self._store.active(repo, level):
            if r.level != "read":
                continue
            self._store.revoke(r.id)
            await self._drop(r.id)
            self._audit.write("revoke", request=r.id, repo=r.repo, level=r.level, caller=caller)
            n += 1
        return n

    async def revoke_all(self, caller: str = "operator") -> int:
        n = 0
        for r in self._store.active(level="read"):
            n += await self.revoke(r.repo, "read", caller)
        return n

    async def _drop(self, rid: str) -> None:
        entry = self._tokens.pop(rid, None)
        if entry:
            await self._app.revoke(entry[0])

    async def sweep(self) -> None:
        """Revoke the token of every grant that is no longer active (expired or revoked)."""
        live = {r.id for r in self._store.active()}
        for rid in [rid for rid in self._tokens if rid not in live]:
            req = self._store.get(rid)
            await self._drop(rid)
            self._audit.write("expire", request=rid, repo=req.repo, state=str(req.state))

    async def run(self, every: float = 30.0) -> None:
        while True:
            try:
                await self.sweep()
            except GitHubError as e:
                self._audit.write("refused", reason=str(e))
            await asyncio.sleep(every)
