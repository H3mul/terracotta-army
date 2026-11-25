"""Write grants: a phone-approved device flow, a one-repo token, revoked at its TTL.

The broker never holds a write credential it could use unasked. The operator approves a device
code on their phone; the resulting user token is narrowed to one repo, the parent is revoked at
once, and the narrowed token (GitHub gives it 8 hours and no way to shorten that) is revoked here
when the grant ends. Until then it sits in a 0600 file next to the state file so a restart can
still revoke it. That file is the only place a live token is ever written (invariant I10).
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import pathlib
import time
from collections.abc import Callable
from dataclasses import replace

from terracotta_general.audit import AuditLog
from terracotta_general.github import DeviceCode, GitHubError, Token, Writer
from terracotta_general.policy import Policy
from terracotta_general.requests import (
    APPROVAL_WINDOW,
    Request,
    RequestStore,
    State,
    TransitionError,
)

RETRY_BASE, RETRY_MAX = 30.0, 300.0  # seconds between attempts to revoke a token, doubling


def write_perms(pol: Policy) -> dict[str, str]:
    return {p: "write" for p in pol.write.permissions}


class WriteGrants:
    def __init__(self, writer: Writer, store: RequestStore, policy: Callable[[], Policy], audit: AuditLog,
                 path: str, spend: Callable[[str], None], paused: Callable[[], bool] = lambda: False,
                 clock: Callable[[], float] = time.time):
        self._w, self._store, self._policy, self._audit = writer, store, policy, audit
        self._path, self._spend, self._paused, self._clock = pathlib.Path(path), spend, paused, clock
        self._flows: dict[str, asyncio.Task] = {}
        self._failed: dict[str, str] = {}  # request id -> fixed reason
        self._retry: dict[str, tuple[int, float]] = {}  # request id -> (attempts, next try)
        self._held: dict[str, Token] = self._load()  # request id -> live scoped token

    # --- the file of tokens still to revoke -------------------------------------------------

    def _load(self) -> dict[str, Token]:
        try:
            raw = json.loads(self._path.read_text())
            return {rid: Token(v["token"], float(v["expires_at"]), frozenset()) for rid, v in raw.items()}
        except FileNotFoundError:
            return {}
        except (ValueError, KeyError, TypeError, AttributeError) as e:  # never silently forget tokens
            raise SystemExit(f"write token file {self._path} is unreadable: {e.__class__.__name__}") from None

    def _save(self) -> None:
        body = {rid: {"token": t.value, "expires_at": t.expires_at} for rid, t in self._held.items()}
        tmp = self._path.with_suffix(".tmp")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(body, f)
        os.replace(tmp, self._path)

    def outstanding(self) -> int:
        """Tokens that exist at GitHub and are not yet confirmed revoked."""
        return len(self._held)

    # --- starting a grant -------------------------------------------------------------------

    async def begin(self, repo: str, ttl: str | None, caller: str) -> tuple[Request, DeviceCode]:
        repo = repo.lower()
        pol = self._policy()
        d = pol.decide(repo, "write")
        if not d.allowed:
            raise PermissionError(d.reason)
        if any(r.repo == repo and r.level == "write" and r.state in (State.PENDING, State.APPROVED)
               for r in self._store.all()):
            raise TransitionError(f"{repo} already has a write grant or an open approval; revoke it first")
        ttl_s = pol.clamp_ttl("write", ttl, repo)
        self._spend("grants")
        self._spend("mints")
        dc = await self._w.device_start()
        req = self._store.create(repo, "write", ttl_s)
        self._audit.write("request", request=req.id, repo=repo, level="write", ttl=ttl_s, caller=caller)
        self._flows[req.id] = asyncio.create_task(self._finish(req, dc, caller))
        return req, dc

    async def _finish(self, req: Request, dc: DeviceCode, caller: str) -> None:
        owner, name = req.repo.split("/", 1)
        try:
            user = await self._w.device_poll(dc, timeout=APPROVAL_WINDOW)
            try:
                tok = await self._w.scoped(user, owner, name, write_perms(self._policy()))
            finally:
                await self._drop_parent(user)  # revoking it does not touch the scoped child
            self._held[req.id] = tok
            reason = ""
            try:
                self._save()
            except OSError:
                reason = "write-token-not-kept"
            else:
                try:
                    if self._paused():
                        reason = "stopped"
                    else:
                        self._store.approve(req.id)
                except TransitionError:
                    reason = "request-closed"
            if reason:
                await self._drop(req.id)
                raise GitHubError(reason)
            self._audit.write("grant", request=req.id, repo=req.repo, level="write", ttl=req.ttl, caller=caller)
        except GitHubError as e:
            self._fail(req, str(e))
        except Exception:  # noqa: BLE001 - a background task must never die unseen
            self._fail(req, "internal-error")
        finally:
            self._flows.pop(req.id, None)

    async def _drop_parent(self, user: str) -> None:
        for _ in range(3):
            try:
                await self._w.revoke_user(user)
                return
            except GitHubError:
                await asyncio.sleep(1)
        # ponytail: if all three fail the parent lives out its 8h unheld (we drop the only copy)

    def _fail(self, req: Request, reason: str) -> None:
        self._failed[req.id] = reason
        with contextlib.suppress(TransitionError):
            self._store.revoke(req.id)
        self._audit.write("refused", request=req.id, repo=req.repo, level="write", reason=reason)

    def status(self, rid: str) -> dict:
        r = self._store.get(rid)
        reason = self._failed.get(rid, "")
        state = "failed" if reason else str(r.state)
        return {"id": rid, "repo": r.repo, "state": state, "reason": reason, "ttl": r.ttl, "ends": r.grant_ends}

    # --- using and ending a grant -----------------------------------------------------------

    async def token_for(self, repo: str) -> Token | None:
        for r in self._store.active(repo, "write"):
            tok = self._held.get(r.id)
            if tok and r.grant_ends and tok.expires_at > self._clock():
                return replace(tok, expires_at=min(tok.expires_at, r.grant_ends))
        return None

    async def _drop(self, rid: str, force: bool = True) -> bool:
        """Revoke the token at GitHub; forget it only once that is confirmed. True if gone."""
        tok = self._held.get(rid)
        if tok is None:
            return True
        attempts, due = self._retry.get(rid, (0, 0.0))
        if not force and self._clock() < due:
            return False
        try:
            await self._w.revoke_user(tok)
        except GitHubError:
            self._retry[rid] = (attempts + 1, self._clock() + min(RETRY_BASE * 2 ** attempts, RETRY_MAX))
            return False
        self._held.pop(rid, None)
        self._retry.pop(rid, None)
        with contextlib.suppress(OSError):  # a stale entry is only revoked again later (404 is fine)
            self._save()
        return True

    async def revoke(self, repo: str, caller: str = "operator") -> int:
        """End write grants and open approvals for `repo` now."""
        n = 0
        for r in self._store.all():
            if r.repo != repo.lower() or r.level != "write" or r.state not in (State.PENDING, State.APPROVED):
                continue
            await self._end(r, caller)
            n += 1
        return n

    async def revoke_all(self, caller: str = "operator") -> int:
        n = 0
        for r in self._store.all():
            if r.level == "write" and r.state in (State.PENDING, State.APPROVED):
                await self._end(r, caller)
                n += 1
        await self.sweep(force=True)  # also anything left over from a failed attempt or a restart
        return n

    async def _end(self, r: Request, caller: str) -> None:
        flow = self._flows.pop(r.id, None)
        if flow:
            flow.cancel()
        with contextlib.suppress(TransitionError):
            self._store.revoke(r.id)
        await self._drop(r.id)
        self._audit.write("revoke", request=r.id, repo=r.repo, level="write", caller=caller)

    async def sweep(self, force: bool = False) -> None:
        """Revoke every held token whose grant is over, and retry earlier failures."""
        live = {r.id for r in self._store.active(level="write")}
        for rid in [rid for rid in self._held if rid not in live]:
            if rid in self._flows:
                continue  # approval still being finished
            if await self._drop(rid, force):
                self._audit.write("expire", request=rid, level="write")

    async def run(self, every: float = 30.0) -> None:
        while True:  # the first pass also clears tokens a previous run left behind
            try:
                await self.sweep()
            except OSError as e:
                self._audit.write("refused", level="write", reason=e.__class__.__name__)
            await asyncio.sleep(every)
