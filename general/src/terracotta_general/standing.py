"""Standing read: always-on read tokens for exactly the repos the policy allowlist matches."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable

from terracotta_general.audit import AuditLog
from terracotta_general.github import App, GitHubError, Token
from terracotta_general.policy import Policy

READ_PERMS = {"contents": "read", "metadata": "read"}
LISTING_PERMS = {"metadata": "read"}
MAX_REPOS_PER_TOKEN = 500
REFRESH_BEFORE = 600  # seconds before expiry


class StandingRead:
    def __init__(self, app: App, policy: Callable[[], Policy], audit: AuditLog,
                 clock: Callable[[], float] = time.time,
                 paused: Callable[[], bool] = lambda: False):
        self._app, self._policy, self._audit, self._clock, self._paused = app, policy, audit, clock, paused
        self._by_repo: dict[str, Token] = {}

    def token_for(self, repo: str) -> Token | None:
        t = self._by_repo.get(repo.lower())
        return t if t and t.expires_at > self._clock() else None

    def repos(self) -> list[str]:
        return sorted(self._by_repo)

    def next_refresh_in(self) -> float:
        """Seconds until the soonest token needs refreshing (0 if nothing is held)."""
        if not self._by_repo:
            return 0.0
        soonest = min(t.expires_at for t in self._by_repo.values())
        return max(0.0, soonest - REFRESH_BEFORE - self._clock())

    async def refresh(self) -> None:
        """Resolve the allowlist against each installation and mint narrowed read tokens."""
        policy = self._policy()
        new: dict[str, Token] = {}
        for inst in await self._app.installations():
            # A metadata-only token lets us list the installation's repos; it is revoked at once.
            lister = await self._app.installation_token(inst.id, None, LISTING_PERMS)
            try:
                names = await self._app.list_repos(lister)
            finally:
                await self._app.revoke(lister)
            allowed = sorted(
                n for n in names if policy.decide(f"{inst.login}/{n}", "standing").allowed)
            for i in range(0, len(allowed), MAX_REPOS_PER_TOKEN):
                chunk = allowed[i:i + MAX_REPOS_PER_TOKEN]
                tok = await self._app.installation_token(inst.id, chunk, READ_PERMS)
                for n in chunk:
                    new[f"{inst.login}/{n}".lower()] = tok
        old = {id(t): t for t in self._by_repo.values()}
        self._by_repo = new
        for t in old.values():  # superseded tokens die now rather than at expiry
            if all(t is not n for n in new.values()):
                await self._app.revoke(t)

    async def drop_all(self) -> None:
        """Revoke and forget every standing token (emergency stop)."""
        old, self._by_repo = {id(t): t for t in self._by_repo.values()}, {}
        for t in old.values():
            await self._app.revoke(t)

    async def run(self, retry: float = 60.0) -> None:
        while True:
            if self._paused():
                await asyncio.sleep(retry)
                continue
            try:
                await self.refresh()
                delay = max(30.0, self.next_refresh_in())
            except GitHubError as e:
                self._audit.write("refused", level="standing", reason=str(e))
                delay = retry
            await asyncio.sleep(delay)
