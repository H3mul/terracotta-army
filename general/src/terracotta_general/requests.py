"""Grant request records and their state machine.

pending --approve--> approved --(ttl elapses)--> expired
   |                    |
   +-- 5 min unapproved +--> revoked (by operator, stop, or policy change)

A request is approved at most once. While approved and inside its TTL it is an
active grant; the broker may serve credentials for it repeatedly (the git helper
calls per operation). It never extends: a new grant is a new request.
"""

from __future__ import annotations

import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from typing import Literal

APPROVAL_WINDOW = 300  # seconds a pending request may wait for approval


class State(StrEnum):
    PENDING = "pending"
    APPROVED = "approved"
    EXPIRED = "expired"
    REVOKED = "revoked"


class TransitionError(Exception):
    pass


@dataclass
class Request:
    id: str
    repo: str
    level: Literal["read", "write"]
    ttl: int
    created: float
    state: State = State.PENDING
    approved_at: float | None = None

    @property
    def grant_ends(self) -> float | None:
        return None if self.approved_at is None else self.approved_at + self.ttl


class RequestStore:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._clock = clock
        self._by_id: dict[str, Request] = {}

    def _refresh(self, r: Request) -> Request:
        deadline = {
            State.PENDING: r.created + APPROVAL_WINDOW,
            State.APPROVED: r.grant_ends,
        }.get(r.state)
        if deadline is not None and self._clock() >= deadline:
            r.state = State.EXPIRED
        return r

    def create(self, repo: str, level: Literal["read", "write"], ttl: int) -> Request:
        r = Request(secrets.token_hex(4), repo.lower(), level, ttl, self._clock())
        self._by_id[r.id] = r
        return r

    def get(self, rid: str) -> Request:
        try:
            return self._refresh(self._by_id[rid])
        except KeyError:
            raise TransitionError(f"unknown request {rid}") from None

    def approve(self, rid: str) -> Request:
        r = self.get(rid)
        if r.state is not State.PENDING:
            raise TransitionError(f"request {rid} is {r.state}, cannot approve")
        r.state, r.approved_at = State.APPROVED, self._clock()
        return r

    def revoke(self, rid: str) -> Request:
        r = self.get(rid)
        if r.state not in (State.PENDING, State.APPROVED):
            raise TransitionError(f"request {rid} is {r.state}, nothing to revoke")
        r.state = State.REVOKED
        return r

    def all(self) -> list[Request]:
        return [self._refresh(r) for r in self._by_id.values()]

    def active(self, repo: str | None = None, level: str | None = None) -> list[Request]:
        return [
            r for r in self.all()
            if r.state is State.APPROVED
            and (repo is None or r.repo == repo.lower())
            and (level is None or r.level == level)
        ]
