"""Append-only, hash-chained audit log (JSON lines).

Each record carries `prev` (the previous record's hash) and its own `hash`.
Records can only be built from a fixed field set with plain values, and any
value that looks like a credential is refused, so a token cannot be logged by
accident.
"""

from __future__ import annotations

import hashlib
import json
import re
import time
from collections.abc import Callable, Iterable
from typing import TextIO

GENESIS = "0" * 64
FIELDS = frozenset({
    "event", "request", "repo", "level", "ttl", "caller", "state", "reason",
    "expires", "status", "contract", "installation",
})
_SECRETISH = re.compile(
    r"gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|-----BEGIN [A-Z ]*KEY-----"
    r"|eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\."
)


class AuditError(Exception):
    pass


def _digest(prev: str, body: dict) -> str:
    return hashlib.sha256((prev + json.dumps(body, sort_keys=True, separators=(",", ":"))).encode()).hexdigest()


class AuditLog:
    def __init__(self, *sinks: TextIO, clock: Callable[[], float] = time.time,
                 prev: str = GENESIS, seq: int = 0):
        self._sinks, self._clock, self._prev, self._seq = sinks, clock, prev, seq

    def write(self, event: str, **fields: str | int) -> dict:
        fields["event"] = event
        for k, v in fields.items():
            if k not in FIELDS:
                raise AuditError(f"field {k!r} is not loggable")
            if not isinstance(v, str | int) or isinstance(v, bool):
                raise AuditError(f"field {k!r} must be str or int")
            if isinstance(v, str) and _SECRETISH.search(v):
                raise AuditError(f"field {k!r} looks like a credential; refusing to log")
        self._seq += 1
        body = {"seq": self._seq, "ts": int(self._clock()), **fields}
        rec = {**body, "prev": self._prev, "hash": _digest(self._prev, body)}
        self._prev = rec["hash"]
        line = json.dumps(rec, sort_keys=True, separators=(",", ":"))
        for s in self._sinks:
            s.write(line + "\n")
            s.flush()
        return rec


def verify(lines: Iterable[str]) -> int:
    """Check the chain. Returns the number of records; raises AuditError at the first break."""
    prev, n = GENESIS, 0
    for i, line in enumerate(l for l in lines if l.strip()):
        try:
            rec = json.loads(line)
            h = rec.pop("hash")
            p = rec.pop("prev")
        except (ValueError, KeyError):
            raise AuditError(f"record {i + 1}: malformed") from None
        if p != prev or _digest(p, rec) != h:
            raise AuditError(f"record {i + 1}: chain broken")
        prev, n = h, n + 1
    return n


def resume_point(lines: list[str]) -> tuple[str, int]:
    """Verify an existing file and return (last hash, last seq) to continue its chain."""
    lines = [x for x in lines if x.strip()]
    if not lines:
        return GENESIS, 0
    verify(lines)
    last = json.loads(lines[-1])
    return last["hash"], last["seq"]
