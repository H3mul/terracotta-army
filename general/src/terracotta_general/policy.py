"""Policy model: which repos the sandbox may read or write, and for how long.

Matching is case-insensitive (GitHub names are) with fnmatch globs on `owner/repo`.
Deny always wins over allow.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

_TTL = re.compile(r"^(\d+)([smh])$")
_UNIT = {"s": 1, "m": 60, "h": 3600}


def parse_ttl(value: str) -> int:
    """`30m` -> 1800. Only s/m/h, positive, no compound forms."""
    m = _TTL.fullmatch(value.strip())
    if not m or int(m.group(1)) == 0:
        raise ValueError(f"not a duration: {value!r} (use e.g. 90s, 30m, 2h)")
    return int(m.group(1)) * _UNIT[m.group(2)]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Rule(_Strict):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)


class AdHoc(_Strict):
    allow: list[str] = Field(default_factory=list)
    max_ttl: str = "8h"


class Read(_Strict):
    standing: Rule = Field(default_factory=Rule)
    adhoc: AdHoc = Field(default_factory=AdHoc)


class Write(_Strict):
    allow: list[str] = Field(default_factory=list)
    deny: list[str] = Field(default_factory=list)
    max_ttl: str = "2h"
    default_ttl: str = "30m"
    permissions: list[str] = Field(default_factory=lambda: ["contents", "pull_requests"])


class Limits(_Strict):
    """Per rolling 24h, ad hoc only. A stolen operator SSH key cannot enumerate repos quickly."""

    grants_per_day: int = Field(default=20, ge=1)
    mints_per_day: int = Field(default=60, ge=1)


Level = Literal["standing", "read", "write"]


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str
    ttl_default: int | None = None
    ttl_max: int | None = None


def _hits(patterns: list[str], repo: str) -> list[str]:
    return [p for p in patterns if fnmatch.fnmatchcase(repo, p.lower())]


class Policy(_Strict):
    read: Read = Field(default_factory=Read)
    write: Write = Field(default_factory=Write)
    limits: Limits = Field(default_factory=Limits)

    @classmethod
    def load(cls, text: str) -> Policy:
        data = yaml.safe_load(text) or {}
        pol = cls.model_validate(data)
        parse_ttl(pol.read.adhoc.max_ttl)
        parse_ttl(pol.write.max_ttl)
        if parse_ttl(pol.write.default_ttl) > parse_ttl(pol.write.max_ttl):
            raise ValueError("write.default_ttl exceeds write.max_ttl")
        return pol

    def decide(self, repo: str, level: Level) -> Decision:
        """Is `repo` (owner/name) permitted at `level`? `reason` is a plain-words trace."""
        repo = repo.lower()
        if level == "standing":
            allow, deny = self.read.standing.allow, self.read.standing.deny
        elif level == "read":
            if self.decide(repo, "standing").allowed:
                return Decision(False, "already readable: it is on the standing allowlist")
            allow, deny = self.read.adhoc.allow, self.read.standing.deny
        else:
            allow, deny = self.write.allow, self.write.deny
        d = _hits(deny, repo)
        if d:
            return Decision(False, f"denied by pattern {d[0]!r}")
        a = _hits(allow, repo)
        if not a:
            return Decision(False, f"no {level} allow pattern matches")
        if level == "write":
            return Decision(True, f"allowed by {a[0]!r}", parse_ttl(self.write.default_ttl),
                            parse_ttl(self.write.max_ttl))
        if level == "read":
            cap = parse_ttl(self.read.adhoc.max_ttl)
            return Decision(True, f"allowed by {a[0]!r}", cap, cap)
        return Decision(True, f"allowed by {a[0]!r}")

    def clamp_ttl(self, level: Literal["read", "write"], requested: str | None, repo: str) -> int:
        """TTL in seconds: the default if none requested, else capped by policy."""
        d = self.decide(repo, level)
        if not d.allowed:
            raise PermissionError(d.reason)
        assert d.ttl_default is not None and d.ttl_max is not None  # set for every allowed read/write
        if not requested:
            return d.ttl_default
        return min(parse_ttl(requested), d.ttl_max)
