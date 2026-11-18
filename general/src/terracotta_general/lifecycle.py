"""What is active versus proposed, and the emergency-stop flag.

The mounted policy file is only a proposal. The policy in force is the one an operator approved,
kept (with the stop flag) in a small state file so it survives a restart without a database.
A fresh broker has no approved policy and denies everything.
"""

from __future__ import annotations

import hashlib
import json
import os
import pathlib

from terracotta_general.policy import Policy


def digest(p: Policy) -> str:
    """Of the parsed policy, so comments and formatting changes do not need a new approval."""
    return hashlib.sha256(p.model_dump_json().encode()).hexdigest()[:12]


def describe_changes(old: Policy, new: Policy) -> list[str]:
    """Plain-words lines, `+` for added and `-` for removed list entries, `~` for changed values."""
    out: list[str] = []

    def walk(prefix: str, a, b) -> None:
        if isinstance(a, dict):
            for k in a:
                walk(f"{prefix}{k}." if isinstance(a[k], dict) else f"{prefix}{k}", a[k], b[k])
        elif isinstance(a, list):
            out.extend(f"+ {prefix}: {x}" for x in b if x not in a)
            out.extend(f"- {prefix}: {x}" for x in a if x not in b)
        elif a != b:
            out.append(f"~ {prefix}: {a} -> {b}")

    walk("", old.model_dump(), new.model_dump())
    return out


class Lifecycle:
    def __init__(self, state_path: str, proposal_path: str):
        self._path, self._proposal = pathlib.Path(state_path), pathlib.Path(proposal_path)
        try:
            saved = json.loads(self._path.read_text())
            self.active = Policy.load(saved["policy"])
            self._active_text = saved["policy"]
            self.stopped = bool(saved["stopped"])
        except FileNotFoundError:
            self.active, self._active_text, self.stopped = Policy(), "{}", False
        except (ValueError, KeyError, TypeError) as e:  # corrupt state is not silently reset
            raise SystemExit(f"state file {self._path} is unreadable: {e}") from None

    def policy(self) -> Policy:
        return self.active

    def proposal(self) -> tuple[Policy | None, str]:
        """The proposed policy, or (None, why it is invalid)."""
        try:
            return Policy.load(self._proposal.read_text()), ""
        except (OSError, ValueError) as e:  # pydantic's ValidationError is a ValueError
            return None, str(e).splitlines()[0]

    def approve(self, want: str) -> Policy:
        """Activate the proposal if it still hashes to `want` (what the operator reviewed)."""
        new, why = self.proposal()
        if new is None:
            raise ValueError(f"proposed policy is invalid: {why}")
        if digest(new) != want:
            raise ValueError(f"proposal is now {digest(new)}, not {want}; run policy show again")
        self.active, self._active_text = new, self._proposal.read_text()
        self._save()
        return new

    def set_stopped(self, stopped: bool) -> None:
        self.stopped = stopped
        self._save()

    def _save(self) -> None:
        tmp = self._path.with_suffix(".tmp")
        self._path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps({"policy": self._active_text, "stopped": self.stopped}))
        os.replace(tmp, self._path)
