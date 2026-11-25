"""The operator's SSH keys, taken from their GitHub account (`https://github.com/<user>.keys`).

Who counts as an operator is a deployment setting (`TG_OPERATOR_GITHUB_USERS`), not the approved
policy: the first login that could approve a policy needs a key that already exists. Anyone who
can add a key to one of those GitHub accounts can log in here, which is the same trust the device
flow approval already places in the account (R6). A refresh that fails, or that yields no keys,
leaves the previous file untouched so a GitHub outage cannot lock the operator out.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
import os
import pathlib
import re

import httpx

from terracotta_general.audit import AuditLog
from terracotta_general.github import WEB

KEY_TYPES = {
    "ssh-ed25519", "sk-ssh-ed25519@openssh.com", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521", "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa",
}
USER = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})")  # GitHub's login rules
MAX_KEYS, MAX_LINE = 50, 2048


class KeysError(Exception):
    """Fixed-word reasons only."""


def parse_key(line: str) -> str | None:
    """`type base64 [comment]` normalised to `type base64`, or None if it is not a public key."""
    parts = line.split()
    if len(parts) < 2 or parts[0] not in KEY_TYPES or len(line) > MAX_LINE:
        return None
    try:
        blob = base64.b64decode(parts[1], validate=True)
    except (binascii.Error, ValueError):
        return None
    return f"{parts[0]} {parts[1]}" if blob.startswith(len(parts[0]).to_bytes(4, "big") + parts[0].encode()) else None


def fingerprint(key: str) -> str:
    digest = hashlib.sha256(base64.b64decode(key.split()[1])).digest()
    return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class KeyRefresher:
    def __init__(self, http: httpx.AsyncClient, users: list[str], path: str, audit: AuditLog,
                 base: str = WEB):
        bad = [u for u in users if not USER.fullmatch(u)]
        if bad:
            raise SystemExit(f"not a GitHub login: {bad[0]!r}")
        self._http, self._users, self._path, self._audit, self._base = http, users, pathlib.Path(path), audit, base

    async def _fetch(self, user: str) -> list[str]:
        try:
            r = await self._http.get(f"{self._base}/{user}.keys", follow_redirects=False)
        except httpx.HTTPError:
            raise KeysError("github-unreachable") from None
        if r.status_code != 200:
            raise KeysError("github-refused")
        keys = [k for k in (parse_key(line) for line in r.text.splitlines()) if k]
        if len(keys) > MAX_KEYS:
            raise KeysError("too-many-keys")
        return keys

    async def refresh(self) -> list[str]:
        """Fingerprints now in force. Raises KeysError and keeps the old file on any problem."""
        try:
            keys: list[str] = []
            for user in self._users:
                keys += [k for k in await self._fetch(user) if k not in keys]
            if not keys:
                raise KeysError("no-keys")
            tmp = self._path.with_suffix(".tmp")
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text("\n".join(keys) + "\n")
            tmp.chmod(0o644)  # sshd runs as another user in the sibling container
            os.replace(tmp, self._path)
        except KeysError as e:
            self._audit.write("refused", level="keys", reason=str(e))
            raise
        except OSError:
            self._audit.write("refused", level="keys", reason="keys-not-written")
            raise KeysError("keys-not-written") from None
        prints = [fingerprint(k) for k in keys]
        self._audit.write("keys", reason=f"{len(keys)} keys from {len(self._users)} accounts")
        return prints

    async def run(self, every: float = 6 * 3600, retry: float = 300) -> None:
        while True:
            wait = every
            try:
                await self.refresh()
            except KeysError:
                wait = retry
            await asyncio.sleep(wait)


