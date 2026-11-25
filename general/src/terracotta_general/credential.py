"""What the sandbox's git credential helper is told for one git request."""

from __future__ import annotations

from terracotta_general.broker import Broker
from terracotta_general.repo import parse_repo

CLI = "terracotta-general"


def _split(path: str) -> str:
    p = path.strip("/")
    p = p.removesuffix(".git")
    return parse_repo(p).lower()


async def serve_credential(b: Broker, host: str, path: str, username: str, caller: str) -> tuple[int, dict]:
    """Returns (http status, json body). Denials carry a `hint` naming the operator command."""
    if b.life and b.life.stopped:
        b.audit.write("denied", caller=caller, reason="emergency stop")
        return 503, {"hint": "emergency stop is active; the operator must run `terracotta-general resume`"}
    if host != "github.com":
        return 403, {"hint": f"host {host!r} is not served"}
    try:
        repo = _split(path)
    except ValueError as e:
        return 400, {"error": str(e)}

    if username == "writer":
        wt = await b.writes.token_for(repo) if b.writes else None
        if wt is not None:
            b.audit.write("served", repo=repo, level="write", caller=caller)
            return 200, {"username": "x-access-token", "password": wt.value, "expires_at": int(wt.expires_at)}
        d = b.policy().decide(repo, "write")
        hint = f"{CLI} grant write {repo}" if d.allowed else f"write refused: {d.reason}"
        b.audit.write("denied", repo=repo, level="write", caller=caller, reason="no active write grant")
        return 403, {"hint": hint}

    token = b.standing.token_for(repo) if b.standing else None
    level = "standing"
    if token is None and b.grants:
        token, level = await b.grants.token_for(repo), "read"
    if token is not None:
        b.audit.write("served", repo=repo, level=level, caller=caller)
        return 200, {"username": "x-access-token", "password": token.value, "expires_at": int(token.expires_at)}

    d = b.policy().decide(repo, "read")
    hint = f"{CLI} grant read {repo}" if d.allowed else f"not readable: {d.reason}"
    b.audit.write("denied", repo=repo, level="read", caller=caller, reason=d.reason)
    return 403, {"hint": hint}
