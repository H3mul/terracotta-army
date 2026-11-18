"""The two HTTP surfaces: the sandbox API (TCP, authenticated) and the admin API (unix socket)."""

from __future__ import annotations

import json

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from terracotta_general import CONTRACT_VERSION
from terracotta_general.broker import Broker
from terracotta_general.credential import serve_credential
from terracotta_general.github import GitHubError
from terracotta_general.lifecycle import describe_changes, digest
from terracotta_general.requests import TransitionError

MIN_CONTRACT = CONTRACT_VERSION  # callers older than this get 426


def _refuse(b: Broker, code: int, reason: str, caller: str = "-") -> JSONResponse:
    b.audit.write("refused", caller=caller, status=code, reason=reason)
    return JSONResponse({"error": reason}, status_code=code)


async def authenticate(b: Broker, request: Request) -> JSONResponse | str:
    """Returns the caller identity, or the refusal response."""
    raw = request.headers.get("x-contract-version", "")
    if not raw.isdigit():
        return _refuse(b, 400, "missing or invalid X-Contract-Version")
    if int(raw) < MIN_CONTRACT:
        return _refuse(b, 426, f"contract version {raw} is below minimum {MIN_CONTRACT}")
    scheme, _, token = request.headers.get("authorization", "").partition(" ")
    if scheme.lower() != "bearer" or not token:
        return _refuse(b, 401, "missing bearer token")
    who = await b.auth.identify(token)
    if who is None:
        return _refuse(b, 401, "token not valid")
    if who != b.sandbox_identity:
        return _refuse(b, 403, "caller is not the sandbox identity", caller=who)
    return who


def sandbox_app(b: Broker) -> Starlette:
    async def healthz(_: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def credential(request: Request) -> JSONResponse:
        who = await authenticate(b, request)
        if isinstance(who, JSONResponse):
            return who
        try:
            body = json.loads(await request.body())
            host, path, username = body["host"], body["path"], body.get("username", "")
            if not all(isinstance(x, str) for x in (host, path, username)):
                raise TypeError
        except (ValueError, KeyError, TypeError):
            return _refuse(b, 400, "body must be JSON with string host and path", caller=who)
        status_code, out = await serve_credential(b, host, path, username, who)
        return JSONResponse(out, status_code=status_code)

    async def status(request: Request) -> JSONResponse:
        who = await authenticate(b, request)
        if isinstance(who, JSONResponse):
            return who
        return JSONResponse({"contract": CONTRACT_VERSION})

    return Starlette(routes=[
        Route("/healthz", healthz),
        Route("/v1/credential", credential, methods=["POST"]),
        Route("/v1/status", status),
    ])


def admin_app(b: Broker) -> Starlette:
    async def status(_: Request) -> JSONResponse:
        return JSONResponse({
            "contract": CONTRACT_VERSION,
            "standing": b.standing.repos() if b.standing else [],
            "grants": [
                {"id": r.id, "repo": r.repo, "level": r.level, "ends": r.grant_ends}
                for r in b.store.active()
            ],
        })

    async def check(request: Request) -> JSONResponse:
        repo = request.query_params.get("repo", "").lower()
        pol = b.policy()
        return JSONResponse({
            "repo": repo,
            "standing": pol.decide(repo, "standing").reason,
            "read": pol.decide(repo, "read").reason,
            "write": pol.decide(repo, "write").reason,
            "standing_token": bool(b.standing and b.standing.token_for(repo)),
            "active": [{"id": r.id, "level": r.level} for r in b.store.active(repo)],
        })

    async def grant(request: Request) -> JSONResponse:
        d = await request.json()
        if d.get("level") != "read" or b.grants is None:
            return JSONResponse({"error": "only read grants are available yet"}, status_code=501)
        try:
            r = await b.grants.grant_read(d["repo"], d.get("ttl") or None, "operator")
        except PermissionError as e:
            return JSONResponse({"error": str(e)}, status_code=403)
        except TransitionError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except GitHubError as e:
            return JSONResponse({"error": str(e)}, status_code=502)
        return JSONResponse({"id": r.id, "repo": r.repo, "ttl": r.ttl, "ends": r.grant_ends})

    async def revoke(request: Request) -> JSONResponse:
        d = await request.json()
        if b.grants is None:
            return JSONResponse({"revoked": 0})
        return JSONResponse({"revoked": await b.grants.revoke(d["repo"], d.get("level") or None)})

    async def policy_show(_: Request) -> JSONResponse:
        proposed, why = b.life.proposal()
        return JSONResponse({
            "active": digest(b.life.active),
            "proposed": digest(proposed) if proposed else None,
            "error": why,
            "changes": describe_changes(b.life.active, proposed) if proposed else [],
        })

    async def policy_approve(request: Request) -> JSONResponse:
        want = (await request.json()).get("hash", "")
        try:
            pol = b.life.approve(want)
        except ValueError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        b.audit.write("policy", caller="operator", reason=f"approved {digest(pol)}")
        revoked = 0
        for r in b.store.active():  # grants the new policy forbids die now
            if not pol.decide(r.repo, r.level).allowed and b.grants:
                revoked += await b.grants.revoke(r.repo, r.level)
        if b.standing:
            try:
                await b.standing.refresh()
            except GitHubError as e:
                b.audit.write("refused", level="standing", reason=str(e))
        return JSONResponse({"active": digest(pol), "revoked": revoked})

    return Starlette(routes=[
        Route("/admin/status", status),
        Route("/admin/policy", policy_show),
        Route("/admin/policy/approve", policy_approve, methods=["POST"]),
        Route("/admin/check", check),
        Route("/admin/grant", grant, methods=["POST"]),
        Route("/admin/revoke", revoke, methods=["POST"]),
    ])
