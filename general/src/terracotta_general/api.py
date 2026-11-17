"""The two HTTP surfaces: the sandbox API (TCP, authenticated) and the admin API (unix socket)."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from terracotta_general import CONTRACT_VERSION
from terracotta_general.broker import Broker

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
        # Credential serving lands with ta-general 2.3.
        return JSONResponse({"hint": "no credentials available yet"}, status_code=403)

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
            "grants": [
                {"id": r.id, "repo": r.repo, "level": r.level, "ends": r.grant_ends}
                for r in b.store.active()
            ],
        })

    return Starlette(routes=[Route("/admin/status", status)])
