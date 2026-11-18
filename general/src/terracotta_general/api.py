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
from terracotta_general.repo import parse_repo
from terracotta_general.requests import TransitionError
from terracotta_general.standing import READ_PERMS

MIN_CONTRACT = CONTRACT_VERSION  # callers older than this get 426


def _refuse(b: Broker, code: int, reason: str, caller: str = "-") -> JSONResponse:
    b.audit.write("refused", caller=caller, status=code, reason=reason)
    return JSONResponse({"error": reason}, status_code=code)


def _need[T](value: T | None, what: str) -> T:
    """Wiring mistakes are bugs, not user errors: the daemon always builds the broker fully."""
    if value is None:
        raise RuntimeError(f"broker was built without {what}")
    return value


async def _body(request: Request) -> dict | None:
    try:
        d = await request.json()
    except ValueError:
        return None
    return d if isinstance(d, dict) else None


def _bad(msg: str) -> JSONResponse:
    return JSONResponse({"error": msg}, status_code=400)


def _valid_repo(v: object) -> str | None:
    try:
        return parse_repo(v).lower() if isinstance(v, str) else None
    except ValueError:
        return None


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
            "stopped": bool(b.life and b.life.stopped),
            "standing": b.standing.repos() if b.standing else [],
            "grants": [
                {"id": r.id, "repo": r.repo, "level": r.level, "ends": r.grant_ends}
                for r in b.store.active()
            ],
        })

    async def protection(repo: str, pol) -> str:
        """Tokens cannot be limited to a branch, so protection on the default branch is the backstop."""
        if not b.app or b.life and b.life.stopped:
            return "unknown: no GitHub access right now"
        if not any(pol.decide(repo, lv).allowed for lv in ("standing", "read", "write")):
            return "unknown: repo is not in policy"
        try:
            inst = await b.app.installation_for_repo(repo)
            tok = await b.app.installation_token(inst, [repo.split("/", 1)[1]], READ_PERMS)
        except GitHubError as e:
            return f"unknown: {e}"
        try:
            branch, protected = await b.app.default_branch_protection(tok, repo)
        except GitHubError as e:
            return f"unknown: {e}"
        finally:
            await b.app.revoke(tok)
        return f"{branch} is protected" if protected else f"{branch} is NOT protected"

    async def check(request: Request) -> JSONResponse:
        repo = _valid_repo(request.query_params.get("repo", ""))
        if repo is None:
            return _bad("repo must be owner/name")
        pol = b.policy()
        return JSONResponse({
            "repo": repo,
            "standing": pol.decide(repo, "standing").reason,
            "read": pol.decide(repo, "read").reason,
            "write": pol.decide(repo, "write").reason,
            "protection": await protection(repo, pol),
            "standing_token": bool(b.standing and b.standing.token_for(repo)),
            "active": [{"id": r.id, "level": r.level} for r in b.store.active(repo)],
        })

    async def grant(request: Request) -> JSONResponse:
        d = await _body(request)
        repo = _valid_repo(d.get("repo")) if d is not None else None
        ttl = d.get("ttl") if d is not None else None
        if d is None or repo is None or not (ttl is None or isinstance(ttl, str)):
            return _bad("body must be JSON with repo (owner/name) and an optional string ttl")
        if b.life and b.life.stopped:
            return JSONResponse({"error": "emergency stop is active; run resume first"}, status_code=409)
        if d.get("level") != "read" or b.grants is None:
            return JSONResponse({"error": "only read grants are available yet"}, status_code=501)
        try:
            r = await b.grants.grant_read(repo, ttl or None, "operator")
        except ValueError as e:  # an unparseable ttl
            return _bad(str(e))
        except PermissionError as e:
            return JSONResponse({"error": str(e)}, status_code=403)
        except TransitionError as e:
            return JSONResponse({"error": str(e)}, status_code=409)
        except GitHubError as e:
            return JSONResponse({"error": str(e)}, status_code=502)
        return JSONResponse({"id": r.id, "repo": r.repo, "ttl": r.ttl, "ends": r.grant_ends})

    async def revoke(request: Request) -> JSONResponse:
        d = await _body(request)
        repo = _valid_repo(d.get("repo")) if d else None
        level = d.get("level") if d else None
        if repo is None or level not in (None, "", "read", "write"):
            return _bad("body must be JSON with repo (owner/name) and level read, write or empty")
        if b.grants is None:
            return JSONResponse({"revoked": 0})
        return JSONResponse({"revoked": await b.grants.revoke(repo, level or None)})

    async def policy_show(_: Request) -> JSONResponse:
        proposed, why = _need(b.life, 'lifecycle').proposal()
        return JSONResponse({
            "active": digest(_need(b.life, 'lifecycle').active),
            "proposed": digest(proposed) if proposed else None,
            "error": why,
            "changes": describe_changes(_need(b.life, 'lifecycle').active, proposed) if proposed else [],
        })

    async def policy_approve(request: Request) -> JSONResponse:
        d = await _body(request)
        want = d.get("hash") if d else None
        if not isinstance(want, str):
            return _bad("body must be JSON with a string hash")
        try:
            pol = _need(b.life, 'lifecycle').approve(want)
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

    async def stop(_: Request) -> JSONResponse:
        """Flag first so nothing more is served even if a later step fails; safe to repeat."""
        _need(b.life, 'lifecycle').set_stopped(True)
        b.audit.write("stop", caller="operator")
        errors, revoked, suspended = [], 0, 0
        try:
            revoked = await b.grants.revoke_all() if b.grants else 0
            if b.standing:
                await b.standing.drop_all()
            app = _need(b.app, 'a GitHub app')
            for inst in await app.installations():
                await app.set_suspended(inst.id, True)
                suspended += 1
        except GitHubError as e:
            errors.append(str(e))
        return JSONResponse({"revoked": revoked, "suspended": suspended, "errors": errors})

    async def resume(_: Request) -> JSONResponse:
        try:
            app = _need(b.app, 'a GitHub app')
            for inst in await app.installations():
                await app.set_suspended(inst.id, False)
        except GitHubError as e:  # stay stopped: serving on half-suspended installations is worse
            return JSONResponse({"error": f"{e}; still stopped, try again"}, status_code=502)
        _need(b.life, 'lifecycle').set_stopped(False)
        b.audit.write("resume", caller="operator")
        if b.standing:
            try:
                await b.standing.refresh()
            except GitHubError as e:
                b.audit.write("refused", level="standing", reason=str(e))
        return JSONResponse({"stopped": False})

    return Starlette(routes=[
        Route("/admin/status", status),
        Route("/admin/stop", stop, methods=["POST"]),
        Route("/admin/resume", resume, methods=["POST"]),
        Route("/admin/policy", policy_show),
        Route("/admin/policy/approve", policy_approve, methods=["POST"]),
        Route("/admin/check", check),
        Route("/admin/grant", grant, methods=["POST"]),
        Route("/admin/revoke", revoke, methods=["POST"]),
    ])
