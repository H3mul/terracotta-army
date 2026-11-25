"""Stand-in for api.github.com, github.com (git over TLS) and Kubernetes TokenReview.

GitHub App behavior is tests/fake_github.py served over HTTP on :8000. Git smart-HTTP for three
bare repos is served over TLS on :443 (the container is aliased as github.com) and accepts only
a live token that covers the repo, like GitHub. `/_state` exposes what the broker did.
"""

import asyncio
import base64
import os
import pathlib
import re
import subprocess
import tempfile

import httpx
import uvicorn
from fake_github import FakeGitHub
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

fake = FakeGitHub(pathlib.Path(os.environ["PUBKEY"]).read_text(),
                  {1: ("octo", ["mine", "other", "secret", "specs"])})
fake.client_id = os.environ["CLIENT_ID"]
fake.writer_secret = os.environ["WRITER_SECRET"]
BROKER_TOKEN = "broker-token"
IDENTITIES = {"sandbox-token": "system:serviceaccount:ws:sandbox",
              "intruder-token": "system:serviceaccount:ws:intruder"}


async def tokenreview(request: Request) -> Response:
    if request.headers.get("authorization") != f"Bearer {BROKER_TOKEN}":
        return Response(status_code=401)
    spec = (await request.json())["spec"]
    who = IDENTITIES.get(spec["token"])
    status = {"authenticated": who is not None}
    if who:
        status |= {"user": {"username": who}, "audiences": spec["audiences"]}
    return JSONResponse({"status": status}, status_code=201)


async def state(_: Request) -> Response:
    return JSONResponse({
        "suspended": sorted(fake.suspended),
        "tokens": [{"repos": t["repos"], "perms": t["perms"], "revoked": t["revoked"]}
                   for t in fake.tokens.values()],
        "live": sum(1 for t in fake.tokens.values() if not t["revoked"]),
        "devices": len(fake.devices),
        "users_live": sum(1 for t in fake.users.values() if not t["revoked"]),
    })


async def approve(request: Request) -> Response:
    """The operator's phone: approve (or deny) the newest device code."""
    fake.approve(request.query_params.get("how", "approved"))
    return Response(status_code=204)


async def protect(request: Request) -> Response:
    fake.protected = set(await request.json())
    return Response(status_code=204)


GIT_ROOT = pathlib.Path("/srv/git")
GIT_URL = re.compile(r"^/([^/]+)/([^/]+)\.git/.*")


EXTRA_FILES = {  # beyond README.md: a project that names its spec store, and the central store repo
    "mine": {"openspec/config.yaml": "store: terracotta-army\n"},
    "specs": {"terracotta-army/openspec/config.yaml": "schema: spec-driven\n",
              "terracotta-army/openspec/specs/.gitkeep": "", "terracotta-army/openspec/changes/.gitkeep": ""},
}


def seed_repos() -> None:
    for name in ("mine", "other", "secret", "specs"):
        bare = GIT_ROOT / "octo" / f"{name}.git"
        subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(bare)], check=True)
        with tempfile.TemporaryDirectory() as w:
            def g(*a):
                subprocess.run(["git", "-C", w, "-c", "user.name=t", "-c", "user.email=t@t", *a], check=True)
            g("init", "-q", "-b", "main")
            files = {"README.md": f"octo/{name}\n", **EXTRA_FILES.get(name, {})}
            for rel, text in files.items():
                f = pathlib.Path(w, rel)
                f.parent.mkdir(parents=True, exist_ok=True)
                f.write_text(text)
            g("add", ".")
            g("commit", "-q", "-m", "seed")
            g("push", "-q", str(bare), "main")


def git_allowed(request: Request, owner: str, repo: str, write: bool) -> int:
    """Like GitHub: 401 for missing, empty, unknown or revoked credentials; 403 for a live token
    that does not cover this repo or permission; 200 otherwise."""
    h = request.headers.get("authorization", "")
    if not h.startswith("Basic "):
        return 401
    pw = base64.b64decode(h[6:]).decode().partition(":")[2]
    t = fake.tokens.get(pw)
    if not t or t["revoked"] or t["inst"] in fake.suspended:
        return 401
    if repo not in t["repos"] or fake.inst[t["inst"]][0] != owner:
        return 403
    have = t["perms"].get("contents")
    return 200 if have == "write" or (have == "read" and not write) else 403


async def git_http(request: Request) -> Response:
    owner, repo = GIT_URL.match(request.url.path).groups()[:2]
    write = "git-receive-pack" in request.url.path or "git-receive-pack" in request.url.query
    code = git_allowed(request, owner, repo, write)
    if code != 200:
        return Response(status_code=code, headers={"WWW-Authenticate": 'Basic realm="github"'} if code == 401 else {})
    env = {"GIT_PROJECT_ROOT": str(GIT_ROOT), "GIT_HTTP_EXPORT_ALL": "1", "REMOTE_USER": "x",
           "REQUEST_METHOD": request.method, "PATH_INFO": request.url.path,
           "QUERY_STRING": request.url.query, "CONTENT_TYPE": request.headers.get("content-type", ""),
           "PATH": os.environ["PATH"]}
    if "content-encoding" in request.headers:
        env["HTTP_CONTENT_ENCODING"] = request.headers["content-encoding"]
    body = await request.body()
    env["CONTENT_LENGTH"] = str(len(body))
    out = await asyncio.to_thread(
        lambda: subprocess.run(["git", "http-backend"], input=body, env=env, capture_output=True, check=False).stdout)
    head, _, payload = out.partition(b"\r\n\r\n")
    headers, status = {}, 200
    for line in head.decode().split("\r\n"):
        k, _, v = line.partition(": ")
        if k.lower() == "status":
            status = int(v.split()[0])
        elif k:
            headers[k] = v
    return Response(payload, status, headers=headers)


async def github(request: Request) -> Response:
    if GIT_URL.match(request.url.path):
        return await git_http(request)
    r = fake.handle(httpx.Request(request.method, str(request.url), headers=dict(request.headers),
                                  content=await request.body()))
    return Response(r.content, r.status_code, media_type="application/json")


app = Starlette(routes=[
    Route("/apis/authentication.k8s.io/v1/tokenreviews", tokenreview, methods=["POST"]),
    Route("/_state", state),
    Route("/_protect", protect, methods=["POST"]),
    Route("/_approve", approve, methods=["POST"]),
    Route("/{path:path}", github, methods=["GET", "POST", "PUT", "DELETE"]),
])

async def serve() -> None:
    seed_repos()
    plain = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=8000, log_level="warning"))
    tls = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=443, log_level="warning",
                                        ssl_certfile="/keys/tls.crt", ssl_keyfile="/keys/tls.key"))
    await asyncio.gather(plain.serve(), tls.serve())


if __name__ == "__main__":
    asyncio.run(serve())
