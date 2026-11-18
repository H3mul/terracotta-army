"""Stand-in for api.github.com and the Kubernetes TokenReview API, for the compose harness.

GitHub behavior is tests/fake_github.py served over HTTP. `/_state` exposes what the broker did.
"""

import json
import os
import pathlib

import httpx
import uvicorn
from fake_github import FakeGitHub
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Route

fake = FakeGitHub(pathlib.Path(os.environ["PUBKEY"]).read_text(),
                  {1: ("octo", ["mine", "other", "secret"])})
fake.client_id = os.environ["CLIENT_ID"]
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
    })


async def protect(request: Request) -> Response:
    fake.protected = set(await request.json())
    return Response(status_code=204)


async def github(request: Request) -> Response:
    r = fake.handle(httpx.Request(request.method, str(request.url), headers=dict(request.headers),
                                  content=await request.body()))
    return Response(r.content, r.status_code, media_type="application/json")


app = Starlette(routes=[
    Route("/apis/authentication.k8s.io/v1/tokenreviews", tokenreview, methods=["POST"]),
    Route("/_state", state),
    Route("/_protect", protect, methods=["POST"]),
    Route("/{path:path}", github, methods=["GET", "POST", "PUT", "DELETE"]),
])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="warning")
