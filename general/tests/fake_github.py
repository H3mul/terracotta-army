"""A small fake of the GitHub App API, for unit and integration tests."""

from __future__ import annotations

import json
import re
import secrets
import time

import httpx
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def new_keypair() -> tuple[str, str]:
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                           serialization.NoEncryption()).decode()
    pub = k.public_key().public_bytes(serialization.Encoding.PEM,
                                      serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    return priv, pub


class FakeGitHub:
    """installations: {id: (login, [repo names])}. `broaden` makes token answers lie (too broad)."""

    def __init__(self, public_key: str, installations: dict[int, tuple[str, list[str]]],
                 clock=time.time):
        self.pub, self.inst, self.clock = public_key, installations, clock
        self.tokens: dict[str, dict] = {}  # token -> {inst, repos, perms, revoked}
        self.broaden = False
        self.calls: list[str] = []
        self.client_id = "Iv-test"

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handle))

    def _app(self, req) -> bool:
        tok = req.headers["authorization"].split(" ", 1)[1]
        try:
            jwt.decode(tok, self.pub, algorithms=["RS256"], issuer=self.client_id)
            return True
        except jwt.PyJWTError:
            return False

    def _bearer(self, req) -> dict | None:
        t = self.tokens.get(req.headers["authorization"].split(" ", 1)[1])
        return t if t and not t["revoked"] else None

    def handle(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        self.calls.append(f"{req.method} {path}")
        if path == "/app/installations":
            if not self._app(req):
                return httpx.Response(401)
            return httpx.Response(200, json=[{"id": i, "account": {"login": v[0]}} for i, v in self.inst.items()])
        m = re.fullmatch(r"/repos/([^/]+)/([^/]+)/installation", path)
        if m:
            if not self._app(req):
                return httpx.Response(401)
            for i, (login, repos) in self.inst.items():
                if login.lower() == m[1].lower() and m[2] in repos:
                    return httpx.Response(200, json={"id": i})
            return httpx.Response(404)
        m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", path)
        if m:
            if not self._app(req):
                return httpx.Response(401)
            iid = int(m[1])
            if iid not in self.inst:
                return httpx.Response(404)
            body = json.loads(req.content)
            all_repos = self.inst[iid][1]
            repos = body.get("repositories")
            granted = all_repos if repos is None else [r for r in repos if r in all_repos]
            if repos is not None and len(granted) != len(repos):
                return httpx.Response(422)
            tok = "ghs_" + secrets.token_hex(20)
            self.tokens[tok] = {"inst": iid, "repos": granted, "perms": body["permissions"], "revoked": False}
            shown = all_repos if self.broaden else granted
            ans = {"token": tok, "expires_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.clock() + 3600)),
                   "permissions": dict(body["permissions"]), "repository_selection": "selected" if repos is not None else "all"}
            if repos is not None:
                ans["repositories"] = [{"name": r, "full_name": f"{self.inst[iid][0]}/{r}"} for r in shown]
            if self.broaden:
                ans["permissions"]["administration"] = "write"
            return httpx.Response(201, json=ans)
        if path == "/installation/repositories":
            t = self._bearer(req)
            if not t:
                return httpx.Response(401)
            return httpx.Response(200, json={"repositories": [{"name": r} for r in self.inst[t["inst"]][1]]})
        if path == "/installation/token" and req.method == "DELETE":
            t = self._bearer(req)
            if not t:
                return httpx.Response(401)
            t["revoked"] = True
            return httpx.Response(204)
        return httpx.Response(404)
