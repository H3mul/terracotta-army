"""A small fake of the GitHub App API, for unit and integration tests."""

from __future__ import annotations

import base64
import json
import re
import secrets
import time
from urllib.parse import parse_qs

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
        self.suspended: set[int] = set()
        self.protected: set[str] = set()  # 'owner/repo' whose default branch is protected
        self.calls: list[str] = []
        self.client_id = "Iv-test"
        # writer App (device flow and user tokens); the same client id serves both Apps here
        self.writer_secret = "writer-secret"
        self.writer_perms = {"contents": "write", "pull_requests": "write"}
        self.devices: dict[str, dict] = {}  # device_code -> {user_code, state}
        self.users: dict[str, dict] = {}  # parent user tokens
        self.pulls: list[dict] = []  # pull requests opened through the API
        self.device_interval = 5  # seconds the device endpoint tells clients to wait
        self.slow_downs = 0  # next N polls answer slow_down
        self.ssh_keys: dict[str, list[str]] = {}  # login -> public key lines served at /<login>.keys
        self.broaden_scoped = False  # scoped answers claim more permissions than asked

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
        return t if t and not t["revoked"] and t["inst"] not in self.suspended else None

    def approve(self, how: str = "approved") -> None:
        """What the operator does on the phone for the newest device code."""
        list(self.devices.values())[-1]["state"] = how

    def _basic_ok(self, req) -> bool:
        h = req.headers.get("authorization", "")
        want = base64.b64encode(f"{self.client_id}:{self.writer_secret}".encode()).decode()
        return h == f"Basic {want}"

    def _writer(self, req: httpx.Request, path: str) -> httpx.Response | None:
        now = self.clock()
        iso = lambda t: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))
        if path == "/login/device/code":
            form = parse_qs(req.content.decode())
            if form.get("client_id") != [self.client_id]:
                return httpx.Response(200, json={"error": "incorrect_client_credentials"})
            code = "dev-" + secrets.token_hex(8)
            self.devices[code] = {"user_code": "ABCD-1234", "state": "pending"}
            return httpx.Response(200, json={"device_code": code, "user_code": "ABCD-1234",
                                             "verification_uri": "https://github.com/login/device",
                                             "expires_in": 899, "interval": self.device_interval})
        if path == "/login/oauth/access_token":
            form = parse_qs(req.content.decode())
            d = self.devices.get(form.get("device_code", [""])[0])
            if form.get("grant_type") != ["urn:ietf:params:oauth:grant-type:device_code"]:
                return httpx.Response(200, json={"error": "incorrect_client_credentials"})
            if d is None:
                return httpx.Response(200, json={"error": "incorrect_device_code"})
            if self.slow_downs:
                self.slow_downs -= 1
                return httpx.Response(200, json={"error": "slow_down", "interval": 10})
            if d["state"] != "approved":
                err = {"pending": "authorization_pending", "denied": "access_denied",
                       "expired": "expired_token"}[d["state"]]
                return httpx.Response(200, json={"error": err})
            tok = "ghu_" + secrets.token_hex(20)
            self.users[tok] = {"revoked": False}
            return httpx.Response(200, json={
                "access_token": tok, "expires_in": 28800, "token_type": "bearer", "scope": "",
                "refresh_token": "ghr_" + secrets.token_hex(30), "refresh_token_expires_in": 15638400})
        if path == f"/applications/{self.client_id}/token/scoped" and req.method == "POST":
            if not self._basic_ok(req):
                return httpx.Response(404)
            body = json.loads(req.content)
            parent = self.users.get(body.get("access_token"))
            if not parent or parent["revoked"]:
                return httpx.Response(401)
            iid = next((i for i, v in self.inst.items() if v[0].lower() == body.get("target", "").lower()), None)
            perms = body.get("permissions", {})
            if iid is None or set(perms) - set(self.writer_perms):
                return httpx.Response(403)
            repos = body.get("repositories")  # absent means the whole installation, like GitHub
            granted = self.inst[iid][1] if repos is None else [r for r in repos if r in self.inst[iid][1]]
            if not granted:
                return httpx.Response(403)
            tok = "ghu_" + secrets.token_hex(20)
            self.tokens[tok] = {"inst": iid, "repos": granted, "perms": perms, "revoked": False}
            shown = {**perms, "administration": "write"} if self.broaden_scoped else perms
            return httpx.Response(200, json={"token": tok, "expires_at": iso(now + 8 * 3600),
                                             "installation": {"permissions": shown}})
        if path == f"/applications/{self.client_id}/token" and req.method == "DELETE":
            if not self._basic_ok(req):
                return httpx.Response(404)
            tok = json.loads(req.content).get("access_token")
            t = self.tokens.get(tok) or self.users.get(tok)
            if not t or t["revoked"]:
                return httpx.Response(404)
            t["revoked"] = True
            return httpx.Response(204)
        return None

    def handle(self, req: httpx.Request) -> httpx.Response:
        path = req.url.path
        self.calls.append(f"{req.method} {path}")
        m = re.fullmatch(r"/repos/([^/]+)/([^/]+)/pulls", path)
        if m and req.method == "POST":
            t = self._bearer(req)
            if not t or m[2] not in t["repos"] or t["perms"].get("pull_requests") != "write":
                return httpx.Response(404)
            body = json.loads(req.content)
            self.pulls.append({"repo": f"{m[1]}/{m[2]}", "head": body["head"], "base": body["base"],
                               "title": body["title"]})
            return httpx.Response(201, json={"html_url": f"https://github.com/{m[1]}/{m[2]}/pull/{len(self.pulls)}"})
        m = re.fullmatch(r"/([^/]+)\.keys", path)
        if m:
            if m[1] not in self.ssh_keys:
                return httpx.Response(404)
            return httpx.Response(200, text="\n".join(self.ssh_keys[m[1]]) + "\n")
        mine = self._writer(req, path)
        if mine is not None:
            return mine
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
        m = re.fullmatch(r"/app/installations/(\d+)/suspended", path)
        if m:
            if not self._app(req) or int(m[1]) not in self.inst:
                return httpx.Response(401)
            (self.suspended.add if req.method == "PUT" else self.suspended.discard)(int(m[1]))
            return httpx.Response(204)
        m = re.fullmatch(r"/app/installations/(\d+)/access_tokens", path)
        if m:
            if not self._app(req):
                return httpx.Response(401)
            iid = int(m[1])
            if iid not in self.inst:
                return httpx.Response(404)
            if iid in self.suspended:
                return httpx.Response(403)
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
        m = re.fullmatch(r"/repos/([^/]+/[^/]+?)(?:/branches/main)?", path)
        if m and not path.endswith("/installation"):
            t = self._bearer(req)
            if not t or m[1].split("/")[1] not in t["repos"] or "contents" not in t["perms"]:
                return httpx.Response(404)
            if path.endswith("/branches/main"):
                return httpx.Response(200, json={"name": "main", "protected": m[1] in self.protected})
            return httpx.Response(200, json={"default_branch": "main"})
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
