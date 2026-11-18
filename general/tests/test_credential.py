import asyncio
import io

import pytest
from fake_github import FakeGitHub, new_keypair
from starlette.testclient import TestClient

from terracotta_general import CONTRACT_VERSION
from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
SANDBOX = "system:serviceaccount:ws:sandbox"
POLICY = Policy.load("""
read:
  standing: {allow: ["octo/mine"], deny: ["octo/secret"]}
  adhoc: {allow: ["octo/*"], max_ttl: 2h}
write: {allow: ["octo/mine"]}
""")
H = {"X-Contract-Version": str(CONTRACT_VERSION), "Authorization": "Bearer good"}


class Auth:
    async def identify(self, t):
        return SANDBOX if t == "good" else None


@pytest.fixture
def env():
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other", "secret"])})
    app = App(fake.client_id, PRIV, fake.client())
    store, buf = RequestStore(), io.StringIO()
    audit = AuditLog(buf)
    b = Broker(lambda: POLICY, store, audit, Auth(), SANDBOX,
               StandingRead(app, lambda: POLICY, audit), Grants(app, store, lambda: POLICY, audit))
    asyncio.run(b.standing.refresh())
    return b, TestClient(sandbox_app(b)), TestClient(admin_app(b)), fake, buf


def cred(client, path, username="", host="github.com"):
    return client.post("/v1/credential", headers=H, json={"host": host, "path": path, "username": username})


def test_standing_repo_gets_token_and_audit_has_no_secret(env):
    _, c, _, _, buf = env
    r = cred(c, "octo/mine.git")
    assert r.status_code == 200 and r.json()["username"] == "x-access-token"
    assert r.json()["password"].startswith("ghs_") and r.json()["password"] not in buf.getvalue()


def test_denial_hints_name_the_operator_command(env):
    _, c, _, _, _ = env
    assert "terracotta-general grant read octo/other" in cred(c, "/octo/other").json()["hint"]
    assert "not readable" in cred(c, "octo/secret").json()["hint"]
    assert "not readable" in cred(c, "stranger/x").json()["hint"]
    assert "grant write octo/mine" in cred(c, "octo/mine", username="writer").json()["hint"]
    assert "write refused" in cred(c, "octo/other", username="writer").json()["hint"]


def test_adhoc_grant_then_credential_then_revoke(env):
    _, c, admin, fake, _ = env
    g = admin.post("/admin/grant", json={"repo": "octo/other", "level": "read", "ttl": "10m"})
    assert g.status_code == 200 and g.json()["ttl"] == 600
    r = cred(c, "octo/other")
    assert r.status_code == 200
    assert admin.post("/admin/revoke", json={"repo": "octo/other"}).json() == {"revoked": 1}
    assert cred(c, "octo/other").status_code == 403
    assert fake.tokens[r.json()["password"]]["revoked"]


def test_admin_grant_errors(env):
    _, _, admin, _, _ = env
    assert admin.post("/admin/grant", json={"repo": "octo/secret", "level": "read"}).status_code == 403
    assert admin.post("/admin/grant", json={"repo": "octo/mine", "level": "write"}).status_code == 501
    admin.post("/admin/grant", json={"repo": "octo/other", "level": "read"})
    assert admin.post("/admin/grant", json={"repo": "octo/other", "level": "read"}).status_code == 409


def test_bad_inputs(env):
    _, c, _, _, _ = env
    assert cred(c, "not-a-repo").status_code == 400
    assert cred(c, "octo/mine", host="gitlab.com").status_code == 403
    assert c.post("/v1/credential", headers=H, json={"host": 1, "path": "x"}).status_code == 400


def test_check_and_status(env):
    _, _, admin, _, _ = env
    out = admin.get("/admin/check", params={"repo": "octo/mine"}).json()
    assert out["standing_token"] is True and "allowed" in out["standing"]
    assert admin.get("/admin/status").json()["standing"] == ["octo/mine"]
