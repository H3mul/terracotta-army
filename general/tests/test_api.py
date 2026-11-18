import io
import json

import pytest
from starlette.testclient import TestClient

from terracotta_general import CONTRACT_VERSION
from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.config import Settings
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore

SANDBOX = "system:serviceaccount:ws:sandbox"


class FakeAuth:
    async def identify(self, token):
        return {"good": SANDBOX, "other": "system:serviceaccount:x:y"}.get(token)


@pytest.fixture
def parts():
    buf = io.StringIO()
    b = Broker(lambda: Policy(), RequestStore(), AuditLog(buf), FakeAuth(), SANDBOX)
    return b, buf


def hdr(token="good", ver=str(CONTRACT_VERSION)):
    h = {"X-Contract-Version": ver}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


@pytest.mark.parametrize("headers,code", [
    (hdr(), 400),                       # authenticated, but no JSON body
    (hdr(ver="abc"), 400),
    (hdr(ver="0"), 426),
    (hdr(token=None), 401),
    (hdr(token="bogus"), 401),
    (hdr(token="other"), 403),
])
def test_sandbox_credential_gating(parts, headers, code):
    b, buf = parts
    r = TestClient(sandbox_app(b)).post("/v1/credential", json={}, headers=headers)
    assert r.status_code == code
    assert json.loads(buf.getvalue().splitlines()[-1])["event"] == "refused"


def test_status_requires_auth_and_healthz_does_not(parts):
    b, _ = parts
    c = TestClient(sandbox_app(b))
    assert c.get("/healthz").status_code == 200
    assert c.get("/v1/status").status_code == 400
    assert c.get("/v1/status", headers=hdr()).json() == {"contract": CONTRACT_VERSION}


def test_admin_status(parts):
    b, _ = parts
    r = b.store.create("o/r", "read", 60)
    b.store.approve(r.id)
    out = TestClient(admin_app(b)).get("/admin/status").json()
    assert out["grants"][0]["repo"] == "o/r"


def test_settings_require_policy_and_identity():
    with pytest.raises(SystemExit):
        Settings.from_env({})
    s = Settings.from_env({"TG_POLICY": "/p", "TG_SANDBOX_IDENTITY": SANDBOX, "TG_LISTEN_PORT": "9",
                           "TG_READER_CLIENT_ID": "Iv", "TG_READER_KEY": "/k"})
    assert s.listen_port == 9 and s.audience == "terracotta-general"
