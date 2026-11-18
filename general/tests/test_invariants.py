"""Threat-model invariants (ta-threat-model design) that the broker can check by itself.

Each test names its invariant. Invariants about the sandbox, egress and the runtime are checked
elsewhere: I1 and I2 in tests/integration (workspace disk and env, no admin route), I6 and I7 in
the homelab deployment.
"""

import asyncio
import io
import json
import pathlib
import re

import pytest
from fake_github import FakeGitHub, new_keypair
from starlette.testclient import TestClient

from terracotta_general import CONTRACT_VERSION
from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditError, AuditLog
from terracotta_general.broker import Broker
from terracotta_general.github import App, GitHubError, Token
from terracotta_general.grants import Grants
from terracotta_general.lifecycle import Lifecycle, digest
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
SANDBOX = "system:serviceaccount:ws:sandbox"
POLICY_TEXT = 'read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/*"]}}'
H = {"X-Contract-Version": str(CONTRACT_VERSION), "Authorization": "Bearer good"}
SRC = pathlib.Path(__file__).parents[1] / "src" / "terracotta_general"


class Auth:
    async def identify(self, t):
        return SANDBOX if t == "good" else None


@pytest.fixture
def rig(tmp_path):
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other", "third"])})
    app = App(fake.client_id, PRIV, fake.client())
    prop = tmp_path / "p.yaml"
    prop.write_text(POLICY_TEXT)
    life = Lifecycle(str(tmp_path / "s.json"), str(prop))
    life.approve(digest(Policy.load(POLICY_TEXT)))
    store, buf = RequestStore(), io.StringIO()
    audit = AuditLog(buf)
    b = Broker(life.policy, store, audit, Auth(), SANDBOX, StandingRead(app, life.policy, audit),
               Grants(app, store, life.policy, audit), life, app)
    asyncio.run(b.standing.refresh())
    return b, fake, buf, tmp_path


def test_I2_sandbox_api_has_no_way_to_start_approve_or_extend_a_grant(rig):
    b, *_ = rig
    paths = {r.path for r in sandbox_app(b).routes}
    assert paths == {"/healthz", "/v1/credential", "/v1/status"}
    c = TestClient(sandbox_app(b))
    for p in ("/admin/grant", "/admin/policy/approve", "/admin/stop", "/v1/grant", "/v1/approve"):
        assert c.post(p, headers=H, json={"repo": "octo/other", "hash": "x"}).status_code == 404


def test_I2_no_admin_route_is_reachable_by_a_sandbox_credential_name(rig):
    b, *_ = rig
    # the admin surface is a separate app on a unix socket; nothing in it is on the sandbox app
    assert not ({r.path for r in admin_app(b).routes} & {r.path for r in sandbox_app(b).routes})


def test_I4_sandbox_read_is_exactly_the_allowlist_plus_active_grants(rig):
    b, fake, *_ = rig
    c = TestClient(sandbox_app(b))

    def ok(repo):
        return c.post("/v1/credential", headers=H, json={"host": "github.com", "path": repo}).status_code == 200
    assert ok("octo/mine") and not ok("octo/other") and not ok("octo/third") and not ok("stranger/x")
    asyncio.run(b.grants.grant_read("octo/other", "10m", "op"))
    assert ok("octo/other") and not ok("octo/third")
    asyncio.run(b.grants.revoke("octo/other"))
    assert not ok("octo/other")
    live = [t for t in fake.tokens.values() if not t["revoked"]]
    assert all(t["repos"] == ["mine"] for t in live)  # nothing broader than the allowlist is alive


def test_I5_a_token_broader_than_requested_is_revoked_and_refused(rig):
    b, fake, *_ = rig
    fake.broaden = True
    before = {t for t, v in fake.tokens.items() if not v["revoked"]}
    with pytest.raises(GitHubError, match="too-broad"):
        asyncio.run(b.grants.grant_read("octo/other", "10m", "op"))
    assert {t for t, v in fake.tokens.items() if not v["revoked"]} == before  # the broad one is dead
    assert not b.store.active("octo/other")


def test_I8_policy_changes_apply_only_after_approval_and_forbidden_grants_die(rig):
    b, _, _, tmp = rig
    asyncio.run(b.grants.grant_read("octo/other", "1h", "op"))
    (tmp / "p.yaml").write_text('read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/third"]}}')
    assert b.policy().decide("octo/other", "read").allowed  # proposal alone changes nothing
    c = TestClient(admin_app(b))
    new = c.get("/admin/policy").json()["proposed"]
    assert c.post("/admin/policy/approve", json={"hash": new}).json()["revoked"] == 1
    assert not b.store.active("octo/other") and not b.policy().decide("octo/other", "read").allowed


def test_I9_secrets_never_reach_logs_or_reprs(rig):
    b, fake, buf, _ = rig
    c = TestClient(sandbox_app(b))
    r = c.post("/v1/credential", headers=H, json={"host": "github.com", "path": "octo/mine"})
    secret = r.json()["password"]
    asyncio.run(b.grants.grant_read("octo/other", "10m", "op"))
    c.post("/v1/credential", headers=H, json={"host": "github.com", "path": "octo/other"})
    assert not any(t in buf.getvalue() for t in fake.tokens)
    assert secret not in repr(Token(secret, 0.0, frozenset())) and secret not in str(Token(secret, 0.0, frozenset()))
    for bad in (secret, "ghs_" + "a" * 36, "-----BEGIN PRIVATE KEY-----", "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.sig"):
        with pytest.raises(AuditError):
            b.audit.write("served", reason=bad)
    # and no module logs: the only writer of operational output is the audit log
    for f in SRC.glob("*.py"):
        text = f.read_text()
        assert not re.search(r"\blogging\b|\bprint\(", text) or f.name in ("cli.py", "sshshell.py"), f.name


def test_I10_nothing_that_grants_access_is_written_to_disk(rig):
    b, _, _, tmp = rig
    asyncio.run(b.grants.grant_read("octo/other", "10m", "op"))
    b.life.set_stopped(True)
    on_disk = json.loads((tmp / "s.json").read_text())
    assert set(on_disk) == {"policy", "stopped"}  # approved policy text and the stop flag, nothing else
    fresh = Broker(lambda: b.life.policy(), RequestStore(), b.audit, Auth(), SANDBOX)
    assert fresh.store.active() == []  # a restarted broker starts with no grants
    assert b.standing.token_for("octo/mine") and "ghs_" not in (tmp / "s.json").read_text()
