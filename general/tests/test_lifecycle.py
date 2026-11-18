import asyncio
import io

import httpx
import pytest
from fake_github import FakeGitHub, new_keypair
from starlette.testclient import TestClient

from terracotta_general.api import admin_app
from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.lifecycle import Lifecycle, describe_changes, digest
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
V1 = 'read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/*"]}}'
V2 = 'read: {standing: {allow: ["octo/mine", "octo/other"]}, adhoc: {allow: ["octo/*"], max_ttl: 1h}}'


def test_digest_ignores_formatting_not_content():
    assert digest(Policy.load(V1)) == digest(Policy.load("# c\n" + V1.replace(": {", ":\n  {")))
    assert digest(Policy.load(V1)) != digest(Policy.load(V2))


def test_changes_in_plain_words():
    assert describe_changes(Policy.load(V1), Policy.load(V2)) == [
        '+ read.standing.allow: octo/other', "~ read.adhoc.max_ttl: 8h -> 1h"]
    assert describe_changes(Policy.load(V2), Policy.load(V1))[0] == "- read.standing.allow: octo/other"


def test_fresh_broker_denies_everything_until_approved(tmp_path):
    prop = tmp_path / "p.yaml"
    prop.write_text(V1)
    life = Lifecycle(str(tmp_path / "s.json"), str(prop))
    assert not life.policy().decide("octo/mine", "standing").allowed
    life.approve(digest(Policy.load(V1)))
    assert life.policy().decide("octo/mine", "standing").allowed


def test_approval_survives_restart_and_is_bound_to_the_reviewed_hash(tmp_path):
    prop, state = tmp_path / "p.yaml", str(tmp_path / "s.json")
    prop.write_text(V1)
    Lifecycle(state, str(prop)).approve(digest(Policy.load(V1)))
    prop.write_text(V2)  # the proposal changes after the restart
    life = Lifecycle(state, str(prop))
    assert not life.policy().decide("octo/other", "standing").allowed  # V1 still in force
    with pytest.raises(ValueError, match="not abc"):
        life.approve("abc")  # not what was reviewed
    prop.write_text("read: {nonsense: 1}")
    with pytest.raises(ValueError, match="invalid"):
        life.approve(digest(Policy.load(V2)))


def test_corrupt_state_is_not_silently_reset(tmp_path):
    (tmp_path / "s.json").write_text("{not json")
    with pytest.raises(SystemExit):
        Lifecycle(str(tmp_path / "s.json"), str(tmp_path / "p.yaml"))


@pytest.fixture
def rig(tmp_path):
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other", "third"])})
    app = App(fake.client_id, PRIV, fake.client())
    prop = tmp_path / "p.yaml"
    prop.write_text(V1)
    life = Lifecycle(str(tmp_path / "s.json"), str(prop))
    life.approve(digest(Policy.load(V1)))
    store, audit = RequestStore(), AuditLog(io.StringIO())
    b = Broker(life.policy, store, audit, None, "sa", StandingRead(app, life.policy, audit),
               Grants(app, store, life.policy, audit), life)
    asyncio.run(b.standing.refresh())
    return b, prop, fake, TestClient(admin_app(b))


def test_show_then_approve_revokes_what_the_new_policy_forbids(rig):
    b, prop, _, c = rig
    asyncio.run(b.grants.grant_read("octo/other", "1h", "t"))
    prop.write_text(V2)  # octo/other becomes standing, so the ad hoc grant is redundant
    shown = c.get("/admin/policy").json()
    assert shown["proposed"] != shown["active"] and "+ read.standing.allow: octo/other" in shown["changes"]
    out = c.post("/admin/policy/approve", json={"hash": shown["proposed"]}).json()
    assert out["revoked"] == 1 and not b.store.active("octo/other", "read")
    assert b.standing.token_for("octo/other")  # standing set refreshed under the new policy
    assert c.get("/admin/policy").json()["changes"] == []


def test_approve_wrong_hash_changes_nothing(rig):
    b, prop, _, c = rig
    prop.write_text(V2)
    r = c.post("/admin/policy/approve", json={"hash": "deadbeef"})
    assert r.status_code == 409 and not b.policy().decide("octo/other", "standing").allowed


def test_invalid_proposal_is_reported_not_applied(rig):
    _, prop, _, c = rig
    prop.write_text("read: {nonsense: 1}")
    out = c.get("/admin/policy").json()
    assert out["proposed"] is None and out["error"]


def test_stop_kills_tokens_blocks_serving_and_survives_restart(rig, tmp_path):
    from terracotta_general.credential import serve_credential
    b, _, fake, c = rig
    b.auth = None
    b.app = b.standing._app
    asyncio.run(b.grants.grant_read("octo/other", "1h", "t"))
    out = c.post("/admin/stop").json()
    assert out == {"revoked": 1, "suspended": 1, "errors": []}
    assert fake.suspended == {1} and not b.standing.repos() and not b.store.active()
    assert all(v["revoked"] or v["inst"] in fake.suspended for v in fake.tokens.values())
    assert asyncio.run(serve_credential(b, "github.com", "octo/mine", "", "sa"))[0] == 503
    assert c.post("/admin/grant", json={"repo": "octo/third", "level": "read"}).status_code == 409
    assert c.get("/admin/status").json()["stopped"] is True
    assert Lifecycle(str(tmp_path / "s.json"), str(tmp_path / "p.yaml")).stopped  # persisted
    assert c.post("/admin/stop").json()["errors"] == []  # repeatable

    assert c.post("/admin/resume").status_code == 200
    assert not fake.suspended and b.standing.token_for("octo/mine")
    assert asyncio.run(serve_credential(b, "github.com", "octo/mine", "", "sa"))[0] == 200


def test_failed_resume_stays_stopped(rig):
    b, _, _, c = rig
    b.app = b.standing._app
    c.post("/admin/stop")
    b.app._http = httpx.AsyncClient(transport=httpx.MockTransport(lambda req: httpx.Response(500)))
    r = c.post("/admin/resume")
    assert r.status_code == 502 and b.life.stopped


def test_check_reports_branch_protection_and_revokes_its_probe_token(rig):
    b, _, fake, c = rig
    b.app = b.standing._app
    fake.protected.add("octo/mine")
    before = set(fake.tokens)
    assert c.get("/admin/check", params={"repo": "octo/mine"}).json()["protection"] == "main is protected"
    assert c.get("/admin/check", params={"repo": "octo/other"}).json()["protection"] == "main is NOT protected"
    probes = [v for t, v in fake.tokens.items() if t not in before]
    assert len(probes) == 2 and all(v["revoked"] and v["repos"] and v["perms"] == {"contents": "read", "metadata": "read"} for v in probes)
    assert c.get("/admin/check", params={"repo": "stranger/x"}).json()["protection"] == "unknown: repo is not in policy"
    b.app = None
    assert c.get("/admin/check", params={"repo": "octo/mine"}).json()["protection"].startswith("unknown")
