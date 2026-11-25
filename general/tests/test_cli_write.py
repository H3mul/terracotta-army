import asyncio
import io

import pytest
from fake_github import FakeGitHub, new_keypair
from starlette.testclient import TestClient
from typer.testing import CliRunner

from terracotta_general import cli
from terracotta_general.api import admin_app
from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.github import App, Writer
from terracotta_general.grants import Grants
from terracotta_general.lifecycle import Lifecycle, digest
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead
from terracotta_general.writes import WriteGrants

PRIV, PUB = new_keypair()
TEXT = """
read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/*"]}}
write: {allow: ["octo/a", "octo/mine"]}
"""
runner = CliRunner()


@pytest.fixture
def rig(monkeypatch, tmp_path):
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "a", "c"])})
    prop = tmp_path / "p.yaml"
    prop.write_text(TEXT)
    life = Lifecycle(str(tmp_path / "s.json"), str(prop))
    life.approve(digest(Policy.load(TEXT)))
    store, audit = RequestStore(), AuditLog(io.StringIO())
    app = App(fake.client_id, PRIV, fake.client(), audit=audit)
    grants = Grants(app, store, life.policy, audit)
    state = {"answer": "approved"}

    async def sleep(_):
        await asyncio.sleep(0.01)
        if fake.devices and state["answer"]:
            fake.approve(state["answer"])

    writer = Writer(fake.client_id, fake.writer_secret, fake.client(), audit=audit, sleep=sleep)
    writes = WriteGrants(writer, store, life.policy, audit, str(tmp_path / "w.json"), grants.spend,
                         paused=lambda: life.stopped)
    b = Broker(life.policy, store, audit, None, "sa", StandingRead(app, life.policy, audit), grants,
               life, app, writes)
    asyncio.run(b.standing.refresh())
    monkeypatch.setattr(cli, "POLL", 0.01)
    with TestClient(admin_app(b), base_url="http://broker") as client:  # one loop keeps the flow task alive
        monkeypatch.setattr(cli, "admin_client", lambda: client)
        yield b, fake, state


def test_grant_write_prints_the_code_then_grants(rig):
    _b, fake, _ = rig
    r = runner.invoke(cli.app, ["grant", "write", "octo/a", "20m"])
    assert r.exit_code == 0, r.output
    assert "ABCD-1234" in r.output and "github.com/login/device" in r.output
    assert "granted write on octo/a for 20m" in r.output
    assert "write" in runner.invoke(cli.app, ["status"]).output
    writes = [t for t in fake.tokens.values() if t["perms"].get("contents") == "write"]
    assert len(writes) == 1 and not writes[0]["revoked"]
    assert runner.invoke(cli.app, ["revoke", "octo/a", "write"]).output.startswith("revoked 1")
    assert writes[0]["revoked"]


@pytest.mark.parametrize("answer,code", [("denied", 3), ("expired", 4)])
def test_denied_and_expired_have_their_own_exit_codes(rig, answer, code):
    rig[2]["answer"] = answer
    r = runner.invoke(cli.app, ["grant", "write", "octo/a"])
    assert r.exit_code == code and "not granted" in r.output


def test_write_outside_policy_is_refused_with_the_reason(rig):
    r = runner.invoke(cli.app, ["grant", "write", "octo/c"])
    assert r.exit_code == 1 and "no write allow pattern matches" in r.output


def test_setup_read_only_for_a_standing_repo_prints_the_clone_command(rig):
    r = runner.invoke(cli.app, ["setup", "octo/mine"])
    assert r.exit_code == 0 and "standing allowlist" in r.output and "ws clone octo/mine" in r.output


def test_setup_with_write_grants_read_then_write(rig):
    r = runner.invoke(cli.app, ["setup", "octo/a", "--write"])
    assert r.exit_code == 0, r.output
    assert "read: granted" in r.output and "granted write on octo/a" in r.output
    assert "ws clone octo/a" in r.output


def test_setup_refuses_what_policy_forbids(rig):
    r = runner.invoke(cli.app, ["setup", "stranger/x"])
    assert r.exit_code == 1 and "not readable" in r.output
    r = runner.invoke(cli.app, ["setup", "octo/c", "--write"])
    assert r.exit_code == 1 and "write refused" in r.output


def test_stop_revokes_write_tokens_and_reports_leftovers(rig):
    _b, fake, _ = rig
    runner.invoke(cli.app, ["grant", "write", "octo/a"])
    r = runner.invoke(cli.app, ["stop"])
    assert r.exit_code == 0 and "revoked 1" in r.output
    assert all(t["revoked"] for t in fake.tokens.values() if t["perms"].get("contents") == "write")


def test_a_policy_without_the_write_rule_kills_the_grant(rig, tmp_path):
    b, fake, _ = rig
    runner.invoke(cli.app, ["grant", "write", "octo/a"])
    assert b.store.active("octo/a", "write")
    p = tmp_path / "p.yaml"
    p.write_text('read: {standing: {allow: ["octo/mine"]}}')
    out = runner.invoke(cli.app, ["policy", "show"]).output
    h = out.split("policy approve ")[1].split()[0]
    runner.invoke(cli.app, ["policy", "approve", h])
    assert not b.store.active("octo/a", "write")
    assert all(t["revoked"] for t in fake.tokens.values() if t["perms"].get("contents") == "write")
