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
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
POLICY = Policy.load('read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/*"], max_ttl: 2h}}')
runner = CliRunner()


@pytest.fixture
def broker(monkeypatch, tmp_path):
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other"])})
    app = App(fake.client_id, PRIV, fake.client())
    store = RequestStore()
    log_file = tmp_path / "audit.log"
    audit = AuditLog(io.StringIO(), log_file.open("a"))
    b = Broker(lambda: POLICY, store, audit, None, "sa",
               StandingRead(app, lambda: POLICY, audit), Grants(app, store, lambda: POLICY, audit))
    asyncio.run(b.standing.refresh())
    monkeypatch.setattr(cli, "admin_client", lambda: TestClient(admin_app(b), base_url="http://broker"))
    return b, log_file


def test_status_check_grant_revoke_flow(broker):
    r = runner.invoke(cli.app, ["status"])
    assert "standing read: 1 repos" in r.output and "octo/mine" in r.output
    r = runner.invoke(cli.app, ["check", "octo/other"])
    assert "allowed by" in r.output and "standing token held: False" in r.output
    r = runner.invoke(cli.app, ["grant", "read", "octo/other", "10m"])
    assert r.exit_code == 0 and "granted read on octo/other for 10m" in r.output
    assert "octo/other" in runner.invoke(cli.app, ["status"]).output
    r = runner.invoke(cli.app, ["revoke", "octo/other"])
    assert "revoked 1 grant(s)" in r.output


def test_refusals_exit_1_with_reason(broker):
    r = runner.invoke(cli.app, ["grant", "read", "stranger/x"])
    assert r.exit_code == 1 and "refused (403)" in r.output
    r = runner.invoke(cli.app, ["grant", "read", "octo/other", "forever"])
    assert r.exit_code == 2  # bad TTL is a usage error, before any call


def test_unreachable_daemon(monkeypatch):
    monkeypatch.setenv("TG_ADMIN_SOCKET", "/nonexistent.sock")
    r = runner.invoke(cli.app, ["status"])
    assert r.exit_code == 1 and "broker not reachable" in r.output


def test_log_verify_and_tamper(broker):
    _, log_file = broker
    runner.invoke(cli.app, ["grant", "read", "octo/other"])
    r = runner.invoke(cli.app, ["log", "--verify", "--file", str(log_file)])
    assert r.exit_code == 0 and "chain ok" in r.output
    r = runner.invoke(cli.app, ["log", "--file", str(log_file), "--since", "5m"])
    assert '"event":"grant"' in r.output
    lines = log_file.read_text().splitlines()
    log_file.write_text("\n".join(lines[1:]) + "\n")  # head cut (tail cuts are undetectable)
    r = runner.invoke(cli.app, ["log", "--verify", "--file", str(log_file)])
    assert r.exit_code == 1 and "CHAIN BROKEN" in r.output
