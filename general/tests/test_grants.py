import asyncio
import io

import pytest
from fake_github import FakeGitHub, new_keypair

from terracotta_general.audit import AuditLog
from terracotta_general.github import App, GitHubError
from terracotta_general.grants import REMINT_BEFORE, Grants
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore, TransitionError

PRIV, PUB = new_keypair()
POLICY = Policy.load("""
read:
  standing: {allow: ["octo/mine"], deny: ["octo/secret"]}
  adhoc: {allow: ["octo/*"], max_ttl: 2h}
""")


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def setup():
    clk = Clock()
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other", "secret"])}, clock=clk)
    store = RequestStore(clk)
    buf = io.StringIO()
    g = Grants(App(fake.client_id, PRIV, fake.client()), store, lambda: POLICY, AuditLog(buf), clk)
    return fake, clk, store, g, buf


def run(c):
    return asyncio.run(c)


def live_tokens(fake):
    return [t for t, v in fake.tokens.items() if not v["revoked"]]


def test_grant_mints_one_repo_token_and_audits_without_it():
    _, _, store, g, buf = setup()
    req = run(g.grant_read("octo/other", "30m", "operator"))
    assert req.ttl == 1800 and store.active("octo/other", "read")
    t = run(g.token_for("octo/other"))
    assert t.repos == {"other"}
    assert "ghs_" not in buf.getvalue() and '"event":"grant"' in buf.getvalue()


def test_policy_refusals_leave_no_token_or_request():
    fake, _, store, g, _ = setup()
    for repo in ("octo/mine", "octo/secret", "stranger/x"):  # standing, denied, outside policy
        with pytest.raises(PermissionError):
            run(g.grant_read(repo, None, "operator"))
    assert not fake.tokens and not store.all()


def test_ttl_capped_and_duplicate_refused():
    _, _, _, g, _ = setup()
    assert run(g.grant_read("octo/other", "99h", "op")).ttl == 7200
    with pytest.raises(TransitionError):
        run(g.grant_read("octo/other", None, "op"))


def test_not_installed_leaves_no_request():
    _, _, store, g, _ = setup()
    policy = Policy.load('read: {adhoc: {allow: ["octo/*"]}}')
    g._policy = lambda: policy
    with pytest.raises(GitHubError, match="not-installed"):
        run(g.grant_read("octo/ghost", None, "op"))
    assert not store.all()


def test_revoke_kills_token_at_github():
    fake, _, _, g, _ = setup()
    run(g.grant_read("octo/other", None, "op"))
    assert run(g.revoke("octo/other")) == 1
    assert not live_tokens(fake) and run(g.token_for("octo/other")) is None


def test_expiry_sweep_revokes_token():
    fake, clk, _, g, buf = setup()
    run(g.grant_read("octo/other", "30m", "op"))
    clk.t += 1801
    assert run(g.token_for("octo/other")) is None
    run(g.sweep())
    assert not live_tokens(fake) and '"event":"expire"' in buf.getvalue()


def test_remint_when_token_nearly_expired_but_grant_still_active():
    fake, clk, _, g, _ = setup()
    run(g.grant_read("octo/other", "2h", "op"))
    old = next(iter(g._tokens.values()))[0]
    clk.t = old.expires_at - REMINT_BEFORE + 1  # grant (2h) still active, token about to lapse
    new = run(g.token_for("octo/other"))
    assert new.value != old.value and fake.tokens[old.value]["revoked"]


def test_revoke_all():
    fake, _, _, g, _ = setup()
    run(g.grant_read("octo/other", None, "op"))
    assert run(g.revoke_all()) == 1 and not live_tokens(fake)


def test_daily_grant_limit_refuses_audits_and_recovers_after_a_day():
    clk, fake = Clock(), FakeGitHub(PUB, {1: ("octo", ["a", "b", "c"])}, clock=Clock())
    pol = Policy.load('read: {adhoc: {allow: ["octo/*"]}}\nlimits: {grants_per_day: 2}')
    buf = io.StringIO()
    g = Grants(App(fake.client_id, PRIV, fake.client()), RequestStore(clk), lambda: pol, AuditLog(buf), clk)
    run(g.grant_read("octo/a", None, "operator"))
    run(g.grant_read("octo/b", None, "operator"))
    with pytest.raises(PermissionError, match="daily limit of 2 ad hoc grants"):
        run(g.grant_read("octo/c", None, "operator"))
    assert "daily limit of 2 grants reached" in buf.getvalue()
    assert g.usage()["grants"] == "2/2 in the last 24h"
    clk.t += 86401
    run(g.grant_read("octo/c", None, "operator"))


def test_daily_mint_limit_keeps_the_old_token_instead_of_failing():
    clk, fake = Clock(), FakeGitHub(PUB, {1: ("octo", ["a"])}, clock=Clock())
    pol = Policy.load('read: {adhoc: {allow: ["octo/*"]}}\nlimits: {mints_per_day: 1}')
    g = Grants(App(fake.client_id, PRIV, fake.client()), RequestStore(clk), lambda: pol, AuditLog(io.StringIO()), clk)
    run(g.grant_read("octo/a", None, "operator"))
    first = run(g.token_for("octo/a"))
    clk.t = first.expires_at - 1  # near expiry, remint wanted but over the cap
    fake.clock = clk
    assert run(g.token_for("octo/a")) is first
