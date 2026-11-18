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
