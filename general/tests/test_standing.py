import asyncio
import io

from fake_github import FakeGitHub, new_keypair

from terracotta_general.audit import AuditLog
from terracotta_general.github import App
from terracotta_general.policy import Policy
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
POLICY = Policy.load('read: {standing: {allow: ["octo/*", "org/one"], deny: ["octo/secret"]}}')


def setup(inst=None):
    fake = FakeGitHub(PUB, inst or {1: ("octo", ["a", "b", "secret"]), 2: ("org", ["one", "two"])})
    app = App(fake.client_id, PRIV, fake.client())
    buf = io.StringIO()
    return fake, StandingRead(app, lambda: POLICY, AuditLog(buf)), buf


def run(c):
    return asyncio.run(c)


def test_refresh_mints_only_for_allowlisted_repos():
    fake, s, buf = setup()
    run(s.refresh())
    assert s.repos() == ["octo/a", "octo/b", "org/one"]
    assert s.token_for("OCTO/a").repos == {"a", "b"}   # one token per installation
    assert s.token_for("octo/secret") is None and s.token_for("org/two") is None
    live = [v for v in fake.tokens.values() if not v["revoked"]]
    assert sorted(v["perms"].get("contents") for v in live) == ["read", "read"]  # listing tokens revoked
    assert all("metadata" in v["perms"] for v in live)
    assert "ghs_" not in buf.getvalue()


def test_refresh_revokes_superseded_tokens():
    fake, s, _ = setup()
    run(s.refresh())
    first = {t for t, v in fake.tokens.items() if not v["revoked"]}
    run(s.refresh())
    assert all(fake.tokens[t]["revoked"] for t in first)
    assert s.token_for("octo/a")


def test_new_repo_matching_glob_appears_on_next_refresh():
    fake, s, _ = setup()
    run(s.refresh())
    fake.inst[1][1].append("fresh")
    run(s.refresh())
    assert s.token_for("octo/fresh")


def test_expiry_and_refresh_timing():
    _f, s, _ = setup()
    t = [1_000.0]
    s._clock = lambda: t[0]
    assert s.next_refresh_in() == 0
    run(s.refresh())
    # fake tokens expire one hour after real time; use the token's own expiry
    tok = s.token_for("octo/a")
    t[0] = tok.expires_at - 700
    assert abs(s.next_refresh_in() - 100) < 1
    t[0] = tok.expires_at + 1
    assert s.token_for("octo/a") is None
