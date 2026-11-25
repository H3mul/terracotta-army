import asyncio
import json

import httpx
import pytest
from fake_github import FakeGitHub, new_keypair

from terracotta_general.github import App, GitHubError, _perms_within

PRIV, PUB = new_keypair()


def make(inst=None):
    fake = FakeGitHub(PUB, inst or {1: ("octo", ["a", "b", "c"])})
    return fake, App(fake.client_id, PRIV, fake.client(), base="https://api.github.com")


def run(c):
    return asyncio.run(c)


def test_installations_and_signed_jwt():
    _, app = make()
    assert [(i.id, i.login) for i in run(app.installations())] == [(1, "octo")]


def test_wrong_key_rejected():
    fake, _ = make()
    other_priv, _ = new_keypair()
    with pytest.raises(GitHubError):
        run(App(fake.client_id, other_priv, fake.client()).installations())


def test_repo_scoped_token_and_listing():
    _, app = make()
    t = run(app.installation_token(1, ["a", "b"], {"contents": "read"}))
    assert t.repos == {"a", "b"} and "ghs_" not in repr(t)
    listing = run(app.installation_token(1, None, {"metadata": "read"}))
    assert run(app.list_repos(listing)) == ["a", "b", "c"]


def test_installation_for_repo_and_missing():
    _, app = make()
    assert run(app.installation_for_repo("octo/a")) == 1
    with pytest.raises(GitHubError, match="not-installed"):
        run(app.installation_for_repo("octo/zzz"))


def test_revoke():
    fake, app = make()
    t = run(app.installation_token(1, ["a"], {"contents": "read"}))
    run(app.revoke(t))
    assert next(iter(fake.tokens.values()))["revoked"]


def test_a_token_without_a_repo_list_is_only_allowed_for_metadata():
    fake, app = make()
    for perms in ({"contents": "read"}, {"metadata": "read", "contents": "read"}):
        with pytest.raises(GitHubError, match="unscoped"):
            run(app.installation_token(1, None, perms))
    assert not fake.tokens
    run(app.installation_token(1, None, {"metadata": "read"}))  # the listing token still works


def test_too_broad_permissions_are_revoked_and_refused():
    fake, app = make()
    fake.broaden = True  # answer claims all repos plus administration:write
    with pytest.raises(GitHubError, match="too-broad"):
        run(app.installation_token(1, ["a"], {"contents": "read"}))
    assert all(v["revoked"] for v in fake.tokens.values())


def test_metadata_read_is_implicit_but_nothing_else_extra():
    assert _perms_within({"contents": "read", "metadata": "read"}, {"contents": "read"})
    assert not _perms_within({"contents": "write"}, {"contents": "read"})
    assert not _perms_within({"issues": "read"}, {"contents": "read"})
    assert not _perms_within({"metadata": "write"}, {"contents": "read"})


def test_repo_set_mismatch_is_too_broad():
    fake, app = make()
    orig = fake.handle

    def lying(req):
        r = orig(req)
        if req.url.path.endswith("access_tokens"):
            ans = json.loads(r.content)
            ans["repositories"] = [{"name": "a"}, {"name": "b"}]
            return httpx.Response(201, json=ans)
        return r

    app._http._transport = httpx.MockTransport(lying)
    with pytest.raises(GitHubError, match="too-broad"):
        run(app.installation_token(1, ["a"], {"contents": "read"}))


def test_mint_and_revoke_are_logged_before_the_call_and_again_after():
    import io

    from terracotta_general.audit import AuditLog

    fake, _ = make()
    buf, seen = io.StringIO(), []
    audit = AuditLog(buf)
    app = App(fake.client_id, PRIV, fake.client(), audit=audit)
    real = app._call

    async def spy(method, path, bearer, **kw):
        seen.append(buf.getvalue().count('"state":"started"') - buf.getvalue().count('"state":"done"'))
        return await real(method, path, bearer, **kw)

    app._call = spy
    t = run(app.installation_token(1, ["a"], {"contents": "read"}))
    run(app.revoke(t))
    recs = [json.loads(x) for x in buf.getvalue().splitlines()]
    assert [(r["event"], r["state"]) for r in recs] == [
        ("mint", "started"), ("mint", "done"), ("revoke_token", "started"), ("revoke_token", "done")]
    assert seen[-2:] == [1, 1]  # an unfinished `started` existed when each request went out
    assert "ghs_" not in buf.getvalue()


def test_refused_mint_is_logged_failed():
    import io

    from terracotta_general.audit import AuditLog

    fake, _ = make()
    buf = io.StringIO()
    app = App(fake.client_id, PRIV, fake.client(), audit=AuditLog(buf))
    with pytest.raises(GitHubError):
        run(app.installation_token(99, ["a"], {"contents": "read"}))
    states = [json.loads(x)["state"] for x in buf.getvalue().splitlines()]
    assert states == ["started", "failed"]
