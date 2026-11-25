import asyncio
import io
import json

import pytest
from fake_github import FakeGitHub, new_keypair

from terracotta_general.audit import AuditLog
from terracotta_general.github import GitHubError, Writer

_, PUB = new_keypair()
PERMS = {"contents": "write", "pull_requests": "write"}


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def setup(secret="writer-secret", approve_after=0):
    clk, buf = Clock(), io.StringIO()
    fake = FakeGitHub(PUB, {1: ("octo", ["a", "b"])}, clock=clk)
    slept: list[float] = []

    async def sleep(n):
        slept.append(n)
        clk.t += n
        if len(slept) == approve_after:  # the phone approval lands during this wait
            fake.approve()

    w = Writer(fake.client_id, secret, fake.client(), clock=clk, audit=AuditLog(buf), sleep=sleep)
    return fake, w, buf, slept


def run(c):
    return asyncio.run(c)


def approved_user_token(fake, w):
    dc = run(w.device_start())
    fake.approve()
    return run(w.device_poll(dc))


def test_device_flow_returns_only_the_access_token_never_the_refresh_token():
    fake, w, buf, _ = setup()
    dc = run(w.device_start())
    assert dc.user_code == "ABCD-1234" and "device_code" not in repr(dc)
    fake.approve()
    tok = run(w.device_poll(dc))
    assert tok.startswith("ghu_") and isinstance(tok, str)
    assert "ghr_" not in buf.getvalue() and "ghr_" not in repr(w.__dict__)


def test_poll_waits_the_interval_and_obeys_slow_down():
    fake, w, _, slept = setup(approve_after=3)
    dc = run(w.device_start())
    fake.slow_downs = 1
    run(w.device_poll(dc))
    assert slept == [5, 10, 10]  # first wait is the interval, then GitHub's slow_down interval sticks


@pytest.mark.parametrize("how,reason", [("denied", "device-denied"), ("expired", "device-expired")])
def test_poll_ends_with_a_fixed_reason(how, reason):
    fake, w, _, _ = setup()
    dc = run(w.device_start())
    fake.approve(how)
    with pytest.raises(GitHubError, match=reason):
        run(w.device_poll(dc))


def test_poll_gives_up_at_the_timeout():
    _, w, _, _ = setup()
    dc = run(w.device_start())
    with pytest.raises(GitHubError, match="device-expired"):
        run(w.device_poll(dc, timeout=12))


def test_unknown_device_code_is_refused():
    _, w, _, _ = setup()
    dc = run(w.device_start())
    object.__setattr__(dc, "device_code", "nope")
    with pytest.raises(GitHubError, match="device-code-invalid"):
        run(w.device_poll(dc))


def test_scoped_token_covers_one_repo_and_the_requested_permissions():
    fake, w, buf, _ = setup()
    user = approved_user_token(fake, w)
    t = run(w.scoped(user, "octo", "a", PERMS))
    assert t.repos == {"a"} and t.value.startswith("ghu_") and t.value != user
    assert fake.tokens[t.value]["repos"] == ["a"] and fake.tokens[t.value]["perms"] == PERMS
    assert "ghu_" not in buf.getvalue() and '"event":"mint_scoped"' in buf.getvalue()


@pytest.mark.parametrize("repo", ["", "octo/a", "a/b"])
def test_a_repo_less_or_qualified_request_is_refused_before_anything_is_sent(repo):
    fake, w, _, _ = setup()
    user = approved_user_token(fake, w)
    before = len(fake.calls)
    with pytest.raises(GitHubError, match="github-unscoped-refused"):
        run(w.scoped(user, "octo", repo, PERMS))
    assert len(fake.calls) == before


def test_scoped_request_always_names_exactly_one_repository():
    fake, w, _, _ = setup()
    sent = []
    inner = fake.handle

    def spy(req):
        if req.url.path.endswith("/token/scoped"):
            sent.append(json.loads(req.content))
        return inner(req)

    import httpx
    w._http = httpx.AsyncClient(transport=httpx.MockTransport(spy))
    run(w.scoped(approved_user_token(fake, w), "octo", "a", PERMS))
    assert sent[0]["repositories"] == ["a"] and sent[0]["target"] == "octo"


def test_a_scoped_answer_with_extra_permissions_is_revoked_and_refused():
    fake, w, _, _ = setup()
    user = approved_user_token(fake, w)
    fake.broaden_scoped = True
    with pytest.raises(GitHubError, match="github-token-too-broad"):
        run(w.scoped(user, "octo", "a", PERMS))
    assert all(t["revoked"] for t in fake.tokens.values())


def test_wrong_secret_gets_nothing():
    fake, w, _, _ = setup(secret="wrong")
    user = approved_user_token(fake, w)
    with pytest.raises(GitHubError, match="github-refused"):
        run(w.scoped(user, "octo", "a", PERMS))


def test_revoke_user_kills_the_token_and_is_idempotent():
    fake, w, buf, _ = setup()
    user = approved_user_token(fake, w)
    t = run(w.scoped(user, "octo", "a", PERMS))
    run(w.revoke_user(t))
    assert fake.tokens[t.value]["revoked"]
    run(w.revoke_user(t))  # already gone is fine
    run(w.revoke_user(user))
    assert fake.users[user]["revoked"] and "ghu_" not in buf.getvalue()
