import asyncio
import io
import json
import os
import stat

import pytest
from fake_github import FakeGitHub, new_keypair

from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.credential import serve_credential
from terracotta_general.github import App, Writer
from terracotta_general.grants import Grants
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore, State, TransitionError
from terracotta_general.writes import WriteGrants

PRIV, PUB = new_keypair()
POLICY = Policy.load("""
read: {standing: {allow: ["octo/mine"]}, adhoc: {allow: ["octo/*"]}}
write: {allow: ["octo/a", "octo/b"], deny: ["octo/b"], max_ttl: 1h, default_ttl: 30m}
""")


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


class Rig:
    def __init__(self, tmp_path, outcome="approved"):
        self.clk, self.buf, self.path = Clock(), io.StringIO(), tmp_path / "write-tokens.json"
        self.fake = FakeGitHub(PUB, {1: ("octo", ["mine", "a", "b", "c"])}, clock=self.clk)
        self.store = RequestStore(self.clk)
        self.audit = AuditLog(self.buf)
        self.outcome, self.stopped = outcome, False

        async def sleep(n):
            if not self.outcome:  # the phone never answers
                await asyncio.Event().wait()
            self.clk.t += n
            if self.outcome and self.fake.devices:
                self.fake.approve(self.outcome)

        self.writer = Writer(self.fake.client_id, self.fake.writer_secret, self.fake.client(),
                             clock=self.clk, audit=self.audit, sleep=sleep)
        self.grants = Grants(App(self.fake.client_id, PRIV, self.fake.client()), self.store,
                             lambda: POLICY, self.audit, self.clk)
        self.make()

    def make(self):
        """(Re)start the broker's write side on the same disk file."""
        self.w = WriteGrants(self.writer, self.store, lambda: POLICY, self.audit, str(self.path),
                             self.grants.spend, paused=lambda: self.stopped, clock=self.clk)

    async def grant(self, repo="octo/a", ttl=None):
        req, dc = await self.w.begin(repo, ttl, "operator")
        await self.settle()
        return req, dc

    async def settle(self):
        await asyncio.gather(*list(self.w._flows.values()), return_exceptions=True)

    def live(self):
        return [t for t, v in self.fake.tokens.items() if not v["revoked"]]

    def users_live(self):
        return [t for t, v in self.fake.users.items() if not v["revoked"]]


def run(c):
    return asyncio.run(c)


def test_approved_flow_leaves_one_scoped_token_and_no_parent(tmp_path):
    async def go():
        r = Rig(tmp_path)
        req, dc = await r.grant(ttl="20m")
        assert dc.user_code == "ABCD-1234" and req.ttl == 1200
        assert r.w.status(req.id)["state"] == "approved"
        t = await r.w.token_for("octo/a")
        assert t and t.repos == {"a"} and t.expires_at == r.clk.t + 1200  # served only for the grant's TTL
        assert len(r.live()) == 1 and not r.users_live()  # parent revoked at once
        assert r.fake.tokens[r.live()[0]]["repos"] == ["a"]
        assert await r.w.token_for("octo/c") is None

    run(go())


def test_no_refresh_token_or_live_token_reaches_the_audit_log_or_state_beyond_the_token_file(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant()
        log = r.buf.getvalue()
        assert "ghr_" not in log and "ghu_" not in log
        disk = r.path.read_text()
        assert "ghr_" not in disk and json.loads(disk)  # only the scoped token, to revoke it later
        assert stat.S_IMODE(os.stat(r.path).st_mode) == 0o600
        assert "ghr_" not in repr(r.w.__dict__) + repr(r.writer.__dict__)

    run(go())


def test_denied_and_expired_approvals_leave_nothing(tmp_path):
    async def go(how, reason):
        r = Rig(tmp_path / how, outcome=how)
        (tmp_path / how).mkdir()
        req, _ = await r.grant()
        s = r.w.status(req.id)
        assert s["state"] == "failed" and s["reason"] == reason
        assert not r.live() and not r.users_live() and r.w.outstanding() == 0
        assert not r.store.active("octo/a", "write")

    run(go("denied", "device-denied"))
    run(go("expired", "device-expired"))


def test_policy_refusals_and_duplicates(tmp_path):
    async def go():
        r = Rig(tmp_path)
        for repo in ("octo/b", "octo/c", "stranger/x"):  # denied, not allowed, outside
            with pytest.raises(PermissionError):
                await r.w.begin(repo, None, "operator")
        assert not r.fake.devices
        await r.grant()
        with pytest.raises(TransitionError):
            await r.w.begin("octo/a", None, "operator")

    run(go())


def test_ttl_is_clamped_by_policy(tmp_path):
    async def go():
        r = Rig(tmp_path)
        req, _ = await r.grant(ttl="5h")
        assert req.ttl == 3600

    run(go())


def test_token_is_revoked_when_the_grant_ends(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant(ttl="10m")
        assert r.live()
        r.clk.t += 599
        await r.w.sweep()
        assert r.live() and await r.w.token_for("octo/a")
        r.clk.t += 2
        assert await r.w.token_for("octo/a") is None  # not served the moment the TTL passes
        await r.w.sweep()
        assert not r.live() and r.w.outstanding() == 0 and json.loads(r.path.read_text()) == {}

    run(go())


def test_revoke_kills_the_token_now(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant()
        assert await r.w.revoke("octo/a") == 1
        assert not r.live() and await r.w.token_for("octo/a") is None
        assert await r.w.revoke("octo/a") == 0

    run(go())


def test_a_restart_revokes_what_the_last_run_left(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant()
        assert r.live()
        r.make()  # new process, same disk, empty request store
        r.store = RequestStore(r.clk)
        r.make()
        assert r.w.outstanding() == 1 and await r.w.token_for("octo/a") is None  # nothing served after a restart
        await r.w.sweep()
        assert not r.live() and r.w.outstanding() == 0

    run(go())


def test_a_failed_revoke_is_kept_and_retried_with_backoff(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant(ttl="10m")
        r.clk.t += 700
        down = {"on": True}
        inner = r.fake.handle

        def flaky(req):
            if req.method == "DELETE" and down["on"]:
                return __import__("httpx").Response(500)
            return inner(req)

        import httpx
        r.writer._http = httpx.AsyncClient(transport=httpx.MockTransport(flaky))
        await r.w.sweep()
        assert r.live() and r.w.outstanding() == 1  # still held, still on disk
        calls = len([c for c in r.fake.calls])
        await r.w.sweep()  # too soon: backoff, no new attempt
        assert len([c for c in r.fake.calls]) == calls
        down["on"] = False
        r.clk.t += 31
        await r.w.sweep()
        assert not r.live() and r.w.outstanding() == 0

    run(go())


def test_revoke_all_forces_the_retry_and_stop_can_see_leftovers(tmp_path):
    async def go():
        r = Rig(tmp_path)
        await r.grant()
        assert await r.w.revoke_all() == 1
        assert not r.live() and r.w.outstanding() == 0

    run(go())


def test_a_flow_awaiting_the_phone_is_cancelled_by_revoke(tmp_path):
    async def go():
        r = Rig(tmp_path, outcome="")  # never approved
        req, _ = await r.w.begin("octo/a", None, "operator")
        await asyncio.sleep(0)
        assert r.store.get(req.id).state is State.PENDING
        assert await r.w.revoke("octo/a") == 1
        await r.settle()
        assert r.store.get(req.id).state is State.REVOKED and not r.live()

    run(go())


def test_stop_during_approval_revokes_the_token_it_just_got(tmp_path):
    async def go():
        r = Rig(tmp_path)
        r.stopped = True
        req, _ = await r.grant()
        assert r.w.status(req.id)["reason"] == "stopped" and not r.live() and r.w.outstanding() == 0

    run(go())


def test_write_grants_count_against_the_daily_limits(tmp_path):
    async def go():
        r = Rig(tmp_path)
        r.grants._policy = lambda: Policy.load(
            'write: {allow: ["octo/*"]}\nlimits: {grants_per_day: 1, mints_per_day: 5}')
        r.w._policy = r.grants._policy
        await r.grant("octo/a")
        with pytest.raises(PermissionError, match="daily limit"):
            await r.w.begin("octo/c", None, "operator")

    run(go())


def test_credential_helper_gets_the_write_token_only_for_the_granted_repo(tmp_path):
    async def go():
        r = Rig(tmp_path)

        class Auth:
            async def identify(self, t):
                return "sb"

        b = Broker(lambda: POLICY, r.store, r.audit, Auth(), "sb", grants=r.grants, writes=r.w)
        code, body = await serve_credential(b, "github.com", "octo/a.git", "writer", "sb")
        assert code == 403 and "grant write octo/a" in body["hint"]
        await r.grant()
        code, body = await serve_credential(b, "github.com", "octo/a.git", "writer", "sb")
        assert code == 200 and body["password"] in r.live() and body["expires_at"] == r.clk.t + 1800
        code, body = await serve_credential(b, "github.com", "octo/c.git", "writer", "sb")
        assert code == 403 and "write refused" in body["hint"]
        code, body = await serve_credential(b, "github.com", "octo/a.git", "", "sb")  # read path unaffected
        assert code == 403

    run(go())


def test_github_refusing_the_scope_fails_the_request_and_still_revokes_the_parent(tmp_path):
    async def go():
        r = Rig(tmp_path)
        r.fake.writer_perms = {"contents": "read"}  # the App cannot give what policy asks for
        req, _ = await r.grant()
        assert r.w.status(req.id)["reason"] == "github-refused"
        assert not r.users_live() and not r.live()

    run(go())
