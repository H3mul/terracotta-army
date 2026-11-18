"""Negative and randomized tests on everything that parses input from outside the broker.

Seeded, so a failure reproduces. Properties, not examples: no input may crash a handler or yield a
token for a repo the policy does not allow.
"""

import asyncio
import io
import random

import pytest
from fake_github import FakeGitHub, new_keypair
from starlette.testclient import TestClient

from terracotta_general import CONTRACT_VERSION
from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditLog
from terracotta_general.broker import Broker
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.policy import Policy, parse_ttl
from terracotta_general.repo import parse_repo
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead

PRIV, PUB = new_keypair()
SANDBOX = "system:serviceaccount:ws:sandbox"
POLICY = Policy.load('read: {standing: {allow: ["octo/mine"], deny: ["octo/secret"]}, adhoc: {allow: ["octo/*"]}}')
H = {"X-Contract-Version": str(CONTRACT_VERSION), "Authorization": "Bearer good"}
ALPHABET = ["a", "b", "o", "c", "t", "m", "i", "n", "e", "0", "9", "/", "/", ".", "..", "-", "_", "%2e", "%2f", "\\",
            "\x00", "\n", " ", "é", "𝕩", "@", ":", "*", "?", "octo", "mine", "secret", ".git", "https://", "\u202e"]


def junk(rng, n):
    return "".join(rng.choice(ALPHABET) for _ in range(rng.randint(0, n)))


class Auth:
    async def identify(self, t):
        return SANDBOX if t == "good" else None


@pytest.fixture(scope="module")
def client():
    fake = FakeGitHub(PUB, {1: ("octo", ["mine", "other", "secret"])})
    app = App(fake.client_id, PRIV, fake.client())
    store, audit = RequestStore(), AuditLog(io.StringIO())
    b = Broker(lambda: POLICY, store, audit, Auth(), SANDBOX, StandingRead(app, lambda: POLICY, audit),
               Grants(app, store, lambda: POLICY, audit))
    asyncio.run(b.standing.refresh())
    return TestClient(sandbox_app(b), raise_server_exceptions=True), TestClient(admin_app(b))


def test_credential_endpoint_never_crashes_and_only_serves_allowed_repos(client):
    c, _ = client
    rng = random.Random(1234)
    served = set()
    for _ in range(600):
        path = junk(rng, 8) if rng.random() < 0.7 else rng.choice(["octo/mine", "/octo/mine.git", "octo/other"]) + junk(rng, 3)
        body = {"host": rng.choice(["github.com", "github.com", junk(rng, 4)]), "path": path, "username": junk(rng, 3)}
        r = c.post("/v1/credential", headers=H, json=body)
        assert r.status_code in (200, 400, 403), (body, r.status_code)
        if r.status_code == 200:
            served.add(body["path"])
            assert body["host"] == "github.com" and r.json()["password"].startswith("ghs_")
    assert all(p.strip("/").removesuffix(".git").lower() in ("octo/mine",) for p in served), served


@pytest.mark.parametrize("body", [
    b"", b"null", b"[]", b'"x"', b"1", b"{", b'{"host": 1, "path": 2}', b'{"host": "github.com"}',
    b'{"host": null, "path": null}', b'{"host": ["github.com"], "path": "octo/mine"}',
    b'{"host": "github.com", "path": "octo/mine", "username": 5}', b"\xff\xfe", b"{" * 5000,
    b'{"host": "github.com", "path": "' + b"a" * 100_000 + b'"}',
])
def test_malformed_bodies_get_400_not_500(client, body):
    c, _ = client
    r = c.post("/v1/credential", headers=H, content=body)
    assert r.status_code == 400 or (r.status_code == 403 and len(body) > 1000)


@pytest.mark.parametrize("headers,code", [
    ({}, 400), ({"X-Contract-Version": "x"}, 400), ({"X-Contract-Version": "-1"}, 400),
    ({"X-Contract-Version": "1"}, 401), ({"X-Contract-Version": "1", "Authorization": "Basic good"}, 401),
    ({"X-Contract-Version": "1", "Authorization": "Bearer"}, 401),
    ({"X-Contract-Version": "1", "Authorization": "Bearer evil"}, 401),
    ({"X-Contract-Version": "0", "Authorization": "Bearer good"}, 426),
])
def test_header_gating_table(client, headers, code):
    c, _ = client
    assert c.post("/v1/credential", headers=headers, json={"host": "github.com", "path": "octo/mine"}).status_code == code


def test_parse_repo_and_parse_ttl_never_raise_anything_but_valueerror():
    rng = random.Random(99)
    for _ in range(3000):
        s = junk(rng, 10)
        for fn in (parse_repo, parse_ttl):
            try:
                out = fn(s)
            except ValueError:
                continue
            assert out and (fn is parse_ttl or "/" in out and ".." not in out and not out.endswith(".git"))


def test_policy_decide_is_total_and_deny_always_wins():
    rng = random.Random(7)
    pol = Policy.load('read: {standing: {allow: ["*/*"], deny: ["octo/secret*"]}, adhoc: {allow: ["*/*"]}}\n'
                      'write: {allow: ["*/*"], deny: ["octo/secret*"]}')
    for _ in range(2000):
        repo = junk(rng, 8)
        for level in ("standing", "read", "write"):
            d = pol.decide(repo, level)
            assert isinstance(d.allowed, bool) and d.reason
            if repo.lower().startswith("octo/secret"):
                assert not d.allowed


@pytest.mark.parametrize("text", [
    "read: {nonsense: 1}", "read: 5", "write: {max_ttl: 3d}", "write: {max_ttl: 1h, default_ttl: 2h}",
    "- a\n- b", "read: {standing: {allow: [1, 2]}}", "!!python/object/apply:os.system ['id']", "{{{{",
    "write: {permissions: 7}", "read: {adhoc: {max_ttl: 0s}}",
])
def test_bad_policies_are_rejected_not_executed(text):
    with pytest.raises(Exception) as e:
        Policy.load(text)
    assert not isinstance(e.value, (SystemExit, KeyboardInterrupt, MemoryError))


@pytest.mark.parametrize("body", [{}, {"repo": 5}, {"repo": "../x"}, {"repo": "octo/mine", "ttl": "forever"},
                                  {"repo": "octo/other", "ttl": "forever"}, {"repo": "octo/other", "ttl": 5}])
def test_admin_grant_rejects_bad_input_without_a_crash(client, body):
    _, adm = client
    try:
        r = adm.post("/admin/grant", json={"level": "read", **body})
    except (KeyError, ValueError, TypeError, AttributeError):
        pytest.fail(f"admin grant crashed on {body}")
    assert r.status_code in (400, 403, 409, 422, 501)
