import asyncio
import io
import os
import stat

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fake_github import FakeGitHub, new_keypair

from terracotta_general.audit import AuditLog
from terracotta_general.keys import KeyRefresher, KeysError, fingerprint, parse_key

_, PUB = new_keypair()


def new_key(comment="me") -> str:
    k = ed25519.Ed25519PrivateKey.generate().public_key()
    raw = k.public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
    return f"{raw} {comment}"


def setup(tmp_path, users=("octo",)):
    fake = FakeGitHub(PUB, {})
    buf = io.StringIO()
    path = tmp_path / "ak.github"
    r = KeyRefresher(fake.client(), list(users), str(path), AuditLog(buf), base="https://github.com")
    return fake, r, path, buf


def run(c):
    return asyncio.run(c)


def test_parse_key_accepts_real_keys_and_drops_the_comment_and_junk():
    k = new_key("laptop")
    assert parse_key(k) == " ".join(k.split()[:2])
    for bad in ("", "ssh-ed25519", "ssh-ed25519 !!notbase64", "ssh-dss AAAAB3NzaC1kc3M=",
                "command=\"x\" " + k, "ssh-ed25519 AAAA"):
        assert parse_key(bad) is None


def test_refresh_writes_the_keys_world_readable_and_returns_fingerprints(tmp_path):
    fake, r, path, buf = setup(tmp_path)
    k1, k2 = new_key("phone"), new_key("laptop")
    fake.ssh_keys["octo"] = [k1, k2, "garbage line"]
    prints = run(r.refresh())
    assert prints == [fingerprint(parse_key(k1)), fingerprint(parse_key(k2))]
    assert path.read_text().splitlines() == [parse_key(k1), parse_key(k2)]
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o644
    assert "phone" not in path.read_text() and '"event":"keys"' in buf.getvalue()


def test_two_accounts_are_merged_without_duplicates(tmp_path):
    fake, r, _path, _ = setup(tmp_path, users=("octo", "cat"))
    shared = new_key()
    fake.ssh_keys.update({"octo": [shared], "cat": [shared, new_key()]})
    assert len(run(r.refresh())) == 2


@pytest.mark.parametrize("setup_fake", ["missing-account", "empty", "one-of-two-fails"])
def test_a_bad_refresh_keeps_the_previous_file(tmp_path, setup_fake):
    fake, r, path, buf = setup(tmp_path, users=("octo", "cat") if setup_fake == "one-of-two-fails" else ("octo",))
    fake.ssh_keys.update({"octo": [new_key()], "cat": [new_key()]})
    run(r.refresh())
    before = path.read_text()
    if setup_fake == "missing-account":
        del fake.ssh_keys["octo"]
    elif setup_fake == "empty":
        fake.ssh_keys["octo"] = ["not a key"]
    else:
        del fake.ssh_keys["cat"]
    with pytest.raises(KeysError):
        run(r.refresh())
    assert path.read_text() == before and '"event":"refused"' in buf.getvalue()


def test_github_being_unreachable_is_a_fixed_reason(tmp_path):
    _fake, r, _, _ = setup(tmp_path)

    def down(req):
        raise httpx.ConnectError("x")

    r._http = httpx.AsyncClient(transport=httpx.MockTransport(down))
    with pytest.raises(KeysError, match="github-unreachable"):
        run(r.refresh())


def test_only_plain_github_logins_are_accepted(tmp_path):
    for bad in ("../x", "a/b", "-x", "x y", ""):
        with pytest.raises(SystemExit):
            setup(tmp_path, users=(bad,))


def test_redirects_are_not_followed(tmp_path):
    _fake, r, _, _ = setup(tmp_path)
    r._http = httpx.AsyncClient(transport=httpx.MockTransport(
        lambda req: httpx.Response(302, headers={"location": "https://evil.example/k.keys"})))
    with pytest.raises(KeysError, match="github-refused"):
        run(r.refresh())
