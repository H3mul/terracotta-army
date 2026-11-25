import io
import json

import pytest

from terracotta_general.audit import AuditError, AuditLog, verify


def make():
    buf = io.StringIO()
    return AuditLog(buf, clock=lambda: 5.0), buf


def test_chain_verifies_and_detects_edits_and_truncation_from_front():
    log, buf = make()
    log.write("grant", repo="o/r", level="read", ttl=60)
    log.write("revoke", repo="o/r")
    log.write("stop")
    lines = buf.getvalue().splitlines()
    assert verify(lines) == 3

    edited = json.loads(lines[1])
    edited["repo"] = "o/other"
    assert_broken([lines[0], json.dumps(edited), lines[2]])
    assert_broken([lines[0], lines[2]])          # record removed from the middle
    assert_broken(lines[1:])                     # head cut off
    assert verify(lines[:2]) == 2                # tail truncation is not detectable by the chain alone


def assert_broken(lines):
    with pytest.raises(AuditError):
        verify(lines)


def test_malformed_line():
    assert_broken(["not json"])


@pytest.mark.parametrize("secret", [
    "ghs_" + "a" * 36,
    "github_pat_" + "B" * 30,
    "-----BEGIN RSA PRIVATE KEY-----",
    "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiIxMjM0NTY3ODkwIn0.sig",
])
def test_secret_like_values_refused(secret):
    log, buf = make()
    with pytest.raises(AuditError):
        log.write("grant", reason=secret)
    assert buf.getvalue() == ""


def test_unknown_field_and_bad_types_refused():
    log, _ = make()
    for bad in ({"token": "x"}, {"repo": ["a"]}, {"ttl": True}):
        with pytest.raises(AuditError):
            log.write("grant", **bad)


def test_chain_continues_across_restarts_and_refuses_a_broken_file():
    import io

    from terracotta_general.audit import AuditError, AuditLog, resume_point, verify
    a = io.StringIO()
    AuditLog(a).write("one")
    prev, seq = resume_point(a.getvalue().splitlines())
    AuditLog(a, prev=prev, seq=seq).write("two")
    assert verify(a.getvalue().splitlines()) == 2
    lines = a.getvalue().splitlines()
    with pytest.raises(AuditError):
        resume_point(lines[1:])


def test_unfinished_ops_after_a_crash_are_reported():
    from terracotta_general.audit import unfinished

    log, buf = make()
    log.write("start", contract=1)
    log.write("mint", op="m1", state="started")
    log.write("mint", op="m1", state="done")
    log.write("revoke_token", op="r2", state="started")  # crash here
    log.write("start", contract=1)
    log.write("mint", op="m1", state="started")           # in flight at the end of the log
    got = [(r["op"], r["crashed"]) for r in unfinished(buf.getvalue().splitlines())]
    assert got == [("r2", True), ("m1", False)]
