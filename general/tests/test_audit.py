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
