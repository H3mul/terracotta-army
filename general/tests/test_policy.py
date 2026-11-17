import pytest

from terracotta_general.policy import Policy, parse_ttl

YAML = """
read:
  standing:
    allow: ["Octo/*", "other/one"]
    deny: ["octo/secrets-*"]
  adhoc:
    allow: ["octo/*", "friend/*"]
    max_ttl: 4h
write:
  allow: ["octo/*"]
  deny: ["octo/prod"]
  max_ttl: 2h
  default_ttl: 30m
"""


@pytest.fixture
def pol():
    return Policy.load(YAML)


@pytest.mark.parametrize("v,s", [("90s", 90), ("30m", 1800), ("2h", 7200)])
def test_ttl(v, s):
    assert parse_ttl(v) == s


@pytest.mark.parametrize("v", ["", "0m", "1d", "1h30m", "-5m", "m30", "1.5h"])
def test_ttl_rejects(v):
    with pytest.raises(ValueError):
        parse_ttl(v)


def test_standing_case_insensitive_and_deny_wins(pol):
    assert pol.decide("OCTO/app", "standing").allowed
    assert not pol.decide("octo/secrets-x", "standing").allowed
    assert "secrets-*" in pol.decide("octo/secrets-x", "standing").reason
    assert not pol.decide("nobody/x", "standing").allowed


def test_adhoc_only_for_non_standing(pol):
    assert not pol.decide("octo/app", "read").allowed  # already standing
    assert pol.decide("friend/x", "read").allowed
    # standing deny also blocks ad hoc: a denied repo cannot be granted around the policy
    assert not pol.decide("octo/secrets-x", "read").allowed


def test_write_rules_and_ttl(pol):
    assert pol.decide("octo/app", "write").allowed
    assert not pol.decide("octo/prod", "write").allowed
    assert pol.clamp_ttl("write", None, "octo/app") == 1800
    assert pol.clamp_ttl("write", "10h", "octo/app") == 7200
    assert pol.clamp_ttl("write", "5m", "octo/app") == 300
    with pytest.raises(PermissionError):
        pol.clamp_ttl("write", "5m", "octo/prod")


def test_unknown_keys_and_bad_ttls_rejected():
    with pytest.raises(ValueError):
        Policy.load("read: {standing: {allw: []}}")
    with pytest.raises(ValueError):
        Policy.load("write: {default_ttl: 3h, max_ttl: 2h}")
    assert Policy.load("").decide("a/b", "standing").allowed is False  # empty = deny all
