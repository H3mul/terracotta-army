import asyncio

import httpx

from terracotta_general.auth import TokenReview

SA = "system:serviceaccount:ws:sandbox"


def review(tmp_path, handler):
    tok = tmp_path / "token"
    tok.write_text("broker-sa-token\n")
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return TokenReview("terracotta-general", "https://k", client, tok)


def run(c):
    return asyncio.run(c)


def test_valid_token(tmp_path):
    seen = {}

    def h(req: httpx.Request):
        seen["auth"] = req.headers["authorization"]
        seen["body"] = req.read()
        return httpx.Response(201, json={"status": {
            "authenticated": True, "audiences": ["terracotta-general"], "user": {"username": SA}}})

    assert run(review(tmp_path, h).identify("sandbox-token")) == SA
    assert seen["auth"] == "Bearer broker-sa-token"
    assert b"sandbox-token" in seen["body"] and b"terracotta-general" in seen["body"]


def test_rejections_fail_closed(tmp_path):
    cases = [
        httpx.Response(201, json={"status": {"authenticated": False}}),
        httpx.Response(201, json={"status": {"authenticated": True, "audiences": ["other"],
                                             "user": {"username": SA}}}),
        httpx.Response(403, json={}),
        httpx.Response(201, json={}),
    ]
    for resp in cases:
        assert run(review(tmp_path, lambda _r, resp=resp: resp).identify("t")) is None


def test_api_unreachable_fails_closed(tmp_path):
    def h(_r):
        raise httpx.ConnectError("down")

    assert run(review(tmp_path, h).identify("t")) is None


def test_missing_ca_does_not_break_startup_and_fails_closed(tmp_path):
    tr = TokenReview("a", ca_path=tmp_path / "nope", broker_token_path=tmp_path / "nope")
    assert run(tr.identify("t")) is None
