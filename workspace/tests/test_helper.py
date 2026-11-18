import http.server
import json
import pathlib
import subprocess
import sys
import threading

import pytest

BIN = pathlib.Path(__file__).parents[1] / "bin"
ANSWERS: dict = {}
SEEN: list = []


class Fake(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        SEEN.append((self.headers["authorization"], self.headers["x-contract-version"], body))
        code, out = ANSWERS["next"]
        data = json.dumps(out).encode()
        self.send_response(code)
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_):
        pass


@pytest.fixture
def broker(tmp_path):
    srv = http.server.HTTPServer(("127.0.0.1", 0), Fake)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    (tmp_path / "token").write_text("tok\n")
    (tmp_path / "contract").write_text("1\n")
    SEEN.clear()
    yield srv, {"TG_BROKER": f"http://127.0.0.1:{srv.server_port}", "TG_TOKEN_FILE": str(tmp_path / "token"),
                "TG_CONTRACT_FILE": str(tmp_path / "contract"), "PATH": "/usr/bin:/bin"}
    srv.shutdown()


def helper(env, stdin, op="get"):
    return subprocess.run([sys.executable, str(BIN / "git-credential-terracotta"), op],
                          input=stdin, capture_output=True, text=True, env=env, check=False)


GET = "protocol=https\nhost=github.com\npath=octo/mine.git\nusername=writer\n\n"


def test_success_prints_credentials_and_sends_identity(broker):
    _, env = broker
    ANSWERS["next"] = (200, {"username": "x-access-token", "password": "ghs_abc", "expires_at": 123})
    r = helper(env, GET)
    assert r.stdout.splitlines() == ["username=x-access-token", "password=ghs_abc", "password_expiry_utc=123"]
    assert SEEN == [("Bearer tok", "1", {"host": "github.com", "path": "octo/mine.git", "username": "writer"})]


@pytest.mark.parametrize("code,body,expect", [
    (403, {"hint": "terracotta-general grant read octo/mine"}, "terracotta-general grant read octo/mine"),
    (503, {"hint": "emergency stop is active"}, "emergency stop"),
    (401, {}, "did not accept this pod's identity"),
    (426, {}, "update the workspace image"),
    (500, {}, "unexpected answer (500)"),
])
def test_denials_print_the_hint_and_no_credentials(broker, code, body, expect):
    _, env = broker
    ANSWERS["next"] = (code, body)
    r = helper(env, GET)
    assert r.stdout == "" and expect in r.stderr and r.returncode == 0


def test_other_hosts_store_and_erase_are_ignored(broker):
    _, env = broker
    assert helper(env, "protocol=https\nhost=example.com\npath=a/b\n\n").stdout == ""
    assert helper(env, GET, op="store").stdout == "" and helper(env, GET, op="erase").stdout == ""
    assert SEEN == []


def test_unreachable_broker_and_missing_token_fail_closed(broker):
    _, env = broker
    r = helper({**env, "TG_BROKER": "http://127.0.0.1:1"}, GET)
    assert r.stdout == "" and "broker unreachable" in r.stderr
    r = helper({**env, "TG_TOKEN_FILE": "/nonexistent"}, GET)
    assert r.stdout == "" and "cannot read /nonexistent" in r.stderr


@pytest.mark.parametrize("arg", ["--upload-pack=x", "a/b/c", "../x", "owner/..", "-x/y", ""])
def test_ws_clone_refuses_odd_repo_names(arg, tmp_path):
    r = subprocess.run([sys.executable, str(BIN / "ws"), "clone", arg], capture_output=True, text=True, check=False,
                       env={"WS_ROOT": str(tmp_path), "PATH": "/usr/bin:/bin"})
    assert r.returncode == 2 and not list(tmp_path.iterdir())
