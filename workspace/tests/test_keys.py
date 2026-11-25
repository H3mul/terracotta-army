import http.server
import importlib.machinery
import importlib.util
import pathlib
import subprocess
import threading

import pytest

BIN = pathlib.Path(__file__).parents[1] / "bin"


def load():
    loader = importlib.machinery.SourceFileLoader("ws_supervisor", str(BIN / "ws-supervisor"))
    spec = importlib.util.spec_from_loader("ws_supervisor", loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


def new_key(tmp_path, name):
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", name, "-f", str(tmp_path / name)], check=True)
    return (tmp_path / f"{name}.pub").read_text().strip()


@pytest.fixture
def github():
    """A tiny github.com: serves /<login>.keys from a dict; `redirect` logins get a 302."""
    served: dict[str, str] = {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            login = self.path.removeprefix("/").removesuffix(".keys")
            if login == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:1/x.keys")
            elif login in served:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(served[login].encode())
                return
            else:
                self.send_response(404)
            self.end_headers()

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield served, f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def test_keys_are_written_with_fingerprints_and_comments_dropped(tmp_path, github):
    served, base = github
    k1, k2 = new_key(tmp_path, "phone"), new_key(tmp_path, "laptop")
    served["octo"] = f"{k1}\nnot a key\n{k2}\n"
    ws = load()
    out = tmp_path / "ak"
    prints = ws.refresh_github_keys(["octo"], out, base)
    assert len(prints) == 2 and all(p.startswith("SHA256:") for p in prints)
    assert out.read_text().splitlines() == [" ".join(k1.split()[:2]), " ".join(k2.split()[:2])]
    assert "phone" not in out.read_text() and oct(out.stat().st_mode & 0o777) == "0o644"


@pytest.mark.parametrize("how", ["missing", "empty", "redirect"])
def test_a_failed_refresh_leaves_the_previous_file(tmp_path, github, how):
    served, base = github
    served["octo"] = new_key(tmp_path, "a") + "\n"
    ws = load()
    out = tmp_path / "ak"
    ws.refresh_github_keys(["octo"], out, base)
    before = out.read_text()
    if how == "missing":
        del served["octo"]
        users = ["octo"]
    elif how == "empty":
        served["octo"] = "nothing useful\n"
        users = ["octo"]
    else:
        users = ["redirect"]
    with pytest.raises(Exception):  # noqa: B017 - URLError, HTTPError or ValueError, all handled by the caller
        ws.refresh_github_keys(users, out, base)
    assert out.read_text() == before


def test_only_plain_logins_are_fetched(tmp_path, github):
    _, base = github
    ws = load()
    for bad in ("../x", "a/b", "-x", "x y"):
        with pytest.raises(ValueError):
            ws.refresh_github_keys([bad], tmp_path / "ak", base)
