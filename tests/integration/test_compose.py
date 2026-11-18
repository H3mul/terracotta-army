"""Container-level scenarios (ta-repo-layout 3.2, minus write until ta-general section 3).

Run: uv run --project general pytest tests/integration -v   (needs docker; builds the images)
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import uuid

import pytest

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE.parents[1] / "general" / "tests"))
from fake_github import new_keypair  # noqa: E402

pytestmark = pytest.mark.skipif(not shutil.which("docker"), reason="docker not available")

POLICY = """
read:
  standing: {allow: ["octo/mine"], deny: ["octo/secret"]}
  adhoc: {allow: ["octo/*"], max_ttl: 1h}
"""


def run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


@pytest.fixture(scope="module")
def env(tmp_path_factory):
    d = tmp_path_factory.mktemp("it")
    priv, pub = new_keypair()
    (d / "reader.pem").write_text(priv)
    (d / "reader.pub").write_text(pub)
    (d / "policy.yaml").write_text(POLICY)
    (d / "broker-token").write_text("broker-token")
    (d / "sandbox-token").write_text("sandbox-token")
    run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=github.com",
         "-addext", "subjectAltName=DNS:github.com", "-keyout", str(d / "tls.key"), "-out", str(d / "tls.crt")],
        check=True)
    run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", str(d / "operator_key")], check=True)
    shutil.copy(d / "operator_key.pub", d / "authorized_keys")
    e = {**os.environ, "TG_IT_DIR": str(d), "COMPOSE_PROJECT_NAME": f"tg-it-{uuid.uuid4().hex[:6]}"}
    compose = ["docker", "compose", "-f", str(HERE / "compose.yaml")]
    up = run([*compose, "up", "-d", "--build", "--wait", "--wait-timeout", "120"], env=e)
    if up.returncode:
        pytest.fail(up.stderr[-2000:])
    import time
    time.sleep(3)  # sshd has no healthcheck
    yield compose, e, d
    run([*compose, "down", "-v", "--rmi", "local"], env=e)


class Harness:
    def __init__(self, compose, e):
        self.compose, self.e = compose, e

    def exec(self, svc, *args):
        return run([*self.compose, "exec", "-T", svc, *args], env=self.e)

    def op(self, *args):
        """An operator command over SSH, as from the phone."""
        r = self.exec("operator", "ssh", "-i", "/key", "-o", "StrictHostKeyChecking=no",
                      "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                      "-p", "2222", "tg@sshd", *args)
        return r.returncode, r.stdout + r.stderr

    def ws_ssh(self, *args):
        """An SSH session into the workspace as the agent user, as from the phone."""
        r = self.exec("operator", "ssh", "-i", "/key", "-o", "StrictHostKeyChecking=no",
                      "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR",
                      "-p", "2222", "agent@sandbox", *args)
        return r.returncode, r.stdout + r.stderr

    def cred(self, repo, token="sandbox-token", contract="1", username=""):
        body = json.dumps({"host": "github.com", "path": f"{repo}.git", "username": username})
        r = self.exec("sandbox", "curl", "-s", "-w", "\n%{http_code}", "-X", "POST",
                      "-H", f"Authorization: Bearer {token}", "-H", f"X-Contract-Version: {contract}",
                      "-d", body, "http://broker:8080/v1/credential")
        text, _, code = r.stdout.rpartition("\n")
        return int(code), json.loads(text) if text else {}

    def sh(self, script):
        """A shell snippet inside the workspace, as the agent user."""
        return self.exec("sandbox", "sh", "-c", script)

    def state(self):
        r = self.exec("sandbox", "curl", "-s", "http://stub:8000/_state")
        return json.loads(r.stdout)


@pytest.fixture(scope="module")
def h(env):
    return Harness(env[0], env[1])


def test_01_nothing_is_served_before_the_policy_is_approved(h):
    code, body = h.cred("octo/mine")
    assert code == 403 and "not readable" in body["hint"]
    rc, out = h.op("policy", "show")
    assert rc == 0 and "+ read.standing.allow: octo/mine" in out
    digest = out.split("policy approve ")[1].split()[0]
    rc, out = h.op("policy", "approve", digest)
    assert rc == 0 and "is active" in out


def test_02_standing_read_is_served_with_a_narrow_token(h):
    import time
    for _ in range(20):  # the refresh runs in the background right after approval
        code, body = h.cred("octo/mine")
        if code == 200:
            break
        time.sleep(0.5)
    assert code == 200 and body["username"] == "x-access-token" and body["password"].startswith("ghs_")
    narrow = [t for t in h.state()["tokens"] if t["repos"] == ["mine"] and not t["revoked"]]
    assert narrow and narrow[0]["perms"] == {"contents": "read", "metadata": "read"}


def test_03_unlisted_and_denied_repos_get_hints_not_tokens(h):
    code, body = h.cred("octo/other")
    assert code == 403 and "terracotta-general grant read octo/other" in body["hint"]
    code, body = h.cred("octo/secret")
    assert code == 403 and "denied by pattern" in body["hint"] and "password" not in body


def test_04_sandbox_identity_and_contract_are_enforced(h):
    assert h.cred("octo/mine", token="intruder-token")[0] == 403
    assert h.cred("octo/mine", token="nonsense")[0] == 401
    assert h.cred("octo/mine", contract="0")[0] == 426


def test_05_writer_username_is_not_served_yet(h):
    code, body = h.cred("octo/mine", username="writer")
    assert code == 403 and "write refused" in body["hint"]


def test_06_adhoc_grant_serves_then_revoke_kills_the_token(h):
    rc, out = h.op("grant", "read", "octo/other", "10m")
    assert rc == 0 and "granted read on octo/other for 10m" in out
    code, body = h.cred("octo/other")
    assert code == 200
    live = h.state()["live"]
    rc, out = h.op("revoke", "octo/other")
    assert rc == 0 and "revoked 1" in out
    assert h.cred("octo/other")[0] == 403
    assert h.state()["live"] == live - 1  # revoked at GitHub, not just forgotten


def test_07_grant_refusals_over_ssh(h):
    assert h.op("grant", "read", "octo/secret")[0] != 0
    assert h.op("grant", "read", "stranger/x")[0] != 0


def test_07a_real_git_clone_uses_the_helper_and_standing_read(h):
    r = h.sh("ws clone octo/mine && cat /workspace/dev/mine/README.md")
    assert r.returncode == 0 and "octo/mine" in r.stdout, r.stderr
    r = h.sh("cd /workspace/dev/mine && git fetch origin && git ls-remote origin main")
    assert r.returncode == 0, r.stderr


def test_07b_clone_of_unlisted_repo_ends_in_the_operator_command_then_works_once_granted(h):
    r = h.sh("ws clone octo/other")
    assert r.returncode != 0 and "terracotta-general grant read octo/other" in r.stderr, r.stderr
    assert "ghs_" not in r.stderr and "Password" not in r.stderr  # no prompt, no token
    assert h.op("grant", "read", "octo/other", "10m")[0] == 0
    r = h.sh("ws clone octo/other && cat /workspace/dev/other/README.md")
    assert r.returncode == 0 and "octo/other" in r.stdout, r.stderr
    assert h.op("revoke", "octo/other")[0] == 0
    r = h.sh("cd /workspace/dev/other && git fetch origin")
    assert r.returncode != 0 and "grant read octo/other" in r.stderr


def test_07c_denied_repo_cannot_be_cloned_and_push_is_refused_with_a_hint(h):
    r = h.sh("ws clone octo/secret")
    assert r.returncode != 0 and "denied by pattern" in r.stderr
    r = h.sh("cd /workspace/dev/mine && git -c user.name=a -c user.email=a@a commit -q --allow-empty -m x "
             "&& git push origin main")
    assert r.returncode != 0 and "write refused" in r.stderr, r.stderr


def test_07d_no_token_is_left_on_the_workspace_disk(h):
    r = h.sh("grep -rIl ghs_ /workspace /home/agent /tmp 2>/dev/null; true")
    assert r.stdout.strip() == ""
    assert "x-access-token" not in h.sh("cat /workspace/dev/mine/.git/config").stdout


def test_08_check_reports_branch_protection(h):
    h.exec("sandbox", "curl", "-s", "-X", "POST", "-d", '["octo/mine"]', "http://stub:8000/_protect")
    rc, out = h.op("check", "octo/mine")
    assert rc == 0 and "main is protected" in out
    assert "main is NOT protected" in h.op("check", "octo/other")[1]


def test_09_operator_ssh_runs_only_the_forced_command(h):
    rc, out = h.op("id")
    assert rc != 0 and "uid=" not in out
    rc, out = h.op("status; id")
    assert "uid=" not in out


def test_10_sandbox_has_no_path_to_admin_surface(h):
    assert h.exec("sandbox", "ls", "/run/terracotta").returncode != 0
    r = h.exec("sandbox", "curl", "-s", "-m", "3", "http://broker:8080/admin/status")
    assert r.stdout.strip() in ("", '{"error"') or "grants" not in r.stdout  # not served on TCP
    assert h.exec("sandbox", "curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}",
                  "http://broker:8080/admin/status").stdout == "404"


def test_11_emergency_stop_and_resume(h):
    rc, out = h.op("stop")
    assert rc == 0 and "suspended 1 installation" in out
    assert h.state()["suspended"] == [1] and h.state()["live"] == 0
    assert h.cred("octo/mine")[0] == 503
    r = h.sh("ws clone octo/mine during-stop")
    assert r.returncode != 0 and "emergency stop" in r.stderr
    assert "EMERGENCY STOP" in h.op("status")[1]
    rc, out = h.op("resume")
    assert rc == 0 and h.state()["suspended"] == []
    import time
    for _ in range(20):
        if h.cred("octo/mine")[0] == 200:
            break
        time.sleep(0.5)
    else:
        pytest.fail("standing read did not come back after resume")


def test_12_stop_survives_a_broker_restart(h, env):
    compose, e, _ = env
    h.op("stop")
    run([*compose, "restart", "broker"], env=e)
    import time
    time.sleep(3)
    assert h.cred("octo/mine")[0] == 503  # the flag is persisted in the state volume
    h.op("resume")


def test_13_audit_chain_verifies_and_holds_no_credentials(h):
    r = h.exec("broker", "terracotta-general", "log", "--verify")
    assert r.returncode == 0 and "chain ok" in r.stdout, r.stdout + r.stderr
    log = h.exec("broker", "cat", "/var/lib/terracotta/audit.log").stdout
    assert "ghs_" not in log and "sandbox-token" not in log
    events = {json.loads(line)["event"] for line in log.splitlines()}
    assert {"grant", "revoke", "served", "denied", "refused", "stop", "resume", "policy"} <= events


def wait_for(fn, what, tries=40):
    import time
    for _ in range(tries):
        if fn():
            return
        time.sleep(0.5)
    pytest.fail(f"timed out waiting for {what}")


def test_14_ssh_session_has_git_helper_and_broker_settings(h):
    wait_for(lambda: h.ws_ssh("true")[0] == 0, "workspace sshd")
    rc, out = h.ws_ssh("ws clone octo/mine via-ssh && cat /workspace/dev/via-ssh/README.md")
    assert rc == 0 and "octo/mine" in out, out  # TG_BROKER etc. reached the SSH session
    rc, out = h.ws_ssh("ws clone octo/secret nope")
    assert rc != 0 and "denied by pattern" in out


def test_15_workspace_is_unprivileged(h):
    assert h.ws_ssh("id -u")[1].strip() == "1000"
    assert h.ws_ssh("sudo -n true")[0] != 0
    assert h.ws_ssh("touch /etc/x")[0] != 0
    assert h.ws_ssh("apt-get install -y cowsay")[0] != 0
    assert h.ws_ssh("ls /var/run/secrets/terracotta/token /run/terracotta")[0] != 0  # no broker admin


def test_16_only_authorized_keys_log_in(h):
    r = h.exec("operator", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", "/tmp/other")
    assert r.returncode == 0
    r = h.exec("operator", "ssh", "-i", "/tmp/other", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
               "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-p", "2222", "agent@sandbox", "true")
    assert r.returncode != 0
    r = h.exec("operator", "ssh", "-i", "/key", "-o", "StrictHostKeyChecking=no", "-o", "BatchMode=yes",
               "-o", "UserKnownHostsFile=/dev/null", "-o", "LogLevel=ERROR", "-p", "2222", "root@sandbox", "true")
    assert r.returncode != 0


def test_17_supervisor_restarts_a_killed_sshd_and_reports_health(h):
    assert h.exec("sandbox", "ws-supervisor", "--health").returncode == 0
    assert h.exec("sandbox", "sh", "-c", "kill $(cat /tmp/sshd.pid)").returncode == 0
    wait_for(lambda: h.ws_ssh("true")[0] == 0, "sshd to come back")
    assert h.exec("sandbox", "ws-supervisor", "--health").returncode == 0


def test_18_host_key_and_home_survive_a_restart(h, env):
    compose, e, _ = env
    scan = lambda: h.exec("operator", "ssh-keyscan", "-p", "2222", "-t", "ed25519", "sandbox").stdout.split()[-1]  # noqa: E731
    wait_for(lambda: scan().startswith("AAAA"), "host key")
    before = scan()
    h.ws_ssh("echo kept > /home/agent/marker")
    run([*compose, "restart", "sandbox"], env=e)
    wait_for(lambda: h.ws_ssh("true")[0] == 0, "sshd after restart")
    assert scan() == before  # same host identity: the operator's known_hosts stays valid
    assert h.ws_ssh("cat /home/agent/marker")[1].strip() == "kept"


def test_19_refuses_to_start_without_authorized_keys(env):
    compose, e, _ = env
    r = run([*compose, "run", "--rm", "--no-deps", "-T", "-v", "/dev/null:/etc/terracotta-workspace/authorized_keys:ro",
             "sandbox"], env=e, timeout=60)
    assert r.returncode == 1 and "refusing to start" in r.stdout + r.stderr


def test_20_agent_rules_are_in_place_and_global_installs_are_refused(h):
    rc, out = h.ws_ssh("cat /workspace/dev/via-ssh/../../CLAUDE.md")
    assert rc == 0 and "Tooling for a project: use this priority list" in out
    assert h.ws_ssh("sh -c 'echo x >> /workspace/AGENTS.md'")[0] != 0  # the rules are not agent-editable
    for cmd in ("apt-get install -y cowsay", "sudo id", "npm install -g left-pad", "pip install requests"):
        rc, out = h.ws_ssh(cmd)
        assert rc == 126 and "ws-tool bootstrap" in out, (cmd, out)


def test_21_toolchain_step_in(h):
    rc, out = h.ws_ssh("cd /workspace/dev/via-ssh && ws-tool detect")
    assert rc == 0 and out.strip() == "none"
    rc, out = h.ws_ssh("cd /workspace/dev/via-ssh && echo '{\"engines\":{\"node\":\">=20\"}}' > package.json "
                       "&& ws-tool bootstrap && ws-tool detect && cat mise.toml && git status --porcelain")
    assert rc == 0 and 'node = "20"' in out and "mise\tmise exec --" in out, out
    status = h.ws_ssh("cd /workspace/dev/via-ssh && git status --porcelain")[1]
    assert "mise.toml" not in status and "package.json" in status  # generated file stays out of git
    h.ws_ssh("cd /workspace/dev/via-ssh && rm -f mise.toml package.json")
    rc, out = h.ws_ssh("cd /workspace/dev/via-ssh && echo '{}' > devbox.json && ws-tool run -- true; echo $?")
    assert "not available in this workspace yet" in out and out.startswith("3")
    h.ws_ssh("cd /workspace/dev/via-ssh && rm -f devbox.json")
