import os
import pathlib
import subprocess
import sys

import pytest

BIN = pathlib.Path(__file__).parents[1] / "bin"
CLEAN_PATH = "/usr/bin:/bin"


def tool(*args, cwd=None, env=None):
    return subprocess.run([sys.executable, str(BIN / "ws-tool"), *args], capture_output=True, text=True,
                          cwd=cwd, check=False, env={"PATH": CLEAN_PATH, **(env or {})})


@pytest.mark.parametrize("files,expect", [
    ({"mise.toml": ""}, "mise\tmise exec --"),
    ({".tool-versions": ""}, "mise\tmise exec --"),
    ({"mise.toml": "", "devbox.json": "{}", "flake.nix": ""}, "mise\tmise exec --"),  # priority order
    ({}, "none"),
])
def test_detect_follows_the_priority_list(tmp_path, files, expect):
    for f, c in files.items():
        (tmp_path / f).write_text(c)
    r = tool("detect", "-C", str(tmp_path))
    assert r.returncode == 0 and r.stdout.strip() == expect


@pytest.mark.parametrize("f", ["devbox.json", "flake.nix"])
def test_devbox_and_nix_are_reported_unavailable_not_half_run(tmp_path, f):
    (tmp_path / f).write_text("{}")
    assert tool("detect", "-C", str(tmp_path)).returncode == 3
    r = tool("run", "-C", str(tmp_path), "--", "true")
    assert r.returncode == 3 and "not available in this workspace yet" in r.stderr


def test_run_with_no_toolchain_runs_the_command_directly(tmp_path):
    r = tool("run", "-C", str(tmp_path), "--", "pwd")
    assert r.returncode == 0 and r.stdout.strip() == str(tmp_path)


def git_repo(path):
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    return path


def test_bootstrap_writes_minimal_mise_toml_and_keeps_git_clean(tmp_path):
    git_repo(tmp_path)
    (tmp_path / "package.json").write_text('{"engines": {"node": ">=20.11"}}')
    (tmp_path / "pyproject.toml").write_text('[project]\nrequires-python = ">=3.11"\n')
    (tmp_path / "go.mod").write_text("module x\n\ngo 1.22.1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "package.json", "pyproject.toml", "go.mod"], check=True)
    r = tool("bootstrap", "-C", str(tmp_path))
    assert r.returncode == 0, r.stderr
    assert (tmp_path / "mise.toml").read_text() == '[tools]\ngo = "1.22"\nnode = "20.11"\npython = "3.11"\n'
    status = subprocess.run(["git", "-C", str(tmp_path), "status", "--porcelain"], capture_output=True,
                            text=True, check=True).stdout
    assert "mise.toml" not in status  # excluded via .git/info/exclude
    again = tool("bootstrap", "-C", str(tmp_path))
    assert "already declared: mise" in again.stdout
    assert (tmp_path / ".git/info/exclude").read_text().count("mise.toml") == 1


def test_bootstrap_does_not_touch_a_project_that_already_declares_a_toolchain(tmp_path):
    (tmp_path / "devbox.json").write_text("{}")
    (tmp_path / "package.json").write_text("{}")
    r = tool("bootstrap", "-C", str(tmp_path))
    assert "already declared: devbox" in r.stdout and not (tmp_path / "mise.toml").exists()


def test_bootstrap_with_unknown_project_writes_nothing(tmp_path):
    assert "nothing to write" in tool("bootstrap", "-C", str(tmp_path)).stdout
    assert not (tmp_path / "mise.toml").exists()


def guard(name, *args, env=None, tmp_path):
    guard_dir = tmp_path / "guard"
    guard_dir.mkdir(exist_ok=True)
    link = guard_dir / name
    if not link.exists():
        link.symlink_to(BIN / "ws-guard")
    e = {"PATH": f"{guard_dir}:{CLEAN_PATH}", "WS_GUARD_DIR": str(guard_dir), **(env or {})}
    return subprocess.run([str(link), *args], capture_output=True, text=True, env=e, check=False)


@pytest.mark.parametrize("name", ["apt", "apt-get", "dpkg", "sudo"])
def test_system_package_managers_are_refused_with_guidance(tmp_path, name):
    r = guard(name, "install", "x", tmp_path=tmp_path)
    assert r.returncode == 126 and "ws-tool bootstrap" in r.stderr


def test_pip_needs_a_virtualenv(tmp_path):
    assert guard("pip", "install", "x", tmp_path=tmp_path).returncode == 126
    r = guard("pip", "--version", env={"VIRTUAL_ENV": "/tmp/v"}, tmp_path=tmp_path)
    assert r.returncode != 126  # delegated to the real pip (present or not)


@pytest.mark.parametrize("args", [["install", "-g", "x"], ["i", "--global", "x"], ["i", "--location=global", "x"],
                                  ["i", "--location", "global", "x"]])
def test_global_npm_is_refused(tmp_path, args):
    assert guard("npm", *args, tmp_path=tmp_path).returncode == 126


def test_local_npm_is_delegated(tmp_path):
    r = guard("npm", "--version", tmp_path=tmp_path)
    assert r.returncode != 126 and os.environ  # real npm, or "not found" in this env, never a refusal
