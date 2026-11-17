import pathlib

import pytest
from typer.testing import CliRunner

from terracotta_general import CONTRACT_VERSION
from terracotta_general.cli import app
from terracotta_general.repo import parse_repo

runner = CliRunner()


def test_contract_version_matches_file():
    root = pathlib.Path(__file__).resolve().parents[2]
    assert int((root / "contract" / "VERSION").read_text()) == CONTRACT_VERSION


@pytest.mark.parametrize("bad", ["", "a", "a/b/c", "a/b.git", "-a/b", "a/..", "a b/c"])
def test_parse_repo_rejects(bad):
    with pytest.raises(ValueError):
        parse_repo(bad)


def test_parse_repo_accepts():
    assert parse_repo("octo-org/my.repo_1") == "octo-org/my.repo_1"


def test_stub_commands_exit_2_and_validate_repo():
    assert runner.invoke(app, ["grant", "write", "octo/repo", "30m"]).exit_code == 2
    assert runner.invoke(app, ["grant", "write", "not-a-repo"]).exit_code == 2  # usage error
    r = runner.invoke(app, ["check", "a/b/c"])
    assert r.exit_code != 0 and "not an owner/repo" in r.output
