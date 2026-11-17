"""CLI skeleton. Every command is a stub until its task in ta-general lands."""

from typing import Annotated

import typer

from terracotta_general.repo import parse_repo

app = typer.Typer(no_args_is_help=True, add_completion=False, help="terracotta-general access broker")
grant = typer.Typer(no_args_is_help=True, help="Request time-boxed repo access")
policy = typer.Typer(no_args_is_help=True, help="Show and activate policy changes")
app.add_typer(grant, name="grant")
app.add_typer(policy, name="policy")


def repo_arg(value: str) -> str:
    try:
        return parse_repo(value)
    except ValueError as e:
        raise typer.BadParameter(str(e)) from e


Repo = Annotated[str, typer.Argument(parser=repo_arg, metavar="OWNER/REPO")]
Ttl = Annotated[str, typer.Argument(help="Duration such as 30m or 2h; policy default and cap apply")]


def todo(name: str) -> None:
    typer.echo(f"{name}: not implemented", err=True)
    raise typer.Exit(2)


@app.command()
def serve() -> None:
    """Run the daemon."""
    todo("serve")


@app.command()
def status() -> None:
    """Active grants, token expiries, policy summary."""
    todo("status")


@grant.command("read")
def grant_read(repo: Repo, ttl: Ttl = "") -> None:
    """Read a private repo outside the standing allowlist."""
    todo("grant read")


@grant.command("write")
def grant_write(repo: Repo, ttl: Ttl = "") -> None:
    """Device flow, then a scoped write token."""
    todo("grant write")


@app.command()
def revoke(repo: Repo, level: str = typer.Argument("", help="read or write; empty = both")) -> None:
    """Revoke grants now."""
    todo("revoke")


@app.command()
def check(repo: Repo) -> None:
    """Why this repo is allowed or denied."""
    todo("check")


@app.command()
def setup(repo: Repo, write: bool = False) -> None:
    """Grant as needed, then print the sandbox clone command."""
    todo("setup")


@app.command()
def log(since: str = "1h", verify: bool = False) -> None:
    """Recent grants, mints, uses, revokes."""
    todo("log")


@policy.command("show")
def policy_show() -> None:
    """Plain-words diff of the proposed policy against the active one."""
    todo("policy show")


@policy.command("approve")
def policy_approve(digest: str) -> None:
    """Activate the proposed policy with this hash."""
    todo("policy approve")


@app.command()
def stop() -> None:
    """Emergency stop: revoke everything, suspend installations."""
    todo("stop")


@app.command()
def resume() -> None:
    """Lift the emergency stop."""
    todo("resume")
