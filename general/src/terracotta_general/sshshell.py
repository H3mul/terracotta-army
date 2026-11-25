"""Forced-command entry for the operator's SSH session.

`ssh <broker> grant write o/r 30m` runs `terracotta-general ssh-shell` with the command in
SSH_ORIGINAL_COMMAND. It is split with shlex (never a shell) and only operator subcommands
are dispatched; with no command, a small prompt loop (easier to type on a phone).
"""

from __future__ import annotations

import os
import shlex
import sys
from collections.abc import Callable

import click
import typer

ALLOWED = {"status", "check", "grant", "revoke", "log", "setup", "policy", "keys", "stop", "resume"}
HELP = "commands: " + ", ".join(sorted(ALLOWED)) + "  (help, exit)"


def run_argv(argv: list[str], dispatch: Callable[[list[str]], None]) -> int:
    """Dispatch one operator command. Returns an exit code; never raises for user errors."""
    if not argv:
        return 0
    if argv[0] not in ALLOWED:
        click.echo(f"not an operator command: {argv[0]!r}. {HELP}", err=True)
        return 2
    try:
        dispatch(argv)
    except click.exceptions.Exit as e:
        return int(e.exit_code)
    except typer.Exit as e:
        return int(e.exit_code)
    except click.ClickException as e:
        e.show()
        return e.exit_code
    return 0


def run_line(line: str, dispatch: Callable[[list[str]], None]) -> int:
    try:
        argv = shlex.split(line)
    except ValueError as e:
        click.echo(f"cannot parse: {e}", err=True)
        return 2
    return run_argv(argv, dispatch)


def main(dispatch: Callable[[list[str]], None], env=os.environ, stdin=sys.stdin) -> int:
    original = env.get("SSH_ORIGINAL_COMMAND", "").strip()
    if original:
        return run_line(original, dispatch)
    click.echo(HELP)
    code = 0
    while True:
        click.echo("terracotta> ", nl=False)
        line = stdin.readline()
        if not line or line.strip() in ("exit", "quit"):
            return code
        if line.strip() == "help":
            click.echo(HELP)
            continue
        code = run_line(line, dispatch)
