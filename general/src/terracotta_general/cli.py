"""The operator CLI: thin commands over the daemon's admin socket (reached over SSH)."""

import json
import os
import sys
import time
from typing import Annotated

import httpx
import typer

from terracotta_general.audit import AuditError, unfinished, verify
from terracotta_general.policy import parse_ttl
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


def admin_client() -> httpx.Client:
    sock = os.environ.get("TG_ADMIN_SOCKET", "/run/terracotta/admin.sock")
    return httpx.Client(transport=httpx.HTTPTransport(uds=sock), base_url="http://broker", timeout=30.0)


def call(method: str, path: str, **kw) -> dict:
    """Talk to the daemon; any failure is a one-line message and exit 1."""
    try:
        r = admin_client().request(method, path, **kw)
    except httpx.HTTPError as e:
        typer.echo(f"broker not reachable: {e.__class__.__name__}", err=True)
        raise typer.Exit(1) from None
    out = r.json()
    if r.status_code >= 400:
        typer.echo(f"refused ({r.status_code}): {out.get('error', out)}", err=True)
        raise typer.Exit(1)
    return out


@app.command()
def serve() -> None:
    """Run the daemon (configured by TG_* environment variables)."""
    from terracotta_general.daemon import main

    main()


@app.command()
def status() -> None:
    """Active grants and the standing read set."""
    out = call("GET", "/admin/status")
    if out["stopped"]:
        typer.echo("EMERGENCY STOP ACTIVE (terracotta-general resume to lift)")
    typer.echo(f"standing read: {len(out['standing'])} repos")
    for r in out["standing"]:
        typer.echo(f"  {r}")
    typer.echo(f"active grants: {len(out['grants'])}")
    for g in out["grants"]:
        left = max(0, int(g["ends"] - time.time()))
        typer.echo(f"  {g['id']}  {g['level']:5}  {g['repo']}  {left // 60}m left")


@grant.command("read")
def grant_read(repo: Repo, ttl: Ttl = "") -> None:
    """Read a private repo outside the standing allowlist."""
    if ttl:
        try:
            parse_ttl(ttl)
        except ValueError as e:
            raise typer.BadParameter(str(e)) from e
    out = call("POST", "/admin/grant", json={"repo": repo, "level": "read", "ttl": ttl})
    typer.echo(f"granted read on {out['repo']} for {out['ttl'] // 60}m (request {out['id']})")


EXIT_DENIED, EXIT_EXPIRED = 3, 4
POLL = 2.0  # seconds between asking the daemon whether the phone approved


def write_flow(repo: str, ttl: str) -> None:
    """Start the device flow, show the code, wait for the daemon to report. Exits 0, 3 (denied), 4 (expired)."""
    out = call("POST", "/admin/grant", json={"repo": repo, "level": "write", "ttl": ttl})
    typer.echo(f"On your phone open {out['verification_uri']} and enter {out['user_code']}")
    typer.echo(f"(check that GitHub names the writer App; waiting up to {out['expires_in'] // 60} min)")
    end = time.time() + out["expires_in"] + 15
    while time.time() < end:
        st = call("GET", f"/admin/grant/{out['id']}")
        if st["state"] == "approved":
            typer.echo(f"granted write on {st['repo']} for {st['ttl'] // 60}m (request {st['id']})")
            return
        if st["state"] != "pending":
            why = st["reason"] or st["state"]
            typer.echo(f"not granted: {why}", err=True)
            raise typer.Exit({"device-denied": EXIT_DENIED, "device-expired": EXIT_EXPIRED}.get(why, 1))
        time.sleep(POLL)
    typer.echo("not granted: timed out waiting for the daemon", err=True)
    raise typer.Exit(EXIT_EXPIRED)


@grant.command("write")
def grant_write(repo: Repo, ttl: Ttl = "") -> None:
    """Device flow on your phone, then a write token for this one repo."""
    if ttl:
        try:
            parse_ttl(ttl)
        except ValueError as e:
            raise typer.BadParameter(str(e)) from e
    write_flow(repo, ttl)


@app.command()
def revoke(repo: Repo, level: str = typer.Argument("", help="read or write; empty = both")) -> None:
    """Revoke grants now."""
    out = call("POST", "/admin/revoke", json={"repo": repo, "level": level})
    typer.echo(f"revoked {out['revoked']} grant(s) on {repo}")


@app.command()
def check(repo: Repo) -> None:
    """Why this repo is allowed or denied."""
    out = call("GET", "/admin/check", params={"repo": repo})
    for k in ("standing", "read", "write"):
        typer.echo(f"{k:9} {out[k]}")
    typer.echo(f"protection {out['protection']}")
    for k, v in out.get("limits", {}).items():
        typer.echo(f"ad hoc {k}: {v}")
    typer.echo(f"standing token held: {out['standing_token']}")
    for a in out["active"]:
        typer.echo(f"active grant: {a['id']} ({a['level']})")


@app.command()
def setup(repo: Repo, write: bool = False) -> None:
    """Grant what is needed, then print the sandbox clone command."""
    out = call("GET", "/admin/check", params={"repo": repo})
    ok, active = out["allowed"], {a["level"] for a in out["active"]}
    if ok["standing"]:
        typer.echo(f"read: {repo} is on the standing allowlist")
    elif "read" in active:
        typer.echo(f"read: {repo} already has an active read grant")
    elif ok["read"]:
        r = call("POST", "/admin/grant", json={"repo": repo, "level": "read", "ttl": ""})
        typer.echo(f"read: granted for {r['ttl'] // 60}m (request {r['id']})")
    else:
        typer.echo(f"not readable: {out['read']}", err=True)
        raise typer.Exit(1)
    if write:
        if "write" in active:
            typer.echo(f"write: {repo} already has an active write grant")
        elif ok["write"]:
            write_flow(repo, "")
        else:
            typer.echo(f"write refused: {out['write']}", err=True)
            raise typer.Exit(1)
    typer.echo(f"\nin the sandbox: ws clone {repo}")


@app.command()
def log(
    since: str = "1h",
    check: bool = typer.Option(False, "--verify", help="Check the hash chain of the whole file"),
    file: str = typer.Option("", envvar="TG_AUDIT_FILE", help="Audit file (TG_AUDIT_FILE)"),
) -> None:
    """Recent grants, mints, uses, revokes (needs the audit file)."""
    if not file:
        typer.echo("no audit file: set TG_AUDIT_FILE or pass --file", err=True)
        raise typer.Exit(1)
    with open(file) as f:
        lines = f.read().splitlines()
    if check:
        try:
            typer.echo(f"chain ok: {verify(lines)} records")
            for r in unfinished(lines):
                where = "cut off by a crash" if r["crashed"] else "no outcome yet (in flight or crashed)"
                typer.echo(f"UNFINISHED {r['event']} op {r['op']} at {r['ts']}: {where}")
        except AuditError as e:
            typer.echo(f"CHAIN BROKEN: {e}", err=True)
            raise typer.Exit(1) from None
        return
    cutoff = time.time() - parse_ttl(since)
    for line in lines:
        rec = json.loads(line)
        if rec["ts"] >= cutoff:
            sys.stdout.write(line + "\n")


@policy.command("show")
def policy_show() -> None:
    """Plain-words diff of the proposed policy against the active one."""
    out = call("GET", "/admin/policy")
    typer.echo(f"active:   {out['active']}")
    if out["error"]:
        typer.echo(f"proposed policy is invalid: {out['error']}", err=True)
        raise typer.Exit(1)
    if out["proposed"] == out["active"]:
        typer.echo("proposed: same as active, nothing to approve")
        return
    typer.echo(f"proposed: {out['proposed']}")
    for line in out["changes"]:
        typer.echo(f"  {line}")
    typer.echo(f"\napprove with: terracotta-general policy approve {out['proposed']}")


@policy.command("approve")
def policy_approve(digest: str) -> None:
    """Activate the proposed policy with this hash."""
    out = call("POST", "/admin/policy/approve", json={"hash": digest})
    typer.echo(f"policy {out['active']} is active; revoked {out['revoked']} grant(s) it forbids")


@app.command()
def stop() -> None:
    """Emergency stop: revoke everything, suspend installations."""
    out = call("POST", "/admin/stop")
    typer.echo(f"stopped: revoked {out['revoked']} grant(s), suspended {out['suspended']} installation(s)")
    if out["errors"]:
        typer.echo(f"INCOMPLETE ({', '.join(out['errors'])}): serving is blocked here, run stop again", err=True)
        raise typer.Exit(1)


@app.command()
def resume() -> None:
    """Lift the emergency stop."""
    call("POST", "/admin/resume")
    typer.echo("resumed: installations unsuspended, standing read refreshing")


@app.command("ssh-shell", hidden=True)
def ssh_shell() -> None:
    """Forced command for operator SSH sessions (see sshshell)."""
    from terracotta_general import sshshell

    def dispatch(argv: list[str]) -> None:
        # standalone_mode=False returns an Exit's code instead of raising it
        code = typer.main.get_command(app).main(args=argv, prog_name="terracotta-general", standalone_mode=False)
        if isinstance(code, int) and code:
            raise typer.Exit(code)

    raise typer.Exit(sshshell.main(dispatch))
