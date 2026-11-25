#!/usr/bin/env python3
"""The workspace egress allowlist: validate it, render the Cilium policy, add a host, diff two versions.

`egress/workspace.toml` is the only input. `generated/workspace-egress.yaml` (a CiliumNetworkPolicy,
written as JSON, which is valid YAML) is what Flux applies, and CI fails if it is not exactly what
`render` produces. Standard library only, so the workspace can run it too.

    egress.py validate | render | check
    egress.py add HOST --reason TEXT [--port 443] [--by NAME]
    egress.py diff BASE_ROOT HEAD_ROOT        # markdown for the PR comment
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
POLICY_NAME, NAMESPACE, SELECTOR = "workspace-egress-allowlist", "terracotta-army", "workspace"
ALLOWED_PORTS = {80, 443}
MAX_HOSTS = 200
LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")
BANNED_SUFFIXES = (".local", ".internal", ".lan", ".home", ".corp", ".svc", ".cluster.local", ".localhost")
# Hosts anyone can publish to or receive from: fine for downloads, but each is also a way out for data.
EXFIL_CAPABLE = (
    "github.io", "githubusercontent.com", "pastebin.com", "transfer.sh", "webhook.site", "requestbin.com",
    "ngrok.io", "ngrok-free.app", "trycloudflare.com", "workers.dev", "pages.dev", "herokuapp.com",
    "vercel.app", "netlify.app", "amazonaws.com", "storage.googleapis.com", "blob.core.windows.net",
    "discord.com", "discordapp.com", "slack.com", "telegram.org", "t.me", "gist.github.com",
)


class PolicyError(ValueError):
    pass


def valid_name(name: str) -> str:
    """The host, or `*.host` for any subdomain; raises PolicyError otherwise."""
    if not isinstance(name, str) or name != name.strip().lower():
        raise PolicyError(f"{name!r}: must be lower case with no spaces")
    base = name.removeprefix("*.")
    labels = base.split(".")
    if len(base) > 253 or len(labels) < 2 or not all(LABEL.fullmatch(x) for x in labels):
        raise PolicyError(f"{name!r}: not a host name")
    if re.fullmatch(r"[0-9.]+", base) or ":" in base:
        raise PolicyError(f"{name!r}: IP addresses are not allowed, name the host")
    if any(base == s[1:] or base.endswith(s) for s in BANNED_SUFFIXES):
        raise PolicyError(f"{name!r}: internal names are never allowed")
    if "*" in base:
        raise PolicyError(f"{name!r}: a wildcard is only allowed as the first label (*.example.com)")
    return name


def load(root: pathlib.Path = ROOT) -> list[dict]:
    try:
        data = tomllib.loads((root / "egress" / "workspace.toml").read_text())
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise PolicyError(f"egress/workspace.toml: {e}") from None
    if set(data) - {"host"}:
        raise PolicyError("egress/workspace.toml: only [[host]] tables are allowed")
    hosts = data.get("host", [])
    if len(hosts) > MAX_HOSTS:
        raise PolicyError(f"more than {MAX_HOSTS} hosts")
    seen: set[str] = set()
    out = []
    for h in hosts:
        if set(h) - {"name", "reason", "ports", "requested_by"}:
            raise PolicyError(f"{h.get('name')!r}: unknown keys {sorted(set(h) - {'name', 'reason', 'ports', 'requested_by'})}")
        name = valid_name(h.get("name"))
        if name in seen:
            raise PolicyError(f"{name!r}: listed twice")
        seen.add(name)
        reason = h.get("reason")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > 200 or "\n" in reason:
            raise PolicyError(f"{name!r}: reason is required (one line, up to 200 characters)")
        ports = h.get("ports", [443])
        if not isinstance(ports, list) or not ports or not set(ports) <= ALLOWED_PORTS:
            raise PolicyError(f"{name!r}: ports must be a non-empty subset of {sorted(ALLOWED_PORTS)}")
        out.append({"name": name, "reason": reason.strip(), "ports": sorted(set(ports)),
                    "requested_by": str(h.get("requested_by", ""))[:60]})
    return out


def render(hosts: list[dict]) -> str:
    by_ports: dict[tuple[int, ...], list[dict]] = {}
    for h in sorted(hosts, key=lambda x: x["name"]):
        by_ports.setdefault(tuple(h["ports"]), []).append(h)
    egress = [{
        "toFQDNs": [({"matchPattern": h["name"]} if h["name"].startswith("*.") else {"matchName": h["name"]})
                    for h in group],
        "toPorts": [{"ports": [{"port": str(p), "protocol": "TCP"} for p in ports]}],
    } for ports, group in sorted(by_ports.items())]
    policy = {
        "apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
        "metadata": {"name": POLICY_NAME, "namespace": NAMESPACE,
                     "annotations": {"terracotta-army/generated-from": "egress/workspace.toml; do not edit"}},
        "spec": {"endpointSelector": {"matchLabels": {"app.kubernetes.io/name": SELECTOR}}, "egress": egress},
    }
    if not egress:  # an empty egress list would mean "no rules"; deny nothing extra instead
        policy["spec"]["egress"] = [{"toFQDNs": [{"matchName": "invalid.invalid"}],
                                     "toPorts": [{"ports": [{"port": "443", "protocol": "TCP"}]}]}]
    return json.dumps(policy, indent=2) + "\n"


def dump_toml(hosts: list[dict]) -> str:
    def q(s: str) -> str:
        return json.dumps(s)  # a JSON string is a valid TOML basic string

    blocks = []
    for h in sorted(hosts, key=lambda x: x["name"]):
        lines = ["[[host]]", f"name = {q(h['name'])}", f"reason = {q(h['reason'])}"]
        if h["ports"] != [443]:
            lines.append(f"ports = [{', '.join(map(str, h['ports']))}]")
        if h.get("requested_by"):
            lines.append(f"requested_by = {q(h['requested_by'])}")
        blocks.append("\n".join(lines))
    return "# The workspace egress allowlist. Change it with a PR (see README); never edit generated/ by hand.\n\n" + "\n\n".join(blocks) + "\n"


def write(root: pathlib.Path, hosts: list[dict]) -> None:
    (root / "egress" / "workspace.toml").write_text(dump_toml(hosts))
    (root / "generated").mkdir(exist_ok=True)
    (root / "generated" / "workspace-egress.yaml").write_text(render(hosts))


def check(root: pathlib.Path = ROOT) -> None:
    hosts = load(root)
    try:
        current = (root / "generated" / "workspace-egress.yaml").read_text()
    except OSError:
        current = ""
    if current != render(hosts):
        raise PolicyError("generated/workspace-egress.yaml is not what `tools/egress.py render` produces from "
                          "egress/workspace.toml; run `tools/egress.py render` and commit the result")


def flags(h: dict) -> list[str]:
    out = []
    if h["name"].startswith("*."):
        out.append("wildcard: every subdomain")
    if 80 in h["ports"]:
        out.append("plain HTTP (port 80)")
    base = h["name"].removeprefix("*.")
    if any(base == d or base.endswith("." + d) for d in EXFIL_CAPABLE):
        out.append("anyone can publish to or receive from this domain: a way out for data")
    return out


def diff(base: pathlib.Path, head: pathlib.Path) -> str:
    old = {h["name"]: h for h in load(base)} if (base / "egress" / "workspace.toml").exists() else {}
    new = {h["name"]: h for h in load(head)}
    lines = ["### Workspace egress: permission diff", ""]
    added = [new[n] for n in sorted(new.keys() - old.keys())]
    removed = sorted(old.keys() - new.keys())
    changed = [new[n] for n in sorted(new.keys() & old.keys()) if new[n] != old[n]]
    if not (added or removed or changed):
        lines.append("No change to the allowlist.")
    for h in added:
        lines.append(f"- **opens** `{h['name']}` on {', '.join(map(str, h['ports']))}: {h['reason']}"
                     + (f" (requested by {h['requested_by']})" if h["requested_by"] else ""))
        lines += [f"  - :warning: {f}" for f in flags(h)]
    for h in changed:
        lines.append(f"- **changes** `{h['name']}`: ports {old[h['name']]['ports']} -> {h['ports']}, reason now: {h['reason']}")
        lines += [f"  - :warning: {f}" for f in flags(h)]
    lines += [f"- closes `{n}`" for n in removed]
    return "\n".join(lines) + "\n"


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "render", "check"):
        sub.add_parser(name)
    add = sub.add_parser("add")
    add.add_argument("host")
    add.add_argument("--reason", required=True)
    add.add_argument("--port", type=int, action="append")
    add.add_argument("--by", default="")
    d = sub.add_parser("diff")
    d.add_argument("base", type=pathlib.Path)
    d.add_argument("head", type=pathlib.Path)
    p.add_argument("--root", type=pathlib.Path, default=ROOT)
    a = p.parse_args(argv)
    try:
        if a.cmd == "validate":
            load(a.root)
            print(f"ok: {len(load(a.root))} hosts")
        elif a.cmd == "render":
            write(a.root, load(a.root))
        elif a.cmd == "check":
            check(a.root)
            print("ok")
        elif a.cmd == "add":
            hosts = load(a.root)
            name = valid_name(a.host.strip().lower())
            if name in {h["name"] for h in hosts}:
                print(f"{name} is already allowed")
                return 0
            hosts.append({"name": name, "reason": a.reason, "ports": sorted(set(a.port or [443])), "requested_by": a.by})
            tmp = a.root / "egress" / "workspace.toml"
            old = tmp.read_text()
            write(a.root, hosts)
            try:
                load(a.root)  # re-validate what was written
            except PolicyError:
                tmp.write_text(old)
                raise
        elif a.cmd == "diff":
            sys.stdout.write(diff(a.base, a.head))
    except PolicyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
