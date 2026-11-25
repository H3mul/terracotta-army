#!/usr/bin/env python3
"""Check the critical repositories against the hardening baseline (docs/hardening.md).

    sweep.py [--policy hardening/critical.toml] [--report report.md] [--json report.json]
             [--fix-commands]

The administrator (default: the repo owner; `[admin] login` in the policy overrides it) owns every
repo: a missing CODEOWNERS file is correct, and one that exists may name only the administrator and the
`owners` exceptions listed for that repo.

Auth: `GITHUB_TOKEN` (or `GH_TOKEN`) if set, which is what the daily workflow uses (a fine-grained
read-only token), otherwise your `gh` login (`gh auth token`), so a manual run needs nothing exported.
It only reads. Exit 0: every condition holds (warnings allowed). Exit 1: a condition fails,
or could not be checked ("unknown": the token cannot see that setting). `--fix-commands` prints the
`gh api` commands that would repair the failures, each one starting with `env -u GITHUB_TOKEN -u GH_TOKEN`
so it runs as your `gh` login even if a read-only token is exported in the shell (gh prefers the
environment over its login); settings with no API come out as `#` comments. Nothing here changes a repo. Standard library only.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import subprocess
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import asdict, dataclass

API = "https://api.github.com"
ROOT = pathlib.Path(__file__).resolve().parent.parent
RENEW_WARN_DAYS = 14

Getter = Callable[[str], tuple[int, object]]


@dataclass
class Result:
    repo: str
    check: str
    status: str  # ok | fail | warn | unknown
    detail: str = ""
    fix: str = ""


def resolve_token(env: dict[str, str] | None = None, run: Callable[..., object] = subprocess.run) -> str:
    """The environment's token, else the `gh` login's; "" if neither exists. Never printed."""
    env = os.environ if env is None else env
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        if env.get(name):
            return env[name]
    try:
        r = run(["gh", "auth", "token"], capture_output=True, text=True, check=False)
    except OSError:
        return ""
    return (r.stdout or "").strip() if getattr(r, "returncode", 1) == 0 else ""


def fix_lines(results: list[Result]) -> list[str]:
    """Copy-pasteable fixes: `gh api` commands run as the gh login, anything else as a comment."""
    out = []
    for fix in dict.fromkeys(x.fix for x in results if x.status in ("fail", "warn") and x.fix):
        if fix.startswith("gh api"):
            out.append("env -u GITHUB_TOKEN -u GH_TOKEN " + fix.replace("\ngh api", "\nenv -u GITHUB_TOKEN -u GH_TOKEN gh api"))
        else:
            out.append(f"# {fix}")
    return out


def http_get(token: str, base: str = API) -> Getter:
    def get(path: str) -> tuple[int, object]:
        req = urllib.request.Request(base + path, headers={
            "Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            try:
                return e.code, json.load(e)
            except ValueError:
                return e.code, {}
        except (urllib.error.URLError, OSError):
            return 0, {}

    return get


class Sweep:
    def __init__(self, get: Getter, cfg: dict, now: float | None = None):
        self.get, self.cfg, self.repo = get, cfg, cfg["name"]
        self.admin = ""  # set once the repo's owner is known
        self.now = now if now is not None else time.time()
        self.out: list[Result] = []
        self.info: dict = {}

    def add(self, check: str, ok: bool, detail: str = "", fix: str = "", level: str = "fail") -> None:
        self.out.append(Result(self.repo, check, "ok" if ok else level, detail, fix))

    def unknown(self, check: str, why: str) -> None:
        self.out.append(Result(self.repo, check, "unknown", why))

    def call(self, check: str, path: str) -> object | None:
        """The JSON body, or None after recording why this could not be read."""
        status, data = self.get(path)
        if status == 200:
            return data
        self.unknown(check, f"GET {path} gave {status}: the token needs Administration read on this repo"
                     if status in (403, 404) else f"GET {path} gave {status}")
        return None

    # --- the checks ----------------------------------------------------------------------------

    def run(self) -> list[Result]:
        r = self.repo
        info = self.call("repository", f"/repos/{r}")
        if not isinstance(info, dict):
            return self.out
        self.info = info
        self.admin = (self.cfg.get("admin") or (info.get("owner") or {}).get("login") or "").lower()
        branch = info.get("default_branch", "main")
        self.repo_flags(info)
        self.branch(branch)
        self.actions(info)
        self.access(info)
        for name in self.cfg.get("environments", []):
            self.environment(name)
        if self.cfg.get("protect_tags"):
            self.tags()
        return self.out

    def repo_flags(self, info: dict) -> None:
        want = self.cfg.get("visibility")
        if want:
            self.add("visibility", info.get("visibility") == want, f"is {info.get('visibility')}, expected {want}")
        self.add("auto-merge off", not info.get("allow_auto_merge"), "auto-merge is enabled",
                 f"gh api -X PATCH repos/{self.repo} -F allow_auto_merge=false")
        if info.get("private"):
            self.add("forking off", not info.get("allow_forking"), "private repo allows forking",
                     f"gh api -X PATCH repos/{self.repo} -F allow_forking=false", level="warn")
        sa = info.get("security_and_analysis")
        if sa is None:
            self.unknown("secret scanning", "security_and_analysis is hidden from this token")
        else:
            for key, label in (("secret_scanning", "secret scanning"), ("secret_scanning_push_protection", "push protection")):
                on = (sa.get(key) or {}).get("status") == "enabled"
                self.add(label, on, f"{label} is off",
                         f"gh api -X PATCH repos/{self.repo} -f 'security_and_analysis[{key}][status]=enabled'")

    def branch(self, branch: str) -> None:
        r, cfg = self.repo, self.cfg
        status, p = self.get(f"/repos/{r}/branches/{branch}/protection")
        want_checks = cfg.get("checks", [])
        body = {"required_status_checks": {"strict": True, "contexts": want_checks} if want_checks else None,
                "enforce_admins": True,
                "required_pull_request_reviews": {"required_approving_review_count": cfg.get("min_approvals", 0),
                                                  "dismiss_stale_reviews": True},
                "restrictions": None, "allow_force_pushes": False, "allow_deletions": False,
                "required_conversation_resolution": True}
        fix = (f"gh api -X PUT repos/{r}/branches/{branch}/protection --input - <<'JSON'\n"
               f"{json.dumps(body, indent=2)}\nJSON")
        if status in (403, 401) or status == 0:
            self.unknown("branch protection", f"GET protection gave {status}: the token needs Administration read")
            return
        if status == 404 and isinstance(p, dict) and "not protected" in str(p.get("message", "")).lower():
            if self.ruleset(branch):
                return
            self.add("branch protection", False, f"{branch} has no protection or ruleset", fix)
            return
        if status != 200 or not isinstance(p, dict):
            self.unknown("branch protection", f"GET protection gave {status}")
            return
        pr = p.get("required_pull_request_reviews")
        self.add("pull request required", pr is not None, "pushes straight to the branch are allowed", fix)
        if pr is not None:
            n = pr.get("required_approving_review_count", 0)
            self.add("approvals", n >= cfg.get("min_approvals", 0), f"{n} required, expected {cfg.get('min_approvals', 0)}", fix)
            self.add("stale reviews dismissed", bool(pr.get("dismiss_stale_reviews")), "an old approval survives new commits",
                     fix, level="warn")
        have = set((p.get("required_status_checks") or {}).get("contexts", [])) | {
            c.get("context") for c in (p.get("required_status_checks") or {}).get("checks", [])}
        if want_checks:
            self.add("required checks", set(want_checks) <= have, f"missing {sorted(set(want_checks) - have)}", fix)
        else:
            self.add("required checks", bool(have), "no status check is required", fix, level="warn")
        self.add("administrators included", bool((p.get("enforce_admins") or {}).get("enabled")),
                 "administrators (and the owner's tokens) can bypass the rules", fix)
        self.add("no force push", not (p.get("allow_force_pushes") or {}).get("enabled"), "force pushes are allowed", fix)
        self.add("no deletion", not (p.get("allow_deletions") or {}).get("enabled"), "the branch can be deleted", fix)
        self.add("conversations resolved", bool((p.get("required_conversation_resolution") or {}).get("enabled")),
                 "review conversations need not be resolved", fix, level="warn")

    def ruleset(self, branch: str) -> bool:
        """True if rulesets protect the branch well enough (and no one can bypass them)."""
        status, rules = self.get(f"/repos/{self.repo}/rules/branches/{branch}")
        if status != 200 or not isinstance(rules, list) or not rules:
            return False
        types = {x.get("type") for x in rules}
        missing = {"pull_request", "non_fast_forward", "deletion"} - types
        bypass = []
        for rid in {x.get("ruleset_id") for x in rules}:
            st, rs = self.get(f"/repos/{self.repo}/rulesets/{rid}")
            if st == 200 and isinstance(rs, dict):
                bypass += rs.get("bypass_actors") or []
        self.add("branch ruleset", not missing and not bypass,
                 (f"rules missing: {sorted(missing)}" if missing else "") + ("; bypass actors exist" if bypass else ""))
        return True

    def actions(self, info: dict) -> None:
        r, cfg = self.repo, self.cfg
        a = self.call("actions", f"/repos/{r}/actions/permissions")
        if isinstance(a, dict) and a.get("enabled"):
            allowed = a.get("allowed_actions")
            self.add("actions limited", allowed != "all" or cfg.get("actions") == "any",
                     "any third-party action may run", f"gh api -X PUT repos/{r}/actions/permissions -F enabled=true -f allowed_actions=selected\n"
                     f"gh api -X PUT repos/{r}/actions/permissions/selected-actions -F github_owned_allowed=true -F verified_allowed=false")
            if allowed == "all" and cfg.get("actions") == "any":
                self.out.append(Result(r, "actions limited", "warn", "any action may run (accepted in the policy); pin them by SHA"))
        w = self.call("actions workflow permissions", f"/repos/{r}/actions/permissions/workflow")
        if isinstance(w, dict):
            self.add("workflow token read-only", w.get("default_workflow_permissions") == "read",
                     "the default workflow token can write",
                     f"gh api -X PUT repos/{r}/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false")
            self.add("actions cannot approve PRs", not w.get("can_approve_pull_request_reviews"),
                     "workflows may approve pull requests",
                     f"gh api -X PUT repos/{r}/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false")
        if not info.get("private"):
            f = self.call("fork PR approval", f"/repos/{r}/actions/permissions/fork-pr-contributor-approval")
            if isinstance(f, dict):
                self.add("fork PR runs need approval", f.get("approval_policy") == "all_external_contributors",
                         f"policy is {f.get('approval_policy')}",
                         f"gh api -X PUT repos/{r}/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors")

    def access(self, info: dict) -> None:
        r, cfg = self.repo, self.cfg
        if not info.get("private"):
            want = cfg.get("interaction", "collaborators_only")
            status, lim = self.get(f"/repos/{r}/interaction-limits")
            if status == 200 and isinstance(lim, dict):
                have = lim.get("limit")
                self.add("only members open PRs", have == want, f"interaction limit is {have!r}, expected {want}",
                         f"gh api -X PUT repos/{r}/interaction-limits -f limit={want} -f expiry=six_months")
                if have == want and lim.get("expires_at"):
                    left = (time.mktime(time.strptime(lim["expires_at"], "%Y-%m-%dT%H:%M:%SZ")) - self.now) / 86400
                    self.add("interaction limit not expiring", left > RENEW_WARN_DAYS,
                             f"expires in {left:.0f} days (GitHub caps it at six months: renew it)",
                             f"gh api -X PUT repos/{r}/interaction-limits -f limit={want} -f expiry=six_months", level="warn")
            else:
                self.unknown("only members open PRs", f"GET interaction-limits gave {status}")
        c = self.call("collaborators", f"/repos/{r}/collaborators?affiliation=direct&per_page=100")
        if isinstance(c, list):
            allowed = {self.admin, *(x.lower() for x in cfg.get("collaborators", []))}
            extra = sorted(x["login"] for x in c if x["login"].lower() not in allowed)
            self.add("collaborators", not extra, f"unexpected direct collaborators: {extra}",
                     f"gh api -X DELETE repos/{r}/collaborators/<login>")
        keys = self.call("deploy keys", f"/repos/{r}/keys")
        if isinstance(keys, list):
            rw = [k.get("title") for k in keys if not k.get("read_only")]
            self.add("deploy keys read-only", not rw, f"writable deploy keys: {rw}", f"gh api -X DELETE repos/{r}/keys/<id>")
        hooks = self.call("webhooks", f"/repos/{r}/hooks")
        if isinstance(hooks, list):
            self.add("no webhooks", not hooks, f"{len(hooks)} webhook(s): check each is expected", level="warn")
        self.codeowners()

    def codeowners(self) -> None:
        """No file is fine: the administrator owns everything. A file may name only exceptions we know."""
        for path in (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS"):
            status, f = self.get(f"/repos/{self.repo}/contents/{path}")
            if status == 200 and isinstance(f, dict):
                break
        else:
            self.add("CODEOWNERS", True)
            return
        try:
            text = base64.b64decode(f.get("content", "")).decode()
        except (ValueError, UnicodeDecodeError):
            self.unknown("CODEOWNERS", "the file could not be read")
            return
        allowed = {self.admin, *(x.lower().lstrip("@") for x in self.cfg.get("owners", []))}
        named = {tok.lstrip("@").lower() for line in text.splitlines() if not line.strip().startswith("#")
                 for tok in line.split()[1:] if tok.startswith("@") or "@" in tok}
        stray = sorted(named - allowed)
        self.add("CODEOWNERS", not stray, f"owners outside the administrator and the listed exceptions: {stray}")

    def environment(self, name: str) -> None:
        env = self.call(f"environment {name}", f"/repos/{self.repo}/environments/{name}")
        if isinstance(env, dict):
            rules = [x for x in env.get("protection_rules", []) if x.get("type") == "required_reviewers"]
            people = {((x.get("reviewer") or {}).get("login") or "").lower()
                      for x in (rules[0].get("reviewers", []) if rules else []) if x.get("type") == "User"}
            self.add(f"environment {name}", self.admin in people,
                     f"the administrator ({self.admin}) is not a required reviewer",
                     f"set required reviewers in Settings, Environments, {name}")

    def tags(self) -> None:
        rs = self.call("tag ruleset", f"/repos/{self.repo}/rulesets?includes_parents=true")
        if isinstance(rs, list):
            ok = any(x.get("target") == "tag" and x.get("enforcement") == "active" for x in rs)
            self.add("release tags protected", ok, "no active tag ruleset: anyone with write can create a release tag",
                     "Settings, Rules, Rulesets: new tag ruleset for v*, restrict creations, updates and deletions", level="warn")


def report(results: list[Result]) -> str:
    icon = {"ok": "ok", "warn": "WARN", "fail": "FAIL", "unknown": "UNKNOWN"}
    lines = ["# Hardening sweep", ""]
    for repo in dict.fromkeys(x.repo for x in results):
        rs = [x for x in results if x.repo == repo]
        bad = [x for x in rs if x.status in ("fail", "unknown")]
        lines.append(f"## {repo}: " + ("ok" if not bad else f"{len(bad)} to fix"))
        for x in rs:
            if x.status != "ok":
                lines.append(f"- **{icon[x.status]}** {x.check}: {x.detail}")
        if not [x for x in rs if x.status != "ok"]:
            lines.append("- every condition holds")
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str], get: Getter | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--policy", type=pathlib.Path, default=ROOT / "hardening" / "critical.toml")
    p.add_argument("--report", type=pathlib.Path)
    p.add_argument("--json", type=pathlib.Path)
    p.add_argument("--fix-commands", action="store_true")
    a = p.parse_args(argv)
    data = tomllib.loads(a.policy.read_text())
    default_admin = (data.get("admin") or {}).get("login", "")
    cfgs = [{"admin": default_admin, **c} if default_admin else c for c in data.get("repo", [])]
    if get is None:
        token = resolve_token()
        if not token:
            print("no token: set GITHUB_TOKEN, or log in with `gh auth login`", file=sys.stderr)
            return 2
        get = http_get(token)
    results: list[Result] = []
    for cfg in cfgs:
        results += Sweep(get, cfg).run()
    text = report(results)
    print(text)
    if a.report:
        a.report.write_text(text)
    if a.json:
        a.json.write_text(json.dumps([asdict(x) for x in results], indent=2))
    if a.fix_commands:
        for line in fix_lines(results):
            print(line)
    return 1 if any(x.status in ("fail", "unknown") for x in results) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
