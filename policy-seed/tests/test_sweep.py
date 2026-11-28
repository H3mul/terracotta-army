import base64
import copy
import importlib.util
import pathlib
import sys
import tempfile
import time
import unittest

HERE = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("sweep", HERE / "tools" / "sweep.py")
sweep = importlib.util.module_from_spec(spec)
sys.modules["sweep"] = sweep  # dataclasses looks its module up here
spec.loader.exec_module(sweep)

NOW = time.mktime(time.strptime("2026-11-25", "%Y-%m-%d"))
R = "H3mul/x"
CFG = {"name": R, "visibility": "public", "checks": ["check", "approve"], "environments": ["egress-approval"],
       "protect_tags": True}


def good() -> dict:
    """What GitHub says about a repo that meets the whole baseline."""
    return {
        f"/repos/{R}": (200, {"default_branch": "main", "visibility": "public", "private": False,
                              "allow_auto_merge": False, "allow_forking": True, "owner": {"login": "H3mul"},
                              "security_and_analysis": {"secret_scanning": {"status": "enabled"},
                                                        "secret_scanning_push_protection": {"status": "enabled"}}}),
        f"/repos/{R}/branches/main/protection": (200, {
            "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": True},
            "required_status_checks": {"contexts": ["check", "approve"], "checks": []},
            "enforce_admins": {"enabled": True}, "allow_force_pushes": {"enabled": False},
            "allow_deletions": {"enabled": False}, "required_conversation_resolution": {"enabled": True}}),
        f"/repos/{R}/actions/permissions": (200, {"enabled": True, "allowed_actions": "selected"}),
        f"/repos/{R}/actions/permissions/selected-actions": (200, {"github_owned_allowed": True, "verified_allowed": False,
                                                                   "patterns_allowed": []}),
        f"/repos/{R}/contents/.github/workflows": (404, {}),
        f"/repos/{R}/actions/permissions/workflow": (200, {"default_workflow_permissions": "read",
                                                           "can_approve_pull_request_reviews": False}),
        f"/repos/{R}/actions/permissions/fork-pr-contributor-approval": (200, {"approval_policy": "all_external_contributors"}),
        f"/repos/{R}/interaction-limits": (200, {"limit": "collaborators_only", "expires_at": "2027-03-01T00:00:00Z"}),
        f"/repos/{R}/collaborators?affiliation=direct&per_page=100": (200, [{"login": "H3mul"}]),
        f"/repos/{R}/keys": (200, []),
        f"/repos/{R}/hooks": (200, []),
        f"/repos/{R}/environments/egress-approval": (200, {"protection_rules": [
            {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"login": "H3mul"}}]}]}),
        f"/repos/{R}/rulesets?includes_parents=true": (200, [{"target": "tag", "enforcement": "active"}]),
    }


def run(table: dict, cfg: dict = CFG):
    return sweep.Sweep(lambda path: table.get(path, (404, {})), cfg, now=NOW).run()


def bad(results):
    return {(x.check, x.status) for x in results if x.status != "ok"}


class Baseline(unittest.TestCase):
    def test_a_fully_hardened_repo_has_nothing_to_report(self):
        self.assertEqual(bad(run(good())), set())

    def break_it(self, path, edit, expect):
        t = copy.deepcopy(good())
        _status, body = t[path]
        edit(body)
        got = bad(run(t))
        self.assertIn(expect, got, msg=f"{expect} not in {got}")
        return got

    def test_each_branch_protection_gap_is_named(self):
        p = f"/repos/{R}/branches/main/protection"
        self.break_it(p, lambda b: b.update(enforce_admins={"enabled": False}), ("administrators included", "fail"))
        self.break_it(p, lambda b: b.update(allow_force_pushes={"enabled": True}), ("no force push", "fail"))
        self.break_it(p, lambda b: b.update(allow_deletions={"enabled": True}), ("no deletion", "fail"))
        self.break_it(p, lambda b: b.update(required_pull_request_reviews=None), ("pull request required", "fail"))
        self.break_it(p, lambda b: b.update(required_status_checks={"contexts": ["check"], "checks": []}), ("required checks", "fail"))
        self.break_it(p, lambda b: b.update(required_conversation_resolution={"enabled": False}), ("conversations resolved", "warn"))

    def test_unprotected_branch_with_no_ruleset_fails_and_a_clean_ruleset_passes(self):
        t = good()
        t[f"/repos/{R}/branches/main/protection"] = (404, {"message": "Branch not protected"})
        self.assertIn(("branch protection", "fail"), bad(run(t)))
        t[f"/repos/{R}/rules/branches/main"] = (200, [{"type": "pull_request", "ruleset_id": 7},
                                                      {"type": "non_fast_forward", "ruleset_id": 7},
                                                      {"type": "deletion", "ruleset_id": 7}])
        t[f"/repos/{R}/rulesets/7"] = (200, {"bypass_actors": []})
        self.assertEqual(bad(run(t)), set())
        t[f"/repos/{R}/rulesets/7"] = (200, {"bypass_actors": [{"actor_type": "RepositoryRole"}]})
        self.assertIn(("branch ruleset", "fail"), bad(run(t)))

    def test_repo_settings(self):
        r = f"/repos/{R}"
        self.break_it(r, lambda b: b.update(allow_auto_merge=True), ("auto-merge off", "fail"))
        self.break_it(r, lambda b: b.update(visibility="private", private=True), ("visibility", "fail"))
        self.break_it(r, lambda b: b["security_and_analysis"]["secret_scanning_push_protection"].update(status="disabled"),
                      ("push protection", "fail"))

    def test_actions_settings(self):
        self.break_it(f"/repos/{R}/actions/permissions", lambda b: b.update(allowed_actions="all"), ("actions limited", "fail"))
        self.break_it(f"/repos/{R}/actions/permissions/workflow", lambda b: b.update(default_workflow_permissions="write"),
                      ("workflow token read-only", "fail"))
        self.break_it(f"/repos/{R}/actions/permissions/workflow", lambda b: b.update(can_approve_pull_request_reviews=True),
                      ("actions cannot approve PRs", "fail"))
        self.break_it(f"/repos/{R}/actions/permissions/fork-pr-contributor-approval",
                      lambda b: b.update(approval_policy="first_time_contributors"), ("fork PR runs need approval", "fail"))

    def workflow_files(self, **files):
        t = good()
        t[f"/repos/{R}/contents/.github/workflows"] = (200, [{"name": n, "path": f".github/workflows/{n}"} for n in files])
        for n, text in files.items():
            t[f"/repos/{R}/contents/.github/workflows/{n}"] = (200, {"content": base64.b64encode(text.encode()).decode()})
        return t

    RENOVATE = "jobs:\n  r:\n    steps:\n      - uses: actions/checkout@v4\n      - uses: renovatebot/github-action@" + "a" * 40 + "\n"

    def test_a_workflow_action_the_allowlist_blocks_is_caught_before_it_fails_at_run_time(self):
        t = self.workflow_files(**{"renovate.yaml": self.RENOVATE})
        got = bad(run(t))
        self.assertIn(("workflow actions allowed", "fail"), got)
        self.assertNotIn(("third-party actions pinned", "warn"), got)  # pinned by SHA
        # the policy allows it, and the repo's allowlist matches the policy
        cfg = {**CFG, "allowed_actions": ["renovatebot/github-action@*"]}
        t[f"/repos/{R}/actions/permissions/selected-actions"] = (200, {"github_owned_allowed": True, "verified_allowed": False,
                                                                       "patterns_allowed": ["renovatebot/github-action@*"]})
        self.assertEqual(bad(run(t, cfg)), set())

    def test_the_allowlist_must_equal_the_policy_both_ways(self):
        cfg = {**CFG, "allowed_actions": ["renovatebot/github-action@*"]}
        self.assertIn(("allowed action patterns", "fail"), bad(run(good(), cfg)))  # repo lacks it
        t = good()
        t[f"/repos/{R}/actions/permissions/selected-actions"] = (200, {"github_owned_allowed": True, "verified_allowed": False,
                                                                       "patterns_allowed": ["evil/*"]})
        self.assertIn(("allowed action patterns", "fail"), bad(run(t)))  # repo has more than the policy
        t[f"/repos/{R}/actions/permissions/selected-actions"] = (200, {"github_owned_allowed": True, "verified_allowed": True,
                                                                       "patterns_allowed": []})
        self.assertIn(("allowed actions", "fail"), bad(run(t)))

    def test_unpinned_third_party_actions_warn_and_fail_when_the_policy_pins(self):
        t = self.workflow_files(**{"ci.yml": "steps:\n  - uses: docker/build-push-action@v6\n  - uses: actions/checkout@v4\n"})
        cfg = {**CFG, "allowed_actions": ["docker/*@*"]}
        t[f"/repos/{R}/actions/permissions/selected-actions"] = (200, {"github_owned_allowed": True, "verified_allowed": False,
                                                                       "patterns_allowed": ["docker/*@*"]})
        self.assertEqual(bad(run(t, cfg)), {("third-party actions pinned", "warn")})
        t[f"/repos/{R}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "selected", "sha_pinning_required": True})
        got = bad(run(t, {**cfg, "pin_actions": True}))
        self.assertEqual(got, {("third-party actions pinned", "fail")})
        t[f"/repos/{R}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "selected"})
        self.assertIn(("SHA pinning enforced", "fail"), bad(run(t, {**cfg, "pin_actions": True})))

    def test_any_mode_still_warns_about_unpinned_actions_but_blocks_nothing(self):
        t = self.workflow_files(**{"ci.yml": "steps:\n  - uses: docker/build-push-action@v6\n"})
        t[f"/repos/{R}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "all"})
        got = bad(run(t, {**CFG, "actions": "any"}))
        self.assertEqual(got, {("actions limited", "warn"), ("third-party actions pinned", "warn")})

    def test_any_action_is_accepted_with_a_warning_when_the_policy_says_so(self):
        t = good()
        t[f"/repos/{R}/actions/permissions"] = (200, {"enabled": True, "allowed_actions": "all"})
        got = bad(run(t, {**CFG, "actions": "any"}))
        self.assertEqual(got, {("actions limited", "warn")})

    def test_only_members_open_prs(self):
        i = f"/repos/{R}/interaction-limits"
        self.break_it(i, lambda b: b.update(limit="existing_users"), ("only members open PRs", "fail"))
        t = good()
        t[i] = (200, {})
        self.assertIn(("only members open PRs", "fail"), bad(run(t)))
        t[i] = (200, {"limit": "collaborators_only", "expires_at": "2026-12-01T00:00:00Z"})
        self.assertIn(("interaction limit not expiring", "warn"), bad(run(t)))

    def test_access_surface(self):
        t = good()
        t[f"/repos/{R}/collaborators?affiliation=direct&per_page=100"] = (200, [{"login": "H3mul"}, {"login": "stranger"}])
        t[f"/repos/{R}/keys"] = (200, [{"title": "ci", "read_only": False}])
        t[f"/repos/{R}/hooks"] = (200, [{"id": 1}])
        self.assertEqual(bad(run(t)), {("collaborators", "fail"), ("deploy keys read-only", "fail"),
                                       ("no webhooks", "warn")})

    def test_the_administrator_is_the_owner_unless_the_policy_says_otherwise(self):
        t = good()
        t[f"/repos/{R}/collaborators?affiliation=direct&per_page=100"] = (200, [{"login": "h3mul"}, {"login": "Pal"}])
        self.assertEqual(bad(run(t)), {("collaborators", "fail")})  # case does not matter, a stranger does
        self.assertEqual(bad(run(t, {**CFG, "collaborators": ["pal"]})), set())  # an exception makes it fine
        self.assertIn(("environment egress-approval", "fail"), bad(run(t, {**CFG, "admin": "pal"})))

    def test_codeowners_missing_is_fine_and_a_file_may_only_name_known_owners(self):
        def file(text):
            return (200, {"content": base64.b64encode(text.encode()).decode()})

        p = f"/repos/{R}/contents/.github/CODEOWNERS"
        t = good()
        self.assertEqual(bad(run(t)), set())  # no file: the administrator owns everything
        t[p] = file("# who reviews what\n* @H3mul\n/tools/ @h3mul\n/docs/\n")
        self.assertEqual(bad(run(t)), set())
        t[p] = file("* @H3mul\n/general/ @H3mul @stranger\n/ci/ @org/security\n")
        self.assertEqual(bad(run(t)), {("CODEOWNERS", "fail")})
        self.assertEqual(bad(run(t, {**CFG, "owners": ["stranger", "@org/security"]})), set())
        t[p] = (200, {"content": "!!not base64!!"})
        self.assertEqual(bad(run(t)), {("CODEOWNERS", "unknown")})

    def test_environment_and_tags(self):
        t = good()
        t[f"/repos/{R}/environments/egress-approval"] = (200, {"protection_rules": [
            {"type": "required_reviewers", "reviewers": [{"type": "User", "reviewer": {"login": "someone-else"}}]}]})
        t[f"/repos/{R}/rulesets?includes_parents=true"] = (200, [])
        self.assertEqual(bad(run(t)), {("environment egress-approval", "fail"), ("release tags protected", "warn")})


class Fixes(unittest.TestCase):
    def test_a_repo_with_no_ci_checks_gets_a_note_not_a_useless_command(self):
        t = good()
        t[f"/repos/{R}/branches/main/protection"][1]["required_status_checks"] = None
        res = run(t, {k: v for k, v in CFG.items() if k != "checks"})
        warn = next(x for x in res if x.check == "required checks")
        self.assertEqual(warn.status, "warn")
        lines = sweep.fix_lines(res)
        self.assertTrue(any(x.startswith("# ") and "no CI check to require" in x for x in lines))
        self.assertFalse(any("branches/main/protection" in x for x in lines))  # nothing re-applied for nothing

    def test_a_missing_environment_is_a_failure_with_a_create_command(self):
        t = good()
        t[f"/repos/{R}/environments/egress-approval"] = (404, {"message": "Not Found"})
        t["/users/h3mul"] = (200, {"id": 4242})
        res = run(t)
        env = next(x for x in res if x.check == "environment egress-approval")
        self.assertEqual(env.status, "fail")
        self.assertIn("does not exist", env.detail)
        cmd = sweep.fix_lines(res)[0]
        self.assertIn(f"gh api -X PUT repos/{R}/environments/egress-approval", cmd)
        self.assertIn('"id": 4242', cmd)
        self.assertIn('"prevent_self_review": false', cmd)

    def test_environment_without_a_user_id_falls_back_to_a_comment(self):
        t = good()
        t[f"/repos/{R}/environments/egress-approval"] = (404, {})
        env = next(x for x in run(t) if x.check == "environment egress-approval")
        self.assertTrue(env.fix.startswith("create environment"))
        self.assertTrue(sweep.fix_lines([env])[0].startswith("# create environment"))

    def test_an_environment_error_other_than_missing_stays_unknown(self):
        t = good()
        t[f"/repos/{R}/environments/egress-approval"] = (500, {})
        self.assertIn(("environment egress-approval", "unknown"), bad(run(t)))


class Unknowns(unittest.TestCase):
    def test_a_token_that_cannot_see_settings_is_unknown_not_ok(self):
        t = {k: v for k, v in good().items() if k == f"/repos/{R}"}
        t[f"/repos/{R}"][1].pop("security_and_analysis")
        got = bad(run(t))
        self.assertIn(("branch protection", "unknown"), got)
        self.assertIn(("secret scanning", "unknown"), got)
        self.assertTrue(all(s != "ok" for _, s in got))

    def test_unreachable_repo_is_one_unknown(self):
        self.assertEqual(bad(run({})), {("repository", "unknown")})


class Auth(unittest.TestCase):
    class Gh:
        def __init__(self, token="", rc=0):
            self.token, self.rc, self.calls = token, rc, []

        def __call__(self, argv, **kw):
            self.calls.append(argv)
            return type("R", (), {"stdout": self.token + "\n", "returncode": self.rc})()

    def test_the_environment_wins_then_the_gh_login(self):
        gh = self.Gh("from-gh")
        self.assertEqual(sweep.resolve_token({"GITHUB_TOKEN": "env1", "GH_TOKEN": "env2"}, gh), "env1")
        self.assertEqual(sweep.resolve_token({"GH_TOKEN": "env2"}, gh), "env2")
        self.assertEqual(gh.calls, [])  # gh is not even asked
        self.assertEqual(sweep.resolve_token({}, gh), "from-gh")
        self.assertEqual(gh.calls, [["gh", "auth", "token"]])

    def test_no_login_and_no_gh_give_nothing(self):
        self.assertEqual(sweep.resolve_token({}, self.Gh("", rc=1)), "")

        def missing(*a, **k):
            raise FileNotFoundError

        self.assertEqual(sweep.resolve_token({}, missing), "")

    def test_fix_commands_run_as_the_gh_login_and_ui_steps_are_comments(self):
        res = [sweep.Result("r", "a", "fail", "", "gh api -X PATCH repos/r -F x=1"),
               sweep.Result("r", "b", "fail", "", "gh api -X PUT repos/r/p --input - <<'JSON'\n{}\nJSON"),
               sweep.Result("r", "c", "warn", "", "set reviewers in Settings, Environments, x"),
               sweep.Result("r", "d", "ok", "", "gh api never printed"),
               sweep.Result("r", "a2", "fail", "", "gh api -X PATCH repos/r -F x=1")]  # a duplicate
        lines = sweep.fix_lines(res)
        self.assertEqual(lines[0], "env -u GITHUB_TOKEN -u GH_TOKEN gh api -X PATCH repos/r -F x=1")
        self.assertTrue(lines[1].startswith("env -u GITHUB_TOKEN -u GH_TOKEN gh api -X PUT") and "<<'JSON'" in lines[1])
        self.assertEqual(lines[2], "# set reviewers in Settings, Environments, x")
        self.assertEqual(len(lines), 3)


class Report(unittest.TestCase):
    def test_exit_code_report_and_fix_commands(self):
        t = good()
        t[f"/repos/{R}/branches/main/protection"][1]["enforce_admins"] = {"enabled": False}
        pol = pathlib.Path(tempfile.mkdtemp()) / "p.toml"
        pol.write_text(f'[[repo]]\nname = "{R}"\nvisibility = "public"\nchecks = ["check", "approve"]\n'
                       'environments = ["egress-approval"]\nprotect_tags = true\n')
        import contextlib
        import io
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = sweep.main(["--policy", str(pol), "--fix-commands"], get=lambda p: t.get(p, (404, {})))
        text = out.getvalue()
        self.assertEqual(rc, 1)
        self.assertIn("**FAIL** administrators included", text)
        self.assertIn(f"env -u GITHUB_TOKEN -u GH_TOKEN gh api -X PUT repos/{R}/branches/main/protection", text)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sweep.main(["--policy", str(pol)], get=lambda p: good().get(p, (404, {}))), 0)

    def test_progress_goes_to_stderr_and_quiet_turns_it_off(self):
        import contextlib
        import io
        pol = pathlib.Path(tempfile.mkdtemp()) / "p.toml"
        pol.write_text(f'[[repo]]\nname = "{R}"\nchecks = ["check", "approve"]\n')
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sweep.main(["--policy", str(pol), "--fix-commands"], get=lambda p: good().get(p, (404, {})))
        self.assertIn("sweeping 1 repo(s)", err.getvalue())
        self.assertIn(f"[1/1] {R} .", err.getvalue())
        self.assertRegex(err.getvalue(), r"\d+ ok, \d+ warn, \d+ to fix \(\d+ API calls, [\d.]+s\)")
        self.assertNotIn("sweeping", out.getvalue())  # the report and commands stay clean
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            sweep.main(["--policy", str(pol), "--quiet"], get=lambda p: good().get(p, (404, {})))
        self.assertEqual(err.getvalue(), "")

    def test_a_policy_wide_administrator_overrides_the_repo_owner(self):
        import contextlib
        import io
        pol = pathlib.Path(tempfile.mkdtemp()) / "p.toml"
        pol.write_text(f'[admin]\nlogin = "pal"\n\n[[repo]]\nname = "{R}"\nchecks = ["check", "approve"]\n')
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rc = sweep.main(["--policy", str(pol)], get=lambda p: good().get(p, (404, {})))
        self.assertEqual(rc, 1)
        self.assertIn("unexpected direct collaborators: ['H3mul']", out.getvalue())

    def test_defaults_apply_to_every_repo_and_a_repo_overrides_them(self):
        with tempfile.TemporaryDirectory() as d:
            pol = pathlib.Path(d) / "p.toml"
            pol.write_text('[defaults]\nallowed_actions = ["a/b@*"]\nvisibility = "public"\n'
                           '[[repo]]\nname = "o/one"\n[[repo]]\nname = "o/two"\nvisibility = "private"\n')
            seen = []

            class Spy:
                def __init__(self, get, cfg, now=None):
                    seen.append(cfg)

                def run(self):
                    return []

            real, sweep.Sweep = sweep.Sweep, Spy
            try:
                sweep.main(["--policy", str(pol), "--quiet"], get=lambda p: (404, {}))
            finally:
                sweep.Sweep = real
        self.assertEqual([c["allowed_actions"] for c in seen], [["a/b@*"], ["a/b@*"]])
        self.assertEqual([c["visibility"] for c in seen], ["public", "private"])

    def test_no_token_still_writes_the_report_the_workflow_reads(self):
        with tempfile.TemporaryDirectory() as d:
            rep = pathlib.Path(d) / "r.md"
            real, sweep.resolve_token = sweep.resolve_token, lambda *a, **k: ""
            try:
                rc = sweep.main(["--report", str(rep), "--quiet"])
            finally:
                sweep.resolve_token = real
            self.assertEqual(rc, 2)
            self.assertIn("HARDENING_READ_TOKEN", rep.read_text())

    def test_the_shipped_policy_parses_and_names_valid_repos(self):
        import tomllib
        repos = tomllib.loads((HERE / "hardening" / "critical.toml").read_text())["repo"]
        self.assertTrue(repos)
        for r in repos:
            self.assertRegex(r["name"], r"^[\w.-]+/[\w.-]+$")


if __name__ == "__main__":
    unittest.main()
