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
        f"/repos/{R}/actions/permissions/workflow": (200, {"default_workflow_permissions": "read",
                                                           "can_approve_pull_request_reviews": False}),
        f"/repos/{R}/actions/permissions/fork-pr-contributor-approval": (200, {"approval_policy": "all_external_contributors"}),
        f"/repos/{R}/interaction-limits": (200, {"limit": "collaborators_only", "expires_at": "2027-03-01T00:00:00Z"}),
        f"/repos/{R}/collaborators?affiliation=direct&per_page=100": (200, [{"login": "H3mul"}]),
        f"/repos/{R}/keys": (200, []),
        f"/repos/{R}/hooks": (200, []),
        f"/repos/{R}/contents/.github/CODEOWNERS": (200, {}),
        f"/repos/{R}/environments/egress-approval": (200, {"protection_rules": [
            {"type": "required_reviewers", "reviewers": [{"type": "User"}]}]}),
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
        t[f"/repos/{R}/contents/.github/CODEOWNERS"] = (404, {})
        self.assertEqual(bad(run(t)), {("collaborators", "fail"), ("deploy keys read-only", "fail"),
                                       ("no webhooks", "warn"), ("CODEOWNERS", "warn")})

    def test_environment_and_tags(self):
        t = good()
        t[f"/repos/{R}/environments/egress-approval"] = (200, {"protection_rules": []})
        t[f"/repos/{R}/rulesets?includes_parents=true"] = (200, [])
        self.assertEqual(bad(run(t)), {("environment egress-approval", "fail"), ("release tags protected", "warn")})


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
        self.assertIn(f"gh api -X PUT repos/{R}/branches/main/protection", text)
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(sweep.main(["--policy", str(pol)], get=lambda p: good().get(p, (404, {}))), 0)

    def test_the_shipped_policy_parses_and_names_valid_repos(self):
        import tomllib
        repos = tomllib.loads((HERE / "hardening" / "critical.toml").read_text())["repo"]
        self.assertTrue(repos)
        for r in repos:
            self.assertRegex(r["name"], r"^[\w.-]+/[\w.-]+$")


if __name__ == "__main__":
    unittest.main()
