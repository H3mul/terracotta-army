# Hardening baseline for critical repositories

A repository is **critical** when whoever can change it can widen what an agent may do: the policy
repo (the egress allowlist and, later, profiles and workflows), the engine repo that builds the
images the pods run, and the Flux repo that defines the cluster. They are listed in
`hardening/critical.toml`. `tools/sweep.py` checks each condition below every day; a failure opens
or updates the issue **Hardening drift** here, and the scheduled run fails so GitHub notifies you.

The sweep only reads. `python3 tools/sweep.py --fix-commands` prints the `gh api` commands that would
repair what it found; you run them.

## Conditions

The **administrator** is the repo owner unless `[admin] login` in `hardening/critical.toml` says otherwise. In the cluster it is the first operator in `TG_OPERATOR_GITHUB_USERS` (Flux `TA_ADMIN`), and the broker's `status` prints it.

| Check | Required | Why |
|---|---|---|
| Pull request required on the default branch | yes | nothing reaches `main` without a PR you can see |
| Required status checks | the repo's CI checks (`checks` in the policy) | an unreviewed or red PR cannot merge |
| Administrators included (`enforce_admins`) | yes | the agent's token acts as you, an administrator: without this it bypasses every rule |
| No force push, no branch deletion | yes | history on `main` cannot be rewritten or removed |
| Stale approvals dismissed, conversations resolved | warn | a late push cannot ride an old approval |
| Branch rulesets instead of classic protection | accepted if they require a PR, block force pushes and deletion, and have **no bypass actors** | same guarantees |
| Auto-merge off | yes | a PR must not merge itself the moment checks pass |
| Secret scanning and push protection on | yes | a pasted token is stopped before it is public |
| Actions limited to selected actions | yes (`actions = "any"` is accepted with a warning) | a third-party action runs with the repo's secrets |
| Workflow token read-only by default; workflows cannot approve PRs | yes | a compromised step cannot write or approve |
| Fork PR workflows need approval (public repos) | `all_external_contributors` | strangers cannot run code in your CI |
| **Only members open PRs** (public repos) | interaction limit `collaborators_only` | strangers cannot open PRs, issues or comments; GitHub caps the limit at six months, so the sweep warns two weeks before it lapses and you renew it |
| Direct collaborators | the administrator only (or `collaborators` in the policy) | write access is the whole game |
| Deploy keys | read-only | a writable key bypasses the token model |
| Webhooks | none (warn) | each one is a data path out |
| CODEOWNERS | optional: the administrator owns everything; a file may name only the administrator and the repo's `owners` exceptions | enforcement never depended on the file (code-owner review is not required, since the agent's token acts as the administrator) |
| Environments named in the policy | exist and have the administrator as a required reviewer | the approval gates are real |
| Release tags protected (`protect_tags`) | an active tag ruleset (warn) | the images the pods run come from release tags |
| Visibility | as stated in the policy | a private repo made public by mistake is caught |

Not covered, on purpose: who is a member of the account, two-factor authentication on it (not
visible through the API for a personal account), and App installations (check them by hand in
Settings, Integrations).

## Applying it once

Do not rely on this list alone: run `GITHUB_TOKEN=<token> python3 tools/sweep.py --fix-commands` first, it
prints only what is missing. As the repo owner (`r` is each critical repo in turn):

    # repo flags and secret scanning
    gh api -X PATCH repos/$r -F allow_auto_merge=false \
      -f 'security_and_analysis[secret_scanning][status]=enabled' \
      -f 'security_and_analysis[secret_scanning_push_protection][status]=enabled'

    # Actions: read-only token, no PR approval, fork PRs need approval
    gh api -X PUT repos/$r/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
    gh api -X PUT repos/$r/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors

    # only members open PRs (GitHub expires it after six months: renew)
    gh api -X PUT repos/$r/interaction-limits -f limit=collaborators_only -f expiry=six_months

    # repos with `actions = "selected"` (ta-policy, homelab-k3s-flux); check they use no third-party action first
    gh api -X PUT repos/$r/actions/permissions -F enabled=true -f allowed_actions=selected
    gh api -X PUT repos/$r/actions/permissions/selected-actions -F github_owned_allowed=true -F verified_allowed=false

    # branch protection (replaces what is there); contexts are the CI job names
    gh api -X PUT repos/$r/branches/main/protection --input - <<'JSON'
    { "required_status_checks": {"strict": true, "contexts": ["check", "approve"]},
      "enforce_admins": true,
      "required_pull_request_reviews": {"required_approving_review_count": 0, "dismiss_stale_reviews": true},
      "restrictions": null, "allow_force_pushes": false, "allow_deletions": false,
      "required_conversation_resolution": true }
    JSON

Contexts per repo: ta-policy `["check","approve"]` (they appear in GitHub only after the workflow has run
once, so open a throwaway PR first); terracotta-army `["general","secrets","integration"]`;
homelab-k3s-flux none yet (`"required_status_checks": null`).

**Protection with administrators included blocks direct pushes to `main`, yours too.** Turn it on for
terracotta-army and the Flux repo once the work in flight is pushed; after that every change is a PR with
green checks.

Only in the web UI: the `egress-approval` and `hardening-read` environments here, a `v*` tag ruleset on
terracotta-army (restrict creation, update and deletion), the writer App installed on this repo. Not
visible to the sweep at all: two-factor on the account and which Apps are installed.

## Running the sweep

`.github/workflows/hardening.yml` runs it daily with a fine-grained token that can only read:

1. Create a fine-grained personal access token (resource owner: you; repositories: the critical ones
   only; expiry: up to a year, put the renewal in your calendar). Repository permissions, all **read**:
   Administration, Contents, Environments, Webhooks, Actions, Metadata.
2. Create the environment `hardening-read` here, restrict **Deployment branches** to `main`, and add
   the token as the **environment** secret `HARDENING_READ_TOKEN`. An environment secret, not a
   repository secret, so only workflows on `main` can read it.
3. Run the workflow once by hand (Actions, hardening-sweep, Run workflow). A check reported as
   **UNKNOWN** names the permission the token still lacks.

Limits to know: GitHub turns off scheduled workflows in a public repo after 60 days without any
activity, which would silence the nag (egress PRs and merges count as activity); and a token that
expires makes every check UNKNOWN, which fails the run and nags too.
