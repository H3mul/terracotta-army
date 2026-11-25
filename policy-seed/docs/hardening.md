# Hardening baseline for critical repositories

A repository is **critical** when whoever can change it can widen what an agent may do: the policy
repo (the egress allowlist and, later, profiles and workflows), the engine repo that builds the
images the pods run, and the Flux repo that defines the cluster. They are listed in
`hardening/critical.toml`. `tools/sweep.py` checks each condition below every day; a failure opens
or updates the issue **Hardening drift** here, and the scheduled run fails so GitHub notifies you.

The sweep only reads. `python3 tools/sweep.py --fix-commands` prints the `gh api` commands that would
repair what it found; you run them.

## Conditions

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
| Direct collaborators | the owner only (or `collaborators` in the policy) | write access is the whole game |
| Deploy keys | read-only | a writable key bypasses the token model |
| Webhooks | none (warn) | each one is a data path out |
| CODEOWNERS file | present (warn) | review requests go to a person |
| Environments named in the policy | exist and have required reviewers | the approval gates are real |
| Release tags protected (`protect_tags`) | an active tag ruleset (warn) | the images the pods run come from release tags |
| Visibility | as stated in the policy | a private repo made public by mistake is caught |

Not covered, on purpose: who is a member of the account, two-factor authentication on it (not
visible through the API for a personal account), and App installations (check them by hand in
Settings, Integrations).

## Applying it once

For each critical repo, with `gh` logged in as the owner:

    python3 tools/sweep.py --fix-commands        # the commands for whatever is missing

Settings that have no API (environments' reviewers, the **Require approval for all outside
collaborators** option on older plans) are named in the report; set them in the web UI.

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
