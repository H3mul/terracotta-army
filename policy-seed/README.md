# ta-policy

Reviewed data that decides what the Terracotta Army workspace may do. Today it holds one thing, the
**workspace egress allowlist**; profiles, routes and workflows join it later (see `ta-policy-repo`).

## Egress

The workspace pod can only reach the hosts in `egress/workspace.toml` (plus DNS and the broker).
Flux applies `generated/workspace-egress.yaml`, a Cilium policy rendered from that file by
`tools/egress.py render`; CI fails if the two disagree.

When the agent meets a blocked host it asks for it:

    ws egress request HOST --reason "why"

That clones this repo, adds the host with `tools/egress.py add`, pushes a branch `egress/<host>`
and opens a PR. Pushing needs a write grant, which only you can give (phone approval):
`terracotta-general grant write <owner>/ta-policy 15m`. The agent cannot merge: CI runs the base
branch's tools on the PR files, comments a permission diff (wildcards, plain HTTP and domains
anyone can publish to are flagged), and the `approve` job waits for you to press
**Review deployments** on the `egress-approval` environment. Merge after that; Flux picks it up
within minutes.

## One-time setup (the repo owner)

1. Create this repo public (branch protection is not available for private repos on the free plan;
   nothing here is secret) and push this content.
2. Settings, Environments, new `egress-approval`: required reviewers = you; leave **Prevent
   self-review** off (the PR shows you as author, because the agent works with your token).
3. Settings, Branches, protect `main`: require a pull request (0 approvals; you cannot approve
   your own), require the status checks `check` and `approve`, and include administrators, so the
   agent's token cannot push `main` or merge before you approve.
4. Install the writer App on this repo, and add it to the broker policy (`write.allow`).
5. Point Flux at it (`cluster/terracotta-army-egress` in the homelab repo).

## Local checks

    python3 -m unittest discover -s tests
    python3 tools/egress.py check
    python3 tools/egress.py add crates.io --reason "Rust crates"
