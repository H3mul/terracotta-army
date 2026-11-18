# terracotta-army

A self-hosted, Kubernetes-backed remote workspace for CLI coding agents, with an
external access broker so the agent sandbox never holds GitHub write credentials.

| Directory | What |
|---|---|
| `general/` | `terracotta-general`: the access broker (Python). One entrypoint of the same name: `serve` runs the daemon, other subcommands are the operator CLI. |
| `workspace/` | `terracotta-workspace`: the sandbox image (sshd, agent CLIs, credential helper). |
| `contract/` | The versioned sandbox-to-broker API. |
| `tests/integration/` | Docker Compose scenarios that run both images against a stub GitHub API and TokenReview (no Kubernetes needed). |
| `tests/hygiene/` | Checks that nothing secret or environment-specific is tracked, and the contract version agrees. |
| `docs/` | Operator runbook and release process. |
| `examples/flux/` | Reference manifests. Not a chart; copy and adapt. |

Both images are built here and released under one tag. Runs on
[kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox).

Status: the read path works end to end in the Compose harness (standing and ad hoc read, approval-gated
policy, emergency stop, audit chain, operator SSH, workspace image with git helper). The write tier
(`grant write`) is not built yet; it waits on a GitHub token-scoping spike. Not yet deployed anywhere.

No secrets, hostnames, App ids or personal identifiers belong in this repository.
License: MIT.
