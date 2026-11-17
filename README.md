# terracotta-army

A self-hosted, Kubernetes-backed remote workspace for CLI coding agents, with an
external access broker so the agent sandbox never holds GitHub write credentials.

| Directory | What |
|---|---|
| `general/` | `terracotta-general`: the access broker (Python). One entrypoint of the same name: `serve` runs the daemon, other subcommands are the operator CLI. |
| `workspace/` | `terracotta-workspace`: the sandbox image (sshd, agent CLIs, credential helper). |
| `contract/` | The versioned sandbox-to-broker API. |
| `tests/integration/` | kind/k3d scenarios that run both images against a stub GitHub API. |
| `examples/flux/` | Reference manifests. Not a chart; copy and adapt. |

Both images are built here and released under one tag. Runs on
[kubernetes-sigs/agent-sandbox](https://github.com/kubernetes-sigs/agent-sandbox).

Status: early scaffold. Nothing here is functional yet.

No secrets, hostnames, App ids or personal identifiers belong in this repository.
License: MIT.
