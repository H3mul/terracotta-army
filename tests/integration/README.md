# Container-level integration harness

Docker Compose, no Kubernetes: the real `terracotta-general` image (daemon and operator sshd), a
sandbox-side curl client, and a stub that serves the GitHub App API (`general/tests/fake_github.py`)
and Kubernetes TokenReview. Scenarios drive the operator over real SSH, as from the phone.

    uv run --project general pytest tests/integration -v     # needs docker; ~70s

Covers: real git clone and fetch through the workspace credential helper against a TLS stub of github.com, push refusal with the broker hint, no token on the workspace disk; approval gate, standing and ad hoc read, hints, identity and contract checks, revoke at
"GitHub", branch-protection report, forced-command SSH, no admin surface for the sandbox,
emergency stop and its persistence across a broker restart, audit chain.

Not covered (by design, see ta-deployment): RBAC, NetworkPolicy, real TokenReview, runtime class.
Write-tier scenarios (grant write then push) arrive with ta-general section 3.
