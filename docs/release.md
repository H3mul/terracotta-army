# Release process

One tag releases both images.

1. Make sure `main` is green: unit tests, mypy, hygiene, and the Compose integration suite
   (`uv run --project general pytest tests/integration -v` locally; the same job runs in CI).
2. If the sandbox-to-broker API changed, bump `contract/VERSION`, `CONTRACT_VERSION` in
   `general/src/terracotta_general/__init__.py`, and `info.version` in `contract/openapi.yaml`
   together (`tests/hygiene` fails if they disagree). A bump is a breaking change for old workspaces:
   the broker answers 426 to callers below its minimum.
3. Tag and push: `git tag vX.Y.Z && git push origin vX.Y.Z`.
4. CI builds `terracotta-general` and `terracotta-workspace` from the same commit, pushes both to
   `ghcr.io/<owner>/` with that tag, signs each by digest with cosign (keyless), and creates a GitHub
   release whose notes carry a digests table and the contract version.
5. In the deployment repo, pin both images by the digests from that table, not by tag.

## Before the first release

- The workflow has not run on GitHub yet; expect to fix small things on the first tag (the cosign step,
  release permissions, GHCR package visibility).
- Pin the workspace base image and the tool versions again if they are stale (`workspace/Dockerfile`
  and `workspace/tools/package.json`; regenerate the lockfile in a container, not on the host).
- The workspace image is about 2.9 GB (the agents' native binaries) and amd64 only.
