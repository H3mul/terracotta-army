# Operator runbook

What you do by hand, in order. Write access (`grant write`) is not built yet; this covers the read path.

## 1. Create the reader GitHub App

On the GitHub account or organisation that owns the repositories:

1. Settings, Developer settings, GitHub Apps, New GitHub App.
2. Name it, set any homepage, untick Webhook (Active).
3. Repository permissions: **Contents: Read-only**. **Metadata: Read-only** is added automatically. Nothing else.
4. Where can it be installed: only on this account.
5. Create, then note the **Client ID** (starts with `Iv`).
6. Generate a **private key** (PEM). It is the only secret the broker holds. Treat it as read access to every repository the App can see.
7. Install the App on the account and choose the repositories it may ever see (the policy narrows further, but the App's installation is the outer limit).

## 2. Write the policy

The policy is a proposal until you approve it (step 5). Example:

```yaml
read:
  standing:                 # the sandbox can always read these
    allow: ["myorg/*", "me/dotfiles"]
    deny:  ["myorg/secrets-*"]
  adhoc:                    # readable only on request, for a limited time
    allow: ["me/*"]
    max_ttl: 4h
write:                      # reserved: write grants are not built yet
  allow: []
```

Patterns are `owner/repo` globs, case-insensitive. `deny` always wins, and also blocks ad hoc grants.

## 3. Run the broker

One image, two containers in one pod (or two services in Compose): the daemon and the operator sshd.

| Setting | Meaning |
|---|---|
| `TG_POLICY` | path to the policy file (the proposal) |
| `TG_SANDBOX_IDENTITY` | the one ServiceAccount allowed to call the sandbox API, `system:serviceaccount:<ns>:<name>` |
| `TG_READER_CLIENT_ID`, `TG_READER_KEY` | the App's Client ID, and the path to its PEM |
| `TG_STATE` | where the approved policy and stop flag persist; mount a small volume (default `/var/lib/terracotta/state.json`) |
| `TG_AUDIT_FILE` | optional audit file (the audit log always goes to stdout); set it on both containers, on the shared state volume, so `log` works over SSH |
| `TG_ADMIN_SOCKET` | admin unix socket, shared with the sshd container (default `/run/terracotta/admin.sock`) |

The sshd container needs your public key(s) at `/etc/terracotta/authorized_keys`, and a volume at `/var/lib/terracotta-ssh` so its host key persists. Run both containers read-only, as non-root, with no capabilities (the Compose harness does).

The workspace calls the broker with its projected ServiceAccount token (audience `terracotta-general`); the broker checks it with TokenReview, so its ServiceAccount needs only the `system:auth-delegator` role.

## 4. Log in

```
ssh -p 2222 tg@<broker-host>            # interactive prompt, easy on a phone
ssh -p 2222 tg@<broker-host> status     # or one command at a time
```

Only the operator commands exist there; anything else is refused.

## 5. First start

A broker with no approved policy denies everything.

```
policy show                # what the proposal would change, in plain words
policy approve <hash>      # activates exactly what you reviewed
status                     # standing read set and active grants
check owner/repo           # why a repo is allowed or denied, and whether its default branch is protected
```

If the proposal changes after you looked, `approve` refuses and you review again.

## 6. Day to day

```
grant read owner/repo [30m]   # time-boxed read of a private repo outside the standing list
revoke owner/repo             # take it back now (the token is revoked at GitHub too)
log --since 1h                # recent events (needs the audit file)
log --verify                  # check the audit hash chain
```

When a workspace git command fails, its message begins `terracotta:` and names the command to run here. Run that command; the agent retries.

## 7. Emergency stop

```
stop      # revokes grants, drops tokens, suspends the App's installations, blocks serving
resume    # lifts it; standing read refreshes
```

`stop` survives a restart. If it prints `INCOMPLETE`, serving is already blocked locally; run it again once GitHub is reachable.

## 8. Rotating the reader key

1. In the App settings generate a new private key.
2. Replace the secret the broker mounts and restart the broker (grants are in memory and end; standing read refreshes on start).
3. Delete the old key in the App settings.

## 9. Things to know

- Tokens cannot be limited to a branch. Protect the default branch of every repository the sandbox can write to (when write exists). `check` reports it.
- Standing read lets the agent read every allowlisted repository and send it to anything the egress policy allows, at least the LLM API. Keep the allowlist narrow.
- A broker restart ends all grants. Standing read comes back within a minute.
- Audit tail truncation is not detectable by the chain alone; ship the stdout stream to durable storage.
