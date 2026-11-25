# Operator runbook

What you do by hand, in order.

## 1. Create the reader GitHub App

On the GitHub account or organisation that owns the repositories:

1. Settings, Developer settings, GitHub Apps, New GitHub App.
2. Name it, set any homepage, untick Webhook (Active).
3. Repository permissions: **Contents: Read-only**. **Metadata: Read-only** is added automatically. Nothing else.
4. Where can it be installed: only on this account.
5. Create, then note the **Client ID** (starts with `Iv`).
6. Generate a **private key** (PEM). It is the only secret the broker holds. Treat it as read access to every repository the App can see.
7. Install the App on the account and choose the repositories it may ever see (the policy narrows further, but the App's installation is the outer limit).
   "All repositories" also covers repositories and forks you create later (checked: narrowed tokens still come back as `selected`), but then a leaked key reads every private repository you own, and only the policy narrows it. "Only select repositories" keeps GitHub's own limit.

### The writer App (needed for `grant write`)

A second App, so the key the broker holds stays read-only:

1. Same steps, but repository permissions **Contents: Read and write** and **Pull requests: Read and write**, and tick **Enable Device Flow**.
2. Leave **Expire user authorization tokens** enabled.
3. Generate a **client secret**. It is the only secret the broker holds for write. Do **not** generate a private key for this App.
4. Install it on the repositories you will ever want to write to. Write grants are still one repository at a time and phone-approved.
5. Give the broker its Client ID and the client secret (see step 3). Without both, the write tier is off and `grant write` says so.

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
write:                      # phone-approved, one repo at a time
  allow: ["me/*"]
  deny:  ["me/dotfiles"]
  max_ttl: 2h
  default_ttl: 30m
limits:                     # optional, rolling 24h, ad hoc only (defaults shown)
  grants_per_day: 20
  mints_per_day: 60
```

Patterns are `owner/repo` globs, case-insensitive. `deny` always wins, and also blocks ad hoc grants.
Over a limit, grants are refused and audited; `check` shows usage. Counts reset on restart.
`log --verify` also lists mints or revokes that were started but never finished (a crash mid-call).

## 3. Run the broker

One image, two containers in one pod (or two services in Compose): the daemon and the operator sshd.

| Setting | Meaning |
|---|---|
| `TG_POLICY` | path to the policy file (the proposal) |
| `TG_SANDBOX_IDENTITY` | the one ServiceAccount allowed to call the sandbox API, `system:serviceaccount:<ns>:<name>` |
| `TG_READER_CLIENT_ID`, `TG_READER_KEY` | the App's Client ID, and the path to its PEM |
| `TG_WRITER_CLIENT_ID`, `TG_WRITER_SECRET` | the writer App's Client ID, and the path to a file holding its client secret (both, or the write tier is off) |
| `TG_WRITE_TOKENS` | where live write tokens are kept until revoked (default `write-tokens.json` beside `TG_STATE`; 0600, broker volume only) |
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
grant write owner/repo [30m]  # prints a code: open github.com/login/device on your phone and enter it
setup owner/repo --write      # read grant if needed, then write, then the `ws clone` line for the sandbox
revoke owner/repo [write]    # take it back now (the token is revoked at GitHub too)
log --since 1h                # recent events (needs the audit file)
log --verify                  # check the audit hash chain
```

`grant write` waits up to 5 minutes for you to approve on GitHub's page (check it names the writer App), then exits 0 (granted), 3 (denied) or 4 (expired). The broker narrows the approved token to that one repo, revokes the parent at once, and revokes the narrowed token when the grant ends. GitHub gives that token 8 hours regardless of the TTL you chose, so the revoke is what enforces it; `log --verify` and the audit show every attempt.

When a workspace git command fails, its message begins `terracotta:` and names the command to run here. Run that command; the agent retries.

## 7. Emergency stop

```
stop      # revokes grants, drops tokens, suspends the App's installations, blocks serving
resume    # lifts it; standing read refreshes
```

`stop` survives a restart. If it prints `INCOMPLETE`, serving is already blocked locally; run it again once GitHub is reachable.

## 8. Rotating keys

1. In the App settings generate a new private key.
2. Replace the secret the broker mounts and restart the broker (grants are in memory and end; standing read refreshes on start).
3. Delete the old key in the App settings.

The writer App has no key. To rotate its client secret: generate a new one in the App settings, replace the file the broker mounts, restart the broker (a restart revokes any write token still held, using the old secret first, so rotate when no write grant is open), then delete the old secret.

## 9. Lost phone or leaked operator key

Your SSH key can start grants and activate the proposed policy; it cannot approve write (that needs your GitHub login on the phone). Act in this order:

1. Remove the key from the authorized keys the sshd container mounts, and restart that container.
2. Sign out the phone's sessions on GitHub (Settings, Sessions) and revoke its authorized apps.
3. Stop everything from the cluster, which needs no SSH: `kubectl exec deploy/<broker> -c broker -- terracotta-general stop`.
4. Check `log --since 24h` for grants you did not make, then add a new key, `resume`, and rotate the writer client secret (step 8) if you saw one.

## 10. Things to know

- Only approve a device code the broker just printed on your own SSH session, and check that GitHub's page names the writer App. A client ID is not secret, so anything with GitHub egress could start a device flow of its own and ask you to approve it; that token would reach every repository the writer App is installed on.
- Put the repository that holds the controller's policy in `write.deny`, and require review on its default branch: a write token can push and open PRs, and without protection it could merge.
- Tokens cannot be limited to a branch. Protect the default branch of every repository the sandbox can write to. `check` reports it.
- Standing read lets the agent read every allowlisted repository and send it to anything the egress policy allows, at least the LLM API. Keep the allowlist narrow.
- A broker restart ends all grants (write tokens still held are revoked at startup). Standing read comes back within a minute.
- Live write tokens are the one thing the broker writes to disk (`write-tokens.json`, 0600, on its own volume), so that a crash cannot leave one unrevocable. Keep that volume off the sandbox's reach.
- Audit tail truncation is not detectable by the chain alone: ship the stdout stream to durable storage, and now and then note the record count and last hash that `status` prints (a shorter log or a different hash at that count means tampering).
