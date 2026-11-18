#!/bin/sh
# Starts the operator sshd as the unprivileged user. Mount a persistent volume at
# /var/lib/terracotta-ssh so the host key (and the operator's known_hosts entry) survives restarts.
set -eu
KEYDIR=/var/lib/terracotta-ssh
[ -f "$KEYDIR/ssh_host_ed25519_key" ] || ssh-keygen -q -t ed25519 -N "" -f "$KEYDIR/ssh_host_ed25519_key"
exec /usr/sbin/sshd -D -e -f /etc/terracotta/sshd_config
