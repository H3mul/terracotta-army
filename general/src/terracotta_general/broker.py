"""The broker's shared state, handed to both HTTP surfaces."""

from __future__ import annotations

from dataclasses import dataclass

from terracotta_general.audit import AuditLog
from terracotta_general.auth import Authenticator
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore


@dataclass
class Broker:
    policy: Policy
    store: RequestStore
    audit: AuditLog
    auth: Authenticator
    sandbox_identity: str  # the one ServiceAccount allowed to call the sandbox API
