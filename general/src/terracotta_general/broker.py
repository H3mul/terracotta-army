"""The broker's shared state, handed to both HTTP surfaces."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from terracotta_general.audit import AuditLog
from terracotta_general.auth import Authenticator
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.lifecycle import Lifecycle
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead
from terracotta_general.writes import WriteGrants


@dataclass
class Broker:
    policy: Callable[[], Policy]  # the active policy; a callable so activation can swap it
    store: RequestStore
    audit: AuditLog
    auth: Authenticator
    sandbox_identity: str  # the one ServiceAccount allowed to call the sandbox API
    standing: StandingRead | None = None
    grants: Grants | None = None
    life: Lifecycle | None = None
    app: App | None = None  # the reader App, for suspending installations
    writes: WriteGrants | None = None  # None until the writer App is configured
