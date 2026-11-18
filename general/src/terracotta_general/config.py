from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    policy_path: str
    sandbox_identity: str
    reader_client_id: str
    reader_key_path: str
    audience: str = "terracotta-general"
    admin_socket: str = "/run/terracotta/admin.sock"
    listen_host: str = "0.0.0.0"
    listen_port: int = 8080
    audit_file: str | None = None
    state_path: str = "/var/lib/terracotta/state.json"

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Settings:
        missing = [k for k in ("TG_POLICY", "TG_SANDBOX_IDENTITY", "TG_READER_CLIENT_ID", "TG_READER_KEY") if not env.get(k)]
        if missing:
            raise SystemExit(f"missing required environment: {', '.join(missing)}")
        return cls(
            policy_path=env["TG_POLICY"],
            sandbox_identity=env["TG_SANDBOX_IDENTITY"],
            reader_client_id=env["TG_READER_CLIENT_ID"],
            reader_key_path=env["TG_READER_KEY"],
            audience=env.get("TG_AUDIENCE", cls.audience),
            admin_socket=env.get("TG_ADMIN_SOCKET", cls.admin_socket),
            listen_host=env.get("TG_LISTEN_HOST", cls.listen_host),
            listen_port=int(env.get("TG_LISTEN_PORT", cls.listen_port)),
            audit_file=env.get("TG_AUDIT_FILE") or None,
            state_path=env.get("TG_STATE", cls.state_path),
        )
