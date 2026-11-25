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
    writer_client_id: str | None = None  # the write tier is off unless both writer settings are set
    writer_secret_path: str | None = None
    write_tokens_path: str | None = None  # default: next to the state file
    state_path: str = "/var/lib/terracotta/state.json"
    # Endpoints and paths below default to production; the compose harness points them at a stub.
    github_api: str = "https://api.github.com"
    github_web: str = "https://github.com"  # device flow host
    kube_api: str = "https://kubernetes.default.svc"
    kube_token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token"
    kube_ca_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

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
            writer_client_id=env.get("TG_WRITER_CLIENT_ID") or None,
            writer_secret_path=env.get("TG_WRITER_SECRET") or None,
            write_tokens_path=env.get("TG_WRITE_TOKENS") or None,
            state_path=env.get("TG_STATE", cls.state_path),
            github_api=env.get("TG_GITHUB_API", cls.github_api),
            github_web=env.get("TG_GITHUB_WEB", cls.github_web),
            kube_api=env.get("TG_KUBE_API", cls.kube_api),
            kube_token_path=env.get("TG_KUBE_TOKEN", cls.kube_token_path),
            kube_ca_path=env.get("TG_KUBE_CA", cls.kube_ca_path),
        )
