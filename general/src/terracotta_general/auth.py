"""Sandbox caller identity: a projected ServiceAccount token checked with TokenReview."""

from __future__ import annotations

import pathlib
import ssl
from typing import Protocol

import httpx

SA_DIR = pathlib.Path("/var/run/secrets/kubernetes.io/serviceaccount")


class Authenticator(Protocol):
    async def identify(self, token: str) -> str | None:
        """Username (`system:serviceaccount:<ns>:<name>`) for a valid token, else None."""


class TokenReview:
    def __init__(
        self,
        audience: str,
        api_url: str = "https://kubernetes.default.svc",
        client: httpx.AsyncClient | None = None,
        broker_token_path: pathlib.Path = SA_DIR / "token",
        ca_path: pathlib.Path = SA_DIR / "ca.crt",
    ):
        self.audience, self.api_url, self._token_path = audience, api_url, broker_token_path
        self._ca_path, self._client = ca_path, client

    async def identify(self, token: str) -> str | None:
        body = {
            "apiVersion": "authentication.k8s.io/v1",
            "kind": "TokenReview",
            "spec": {"token": token, "audiences": [self.audience]},
        }
        try:
            # Built lazily: outside a cluster the CA file is absent, and that must fail closed
            # on the first request rather than stop the daemon from starting.
            if self._client is None:
                # Plain http is only for the compose harness; the cluster API is always https.
                verify = (ssl.create_default_context(cafile=str(self._ca_path))
                          if self.api_url.startswith("https://") else True)
                self._client = httpx.AsyncClient(verify=verify, timeout=5.0)
            r = await self._client.post(
                f"{self.api_url}/apis/authentication.k8s.io/v1/tokenreviews",
                json=body,
                headers={"Authorization": f"Bearer {self._token_path.read_text().strip()}"},
            )
        except (httpx.HTTPError, OSError):
            return None  # fail closed
        if r.status_code not in (200, 201):
            return None
        st = r.json().get("status", {})
        if not st.get("authenticated") or self.audience not in st.get("audiences", []):
            return None
        return st.get("user", {}).get("username")
