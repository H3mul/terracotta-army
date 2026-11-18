"""`terracotta-general serve`: policy load, audit sinks, and both HTTP servers."""

from __future__ import annotations

import asyncio
import contextlib
import os
import pathlib
import sys

import httpx
import uvicorn

from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditLog
from terracotta_general.auth import TokenReview
from terracotta_general.broker import Broker
from terracotta_general.config import Settings
from terracotta_general.github import App
from terracotta_general.grants import Grants
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead


def build(settings: Settings, auth=None, sinks=None, http: httpx.AsyncClient | None = None) -> Broker:
    policy = Policy.load(pathlib.Path(settings.policy_path).read_text())
    if sinks is None:
        sinks = [sys.stdout]
        if settings.audit_file:
            sinks.append(open(settings.audit_file, "a"))  # noqa: SIM115 - lives for the process
    audit = AuditLog(*sinks)
    store = RequestStore()
    app = App(settings.reader_client_id, pathlib.Path(settings.reader_key_path).read_text(),
              http or httpx.AsyncClient(timeout=10.0))
    active = lambda: policy
    return Broker(
        policy=active,
        store=store,
        audit=audit,
        auth=auth or TokenReview(settings.audience),
        sandbox_identity=settings.sandbox_identity,
        standing=StandingRead(app, active, audit),
        grants=Grants(app, store, active, audit),
    )


async def run(settings: Settings) -> None:
    b = build(settings)
    b.audit.write("start", contract=1)
    sock = pathlib.Path(settings.admin_socket)
    sock.parent.mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(FileNotFoundError):
        sock.unlink()
    tcp = uvicorn.Server(uvicorn.Config(
        sandbox_app(b), host=settings.listen_host, port=settings.listen_port, log_level="warning"))
    admin = uvicorn.Server(uvicorn.Config(admin_app(b), uds=str(sock), log_level="warning"))
    tasks = [asyncio.create_task(b.standing.run()), asyncio.create_task(b.grants.run())]
    try:
        await asyncio.gather(tcp.serve(), admin.serve())
    finally:
        for t in tasks:
            t.cancel()


def main() -> None:
    asyncio.run(run(Settings.from_env(os.environ)))
