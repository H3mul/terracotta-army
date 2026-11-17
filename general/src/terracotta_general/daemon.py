"""`terracotta-general serve`: policy load, audit sinks, and both HTTP servers."""

from __future__ import annotations

import asyncio
import contextlib
import os
import pathlib
import sys

import uvicorn

from terracotta_general.api import admin_app, sandbox_app
from terracotta_general.audit import AuditLog
from terracotta_general.auth import TokenReview
from terracotta_general.broker import Broker
from terracotta_general.config import Settings
from terracotta_general.policy import Policy
from terracotta_general.requests import RequestStore


def build(settings: Settings, auth=None, sinks=None) -> Broker:
    policy = Policy.load(pathlib.Path(settings.policy_path).read_text())
    if sinks is None:
        sinks = [sys.stdout]
        if settings.audit_file:
            sinks.append(open(settings.audit_file, "a"))  # noqa: SIM115 - lives for the process
    return Broker(
        policy=policy,
        store=RequestStore(),
        audit=AuditLog(*sinks),
        auth=auth or TokenReview(settings.audience),
        sandbox_identity=settings.sandbox_identity,
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
    await asyncio.gather(tcp.serve(), admin.serve())


def main() -> None:
    asyncio.run(run(Settings.from_env(os.environ)))
