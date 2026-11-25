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
from terracotta_general.audit import GENESIS, AuditError, AuditLog, resume_point
from terracotta_general.auth import TokenReview
from terracotta_general.broker import Broker
from terracotta_general.config import Settings
from terracotta_general.github import App, Writer
from terracotta_general.grants import Grants
from terracotta_general.lifecycle import Lifecycle
from terracotta_general.requests import RequestStore
from terracotta_general.standing import StandingRead
from terracotta_general.writes import WriteGrants


def build(settings: Settings, auth=None, sinks=None, http: httpx.AsyncClient | None = None) -> Broker:
    life = Lifecycle(settings.state_path, settings.policy_path)
    prev, seq = GENESIS, 0
    if sinks is None:
        sinks = [sys.stdout]
        if settings.audit_file:
            path = pathlib.Path(settings.audit_file)
            try:  # continue the previous run's chain; refuse to start on a broken one
                prev, seq = resume_point(path.read_text().splitlines()) if path.exists() else (GENESIS, 0)
            except AuditError as e:
                raise SystemExit(f"audit file {path} fails verification: {e}") from None
            sinks.append(open(path, "a"))  # noqa: SIM115 - lives for the process
    audit = AuditLog(*sinks, prev=prev, seq=seq)
    store = RequestStore()
    app = App(settings.reader_client_id, pathlib.Path(settings.reader_key_path).read_text(),
              http or httpx.AsyncClient(timeout=10.0), base=settings.github_api, audit=audit)
    active = life.policy
    grants = Grants(app, store, active, audit)
    writes = None
    if settings.writer_client_id and settings.writer_secret_path:
        writer = Writer(settings.writer_client_id,
                        pathlib.Path(settings.writer_secret_path).read_text().strip(),
                        http or httpx.AsyncClient(timeout=10.0), base=settings.github_api,
                        web=settings.github_web, audit=audit)
        tokens = settings.write_tokens_path or str(pathlib.Path(settings.state_path).with_name("write-tokens.json"))
        writes = WriteGrants(writer, store, active, audit, tokens, grants.spend, paused=lambda: life.stopped)
    return Broker(
        policy=active,
        store=store,
        audit=audit,
        auth=auth or TokenReview(
            settings.audience, settings.kube_api, None,
            pathlib.Path(settings.kube_token_path), pathlib.Path(settings.kube_ca_path)),
        sandbox_identity=settings.sandbox_identity,
        standing=StandingRead(app, active, audit, paused=lambda: life.stopped),
        grants=grants,
        life=life,
        app=app,
        writes=writes,
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
    assert b.standing and b.grants  # build() always wires both
    tasks = [asyncio.create_task(b.standing.run()), asyncio.create_task(b.grants.run())]
    if b.writes:
        tasks.append(asyncio.create_task(b.writes.run()))
    try:
        await asyncio.gather(tcp.serve(), admin.serve())
    finally:
        for t in tasks:
            t.cancel()


def main() -> None:
    asyncio.run(run(Settings.from_env(os.environ)))
