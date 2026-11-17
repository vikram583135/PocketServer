"""Explicit, temporary publication of a verified web/API origin only."""
from __future__ import annotations
import json
import os
from pathlib import Path
import re
import shutil
import uuid

from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import atomic_write, check_path, check_private, private_dir, read_private

URL = re.compile(r"https://[a-z0-9]+(?:-[a-z0-9]+)*\.trycloudflare\.com\b")


def _path(context):
    return context.paths["state"] / "tunnel-publication.json"


def _read(context):
    path = _path(context)
    check_path(path)
    if not path.exists():
        return {}
    try:
        value = json.loads(read_private(path, 16384))
        if not isinstance(value, dict):
            raise ValueError()
        return value
    except (ValueError, TypeError) as exc:
        raise PocketError("recovery_required", "Publication state is invalid.", 503) from exc


def _write(context, state):
    atomic_write(_path(context), json.dumps(state, sort_keys=True).encode())


def _directory(context, state):
    identifier = state.get("publication_id", "")
    if not isinstance(identifier, str) or not re.fullmatch(r"[0-9a-f]{32}", identifier):
        raise PocketError("publication_required", "Fresh publication approval is required.", 409)
    return context.paths["state"] / ("cloudflared-" + identifier)


def foreground_environment(context):
    directory = _directory(context, _read(context))
    env = {k: os.environ[k] for k in ("PATH", "PREFIX", "TMPDIR") if k in os.environ}
    env.update(HOME=str(directory), XDG_CONFIG_HOME=str(directory), NO_COLOR="1")
    return env


def foreground_command(context):
    context.ensure_mutable()
    if context.mode == "mock":
        raise PocketError("unsupported", "Mock mode cannot publish a public tunnel.", 503)
    from core.supervisor import read_gate
    state = _read(context)
    gate = read_gate(context, "tunnel")
    run_id = os.environ.get("POCKETSERVER_RUN_ID")
    if not state.get("approved") or not run_id or gate.get("run_id") != run_id or not gate.get("desired"):
        raise PocketError("publication_required", "Fresh explicit publication approval is required.", 409)
    cfg = ConfigManager(context).get_config()
    target = state.get("target_service")
    if target not in ("web", "api") or cfg["revision"] != state.get("config_revision") or cfg["services"][target]["port"] != state.get("port"):
        raise PocketError("publication_required", "The approved target configuration changed.", 409)
    executable = shutil.which("cloudflared")
    if not executable:
        raise PocketError("unsupported", "Install cloudflared locally before publication.", 503)
    directory = _directory(context, state)
    private_dir(directory)
    atomic_write(directory / "config.yml", b"{}\n")
    atomic_write(directory / "current.log", b"")
    state.update(connector_run_id=run_id, approved=False, url=None, connected=False)
    _write(context, state)
    return [str(Path(executable).absolute()), "--no-autoupdate", "--config", str(directory / "config.yml"),
            "tunnel", "--url", "http://127.0.0.1:" + str(state["port"])]


def note_output(context, run_id, chunk):
    """Called by the bounded owned logger; historical output cannot set a URL."""
    with FileLock(context.paths["locks"] / "tunnel-output.lock"):
        state = _read(context)
        if state.get("connector_run_id") != run_id:
            return
        path = _directory(context, state) / "current.log"
        existing = read_private(path, 65536) if path.exists() else b""
        chunk = chunk.encode("utf-8", "replace") if isinstance(chunk, str) else bytes(chunk)
        output = (existing + chunk[-65536:])[-65536:]
        atomic_write(path, output)
        # Process new events only. Scanning historical retained bytes would
        # resurrect a connected marker after a later disconnect.
        text = chunk[-65536:].decode("utf-8", "replace")
        match = URL.search(text)
        if match:
            state["url"] = match.group(0)
        if "Registered tunnel connection" in text:
            state["connected"] = True
        if any(marker in text.lower() for marker in ("connection terminated", "unregistered tunnel", "failed to serve tunnel", "retrying connection")):
            state.update(connected=False, url=None)
        _write(context, state)


def tunnel_observation(context, run_id):
    state = _read(context)
    current = bool(run_id) and state.get("connector_run_id") == run_id
    ready = current and bool(state.get("url")) and state.get("connected") is True
    return {"ready": ready, "url": state.get("url") if ready else None, "run_id": run_id,
            "reason": None if ready else "current_publication_unready"}


class TunnelManager:
    def __init__(self, context, supervisor, config=None):
        self.context, self.supervisor = context, supervisor
        self.config = config or ConfigManager(context)

    def _cfg(self):
        return self.config.get_config() if hasattr(self.config, "get_config") else self.config

    def start(self, target_service, acknowledge_public=False):
        self.context.ensure_mutable()
        if target_service not in ("web", "api"):
            raise PocketError("invalid_target", "Only the managed web or API service can be published.")
        if acknowledge_public is not True:
            raise PocketError("acknowledgement_required", "Explicitly acknowledge that this origin will be public.", 409)
        if self.context.mode == "mock":
            raise PocketError("unsupported", "Mock mode does not publish public tunnels.", 503)
        target = self.supervisor.status(target_service)
        if not target.get("ready") or not target.get("owned") or not target.get("run_id") or target.get("restart_required"):
            raise PocketError("target_unready", "Publication requires the current owned, ready target configuration.", 409)
        cfg = self._cfg()
        if target.get("effective_config", {}).get("port") != cfg["services"][target_service]["port"]:
            raise PocketError("target_unready", "The effective target port is not the configured port.", 409)
        self.stop()
        from core.storage import maintenance_lease
        with maintenance_lease(self.context), FileLock(self.context.paths["locks"] / "tunnel.lock"):
            state = {"publication_id": uuid.uuid4().hex, "target_service": target_service,
                     "port": cfg["services"][target_service]["port"], "target_run_id": target["run_id"],
                     "config_revision": cfg["revision"], "approved": True, "url": None, "connected": False}
            _write(self.context, state)
        try:
            self.supervisor._start_publication()
        except BaseException:
            self.stop()
            raise
        return self.status()

    def stop(self):
        self.context.ensure_mutable()
        try:
            result = self.supervisor.stop("tunnel")
        finally:
            # Invalidate even if local shutdown cannot yet be confirmed.
            with FileLock(self.context.paths["locks"] / "tunnel-output.lock"):
                state = _read(self.context)
                if state:
                    state.update(approved=False, url=None, connected=False, connector_run_id=None)
                    _write(self.context, state)
        if not result.get("running") and state:
            directory = _directory(self.context, state)
            check_path(directory)
            if directory.exists():
                check_private(directory, directory=True)
                shutil.rmtree(directory)
        return {"stopped": not result.get("running"), "url": None}

    def stop_if_target(self, service_id):
        if _read(self.context).get("target_service") == service_id:
            return self.stop()
        return None

    def status(self):
        observed = self.supervisor.status("tunnel")
        state = _read(self.context)
        current = tunnel_observation(self.context, observed.get("run_id"))
        return {**observed, "target_service": state.get("target_service"),
                "url": current["url"] if observed.get("running") else None,
                "public": bool(observed.get("running") and current["ready"]), "mode": "quick"}

    def reconcile(self):
        state = _read(self.context)
        observed = self.supervisor.status("tunnel")
        if not observed.get("running") and not observed.get("owned"):
            return self.status()
        target = self.supervisor.status(state.get("target_service")) if state.get("target_service") in ("web", "api") else {}
        cfg = self._cfg()
        if not target.get("ready") or target.get("run_id") != state.get("target_run_id") or cfg["revision"] != state.get("config_revision") or target.get("restart_required"):
            self.stop()
        return self.status()
