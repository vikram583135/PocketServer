"""Lifecycle authority belongs to an owned backend, never a persisted PID."""
from __future__ import annotations
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import uuid
from contextlib import nullcontext
from pathlib import Path
from core.config import ConfigManager
from core.env import get_runtime_paths, request_wake_lock
from core.errors import PocketError
from core.locking import FileLock
from core.logs import MAX_LOG_BACKUPS, MAX_LOG_SIZE_BYTES, redact_secrets, rotate_log_file, tail_log
from core.runtime import RuntimeContext, atomic_write, check_path, check_private, private_dir, read_private
from core.services import SERVICE_PROFILES, check_http_endpoint, service_config, validate_service_id

class FakeBackend:
    """Invocation-local deterministic backend. It never launches host processes."""
    name = "fake"
    def __init__(self, *, clock=None):
        self.clock = clock or time.monotonic
        self.states = {}
        self.starts = []
        self.stops = []
        self.fail_start = set()
        self.fail_stop = set()
        self.unready = set()
    def observe(self, service_id, cfg=None):
        state = self.states.get(service_id, {})
        running = bool(state.get("running"))
        return {"running": running, "owned": running, "ready": running and service_id not in self.unready,
                "state": "running" if running else "stopped", "reason": "invocation_local_mock",
                "pid": None, "run_id": state.get("run_id"), "started": state.get("started")}
    def start(self, service_id, cfg=None):
        self.starts.append(service_id)
        if service_id in self.fail_start:
            raise PocketError("start_failed", "Injected backend start failure")
        self.states[service_id] = {"running": True, "run_id": uuid.uuid4().hex, "started": self.clock()}
    def stop(self, service_id, *, force=False):
        self.stops.append((service_id, force))
        if service_id not in self.fail_stop:
            self.states.pop(service_id, None)

class RunitBackend:
    name = "runit"
    def __init__(self, context, *, runner=None):
        self.context = context
        self.runner = runner or subprocess.run
    def _directory(self, service_id):
        validate_service_id(service_id)
        registration = self.context.root / "state" / "runit-install.json"
        try:
            check_private(registration)
            manifest = json.loads(read_private(registration, 65536))
            directory = Path(manifest["service_root"]) / ("pocketserver-" + service_id)
            check_private(directory, directory=True)
            marker = directory / "pocketserver-owner"
            check_private(marker)
            if marker.read_text(encoding="utf-8") != str(self.context.root):
                raise ValueError("owner mismatch")
            return directory
        except (OSError, ValueError, KeyError):
            raise PocketError("unsupported", "Owned runit entries are not installed or verified", status=503)
    def _sv(self, service_id, command):
        executable = shutil.which("sv")
        if not executable:
            raise PocketError("unsupported", "The runit sv command is unavailable", status=503)
        directory = self._directory(service_id)
        try:
            return self.runner([executable, "-w", "0", command, str(directory)],
                               capture_output=True, text=True, timeout=2, check=False)
        except (OSError, subprocess.TimeoutExpired):
            raise PocketError("backend_unavailable", "runit did not respond", status=503)
    def observe(self, service_id, cfg=None):
        try:
            result = self._sv(service_id, "status")
        except PocketError as exc:
            return {"running": False, "owned": False, "ready": False, "state": "unsupported",
                    "reason": exc.code, "pid": None, "run_id": None}
        text = result.stdout.strip()
        if result.returncode != 0 or not (text.startswith("run:") or text.startswith("down:")):
            return {"running": False, "owned": False, "ready": False, "state": "unknown",
                    "reason": "runit_status_unavailable", "pid": None, "run_id": None}
        running = text.startswith("run:")
        gate = read_gate(self.context, service_id)
        # A runsv-managed launch gate is not itself a running payload.
        active = running and gate.get("payload") is True
        run_id = gate.get("run_id") if active else None
        ready = False
        effective = gate.get("effective", {})
        if active and service_id == "controller":
            ready = bool(read_epoch(self.context)) and gate.get("epoch") == read_epoch(self.context)
        elif active and service_id in ("web", "api", "dashboard"):
            host = effective.get("bind_address", "127.0.0.1")
            host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
            ready = check_http_endpoint(host, effective.get("port"), SERVICE_PROFILES[service_id].health_path,
                                        service_id=service_id, run_id=run_id)
        elif active and service_id == "ssh":
            from core.ssh_git import ssh_observation
            ready = bool(ssh_observation(self.context, run_id).get("ready"))
        elif active and service_id == "tunnel":
            from core.tunnel import tunnel_observation
            ready = bool(tunnel_observation(self.context, run_id).get("ready"))
        match = re.search(r"\(pid (\d+)\)", text)
        return {"running": active, "owned": running, "ready": ready,
                "state": "running" if active else ("starting" if running else "stopped"),
                "reason": gate.get("reason") if running else None,
                "pid": int(match.group(1)) if match and active else None, "run_id": run_id,
                "effective_config": effective, "started": gate.get("started")}
    def start(self, service_id, cfg=None):
        if service_id != "controller" and not read_epoch(self.context):
            raise PocketError("controller_unavailable", "Start the owned controller before payloads", status=503)
        with FileLock(self.context.root / "locks" / ("gate-" + service_id + ".lock")):
            write_gate(self.context, service_id, {"desired": True, "epoch": read_epoch(self.context),
                        "attempts": [], "payload": False, "effective": service_config(cfg, service_id)})
        result = self._sv(service_id, "up")
        if result.returncode != 0:
            raise PocketError("start_failed", "runit rejected service activation")
    def stop(self, service_id, *, force=False):
        with FileLock(self.context.root / "locks" / ("gate-" + service_id + ".lock")):
            gate = read_gate(self.context, service_id)
            gate.update(desired=False)
            write_gate(self.context, service_id, gate)
        result = self._sv(service_id, "force-stop" if force else "down")
        if result.returncode != 0 and force:
            raise PocketError("stop_failed", "runit could not confirm service shutdown")

def gate_path(context, service_id):
    validate_service_id(service_id)
    return context.root / "state" / ("gate-" + service_id + ".json")

def read_gate(context, service_id):
    path = gate_path(context, service_id)
    try:
        check_private(path)
        value = json.loads(read_private(path, 65536))
        if not isinstance(value, dict):
            return {}
        if "started" in value and type(value["started"]) not in (int, float):
            return {}
        if "attempts" in value and (not isinstance(value["attempts"], list) or len(value["attempts"]) > 4 or any(type(item) not in (int, float) for item in value["attempts"])):
            return {}
        if "effective" in value and not isinstance(value["effective"], dict):
            return {}
        return value
    except (OSError, ValueError):
        return {}

def write_gate(context, service_id, value):
    atomic_write(gate_path(context, service_id), json.dumps(value, sort_keys=True).encode())

def read_epoch(context):
    path = context.root / "state" / "controller-epoch.json"
    try:
        check_private(path)
        value = json.loads(read_private(path, 4096))
        # Monotonic values are meaningful only within the same boot.
        if value.get("boot_id") != boot_id():
            return None
        return value["epoch"] if time.monotonic() - value["heartbeat"] < 15 else None
    except (OSError, ValueError, KeyError, TypeError):
        return None

def boot_id():
    try:
        return Path("/proc/sys/kernel/random/boot_id").read_text().strip()
    except OSError:
        return "mock-process-" + str(os.getpid())

def install_runit_entries(context, service_root=None, *, app_root=None, interpreter=None, lock_held=False, recovery_held=False):
    """Explicit setup only. Ordinary entries retain down across all transitions."""
    if not recovery_held:
        context.ensure_mutable()
    if context.mode not in ("termux", "production"):
        raise PocketError("unsupported", "runit installation requires production Termux", status=503)
    for executable in ("sv", "runsv", "svlogd"):
        if not shutil.which(executable):
            raise PocketError("unsupported", "Required runit executable is unavailable", status=503)
    service_root = Path(service_root or (Path(os.environ["PREFIX"]) / "var" / "service"))
    check_path(service_root)
    if not service_root.is_dir():
        raise PocketError("unsupported", "The runit service directory is unavailable", status=503)
    app_root = Path(app_root) if app_root else Path(__file__).resolve().parent.parent
    python = str(Path(interpreter)) if interpreter else str(Path(sys.executable).resolve())
    check_path(app_root)
    check_path(Path(python))
    lease = nullcontext() if lock_held else FileLock(context.root / "locks" / "operation.lock")
    with lease:
        for service_id in SERVICE_PROFILES:
            directory = service_root / ("pocketserver-" + service_id)
            if directory.exists():
                check_private(directory, directory=True)
                marker = directory / "pocketserver-owner"
                if not marker.is_file() or marker.read_text(encoding="utf-8") != str(context.root):
                    raise PocketError("unsafe_path", "Refusing an unowned service directory")
            private_dir(directory)
            # runsv may discover the directory immediately. Down must precede
            # every executable launcher, including first installation.
            atomic_write(directory / "down", b"")
            atomic_write(directory / "pocketserver-owner", str(context.root).encode())
            args = [python, "-m", "core.service_entry", service_id, "--root", str(context.root), "--gate"]
            finish_args = [python, "-m", "core.service_entry", service_id, "--root", str(context.root), "--finish"]
            shell = Path(os.environ["PREFIX"]) / "bin" / "sh"
            prelude = "#!" + str(shell) + "\numask 077\nexec 2>&1\ncd " + shlex.quote(str(app_root)) + "\n"
            atomic_write(directory / "run", (prelude + "exec " + shlex.join(args) + "\n").encode(), mode=0o700)
            atomic_write(directory / "finish", (prelude + "exec " + shlex.join(finish_args) + "\n").encode(), mode=0o700)
            atomic_write(directory / "down", b"")
            atomic_write(directory / "pocketserver-owner", str(context.root).encode())
            log_service = directory / "log"
            private_dir(log_service)
            log_dir = context.root / "logs" / (service_id + "-runit")
            private_dir(log_dir)
            # svlogd sees only bounded lines from the trusted drain. The fixed
            # 4096-byte line ceiling bounds its per-file overshoot explicitly.
            atomic_write(log_dir / "config", b"s1048576\nn2\n")
            log_args = [python, "-m", "core.service_entry", service_id,
                        "--root", str(context.root), "--log-stream"]
            atomic_write(log_service / "run", (prelude + "exec " + shlex.join(log_args) + "\n").encode(), mode=0o700)
        atomic_write(context.root / "state" / "runit-install.json",
                     json.dumps({"service_root": str(service_root)}).encode())
    return {"installed": list(SERVICE_PROFILES), "verified_daemon": False}

class Supervisor:
    def __init__(self, config_manager=None, context=None, backend=None, *, clock=None, sleep=None):
        self.context = context or getattr(config_manager, "context", None) or RuntimeContext.discover()
        self.config_manager = config_manager or ConfigManager(self.context)
        self.paths = self.context.paths
        self.clock, self.sleep = clock or time.monotonic, sleep or time.sleep
        self.backend = backend or (RunitBackend(self.context) if self.context.mode in ("termux", "production") else FakeBackend(clock=self.clock))
        self._mutex = threading.RLock()
        self._errors = {}
        self._retries = {}
    def _guard(self, shutdown=False):
        if shutdown:
            try:
                check_private(self.context.root / "locks", directory=True)
            except FileNotFoundError:
                raise PocketError("not_initialized", "Initialize PocketServer before lifecycle control.", status=409) from None
        else:
            self.context.ensure_mutable()
        # Locks never implicitly initialize missing runtimes.
        return FileLock(self.context.root / "locks" / "operation.lock", timeout=5)
    def _cfg(self):
        return self.config_manager.get_config()
    def status(self, service_id=None):
        if service_id is None:
            return self.status_all()
        validate_service_id(service_id)
        cfg = self._cfg()
        pending = service_config(cfg, service_id)
        observed = self.backend.observe(service_id, cfg)
        running, ready = bool(observed.get("running")), bool(observed.get("ready"))
        effective = observed.get("effective_config", pending)
        return {**observed, "service": service_id, "name": SERVICE_PROFILES[service_id].name,
                "backend": self.backend.name, "running": running, "ready": ready,
                "readiness": "ready" if ready else ("unready" if running else "unknown"),
                "healthy": ready, "state": ("degraded" if running and not ready else observed.get("state", "unknown")),
                "autostart": bool(pending.get("autostart")), "port": effective.get("port"),
                "bind_address": effective.get("bind_address"), "effective_config": effective,
                "pending_config": pending, "restart_required": running and effective != pending,
                "uptime_seconds": max(0, int(self.clock() - observed["started"])) if observed.get("started") is not None else None,
                "observation_time": time.time(), "last_error": self._errors.get(service_id)}
    def status_all(self):
        return {service_id: self.status(service_id) for service_id in SERVICE_PROFILES}
    def _wake(self):
        demand = any(s["running"] for sid, s in self.status_all().items() if sid != "controller")
        from core.jobs import owned_jobs_running
        demand = demand or owned_jobs_running(self.context)
        return request_wake_lock(demand, policy=self._cfg().get("power", {}).get("wake_policy", "manual"), context=self.context)
    def _wait(self, service_id, ready, timeout):
        deadline = self.clock() + timeout
        while True:
            status = self.status(service_id)
            if ready and status["running"] and status["ready"]:
                return status
            if not ready and not status["running"] and not status.get("owned") and status["state"] == "stopped":
                return status
            if self.clock() >= deadline:
                return None
            self.sleep(min(0.1, max(0, deadline - self.clock())))
    def start(self, service_id, *, maintenance_held=False):
        validate_service_id(service_id)
        if service_id == "tunnel":
            raise PocketError("publication_required", "Use explicit publication with a validated origin", status=409)
        self.context.ensure_mutable()
        lease = nullcontext() if maintenance_held else FileLock(self.context.root / "locks" / "maintenance.lock", shared=True)
        with self._mutex, lease, self._guard():
            if self.backend.name == "runit" and service_id != "controller" and not self.status("controller")["ready"]:
                self._start("controller")
            return self._start(service_id)
    def _start(self, service_id):
        current = self.status(service_id)
        if current["state"] in ("unsupported", "unknown"):
            raise PocketError("unsupported", "Service supervision is unavailable; verify the owned runit installation", status=503)
        if current["state"] == "starting":
            raise PocketError("busy", "An owned launch is already in progress", status=409)
        if current["running"]:
            if current["ready"]:
                return current
            raise PocketError("start_failed", "An owned instance is running but unready", status=409)
        cfg = self._cfg()
        if not cfg.get("auth", {}).get("initialized"):
            raise PocketError("not_initialized", "Initialize administrator credentials before activation", status=409)
        if shutil.disk_usage(self.context.root).free < 250 * 1048576:
            raise PocketError("insufficient_storage", "Service activation requires 250 MiB free storage", status=409)
        if service_id != "controller":
            request_wake_lock(True, policy=cfg.get("power", {}).get("wake_policy", "manual"), context=self.context)
        try:
            self.backend.start(service_id, cfg)
            result = self._wait(service_id, True, 30 if service_id == "tunnel" else 10)
            if result:
                self._errors.pop(service_id, None)
                return result
            raise PocketError("start_failed", "Service did not become ready within its deadline")
        except Exception as exc:
            self._errors[service_id] = redact_secrets(getattr(exc, "message", "Service activation failed"))
            try:
                self._stop(service_id)
            except PocketError:
                self._errors[service_id] = "Activation failed; shutdown could not be confirmed"
                raise PocketError("stop_failed", self._errors[service_id], status=503) from None
            if isinstance(exc, PocketError):
                raise
            raise PocketError("start_failed", "Service activation failed") from None
        finally:
            self._wake()
    def _start_publication(self):
        """Internal handoff after TunnelManager validates explicit publication."""
        self.context.ensure_mutable()
        with self._mutex, FileLock(self.context.root / "locks" / "maintenance.lock", shared=True), self._guard():
            if self.backend.name == "runit" and not self.status("controller")["ready"]:
                self._start("controller")
            return self._start("tunnel")
    def stop(self, service_id, timeout=5, *, maintenance_held=False):
        validate_service_id(service_id)
        # Shutdown is the documented exception: no new maintenance lease, so
        # completion/cancellation remains possible while an exclusive waiter waits.
        with self._mutex, self._guard(shutdown=True):
            return self._stop(service_id, timeout)
    def _stop(self, service_id, timeout=5):
        try:
            self.backend.stop(service_id)
            result = self._wait(service_id, False, min(5, max(0, timeout)))
            if not result:
                self.backend.stop(service_id, force=True)
                result = self._wait(service_id, False, 2)
            if not result:
                self._errors[service_id] = "Owned service termination is uncertain"
                raise PocketError("stop_failed", self._errors[service_id], status=503)
            from core.state import ReservationStore
            try:
                ReservationStore(self.context).release("listener:" + service_id)
            except PocketError as exc:
                if exc.code not in ("not_initialized", "recovery_required"):
                    raise
            return result
        finally:
            self._wake()
    def restart(self, service_id, *, maintenance_held=False):
        validate_service_id(service_id)
        if service_id == "tunnel":
            self.stop(service_id)
            raise PocketError("publication_required", "Tunnel stopped; fresh publication approval is required", status=409)
        self.context.ensure_mutable()
        lease = nullcontext() if maintenance_held else FileLock(self.context.root / "locks" / "maintenance.lock", shared=True)
        with self._mutex, lease, self._guard():
            self._stop(service_id)
            return self._start(service_id)
    def reconcile(self, *, startup=True, maintenance_held=False):
        """Do not publish or replay failed non-idempotent work on recovery."""
        self.context.ensure_mutable()
        lease = nullcontext() if maintenance_held else FileLock(self.context.root / "locks" / "maintenance.lock", shared=True)
        with self._mutex, lease, self._guard():
            # Publication never survives target loss or a controller recovery.
            tunnel = self.status("tunnel")
            if tunnel.get("owned") or tunnel["running"]:
                self._stop("tunnel")
            errors = {}
            if startup:
                cfg = self._cfg()
                for service_id in ("web", "api", "ssh", "dashboard"):
                    try:
                        current = self.status(service_id)
                        if self.backend.name == "runit" and current.get("owned"):
                            # Old activations cannot be inherited by a new epoch.
                            self._stop(service_id)
                        if service_config(cfg, service_id).get("autostart"):
                            self._start(service_id)
                    except PocketError as exc:
                        errors[service_id] = {"code": exc.code, "message": exc.message}
            return {"services": self.status_all(), "wake": self._wake(), "errors": errors}
    def get_logs(self, service_id, lines=100, redact=True):
        validate_service_id(service_id)
        if redact is not True:
            raise PocketError("invalid_request", "Raw logs require explicit owner filesystem access")
        path = self.paths["logs"] / (service_id + "-runit") / "current" if self.backend.name == "runit" else self.paths["logs"] / (service_id + ".log")
        check_path(path)
        return tail_log(path, lines)
