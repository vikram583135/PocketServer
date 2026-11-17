"""Shared operations used by CLI, controller and authenticated thin routes."""
from __future__ import annotations

from core.config import ConfigManager
from core.errors import PocketError
from core.runtime import RuntimeContext
from core.state import OperationsStore, ReservationStore, StateStore
from core.supervisor import Supervisor


class Application:
    def __init__(self, context=None, *, backend=None):
        self.context = context or RuntimeContext.discover()
        self.config = ConfigManager(context=self.context)
        self.supervisor = Supervisor(config_manager=self.config, context=self.context, backend=backend)
        self.operations = OperationsStore(self.context)

    def initialize(self, password):
        result = self.config.initialize(password)
        StateStore(self.context).initialize()
        return result

    @property
    def vault(self):
        from core.storage import FileVault
        return FileVault(self.context)

    @property
    def backups(self):
        from core.backups import BackupManager
        return BackupManager(self.context, config=self.config, supervisor=self.supervisor)

    @property
    def ssh_git(self):
        from core.ssh_git import SSHGitManager
        return SSHGitManager(self.context, config=self.config)

    @property
    def jobs(self):
        from core.jobs import JobManager
        return JobManager(self.context, config=self.config)

    @property
    def tunnel(self):
        from core.tunnel import TunnelManager
        return TunnelManager(self.context, supervisor=self.supervisor, config=self.config)

    def status(self):
        from core.env import get_system_metrics
        config = self.config.get_config()
        services = self.supervisor.status()
        for identifier, observed in services.items():
            observed["publication_allowed"] = identifier in {"web", "api"} and observed.get("owned", False) and observed.get("ready", False) and not observed.get("restart_required", False)
        return {"mode": self.context.mode, "simulated": self.context.mode == "mock",
                "config_revision": config["revision"], "services": services,
                "controller": services.get("controller", {}), "tunnel": self.tunnel.status(),
                "telemetry": get_system_metrics(context=self.context),
                "power_policy": config["power"]["wake_policy"],
                "capabilities": self.capabilities()}

    def capabilities(self):
        import shutil
        from core.storage import secure_filesystem_available
        return {"files": {"available": secure_filesystem_available(), "reason": "Descriptor confinement requires supported POSIX operations."},
                "git": {"available": bool(shutil.which("git"))},
                "ssh": {"available": bool(shutil.which("sshd") and shutil.which("ssh-keygen"))},
                "tunnel": {"available": bool(shutil.which("cloudflared"))},
                "workers": {"available": self.context.mode == "termux"}}

    def queue(self, action, target, payload=None, *, actor="dashboard", idempotency_key=None):
        self.context.ensure_mutable()
        controller = self.supervisor.status("controller")
        if not controller.get("running"):
            raise PocketError("unsupported", "The operation controller is not running; start it locally.", 503)
        return self.operations.enqueue(action, target, payload, actor, idempotency_key)

    def execute_operation(self, operation):
        action, target = operation["action"], operation["target"]
        payload = operation.get("payload") or {}
        if action in {"start", "stop", "restart"}:
            if operation.get("actor") == "dashboard" and target in {"dashboard", "controller", "all", "tunnel"}:
                raise PocketError("invalid_input", "That lifecycle action is local-only.", 403)
            return getattr(self.supervisor, action)(target)
        if action == "backup":
            return self.backups.create(external_writers_stopped=payload.get("acknowledge_external_writers") is True)
        if action == "tunnel_start":
            return self.tunnel.start(payload.get("target_service"), acknowledge_public=payload.get("acknowledge_public", False))
        if action == "tunnel_stop":
            return self.tunnel.stop()
        if action == "job_run":
            return self.jobs.run(target, parameters=payload.get("parameters", {}), run_id=operation["id"])
        raise PocketError("invalid_input", "Unknown queued operation.", 400)

    def configure_service(self, identifier, changes, revision):
        if identifier not in {"dashboard", "web", "api", "ssh"}:
            raise PocketError("invalid_input", "This service has no remotely editable configuration.", 400)
        if not isinstance(changes, dict) or not changes or set(changes) - {"port", "bind_address", "autostart"}:
            raise PocketError("invalid_input", "Unexpected configuration fields.", 400)
        current = self.config.get_config()
        if type(revision) is not int or revision != current["revision"]:
            raise PocketError("conflict", "Configuration changed. Refresh before editing.", 409)
        from core.config import validate_config
        import copy
        candidate = copy.deepcopy(current)
        candidate_target = candidate["dashboard"] if identifier == "dashboard" else candidate["services"][identifier]
        candidate_target.update(changes)
        validate_config(candidate)
        previous = current["dashboard"] if identifier == "dashboard" else current["services"][identifier]
        changed_endpoint = any(key in changes and changes[key] != previous[key] for key in ("port", "bind_address"))
        # Invalid or stale edits have no publication side effects. A committed
        # target change must revoke publication before reporting success.
        result = self.config.update_service(identifier, changes, expected_revision=revision)
        if changed_endpoint and identifier in {"web", "api"}:
            self.tunnel.stop_if_target(identifier)
        return {"config_revision": self.config.get_config()["revision"],
                "restart_required": changed_endpoint and self.supervisor.status(identifier).get("running", False)}
