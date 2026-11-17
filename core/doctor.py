"""Read-only diagnostics with evidence and explicit uncertainty."""
from __future__ import annotations
import importlib.util
import shutil
import sys
import time
from core.config import ConfigManager
from core.env import get_storage_metrics, get_system_metrics
from core.errors import PocketError
from core.runtime import RuntimeContext, check_private
from core.supervisor import Supervisor

def run_diagnostics(config_manager=None, context=None, supervisor=None):
    context = context or getattr(config_manager, "context", None) or RuntimeContext.discover()
    manager = config_manager or ConfigManager(context)
    checks = []
    def add(identifier, state, evidence, remediation="", required=True):
        checks.append({"id": identifier, "state": state, "status": state, "required": required,
                       "evidence": evidence, "observation_time": time.time(), "remediation": remediation})
    add("runtime.python", "PASS" if sys.version_info >= (3, 11) else "FAIL", sys.version.split()[0], "Use a qualified Python 3.11+ interpreter.")
    add("runtime.mode", "WARN" if context.mode == "mock" else "PASS",
        "Mock has invocation-local service state." if context.mode == "mock" else "Termux selected.",
        "Physical Termux qualification remains required.", required=False)
    for package in ("flask", "werkzeug", "waitress", "sqlite3"):
        add("dependency." + package, "PASS" if importlib.util.find_spec(package) else "FAIL",
            "Import specification inspected.", "Install the vetted offline dependencies.")
    cfg = None
    try:
        cfg = manager.get_config()
        add("config.schema", "PASS", {"schema": cfg["schema_version"], "revision": cfg["revision"]})
        add("credentials", "PASS" if manager.is_initialized() else "FAIL", "Credential policy validated without disclosing values.", "Initialize locally.")
        manager.get_or_create_secret_key()
        add("credentials.signing_key", "PASS", "Existing key shape and private storage checked.")
        for directory in context.directories():
            check_private(directory, directory=True)
        add("runtime.permissions", "PASS" if context.mode == "termux" else "WARN",
            "Runtime paths checked; POSIX privacy applies only on POSIX.", required=context.mode == "termux")
    except PocketError as exc:
        add("config.schema", "FAIL", exc.code, exc.message)
    except OSError:
        add("runtime.permissions", "FAIL", "A required runtime entry is unavailable.", "Run explicit local recovery.")
    pending = context.pending_recovery()
    add("recovery", "FAIL" if pending else "PASS", {"pending": len(pending)}, "Run local recover." if pending else "")
    storage = get_storage_metrics(context.root)
    add("storage.headroom", "PASS" if storage["has_min_free_space"] else ("FAIL" if storage["available"] else "UNKNOWN"),
        storage, "Keep at least 250 MiB available.")
    if cfg:
        status = (supervisor or Supervisor(manager, context)).status()
        if context.mode == "termux":
            for command in ("sv", "runsv", "svlogd", "service-daemon"):
                add("runit." + command, "PASS" if shutil.which(command) else "FAIL", "Executable availability.", "Install and qualify termux-services locally.")
            add("controller.readiness", "PASS" if status["controller"]["ready"] else "FAIL",
                status["controller"], "Install owned runit entries and start the controller.")
        else:
            add("runit", "NOT_APPLICABLE", "Windows/POSIX mock does not claim detached background control.", required=False)
        log_files = list(context.paths["logs"].rglob("*"))
        log_bytes = sum(path.stat().st_size for path in log_files if path.is_file() and not path.is_symlink())
        add("logs.budget", "PASS" if log_bytes <= cfg["logs"]["total_bytes"] else "FAIL",
            {"bytes": log_bytes, "budget": cfg["logs"]["total_bytes"]}, "Inspect retained logs and configured budgets.")
        add("wake.policy", "PASS", {"policy": cfg["power"]["wake_policy"], "os_held": None},
            "Wake requests do not establish OS-held lock ownership.", required=False)
    add("android.background", "UNKNOWN" if context.mode == "termux" else "NOT_APPLICABLE",
        "Doze/OEM/force-stop behavior needs physical-device evidence.", "Run the release device matrix.", required=False)
    add("boot.reboot_evidence", "UNKNOWN", "Script setup is not a recorded reboot test.", "Record an actual reboot test.", required=False)
    failed = any(item["required"] and item["state"] == "FAIL" for item in checks)
    return {"ok": not failed, "checks": checks, "mode": context.mode, "observation_time": time.time()}

def create_backup(config_manager=None):
    from core.backups import BackupManager
    manager = config_manager or ConfigManager()
    return BackupManager(manager.context, config=manager).create()

def restore_backup(archive, config_manager=None):
    from core.backups import BackupManager
    manager = config_manager or ConfigManager()
    return BackupManager(manager.context, config=manager).restore(archive, apply=False)

def install_boot_script(config_manager=None):
    from core.boot import install_boot
    manager = config_manager or ConfigManager()
    return install_boot(manager.context)

