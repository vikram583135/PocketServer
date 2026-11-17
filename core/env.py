"""Read-only telemetry and explicit, honest wake requests."""
from __future__ import annotations
import json
import os
import shutil
import socket
import subprocess
import time
from pathlib import Path
_MOCK_WAKE_LOCK_STATE = False
_WAKE_RESULT = {"state": "unknown", "held": None, "source": "not_observable"}

def get_repo_root():
    return Path(__file__).resolve().parent.parent

def is_termux():
    return os.environ.get("POCKETSERVER_ENV", "auto").lower() != "mock" and os.environ.get("PREFIX", "").startswith("/data/data/com.termux")

def is_mock_mode():
    return not is_termux()

def get_base_dir():
    from core.runtime import RuntimeContext
    return RuntimeContext.discover().root

def get_runtime_paths():
    from core.runtime import RuntimeContext
    return RuntimeContext.discover().paths

def ensure_runtime_dirs():
    from core.runtime import RuntimeContext
    context = RuntimeContext.discover()
    context.initialize()
    return context.paths

def get_storage_metrics(path=None):
    target = Path(path) if path else get_base_dir()
    try:
        usage = shutil.disk_usage(target)
        return {"available": True, "total_mb": round(usage.total / 1048576, 1),
                "used_mb": round(usage.used / 1048576, 1), "free_mb": round(usage.free / 1048576, 1),
                "free_pct": round(100 * usage.free / usage.total, 1),
                "has_min_free_space": usage.free >= 250 * 1048576,
                "min_required_mb": 250, "path": str(target), "source": "shutil.disk_usage"}
    except OSError:
        return {"available": False, "total_mb": None, "used_mb": None, "free_mb": None,
                "free_pct": None, "has_min_free_space": None, "path": str(target), "source": "unavailable"}

def get_memory_metrics():
    try:
        values = {}
        with Path("/proc/meminfo").open(encoding="ascii") as source:
            for line in source:
                key, value = line.split(":", 1)
                values[key] = int(value.strip().split()[0])
        total, available = values["MemTotal"], values["MemAvailable"]
        return {"available": True, "total_mb": total / 1024, "available_mb": available / 1024,
                "used_mb": (total - available) / 1024, "used_pct": 100 * (total - available) / total,
                "source": "/proc/meminfo"}
    except (OSError, ValueError, KeyError):
        return {"available": False, "total_mb": None, "available_mb": None, "used_mb": None,
                "used_pct": None, "source": "unavailable"}

def get_network_ips():
    try:
        addresses = socket.gethostbyname_ex(socket.gethostname())[2]
    except OSError:
        addresses = []
    return {"lan_ip": next((ip for ip in addresses if not ip.startswith("127.")), None),
            "vpn_ip": None, "source": "hostname_resolution", "reachability": "unknown"}

def get_battery_thermal():
    command = shutil.which("termux-battery-status") if is_termux() else None
    if command:
        try:
            result = subprocess.run([command], capture_output=True, text=True, timeout=2, check=False)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                return {"available": True, "percentage": data.get("percentage"),
                        "temperature_c": data.get("temperature"), "status": data.get("status"),
                        "source": "termux-api"}
        except (OSError, subprocess.TimeoutExpired, ValueError):
            pass
    return {"available": False, "percentage": None, "temperature_c": None,
            "status": None, "source": "unavailable"}

def request_wake_lock(acquire, *, policy="manual", runner=None, termux=None, context=None):
    global _WAKE_RESULT
    runner = runner or subprocess.run
    def observed(value):
        global _WAKE_RESULT
        from core.supervisor import boot_id
        _WAKE_RESULT = {**value, "observed_at": time.time(), "boot_id": boot_id(),
                        "run_id": os.environ.get("POCKETSERVER_RUN_ID"), "policy": policy}
        if context is not None:
            from core.runtime import atomic_write
            atomic_write(context.paths["state"] / "wake.json", json.dumps(_WAKE_RESULT).encode())
        return dict(_WAKE_RESULT)
    if policy != "pocketserver-managed":
        return observed({"state": "unknown", "held": None, "source": "manual_policy"})
    command = shutil.which("termux-wake-lock" if acquire else "termux-wake-unlock") if (is_termux() if termux is None else termux) else None
    if not command:
        return observed({"state": "failed", "held": None, "source": "command_unavailable"})
    try:
        result = runner([command], capture_output=True, timeout=2, check=False)
        _WAKE_RESULT = {"state": ("requested" if acquire else "released") if result.returncode == 0 else "failed",
                        "held": None, "source": "command_exit", "returncode": result.returncode}
    except (OSError, subprocess.TimeoutExpired):
        _WAKE_RESULT = {"state": "failed", "held": None, "source": "command_error_or_timeout"}
    return observed(_WAKE_RESULT)

def acquire_wake_lock():
    return request_wake_lock(True)

def release_wake_lock():
    return request_wake_lock(False)

def is_wake_lock_active():
    return None

def get_system_metrics(context=None):
    from core.runtime import RuntimeContext
    context = context or RuntimeContext.discover()
    wake = {"state": "unknown", "held": None, "source": "not_observable"}
    path = context.paths["state"] / "wake.json"
    if path.exists():
        try:
            from core.runtime import read_private
            value = json.loads(read_private(path, 4096))
            if isinstance(value, dict):
                wake = {**value, "held": None}
        except (OSError, ValueError):
            pass
    return {"environment": context.mode, "base_dir": str(context.root),
            "storage": get_storage_metrics(context.root), "memory": get_memory_metrics(),
            "network": get_network_ips(), "battery": get_battery_thermal(),
            "wake_lock_active": None, "wake_lock": wake}

