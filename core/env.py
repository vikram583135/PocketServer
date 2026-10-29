"""PocketServer Environment & Hardware Telemetry.

Zero-compilation, non-root Termux compliant environment detection,
runtime directory management, hardware metrics, and wake-lock controls.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

# Track wake-lock state in-memory (and in state file for persistence)
_MOCK_WAKE_LOCK_STATE: bool = False


def get_repo_root() -> Path:
    """Return the absolute path to the PocketServer repository root."""
    return Path(__file__).resolve().parent.parent


def is_termux() -> bool:
    """Check if currently running inside a real Termux environment."""
    if os.environ.get("POCKETSERVER_ENV", "").lower() == "mock":
        return False

    prefix = os.environ.get("PREFIX", "")
    has_termux_prefix = prefix.startswith("/data/data/com.termux")
    has_pkg = shutil.which("pkg") is not None
    return has_termux_prefix and has_pkg


def is_mock_mode() -> bool:
    """Check if running in Antigravity IDE / developer mock mode."""
    return not is_termux()


def get_base_dir() -> Path:
    """Return the base runtime directory for PocketServer data & config."""
    if is_mock_mode():
        return get_repo_root() / ".mock_termux" / "home" / ".pocketserver"
    return Path.home() / ".pocketserver"


def get_runtime_paths() -> Dict[str, Path]:
    """Return a dictionary of all critical PocketServer runtime paths."""
    base = get_base_dir()
    return {
        "base": base,
        "config_file": base / "config.json",
        "secret_file": base / "secret.key",
        "pids": base / "pids",
        "logs": base / "logs",
        "data": base / "data",
        "www": base / "data" / "www",
        "api": base / "data" / "api",
        "files": base / "data" / "files",
        "git": base / "data" / "git",
        "jobs": base / "data" / "jobs",
        "backups": base / "backups",
        "state_wake_lock": base / "pids" / "wake_lock.state",
    }


def ensure_runtime_dirs() -> Dict[str, Path]:
    """Ensure all required runtime directories exist with appropriate permissions."""
    paths = get_runtime_paths()
    dirs_to_create = [
        paths["base"],
        paths["pids"],
        paths["logs"],
        paths["data"],
        paths["www"],
        paths["api"],
        paths["files"],
        paths["git"],
        paths["jobs"],
        paths["backups"],
    ]
    for d in dirs_to_create:
        d.mkdir(parents=True, exist_ok=True)
    return paths


def get_storage_metrics(path: Optional[Path] = None) -> Dict[str, Any]:
    """Gather storage space metrics using os-level statvfs/disk_usage.

    Requires at least 250 MB free space for healthy operation.
    """
    target_path = str(path or get_base_dir())
    try:
        # shutil.disk_usage works on Windows, Linux, and Android
        usage = shutil.disk_usage(target_path)
        total_mb = round(usage.total / (1024 * 1024), 1)
        free_mb = round(usage.free / (1024 * 1024), 1)
        used_mb = round(usage.used / (1024 * 1024), 1)
        free_pct = round((usage.free / usage.total) * 100, 1) if usage.total > 0 else 0.0
        has_min_free = free_mb >= 250.0

        return {
            "total_mb": total_mb,
            "used_mb": used_mb,
            "free_mb": free_mb,
            "free_pct": free_pct,
            "has_min_free_space": has_min_free,
            "min_required_mb": 250.0,
            "path": target_path,
        }
    except Exception as e:
        return {
            "total_mb": 0.0,
            "used_mb": 0.0,
            "free_mb": 0.0,
            "free_pct": 0.0,
            "has_min_free_space": False,
            "error": str(e),
            "path": target_path,
        }


def get_memory_metrics() -> Dict[str, Any]:
    """Read memory metrics from /proc/meminfo (safe on all Android versions).

    Falls back to mock telemetry when running in Mock / Windows environments.
    """
    meminfo_path = Path("/proc/meminfo")
    if meminfo_path.exists():
        try:
            mem_data: Dict[str, int] = {}
            with open(meminfo_path, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val_str = parts[1].strip().split()[0]
                        if val_str.isdigit():
                            mem_data[key] = int(val_str)

            total_kb = mem_data.get("MemTotal", 0)
            avail_kb = mem_data.get("MemAvailable", 0)

            # Fallback for older kernels without MemAvailable
            if avail_kb == 0 and "MemFree" in mem_data:
                free_kb = mem_data.get("MemFree", 0)
                buffers_kb = mem_data.get("Buffers", 0)
                cached_kb = mem_data.get("Cached", 0)
                avail_kb = free_kb + buffers_kb + cached_kb

            total_mb = round(total_kb / 1024, 1)
            avail_mb = round(avail_kb / 1024, 1)
            used_mb = round(total_mb - avail_mb, 1)
            used_pct = round((used_mb / total_mb) * 100, 1) if total_mb > 0 else 0.0

            return {
                "total_mb": total_mb,
                "available_mb": avail_mb,
                "used_mb": used_mb,
                "used_pct": used_pct,
                "source": "/proc/meminfo",
            }
        except Exception as e:
            return {
                "total_mb": 0.0,
                "available_mb": 0.0,
                "used_mb": 0.0,
                "used_pct": 0.0,
                "error": str(e),
                "source": "error",
            }

    # Mock mode fallback (e.g. Windows / IDE container without /proc/meminfo)
    return {
        "total_mb": 4096.0,
        "available_mb": 2048.0,
        "used_mb": 2048.0,
        "used_pct": 50.0,
        "source": "mock",
    }


def get_network_ips() -> Dict[str, Optional[str]]:
    """Determine the LAN IP and optional Tailscale/VPN IP without external traffic."""
    lan_ip = "127.0.0.1"
    vpn_ip: Optional[str] = None

    # Determine primary outbound LAN IP using a dummy UDP connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        # Using 10.255.255.255 doesn't send packets but forces OS routing table resolution
        s.connect(("10.255.255.255", 1))
        resolved_ip = s.getsockname()[0]
        if resolved_ip and not resolved_ip.startswith("127."):
            lan_ip = resolved_ip
        s.close()
    except Exception:
        pass

    # Attempt to detect VPN / Tailscale IP (e.g. 100.64.0.0/10 CGNAT range)
    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if ip.startswith("100."):
                vpn_ip = ip
                break
    except Exception:
        pass

    return {
        "lan_ip": lan_ip,
        "vpn_ip": vpn_ip,
    }


def get_battery_thermal() -> Dict[str, Any]:
    """Gather battery & thermal status via Termux API if installed."""
    if not is_termux():
        return {
            "available": False,
            "status": "Mock Mode (AC Connected)",
            "percentage": 100,
            "temperature_c": 30.0,
        }

    cmd = shutil.which("termux-battery-status")
    if not cmd:
        return {
            "available": False,
            "message": "N/A (Install termux-api)",
        }

    try:
        res = subprocess.run([cmd], capture_output=True, text=True, timeout=2.0)
        if res.returncode == 0 and res.stdout.strip():
            data = json.loads(res.stdout)
            return {
                "available": True,
                "percentage": data.get("percentage"),
                "status": data.get("status"),
                "temperature_c": data.get("temperature"),
                "plugged": data.get("plugged"),
            }
    except Exception as e:
        return {
            "available": False,
            "message": f"Error querying battery: {e}",
        }

    return {
        "available": False,
        "message": "N/A (Install termux-api)",
    }


def acquire_wake_lock() -> bool:
    """Acquire Android wake-lock to prevent CPU sleep when servers run."""
    global _MOCK_WAKE_LOCK_STATE
    ensure_runtime_dirs()
    state_file = get_runtime_paths()["state_wake_lock"]

    if is_termux():
        cmd = shutil.which("termux-wake-lock")
        if cmd:
            try:
                subprocess.run([cmd], capture_output=True, timeout=2.0)
                state_file.write_text("active", encoding="utf-8")
                return True
            except Exception:
                return False
        return False

    # Mock mode
    _MOCK_WAKE_LOCK_STATE = True
    state_file.write_text("active_mock", encoding="utf-8")
    return True


def release_wake_lock() -> bool:
    """Release Android wake-lock when all services are stopped."""
    global _MOCK_WAKE_LOCK_STATE
    state_file = get_runtime_paths()["state_wake_lock"]

    if is_termux():
        cmd = shutil.which("termux-wake-unlock")
        if cmd:
            try:
                subprocess.run([cmd], capture_output=True, timeout=2.0)
                if state_file.exists():
                    state_file.unlink(missing_ok=True)
                return True
            except Exception:
                return False
        return False

    # Mock mode
    _MOCK_WAKE_LOCK_STATE = False
    if state_file.exists():
        state_file.unlink(missing_ok=True)
    return True


def is_wake_lock_active() -> bool:
    """Check if wake lock is currently recorded as active."""
    global _MOCK_WAKE_LOCK_STATE
    state_file = get_runtime_paths()["state_wake_lock"]
    if is_termux():
        return state_file.exists()
    return _MOCK_WAKE_LOCK_STATE or state_file.exists()


def get_system_metrics() -> Dict[str, Any]:
    """Aggregate complete hardware, network, and environment telemetry."""
    ensure_runtime_dirs()
    return {
        "environment": "termux" if is_termux() else "mock",
        "base_dir": str(get_base_dir()),
        "storage": get_storage_metrics(),
        "memory": get_memory_metrics(),
        "network": get_network_ips(),
        "battery": get_battery_thermal(),
        "wake_lock_active": is_wake_lock_active(),
    }

