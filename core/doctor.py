"""PocketServer Diagnostics, Boot Integration & Backup Engine.

Implements system doctor checks (CHK-ENV, CHK-DISK, CHK-DEPS, CHK-WAKE,
CHK-PHANTOM, CHK-PORTS, CHK-BOOT), Termux:Boot automation, and
secure .tar.gz backup & restore capabilities.
"""

from __future__ import annotations

import datetime
import os
import shutil
import socket
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import ConfigManager
from core.env import (
    ensure_runtime_dirs,
    get_base_dir,
    get_runtime_paths,
    get_storage_metrics,
    is_mock_mode,
    is_termux,
    is_wake_lock_active,
)
from core.services import SERVICE_PROFILES, check_tcp_port

PHANTOM_KILLER_ADB_COMMAND = (
    'adb shell "/system/bin/device_config set_sync_disabled_for_tests persistent; '
    '/system/bin/device_config put activity_manager max_phantom_processes 2147483647"'
)


def get_android_sdk_version() -> Optional[int]:
    """Retrieve Android SDK version using getprop if running on Android."""
    getprop = shutil.which("getprop")
    if not getprop:
        return None

    try:
        res = subprocess.run([getprop, "ro.build.version.sdk"], capture_output=True, text=True, timeout=2.0)
        val = res.stdout.strip()
        if val.isdigit():
            return int(val)
    except Exception:
        pass
    return None


def run_diagnostics(config_manager: Optional[ConfigManager] = None) -> Dict[str, Any]:
    """Run comprehensive diagnostics covering all failure modes and OS limits."""
    ensure_runtime_dirs()
    cfg_mgr = config_manager or ConfigManager()
    cfg = cfg_mgr.get_config()
    paths = get_runtime_paths()

    checks: List[Dict[str, Any]] = []

    # -------------------------------------------------------------------------
    # 1. CHK-ENV: Termux Environment Verification
    # -------------------------------------------------------------------------
    if is_termux():
        prefix = os.environ.get("PREFIX", "")
        if prefix.startswith("/data/data/com.termux"):
            checks.append({
                "id": "CHK-ENV",
                "name": "Termux Environment",
                "status": "PASS",
                "message": f"Valid Termux installation ({prefix})",
                "remediation": None,
            })
        else:
            checks.append({
                "id": "CHK-ENV",
                "name": "Termux Environment",
                "status": "WARN",
                "message": f"Non-standard Termux prefix detected: {prefix}",
                "remediation": "Ensure Termux was installed from F-Droid or GitHub Releases, not Google Play.",
            })
    else:
        checks.append({
            "id": "CHK-ENV",
            "name": "Environment Mode",
            "status": "PASS",
            "message": f"Running in Antigravity Mock Mode ({paths['base']})",
            "remediation": None,
        })

    # -------------------------------------------------------------------------
    # 2. CHK-DISK: Storage Headroom Threshold (>= 250 MB)
    # -------------------------------------------------------------------------
    storage = get_storage_metrics()
    if storage["has_min_free_space"]:
        checks.append({
            "id": "CHK-DISK",
            "name": "Storage Space",
            "status": "PASS",
            "message": f"{storage['free_mb']} MB free ({storage['free_pct']}% available)",
            "remediation": None,
        })
    else:
        checks.append({
            "id": "CHK-DISK",
            "name": "Storage Space",
            "status": "FAIL",
            "message": f"Low storage space: only {storage['free_mb']} MB free. Minimum required is 250 MB.",
            "remediation": "Free up storage on device to prevent process crashes or database corruption.",
        })

    # -------------------------------------------------------------------------
    # 3. CHK-DEPS: Essential Binaries Check
    # -------------------------------------------------------------------------
    missing_deps: List[str] = []
    py_bin = shutil.which("python3") or shutil.which("python")
    git_bin = shutil.which("git")
    ssh_bin = shutil.which("sshd")

    if not py_bin:
        missing_deps.append("python")
    if not git_bin:
        missing_deps.append("git")
    if is_termux() and not ssh_bin:
        missing_deps.append("openssh")

    if not missing_deps:
        checks.append({
            "id": "CHK-DEPS",
            "name": "Package Dependencies",
            "status": "PASS",
            "message": "All required binaries are installed (Python, Git, OpenSSH)",
            "remediation": None,
        })
    else:
        checks.append({
            "id": "CHK-DEPS",
            "name": "Package Dependencies",
            "status": "WARN" if not is_termux() else "FAIL",
            "message": f"Missing recommended binaries: {', '.join(missing_deps)}",
            "remediation": f"Install missing packages: pkg install -y {' '.join(missing_deps)}",
        })

    # -------------------------------------------------------------------------
    # 4. CHK-WAKE: Wake-Lock State & Battery Optimization
    # -------------------------------------------------------------------------
    # Check if any services are active
    active_pids = list(paths["pids"].glob("*.pid"))
    wake_active = is_wake_lock_active()

    if active_pids and not wake_active:
        checks.append({
            "id": "CHK-WAKE",
            "name": "Background Wake-Lock",
            "status": "WARN",
            "message": f"{len(active_pids)} service(s) running, but wake-lock is inactive.",
            "remediation": "Run 'termux-wake-lock' and disable Android Battery Optimization for Termux in Settings.",
        })
    elif wake_active:
        checks.append({
            "id": "CHK-WAKE",
            "name": "Background Wake-Lock",
            "status": "PASS",
            "message": "Wake-lock is active (CPU sleep disabled for background servers)",
            "remediation": None,
        })
    else:
        checks.append({
            "id": "CHK-WAKE",
            "name": "Background Wake-Lock",
            "status": "PASS",
            "message": "Idle (no services currently running)",
            "remediation": None,
        })

    # -------------------------------------------------------------------------
    # 5. CHK-PHANTOM: Android 12+ Phantom Process Killer
    # -------------------------------------------------------------------------
    sdk_ver = get_android_sdk_version()
    if sdk_ver and sdk_ver >= 31:
        checks.append({
            "id": "CHK-PHANTOM",
            "name": "Phantom Process Killer (Android 12+)",
            "status": "WARN",
            "message": f"Android SDK {sdk_ver} detected. Android kills background apps exceeding 32 child processes.",
            "remediation": f"Run this command via Wireless ADB or computer terminal to disable the killer:\n{PHANTOM_KILLER_ADB_COMMAND}",
        })
    else:
        checks.append({
            "id": "CHK-PHANTOM",
            "name": "Phantom Process Killer",
            "status": "PASS",
            "message": "Android SDK < 31 or running in mock environment (Phantom Killer not active)",
            "remediation": None,
        })

    # -------------------------------------------------------------------------
    # 6. CHK-PORTS: Port Collision Probes
    # -------------------------------------------------------------------------
    ports_to_probe = [
        ("dashboard", cfg.get("dashboard", {}).get("port", 8888)),
        ("web", cfg.get("services", {}).get("web", {}).get("port", 8080)),
        ("api", cfg.get("services", {}).get("api", {}).get("port", 8081)),
        ("ssh", cfg.get("services", {}).get("ssh", {}).get("port", 8022)),
    ]

    port_collisions: List[str] = []
    for s_name, p_num in ports_to_probe:
        pid_file = paths["pids"] / f"{s_name}.pid"
        is_service_running = pid_file.exists()
        is_port_occupied = check_tcp_port("127.0.0.1", p_num, timeout=0.5)

        # Collision occurs if port is in use but NOT by our own running service
        if is_port_occupied and not is_service_running:
            port_collisions.append(f"{s_name} ({p_num})")

    if not port_collisions:
        checks.append({
            "id": "CHK-PORTS",
            "name": "Port Availability",
            "status": "PASS",
            "message": "No port collisions detected for configured services",
            "remediation": None,
        })
    else:
        checks.append({
            "id": "CHK-PORTS",
            "name": "Port Availability",
            "status": "WARN",
            "message": f"Port(s) occupied by external processes: {', '.join(port_collisions)}",
            "remediation": "Change ports in config.json or terminate colliding external processes.",
        })

    # -------------------------------------------------------------------------
    # 7. CHK-BOOT: Termux:Boot Auto-Start Script
    # -------------------------------------------------------------------------
    boot_script_path = get_boot_script_path()
    if boot_script_path.exists():
        checks.append({
            "id": "CHK-BOOT",
            "name": "Auto-Start on Boot",
            "status": "PASS",
            "message": f"Boot script installed ({boot_script_path})",
            "remediation": None,
        })
    else:
        checks.append({
            "id": "CHK-BOOT",
            "name": "Auto-Start on Boot",
            "status": "INFO",
            "message": "Termux:Boot script not installed (manual start required after phone reboot)",
            "remediation": "Run 'python pocketctl.py doctor --fix-boot' to generate the boot script.",
        })

    # -------------------------------------------------------------------------
    # Summary Rollup
    # -------------------------------------------------------------------------
    pass_count = sum(1 for c in checks if c["status"] == "PASS")
    warn_count = sum(1 for c in checks if c["status"] == "WARN")
    fail_count = sum(1 for c in checks if c["status"] == "FAIL")
    info_count = sum(1 for c in checks if c["status"] == "INFO")

    overall = "HEALTHY"
    if fail_count > 0:
        overall = "CRITICAL"
    elif warn_count > 0:
        overall = "WARNING"

    return {
        "status": overall,
        "pass_count": pass_count,
        "warn_count": warn_count,
        "fail_count": fail_count,
        "info_count": info_count,
        "total_checks": len(checks),
        "checks": checks,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def get_boot_script_path() -> Path:
    """Return the platform-appropriate path for the Termux:Boot script."""
    if is_mock_mode():
        return get_base_dir() / "boot" / "start-pocketserver.sh"
    return Path.home() / ".termux" / "boot" / "start-pocketserver.sh"


def install_boot_script() -> Path:
    """Generate and install the Termux:Boot auto-start script."""
    boot_script = get_boot_script_path()
    boot_script.parent.mkdir(parents=True, exist_ok=True)

    repo_dir = Path(__file__).resolve().parent.parent
    ctl_path = repo_dir / "pocketctl.py"

    content = f"""#!/data/data/com.termux/files/usr/bin/sh
# PocketServer Auto-Start Script (Termux:Boot)
termux-wake-lock
python3 "{ctl_path}" start dashboard
"""
    boot_script.write_text(content, encoding="utf-8")
    try:
        os.chmod(boot_script, 0o755)
    except OSError:
        pass

    return boot_script


# -----------------------------------------------------------------------------
# Secure Backup & Restore Engine
# -----------------------------------------------------------------------------

def create_backup(output_dir: Optional[Path] = None) -> Path:
    """Create a compressed .tar.gz archive of configuration, data, and keys."""
    ensure_runtime_dirs()
    paths = get_runtime_paths()
    target_dir = output_dir or paths["backups"]
    target_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    archive_name = f"pocketserver-backup-{timestamp}.tar.gz"
    archive_path = target_dir / archive_name

    items_to_backup = [
        paths["config_file"],
        paths["secret_file"],
        paths["www"],
        paths["api"],
        paths["git"],
        paths["jobs"],
    ]

    base_dir = paths["base"]
    with tarfile.open(archive_path, "w:gz") as tar:
        for item in items_to_backup:
            if item.exists():
                arcname = item.relative_to(base_dir)
                tar.add(item, arcname=str(arcname))

    return archive_path


def restore_backup(archive_path: Path) -> Dict[str, Any]:
    """Safely restore a .tar.gz backup with strict path traversal prevention."""
    if not archive_path.exists():
        raise FileNotFoundError(f"Backup archive not found: {archive_path}")

    paths = get_runtime_paths()
    base_dir = paths["base"].resolve()

    restored_files: List[str] = []

    with tarfile.open(archive_path, "r:gz") as tar:
        # Security Gate: verify no member escapes base_dir (Zip-Slip defense)
        for member in tar.getmembers():
            target_path = (base_dir / member.name).resolve()
            if not str(target_path).startswith(str(base_dir) + os.sep) and target_path != base_dir:
                raise ValueError(f"Security Alert: Malicious archive member escapes base directory: {member.name}")

        # Safe extraction
        for member in tar.getmembers():
            tar.extract(member, path=base_dir)
            restored_files.append(member.name)

    # Re-validate configuration after restoration
    cfg_mgr = ConfigManager()
    cfg_mgr.load()

    return {
        "success": True,
        "restored_count": len(restored_files),
        "restored_files": restored_files,
        "archive": str(archive_path),
    }

