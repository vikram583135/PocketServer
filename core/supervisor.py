"""PocketServer Process Supervisor & Lifecycle Engine.

Provides process lifecycle management (start, stop, restart, status),
stale PID detection via /proc/{pid}/cmdline (Linux/Android) and QueryFullProcessImageName (Windows),
bounded 1MB log rotation, secret redaction, and automatic wake-lock coordination.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.config import ConfigManager
from core.env import (
    acquire_wake_lock,
    ensure_runtime_dirs,
    get_runtime_paths,
    is_termux,
    release_wake_lock,
)
from core.services import SERVICE_PROFILES, check_tcp_port, seed_default_payloads

MAX_LOG_SIZE_BYTES = 1024 * 1024  # 1 MB boundary
MAX_LOG_BACKUPS = 2

# Regex patterns for redacting sensitive credentials in logs
SECRET_PATTERNS = [
    (re.compile(r"(--token\s+)([^\s]+)", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(token=)([^\s&]+)", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Bearer\s+)([a-zA-Z0-9_\-\.]+)", re.IGNORECASE), r"\1[REDACTED_BEARER]"),
    (re.compile(r"(password[=:\s]+)([^\s,;]+)", re.IGNORECASE), r"\1[REDACTED_PASSWORD]"),
    (re.compile(r"(pbkdf2:sha256:[a-zA-Z0-9$]+)", re.IGNORECASE), r"[REDACTED_HASH]"),
]


def redact_secrets(text: str) -> str:
    """Sanitize sensitive credentials, tokens, and hashes from log text."""
    redacted = text
    for pattern, replacement in SECRET_PATTERNS:
        redacted = pattern.sub(replacement, redacted)
    return redacted


def rotate_log_file(log_path: Path, max_bytes: int = MAX_LOG_SIZE_BYTES, max_backups: int = MAX_LOG_BACKUPS) -> None:
    """Rotate log file if it exceeds the specified maximum byte boundary."""
    if not log_path.exists():
        return

    try:
        if log_path.stat().st_size >= max_bytes:
            for i in range(max_backups - 1, 0, -1):
                src = log_path.with_name(f"{log_path.name}.{i}")
                dst = log_path.with_name(f"{log_path.name}.{i + 1}")
                if src.exists():
                    os.replace(src, dst)
            backup_1 = log_path.with_name(f"{log_path.name}.1")
            os.replace(log_path, backup_1)
    except OSError:
        pass


def _get_process_name_windows(pid: int) -> Optional[str]:
    """Retrieve full process image path on Windows using ctypes without external libraries."""
    try:
        import ctypes
        from ctypes import wintypes

        kernel32 = ctypes.windll.kernel32
        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        if not handle:
            return None

        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        success = kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size))
        kernel32.CloseHandle(handle)
        if success:
            return buf.value
    except Exception:
        pass
    return None


def _kill_process_windows(pid: int) -> bool:
    """Terminate process forcefully on Windows using ctypes."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_TERMINATE = 0x0001
        handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
        if not handle:
            return False
        ret = kernel32.TerminateProcess(handle, 1)
        kernel32.CloseHandle(handle)
        return bool(ret)
    except Exception:
        return False


class Supervisor:
    """Supervises PocketServer background services."""

    def __init__(self, config_manager: Optional[ConfigManager] = None) -> None:
        self.config_manager = config_manager or ConfigManager()
        self.paths = get_runtime_paths()
        ensure_runtime_dirs()
        seed_default_payloads()

    def _get_pid_file(self, service_id: str) -> Path:
        return self.paths["pids"] / f"{service_id}.pid"

    def _get_state_file(self, service_id: str) -> Path:
        return self.paths["pids"] / f"{service_id}.json"

    def _get_log_file(self, service_id: str) -> Path:
        return self.paths["logs"] / f"{service_id}.log"

    def _is_process_alive(self, pid: int, expected_bin: str) -> bool:
        """Verify process existence and validate against recycled PID collisions."""
        if pid <= 0:
            return False

        # 1. Base OS signal check
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, OSError):
            return False

        # 2. Windows-specific validation via QueryFullProcessImageName
        if sys.platform == "win32":
            img_path = _get_process_name_windows(pid)
            if img_path is None:
                return False
            if expected_bin.lower() not in img_path.lower():
                return False
            return True

        # 3. Linux / Termux validation via /proc/{pid}/cmdline to prevent recycled PID collision
        proc_cmdline = Path(f"/proc/{pid}/cmdline")
        if proc_cmdline.exists():
            try:
                raw = proc_cmdline.read_bytes().replace(b"\x00", b" ").decode("utf-8", errors="ignore")
                if expected_bin.lower() not in raw.lower():
                    # Process exists but is an unrelated program that reused this PID
                    return False
            except Exception:
                return False

        return True

    def start(self, service_id: str) -> Dict[str, Any]:
        """Start a service in the background with bounded logging and wake-lock."""
        if service_id not in SERVICE_PROFILES:
            raise ValueError(f"Unknown service '{service_id}'. Available: {list(SERVICE_PROFILES.keys())}")

        profile = SERVICE_PROFILES[service_id]
        cfg = self.config_manager.get_config()

        # Check if already running
        cur_status = self.status(service_id)
        if cur_status["running"]:
            return cur_status

        # Port conflict check
        port = None
        bind_addr = "127.0.0.1"
        if service_id == "dashboard":
            port = cfg.get("dashboard", {}).get("port", 8888)
            bind_addr = cfg.get("dashboard", {}).get("bind_address", "127.0.0.1")
        elif service_id in cfg.get("services", {}):
            s_cfg = cfg["services"][service_id]
            port = s_cfg.get("port")
            bind_addr = s_cfg.get("bind_address", "127.0.0.1")

        if port and check_tcp_port(bind_addr, port):
            raise RuntimeError(f"Cannot start '{service_id}': port {port} ({bind_addr}) is already in use.")

        # Ensure bounded log rotation
        log_file = self._get_log_file(service_id)
        rotate_log_file(log_file)

        # Build execution command (strictly shell=False)
        cmd = profile.command_builder(cfg, self.paths)

        # Launch process
        log_handle = open(log_file, "a", encoding="utf-8")
        try:
            kwargs: Dict[str, Any] = {
                "stdout": log_handle,
                "stderr": subprocess.STDOUT,
                "cwd": str(self.paths["base"]),
                "shell": False,
            }

            # Detach from process group so signals to CLI don't kill daemon
            if sys.platform == "win32":
                kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
            else:
                kwargs["start_new_session"] = True

            proc = subprocess.Popen(cmd, **kwargs)
        except Exception as e:
            log_handle.close()
            raise RuntimeError(f"Failed to launch service '{service_id}': {e}") from e

        # Persist PID & runtime metadata
        pid = proc.pid
        self._get_pid_file(service_id).write_text(str(pid), encoding="utf-8")
        state_data = {
            "service_id": service_id,
            "pid": pid,
            "port": port,
            "bind_address": bind_addr,
            "start_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "command": [str(c) for c in cmd],
        }
        self._get_state_file(service_id).write_text(json.dumps(state_data, indent=2), encoding="utf-8")

        # Acquire wake-lock to prevent Android Doze suspension
        acquire_wake_lock()

        # Update enabled flag in configuration
        if service_id == "dashboard":
            cfg["dashboard"]["enabled"] = True
            self.config_manager.save()
        elif service_id in cfg.get("services", {}):
            self.config_manager.update_service(service_id, {"enabled": True})

        # Wait briefly to confirm it didn't immediately crash
        time.sleep(0.3)
        if not self._is_process_alive(pid, profile.expected_bin):
            log_handle.close()
            # Clean up stale files
            self._get_pid_file(service_id).unlink(missing_ok=True)
            self._get_state_file(service_id).unlink(missing_ok=True)
            # Read last lines of log to explain failure
            err_log = self.get_logs(service_id, lines=5)
            raise RuntimeError(f"Service '{service_id}' exited immediately after launch.\nLog output:\n{err_log}")

        return self.status(service_id)

    def stop(self, service_id: str, timeout: float = 3.0) -> Dict[str, Any]:
        """Stop a running service gracefully (SIGTERM), escalating to SIGKILL if needed."""
        pid_file = self._get_pid_file(service_id)
        state_file = self._get_state_file(service_id)

        if not pid_file.exists():
            return {
                "service": service_id,
                "running": False,
                "pid": None,
                "healthy": False,
                "message": f"Service '{service_id}' is not running.",
            }

        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = -1

        if pid > 0:
            # 1. Graceful termination
            if sys.platform == "win32":
                _kill_process_windows(pid)
            else:
                try:
                    os.kill(pid, signal.SIGTERM)
                except OSError:
                    pass

            # Poll for termination
            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    os.kill(pid, 0)
                    time.sleep(0.1)
                except OSError:
                    break
            else:
                # 2. Forceful kill if still hanging
                if sys.platform == "win32":
                    subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
                else:
                    try:
                        os.kill(pid, signal.SIGKILL)
                    except OSError:
                        pass

        # Cleanup PID and state files
        pid_file.unlink(missing_ok=True)
        state_file.unlink(missing_ok=True)

        # Update config state
        cfg = self.config_manager.get_config()
        if service_id == "dashboard":
            cfg["dashboard"]["enabled"] = False
            self.config_manager.save()
        elif service_id in cfg.get("services", {}):
            self.config_manager.update_service(service_id, {"enabled": False})

        # If no other services are running, release wake-lock
        active_services = [s for s, st in self.status_all().items() if st["running"]]
        if not active_services:
            release_wake_lock()

        return {
            "service": service_id,
            "running": False,
            "pid": None,
            "healthy": False,
            "message": f"Service '{service_id}' stopped.",
        }

    def restart(self, service_id: str) -> Dict[str, Any]:
        """Restart a service cleanly."""
        self.stop(service_id)
        time.sleep(0.4)
        return self.start(service_id)

    def status(self, service_id: str) -> Dict[str, Any]:
        """Query live status, PID health, and uptime of a service."""
        if service_id not in SERVICE_PROFILES:
            raise ValueError(f"Unknown service '{service_id}'.")

        profile = SERVICE_PROFILES[service_id]
        pid_file = self._get_pid_file(service_id)
        state_file = self._get_state_file(service_id)

        cfg = self.config_manager.get_config()
        port = None
        bind_addr = "127.0.0.1"
        if service_id == "dashboard":
            port = cfg.get("dashboard", {}).get("port", 8888)
            bind_addr = cfg.get("dashboard", {}).get("bind_address", "127.0.0.1")
        elif service_id in cfg.get("services", {}):
            s_cfg = cfg["services"][service_id]
            port = s_cfg.get("port")
            bind_addr = s_cfg.get("bind_address", "127.0.0.1")

        if not pid_file.exists():
            return {
                "service": service_id,
                "name": profile.name,
                "running": False,
                "pid": None,
                "port": port,
                "bind_address": bind_addr,
                "healthy": False,
                "uptime_seconds": 0,
            }

        try:
            pid = int(pid_file.read_text(encoding="utf-8").strip())
        except (ValueError, OSError):
            pid = -1

        # Check if process is genuinely alive
        alive = self._is_process_alive(pid, profile.expected_bin)
        if not alive:
            # Stale PID cleanup
            pid_file.unlink(missing_ok=True)
            state_file.unlink(missing_ok=True)
            return {
                "service": service_id,
                "name": profile.name,
                "running": False,
                "pid": None,
                "port": port,
                "bind_address": bind_addr,
                "healthy": False,
                "uptime_seconds": 0,
            }

        # Calculate uptime
        uptime = 0
        if state_file.exists():
            try:
                s_data = json.loads(state_file.read_text(encoding="utf-8"))
                start_iso = s_data.get("start_time")
                if start_iso:
                    start_dt = datetime.datetime.fromisoformat(start_iso)
                    uptime = max(0, int((datetime.datetime.now(datetime.timezone.utc) - start_dt).total_seconds()))
            except Exception:
                pass

        # Perform health check probe
        healthy = False
        if port:
            probe_host = "127.0.0.1" if bind_addr in ("0.0.0.0", "127.0.0.1") else bind_addr
            healthy = profile.health_checker(probe_host, port)
        elif service_id == "tunnel":
            healthy = True

        return {
            "service": service_id,
            "name": profile.name,
            "running": True,
            "pid": pid,
            "port": port,
            "bind_address": bind_addr,
            "healthy": healthy,
            "uptime_seconds": uptime,
        }

    def status_all(self) -> Dict[str, Dict[str, Any]]:
        """Return status for all supervised services."""
        return {s_id: self.status(s_id) for s_id in SERVICE_PROFILES}

    def get_logs(self, service_id: str, lines: int = 100, redact: bool = True) -> str:
        """Return the tail of service logs with bounded memory and optional redaction."""
        log_file = self._get_log_file(service_id)
        if not log_file.exists():
            return f"[No logs found for service '{service_id}']"

        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                all_lines = f.readlines()
            tail_lines = all_lines[-lines:] if len(all_lines) > lines else all_lines
            content = "".join(tail_lines)
            return redact_secrets(content) if redact else content
        except Exception as e:
            return f"[Error reading logs: {e}]"
