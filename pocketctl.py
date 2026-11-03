#!/usr/bin/env python3
"""PocketServer Unified Command-Line Interface (pocketctl).

Provides complete lifecycle control, diagnostics, backups, and user management:
  pocketctl init       - Initialize environment and set admin password
  pocketctl status     - View service health and system telemetry
  pocketctl start      - Start service(s)
  pocketctl stop       - Stop service(s)
  pocketctl restart    - Restart service(s)
  pocketctl logs       - Tail service log with credential redaction
  pocketctl doctor     - Run comprehensive system and Android diagnostics
  pocketctl backup     - Create compressed .tar.gz archive
  pocketctl restore    - Restore configuration and data from backup archive
  pocketctl passwd     - Change admin password
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
from pathlib import Path

# Ensure UTF-8 output encoding on legacy Windows consoles
if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Ensure repository root is on sys.path
REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from core.config import ConfigManager
from core.doctor import (
    create_backup,
    install_boot_script,
    restore_backup,
    run_diagnostics,
)
from core.env import (
    ensure_runtime_dirs,
    get_base_dir,
    get_system_metrics,
    is_mock_mode,
    is_termux,
)
from core.services import SERVICE_PROFILES
from core.supervisor import Supervisor


def _format_bytes(size_bytes: int) -> str:
    """Format bytes into readable KB/MB."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    return f"{size_bytes / (1024 * 1024):.1f} MB"


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize PocketServer runtime directories and admin credentials."""
    print("=" * 60)
    print("  PocketServer Initialization")
    print("=" * 60)

    ensure_runtime_dirs()
    cfg_mgr = ConfigManager()
    base_dir = get_base_dir()

    print(f"[*] Base Directory: {base_dir}")
    print(f"[*] Environment:    {'Real Termux' if is_termux() else 'Mock Mode'}")

    # Check or set admin password
    if cfg_mgr.is_initialized() and not args.force:
        print("[+] Admin password is already configured.")
    else:
        password = args.password
        if not password:
            while True:
                p1 = getpass.getpass("Enter new admin password: ")
                if len(p1) < 4:
                    print("[-] Password must be at least 4 characters long. Try again.")
                    continue
                p2 = getpass.getpass("Confirm admin password: ")
                if p1 != p2:
                    print("[-] Passwords do not match. Try again.")
                    continue
                password = p1
                break

        cfg_mgr.set_admin_password(password)
        print("[+] Admin password set successfully (PBKDF2-SHA256).")

    # Generate or show secret key
    secret_key = cfg_mgr.get_or_create_secret_key()
    print(f"[+] Session Secret Key: Verified ({len(secret_key)} hex chars)")

    # Seed default payloads
    Supervisor(cfg_mgr)
    print("[+] Default payloads seeded (data/www/index.html & data/api/server.py)")

    metrics = get_system_metrics()
    lan_ip = metrics["network"]["lan_ip"]
    dash_port = cfg_mgr.get_config().get("dashboard", {}).get("port", 8888)

    print("-" * 60)
    print("Initialization complete! Ready to start PocketServer.")
    print(f"Run: python pocketctl.py start dashboard")
    print(f"Dashboard URL: http://{lan_ip}:{dash_port} (or http://127.0.0.1:{dash_port})")
    print("-" * 60)
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Display live service status table and system telemetry."""
    supervisor = Supervisor()
    cfg = supervisor.config_manager.get_config()

    if args.service:
        s_id = args.service.lower()
        if s_id not in SERVICE_PROFILES:
            print(f"[-] Unknown service '{s_id}'. Available: {list(SERVICE_PROFILES.keys())}")
            return 1
        st = supervisor.status(s_id)
        print(f"Service: {st['service']} ({st['name']})")
        print(f"Status:  {'RUNNING' if st['running'] else 'STOPPED'}")
        print(f"PID:     {st['pid'] or 'N/A'}")
        print(f"Port:    {st['port'] or 'N/A'}")
        print(f"Healthy: {'YES' if st['healthy'] else 'NO'}")
        print(f"Uptime:  {st['uptime_seconds']}s")
        return 0

    # System Overview
    metrics = get_system_metrics()
    mem = metrics["memory"]
    disk = metrics["storage"]
    net = metrics["network"]

    print("=" * 72)
    print("  PocketServer System & Service Status")
    print("=" * 72)
    print(f"Environment: {'Termux' if is_termux() else 'Mock'}  |  LAN IP: {net['lan_ip']}  |  VPN: {net['vpn_ip'] or 'None'}")
    print(f"RAM: {mem['used_mb']} MB / {mem['total_mb']} MB ({mem['used_pct']}%)  |  Disk: {disk['free_mb']} MB free  |  Wake-Lock: {'ACTIVE' if metrics['wake_lock_active'] else 'INACTIVE'}")
    print("-" * 72)

    # Services Table
    headers = f"{'SERVICE':<12} {'NAME':<24} {'STATUS':<10} {'PORT':<8} {'PID':<8} {'HEALTH':<8} {'UPTIME'}"
    print(headers)
    print("-" * 72)

    all_statuses = supervisor.status_all()
    for s_id, st in all_statuses.items():
        status_str = "RUNNING" if st["running"] else "STOPPED"
        port_str = str(st["port"]) if st["port"] else "-"
        pid_str = str(st["pid"]) if st["pid"] else "-"
        health_str = "OK" if st["healthy"] else ("FAIL" if st["running"] else "-")
        uptime_str = f"{st['uptime_seconds']}s" if st["running"] else "-"

        row = f"{s_id:<12} {st['name']:<24} {status_str:<10} {port_str:<8} {pid_str:<8} {health_str:<8} {uptime_str}"
        print(row)

    print("=" * 72)
    return 0


def cmd_start(args: argparse.Namespace) -> int:
    """Start a specific service or all services."""
    supervisor = Supervisor()
    target = args.service.lower()

    if target == "all":
        services_to_start = ["dashboard", "web", "api"]
        for s in services_to_start:
            try:
                st = supervisor.start(s)
                print(f"[+] Started '{s}' (PID: {st['pid']}, Port: {st['port']})")
            except Exception as e:
                print(f"[-] Failed to start '{s}': {e}")
        return 0

    if target not in SERVICE_PROFILES:
        print(f"[-] Unknown service '{target}'. Available: {list(SERVICE_PROFILES.keys())} or 'all'")
        return 1

    try:
        st = supervisor.start(target)
        print(f"[+] Successfully started '{target}' (PID: {st['pid']}, Port: {st['port'] or 'N/A'})")
        return 0
    except Exception as e:
        print(f"[-] Error: {e}")
        return 1


def cmd_stop(args: argparse.Namespace) -> int:
    """Stop a specific service or all services."""
    supervisor = Supervisor()
    target = args.service.lower()

    if target == "all":
        for s in SERVICE_PROFILES:
            st = supervisor.stop(s)
            if st["running"] is False and "stopped" in st.get("message", ""):
                print(f"[+] Stopped '{s}'")
        print("[+] All services stopped.")
        return 0

    if target not in SERVICE_PROFILES:
        print(f"[-] Unknown service '{target}'. Available: {list(SERVICE_PROFILES.keys())} or 'all'")
        return 1

    st = supervisor.stop(target)
    print(f"[+] {st.get('message', f'Service {target} stopped.')}")
    return 0


def cmd_restart(args: argparse.Namespace) -> int:
    """Restart a specific service or all services."""
    supervisor = Supervisor()
    target = args.service.lower()

    if target == "all":
        cmd_stop(args)
        cmd_start(args)
        return 0

    if target not in SERVICE_PROFILES:
        print(f"[-] Unknown service '{target}'.")
        return 1

    try:
        st = supervisor.restart(target)
        print(f"[+] Restarted '{target}' (PID: {st['pid']})")
        return 0
    except Exception as e:
        print(f"[-] Error restarting '{target}': {e}")
        return 1


def cmd_logs(args: argparse.Namespace) -> int:
    """Display service log output."""
    supervisor = Supervisor()
    target = args.service.lower()

    if target not in SERVICE_PROFILES:
        print(f"[-] Unknown service '{target}'. Available: {list(SERVICE_PROFILES.keys())}")
        return 1

    output = supervisor.get_logs(target, lines=args.lines, redact=not args.no_redact)
    print(f"--- [Logs: {target} (last {args.lines} lines)] ---")
    print(output.rstrip())
    return 0


def cmd_doctor(args: argparse.Namespace) -> int:
    """Execute complete system and Android limitation diagnostics."""
    if args.fix_boot:
        path = install_boot_script()
        print(f"[+] Installed Termux:Boot auto-start script at: {path}")

    diag = run_diagnostics()

    status_symbol = {
        "PASS": "[PASS]",
        "WARN": "[WARN]",
        "FAIL": "[FAIL]",
        "INFO": "[INFO]",
    }

    print("=" * 72)
    print(f"  PocketServer Diagnostics — Status: {diag['status']}")
    print("=" * 72)
    print(f"Checks: {diag['pass_count']} Passed, {diag['warn_count']} Warnings, {diag['fail_count']} Failed")
    print("-" * 72)

    for c in diag["checks"]:
        sym = status_symbol.get(c["status"], "[?]")
        print(f"{sym:<8} {c['name']:<32} {c['message']}")
        if c.get("remediation"):
            print(f"         --> Remediation: {c['remediation']}")

    print("=" * 72)
    return 1 if diag["fail_count"] > 0 else 0


def cmd_backup(args: argparse.Namespace) -> int:
    """Create a compressed .tar.gz archive of configuration and data."""
    try:
        archive_path = create_backup()
        size_str = _format_bytes(archive_path.stat().st_size)
        print(f"[+] Backup created successfully!")
        print(f"[*] Archive: {archive_path}")
        print(f"[*] Size:    {size_str}")
        return 0
    except Exception as e:
        print(f"[-] Failed to create backup: {e}")
        return 1


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore configuration and data from an archive."""
    archive_path = Path(args.archive_file).resolve()
    print(f"[*] Restoring from: {archive_path}")

    try:
        res = restore_backup(archive_path)
        print(f"[+] Successfully restored {res['restored_count']} files!")
        return 0
    except Exception as e:
        print(f"[-] Restore failed: {e}")
        return 1


def cmd_passwd(args: argparse.Namespace) -> int:
    """Safely update the administrative password."""
    cfg_mgr = ConfigManager()
    while True:
        p1 = getpass.getpass("Enter new admin password: ")
        if len(p1) < 4:
            print("[-] Password must be at least 4 characters long.")
            continue
        p2 = getpass.getpass("Confirm new admin password: ")
        if p1 != p2:
            print("[-] Passwords do not match.")
            continue
        cfg_mgr.set_admin_password(p1)
        print("[+] Admin password updated successfully.")
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="pocketctl",
        description="PocketServer Unified Controller CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", help="Initialize runtime directories and set admin password")
    p_init.add_argument("--password", type=str, help="Admin password (skip interactive prompt)")
    p_init.add_argument("--force", action="store_true", help="Force overwrite existing password")
    p_init.set_defaults(func=cmd_init)

    # status
    p_status = subparsers.add_parser("status", help="Show system and service status")
    p_status.add_argument("service", nargs="?", help="Optional specific service to inspect")
    p_status.set_defaults(func=cmd_status)

    # start
    p_start = subparsers.add_parser("start", help="Start service(s)")
    p_start.add_argument("service", help="Service ID (web, api, dashboard, ssh, tunnel, all)")
    p_start.set_defaults(func=cmd_start)

    # stop
    p_stop = subparsers.add_parser("stop", help="Stop service(s)")
    p_stop.add_argument("service", help="Service ID (web, api, dashboard, ssh, tunnel, all)")
    p_stop.set_defaults(func=cmd_stop)

    # restart
    p_restart = subparsers.add_parser("restart", help="Restart service(s)")
    p_restart.add_argument("service", help="Service ID (web, api, dashboard, ssh, tunnel, all)")
    p_restart.set_defaults(func=cmd_restart)

    # logs
    p_logs = subparsers.add_parser("logs", help="Tail service logs")
    p_logs.add_argument("service", help="Service ID")
    p_logs.add_argument("--lines", type=int, default=50, help="Number of lines to tail")
    p_logs.add_argument("--no-redact", action="store_true", help="Disable secret redaction")
    p_logs.set_defaults(func=cmd_logs)

    # doctor
    p_doctor = subparsers.add_parser("doctor", help="Run system diagnostics")
    p_doctor.add_argument("--fix-boot", action="store_true", help="Generate and install Termux:Boot script")
    p_doctor.set_defaults(func=cmd_doctor)

    # backup
    p_backup = subparsers.add_parser("backup", help="Create compressed backup archive")
    p_backup.set_defaults(func=cmd_backup)

    # restore
    p_restore = subparsers.add_parser("restore", help="Restore from backup archive")
    p_restore.add_argument("archive_file", help="Path to .tar.gz archive")
    p_restore.set_defaults(func=cmd_restore)

    # passwd
    p_passwd = subparsers.add_parser("passwd", help="Change admin password")
    p_passwd.set_defaults(func=cmd_passwd)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
