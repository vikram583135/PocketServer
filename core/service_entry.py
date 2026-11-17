"""Trusted foreground payloads, runit launch gates and bounded log drain."""
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.logs import redact_secrets
from core.runtime import RuntimeContext
from core.services import service_config, validate_service_id
from core.supervisor import read_epoch, read_gate, write_gate

def launch_gate(context, service_id, *, clock=time.monotonic, sleep=time.sleep, once=False):
    """Checks every respawn, including runit restarts without controller polling."""
    validate_service_id(service_id)
    context.ensure_mutable()
    while True:
        allowed = False
        delay = 1
        with FileLock(context.root / "locks" / ("gate-" + service_id + ".lock")):
            context.ensure_mutable()
            cfg = ConfigManager(context).get_config()
            gate = read_gate(context, service_id)
            now = clock()
            attempts = [stamp for stamp in gate.get("attempts", []) if 0 <= now - stamp < 60]
            epoch = read_epoch(context)
            valid_epoch = service_id == "controller" or (epoch and epoch == gate.get("epoch"))
            if not gate.get("desired") or not valid_epoch or not cfg.get("auth", {}).get("initialized"):
                gate.update(payload=False, reason=gate.get("reason") if gate.get("reason") == "restart_budget_exhausted" else "activation_required")
            elif len(attempts) >= 4:
                gate.update(desired=False, payload=False, reason="restart_budget_exhausted")
            else:
                earliest = gate.get("next_attempt", 0)
                if now >= earliest:
                    attempts.append(now)
                    run_id = uuid.uuid4().hex
                    gate.update(attempts=attempts, payload=True, run_id=run_id,
                                started=now, reason=None)
                    allowed = True
                else:
                    delay = min(1, earliest - now)
            write_gate(context, service_id, gate)
        if allowed:
            os.environ["POCKETSERVER_RUN_ID"] = run_id
            return run_id
        if once:
            return None
        sleep(delay)

def finish_gate(context, service_id, *, clock=time.monotonic):
    with FileLock(context.root / "locks" / ("gate-" + service_id + ".lock")):
        gate = read_gate(context, service_id)
        attempts = gate.get("attempts", [])
        gate.update(payload=False, next_attempt=clock() + (1, 2, 4)[min(2, max(0, len(attempts) - 1))])
        if len(attempts) >= 4:
            gate.update(desired=False, reason="restart_budget_exhausted")
        write_gate(context, service_id, gate)

def drain_logs(context, service_id):
    """Bound lines before svlogd; block producers and drop overlong remainder."""
    log_dir = context.root / "logs" / (service_id + "-runit")
    executable = shutil.which("svlogd")
    if not executable:
        raise PocketError("unsupported", "svlogd is unavailable", status=503)
    # The logger child is a direct owned handle, never reacquired by PID.
    with subprocess.Popen([executable, str(log_dir)], stdin=subprocess.PIPE, shell=False) as logger:
        active_log_run = None
        def emit_line(raw):
            nonlocal active_log_run
            if raw.startswith(b"POCKETSERVER_RUN:"):
                candidate = raw.decode("ascii", "ignore").partition(":")[2].strip()
                if candidate == read_gate(context, service_id).get("run_id"):
                    active_log_run = candidate
                return
            safe = redact_secrets(raw.decode("utf-8", "replace")).encode() + b"\n"
            if service_id == "tunnel":
                from core.tunnel import note_output
                if active_log_run:
                    note_output(context, active_log_run, safe)
            logger.stdin.write(safe)
            logger.stdin.flush()
        pending = bytearray()
        dropping = False
        try:
            while True:
                chunk = sys.stdin.buffer.read1(1024)
                if not chunk:
                    break
                for byte in chunk:
                    if byte == 10:
                        if pending:
                            emit_line(pending)
                        pending.clear()
                        dropping = False
                    elif not dropping:
                        pending.append(byte)
                        if len(pending) >= 4096:
                            emit_line(pending + b" [line truncated]")
                            pending.clear()
                            dropping = True
            if pending:
                emit_line(pending)
        finally:
            logger.stdin.close()
            logger.stdin = None
            try:
                logger.wait(timeout=5)
            except subprocess.TimeoutExpired:
                logger.terminate()
                try:
                    logger.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    logger.kill()
                    logger.wait(timeout=2)

def serve(context, service_id):
    cfg = ConfigManager(context).get_config()
    if not cfg.get("auth", {}).get("initialized"):
        raise PocketError("not_initialized", "Initialize credentials first")
    if service_id == "controller":
        from core.controller import Controller
        Controller(context).run()
        return
    if service_id == "tunnel":
        from core.tunnel import foreground_command, foreground_environment
        argv = foreground_command(context)
        sys.stdout.write("POCKETSERVER_RUN:" + os.environ.get("POCKETSERVER_RUN_ID", "") + "\n")
        sys.stdout.flush()
        os.execve(argv[0], argv, foreground_environment(context))
    if service_id == "ssh":
        from core.ssh_git import SSHGitManager
        manager = SSHGitManager(context)
        argv = manager.foreground_command()
        os.execv(argv[0], argv)
    config = service_config(cfg, service_id)
    if service_id == "dashboard":
        from dashboard.app import create_app
        app = create_app(context=context)
    else:
        from core.http_services import create_api_app, create_web_app
        app = create_web_app(context) if service_id == "web" else create_api_app(context)
    # The supported WSGI server is a bounded implementation supplied by http_services.
    from core.http_services import serve_wsgi
    serve_wsgi(app, config["bind_address"], config["port"])

def main(argv=None):
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    parser.add_argument("service")
    parser.add_argument("--root", required=True)
    parser.add_argument("--gate", action="store_true")
    parser.add_argument("--finish", action="store_true")
    parser.add_argument("--log-stream", action="store_true")
    args = parser.parse_args(argv)
    validate_service_id(args.service)
    context = RuntimeContext.discover(root=args.root)
    if args.log_stream:
        return drain_logs(context, args.service)
    if args.finish:
        return finish_gate(context, args.service)
    if args.gate:
        launch_gate(context, args.service)
    return serve(context, args.service)

if __name__ == "__main__":
    try:
        main()
    except PocketError as exc:
        sys.stderr.write(exc.code + ": " + exc.message + "\n")
        raise SystemExit(1)

