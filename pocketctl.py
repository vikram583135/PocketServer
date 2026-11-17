#!/usr/bin/env python3
"""PocketServer CLI: local core operations, explicit mutation, honest exits."""
from __future__ import annotations
import argparse
import json
import os
import sys
import uuid
from pathlib import Path
from core.application import Application
from core.config import read_password, validate_config
from core.errors import PocketError
from core.runtime import RuntimeContext
from core.services import SERVICE_PROFILES, seed_default_payloads

def parser():
    root = argparse.ArgumentParser(prog="pocketctl")
    root.add_argument("--home")
    root.add_argument("--env", choices=("auto", "mock", "termux"), default=None)
    root.add_argument("--json", action="store_true")
    commands = root.add_subparsers(dest="command", required=True)
    def command(name, parent=commands):
        child = parent.add_parser(name)
        child.add_argument("--json", action="store_true", default=argparse.SUPPRESS)
        child.add_argument("--home", default=argparse.SUPPRESS)
        child.add_argument("--env", choices=("auto", "mock", "termux"), default=argparse.SUPPRESS)
        return child
    init = command("init"); init.add_argument("--password-stdin", action="store_true")
    status = command("status"); status.add_argument("target", nargs="?"); status.add_argument("--require-ready", action="store_true")
    for name in ("start", "stop", "restart"):
        child = command(name); child.add_argument("target", nargs="?", default="all")
    for name in ("enable", "disable"):
        child = command(name); child.add_argument("target", choices=("dashboard", "web", "api", "ssh")); child.add_argument("--revision", type=int)
    logs = command("logs"); logs.add_argument("target", choices=tuple(SERVICE_PROFILES)); logs.add_argument("--lines", type=int, default=100)
    doctor = command("doctor"); doctor.add_argument("--strict", action="store_true")
    password = command("passwd"); password.add_argument("--password-stdin", action="store_true")
    config = command("config"); sub = config.add_subparsers(dest="config_action", required=True)
    command("validate", sub)
    command("rotate-key", sub)
    migrate = command("migrate", sub); migrate.add_argument("--apply", action="store_true"); migrate.add_argument("--legacy-stopped", action="store_true")
    setter = command("set", sub); setter.add_argument("field"); setter.add_argument("value"); setter.add_argument("--revision", type=int, required=True)
    ssh = command("ssh"); keys = ssh.add_subparsers(dest="ssh_action", required=True); key = command("key", keys)
    key_sub = key.add_subparsers(dest="key_action", required=True)
    add = command("add", key_sub); add.add_argument("public_key_file"); add.add_argument("--role", choices=("owner", "git"), default="owner"); add.add_argument("--repository", action="append", default=[])
    command("list", key_sub)
    remove = command("remove", key_sub); remove.add_argument("fingerprint")
    git = command("git"); git_sub = git.add_subparsers(dest="git_action", required=True)
    create = command("create", git_sub); create.add_argument("name")
    command("list", git_sub)
    job = command("job"); job_sub = job.add_subparsers(dest="job_action", required=True)
    register = command("register", job_sub); register.add_argument("id"); register.add_argument("script"); register.add_argument("--arg", action="append", default=[]); register.add_argument("--cwd"); register.add_argument("--timeout", type=int)
    run = command("run", job_sub); run.add_argument("id"); run.add_argument("--parameters", default="{}")
    cancel = command("cancel", job_sub); cancel.add_argument("id")
    command("list", job_sub)
    job_status = command("status", job_sub); job_status.add_argument("id")
    tunnel = command("tunnel"); tunnel_sub = tunnel.add_subparsers(dest="tunnel_action", required=True)
    publish = command("publish", tunnel_sub); publish.add_argument("target", choices=("web", "api")); publish.add_argument("--acknowledge-public", action="store_true")
    command("stop", tunnel_sub); command("status", tunnel_sub)
    backup = command("backup"); backup.add_argument("--external-writers-stopped", action="store_true")
    backup_sub = backup.add_subparsers(dest="backup_action")
    backup_create = command("create", backup_sub); backup_create.add_argument("--external-writers-stopped", action="store_true", default=argparse.SUPPRESS)
    command("list", backup_sub)
    backup_validate = command("validate", backup_sub); backup_validate.add_argument("archive")
    backup_import = command("import-legacy", backup_sub); backup_import.add_argument("archive")
    restore = command("restore"); restore.add_argument("archive"); restore.add_argument("--apply", action="store_true"); restore.add_argument("--trust-executable-content", action="store_true"); restore.add_argument("--external-writers-stopped", action="store_true")
    recover = command("recover"); recovery_kind = recover.add_mutually_exclusive_group(); recovery_kind.add_argument("--config", action="store_true"); recovery_kind.add_argument("--state", action="store_true"); recover.add_argument("--apply", action="store_true")
    boot = command("boot"); boot_sub = boot.add_subparsers(dest="boot_action", required=True)
    for name in ("install", "remove", "reconcile", "status"):
        command(name, boot_sub)
    serve = command("serve"); serve.add_argument("--foreground", action="store_true", required=True); serve.add_argument("--service", choices=("dashboard", "web", "api"), default="dashboard")
    install = command("install"); install.add_argument("--source", required=True); install.add_argument("--install-root"); install.add_argument("--wheelhouse"); install.add_argument("--password-stdin", action="store_true"); install.add_argument("--allow-unqualified", action="store_true")
    setup = command("services-install")
    uninstall = command("uninstall"); uninstall.add_argument("--purge-data", action="store_true"); uninstall.add_argument("--yes-purge-data", action="store_true")
    return root

def _error_exit(error):
    if error.code in {"recovery_required", "durability_uncertain", "migration_required"}:
        return 5
    if error.code in {"busy", "timeout", "lock_timeout"}:
        return 4
    if error.code in {"unsupported", "backend_unavailable", "controller_unavailable", "not_installed"}:
        return 3
    if error.code.startswith(("invalid", "unknown")) or error.code in {"unsafe_path", "not_initialized"}:
        return 2
    return 1

def _aggregate(app, action):
    supervisor = app.supervisor
    cfg = app.config.get_config()
    statuses = supervisor.status()
    order = ("tunnel", "ssh", "api", "web", "dashboard", "controller")
    if action == "start":
        selected = [sid for sid in ("web", "api", "ssh", "dashboard") if (cfg["dashboard"] if sid == "dashboard" else cfg["services"][sid])["autostart"]]
        if not selected:
            raise PocketError("invalid_input", "No private autostart services are selected; use enable first.")
        targets = ["controller"] + selected
    else:
        targets = [sid for sid in order if statuses[sid]["running"] or statuses[sid].get("owned")]
    results, errors = {}, {}
    if action == "stop":
        app.jobs.shutdown_owned()
    if action in ("stop", "restart"):
        for sid in targets:
            try:
                results[sid] = supervisor.stop(sid)
            except PocketError as exc:
                errors[sid] = {"code": exc.code, "message": exc.message}
        if action == "stop":
            return {"ok": not errors, "results": results, "errors": errors}
        if "tunnel" in targets:
            results["tunnel"] = {"running": False, "reason": "publication_reapproval_required"}
        targets = (["controller"] if targets else []) + [sid for sid in ("web", "api", "ssh", "dashboard") if sid in targets]
    for sid in targets:
        if sid in errors:
            continue
        if sid != "controller" and "controller" in errors:
            errors[sid] = {"code": "controller_unavailable", "message": "Controller activation failed."}
            continue
        try:
            results[sid] = supervisor.start(sid)
        except PocketError as exc:
            errors[sid] = {"code": exc.code, "message": exc.message}
    return {"ok": not errors, "results": results, "errors": errors}

def execute(args, app):
    name = args.command
    if name == "init":
        app.initialize(read_password(args.password_stdin))
        seed_default_payloads(app.context)
        return {"initialized": True, "mode": app.context.mode, "runtime_root": str(app.context.root)}
    if name == "status":
        result = app.supervisor.status(args.target) if args.target else app.status()
        statuses = {args.target: result} if args.target else result["services"]
        if args.require_ready and not all(item["ready"] for item in statuses.values() if item.get("autostart") or args.target):
            return {"ok": False, "status": result}
        return result
    if name in ("start", "stop", "restart"):
        return _aggregate(app, name) if args.target == "all" else getattr(app.supervisor, name)(args.target)
    if name in ("enable", "disable"):
        app.config.update_service(args.target, {"autostart": name == "enable"}, expected_revision=args.revision)
        return {"service": args.target, "autostart": name == "enable", "revision": app.config.get_config()["revision"]}
    if name == "logs":
        return {"service": args.target, "text": app.supervisor.get_logs(args.target, args.lines)}
    if name == "doctor":
        from core.doctor import run_diagnostics
        result = run_diagnostics(app.config, app.context)
        if args.strict and any(check["required"] and check["state"] in ("WARN", "UNKNOWN") for check in result["checks"]):
            result["ok"] = False
        return result
    if name == "passwd":
        app.config.set_admin_password(read_password(args.password_stdin))
        return {"password_changed": True, "sessions_revoked": True}
    if name == "config":
        if args.config_action == "rotate-key":
            app.config.rotate_secret_key()
            return {"signing_key_rotated": True, "sessions_revoked": True}
        if args.config_action == "validate":
            cfg = app.config.get_config(); validate_config(cfg)
            return {"valid": True, "schema_version": cfg["schema_version"], "revision": cfg["revision"]}
        if args.config_action == "migrate":
            return app.config.migrate(apply=args.apply, legacy_stopped=args.legacy_stopped)
        pieces = args.field.split(".")
        if len(pieces) < 2 or pieces[0] not in {"dashboard", "services", "files", "power", "logs", "jobs"} or any(not piece for piece in pieces):
            raise PocketError("invalid_input", "Choose an existing noncredential configuration field.")
        try:
            value = json.loads(args.value)
        except ValueError:
            value = args.value
        def change(cfg):
            destination = cfg
            for piece in pieces[:-1]:
                if not isinstance(destination, dict) or piece not in destination:
                    raise PocketError("invalid_input", "Unknown configuration field.")
                destination = destination[piece]
            if not isinstance(destination, dict) or pieces[-1] not in destination:
                raise PocketError("invalid_input", "Unknown configuration field.")
            destination[pieces[-1]] = value
        app.config.transaction(change, expected_revision=args.revision)
        return {"revision": app.config.get_config()["revision"]}
    if name == "ssh":
        if args.key_action == "list":
            return app.ssh_git.list_keys()
        if args.key_action == "remove":
            return app.ssh_git.remove_key(args.fingerprint, local=True)
        path = Path(args.public_key_file)
        if path.stat().st_size > 16384:
            raise PocketError("invalid_key", "The public-key file is too large.")
        return app.ssh_git.add_key(path.read_text().strip(), args.role, args.repository)
    if name == "git":
        return app.ssh_git.create_repo(args.name) if args.git_action == "create" else app.ssh_git.list_repos()
    if name == "job":
        if args.job_action == "list": return app.jobs.list()
        if args.job_action == "status": return app.jobs.get_run(args.id)
        if args.job_action == "register": return app.jobs.register(args.id, args.script, argv=args.arg, cwd=args.cwd, timeout=args.timeout)
        if args.job_action == "cancel": return app.jobs.cancel(args.id)
        try:
            parameters = json.loads(args.parameters)
        except ValueError:
            raise PocketError("invalid_input", "Job parameters must be JSON.")
        return app.jobs.run(args.id, parameters=parameters)
    if name == "tunnel":
        if args.tunnel_action == "publish": return app.tunnel.start(args.target, acknowledge_public=args.acknowledge_public)
        return getattr(app.tunnel, args.tunnel_action)()
    if name == "backup":
        if args.backup_action == "list": return app.backups.list()
        if args.backup_action == "validate": return app.backups.validate(args.archive)
        if args.backup_action == "import-legacy": return app.backups.import_legacy(args.archive)
        return app.backups.create(external_writers_stopped=args.external_writers_stopped)
    if name == "restore":
        return app.backups.restore(args.archive, apply=args.apply, trust_executable_content=args.trust_executable_content,
                                   external_writers_stopped=args.external_writers_stopped)
    if name == "recover":
        if args.state:
            from core.state import StateStore
            return StateStore(app.context).recover(supervisor=app.supervisor, apply=args.apply)
        if args.config:
            return app.config.recover()
        from core.boot import recover_installation
        return recover_installation(app.context) or app.backups.recover()
    if name == "boot":
        from core.boot import install_boot, remove_boot, reconcile_boot
        if args.boot_action == "status":
            path = app.context.root / "state" / "boot.json"
            if not path.exists(): return {"setup": False, "reboot_verified": False}
            from core.runtime import read_private
            return json.loads(read_private(path, 65536))
        return {"install": install_boot, "remove": remove_boot, "reconcile": reconcile_boot}[args.boot_action](app.context)
    if name == "services-install":
        from core.supervisor import install_runit_entries
        return install_runit_entries(app.context)
    if name == "serve":
        from core.service_entry import serve
        os.environ["POCKETSERVER_RUN_ID"] = uuid.uuid4().hex
        serve(app.context, args.service)
        return {"stopped": True}
    if name == "install":
        from core.boot import install_application
        if not app.config.is_initialized():
            app.initialize(read_password(args.password_stdin))
            seed_default_payloads(app.context)
        return install_application(app.context, args.source, install_root=args.install_root, wheelhouse=args.wheelhouse, allow_unqualified=args.allow_unqualified)
    if name == "uninstall":
        from core.boot import uninstall_application
        confirmation = None
        if args.purge_data:
            if args.yes_purge_data:
                confirmation = str(app.context.root)
            else:
                sys.stderr.write("Permanently delete runtime data at " + str(app.context.root) + "\n")
                if not sys.stdin.isatty():
                    raise PocketError("confirmation_required", "Use --yes-purge-data for deliberate noninteractive purge.", 409)
                confirmation = input("Type the full runtime root to confirm: ")
        return uninstall_application(app.context, purge_data=args.purge_data, confirm=confirmation)
    raise PocketError("invalid_input", "Unknown command.")

def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    request_id = uuid.uuid4().hex
    try:
        context = RuntimeContext.discover(root=args.home, mode=args.env)
        result = execute(args, Application(context))
        ok = not isinstance(result, dict) or result.get("ok", True)
        if args.command == "job" and args.job_action == "run" and isinstance(result, dict) and result.get("state") in {"failed", "timed_out", "cancelled", "interrupted"}:
            ok = False
        envelope = {"ok": bool(ok), "data": result, "request_id": request_id}
        code = 0 if ok else 1
    except PocketError as exc:
        envelope = {"ok": False, "error": {"code": exc.code, "message": exc.message}, "request_id": request_id}
        code = _error_exit(exc)
    except (OSError, ValueError):
        envelope = {"ok": False, "error": {"code": "operation_failed", "message": "Operation failed; inspect local paths and supplied values."}, "request_id": request_id}
        code = 1
    if args.json:
        print(json.dumps(envelope, ensure_ascii=False, default=str))
    elif envelope["ok"]:
        print(json.dumps(envelope["data"], ensure_ascii=False, indent=2, default=str))
    else:
        error = envelope.get("error")
        print(error["code"] + ": " + error["message"] if error else json.dumps(envelope["data"], indent=2, default=str), file=sys.stderr)
    return code

if __name__ == "__main__":
    raise SystemExit(main())
