"""Explicit owned boot and installation artifacts; no setup from read paths."""
from __future__ import annotations
import hashlib
import base64
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path
from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import RuntimeContext, atomic_write, check_path, check_private, private_dir, read_private

def _production(context):
    context.ensure_mutable()
    if context.mode != "termux":
        raise PocketError("unsupported", "Installation and Android boot require a qualified Termux runtime.", 503)

def _read_registration(context):
    path = context.root / "state" / "installation.json"
    try:
        result = json.loads(read_private(path, 65536))
        if result["runtime_root"] != str(context.root):
            raise ValueError()
        return result
    except (OSError, KeyError, ValueError):
        raise PocketError("not_installed", "No valid owned installation registration was found.", 409)

def _boot_script(context):
    return Path.home() / ".termux" / "boot" / "pocketserver"

def install_boot(context):
    _production(context)
    registration = _read_registration(context)
    script = _boot_script(context)
    check_path(script)
    private_dir(script.parent)
    marker = "# pocketserver-runtime:" + str(context.root)
    if script.exists() and marker not in script.read_text(encoding="utf-8").splitlines():
        raise PocketError("unsafe_path", "Refusing an unowned boot script.")
    argv = [registration["interpreter"], str(Path(registration["active_generation"]) / "app" / "pocketctl.py"),
            "--home", str(context.root), "--env", "termux", "boot", "reconcile"]
    shell = str(Path(os.environ["PREFIX"]) / "bin" / "sh")
    content = "#!" + shell + "\n" + marker + "\numask 077\nexec " + shlex.join(argv) + "\n"
    with FileLock(context.root / "locks" / "operation.lock"):
        atomic_write(script, content.encode(), mode=0o700)
        atomic_write(context.root / "state" / "boot.json",
                     json.dumps({"script": str(script), "setup": True, "reboot_verified": False}).encode())
    return {"installed": str(script), "reboot_verified": False,
            "guidance": "Install compatible Termux:Boot and launch the add-on once; record a real reboot test."}

def remove_boot(context):
    context.ensure_mutable()
    script = _boot_script(context)
    check_path(script)
    marker = "# pocketserver-runtime:" + str(context.root)
    if script.exists():
        if marker not in script.read_text(encoding="utf-8").splitlines():
            raise PocketError("unsafe_path", "Refusing an unowned boot script.")
        script.unlink()
    state = context.root / "state" / "boot.json"
    if state.exists():
        atomic_write(state, b'{"setup":false,"reboot_verified":false}')
    return {"removed": str(script)}

def reconcile_boot(context, *, runner=None):
    _production(context)
    runner = runner or subprocess.run
    command = shutil.which("service-daemon")
    if not command:
        raise PocketError("unsupported", "Install and qualify termux-services; service-daemon is missing.", 503)
    environment = dict(os.environ)
    environment["SVDIR"] = str(Path(os.environ["PREFIX"]) / "var" / "service")
    result = runner([command, "start"], capture_output=True, timeout=10, check=False, env=environment)
    from core.supervisor import Supervisor
    supervisor = Supervisor(context=context)
    deadline = time.monotonic() + 5
    while supervisor.status("controller")["state"] in ("unknown", "unsupported"):
        if time.monotonic() >= deadline:
            raise PocketError("backend_unavailable", "The Termux service daemon did not become observable; verify the owned runit installation.", 503)
        time.sleep(0.1)
    supervisor.start("controller")
    result = supervisor.reconcile()
    return {"services": result, "reboot_verified": False}

def install_application(context, source, *, install_root=None, wheelhouse=None, runner=None, allow_unqualified=False):
    """Offline generation install. No package-manager/network fallback is allowed."""
    _production(context)
    runner = runner or subprocess.run
    source = Path(source).absolute()
    check_path(source)
    lock = source / "requirements.lock"
    wheels = Path(wheelhouse).absolute() if wheelhouse else source / "wheelhouse"
    manifest_path = wheels / "manifest.json"
    if not lock.is_file() or not manifest_path.is_file():
        raise PocketError("unsupported", "Provide requirements.lock and the vetted wheelhouse/manifest.json.", 503)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if manifest["format_version"] != 1:
            raise ValueError()
        if manifest.get("qualified_on_termux") is not True and not allow_unqualified:
            raise PocketError("unsupported", "This wheelhouse has no physical Termux qualification; use --allow-unqualified only for local qualification.", 503)
        records = manifest["wheels"]
        entries = {item["filename"]: item["sha256"] for item in records}
        if not entries or len(entries) != len(records):
            raise ValueError()
        locked_text = lock.read_text(encoding="utf-8")
        locked = {(name.lower().replace("_", "-"), version) for name, version in re.findall(r"(?m)^([A-Za-z0-9_.-]+)==([^\s\\]+)", locked_text)}
        described = {(item["name"].lower().replace("_", "-"), item["version"]) for item in records}
        if locked != described or not locked:
            raise ValueError()
        for filename, digest in entries.items():
            item = wheels / filename
            if Path(filename).name != filename or not filename.endswith(".whl") or len(digest) != 64:
                raise ValueError()
            check_path(item)
            if hashlib.sha256(item.read_bytes()).hexdigest() != digest:
                raise ValueError()
            if "--hash=sha256:" + digest not in locked_text:
                raise ValueError()
        if {item.name for item in wheels.glob("*.whl")} != set(entries):
            raise ValueError()
    except PocketError:
        raise
    except (OSError, ValueError, KeyError, TypeError):
        raise PocketError("invalid_archive", "The offline wheelhouse manifest failed verification.")
    from core.supervisor import Supervisor
    if any(item.get("owned") or item["running"] for item in Supervisor(context=context).status().values()):
        raise PocketError("busy", "Stop owned services before installing a new generation.", 409)
    for command in ("sv", "runsv", "svlogd", "service-daemon"):
        if not shutil.which(command):
            raise PocketError("unsupported", "Required Termux service tools are missing: " + command, 503)
    destination = Path(install_root) if install_root else Path.home() / ".local" / "share" / "pocketserver"
    check_path(destination)
    if destination == context.root or destination in context.root.parents or context.root in destination.parents:
        raise PocketError("unsafe_path", "Application generations and runtime data need separate roots.")
    if destination.is_relative_to(source) or source.is_relative_to(destination):
        raise PocketError("unsafe_path", "Keep installation generations outside the source tree.")
    private_dir(destination)
    private_dir(destination / "generations")
    generation = destination / "generations" / ("gen-" + uuid.uuid4().hex)
    private_dir(generation)
    atomic_write(generation / "pocketserver-owner", str(context.root).encode())
    # Never copy runtime credentials, VCS metadata, caches, or unbounded artifacts.
    ignored = {".git", ".mock_termux", ".pytest_cache", "__pycache__", ".agents", ".codex", "wheelhouse", ".venv", ".test-venv", "venv", ".build", "node_modules", ".gemini"}
    def ignore(directory, names):
        return [name for name in names if name in ignored or Path(directory) / name == context.root]
    for directory, names, files in os.walk(source):
        names[:] = [name for name in names if name not in ignored and Path(directory) / name != context.root]
        for name in names + files:
            check_path(Path(directory) / name)
    with FileLock(context.root / "locks" / "maintenance.lock"), FileLock(context.root / "locks" / "operation.lock"):
        shutil.copytree(source, generation / "app", ignore=ignore)
        for argv in ([sys.executable, "-m", "venv", "--copies", str(generation / "venv")],):
            result = runner(argv, capture_output=True, timeout=120, check=False)
            if result.returncode:
                raise PocketError("install_failed", "Offline virtual environment creation failed.")
        interpreter = generation / "venv" / "bin" / "python"
        argv = [str(interpreter), "-m", "pip", "install", "--no-index", "--require-hashes",
                "--only-binary=:all:", "--find-links", str(wheels), "-r", str(lock)]
        result = runner(argv, capture_output=True, timeout=180, check=False)
        if result.returncode:
            raise PocketError("install_failed", "Vetted offline dependency installation failed; previous generation remains active.")
        result = runner([str(interpreter), "-c", "import flask, werkzeug, waitress, sqlite3, core.application"],
                        cwd=generation / "app", capture_output=True, timeout=15, check=False)
        if result.returncode:
            raise PocketError("install_failed", "Staged application validation failed; previous generation remains active.")
        registration_path = context.root / "state" / "installation.json"
        previous = _read_registration(context) if registration_path.exists() else {}
        previous_bytes = read_private(registration_path, 65536) if registration_path.exists() else None
        launcher = destination / "pocketserver"
        old_launcher = launcher.read_bytes() if launcher.exists() else None
        if launcher.exists() and not previous:
            raise PocketError("unsafe_path", "Refusing an unregistered launcher.")
        shell = str(Path(os.environ["PREFIX"]) / "bin" / "sh")
        content = "#!" + shell + "\n# pocketserver-owned\numask 077\nexec " + shlex.join(
            [str(interpreter), str(generation / "app" / "pocketctl.py"), "--home", str(context.root), "--env", "termux"]) + ' "$@"\n'
        registration = {"runtime_root": str(context.root), "install_root": str(destination),
                        "active_generation": str(generation), "previous_generation": previous.get("active_generation"),
                        "interpreter": str(interpreter), "launcher": str(launcher),
                        "generations": previous.get("generations", []) + [str(generation)], "installed_at": time.time(),
                        "lock_sha256": hashlib.sha256(lock.read_bytes()).hexdigest(),
                        "wheelhouse_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                        "qualified_on_termux": manifest.get("qualified_on_termux") is True}
        journal = context.root / "recovery" / ("install-" + uuid.uuid4().hex + ".json")
        journal_record = {"kind": "installation", "phase": "PREPARED", "runtime_root": str(context.root),
                          "install_root": str(destination), "launcher": str(launcher),
                          "previous_registration": previous,
                          "previous_launcher": base64.b64encode(old_launcher).decode() if old_launcher is not None else None,
                          "generation": str(generation)}
        atomic_write(journal, json.dumps(journal_record).encode())
        try:
            if context.mode == "termux":
                from core.supervisor import install_runit_entries
                install_runit_entries(context, app_root=generation / "app", interpreter=interpreter,
                                      lock_held=True, recovery_held=True)
            atomic_write(launcher, content.encode(), mode=0o700)
            atomic_write(registration_path, json.dumps(registration).encode())
            atomic_write(journal, json.dumps({**journal_record, "phase": "FINALIZED"}).encode())
        except Exception:
            if old_launcher is not None:
                atomic_write(launcher, old_launcher, mode=0o700)
            elif launcher.exists():
                launcher.unlink()
            if previous_bytes is not None:
                atomic_write(registration_path, previous_bytes)
            elif registration_path.exists():
                registration_path.unlink()
            if previous and context.mode == "termux":
                from core.supervisor import install_runit_entries
                install_runit_entries(context, app_root=Path(previous["active_generation"]) / "app",
                                      interpreter=previous["interpreter"], lock_held=True, recovery_held=True)
            atomic_write(journal, json.dumps({**journal_record, "phase": "FINALIZED", "rolled_back": True}).encode())
            raise
    return {"installed": str(generation), "launcher": str(launcher), "previous_generation": previous.get("active_generation"),
            "device_qualified": False, "services_installed": context.mode == "termux", "supervision_available": False}

def recover_installation(context):
    """Local fail-closed rollback of an interrupted launcher/registration switch."""
    journals = []
    for path in context.paths["recovery"].glob("install-*.json"):
        value = json.loads(read_private(path, 262144))
        if value.get("kind") == "installation" and value.get("phase") != "FINALIZED":
            journals.append((path, value))
    if not journals:
        return None
    if not ConfigManager(context).is_initialized():
        raise PocketError("not_initialized", "Initialized credentials are required for local recovery.", 409)
    with FileLock(context.root / "locks" / "maintenance.lock"), FileLock(context.root / "locks" / "operation.lock"):
        for journal, record in journals:
            if record.get("runtime_root") != str(context.root):
                raise PocketError("unsafe_path", "Installation recovery belongs to a different runtime.")
            destination = Path(record["install_root"])
            launcher = Path(record["launcher"])
            check_path(destination)
            check_path(launcher)
            if launcher != destination / "pocketserver" or destination in (context.root, Path.home(), Path(destination.anchor)):
                raise PocketError("unsafe_path", "Installation recovery paths are unsafe.")
            previous = record.get("previous_registration") or {}
            old_launcher = record.get("previous_launcher")
            if old_launcher is not None:
                content = base64.b64decode(old_launcher, validate=True)
                if b"# pocketserver-owned" not in content:
                    raise PocketError("unsafe_path", "The prior launcher has no ownership marker.")
                atomic_write(launcher, content, mode=0o700)
            elif launcher.exists():
                if "# pocketserver-owned" not in launcher.read_text():
                    raise PocketError("unsafe_path", "Refusing an unowned launcher during recovery.")
                launcher.unlink()
            registration_path = context.root / "state" / "installation.json"
            if previous:
                generation = Path(previous["active_generation"])
                check_path(generation)
                if generation.parent != destination / "generations" or (generation / "pocketserver-owner").read_text() != str(context.root):
                    raise PocketError("unsafe_path", "Prior generation ownership could not be established.")
                atomic_write(registration_path, json.dumps(previous).encode())
                if context.mode == "termux":
                    from core.supervisor import install_runit_entries
                    install_runit_entries(context, app_root=generation / "app", interpreter=previous["interpreter"],
                                          lock_held=True, recovery_held=True)
            elif registration_path.exists():
                registration_path.unlink()
            atomic_write(journal, json.dumps({**record, "phase": "FINALIZED", "rolled_back": True}).encode())
    return {"recovered": len(journals), "action": "rolled_back_installation", "services_started": False}

def uninstall_application(context, *, purge_data=False, confirm=None):
    _production(context)
    registration = _read_registration(context)
    install_root = Path(registration["install_root"])
    check_path(install_root)
    if install_root in (context.root, Path.home(), Path(install_root.anchor)) or context.root.is_relative_to(install_root):
        raise PocketError("unsafe_path", "The registered installation root is unsafe.")
    if purge_data and confirm != str(context.root):
        raise PocketError("confirmation_required", "Confirm the exact registered runtime root before purging.", 409)
    if purge_data:
        from core.ssh_git import SSHGitManager
        SSHGitManager(context).verify_quiescent()
    from core.supervisor import Supervisor, RunitBackend, SERVICE_PROFILES
    supervisor = Supervisor(context=context)
    statuses = supervisor.status()
    for service_id in ("tunnel", "ssh", "api", "web", "dashboard", "controller"):
        if statuses[service_id].get("owned") or statuses[service_id]["running"]:
            supervisor.stop(service_id)
    remove_boot(context)
    runit_registration = context.root / "state" / "runit-install.json"
    if runit_registration.exists():
        backend = RunitBackend(context)
        for service_id in SERVICE_PROFILES:
            directory = backend._directory(service_id)
            result = subprocess.run([shutil.which("sv"), "-w", "5", "exit", str(directory)],
                                    capture_output=True, timeout=7, check=False)
            if result.returncode:
                raise PocketError("stop_failed", "Owned runit supervisor could not be stopped.", 503)
            shutil.rmtree(directory)
        runit_registration.unlink()
    with FileLock(context.root / "locks" / "maintenance.lock"), FileLock(context.root / "locks" / "operation.lock"):
        for value in registration["generations"]:
            generation = Path(value)
            check_path(generation)
            if generation.parent != install_root / "generations":
                raise PocketError("unsafe_path", "A registered generation escaped the install root.")
            if generation.exists():
                if (generation / "pocketserver-owner").read_text() != str(context.root):
                    raise PocketError("unsafe_path", "An installed generation has no matching ownership marker.")
                shutil.rmtree(generation)
        launcher = Path(registration["launcher"])
        if launcher != install_root / "pocketserver":
            raise PocketError("unsafe_path", "Launcher registration escaped the install root.")
        if launcher.exists():
            check_path(launcher)
            if "# pocketserver-owned" not in launcher.read_text():
                raise PocketError("unsafe_path", "Refusing an unowned launcher.")
            launcher.unlink()
        atomic_write(context.root / "state" / "installation.json",
                     json.dumps({**registration, "uninstalled": True, "generations": []}).encode())
    if purge_data:
        # Locks have been released; exact dedicated root was previewed/confirmed.
        check_private(context.root, directory=True)
        if context.root == Path.home() or context.root == Path(context.root.anchor):
            raise PocketError("unsafe_path", "Refusing an unsafe purge root.")
        shutil.rmtree(context.root)
    return {"uninstalled": True, "data_preserved": not purge_data, "runtime_root": str(context.root)}

