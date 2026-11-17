"""Local immutable Python jobs, bounded durable results and owned POSIX children.

Cancellation requests are data; only a runner's live Popen handle authorizes a
signal. A restarted controller interrupts old work instead of executing it again.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field

from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.logs import redact_secrets
from core.runtime import atomic_write, check_path, check_private, private_dir, read_private, sync_directory
from core.storage import maintenance_lease

IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}\Z")
TERMINAL = {"succeeded", "failed", "timed_out", "cancelled", "interrupted"}
_OWNED = {}
_MUTEX = threading.RLock()

def _kernel_boot_id():
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        return value if re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", value) else None
    except OSError:
        return None


@dataclass
class _OwnedChild:
    process: object
    stop: threading.Event = field(default_factory=threading.Event)
    lock: threading.RLock = field(default_factory=threading.RLock)
    reaped: bool = False
    exit_code: int | None = None


def owned_jobs_running(context):
    with _MUTEX:
        return any(root == str(context.root) and not owned.reaped
                   for (root, _), owned in _OWNED.items())


def _id(value):
    if not isinstance(value, str) or not IDENTIFIER.fullmatch(value):
        raise PocketError("invalid_job", "Use a bounded alphanumeric job or run ID.")
    return value


class JobManager:
    def __init__(self, context, config=None, *, popen=None, clock=None, sleep=None):
        self.context = context
        self.config = config or ConfigManager(context)
        self.popen = popen or subprocess.Popen
        self.clock, self.sleep = clock or time.monotonic, sleep or time.sleep
        self.definitions = context.paths["jobs"]
        self.runs = context.paths["state"] / "job-runs"

    def _cfg(self):
        return self.config.get_config() if hasattr(self.config, "get_config") else self.config

    def verify_quiescent(self):
        """A persisted PID never permits signaling or proves a lost child exited."""
        current = _kernel_boot_id()
        marker = self.context.paths["state"] / "job-child.json"
        if marker.exists():
            record = self._read(marker)
            previous = record.get("boot_id")
            previous = previous if isinstance(previous, str) and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", previous) else None
            if not current or not previous or current == previous:
                raise PocketError("job_children_uncertain", "A previous runner may still own writing descendants. Reboot and verify the kernel boot identity before recovery.", 409)
        for record in self._records():
            if (record["state"] == "running" or record["state"] == "interrupted" and record.get("started")) and not record.get("ownership_closed"):
                previous = record.get("boot_id")
                previous = previous if isinstance(previous, str) and re.fullmatch(r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}", previous) else None
                if not current or not previous or current == previous:
                    raise PocketError("job_children_uncertain", "A lost runner has no verified descendant-closure evidence.", 409)
        return True

    def _execution_supported(self):
        return (os.name == "posix" and self.context.mode == "termux"
                and all(hasattr(os, name) for name in ("waitid", "WNOWAIT", "P_PID", "WEXITED", "WNOHANG")))

    def _lock(self):
        return FileLock(self.context.paths["locks"] / "jobs.lock")

    def _read(self, path):
        try:
            record = json.loads(read_private(path, 256 * 1024))
            if not isinstance(record, dict):
                raise ValueError()
            return record
        except FileNotFoundError as exc:
            raise PocketError("not_found", "Unknown registered job or run.", 404) from exc
        except (ValueError, TypeError) as exc:
            raise PocketError("recovery_required", "Job state requires local recovery.", 503) from exc

    def _save(self, record):
        atomic_write(self.runs / (_id(record["id"]) + ".json"), json.dumps(record, sort_keys=True).encode())

    def _definition(self, job_id):
        return self._read(self.definitions / (_id(job_id) + ".json"))

    def register(self, id, script, argv=None, cwd=None, timeout=None):
        """Local CLI contract only. The HTTP layer must never expose registration."""
        self.context.ensure_mutable()
        _id(id)
        script = Path(script)
        check_path(script)
        check_private(script)
        if script.suffix.lower() != ".py" or script.is_relative_to(self.context.paths["files"]):
            raise PocketError("invalid_job", "Register a trusted local Python script outside the upload vault.")
        argv = [] if argv is None else argv
        if not isinstance(argv, list) or len(argv) > 32 or any(not isinstance(v, str) or len(v) > 4096 or "\x00" in v for v in argv):
            raise PocketError("invalid_job", "Job argv must be a bounded list of fixed strings.")
        cwd = Path(cwd) if cwd is not None else script.parent
        check_path(cwd)
        check_private(cwd, directory=True)
        if cwd.is_relative_to(self.context.paths["files"]):
            raise PocketError("invalid_job", "An uploaded directory cannot be a job working directory.")
        cfg = self._cfg()["jobs"]
        timeout = cfg["default_timeout_seconds"] if timeout is None else timeout
        if type(timeout) is not int or not 1 <= timeout <= cfg["max_timeout_seconds"]:
            raise PocketError("invalid_job", "Timeout must be within the configured bound.")
        record = {"id": id, "script": str(script), "argv": argv, "cwd": str(cwd), "timeout": timeout,
                  "sha256": hashlib.sha256(read_private(script, 8 * 1024 * 1024)).hexdigest(), "parameters": {}}
        with maintenance_lease(self.context), self._lock():
            path = self.definitions / (id + ".json")
            if path.exists():
                raise PocketError("conflict", "Registered job definitions are immutable. Choose a new ID.", 409)
            atomic_write(path, json.dumps(record, sort_keys=True).encode())
        return record

    def list(self):
        check_path(self.definitions)
        if not self.definitions.exists():
            return []
        return [self._read(path) for path in sorted(self.definitions.glob("*.json"))]

    def _records(self):
        check_path(self.runs)
        if not self.runs.exists():
            return []
        check_private(self.runs, directory=True)
        return [self._read(path) for path in self.runs.glob("*.json")]

    def get_run(self, run_id):
        return self._read(self.runs / (_id(run_id) + ".json"))

    def _prune(self):
        results = sorted((r for r in self._records() if r["state"] in TERMINAL), key=lambda r: r["created"], reverse=True)
        budget = self._cfg()["logs"]["total_bytes"] // 2
        used = 0
        for index, result in enumerate(results):
            path = self.runs / (result["id"] + ".json")
            used += path.stat().st_size
            if index >= 100 or result["created"] < time.time() - 7 * 86400 or used > budget:
                path.unlink()

    def _finish(self, run_id, state, **fields):
        # Completion and cancellation never reacquire maintenance.
        if isinstance(fields.get("output"), str):
            known = (self.config.get_or_create_secret_key(), self._cfg()["auth"]["password_hash"])
            fields["output"] = redact_secrets(fields["output"], known)
        with self._lock():
            record = self.get_run(run_id)
            record.update(state=state, finished=time.time(), **fields)
            self._save(record)
            self._prune()
            return record

    def cancel(self, run_id):
        self.context.ensure_mutable()
        with self._lock():
            record = self.get_run(run_id)
            if record["state"] not in TERMINAL:
                record["cancel_requested"] = True
                if record["state"] == "queued":
                    record.update(state="cancelled", finished=time.time())
                self._save(record)
            return record

    def reconcile_interrupted(self):
        self.context.ensure_mutable()
        # A held runner lease means a live owner may still be writing. Refuse.
        with FileLock(self.context.paths["locks"] / "jobs-runner.lock", timeout=0), self._lock():
            for record in self._records():
                if record["state"] in ("queued", "running"):
                    record.update(state="interrupted", finished=time.time(), error="Controller execution was lost; it was not replayed.")
                    self._save(record)
            self._prune()

    @staticmethod
    def _signal(process, sig):
        try:
            os.killpg(process.pid, sig)
        except ProcessLookupError:
            pass

    def _exited_without_reaping(self, process):
        observation = os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
        return observation is not None and observation.si_pid == process.pid

    def _teardown(self, owned):
        """Keep the leader unreaped until every group signal has been issued.

        A zombie leader reserves its numeric PID/group identity. Calling poll or
        wait before the last group signal would destroy that ownership proof.
        The ownership lock also prevents shutdown from racing a runner's reap.
        """
        with owned.lock:
            if owned.reaped:
                return owned.exit_code
            if not self._exited_without_reaping(owned.process):
                self._signal(owned.process, signal.SIGTERM)
                deadline = self.clock() + 1
                while not self._exited_without_reaping(owned.process) and self.clock() < deadline:
                    self.sleep(0.05)
            # The still-unreaped direct child anchors this group even if it
            # already exited while descendants retain stdout/stderr pipes.
            self._signal(owned.process, signal.SIGKILL)
            owned.exit_code = owned.process.wait(timeout=2)
            owned.reaped = True
            return owned.exit_code

    def shutdown_owned(self):
        """Signal only process groups belonging to live handles in this process."""
        with _MUTEX:
            owned = [(key, value) for key, value in _OWNED.items() if key[0] == str(self.context.root)]
        for (_, run_id), child in owned:
            child.stop.set()
            try:
                self.cancel(run_id)
            except PocketError:
                # A recovery/config failure must not strand the actual owned
                # child. The live stop event still reaches its runner.
                pass
            self._teardown(child)
        return len(owned)

    def run(self, id, parameters=None, run_id=None):
        self.context.ensure_mutable()
        definition = self._definition(id)
        if parameters not in (None, {}):
            raise PocketError("invalid_parameters", "This immutable job accepts no parameters.")
        if not self._execution_supported():
            raise PocketError("unsupported", "Job execution requires the owned POSIX production runner.", 503)
        run_id = _id(run_id or uuid.uuid4().hex)
        private_dir(self.runs)
        with self._lock():
            path = self.runs / (run_id + ".json")
            if path.exists():
                old = self.get_run(run_id)
                if old["job_id"] != id:
                    raise PocketError("conflict", "Run ID already identifies another job.", 409)
                return old
            # Cancellation may arrive after the dispatcher claims an operation
            # and before its runner record exists. The operation tombstone is
            # durable; inspect it under the same lock used to publish the run.
            if (self.context.root / "state.sqlite3").is_file():
                from core.state import OperationsStore
                try:
                    operation = OperationsStore(self.context).get(run_id)
                except PocketError as exc:
                    if exc.code != "not_found":
                        raise
                else:
                    if operation["phase"] in {"cancelled", "cancelling"}:
                        record = {"id": run_id, "job_id": id, "state": "cancelled", "created": time.time(), "finished": time.time(), "cancel_requested": True, "output": "", "dropped_output_bytes": 0, "exit_code": None}
                        self._save(record)
                        return record
            self._prune()
            if sum(r["state"] == "queued" for r in self._records()) >= min(10, self._cfg()["jobs"]["queue_limit"]):
                raise PocketError("queue_full", "The job queue is full.", 409)
            self._save({"id": run_id, "job_id": id, "state": "queued", "created": time.time(), "cancel_requested": False,
                        "output": "", "dropped_output_bytes": 0, "exit_code": None})
        # Waiting callers hold no maintenance lease and remain cancellable.
        while True:
            if self.get_run(run_id)["state"] in TERMINAL:
                return self.get_run(run_id)
            entered_execution = False
            try:
                with maintenance_lease(self.context), FileLock(self.context.paths["locks"] / "jobs-runner.lock", timeout=0):
                    entered_execution = True
                    return self._execute(definition, run_id)
            except PocketError as exc:
                if exc.code == "busy" and not entered_execution:
                    self.sleep(0.05)
                    continue
                self._finish(run_id, "interrupted", error="Runner stopped; execution was not replayed.")
                raise
            except BaseException:
                self._finish(run_id, "interrupted", error="Runner stopped; execution was not replayed.")
                raise

    def _execute(self, definition, run_id):
        with self._lock():
            record = self.get_run(run_id)
            if record["state"] in TERMINAL:
                return record
            self.verify_quiescent()
            for old in self._records():
                if old["state"] == "running":
                    old.update(state="interrupted", finished=time.time())
                    self._save(old)
            record.update(state="running", started=time.time(), boot_id=_kernel_boot_id())
            self._save(record)
        script = Path(definition["script"])
        if hashlib.sha256(read_private(script, 8 * 1024 * 1024)).hexdigest() != definition["sha256"]:
            return self._finish(run_id, "failed", error="Registered script changed; register a new immutable definition.")
        check_private(Path(definition["cwd"]), directory=True)
        timeout = min(definition["timeout"], self._cfg()["jobs"]["max_timeout_seconds"])
        logs = self._cfg()["logs"]
        # JSON can expand one control byte to six bytes. Keep the complete
        # durable record within the 256 KiB strict-read limit even then.
        cap = min(32768, logs["max_bytes"] // 6, max(1, logs["total_bytes"] // 24))
        output = bytearray()
        dropped = [0]
        output_lock = threading.Lock()
        env = {key: os.environ[key] for key in ("PATH", "PREFIX", "TMPDIR") if key in os.environ}
        env.update(HOME=str(self.context.root), PYTHONUNBUFFERED="1", POCKETSERVER_HOME=str(self.context.root))
        process = None
        owned = None
        threads = []
        intent = self.context.paths["state"] / "job-child.json"

        def drain(stream):
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    with output_lock:
                        remaining = max(0, cap - len(output))
                        output.extend(chunk[:remaining])
                        dropped[0] += max(0, len(chunk) - remaining)
            finally:
                stream.close()

        try:
            atomic_write(intent, json.dumps({"run_id": run_id, "boot_id": _kernel_boot_id(), "phase": "launch_intent"}).encode())
            process = self.popen([sys.executable, str(script), *definition["argv"]], cwd=definition["cwd"], env=env,
                                 stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 start_new_session=True, close_fds=True)
            owned = _OwnedChild(process)
            with _MUTEX:
                _OWNED[(str(self.context.root), run_id)] = owned
            for stream in (process.stdout, process.stderr):
                thread = threading.Thread(target=drain, args=(stream,), daemon=True)
                thread.start()
                threads.append(thread)
            deadline = self.clock() + timeout
            state = None
            while True:
                with owned.lock:
                    exited = owned.reaped or self._exited_without_reaping(process)
                if exited:
                    break
                if owned.stop.is_set() or self.get_run(run_id).get("cancel_requested"):
                    state = "cancelled"
                    break
                if self.clock() >= deadline:
                    state = "timed_out"
                    break
                self.sleep(0.05)
            if owned.stop.is_set():
                state = "cancelled"
            code = self._teardown(owned)
            for thread in threads:
                thread.join(timeout=2)
            if any(thread.is_alive() for thread in threads):
                raise PocketError("runner_uncertain", "Owned output drain did not finish.", 503)
            return self._finish(run_id, state or ("succeeded" if code == 0 else "failed"), exit_code=code,
                                output=output.decode("utf-8", "replace"), dropped_output_bytes=dropped[0], ownership_closed=True)
        except OSError as exc:
            return self._finish(run_id, "failed", error="The owned runner could not launch or supervise this job.")
        finally:
            if owned is not None:
                self._teardown(owned)
                with _MUTEX:
                    _OWNED.pop((str(self.context.root), run_id), None)
            if process is None or owned is not None and owned.reaped:
                intent.unlink(missing_ok=True)
                sync_directory(intent.parent)
