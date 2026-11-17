import io
from pathlib import Path

import pytest

from core.config import ConfigManager
from core.errors import PocketError
from core.jobs import JobManager
from core.runtime import RuntimeContext, atomic_write, private_dir


@pytest.fixture
def manager(isolated_runtime, monkeypatch):
    # Only mocked POSIX process effects are exercised on the Windows host.
    monkeypatch.setattr("core.jobs.signal.SIGKILL", 9, raising=False)
    monkeypatch.setattr("core.config.PBKDF2_ITERATIONS", 1000)
    context = RuntimeContext(isolated_runtime, "mock")
    ConfigManager(context).initialize("a-long-safe-test-password")
    manager = JobManager(context)
    monkeypatch.setattr(manager, "_exited_without_reaping", lambda process: not process.running)
    return manager


def register(manager):
    script = manager.context.root / "trusted.py"
    atomic_write(script, b"print('hello')\n")
    return manager.register("demo", str(script), argv=["fixed"], timeout=2)


def queued(manager, identifier="run1"):
    private_dir(manager.runs)
    manager._save({"id": identifier, "job_id": "demo", "state": "queued", "created": __import__("time").time(), "cancel_requested": False})


def test_registration_is_immutable_and_rejects_uploaded_scripts(manager):
    record = register(manager)
    assert manager.list() == [record]
    with pytest.raises(PocketError, match="immutable"):
        manager.register("demo", record["script"])
    uploaded = manager.context.paths["files"] / "bad.py"
    atomic_write(uploaded, b"pass\n")
    with pytest.raises(PocketError, match="upload vault"):
        manager.register("bad", str(uploaded))


def test_mock_execution_and_unregistered_parameters_refused(manager):
    register(manager)
    with pytest.raises(PocketError) as exc:
        manager.run("demo")
    assert exc.value.code == "unsupported"
    with pytest.raises(PocketError) as exc:
        manager.run("demo", parameters={"command": "evil"})
    assert exc.value.code == "invalid_parameters"


def test_cross_manager_cancel_is_persistent_and_never_signals_a_pid(manager):
    queued(manager)
    other = JobManager(manager.context)
    other.cancel("run1")
    assert manager.get_run("run1")["state"] == "cancelled"
    assert manager.get_run("run1")["cancel_requested"] is True


def test_cancel_between_claim_and_runner_record_prevents_execution(manager, monkeypatch):
    from core.state import OperationsStore, StateStore
    register(manager)
    StateStore(manager.context).initialize()
    operations = OperationsStore(manager.context)
    op = operations.enqueue("job_run", "demo")
    operations.claim_next()
    operations.cancel_queued_job(op["id"])
    monkeypatch.setattr(manager, "_execution_supported", lambda: True)
    monkeypatch.setattr(manager, "_execute", lambda *args: pytest.fail("Cancelled work must not launch"))
    assert manager.run("demo", run_id=op["id"])["state"] == "cancelled"


def test_restart_marks_both_running_and_queued_interrupted(manager):
    queued(manager)
    record = manager.get_run("run1")
    record.update(state="running", pid=12345)
    manager._save(record)
    queued(manager, "run2")
    manager.reconcile_interrupted()
    assert manager.get_run("run1")["state"] == "interrupted"
    assert manager.get_run("run2")["state"] == "interrupted"
    assert manager.shutdown_owned() == 0


class FakeProcess:
    pid = 987654
    def __init__(self, *, output=b"ok\n", running=False):
        self.stdout, self.stderr = io.BytesIO(output), io.BytesIO(b"stderr\n")
        self.running = running
        self.reaped = False
    def poll(self):
        return None if self.running else 0
    def wait(self, timeout=None):
        self.running = False
        self.reaped = True
        return 0


def test_owned_runner_bounded_output_and_fixed_argv(manager, monkeypatch):
    definition = register(manager)
    queued(manager)
    calls, signals = [], []
    def popen(argv, **kwargs):
        calls.append((argv, kwargs))
        return FakeProcess(output=b"x" * 100000)
    manager.popen = popen
    monkeypatch.setattr(manager, "_signal", lambda process, sig: signals.append((process, sig)))
    result = manager._execute(definition, "run1")
    assert result["state"] == "succeeded"
    assert len(result["output"].encode()) <= 65536
    assert result["dropped_output_bytes"] > 0
    assert calls[0][0][-1] == "fixed"
    assert calls[0][1]["start_new_session"] is True
    assert calls[0][1]["stdin"] is not None
    assert signals


def test_job_results_redact_tokens_and_signing_material_before_persistence(manager, monkeypatch):
    definition = register(manager)
    queued(manager)
    secret = manager.config.get_or_create_secret_key()
    process = FakeProcess(output=("token=do-not-expose\n" + secret).encode())
    manager.popen = lambda *args, **kwargs: process
    monkeypatch.setattr(manager, "_signal", lambda *args: None)
    result = manager._execute(definition, "run1")
    assert "do-not-expose" not in result["output"] and secret not in result["output"]
    assert "do-not-expose" not in (manager.runs / "run1.json").read_text()


def test_timeout_kills_owned_group_and_reaps(manager, monkeypatch):
    definition = register(manager)
    queued(manager)
    process = FakeProcess(running=True)
    manager.popen = lambda *a, **kw: process
    times = iter([0, 5, 6, 8])
    manager.clock = lambda: next(times)
    signals = []
    def owned_signal(owned, sig):
        assert not owned.reaped, "A group signal followed reaping its leader"
        signals.append((owned, sig))
        owned.running = False
    monkeypatch.setattr(manager, "_signal", owned_signal)
    assert manager._execute(definition, "run1")["state"] == "timed_out"
    assert all(owned is process for owned, sig in signals)
    assert process.poll() == 0
    assert process.reaped


def test_modified_script_is_not_executed(manager):
    definition = register(manager)
    atomic_write(Path(definition["script"]), b"print('changed')\n")
    queued(manager)
    manager.popen = lambda *a, **kw: pytest.fail("Changed script executed")
    assert manager._execute(definition, "run1")["state"] == "failed"


def test_running_cancel_reaches_owned_handle(manager, monkeypatch):
    definition = register(manager)
    queued(manager)
    process = FakeProcess(running=True)
    def popen(*args, **kwargs):
        JobManager(manager.context).cancel("run1")
        return process
    manager.popen = popen
    signals = []
    def owned_signal(owned, sig):
        assert not owned.reaped, "A group signal followed reaping its leader"
        signals.append(owned)
        owned.running = False
    monkeypatch.setattr(manager, "_signal", owned_signal)
    assert manager._execute(definition, "run1")["state"] == "cancelled"
    assert signals and all(owned is process for owned in signals)


def test_run_id_deduplicates_without_reexecuting(manager, monkeypatch):
    register(manager)
    monkeypatch.setattr(manager, "_execution_supported", lambda: True)
    monkeypatch.setattr(manager, "_signal", lambda *args: None)
    calls = []
    def popen(*args, **kwargs):
        calls.append(args)
        return FakeProcess(output=b"\x00" * 100000)
    manager.popen = popen
    first = manager.run("demo", run_id="once")
    assert first["state"] == "succeeded"
    assert manager.run("demo", run_id="once") == first
    assert len(calls) == 1
    assert (manager.runs / "once.json").stat().st_size < 256 * 1024


def test_pending_queue_limit_is_enforced(manager, monkeypatch):
    register(manager)
    monkeypatch.setattr(manager, "_execution_supported", lambda: True)
    for index in range(10):
        queued(manager, "pending" + str(index))
    with pytest.raises(PocketError) as exc:
        manager.run("demo")
    assert exc.value.code == "queue_full"


def test_lost_child_intent_survives_record_pruning_and_requires_boot_proof(manager, monkeypatch):
    monkeypatch.setattr("core.jobs._kernel_boot_id", lambda: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
    marker = manager.context.paths["state"] / "job-child.json"
    atomic_write(marker, b'{"run_id":"old","boot_id":"aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"}')
    with pytest.raises(PocketError) as error:
        manager.verify_quiescent()
    assert error.value.code == "job_children_uncertain"
    monkeypatch.setattr("core.jobs._kernel_boot_id", lambda: None)
    with pytest.raises(PocketError):
        manager.verify_quiescent()
    monkeypatch.setattr("core.jobs._kernel_boot_id", lambda: "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")
    assert manager.verify_quiescent()
    assert marker.exists(), "Read-only observation preserves closure evidence"


def test_shutdown_reaps_owned_child_when_persistence_is_unavailable(manager, monkeypatch):
    from core.jobs import _OWNED, _OwnedChild
    process = FakeProcess(running=True)
    child = _OwnedChild(process)
    key = (str(manager.context.root), "owned")
    _OWNED[key] = child
    def unavailable(run_id):
        raise PocketError("recovery_required", "state unavailable", 503)
    monkeypatch.setattr(manager, "cancel", unavailable)
    signals = []
    def signal_owned(owned, sig):
        assert not owned.reaped
        signals.append(sig)
        owned.running = False
    monkeypatch.setattr(manager, "_signal", signal_owned)
    try:
        assert manager.shutdown_owned() == 1
        assert child.stop.is_set() and process.reaped and signals
        # Repeating shutdown cannot signal the reaped group a second time.
        manager.shutdown_owned()
        assert len(signals) == 2
    finally:
        _OWNED.pop(key, None)
