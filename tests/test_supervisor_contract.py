"""Lifecycle contracts use fake clocks/backends and private temporary roots."""
import json
import threading
from pathlib import Path
import pytest
from core import config, env
from core.errors import PocketError
from core.logs import BoundedLogWriter, tail_log
from core.runtime import RuntimeContext, atomic_write
from core.service_entry import finish_gate, launch_gate
from core.supervisor import FakeBackend, Supervisor, boot_id, read_gate, write_gate
from core.controller import Controller
from core.locking import FileLock

class Clock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now
    def sleep(self, duration):
        self.now += duration

@pytest.fixture
def runtime(isolated_runtime, monkeypatch):
    monkeypatch.setattr(config, "_hash", lambda password: "pbkdf2:sha256:1000000$testsalt$" + "a" * 64)
    context = RuntimeContext.discover(root=isolated_runtime, mode="mock")
    manager = config.ConfigManager(context)
    manager.initialize("Correct horse battery staple!")
    return context, manager

def instance(runtime):
    context, manager = runtime
    clock = Clock()
    backend = FakeBackend(clock=clock)
    return Supervisor(manager, context, backend, clock=clock, sleep=clock.sleep), backend, clock

def test_construction_and_telemetry_do_not_initialize(isolated_runtime):
    context = RuntimeContext.discover(root=isolated_runtime, mode="mock")
    Supervisor(context=context)
    assert env.get_system_metrics(context)["wake_lock_active"] is None
    assert not isolated_runtime.exists()

@pytest.mark.parametrize("method", ["start", "stop", "restart", "status", "get_logs"])
@pytest.mark.parametrize("identifier", ["../web", "files", "", "web/../../evil"])
def test_every_public_service_path_validates_first(runtime, method, identifier):
    supervisor, backend, _ = instance(runtime)
    with pytest.raises(PocketError) as error:
        getattr(supervisor, method)(identifier)
    assert error.value.code == "invalid_service"
    assert not backend.starts and not backend.stops

def test_pid_evidence_is_never_control_authority(runtime):
    supervisor, backend, _ = instance(runtime)
    root = runtime[0].root
    (root / "pids" / "web.pid").write_text("424242")
    assert supervisor.status("web")["running"] is False
    supervisor.stop("web")
    assert (root / "pids" / "web.pid").read_text() == "424242"
    assert backend.stops == [("web", False)]

def test_start_is_ready_and_does_not_change_autostart(runtime):
    supervisor, backend, _ = instance(runtime)
    assert supervisor.start("web")["ready"]
    assert supervisor.start("web")["ready"]
    assert backend.starts == ["web"]
    assert runtime[1].get_service("web")["autostart"] is False
    assert supervisor.stop("web")["state"] == "stopped"

def test_readiness_timeout_rolls_back_and_releases_demand(runtime):
    supervisor, backend, clock = instance(runtime)
    backend.unready.add("web")
    with pytest.raises(PocketError) as error:
        supervisor.start("web")
    assert error.value.code == "start_failed"
    assert clock.now == pytest.approx(110)
    assert not supervisor.status("web")["running"]
    assert backend.stops == [("web", False)]

def test_failed_stop_prevents_restart(runtime):
    supervisor, backend, clock = instance(runtime)
    supervisor.start("web")
    backend.fail_stop.add("web")
    with pytest.raises(PocketError) as error:
        supervisor.restart("web")
    assert error.value.code == "stop_failed"
    assert backend.starts == ["web"]
    assert backend.stops == [("web", False), ("web", True)]
    assert clock.now == pytest.approx(107)
    assert supervisor.status("web")["running"]

def test_generic_tunnel_never_publishes(runtime):
    supervisor, backend, _ = instance(runtime)
    with pytest.raises(PocketError) as error:
        supervisor.start("tunnel")
    assert error.value.code == "publication_required"
    assert not backend.starts

def test_fake_state_does_not_claim_cross_invocation_ownership(runtime):
    supervisor, _, _ = instance(runtime)
    supervisor.start("web")
    fresh = Supervisor(runtime[1], runtime[0])
    assert not fresh.status("web")["running"]

def test_concurrent_starts_serialize(runtime):
    supervisor, backend, _ = instance(runtime)
    errors = []
    def start():
        try:
            supervisor.start("api")
        except Exception as exc:
            errors.append(exc)
    threads = [threading.Thread(target=start) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(10)
    assert not errors
    assert backend.starts == ["api"]

def test_launch_gate_retries_are_bounded_and_epoch_checked(runtime, monkeypatch):
    context, _ = runtime
    clock = Clock()
    monkeypatch.setattr("core.supervisor.time.monotonic", clock)
    atomic_write(context.root / "state" / "controller-epoch.json",
                 json.dumps({"epoch": "active", "boot_id": boot_id(), "heartbeat": clock()}).encode())
    write_gate(context, "web", {"desired": True, "epoch": "active", "attempts": []})
    for number, delay in enumerate((1, 2, 4, 4)):
        assert launch_gate(context, "web", clock=clock, sleep=clock.sleep, once=True)
        finish_gate(context, "web", clock=clock)
        clock.sleep(delay)
    assert launch_gate(context, "web", clock=clock, sleep=clock.sleep, once=True) is None
    assert read_gate(context, "web")["reason"] == "restart_budget_exhausted"
    write_gate(context, "api", {"desired": True, "epoch": "old", "attempts": []})
    assert launch_gate(context, "api", clock=clock, once=True) is None

def test_tail_and_continuous_sink_bound_long_line(runtime):
    path = runtime[0].paths["logs"] / "web.log"
    writer = BoundedLogWriter(path, max_bytes=1024, backups=2)
    writer.write("password=topsecret\n" + "x" * 300000)
    assert writer.dropped_bytes > 0
    assert path.stat().st_size <= 1024
    assert sum(item.stat().st_size for item in path.parent.glob("web.log*")) <= 3072
    path.write_bytes(b"x" * 200000 + b"\ntoken=secret\n\x1b[31mred")
    text = tail_log(path, 100)
    assert "truncated" in text
    assert "secret" not in text and "\x1b" not in text
    assert len(text.encode()) < 66000

@pytest.mark.parametrize("lines", [0, -1, 1001, True, "10"])
def test_tail_line_bounds(runtime, lines):
    with pytest.raises(ValueError):
        tail_log(runtime[0].paths["logs"] / "web.log", lines)

def test_manual_wake_policy_has_no_command_or_marker(runtime):
    def forbidden(*args, **kwargs):
        raise AssertionError("manual policy invoked a command")
    result = env.request_wake_lock(False, policy="manual", runner=forbidden)
    assert result["held"] is None and result["state"] == "unknown"
    assert not runtime[0].paths["state_wake_lock"].exists()

def test_wake_nonzero_exit_is_failure(runtime, monkeypatch):
    monkeypatch.setattr(env.shutil, "which", lambda name: "/trusted/" + name)
    class Failure:
        returncode = 7
    result = env.request_wake_lock(True, policy="pocketserver-managed", termux=True,
                                   runner=lambda *args, **kwargs: Failure())
    assert result["state"] == "failed" and result["held"] is None

def test_controller_shutdown_cancels_owned_work_and_invalidates_epoch(runtime):
    from types import SimpleNamespace
    context, _ = runtime
    executing, released = threading.Event(), threading.Event()
    interrupts = []
    class Store:
        claimed = False
        def interrupt_running(self): interrupts.append(True)
        def claim_next(self):
            if self.claimed: return None
            self.claimed = True
            return {"id":"owned-operation"}
        def finish(self, *args, **kwargs): pass
    def execute(operation):
        executing.set()
        released.wait(5)
        return {"cancelled":True}
    application = SimpleNamespace(execute_operation=execute,
        jobs=SimpleNamespace(reconcile_interrupted=lambda:None, shutdown_owned=released.set),
        tunnel=SimpleNamespace(reconcile=lambda:None))
    supervisor = SimpleNamespace(reconcile=lambda:None, _wake=lambda:None)
    controller = Controller(context, store=Store(), application=application, supervisor=supervisor)
    thread = threading.Thread(target=controller.run)
    thread.start()
    assert executing.wait(5)
    controller.shutdown.set()
    thread.join(5)
    assert not thread.is_alive() and released.is_set()
    assert len(interrupts) == 2
    assert json.loads((context.root / "state" / "controller-epoch.json").read_text()) == {}

def test_controller_lifetime_lock_rejects_duplicate_dispatcher(runtime):
    from types import SimpleNamespace
    context, _ = runtime
    def forbidden(): raise AssertionError("Duplicate dispatcher touched the operation store")
    controller = Controller(context, store=SimpleNamespace(interrupt_running=forbidden))
    with FileLock(context.root / "locks" / "controller.lock"):
        with pytest.raises(PocketError) as error:
            controller.run()
    assert error.value.code == "busy"

