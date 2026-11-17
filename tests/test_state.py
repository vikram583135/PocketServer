import pytest

from core.config import ConfigManager
from core.errors import PocketError
from core.runtime import RuntimeContext
from core.state import OperationsStore, ReservationStore, StateStore


@pytest.fixture
def context(isolated_runtime):
    context = RuntimeContext(isolated_runtime, "mock")
    ConfigManager(context=context).initialize("correct horse battery")
    StateStore(context).initialize()
    return context


def test_operation_idempotency_and_terminal_result(context):
    store = OperationsStore(context)
    first = store.enqueue("start", "web", idempotency_key="unique-request")
    assert store.enqueue("start", "web", idempotency_key="unique-request")["id"] == first["id"]
    with pytest.raises(PocketError, match="different request"):
        store.enqueue("stop", "web", idempotency_key="unique-request")
    claimed = store.claim_next()
    assert claimed["id"] == first["id"] and claimed["phase"] == "running"
    assert store.claim_next() is None
    store.finish(first["id"], {"running": True})
    assert store.get(first["id"])["phase"] == "succeeded"


def test_operation_queue_bound_and_no_crash_replay(context):
    store = OperationsStore(context)
    for _ in range(16):
        store.enqueue("start", "web")
    with pytest.raises(PocketError, match="full"):
        store.enqueue("start", "web")
    running = store.claim_next()
    store.interrupt_running()
    assert store.get(running["id"])["phase"] == "interrupted"
    assert store.claim_next()["id"] != running["id"]


def test_aggregate_reservations_preserve_headroom(context):
    store = ReservationStore(context)
    free = store.HEADROOM + 100
    store.reserve("listener", 75, free_bytes=free)
    with pytest.raises(PocketError, match="Insufficient"):
        store.reserve("upload", 26, free_bytes=free)
    store.reserve("upload", 25, free_bytes=free)
    assert store.total() == 100
    store.release("listener")
    assert store.total() == 25


def test_corrupt_state_is_not_recreated(context):
    store = StateStore(context)
    store.path.write_bytes(b"not a database")
    with pytest.raises(PocketError, match="recovery"):
        store.initialize()
    assert store.path.read_bytes() == b"not a database"


def test_init_refuses_to_reconstruct_missing_security_tables(context):
    store = StateStore(context)
    with store.connection(write=True) as db:
        db.execute("DROP TABLE sessions")
    original = store.path.read_bytes()
    with pytest.raises(PocketError, match="explicit local state recovery"):
        store.initialize()
    assert store.path.read_bytes() == original


def test_rate_limit_has_global_and_client_bounds(context):
    store = StateStore(context)
    for _ in range(5):
        store.rate_attempt("one", now=100)
    with pytest.raises(PocketError) as error:
        store.rate_attempt("one", now=101)
    assert error.value.status == 429
    store.rate_attempt("one", now=161)


def test_successful_hash_refunds_only_the_reserved_rate_window(context):
    store = StateStore(context)
    for _ in range(4):
        store.rate_attempt("owner", now=100)
    success = store.rate_attempt("owner", now=101)
    store.rate_success(success)
    store.rate_attempt("owner", now=102)
    with pytest.raises(PocketError):
        store.rate_attempt("owner", now=103)
    for _ in range(5):
        store.rate_attempt("owner", now=165)
    store.rate_success(success)
    with pytest.raises(PocketError):
        store.rate_attempt("owner", now=166)


def test_job_cancellation_before_and_after_dispatch_is_durable(context):
    store = OperationsStore(context)
    first = store.enqueue("job_run", "job")
    assert store.cancel_queued_job(first["id"])["state"] == "cancelled"
    assert store.cancel_queued_job(first["id"])["state"] == "cancelled"
    assert store.claim_next() is None
    second = store.enqueue("job_run", "job")
    store.claim_next()
    assert store.cancel_queued_job(second["id"]) is None
    assert store.get(second["id"])["phase"] == "cancelling"
    store.finish(second["id"], result={"state": "cancelled"})
    assert store.get(second["id"])["phase"] == "cancelled"


def test_job_queue_has_separate_admission_bound(context):
    store = OperationsStore(context)
    for _ in range(10):
        store.enqueue("job_run", "job")
    with pytest.raises(PocketError, match="job admission"):
        store.enqueue("job_run", "job")


@pytest.mark.parametrize("result,phase", [({"state":"failed"}, "failed"), ({"state":"timed_out"}, "timed_out"), ({"ok":False}, "failed")])
def test_failed_results_never_become_successful_operations(context, result, phase):
    store = OperationsStore(context)
    op = store.enqueue("job_run", "job")
    store.claim_next()
    store.finish(op["id"], result=result)
    assert store.get(op["id"])["phase"] == phase


def _damaged(context):
    from core.runtime import atomic_write
    store = StateStore(context)
    atomic_write(store.path, b"preserve the corrupt database")
    sidecar = store.path.with_name(store.path.name + "-wal")
    atomic_write(sidecar, b"preserve WAL evidence")
    return store, sidecar


def test_state_rebuild_is_explicit_preserves_database_and_sidecars(context):
    from pathlib import Path
    store, sidecar = _damaged(context)
    before = ConfigManager(context).get_config()
    key = ConfigManager(context).get_or_create_secret_key()
    preview = store.recover()
    assert preview["needed"] and not preview["applied"]
    assert store.path.read_bytes() == b"preserve the corrupt database"
    assert not list(context.paths["recovery"].glob("state-db-*"))
    result = store.recover(apply=True)
    assert result["applied"] and not result["restore_finalization_pending"]
    assert Path(result["preserved"]["state.sqlite3"]).read_bytes() == b"preserve the corrupt database"
    assert Path(result["preserved"]["state.sqlite3-wal"]).read_bytes() == b"preserve WAL evidence"
    assert not sidecar.exists()
    assert ConfigManager(context).get_or_create_secret_key() == key
    now = ConfigManager(context).get_config()
    assert now["revision"] == before["revision"] + 1
    assert now["auth"]["auth_generation"] == before["auth"]["auth_generation"] + 1
    with store.connection() as db:
        for table in ("sessions", "operations", "rates", "reservations"):
            assert db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0
    assert not store.recover(apply=True)["needed"]
    assert ConfigManager(context).get_config() == now


def test_healthy_state_and_dry_run_have_no_repair_side_effects(context):
    store = StateStore(context)
    operation = OperationsStore(context).enqueue("start", "web")
    old = ConfigManager(context).get_config()
    assert store.recover() == store.recover(apply=True)
    assert not store.recover()["needed"]
    assert OperationsStore(context).get(operation["id"])["phase"] == "queued"
    assert ConfigManager(context).get_config() == old


@pytest.mark.parametrize("step", [1, 2, 3])
def test_state_rebuild_resumes_after_each_preserve_or_publish_rename(context, monkeypatch, step):
    from core import state
    store, _ = _damaged(context)
    current = ConfigManager(context).get_config()
    move = state._state_move
    count = 0
    def interrupt(source, dest):
        nonlocal count
        move(source, dest)
        count += 1
        if count == step:
            raise KeyboardInterrupt("simulated process death")
    with monkeypatch.context() as patch:
        patch.setattr(state, "_state_move", interrupt)
        with pytest.raises(KeyboardInterrupt):
            store.recover(apply=True)
    with pytest.raises(PocketError, match="pending journal"):
        with store.connection():
            pass
    assert store.recover(apply=True)["applied"]
    assert not context.pending_recovery()
    assert ConfigManager(context).get_config()["revision"] == current["revision"] + 1


def test_state_repair_handles_nested_config_commit_interruption(context, monkeypatch):
    from core import config
    store, _ = _damaged(context)
    before = ConfigManager(context).get_config()
    write = config.atomic_write
    def interrupt(path, data, *args):
        write(path, data, *args)
        if path == context.paths["config_file"]:
            raise KeyboardInterrupt("after config replace before its durability marker cleanup")
    with monkeypatch.context() as patch:
        patch.setattr(config, "atomic_write", interrupt)
        with pytest.raises(KeyboardInterrupt):
            store.recover(apply=True)
    assert len(context.pending_recovery()) == 2
    assert store.recover(apply=True)["applied"]
    assert not context.pending_recovery()
    after = ConfigManager(context).get_config()
    assert after["revision"] == before["revision"] + 1
    assert after["auth"]["auth_generation"] == before["auth"]["auth_generation"] + 1


def test_state_repair_rejects_unrelated_journal_and_live_writer(context):
    from core.runtime import atomic_write
    from core.supervisor import Supervisor
    store, _ = _damaged(context)
    supervisor = Supervisor(context=context)
    supervisor.backend.start("web")
    with pytest.raises(PocketError, match="Stop all relevant services"):
        store.recover(supervisor, apply=True)
    supervisor.backend.stop("web")
    atomic_write(context.paths["recovery"] / "unknown.json", b'{"phase":"pending"}')
    with pytest.raises(PocketError, match="unrelated"):
        store.recover(supervisor, apply=True)
    assert store.path.read_bytes() == b"preserve the corrupt database"


def test_state_repair_rejects_substituted_evidence(context, monkeypatch):
    from core import state
    from core.runtime import atomic_write
    store, _ = _damaged(context)
    move = state._state_move
    def interrupt(source, dest):
        move(source, dest)
        raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(state, "_state_move", interrupt)
        with pytest.raises(KeyboardInterrupt):
            store.recover(apply=True)
    preserved = next(context.paths["recovery"].glob("*.original-state.sqlite3-wal"))
    atomic_write(preserved, b"wrong evidence")
    with pytest.raises(PocketError, match="registered recovery evidence"):
        store.recover(apply=True)
    assert context.pending_recovery()


def test_state_repair_unblocks_data_committed_restore_finalization(context, monkeypatch):
    from core.backups import BackupManager
    from core.storage import secure_filesystem_available
    from core.runtime import atomic_write
    if not secure_filesystem_available():
        pytest.skip("requires the POSIX restore backend")
    manager = BackupManager(context)
    archive = manager.create(external_writers_stopped=True)
    def interrupt(self, journal):
        raise KeyboardInterrupt("before volatile state finalization")
    with monkeypatch.context() as patch:
        patch.setattr(StateStore, "clear_for_restore", interrupt)
        with pytest.raises(KeyboardInterrupt):
            manager.restore(archive["id"], apply=True, external_writers_stopped=True)
    before = ConfigManager(context).get_config()
    store, _ = _damaged(context)
    repair = store.recover(apply=True)
    assert repair["applied"] and repair["restore_finalization_pending"]
    assert len(context.pending_recovery()) == 1
    assert manager.recover()["recovered"] == 1
    assert not context.pending_recovery()
    after = ConfigManager(context).get_config()
    assert after["revision"] == before["revision"] + 1
    assert after["auth"]["auth_generation"] == before["auth"]["auth_generation"] + 1
