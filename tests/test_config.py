import concurrent.futures
import copy
import hashlib
import io
import json
import os
import sys
import threading

import pytest
from werkzeug.security import generate_password_hash

from core import config, runtime
from core.config import ConfigManager, get_default_config, validate_config
from core.errors import PocketError
from core.runtime import RuntimeContext, atomic_write

PASSWORD = "a local test password"


def _initialized():
    manager = ConfigManager()
    manager.initialize(PASSWORD)
    return manager


def test_reads_never_initialize_and_corruption_is_preserved(isolated_runtime):
    manager = ConfigManager()
    assert not manager.is_initialized()
    with pytest.raises(PocketError) as missing:
        manager.get_config()
    assert missing.value.code == "not_initialized"
    assert not isolated_runtime.exists()
    manager.context.initialize()
    original = b'{"auth": broken'
    atomic_write(manager.config_path, original)
    with pytest.raises(PocketError):
        manager.get_config()
    assert manager.config_path.read_bytes() == original
    assert not manager.secret_path.exists()


@pytest.mark.parametrize("field,bad", [
    (("schema_version",), True), (("revision",), 0),
    (("dashboard", "bind_address"), "0.0.0.0"), (("dashboard", "port"), 8080),
    (("dashboard", "session_lifetime_hours"), float("inf")), (("dashboard", "trusted_hosts"), ["evil.test"]),
    (("dashboard", "trusted_origins"), ["http://localhost:80@evil.test"]),
    (("services", "ssh", "port"), True), (("services", "tunnel", "autostart"), True),
    (("services", "tunnel", "target_service"), "dashboard"), (("services", "web", "enabled"), True),
    (("services", "tunnel", "token"), "invalid"), (("files", "max_upload_size_mb"), float("nan")),
    (("auth", "csrf_enabled"), False), (("auth", "password_hash"), "md5:123"),
    (("jobs", "concurrency"), 2), (("metadata", "created_at"), "never"),
])
def test_schema_rejects_invalid_fields(field, bad):
    candidate = get_default_config()
    entry = candidate
    for part in field[:-1]:
        entry = entry[part]
    entry[field[-1]] = bad
    with pytest.raises(PocketError) as invalid:
        validate_config(candidate)
    assert invalid.value.code == "invalid_config"


@pytest.mark.parametrize("data", [b'{"a":1,"a":2}', b'{"number":NaN}', b'{"number":Infinity}'])
def test_ambiguous_json_rejected(data):
    with pytest.raises(PocketError):
        config._decode(data)


def test_password_stdin_and_bounds(monkeypatch):
    monkeypatch.setattr(sys, "stdin", io.StringIO("password with spaces  \n"))
    assert config.read_password(True) == "password with spaces  "
    for password in ("short", "x" * 129):
        with pytest.raises(PocketError):
            config.validate_password(password)


def test_parallel_init_preserves_one_credential_and_key(isolated_runtime):
    passwords = ["first test password", "second test password"]
    barrier = threading.Barrier(2)
    def init(value):
        manager = ConfigManager()
        barrier.wait()
        return manager.initialize(value), manager.get_or_create_secret_key()
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        results = list(pool.map(init, passwords))
    assert results[0] == results[1]
    manager = ConfigManager()
    assert sum(map(manager.verify_password, passwords)) == 1
    assert manager.get_config()["revision"] == 1
    assert len(results[0][1]) == 64


def test_independent_editors_no_lost_updates_and_cas(isolated_runtime):
    manager = _initialized()
    with concurrent.futures.ThreadPoolExecutor(2) as pool:
        futures = [pool.submit(ConfigManager().update_service, name, {"port": port})
                   for name, port in (("api", 9990), ("web", 9991))]
        for future in futures:
            future.result()
    before = manager.get_config()
    assert before["services"]["api"]["port"] == 9990
    assert before["services"]["web"]["port"] == 9991
    assert before["revision"] == 3
    with pytest.raises(PocketError) as conflict:
        manager.update_service("web", {"port": 9090}, expected_revision=1)
    assert conflict.value.code == "conflict"
    with pytest.raises(PocketError):
        manager.transaction(lambda cfg: cfg["auth"].update(auth_generation=123))
    with pytest.raises(PocketError):
        manager.update_service("ssh", {"port": 9991})
    assert manager.get_config() == before
    before["services"].clear()
    assert manager.get_service("ssh")["port"] == 8022


def test_password_change_increments_generation_and_malformed_key_blocks(isolated_runtime):
    manager = _initialized()
    manager.set_admin_password("rotated test password")
    cfg = manager.get_config()
    assert cfg["auth"]["auth_generation"] == 2 and cfg["revision"] == 2
    assert not manager.verify_password(PASSWORD)
    assert manager.verify_password("rotated test password")
    atomic_write(manager.secret_path, b"X" * 64)
    with pytest.raises(PocketError):
        manager.initialize(PASSWORD)
    with pytest.raises(PocketError):
        manager.context.ensure_mutable()
    assert manager.secret_path.read_bytes() == b"X" * 64


def test_post_replace_sync_failure_blocks_until_recovery(isolated_runtime, monkeypatch):
    manager = _initialized()
    def fail_root(path):
        if path == manager.context.root:
            raise OSError("simulated sync failure")
    with monkeypatch.context() as patch:
        patch.setattr(runtime, "sync_directory", fail_root)
        with pytest.raises(PocketError) as uncertain:
            manager.update_service("web", {"port": 9191})
        assert uncertain.value.code == "durability_uncertain"
    assert manager.get_config()["revision"] == 2
    with pytest.raises(PocketError) as blocked:
        manager.context.ensure_mutable()
    assert blocked.value.code == "recovery_required"
    assert manager.recover() == {"recovered": 1}
    manager.context.ensure_mutable()


def test_interrupt_after_config_replace_has_prepared_recovery_evidence(isolated_runtime, monkeypatch):
    manager = _initialized()
    original_write = config.atomic_write
    def interrupt(path, data, *args):
        original_write(path, data, *args)
        if path == manager.config_path:
            raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(config, "atomic_write", interrupt)
        with pytest.raises(KeyboardInterrupt):
            manager.update_service("api", {"port": 9101})
    assert manager.context.pending_recovery()
    assert manager.recover() == {"recovered": 1}
    assert manager.get_service("api")["port"] == 9101


def test_local_rotation_repairs_malformed_signing_key_and_revokes_sessions(isolated_runtime):
    manager = _initialized()
    atomic_write(manager.secret_path, b"damaged")
    manager.rotate_secret_key()
    assert len(manager.get_or_create_secret_key()) == 64
    cfg = manager.get_config()
    assert cfg["auth"]["auth_generation"] == 2 and cfg["revision"] == 2


def _legacy(manager):
    manager.context.initialize()
    hashed = generate_password_hash("tiny", method="pbkdf2:sha256:1000")
    data = {"dashboard": {"enabled": True, "port": 8890, "bind_address": "0.0.0.0"},
            "services": {"web": {"enabled": True, "port": 8000}, "tunnel": {"enabled": True, "token": "private"}},
            "auth": {"password_hash": hashed}, "metadata": {"version": "2.0.0"}}
    raw = json.dumps(data).encode()
    atomic_write(manager.config_path, raw)
    atomic_write(manager.secret_path, b"a" * 64)
    atomic_write(manager.context.paths["pids"] / "web.pid", b"12345")
    return raw, hashed


def test_migration_preview_preserves_bytes_and_requires_explicit_new_password(isolated_runtime):
    manager = ConfigManager()
    raw, hashed = _legacy(manager)
    report = manager.migrate()
    assert "private" not in repr(report) and hashed not in repr(report)
    assert manager.config_path.read_bytes() == raw
    with pytest.raises(PocketError):
        manager.migrate(True)
    result = manager.migrate(True, legacy_stopped=True)
    assert result["applied"]
    from pathlib import Path
    assert Path(result["snapshot"]).read_bytes() == raw
    cfg = manager.get_config()
    assert cfg["auth"]["password_hash"] == hashed and not cfg["auth"]["password_policy_verified"]
    assert not any(service["autostart"] for service in cfg["services"].values())
    assert cfg["dashboard"]["port"] == 8890 and cfg["dashboard"]["bind_address"] == "127.0.0.1"
    assert manager.secret_path.read_bytes() == b"a" * 64
    assert not (manager.context.paths["pids"] / "web.pid").exists()
    manager.set_admin_password(PASSWORD)
    assert manager.verify_password(PASSWORD)


def test_interrupted_migration_rolls_back_exact_legacy_bytes(isolated_runtime, monkeypatch):
    manager = ConfigManager()
    raw, _ = _legacy(manager)
    write = config.atomic_write
    def interrupt(path, data, *args):
        if path.name == "journal.json" and b'"FINALIZED"' in data:
            raise KeyboardInterrupt()
        write(path, data, *args)
    with monkeypatch.context() as patch:
        patch.setattr(config, "atomic_write", interrupt)
        with pytest.raises(KeyboardInterrupt):
            manager.migrate(True, legacy_stopped=True)
    assert manager.context.pending_recovery()
    assert manager.recover() == {"recovered": 1}
    assert manager.config_path.read_bytes() == raw
    assert (manager.context.paths["pids"] / "web.pid").read_bytes() == b"12345"
