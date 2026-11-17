import os
import threading
from pathlib import Path

import pytest

from core.errors import PocketError
from core.locking import FileLock
from core.runtime import RuntimeContext, atomic_write


def test_discovery_is_read_only(isolated_runtime):
    context = RuntimeContext.discover()
    assert context.mode == "mock" and context.root == isolated_runtime
    assert all(p == isolated_runtime or isolated_runtime in p.parents for p in context.paths.values())
    with pytest.raises(PocketError, match="Initialize"):
        context.ensure_mutable()
    assert not context.root.exists()


def test_unsafe_root_and_selection(isolated_runtime, monkeypatch):
    for path in (Path("relative"), isolated_runtime / ".." / "escape", isolated_runtime / ".git" / "child"):
        with pytest.raises(PocketError) as error:
            RuntimeContext.discover(path, "mock")
        assert error.value.code == "unsafe_path"
    with pytest.raises(PocketError):
        RuntimeContext.discover(mode="fallback")
    monkeypatch.delenv("PREFIX", raising=False)
    with pytest.raises(PocketError) as error:
        RuntimeContext.discover(mode="termux")
    assert error.value.code == "unsupported"


def test_linked_ancestor_rejected(tmp_path):
    target = tmp_path / "destination"
    target.mkdir()
    link = tmp_path / "alias"
    try:
        link.symlink_to(target, target_is_directory=True)
    except OSError:
        pytest.skip("host cannot create symlinks")
    with pytest.raises(PocketError):
        RuntimeContext.discover(link / "nested", "mock")
    assert list(target.iterdir()) == []


def test_shared_readers_block_exclusive_writer(isolated_runtime):
    context = RuntimeContext.discover()
    context.initialize()
    lock = context.paths["locks"] / "maintenance.lock"
    with FileLock(lock, shared=True), FileLock(lock, shared=True):
        with pytest.raises(PocketError) as unavailable:
            with FileLock(lock, timeout=0):
                pytest.fail("writer overlapped readers")
        assert unavailable.value.code == "busy"
    with FileLock(lock, timeout=0):
        with pytest.raises(PocketError):
            with FileLock(lock, timeout=0, shared=True):
                pytest.fail("reader overlapped writer")
    assert lock.exists()


def test_atomic_write_precommit_failure_leaves_old_bytes(isolated_runtime, monkeypatch):
    context = RuntimeContext.discover()
    context.initialize()
    path = context.root / "example"
    atomic_write(path, b"old")
    def reject(src, dest):
        raise PermissionError("simulated")
    monkeypatch.setattr(os, "replace", reject)
    with pytest.raises(PermissionError):
        atomic_write(path, b"new")
    assert path.read_bytes() == b"old"
    assert list(path.parent.glob(".example.*")) == []


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and permissions")
def test_init_and_atomic_write_are_private(isolated_runtime):
    context = RuntimeContext.discover()
    context.initialize()
    path = context.root / "key"
    atomic_write(path, b"key")
    assert path.stat().st_mode & 0o777 == 0o600
    assert all(p.stat().st_mode & 0o077 == 0 for p in [context.root, *context.directories()])
    path.chmod(0o644)
    with pytest.raises(PocketError, match="private"):
        atomic_write(path, b"new")
@pytest.mark.skipif(os.name != "nt", reason="Windows replacement sharing semantics")
def test_atomic_replacement_retries_transient_windows_sharing_error(isolated_runtime, monkeypatch):
    from core import runtime
    context = runtime.RuntimeContext(isolated_runtime, "mock")
    context.initialize()
    target = context.root / "private-value"
    runtime.atomic_write(target, b"old")
    original = runtime.os.replace
    attempts = []
    def busy_once(source, destination):
        attempts.append(1)
        if len(attempts) == 1:
            assert target.read_bytes() == b"old"
            failure = PermissionError("Transient sharing violation")
            failure.winerror = 32
            raise failure
        return original(source, destination)
    monkeypatch.setattr(runtime.os, "replace", busy_once)
    runtime.atomic_write(target, b"new")
    assert target.read_bytes() == b"new" and len(attempts) == 2
