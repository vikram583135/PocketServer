"""P0 harness: every test gets a fresh mock root and no process authority."""

import os
import subprocess

import pytest


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    root = tmp_path / "runtime"
    monkeypatch.setenv("POCKETSERVER_ENV", "mock")
    monkeypatch.setenv("POCKETSERVER_HOME", str(root))

    from core import env

    # The baseline ignores POCKETSERVER_HOME. Patch its path adapter before any
    # manager construction; imported get_runtime_paths aliases use this adapter.
    monkeypatch.setattr(env, "get_base_dir", lambda: root)
    monkeypatch.setattr(env, "_MOCK_WAKE_LOCK_STATE", False, raising=False)

    def forbidden_process_action(*args, **kwargs):
        raise AssertionError("P0 tests must not launch or signal real processes")

    monkeypatch.setattr(os, "kill", forbidden_process_action)
    monkeypatch.setattr(subprocess, "Popen", forbidden_process_action)
    return root
