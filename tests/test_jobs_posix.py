"""Explicit opt-in harness retains handles only to its own temporary children."""
import os
import subprocess
import threading
import time

import pytest

from core.config import ConfigManager
from core.jobs import JobManager
from core.runtime import RuntimeContext, atomic_write

REAL_POPEN = subprocess.Popen
pytestmark = pytest.mark.skipif(os.name != "posix" or os.environ.get("POCKETSERVER_REAL_PROCESS_TESTS") != "1", reason="opt-in owned POSIX process harness")

@pytest.fixture
def manager(isolated_runtime, monkeypatch):
    monkeypatch.setattr("core.config.PBKDF2_ITERATIONS", 1000)
    context = RuntimeContext(isolated_runtime, "mock")
    ConfigManager(context).initialize("a long test password")
    result = JobManager(context, popen=REAL_POPEN)
    monkeypatch.setattr(result, "_execution_supported", lambda: hasattr(os, "waitid") and hasattr(os, "WNOWAIT"))
    script = isolated_runtime / "trusted.py"
    atomic_write(script, b"import time,sys,subprocess,signal\nchild=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)'])\nprint(child.pid,flush=True)\ndef finish(*args):\n child.wait(timeout=2)\n raise SystemExit(0)\nsignal.signal(signal.SIGTERM,finish)\ntime.sleep(60)\n")
    result.register("owned", str(script), timeout=1)
    return result

def assert_no_live_descendant(result):
    pid = int(result["output"].strip().splitlines()[0])
    path = __import__("pathlib").Path(f"/proc/{pid}/stat")
    if path.exists():
        # An init-owned zombie is exited; a live sleeping child is a leak.
        assert path.read_text().split(") ", 1)[1].split()[0] == "Z"

def test_real_timeout_terminates_owned_group_before_reaping(manager):
    result = manager.run("owned", run_id="real-timeout")
    assert result["state"] == "timed_out"
    assert_no_live_descendant(result)
    assert manager.shutdown_owned() == 0

def test_real_cross_thread_cancel_is_bounded(manager):
    result = {}
    worker = threading.Thread(target=lambda: result.update(manager.run("owned", run_id="real-cancel")))
    worker.start()
    deadline = time.monotonic() + 3
    while time.monotonic() < deadline:
        try:
            if manager.get_run("real-cancel")["state"] == "running":
                break
        except ValueError:
            pass
        time.sleep(0.01)
    # Give the owned test program time to emit its descendant identity.
    time.sleep(0.2)
    manager.cancel("real-cancel")
    worker.join(5)
    assert not worker.is_alive()
    assert result["state"] == "cancelled"
    assert_no_live_descendant(result)
