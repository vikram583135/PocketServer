"""Run an offline, isolated Linux snapshot qualification; retains its temp root.

Run with Ubuntu Python, not Windows Python. This does not qualify Android.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import venv


def main():
    if os.name != "posix":
        raise SystemExit("Use an existing POSIX Python environment.")
    source = Path(__file__).resolve().parent.parent
    temporary = Path(tempfile.mkdtemp(prefix="pocketserver-posix-"))
    snapshot = temporary / "source"
    snapshot.mkdir(mode=0o700)
    for name in ("core", "dashboard", "tests", "scripts", "wheelhouse"):
        shutil.copytree(source / name, snapshot / name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    for name in ("pocketctl.py", "requirements.txt", "requirements.lock", "bootstrap.sh", "uninstall.sh"):
        shutil.copy2(source / name, snapshot / name)
    # Source files came from a Windows drive; set private test-owned modes.
    for item in snapshot.rglob("*"):
        item.chmod(0o700 if item.is_dir() else 0o600)
    test_wheels = source / ".build" / "test-wheels"
    pip_wheel = next(test_wheels.glob("pip-*.whl"))
    environment = temporary / "venv"
    venv.EnvBuilder(with_pip=False).create(environment)
    python = str(environment / "bin" / "python")
    env = {**os.environ, "PYTHONPATH": str(pip_wheel), "PYTHONNOUSERSITE": "1", "PIP_NO_INDEX": "1", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1", "POCKETSERVER_REAL_PROCESS_TESTS": "1"}
    commands = [[python, "-m", "pip", "install", "--no-index", "--find-links", str(snapshot / "wheelhouse"), "--require-hashes", "--only-binary=:all:", "-r", str(snapshot / "requirements.lock")],
                [python, "-m", "pip", "install", "--no-index", "--no-deps", *[str(p) for p in sorted(test_wheels.glob("*.whl")) if not p.name.startswith("pip-")]]]
    for command in commands:
        result = subprocess.run(command, cwd=snapshot, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        print(result.stdout, flush=True)
        if result.returncode:
            return result.returncode
    env.pop("PYTHONPATH", None)
    evidence_dir = source / ".build"
    evidence_dir.mkdir(exist_ok=True)
    started = time.time()
    result = subprocess.run([python, "-m", "pytest", "tests", "-q", "-ra", "--tb=short", f"--junitxml={evidence_dir / 'posix-junit.xml'}"],
                            cwd=snapshot, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
    print(result.stdout, flush=True)
    evidence = {"platform": platform.platform(), "python": sys.version, "android_qualified": False,
                "temporary_root": str(temporary), "snapshot": str(snapshot), "exit_code": result.returncode,
                "elapsed_seconds": round(time.time() - started, 2), "output": result.stdout,
                "source_sha256": {str(p.relative_to(snapshot)): hashlib.sha256(p.read_bytes()).hexdigest()
                                  for p in snapshot.rglob("*.py")}}
    (evidence_dir / "posix-evidence.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(f"Retained isolated Linux snapshot: {snapshot}", flush=True)
    return result.returncode

if __name__ == "__main__":
    raise SystemExit(main())
