"""CLI checks execute in-process with fake lifecycle state only."""
import io
import json
import pytest
import pocketctl
from core import config
from core.application import Application
from core.errors import PocketError
from core.runtime import RuntimeContext

@pytest.fixture
def app(isolated_runtime, monkeypatch):
    monkeypatch.setattr(config, "_hash", lambda password: "pbkdf2:sha256:1000000$salt$" + "b" * 64)
    value = Application(RuntimeContext.discover(root=isolated_runtime, mode="mock"))
    value.initialize("Correct horse battery staple!")
    monkeypatch.setattr(pocketctl, "Application", lambda context: value)
    return value

def result(capsys):
    return json.loads(capsys.readouterr().out)

def test_read_status_uninitialized_does_not_create(isolated_runtime, capsys):
    assert pocketctl.main(["--json", "status"]) == 2
    assert result(capsys)["error"]["code"] == "not_initialized"
    assert not isolated_runtime.exists()

def test_uninitialized_start_fails_without_creating_locks(isolated_runtime, capsys):
    assert pocketctl.main(["start", "web", "--json"]) == 2
    assert result(capsys)["error"]["code"] == "not_initialized"
    assert not isolated_runtime.exists()

def test_password_argv_is_not_supported():
    with pytest.raises(SystemExit) as error:
        pocketctl.parser().parse_args(["init", "--password", "secret"])
    assert error.value.code == 2

def test_json_flags_work_after_nested_read(app, capsys):
    assert pocketctl.main(["config", "validate", "--json"]) == 0
    assert result(capsys)["data"]["valid"]

def test_empty_start_all_fails(app, capsys):
    assert pocketctl.main(["start", "all", "--json"]) == 2
    assert result(capsys)["error"]["code"] == "invalid_input"
    assert not app.supervisor.backend.starts


def test_failed_job_returns_nonzero_with_its_result(app, capsys, monkeypatch):
    from core.jobs import JobManager
    monkeypatch.setattr(JobManager, "run", lambda *args, **kwargs: {"state": "failed", "exit_code": 7})
    assert pocketctl.main(["job", "run", "local-job", "--json"]) == 1
    assert result(capsys)["data"]["exit_code"] == 7

def test_start_all_bootstraps_and_excludes_tunnel(app, capsys):
    app.config.update_service("web", {"autostart": True})
    assert pocketctl.main(["start", "all", "--json"]) == 0
    data = result(capsys)
    assert data["ok"]
    assert app.supervisor.backend.starts == ["controller", "web"]

def test_bulk_partial_failure_returns_nonzero(app, capsys):
    app.config.update_service("web", {"autostart": True})
    app.config.update_service("api", {"autostart": True})
    app.supervisor.backend.fail_start.add("api")
    assert pocketctl.main(["start", "all", "--json"]) == 1
    data = result(capsys)["data"]
    assert "api" in data["errors"] and data["results"]["web"]["ready"]

def test_restart_all_snapshots_running_set_and_requires_republication(app, capsys):
    app.supervisor.start("web")
    app.supervisor.backend.start("tunnel", app.config.get_config())
    assert pocketctl.main(["restart", "all", "--json"]) == 0
    data = result(capsys)["data"]
    assert data["results"]["tunnel"]["reason"] == "publication_reapproval_required"
    assert app.supervisor.backend.starts == ["web", "tunnel", "controller", "web"]

def test_enable_changes_preference_only(app, capsys):
    assert pocketctl.main(["enable", "api", "--json"]) == 0
    assert result(capsys)["data"]["autostart"]
    assert not app.supervisor.status("api")["running"]

def test_status_readiness_gate_and_valid_stopped_status(app, capsys):
    assert pocketctl.main(["status", "web", "--json"]) == 0
    assert result(capsys)["data"]["state"] == "stopped"
    assert pocketctl.main(["status", "web", "--require-ready", "--json"]) == 1
    assert not result(capsys)["ok"]

@pytest.mark.parametrize("code,exit_code", [("unsupported",3),("busy",4),("recovery_required",5),("stop_failed",1)])
def test_structured_exit_codes(app, capsys, monkeypatch, code, exit_code):
    def fail(*args):
        raise PocketError(code, "Actionable error")
    monkeypatch.setattr(app.supervisor, "start", fail)
    assert pocketctl.main(["start", "web", "--json"]) == exit_code
    assert result(capsys)["error"]["code"] == code

def test_config_cannot_set_credentials(app, capsys):
    assert pocketctl.main(["config","set","auth.password_hash","bad","--revision","1","--json"]) == 2
    assert result(capsys)["error"]["code"] == "invalid_input"

def test_local_serve_requires_explicit_foreground_flag():
    with pytest.raises(SystemExit):
        pocketctl.parser().parse_args(["serve"])

def test_global_runtime_options_after_leaf():
    args = pocketctl.parser().parse_args(["status","--home","C:/runtime","--env","mock"])
    assert args.home == "C:/runtime" and args.env == "mock"

