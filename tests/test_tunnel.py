from types import SimpleNamespace

import pytest

from core.config import ConfigManager
from core.errors import PocketError
from core.runtime import RuntimeContext, atomic_write, private_dir
from core.tunnel import TunnelManager, _write, _read, _directory, note_output, tunnel_observation, foreground_environment


@pytest.fixture
def manager(isolated_runtime, monkeypatch):
    monkeypatch.setattr("core.config.PBKDF2_ITERATIONS", 1000)
    ctx = RuntimeContext(isolated_runtime, "mock")
    ConfigManager(ctx).initialize("a-long-safe-test-password")
    states = {"tunnel": {"running": False, "owned": False, "run_id": None}}
    stops = []
    def stop(service):
        stops.append(service)
        states[service] = {"running": False, "owned": False, "run_id": None}
        return states[service]
    supervisor = SimpleNamespace(status=lambda service: states.get(service, {}), stop=stop, stops=stops, states=states)
    return TunnelManager(ctx, supervisor)


@pytest.mark.parametrize("target", ["dashboard", "files", "ssh", "http://127.0.0.1:8888", 8080])
def test_arbitrary_origins_rejected(manager, target):
    with pytest.raises(PocketError) as exc:
        manager.start(target, acknowledge_public=True)
    assert exc.value.code == "invalid_target"


def test_acknowledgement_and_mock_refusal(manager):
    with pytest.raises(PocketError) as exc:
        manager.start("web")
    assert exc.value.code == "acknowledgement_required"
    with pytest.raises(PocketError) as exc:
        manager.start("web", acknowledge_public=True)
    assert exc.value.code == "unsupported"


def publication(manager):
    state = {"publication_id": "a" * 32, "connector_run_id": "fresh", "target_service": "web", "target_run_id": "origin",
             "config_revision": 1, "url": None, "connected": False}
    _write(manager.context, state)
    private_dir(_directory(manager.context, state))
    return state


def test_only_current_run_output_can_publish_url(manager):
    publication(manager)
    text = "https://test-name.trycloudflare.com\nRegistered tunnel connection\n"
    note_output(manager.context, "stale", text)
    assert tunnel_observation(manager.context, "fresh")["ready"] is False
    note_output(manager.context, "fresh", text)
    assert tunnel_observation(manager.context, "fresh")["url"] == "https://test-name.trycloudflare.com"
    assert tunnel_observation(manager.context, "stale")["url"] is None
    note_output(manager.context, "fresh", "retrying connection")
    assert tunnel_observation(manager.context, "fresh")["url"] is None
    note_output(manager.context, "fresh", "ordinary later output")
    assert tunnel_observation(manager.context, "fresh")["url"] is None


def test_logs_are_bounded_and_credentials_environment_excluded(manager, monkeypatch):
    state = publication(manager)
    note_output(manager.context, "fresh", b"x" * 100000)
    assert (_directory(manager.context, state) / "current.log").stat().st_size == 65536
    monkeypatch.setenv("TUNNEL_TOKEN", "secret")
    monkeypatch.setenv("CLOUDFLARED_CONFIG", "untrusted")
    env = foreground_environment(manager.context)
    assert "TUNNEL_TOKEN" not in env and "CLOUDFLARED_CONFIG" not in env
    assert env["HOME"] == env["XDG_CONFIG_HOME"]


def test_stop_clears_url_even_if_backend_shutdown_fails(manager):
    state = publication(manager)
    state.update(url="https://old.trycloudflare.com", connected=True)
    _write(manager.context, state)
    def fail(service):
        raise PocketError("stop_failed", "uncertain", 503)
    manager.supervisor.stop = fail
    with pytest.raises(PocketError):
        manager.stop()
    assert _read(manager.context)["url"] is None
    assert _read(manager.context)["connector_run_id"] is None


def test_target_run_change_revokes_and_never_republishes(manager):
    publication(manager)
    manager.supervisor.states["tunnel"] = {"running": True, "owned": True, "run_id": "fresh"}
    manager.supervisor.states["web"] = {"ready": True, "run_id": "replacement"}
    manager.reconcile()
    assert manager.supervisor.stops == ["tunnel"]
    assert manager.status()["url"] is None
