"""Installation safety is checked with inert runners, never package operations."""
import hashlib
import base64
import json
from pathlib import Path
from types import SimpleNamespace
import pytest
from core import boot, config
from core.errors import PocketError
from core.runtime import RuntimeContext, atomic_write

@pytest.fixture
def setup(isolated_runtime, tmp_path, monkeypatch):
    monkeypatch.setattr(config, "_hash", lambda password: "pbkdf2:sha256:1000000$salt$" + "c" * 64)
    context = RuntimeContext.discover(root=isolated_runtime, mode="mock")
    config.ConfigManager(context).initialize("Correct horse battery staple!")
    monkeypatch.setattr(boot, "_production", lambda context: context.ensure_mutable())
    monkeypatch.setattr(boot.shutil, "which", lambda name: "/trusted/" + name)
    monkeypatch.setenv("PREFIX", "/data/data/com.termux/files/usr")
    source = tmp_path / "source"
    source.mkdir()
    (source / "pocketctl.py").write_text("# inert source fixture")
    wheels = source / "wheelhouse"
    wheels.mkdir()
    wheel = wheels / "example-1.0-py3-none-any.whl"
    wheel.write_bytes(b"inert test data; not an installable package")
    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (source / "requirements.lock").write_text("example==1.0 --hash=sha256:" + digest + "\n")
    manifest = {"format_version": 1, "qualified_on_termux": False,
                "wheels": [{"name": "example", "version":"1.0", "filename":wheel.name, "sha256":digest}]}
    (wheels / "manifest.json").write_text(json.dumps(manifest))
    destination = tmp_path / "installed"
    return context, source, destination

def test_unqualified_wheelhouse_blocks_before_any_runner(setup):
    context, source, destination = setup
    def forbidden(*args, **kwargs):
        raise AssertionError("Package operations must not run")
    with pytest.raises(PocketError) as error:
        boot.install_application(context, source, install_root=destination, runner=forbidden)
    assert error.value.code == "unsupported"
    assert not destination.exists()

def test_offline_generation_install_records_exact_commands(setup):
    context, source, destination = setup
    commands = []
    def runner(argv, **kwargs):
        commands.append(argv)
        return SimpleNamespace(returncode=0)
    result = boot.install_application(context, source, install_root=destination, runner=runner, allow_unqualified=True)
    assert result["device_qualified"] is False
    assert len(commands) == 3
    pip = commands[1]
    for flag in ("--no-index", "--require-hashes", "--only-binary=:all:", "--find-links"):
        assert flag in pip
    assert not any("pkg" in command for command in commands)
    assert (destination / "pocketserver").exists()
    assert json.loads((context.root / "state" / "installation.json").read_text())["runtime_root"] == str(context.root)

def test_failed_upgrade_preserves_old_launcher_and_registration(setup):
    context, source, destination = setup
    success = lambda *args, **kwargs: SimpleNamespace(returncode=0)
    first = boot.install_application(context, source, install_root=destination, runner=success, allow_unqualified=True)
    launcher = (destination / "pocketserver").read_bytes()
    original = (context.root / "state" / "installation.json").read_bytes()
    def failure(argv, **kwargs):
        return SimpleNamespace(returncode=1 if "pip" in argv else 0)
    with pytest.raises(PocketError) as error:
        boot.install_application(context, source, install_root=destination, runner=failure, allow_unqualified=True)
    assert error.value.code == "install_failed"
    assert (destination / "pocketserver").read_bytes() == launcher
    assert (context.root / "state" / "installation.json").read_bytes() == original

def test_manifest_hash_mismatch_blocks_package_operation(setup):
    context, source, destination = setup
    next((source / "wheelhouse").glob("*.whl")).write_bytes(b"changed")
    with pytest.raises(PocketError) as error:
        boot.install_application(context, source, install_root=destination, allow_unqualified=True,
                                 runner=lambda *args, **kwargs: pytest.fail("runner invoked"))
    assert error.value.code == "invalid_archive"

def test_purge_requires_exact_runtime_confirmation_before_shutdown(setup):
    context, source, destination = setup
    boot.install_application(context, source, install_root=destination, allow_unqualified=True,
                             runner=lambda *args, **kwargs: SimpleNamespace(returncode=0))
    with pytest.raises(PocketError) as error:
        boot.uninstall_application(context, purge_data=True, confirm="yes")
    assert error.value.code == "confirmation_required"
    assert context.root.exists()

def test_boot_uses_quoted_registered_paths_and_never_claims_reboot(setup, tmp_path, monkeypatch):
    context, source, destination = setup
    boot.install_application(context, source, install_root=destination, allow_unqualified=True,
                             runner=lambda *args, **kwargs: SimpleNamespace(returncode=0))
    script = tmp_path / "boot directory" / "pocketserver"
    monkeypatch.setattr(boot, "_boot_script", lambda context: script)
    result = boot.install_boot(context)
    assert result["reboot_verified"] is False
    text = script.read_text()
    assert str(context.root) in text and "boot reconcile" in text
    assert "service-daemon stop" not in text
    boot.remove_boot(context)
    assert not script.exists()

def test_boot_refuses_unowned_script(setup, tmp_path, monkeypatch):
    context, source, destination = setup
    boot.install_application(context, source, install_root=destination, allow_unqualified=True,
                             runner=lambda *args, **kwargs: SimpleNamespace(returncode=0))
    script = tmp_path / "boot" / "pocketserver"
    script.parent.mkdir()
    script.write_text("# another application")
    monkeypatch.setattr(boot, "_boot_script", lambda context: script)
    with pytest.raises(PocketError) as error:
        boot.install_boot(context)
    assert error.value.code == "unsafe_path"
    assert script.read_text() == "# another application"

def test_interrupted_installation_requires_and_supports_local_rollback(setup):
    context, source, destination = setup
    boot.install_application(context, source, install_root=destination, allow_unqualified=True,
                             runner=lambda *args, **kwargs: SimpleNamespace(returncode=0))
    registration_path = context.root / "state" / "installation.json"
    previous = json.loads(registration_path.read_text())
    launcher = destination / "pocketserver"
    old_content = launcher.read_bytes()
    launcher.write_text("#!/inert\n# pocketserver-owned\n# interrupted new generation\n")
    journal = context.root / "recovery" / "install-test.json"
    atomic_write(journal, json.dumps({"kind":"installation", "phase":"PREPARED", "runtime_root":str(context.root),
        "install_root":str(destination), "launcher":str(launcher), "previous_registration":previous,
        "previous_launcher":base64.b64encode(old_content).decode()}).encode())
    with pytest.raises(PocketError) as error:
        context.ensure_mutable()
    assert error.value.code == "recovery_required"
    assert boot.recover_installation(context)["services_started"] is False
    assert launcher.read_bytes() == old_content
    context.ensure_mutable()

def test_registration_write_failure_rolls_back_launcher_and_snapshot(setup, monkeypatch):
    context, source, destination = setup
    success = lambda *args, **kwargs: SimpleNamespace(returncode=0)
    boot.install_application(context, source, install_root=destination, allow_unqualified=True, runner=success)
    registration = context.root / "state" / "installation.json"
    before = registration.read_bytes()
    launcher_before = (destination / "pocketserver").read_bytes()
    original_write = boot.atomic_write
    failed = False
    def fail_once(path, value, *args, **kwargs):
        nonlocal failed
        if path == registration and not failed:
            failed = True
            raise OSError("synthetic commit failure")
        return original_write(path, value, *args, **kwargs)
    monkeypatch.setattr(boot, "atomic_write", fail_once)
    with pytest.raises(OSError):
        boot.install_application(context, source, install_root=destination, allow_unqualified=True, runner=success)
    assert registration.read_bytes() == before
    assert (destination / "pocketserver").read_bytes() == launcher_before
    context.ensure_mutable()

