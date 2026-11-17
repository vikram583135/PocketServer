"""Manifest parsing is cross-platform. POSIX-only cases use private temporary roots."""
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import tarfile

import pytest

from core import backups
from core.backups import BackupManager, ROOTS
from core.config import ConfigManager, get_default_config
from core.errors import PocketError
from core.runtime import RuntimeContext, atomic_write
from core.state import ReservationStore, StateStore
from core.storage import secure_filesystem_available


def archive_parts():
    cfg = json.dumps(get_default_config()).encode()
    files = [(root, None) for root in ROOTS[:-1]] + [("config.json", cfg), ("data/www/index.html", b"hello")]
    entries = [{"path": path, "type": "directory" if data is None else "file", "size": len(data or b""),
                "sha256": None if data is None else hashlib.sha256(data).hexdigest()} for path, data in files]
    return backups._new_manifest(entries, "quiesced"), files


def archive_bytes(manifest, files):
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w", format=tarfile.USTAR_FORMAT) as tar:
        for path, data in [("manifest.json", json.dumps(manifest).encode()), *files]:
            info = tarfile.TarInfo(path)
            if data is None:
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            else:
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))
    return out.getvalue()


def test_standalone_validation_is_read_only(tmp_path, isolated_runtime):
    archive = tmp_path / "sample.tar"
    archive.write_bytes(archive_bytes(*archive_parts()))
    report = BackupManager(RuntimeContext.discover()).restore(archive)
    assert report["entries"] == 7
    assert report["valid"] and not report["applied"]
    assert not isolated_runtime.exists()


@pytest.mark.parametrize("defect", ["digest", "missing", "unlisted", "duplicate-payload", "duplicate-manifest",
                                    "case-collision", "traversal", "type", "unknown-root", "unexpected-git",
                                    "huge-size", "absent-parent", "bad-config", "bad-trailer", "extension", "symlink"])
def test_archive_variations_fail_closed(tmp_path, defect):
    manifest, files = archive_parts()
    entries = manifest["entries"]
    if defect == "digest":
        entries[-1]["sha256"] = "0" * 64
    elif defect == "missing":
        files.pop()
    elif defect == "unlisted":
        files.append(("data/files/extra", b"x"))
    elif defect == "duplicate-payload":
        files.append(files[-1])
    elif defect == "duplicate-manifest":
        files.append(("manifest.json", b"{}"))
    elif defect == "case-collision":
        entries.append(dict(entries[-1], path="data/www/INDEX.html"))
    elif defect == "traversal":
        entries[-1]["path"] = "data/www/../../secret.key"
    elif defect == "type":
        entries[-1].update(type="directory", size=0, sha256=None)
    elif defect == "unknown-root":
        entries[-1]["path"] = "private/config"
    elif defect == "unexpected-git":
        entries[-1]["path"] = "data/git/config"
    elif defect == "huge-size":
        entries[-1]["size"] = 2**62
    elif defect == "absent-parent":
        entries[-1]["path"] = "data/www/missing/child"
    elif defect == "bad-config":
        raw = b'{"revision":1,"revision":2}'
        files[-2] = ("config.json", raw)
        entries[-2].update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
    data = archive_bytes(manifest, files)
    if defect == "bad-trailer":
        data += b"garbage"
    if defect in ("extension", "symlink"):
        info = tarfile.TarInfo("manifest.json")
        info.type = tarfile.XHDTYPE if defect == "extension" else tarfile.SYMTYPE
        info.size = 2**32
        data = info.tobuf(tarfile.USTAR_FORMAT) + data[512:]
    path = tmp_path / "archive.tar"
    path.write_bytes(data)
    with pytest.raises(PocketError):
        BackupManager(RuntimeContext.discover()).validate(path)


@pytest.mark.parametrize("setting", [b'[include]\npath = elsewhere', b'[core]\nbare = true\nhooksPath = bad',
                                    b'[uploadpack]\npackObjectsHook = bad', b'[core]\nbare = false'])
def test_git_config_is_allowlisted(setting):
    with pytest.raises(PocketError):
        backups._git_policy("data/git/owned.git/config", setting)


def test_create_requires_explicit_owner_ack_and_secure_filesystem(monkeypatch):
    manager = BackupManager(RuntimeContext.discover())
    with pytest.raises(PocketError, match="external writers"):
        manager.create()
    monkeypatch.setattr(backups, "secure_filesystem_available", lambda: False)
    with pytest.raises(PocketError) as error:
        manager.create(external_writers_stopped=True)
    assert error.value.code == "unsupported"


@pytest.fixture
def installation():
    if not secure_filesystem_available():
        pytest.skip("requires descriptor-relative POSIX filesystem operations")
    manager = ConfigManager()
    manager.initialize("a strong local password")
    StateStore(manager.context).initialize()
    return BackupManager(manager.context, config=manager)


def test_create_restore_quarantine_and_security_finalization(installation):
    manager = installation
    paths = manager.context.paths
    for key in ("api", "jobs", "files"):
        atomic_write(paths[key] / "original", b"payload")
    repo = paths["git"] / "sample.git"
    for root in (repo, repo / "refs", repo / "objects", repo / "hooks"):
        root.mkdir(mode=0o700)
    atomic_write(repo / "HEAD", b"ref: refs/heads/main\n")
    atomic_write(repo / "config", backups.SAFE_GIT_CONFIG)
    atomic_write(repo / "hooks" / "post-receive", b"imported hook")
    before_key = manager.config.get_or_create_secret_key()
    manager.config.update_service("web", {"autostart": True})
    archive = manager.create(external_writers_stopped=True)
    assert manager.validate(archive["id"])["valid"]
    atomic_write(paths["files"] / "original", b"live")
    live = manager.config.get_config()
    result = manager.restore(archive["id"], apply=True, external_writers_stopped=True)
    assert result["applied"] and not manager.context.pending_recovery()
    assert (paths["files"] / "original").read_bytes() == b"payload"
    assert list(paths["api"].iterdir()) == list(paths["jobs"].iterdir()) == []
    saved = Path(result["rollback_location"])
    assert (saved / "data/files/original").read_bytes() == b"live"
    assert (saved.parent / "quarantine/api/original").read_bytes() == b"payload"
    assert (saved.parent / "quarantine/git/sample.git-hooks/post-receive").exists()
    assert not (repo / "hooks").exists()
    cfg = manager.config.get_config()
    assert cfg["revision"] == live["revision"] + 1
    assert cfg["auth"]["auth_generation"] == live["auth"]["auth_generation"] + 1
    assert manager.config.get_or_create_secret_key() != before_key
    assert not cfg["services"]["web"]["autostart"]
    assert manager.list()[0]["id"] == archive["id"]


def test_resume_failure_attempts_remaining_private_services_and_reports_partial_result(installation, monkeypatch):
    manager = installation
    supervisor = manager.supervisor
    supervisor.start("web")
    supervisor.start("api")
    start = supervisor.start
    def resume(identifier, **kwargs):
        if identifier == "web":
            raise PocketError("start_failed", "Injected readiness failure")
        return start(identifier, **kwargs)
    monkeypatch.setattr(supervisor, "start", resume)
    result = manager.create(external_writers_stopped=True)
    assert not result["ok"]
    assert result["resume_errors"]["web"]["code"] == "start_failed"
    assert "api" in result["resumed"] and supervisor.status("api")["running"]
    assert manager.validate(result["id"])["valid"]


@pytest.mark.parametrize("boundary", range(1, 13))
def test_restore_interruption_after_each_root_rename_rolls_back(installation, monkeypatch, boundary):
    manager = installation
    path = manager.context.paths["files"] / "owner"
    atomic_write(path, b"archived")
    archive = manager.create(external_writers_stopped=True)
    atomic_write(path, b"new live data")
    before = manager.config.get_config()
    key = manager.config.get_or_create_secret_key()
    move = backups._move
    counter = 0
    def interrupted(source, destination):
        nonlocal counter
        move(source, destination)
        if source in [manager.context.root / r for r in ROOTS] or destination in [manager.context.root / r for r in ROOTS]:
            counter += 1
            if counter == boundary:
                raise KeyboardInterrupt("simulated stop after durable rename")
    with monkeypatch.context() as patch:
        patch.setattr(backups, "_move", interrupted)
        with pytest.raises(KeyboardInterrupt):
            manager.restore(archive["id"], apply=True, external_writers_stopped=True)
    assert manager.context.pending_recovery()
    assert manager.recover()["recovered"] == 1
    assert manager.config.get_config() == before and manager.config.get_or_create_secret_key() == key
    assert path.read_bytes() == b"new live data"


def test_finalize_interruption_resumes_without_second_rotation(installation, monkeypatch):
    manager = installation
    archive = manager.create(external_writers_stopped=True)
    def interrupt(self, journal):
        raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(StateStore, "clear_for_restore", interrupt)
        with pytest.raises(KeyboardInterrupt):
            manager.restore(archive["id"], apply=True, external_writers_stopped=True)
    key = manager.config.get_or_create_secret_key()
    with pytest.raises(PocketError, match="pending journal"):
        manager.context.ensure_mutable()
    assert manager.recover()["recovered"] == 1
    assert manager.config.get_or_create_secret_key() == key
    assert manager.recover()["recovered"] == 0


def test_actual_legacy_gzip_pax_import_strips_session_key(installation, tmp_path):
    manager = installation
    path = tmp_path / "legacy.tar.gz"
    actual = manager.config.get_config()
    legacy = {"metadata": {"version": "2.0.0"}, "auth": {"password_hash": actual["auth"]["password_hash"]},
              "dashboard": {"enabled": True}, "services": {"web": {"enabled": True}}}
    with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as tar:
        for name, data in (("config.json", json.dumps(legacy).encode()), ("secret.key", b"x" * 64), ("data/www/index", b"page")):
            info = tarfile.TarInfo(name)
            info.mtime = 12345.125
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    result = manager.import_legacy(path)
    assert result["consistency"] == "legacy-import" and "data/files" in result["omitted_roots"]
    assert manager.validate(result["id"])["valid"]
    with tarfile.open(manager.download(result["id"]), "r:") as imported:
        assert "secret.key" not in imported.getnames()
        cfg = json.loads(imported.extractfile("config.json").read())
        assert not cfg["auth"]["password_policy_verified"]


def test_inconsistent_rollback_evidence_is_preserved(installation, monkeypatch):
    manager = installation
    archive = manager.create(external_writers_stopped=True)
    original = backups._move
    def stop(source, dest):
        original(source, dest)
        if source == manager.context.paths["www"]:
            raise KeyboardInterrupt()
    with monkeypatch.context() as patch:
        patch.setattr(backups, "_move", stop)
        with pytest.raises(KeyboardInterrupt):
            manager.restore(archive["id"], apply=True, external_writers_stopped=True)
    manager.context.paths["www"].mkdir(mode=0o700)
    with pytest.raises(PocketError, match="evidence is inconsistent"):
        manager.recover()
    assert manager.context.pending_recovery()


def test_abandoned_writer_cleanup_requires_registered_ownership(installation):
    manager = installation
    reservations = ReservationStore(manager.context)
    upload = "upload-" + "a" * 32
    backup = "backup-" + "b" * 32
    for owner in (upload, backup, "listener:dashboard"):
        reservations.reserve(owner, 1024)
    stage = manager.context.paths["staging"] / upload
    atomic_write(stage, b"published")
    target = manager.context.paths["files"] / "complete"
    os.link(stage, target)
    abandoned = manager.base / ("20200101T010101Z-" + "b" * 32 + ".partial")
    unrelated = manager.base / ("20200101T010101Z-" + "f" * 32 + ".partial")
    for path in (abandoned, unrelated):
        atomic_write(path, b"unfinished")
    result = manager.recover()
    assert set(result["abandoned_writers"]) == {upload, backup}
    assert not stage.exists() and not abandoned.exists() and unrelated.exists()
    assert target.read_bytes() == b"published" and target.stat().st_nlink == 1
    assert reservations.total() == 1024
