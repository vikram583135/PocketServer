"""Bounded manifest-first USTAR archives, offline restore, and crash recovery."""
from __future__ import annotations

from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import tarfile
import time
import uuid
import zlib

from core import __version__
from core.config import CONFIG_LIMIT, ConfigManager, _decode, validate_config
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import atomic_write, check_path, check_private, private_dir, read_private, sync_directory
from core.state import ReservationStore, StateStore
from core.storage import maintenance_lease, open_directory, secure_filesystem_available, validate_relative

ROOTS = ("data/www", "data/api", "data/files", "data/git", "data/jobs", "config.json")
EXCLUDED = ["SSH keys and identity", "session signing key", "state database and sessions", "PID and wake state",
            "logs", "locks", "staging and recovery", "backups", "external Termux files"]
ARCHIVE_LIMIT = 1024 ** 3
FILE_LIMIT = 256 * 1024 ** 2
MANIFEST_LIMIT = 4 * 1024 ** 2
ENTRY_LIMIT = 10_000
DEADLINE_SECONDS = 600
CHUNK = 256 * 1024
ZERO = bytes(512)
ID_PATTERN = r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{32}"
SAFE_GIT_CONFIG = b"[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = true\n"


def _invalid(message):
    raise PocketError("invalid_archive", message, 400)


def _deadline(end):
    if time.monotonic() > end:
        raise PocketError("timeout", "Archive processing exceeded its deadline.", 409)


def _json(value):
    return (json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")) + "\n").encode()


def _decode_archive(value):
    try:
        return _decode(value)
    except PocketError as exc:
        raise PocketError("invalid_archive", "Invalid or ambiguous JSON in the archive.") from exc


def _archive_path(name):
    try:
        validate_relative(name)
    except PocketError as exc:
        raise PocketError("invalid_archive", "Invalid archive member path.") from exc
    if name not in ROOTS and not any(name.startswith(root + "/") for root in ROOTS[:-1]):
        _invalid("Archive member is outside the selected roots.")
    return name


def _identity(info):
    return info.st_dev, info.st_ino, info.st_mode, info.st_size, info.st_mtime_ns, info.st_ctime_ns


@contextmanager
def _input(path):
    path = Path(path).absolute()
    check_path(path)
    entry = path.stat()
    if not stat.S_ISREG(entry.st_mode) or entry.st_nlink != 1 or not 0 < entry.st_size <= ARCHIVE_LIMIT:
        _invalid("Archive input must be a bounded regular file with one link.")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        opened = os.fstat(fd)
        if (not os.path.samestat(opened, entry) or not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1 or opened.st_size != entry.st_size):
            _invalid("Archive identity changed before opening.")
        yield stream
        check_path(path)
        final = os.fstat(fd)
        if _identity(final) != _identity(opened) or final.st_nlink != 1 or not os.path.samestat(path.stat(), opened):
            _invalid("Archive identity changed during processing.")


class _Reader:
    """No parsing library consumes unbounded extension records or compressed data."""
    def __init__(self, stream, end):
        self.stream = stream
        self.end = end
        self.count = 0

    def read(self, size):
        _deadline(self.end)
        if size < 0 or self.count + size > ARCHIVE_LIMIT:
            _invalid("Archive stream exceeds the input limit.")
        data = self.stream.read(size)
        self.count += len(data)
        if len(data) != size:
            _invalid("Truncated archive.")
        return data

    def header(self, *, legacy=False):
        block = self.read(512)
        if block == ZERO:
            if self.read(512) != ZERO:
                _invalid("Archive is missing its second end marker.")
            tail = self.stream.read(10241)
            if len(tail) > 10240 or self.count + len(tail) > ARCHIVE_LIMIT or any(tail):
                _invalid("Unrecognized data after archive end.")
            return None
        allowed = (b"0", b"\0", b"5", b"x") if legacy else (b"0", b"\0", b"5")
        if block[156:157] not in allowed or block[257:263] != b"ustar\0":
            _invalid("Only ordinary POSIX USTAR file and directory headers are supported.")
        try:
            info = tarfile.TarInfo.frombuf(block, "utf-8", "strict")
        except (ValueError, tarfile.HeaderError, UnicodeError) as exc:
            raise PocketError("invalid_archive", "Malformed USTAR header.") from exc
        if not 0 <= info.size <= FILE_LIMIT or info.linkname or info.isdir() and info.size:
            _invalid("Invalid USTAR member dimensions.")
        if info.type == b"x":
            if info.size > 16384:
                _invalid("Legacy extended metadata exceeds 16 KiB.")
            attributes = _pax_fields(self.read(info.size))
            self.padding(info.size)
            info = self.header()
            if info is None:
                _invalid("Missing member after extended metadata.")
            validate_relative(info.name)
            info.name = attributes.get("path", info.name)
        return info

    def padding(self, size):
        if any(self.read((-size) % 512)):
            _invalid("Nonzero data in member padding.")


def _parse_manifest(value):
    keys = {"format_version", "app_version", "schema_version", "created_at", "compression", "roots",
            "consistency", "entries"}
    if type(value) is not dict or set(value) != keys:
        _invalid("Manifest fields do not match format version 1.")
    if (type(value["format_version"]) is not int or value["format_version"] != 1
            or type(value["schema_version"]) is not int or value["schema_version"] != 3
            or value["compression"] != "none" or value["consistency"] not in ("quiesced", "legacy-import")
            or value["roots"] != list(ROOTS) or type(value["app_version"]) is not str
            or not 0 < len(value["app_version"]) <= 64):
        _invalid("Unsupported archive format, root selection, or schema.")
    try:
        stamp = datetime.fromisoformat(value["created_at"])
        if stamp.utcoffset() is None:
            _invalid("Manifest timestamp must include a time zone.")
    except (ValueError, TypeError) as exc:
        raise PocketError("invalid_archive", "Invalid creation timestamp.") from exc
    entries = value["entries"]
    if type(entries) is not list or not 1 <= len(entries) <= ENTRY_LIMIT:
        _invalid("Invalid archive entry count.")
    by_name, folded, total = {}, set(), 0
    for entry in entries:
        if type(entry) is not dict or set(entry) != {"path", "type", "size", "sha256"}:
            _invalid("Invalid manifest entry.")
        name = _archive_path(entry["path"])
        if name.casefold() in folded:
            _invalid("Duplicate or case-colliding archive path.")
        folded.add(name.casefold())
        kind, size, digest = entry["type"], entry["size"], entry["sha256"]
        if type(size) is not int or not 0 <= size <= FILE_LIMIT or kind not in ("file", "directory"):
            _invalid("Invalid member type or size.")
        if kind == "directory":
            if size or digest is not None:
                _invalid("Directories must declare size zero and no digest.")
        elif type(digest) is not str or not re.fullmatch(r"[a-f0-9]{64}", digest):
            _invalid("A file must declare a SHA-256 digest.")
        total += size
        if total > ARCHIVE_LIMIT:
            _invalid("Expanded data exceeds the archive budget.")
        by_name[name] = entry
    if any(root not in by_name or by_name[root]["type"] != ("file" if root == "config.json" else "directory") for root in ROOTS):
        _invalid("Archive is missing a required root.")
    for name in by_name:
        if name not in ROOTS and by_name.get(name.rpartition("/")[0], {}).get("type") != "directory":
            _invalid("A member's parent is missing or is not a directory.")
    if by_name["config.json"]["size"] > CONFIG_LIMIT:
        _invalid("Archived configuration exceeds its size limit.")
    return by_name, total


def _git_policy(name, data=None):
    """Never consult imported Git configuration or spawn Git during validation."""
    parts = name.split("/")
    if parts[:2] != ["data", "git"] or len(parts) < 3:
        return
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.git", parts[2]):
        _invalid("Unrecognized bare repository name.")
    if len(parts) < 4:
        return
    tail = "/".join(parts[3:]).casefold()
    if tail == "hooks" or tail.startswith("hooks/"):
        return
    if tail in ("objects/info/alternates", "objects/info/http-alternates", "info/grafts", "config.worktree",
                "commondir", "gitdir", "shallow") or parts[3].casefold() not in (
                "objects", "refs", "head", "config", "packed-refs", "info", "description", "branches", "logs"):
        _invalid("Unsupported executable or external-path Git metadata.")
    if tail == "config" and data is not None:
        try:
            text = data.decode("ascii")
        except UnicodeError as exc:
            raise PocketError("invalid_archive", "Unsupported Git configuration encoding.") from exc
        seen, core = set(), False
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.lower() == "[core]" and not core:
                core = True
                continue
            key, sep, value = line.partition("=")
            key, value = key.strip().lower(), value.strip().lower()
            allowed = {"repositoryformatversion": ("0",), "filemode": ("true", "false"),
                       "bare": ("true",), "logallrefupdates": ("true", "false")}
            if not core or not sep or key in seen or value not in allowed.get(key, ()):
                _invalid("Repository configuration contains a non-allowlisted setting.")
            seen.add(key)
        if "bare" not in seen:
            _invalid("Repository configuration must declare a bare repository.")
    if tail == "head" and data is not None:
        if not re.fullmatch(rb"(?:ref: refs/heads/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*|[a-f0-9]{40})\n?", data):
            _invalid("Invalid repository HEAD.")


def _manifest(reader):
    first = reader.header()
    if not first or first.name != "manifest.json" or not first.isreg() or first.size > MANIFEST_LIMIT:
        _invalid("The first member must be a bounded manifest.json.")
    value = _decode_archive(reader.read(first.size))
    reader.padding(first.size)
    by_name, total = _parse_manifest(value)
    return value, by_name, total


def _consume(reader, by_name, dest=None, reserve_remaining=None):
    seen = set()
    config = None
    for name in by_name:
        _git_policy(name)
        if name.startswith("data/git/") and len(name.split("/")) == 3:
            for child, kind in (("HEAD", "file"), ("config", "file"), ("refs", "directory"), ("objects", "directory")):
                if by_name.get(name + "/" + child, {}).get("type") != kind:
                    _invalid("Incomplete bare repository.")
    if dest:
        (dest / "data").mkdir(mode=0o700)
        for item in sorted(by_name.values(), key=lambda e: e["path"].count("/")):
            if item["type"] == "directory":
                (dest / item["path"]).mkdir(mode=0o700)
    while (info := reader.header()) is not None:
        name = _archive_path(info.name)
        item = by_name.get(name)
        if not item or name in seen or item["size"] != info.size or (item["type"] == "directory") != info.isdir():
            _invalid("Archive member differs from its manifest, or appeared twice.")
        seen.add(name)
        if info.isdir():
            continue
        metadata = name == "config.json" or (name.startswith("data/git/") and name.split("/")[3:] in (["config"], ["HEAD"]))
        if metadata and info.size > CONFIG_LIMIT:
            _invalid("Archived metadata exceeds its size limit.")
        captured = bytearray()
        digest = hashlib.sha256()
        left = info.size
        with ExitStack() as opened:
            out = None
            if dest:
                fd = os.open(dest / name, os.O_EXCL | os.O_CREAT | os.O_WRONLY, 0o600)
                out = opened.enter_context(os.fdopen(fd, "wb"))
            while left:
                size = min(left, CHUNK)
                chunk = reader.read(size)
                digest.update(chunk)
                if metadata:
                    captured.extend(chunk)
                if out:
                    if reserve_remaining:
                        reserve_remaining(size)
                    out.write(chunk)
                left -= size
            if out:
                out.flush()
                os.fsync(out.fileno())
        if digest.hexdigest() != item["sha256"]:
            _invalid("Archive payload digest mismatch.")
        reader.padding(info.size)
        if name == "config.json":
            config = _decode_archive(captured)
            validate_config(config)
        elif metadata:
            _git_policy(name, captured)
    if seen != by_name.keys():
        _invalid("An archive member listed in the manifest is missing.")
    return config

def _descriptor_support():
    if not secure_filesystem_available():
        raise PocketError("unsupported", "Secure archive filesystem operations require descriptor-relative POSIX support.", 501)


@contextmanager
def _source(path, expected):
    with open_directory(path.parent) as parent:
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or _identity(info) != expected:
                _invalid("Archive source changed or is not a single-link regular file.")
            yield stream
            if _identity(os.fstat(fd)) != expected:
                _invalid("Archive source changed while being read.")


def _inventory(root, end, hash_files=True):
    entries, identities = [], {}
    total = 0

    def visit(name):
        nonlocal total
        _deadline(end)
        _archive_path(name)
        if len(entries) >= ENTRY_LIMIT:
            _invalid("Archive exceeds its entry limit.")
        path = root / name
        with open_directory(path.parent) as parent:
            info = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        identities[name] = ident = _identity(info)
        if stat.S_ISDIR(info.st_mode):
            entries.append({"path": name, "type": "directory", "size": 0, "sha256": None})
            with open_directory(path) as fd, os.scandir(fd) as iterator:
                if _identity(os.fstat(fd)) != ident:
                    _invalid("Source directory changed.")
                for child in iterator:
                    visit(name + "/" + child.name)
                if _identity(os.fstat(fd)) != ident:
                    _invalid("Source directory changed during inventory.")
        else:
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or getattr(info, "st_blocks", None) is None:
                _invalid("Unsupported source entry: " + name)
            total += info.st_size
            if info.st_size > FILE_LIMIT or total > ARCHIVE_LIMIT or info.st_blocks * 512 < info.st_size:
                _invalid("Sparse or oversized archive entry: " + name)
            digest = hashlib.sha256()
            if hash_files:
                with _source(path, ident) as stream:
                    left = info.st_size
                    while left:
                        _deadline(end)
                        chunk = stream.read(min(CHUNK, left))
                        if not chunk:
                            _invalid("Truncated archive source.")
                        digest.update(chunk)
                        left -= len(chunk)
            entries.append({"path": name, "type": "file", "size": info.st_size, "sha256": digest.hexdigest()})

    for name in ROOTS:
        visit(name)
    return entries, identities


def _new_manifest(entries, consistency):
    value = {"format_version": 1, "compression": "none", "app_version": __version__, "schema_version": 3,
             "created_at": datetime.now(timezone.utc).isoformat(), "roots": list(ROOTS),
             "consistency": consistency, "entries": entries}
    _parse_manifest(value)
    return value


def _header(name, size, directory=False):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    info.mode = 0o700 if directory else 0o600
    info.size = size
    try:
        return info.tobuf(tarfile.USTAR_FORMAT, "utf-8", "strict")
    except (ValueError, UnicodeError) as exc:
        raise PocketError("invalid_archive", "Path cannot be represented by the supported USTAR format: " + name) from exc


def _write_archive(out, root, manifest, identities, end, limit, reserve):
    value = _json(manifest)
    if len(value) > MANIFEST_LIMIT:
        _invalid("Manifest exceeds 4 MiB.")
    archive_size = 512 + len(value) + (-len(value) % 512) + 1024
    archive_size += sum(512 + e["size"] + (-e["size"] % 512) for e in manifest["entries"])
    if archive_size > limit:
        _invalid("The complete archive exceeds the configured byte limit.")
    reserve(archive_size)
    out.write(_header("manifest.json", len(value)))
    out.write(value)
    out.write(bytes(-len(value) % 512))
    for entry in manifest["entries"]:
        _deadline(end)
        name, size = entry["path"], entry["size"]
        directory = entry["type"] == "directory"
        out.write(_header(name, size, directory))
        if directory:
            continue
        digest = hashlib.sha256()
        with _source(root / name, identities[name]) as stream:
            left = size
            while left:
                _deadline(end)
                chunk = stream.read(min(CHUNK, left))
                if not chunk:
                    _invalid("Source was truncated while archiving.")
                reserve(archive_size - out.tell())
                out.write(chunk)
                digest.update(chunk)
                left -= len(chunk)
        if digest.hexdigest() != entry["sha256"]:
            _invalid("Source content changed during archive creation.")
        out.write(bytes(-size % 512))
    out.write(ZERO * 2)
    out.flush()
    os.fsync(out.fileno())
    if _inventory(root, end, hash_files=False)[1] != identities:
        _invalid("The source tree changed before archive publication.")


def _id(suffix):
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + suffix


class BackupManager:
    def __init__(self, context, config=None, supervisor=None):
        self.context = context
        self.config = config or ConfigManager(context)
        if supervisor is None:
            from core.supervisor import Supervisor
            supervisor = Supervisor(config_manager=self.config, context=context)
        self.supervisor = supervisor
        self.base = context.paths["backups"]

    def list(self):
        check_private(self.base, directory=True)
        result = []
        for path in self.base.iterdir():
            if not re.fullmatch(ID_PATTERN + r"\.tar", path.name):
                continue
            check_private(path)
            result.append({"id": path.stem, "size": path.stat().st_size,
                           "created_at": datetime.strptime(path.name[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).isoformat()})
        return sorted(result, key=lambda entry: entry["id"], reverse=True)

    def download(self, identifier):
        if not isinstance(identifier, str) or not re.fullmatch(ID_PATTERN, identifier):
            raise PocketError("invalid_input", "Invalid archive identifier.")
        path = self.base / (identifier + ".tar")
        try:
            check_private(self.base, directory=True)
            check_private(path)
        except FileNotFoundError as exc:
            raise PocketError("not_found", "Archive does not exist.", 404) from exc
        return path

    def delete(self, identifier):
        self.context.ensure_mutable()
        with maintenance_lease(self.context, exclusive=True):
            self.download(identifier).unlink()
            sync_directory(self.base)
        return {"id": identifier, "deleted": True}

    def _path(self, archive):
        return self.download(archive) if isinstance(archive, str) and re.fullmatch(ID_PATTERN, archive) else Path(archive)

    def validate(self, archive):
        end = time.monotonic() + DEADLINE_SECONDS
        with _input(self._path(archive)) as stream:
            reader = _Reader(stream, end)
            value, by_name, total = _manifest(reader)
            _consume(reader, by_name)
        return {"valid": True, "format_version": 1, "schema_version": 3, "entries": len(by_name), "expanded_bytes": total,
                "consistency": value["consistency"], "excluded": EXCLUDED}

    def _check_offline(self, *, infrastructure=False):
        for name, status in self.supervisor.status_all().items():
            if infrastructure and name in ("controller", "dashboard"):
                continue
            if status.get("state") != "stopped" or status.get("running") or status.get("owned"):
                raise PocketError("busy", "Stop all relevant services and verify their ownership before continuing.", 409)
        from core.ssh_git import SSHGitManager
        from core.jobs import JobManager
        SSHGitManager(self.context).verify_quiescent()
        JobManager(self.context, config=self.config).verify_quiescent()

    def _pause(self, stopped):
        for name in ("tunnel", "ssh", "api", "web"):
            observation = self.supervisor.status(name)
            if observation.get("running"):
                if not observation.get("owned"):
                    raise PocketError("busy", "The service owner cannot be verified.", 409)
                self.supervisor.stop(name, maintenance_held=True)
                if name != "tunnel" and observation.get("bind_address") == "127.0.0.1":
                    stopped.append(name)
        self._check_offline(infrastructure=True)

    def _publish(self, root, consistency, end, reservation, owner):
        settings = self.config.get("backups")
        limit = min(ARCHIVE_LIMIT, settings["max_bytes"])
        reservation.reserve(owner, limit)
        identifier = _id(owner.rpartition("-")[2])
        partial = self.base / (identifier + ".partial")
        final = self.base / (identifier + ".tar")
        fd = os.open(partial, os.O_EXCL | os.O_CREAT | os.O_WRONLY, 0o600)
        try:
            with os.fdopen(fd, "wb") as output:
                entries, identities = _inventory(root, end)
                manifest = _new_manifest(entries, consistency)
                _write_archive(output, root, manifest, identities, end, limit, lambda n: reservation.reserve(owner, n))
            with _input(partial) as stream:
                reader = _Reader(stream, end)
                _, by_name, _ = _manifest(reader)
                _consume(reader, by_name)
            _move(partial, final)
            retained = self.list()
            size = sum(x["size"] for x in retained)
            while len(retained) > max(2, settings["max_count"]) or size > 2 * ARCHIVE_LIMIT and len(retained) > 2:
                candidates = [x for x in reversed(retained) if x["id"] != identifier]
                oldest = candidates[0]
                self.download(oldest["id"]).unlink()
                size -= oldest["size"]
                retained.remove(oldest)
            sync_directory(self.base)
            return {"id": identifier, "entries": len(entries), "consistency": consistency, "excluded": EXCLUDED,
                    "sensitive": True, "encrypted": False}
        finally:
            partial.unlink(missing_ok=True)

    def create(self, *, external_writers_stopped=False):
        if external_writers_stopped is not True:
            raise PocketError("confirmation_required", "Confirm external writers have stopped before backup.", 409)
        _descriptor_support()
        self.context.ensure_mutable()
        end = time.monotonic() + DEADLINE_SECONDS
        stopped = []
        resumed, resume_errors = [], {}
        owner, reservations = "backup-" + uuid.uuid4().hex, ReservationStore(self.context)
        with maintenance_lease(self.context, exclusive=True):
            try:
                self._pause(stopped)
                result = self._publish(self.context.root, "quiesced", end, reservations, owner)
            finally:
                reservations.release(owner)
                for name in reversed(stopped):
                    try:
                        self.supervisor.start(name, maintenance_held=True)
                        resumed.append(name)
                    except PocketError as exc:
                        resume_errors[name] = {"code": exc.code, "message": exc.message}
            result.update(ok=not resume_errors, resumed=resumed, resume_errors=resume_errors)
            return result

    def _stage_payload(self, stream, stage, end, reservation, owner, trust):
        reader = _Reader(stream, end)
        _, entries, total = _manifest(reader)
        remaining = total + MANIFEST_LIMIT
        reservation.reserve(owner, remaining)
        def prewrite(size):
            nonlocal remaining
            reservation.reserve(owner, remaining)
            remaining -= size
        payload = stage / "payload"
        private_dir(payload)
        cfg = _consume(reader, entries, payload, prewrite)
        if not cfg["auth"]["initialized"]:
            _invalid("Restore requires a configuration with existing administrator credentials.")
        private_dir(stage / "prepared")
        quarantine = stage / "prepared" / "quarantine"
        private_dir(quarantine)
        isolated = []
        if not trust:
            for name in ("api", "jobs"):
                path = payload / "data" / name
                _move(path, quarantine / name)
                private_dir(path)
                isolated.append("data/" + name)
        for repo in (payload / "data" / "git").iterdir():
            hooks = repo / "hooks"
            if hooks.exists():
                git = quarantine / "git"
                private_dir(git)
                _move(hooks, git / (repo.name + "-hooks"))
                isolated.append("data/git/" + repo.name + "/hooks")
            atomic_write(repo / "config", SAFE_GIT_CONFIG)
        return cfg, isolated

    def restore(self, archive, apply=False, trust_executable_content=False, *, external_writers_stopped=False):
        if apply is not True:
            return dict(self.validate(archive), applied=False)
        if external_writers_stopped is not True:
            raise PocketError("confirmation_required", "Confirm that external writers have stopped before restoring.", 409)
        _descriptor_support()
        self.context.ensure_mutable()
        end = time.monotonic() + DEADLINE_SECONDS
        ident = "restore-" + uuid.uuid4().hex
        stage = self.context.paths["staging"] / ident
        recovery = self.context.paths["recovery"] / ident
        reservation = ReservationStore(self.context)
        with maintenance_lease(self.context, exclusive=True):
            self.context.check_recovery()
            self._check_offline()
            stage.mkdir(mode=0o700)
            try:
                with _input(self._path(archive)) as stream:
                    cfg, isolated = self._stage_payload(stream, stage, end, reservation, ident, trust_executable_content is True)
                reservation.reserve(ident, MANIFEST_LIMIT)
                with FileLock(self.context.paths["locks"] / "operation.lock"), FileLock(self.config.config_lock):
                    self._check_offline()
                    self.context.check_recovery()
                    current = self.config.get_config()
                    cfg["auth"]["auth_generation"] = current["auth"]["auth_generation"] + 1
                    cfg["revision"] = current["revision"] + 1
                    cfg["metadata"]["updated_at"] = datetime.now(timezone.utc).isoformat()
                    cfg["dashboard"]["autostart"] = False
                    for service in cfg["services"].values():
                        service["autostart"] = False
                    validate_config(cfg)
                    atomic_write(stage / "payload" / "config.json", _json(cfg))
                    prepared = stage / "prepared"
                    private_dir(prepared / "old" / "data")
                    private_dir(prepared / "observations")
                    atomic_write(prepared / "new-session.key", secrets.token_hex(32).encode())
                    record = {"kind": "restore", "version": 1, "id": ident, "phase": "PREPARED", "data_committed": False,
                              "revision": cfg["revision"], "auth_generation": cfg["auth"]["auth_generation"],
                              "roots": list(ROOTS), "old_ids": {}, "new_ids": {}, "completed": [], "quarantined": isolated}
                    for name in ROOTS:
                        record["old_ids"][name] = _node_id(self.context.root / name)
                        record["new_ids"][name] = _node_id(stage / "payload" / name)
                    if any(x is None for x in [*record["old_ids"].values(), *record["new_ids"].values()]):
                        raise PocketError("recovery_required", "One or more managed roots are missing.")
                    _save_journal(prepared, record)
                    _sync_tree(stage, end)
                    sync_directory(stage.parent)
                    _move(prepared, recovery)
                    try:
                        self._commit_restore(stage, recovery, record)
                        self._finalize(recovery, record)
                    except Exception:
                        # Recover from durable evidence, including a replace that
                        # succeeded before its directory sync reported failure.
                        durable = self._load_record(recovery)
                        if not durable["data_committed"]:
                            self._rollback(stage, recovery, durable)
                        raise
                return {"applied": True, "restored": list(ROOTS), "quarantined": isolated,
                        "excluded": EXCLUDED, "rollback_location": str(recovery / "old"), "autostart": False}
            finally:
                # Incomplete transactions keep all evidence for local recovery.
                if not self.context.pending_recovery():
                    reservation.release(ident)
                    self._remove_stage(stage)

    def _commit_restore(self, stage, directory, record):
        for name in ROOTS:
            record.update(phase="MOVING", intent=name)
            _save_journal(directory, record)
            live, staged, old = self.context.root / name, stage / "payload" / name, directory / "old" / name
            if _node_id(live) != record["old_ids"][name] or _node_id(staged) != record["new_ids"][name]:
                raise PocketError("recovery_required", "A root changed immediately before restore commit.", 503)
            _move(live, old)
            _move(staged, live)
            record["completed"].append(name)
            _save_journal(directory, record)
        record.update(phase="DATA_COMMITTED", data_committed=True, intent=None)
        _save_journal(directory, record)

    def _load_record(self, directory):
        record = _decode_archive(read_private(directory / "journal.json", MANIFEST_LIMIT))
        if (not isinstance(record, dict) or record.get("kind") != "restore" or record.get("version") != 1
                or not re.fullmatch(r"restore-[0-9a-f]{32}", directory.name) or record.get("id") != directory.name
                or record.get("roots") != list(ROOTS) or type(record.get("data_committed")) is not bool
                or record.get("phase") not in ("PREPARED", "MOVING", "DATA_COMMITTED", "FINALIZING", "FINALIZED", "ROLLING_BACK")
                or type(record.get("revision")) is not int or type(record.get("auth_generation")) is not int):
            raise PocketError("recovery_required", "Invalid restore journal. Preserve all recovery files.", 503)
        if record["phase"] != "FINALIZED" and record["data_committed"] != (record["phase"] in ("DATA_COMMITTED", "FINALIZING")):
            raise PocketError("recovery_required", "Inconsistent restore commit phase.", 503)
        for group in ("old_ids", "new_ids"):
            ids = record.get(group)
            if (not isinstance(ids, dict) or set(ids) != set(ROOTS) or any(not isinstance(v, list) or len(v) != 2
                    or any(type(i) is not int or i < 0 for i in v) for v in ids.values())):
                raise PocketError("recovery_required", "Invalid restore root identity evidence.", 503)
        return record

    def _rollback(self, stage, directory, record):
        record.update(phase="ROLLING_BACK")
        _save_journal(directory, record)
        for name in reversed(ROOTS):
            live = self.context.root / name
            staged = stage / "payload" / name
            old = directory / "old" / name
            actual = (_node_id(live), _node_id(staged), _node_id(old))
            before, after = record["old_ids"][name], record["new_ids"][name]
            if actual == (after, None, before):
                _move(live, staged)
                _move(old, live)
            elif actual == (None, after, before):
                _move(old, live)
            elif actual != (before, after, None):
                raise PocketError("recovery_required", "Restore rollback evidence is inconsistent. Preserve all copies.", 503)
            record["intent"] = "rolled back " + name
            _save_journal(directory, record)
        self.config.get_config()
        self.config.get_or_create_secret_key()
        record.update(phase="FINALIZED", result="rolled_back", intent=None)
        _save_journal(directory, record)

    def _finalize(self, directory, record):
        if not record["data_committed"]:
            raise PocketError("recovery_required", "Restore has no durable data commit.", 503)
        for name in ROOTS:
            if _node_id(self.context.root / name) != record["new_ids"][name]:
                raise PocketError("recovery_required", "A committed root no longer matches its journal.", 503)
        cfg = self.config.get_config()
        if (cfg["revision"] != record["revision"] or cfg["auth"]["auth_generation"] != record["auth_generation"]
                or cfg["dashboard"]["autostart"] or any(x["autostart"] for x in cfg["services"].values())):
            raise PocketError("recovery_required", "Security generation or autostart policy differs from the restore record.", 503)
        record.update(phase="FINALIZING", intent="rotate session key")
        _save_journal(directory, record)
        key = read_private(directory / "new-session.key", 64)
        if not re.fullmatch(rb"[a-f0-9]{64}", key):
            raise PocketError("recovery_required", "Invalid restore-specific signing key.", 503)
        atomic_write(self.config.secret_path, key)
        record["intent"] = "invalidate sessions and observations"
        _save_journal(directory, record)
        StateStore(self.context).clear_for_restore(directory / "journal.json")
        state = self.context.paths["state"]
        observations = directory / "observations"
        names = ["controller-epoch.json", "wake.json", "tunnel-publication.json", "job-runs", "job-child.json",
                 *("gate-" + n + ".json" for n in ("api", "web", "dashboard", "ssh", "tunnel", "controller"))]
        for name in names:
            source, retained = state / name, observations / name
            check_path(source)
            if source.exists():
                _move(source, retained)
        self._check_offline()
        record.update(phase="FINALIZED", result="restored", intent=None)
        _save_journal(directory, record)
        (directory / "new-session.key").unlink()
        sync_directory(directory)

    def _remove_stage(self, stage):
        if (stage.parent != self.context.paths["staging"] or not re.fullmatch(r"(?:restore|import)-[0-9a-f]{32}", stage.name)):
            raise PocketError("unsafe_path", "Invalid staging cleanup target.")
        check_path(stage)
        if stage.exists():
            check_private(stage, directory=True)
            shutil.rmtree(stage)
            sync_directory(stage.parent)

    def recover(self):
        if not self.context.pending_recovery() and not self._reserved_writers():
            return {"recovered": 0}
        _descriptor_support()
        recovered = []
        with maintenance_lease(self.context, exclusive=True), FileLock(self.context.paths["locks"] / "operation.lock"), FileLock(self.config.config_lock):
            for journal in self.context.pending_recovery():
                if journal.name != "journal.json" or journal.parent.parent != self.context.paths["recovery"]:
                    raise PocketError("recovery_required", "Use the local recovery procedure matching this journal.", 503)
                directory = journal.parent
                record = self._load_record(directory)
                stage = self.context.paths["staging"] / record["id"]
                if record["data_committed"]:
                    self._check_offline()
                    self._finalize(directory, record)
                else:
                    # A crash between the two config renames can leave no live
                    # config. Observe via the preserved generation in that case.
                    source = self.config.config_path
                    if not source.exists():
                        source = directory / "old" / "config.json"
                    cfg = _decode_archive(read_private(source, CONFIG_LIMIT))
                    validate_config(cfg)
                    for name in ("controller", "dashboard", "api", "web", "ssh", "tunnel"):
                        seen = self.supervisor.backend.observe(name, cfg)
                        if seen.get("running") or seen.get("owned") or seen.get("state") != "stopped":
                            raise PocketError("busy", "All services must be confirmed offline for rollback.", 409)
                    self._rollback(stage, directory, record)
                recovered.append(record["id"])
                self._remove_stage(stage)
            for ident in recovered:
                ReservationStore(self.context).release(ident)
            abandoned = self._clean_abandoned()
        return {"recovered": len(recovered) + len(abandoned), "operations": recovered, "abandoned_writers": abandoned}

    def _reserved_writers(self):
        # Filter by explicit application-owned UUID namespaces. Listener
        # buffering reservations have different owners and survive this cleanup.
        with StateStore(self.context).connection() as db:
            rows = db.execute("SELECT owner FROM reservations")
            return [owner for (owner,) in rows if re.fullmatch(r"(?:upload|restore|import|backup)-[a-f0-9]{32}", owner)]

    def _clean_abandoned(self):
        """Caller holds exclusive maintenance, so no writer with these leases is active."""
        owners = self._reserved_writers()
        for owner in owners:
            kind, ident = owner.split("-")
            stage = self.context.paths["staging"] / owner
            if kind == "upload":
                check_path(stage)
                if stage.exists():
                    info = stage.lstat()
                    # Publication may have completed immediately before death.
                    # Unlink only the reserved staging name, leaving the vault name.
                    if (not stat.S_ISREG(info.st_mode) or info.st_nlink not in (1, 2)
                            or info.st_uid != os.getuid() or info.st_mode & 0o077):
                        raise PocketError("recovery_required", "Abandoned upload evidence has an unexpected identity.", 503)
                    stage.unlink()
                    sync_directory(stage.parent)
            if kind in ("restore", "import"):
                self._remove_stage(stage)
            if kind in ("backup", "import"):
                for path in self.base.glob("*-" + ident + ".partial"):
                    if re.fullmatch(ID_PATTERN + r"\.partial", path.name):
                        check_private(path)
                        path.unlink()
                        sync_directory(self.base)
            ReservationStore(self.context).release(owner)
        return owners

    def import_legacy(self, archive):
        """Convert, never install, v2 payloads. Do not import the signing key."""
        _descriptor_support()
        self.context.ensure_mutable()
        ident = "import-" + uuid.uuid4().hex
        stage = self.context.paths["staging"] / ident
        end = time.monotonic() + DEADLINE_SECONDS
        reservation = ReservationStore(self.context)
        seen = set()
        total = 0
        with maintenance_lease(self.context, exclusive=True):
            reservation.reserve(ident, 2 * ARCHIVE_LIMIT)
            try:
                stage.mkdir(mode=0o700)
                for root in ROOTS[:-1]:
                    private_dir(stage / root)
                with _input(archive) as source:
                    signature = source.read(2)
                    source.seek(0)
                    reader = _Reader(_GzipStream(source, end) if signature == b"\x1f\x8b" else source, end)
                    while (info := reader.header(legacy=True)) is not None:
                        name = info.name
                        if name != "secret.key":
                            _archive_path(name)
                            _git_policy(name)
                        if name.casefold() in seen or len(seen) >= ENTRY_LIMIT:
                            _invalid("Legacy archive has duplicate names or too many entries.")
                        seen.add(name.casefold())
                        if (name in ROOTS[:-1] and not info.isdir()) or (name in ("secret.key", "config.json") and info.isdir()):
                            _invalid("Legacy root has an invalid type.")
                        if name == "config.json" and info.size > CONFIG_LIMIT or name == "secret.key" and info.size > 256:
                            _invalid("Legacy credential metadata is oversized.")
                        destination = stage / name
                        if info.isdir():
                            private_dir(destination)
                            continue
                        total += info.size
                        if total > ARCHIVE_LIMIT:
                            _invalid("Expanded legacy archive exceeds its limit.")
                        with ExitStack() as opened:
                            out = None
                            if name != "secret.key":
                                private_dir(destination.parent)
                                fd = os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                                out = opened.enter_context(os.fdopen(fd, "wb"))
                            left = info.size
                            while left:
                                block = reader.read(min(CHUNK, left))
                                if out:
                                    reservation.reserve(ident, 2 * ARCHIVE_LIMIT - total + left)
                                    out.write(block)
                                left -= len(block)
                        reader.padding(info.size)
                if "config.json" not in seen:
                    _invalid("Legacy archive is missing its configuration.")
                raw = read_private(stage / "config.json", CONFIG_LIMIT)
                cfg, mapping = self.config._legacy_plan(raw)
                if not cfg["auth"]["initialized"]:
                    _invalid("Legacy archive lacks administrator credentials.")
                atomic_write(stage / "config.json", _json(cfg))
                result = self._publish(stage, "legacy-import", end, reservation, ident)
                return dict(result, omitted_roots=[r for r in ROOTS[:-1] if r not in seen], discarded=["session signing key"],
                            migration=mapping)
            finally:
                self._remove_stage(stage)
                reservation.release(ident)


def _save_journal(directory, record):
    atomic_write(directory / "journal.json", _json(record))


def _node_id(path):
    check_path(path)
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(info.st_mode) and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
        raise PocketError("unsafe_path", "Invalid restore root type.")
    return [info.st_dev, info.st_ino]


def _move(source, destination):
    check_path(source)
    check_path(destination)
    if destination.exists():
        raise PocketError("recovery_required", "A restore destination already exists. Preserve the existing evidence.", 503)
    os.rename(source, destination)
    sync_directory(source.parent)
    if source.parent != destination.parent:
        sync_directory(destination.parent)


def _sync_tree(root, end):
    for directory, _, _ in os.walk(root, topdown=False):
        _deadline(end)
        sync_directory(Path(directory))


def _pax_fields(data):
    result = {}
    while data:
        raw, space, rest = data.partition(b" ")
        if not space or not re.fullmatch(rb"[1-9][0-9]{0,4}", raw):
            _invalid("Malformed legacy extended header length.")
        size = int(raw)
        if not len(raw) + 3 < size <= len(data) or data[size-1:size] != b"\n":
            _invalid("Malformed legacy extended header.")
        record = data[len(raw)+1:size-1]
        key, equal, value = record.partition(b"=")
        if not equal or key not in (b"mtime", b"ctime", b"atime", b"path"):
            _invalid("Unsupported legacy extended metadata field.")
        try:
            key = key.decode("ascii")
            value = value.decode("utf-8")
        except UnicodeError as exc:
            raise PocketError("invalid_archive", "Invalid extended metadata encoding.") from exc
        if key in result:
            _invalid("Duplicate legacy extended header field.")
        if key == "path":
            validate_relative(value.rstrip("/"))
            value = value.rstrip("/")
        elif not re.fullmatch(r"-?[0-9]{1,16}(?:\.[0-9]{1,16})?", value):
            _invalid("Invalid legacy timestamp.")
        result[key] = value
        data = data[size:]
    return result


class _GzipStream:
    """Decode a single gzip member with bounded input and output per iteration."""
    def __init__(self, source, end):
        self.source = source
        self.end = end
        self.decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)

    def read(self, size):
        out = bytearray()
        try:
            while len(out) < size and not self.decoder.eof:
                _deadline(self.end)
                compressed = self.decoder.unconsumed_tail or self.source.read(64 * 1024)
                if not compressed:
                    _invalid("Truncated gzip stream.")
                out.extend(self.decoder.decompress(compressed, size - len(out)))
            if self.decoder.eof and (self.decoder.unused_data or self.source.read(1)):
                _invalid("Extra gzip members or trailing input are unsupported.")
        except zlib.error as exc:
            raise PocketError("invalid_archive", "Invalid gzip archive.") from exc
        return bytes(out)
