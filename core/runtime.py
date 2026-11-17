"""Runtime discovery is read-only. Only explicit initialization creates a layout."""

from __future__ import annotations

import errno
import json
import os
import re
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

from core.errors import PocketError


def check_path(path: Path) -> None:
    """Refuse link/reparse traversal, including existing parents of a new path."""
    if not path.is_absolute() or ".." in path.parts:
        raise PocketError("unsafe_path", "An absolute path without parent traversal is required.")
    for item in (*reversed(path.parents), path):
        try:
            info = item.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & 0x400:
            raise PocketError("unsafe_path", "A runtime path contains a symbolic link or reparse point.")


def check_private(path: Path, *, directory: bool = False, legacy: bool = False) -> None:
    check_path(path)
    info = path.stat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    if not kind(info.st_mode) or (not directory and info.st_nlink != 1):
        raise PocketError("unsafe_path", "The runtime entry has an unsafe type or hard link.")
    if os.name == "posix":
        forbidden = 0o022 if legacy else 0o077
        if info.st_uid != os.getuid() or info.st_mode & forbidden:
            raise PocketError("unsafe_path", "The runtime entry must be owner-controlled and private.")


def private_dir(path: Path) -> None:
    check_path(path)
    if not path.parent.exists():
        private_dir(path.parent)
    path.mkdir(mode=0o700, exist_ok=True)
    check_private(path, directory=True)


def sync_directory(path: Path) -> None:
    """Windows has no equivalent supported directory-fsync contract."""
    if os.name != "posix":
        return
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        try:
            os.fsync(fd)
        except OSError as exc:
            if exc.errno not in (errno.EINVAL, errno.ENOTSUP):
                raise
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    """The replace is the commit point. A later sync failure has a distinct error."""
    path = Path(path)
    check_private(path.parent, directory=True)
    check_path(path)
    if path.exists():
        check_private(path)
    fd, temp_name = tempfile.mkstemp(prefix=".pocket-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            if os.name == "posix":
                os.fchmod(stream.fileno(), mode)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        deadline = time.monotonic() + 0.5
        while True:
            try:
                os.replace(temp_name, path)
                break
            except OSError as exc:
                # Windows readers/indexers can briefly deny replacement. Retry
                # only sharing/access conflicts, while retaining the same
                # private prepared file and the original commit point.
                if os.name != "nt" or getattr(exc, "winerror", None) not in (5, 32, 33) or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        try:
            sync_directory(path.parent)
        except OSError as exc:
            raise PocketError("durability_uncertain", "Replacement committed but directory sync failed. Run recovery.", 503) from exc
    finally:
        Path(temp_name).unlink(missing_ok=True)


def read_private(path: Path, limit: int, *, legacy: bool = False) -> bytes:
    check_private(path, legacy=legacy)
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as stream:
        if not os.path.samestat(path.stat(), os.fstat(fd)):
            raise PocketError("unsafe_path", "The runtime entry changed during access.")
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise PocketError("invalid_config", "The runtime entry exceeds its size limit.")
    return value


@dataclass(frozen=True)
class RuntimeContext:
    root: Path
    mode: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", Path(self.root))
        check_path(self.root)
        if self.mode not in ("termux", "mock"):
            raise PocketError("invalid_config", "Invalid runtime mode.")
        if self.root == Path(self.root.anchor) or self.root == Path.home() or ".git" in [p.casefold() for p in self.root.parts]:
            raise PocketError("unsafe_path", "Choose a dedicated private runtime directory.")
        if self.mode == "termux" and not self.root.is_relative_to(Path.home()):
            raise PocketError("unsafe_path", "Production storage must be under the private Termux home.")

    @classmethod
    def discover(cls, root=None, mode=None) -> RuntimeContext:
        requested = mode if mode is not None else os.environ.get("POCKETSERVER_ENV", "auto")
        if requested not in ("auto", "mock", "termux"):
            raise PocketError("invalid_config", "POCKETSERVER_ENV must be auto, mock or termux.")
        prefix = os.environ.get("PREFIX", "")
        hint = bool(os.environ.get("TERMUX_VERSION") or re.match(r"/data/(data|user/\d+)/com\.termux(?:/|$)", prefix))
        termux = (os.name == "posix" and prefix.endswith("/com.termux/files/usr")
                  and hint and os.access(Path(prefix) / "bin" / "pkg", os.X_OK))
        if requested == "termux" and not termux or requested == "auto" and hint and not termux:
            raise PocketError("unsupported", "Incomplete Termux environment. Use a supported private Termux session.", 503)
        selected = "termux" if requested != "mock" and termux else "mock"
        supplied = root if root is not None else os.environ.get("POCKETSERVER_HOME")
        default = (Path.home() / ".pocketserver" if selected == "termux" else
                   Path(__file__).resolve().parent.parent / ".mock_termux" / "home" / ".pocketserver")
        return cls(Path(supplied) if supplied is not None else default, selected)

    @property
    def paths(self) -> dict[str, Path]:
        paths = {key: self.root / key for key in ("pids", "logs", "data", "locks", "state", "ssh", "backups", "staging", "recovery")}
        paths.update({key: paths["data"] / key for key in ("www", "api", "files", "git", "jobs")})
        paths.update(base=self.root, config_file=self.root / "config.json", secret_file=self.root / "secret.key",
                     db=self.root / "state.sqlite3", state_wake_lock=paths["pids"] / "wake_lock.state")
        return paths

    def initialize(self) -> None:
        for path in [self.root, *self.directories()]:
            private_dir(path)

    def directories(self) -> list[Path]:
        return [self.paths[key] for key in ("locks", "state", "logs", "data", "www", "api", "files", "git", "jobs",
                                            "ssh", "pids", "backups", "staging", "recovery")]

    def pending_recovery(self) -> list[Path]:
        directory = self.paths["recovery"]
        check_path(directory)
        if not directory.exists():
            return []
        check_private(directory, directory=True)
        pending = []
        for item in directory.iterdir():
            check_path(item)
            if item.is_dir():
                check_private(item, directory=True)
                journal = item / "journal.json"
                check_path(journal)
                if not journal.exists():
                    pending.append(item)
                    continue
            elif item.suffix == ".json":
                journal = item
            else:
                continue
            if journal == directory / "config-durability.json":
                # A live config writer holds this lease across its prepared
                # journal and replace. Wait for that bounded commit before
                # classifying evidence left by an interrupted writer.
                writing = self.paths["locks"] / "config-write.lock"
                check_path(writing)
                if writing.exists():
                    from core.locking import FileLock
                    with FileLock(writing, shared=True):
                        if not journal.exists():
                            continue
            try:
                record = json.loads(read_private(journal, 4 * 1024 * 1024))
            except FileNotFoundError:
                if journal == directory / "config-durability.json":
                    continue
                pending.append(journal)
                continue
            except (OSError, ValueError):
                pending.append(journal)
                continue
            if not isinstance(record, dict) or record.get("phase") != "FINALIZED":
                pending.append(journal)
        return pending

    def check_recovery(self) -> None:
        if self.pending_recovery():
            raise PocketError("recovery_required", "A pending journal requires local recovery.", 503)

    def ensure_mutable(self) -> None:
        from core.config import ConfigManager
        self.check_recovery()
        manager = ConfigManager(context=self)
        if not manager.is_initialized():
            raise PocketError("not_initialized", "Initialize PocketServer locally before making changes.", 409)
        for directory in self.directories():
            try:
                check_private(directory, directory=True)
            except FileNotFoundError as exc:
                raise PocketError("recovery_required", "The initialized runtime is missing a directory.", 503) from exc
        manager.get_or_create_secret_key()
