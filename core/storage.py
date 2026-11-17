"""Descriptor-relative file vault and shared/exclusive maintenance admission."""

from contextlib import ExitStack, contextmanager
import errno
import os
from pathlib import Path
import re
import stat
import time
import unicodedata
import uuid

from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.state import ReservationStore


def validate_relative(path, allow_empty=False):
    """Return a canonical portable relative path without decoding it again."""
    if not isinstance(path, str) or len(path) > 1024:
        raise PocketError("unsafe_path", "Relative path exceeds the supported limits.")
    if path == "" and allow_empty:
        return path
    parts = path.split("/")
    if len(parts) > 32:
        raise PocketError("unsafe_path", "Relative path exceeds the supported depth.")
    for part in parts:
        try:
            count = len(part.encode("utf-8"))
        except UnicodeError as exc:
            raise PocketError("unsafe_path", "Invalid Unicode in path.") from exc
        if (part in ("", ".", "..") or count > 255 or part.endswith((".", " "))
                or unicodedata.normalize("NFC", part) != part
                or re.search(r'[\\:<>|"?*]', part)
                or any(unicodedata.category(c) == "Cc" for c in part)
                or re.fullmatch(r"(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\..*)?", part, re.I)):
            raise PocketError("unsafe_path", "Invalid or ambiguous relative path component.")
    return path


def secure_filesystem_available():
    required = {os.open, os.stat, os.link, os.unlink, os.rmdir, os.mkdir, os.rename}
    return (os.name == "posix" and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY")
            and required <= os.supports_dir_fd and os.scandir in os.supports_fd
            and os.stat in os.supports_follow_symlinks and os.link in os.supports_follow_symlinks)


@contextmanager
def maintenance_lease(context, exclusive=False, timeout=5):
    """Hold admission while obtaining the lease so an exclusive waiter can drain writers."""
    locks = context.paths["locks"]
    deadline = time.monotonic() + timeout
    with ExitStack() as lease:
        with FileLock(locks / "admission.lock", timeout=timeout):
            lease.enter_context(FileLock(locks / "maintenance.lock", shared=not exclusive,
                                         timeout=max(0, deadline - time.monotonic())))
        yield


@contextmanager
def open_directory(path):
    """Open each absolute component relative to the previous pinned directory."""
    if not secure_filesystem_available():
        raise PocketError("unsupported", "Secure descriptor-relative filesystem operations are unavailable.", 501)
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise PocketError("unsafe_path", "An absolute confined directory is required.")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    fd = os.open(path.anchor, flags)
    try:
        for part in path.parts[1:]:
            child = os.open(part, flags, dir_fd=fd)
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _safe_error(exc):
    if exc.errno == errno.ENOENT:
        return PocketError("not_found", "The requested entry was not found.", 404)
    if exc.errno == errno.EEXIST:
        return PocketError("conflict", "An entry already exists at this path.", 409)
    if exc.errno in (errno.ENOTEMPTY, errno.EISDIR):
        return PocketError("conflict", "This operation requires a file or empty directory.", 409)
    if exc.errno in (errno.ENOSPC, errno.EDQUOT):
        return PocketError("insufficient_storage", "The filesystem has insufficient space.", 409)
    return PocketError("unsafe_path", "The requested entry could not be accessed safely.", 400)


def _check_regular(info):
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise PocketError("unsafe_path", "Only a regular file with one link can be accessed.")


class FileVault:
    def __init__(self, context, root=None):
        self.context = context
        self.root = Path(root) if root is not None else context.paths["files"]
        if self.root not in (context.paths["files"], context.paths["www"]):
            raise PocketError("unsafe_path", "The requested vault root is not an exposed file root.")
        self._identity = None

    @contextmanager
    def _directory(self, relative=""):
        parts = validate_relative(relative, allow_empty=True).split("/") if relative else []
        try:
            with open_directory(self.root) as root:
                info = os.fstat(root)
                if self._identity is not None and not os.path.samestat(info, self._identity):
                    raise PocketError("unsafe_path", "The file root changed since it was opened.")
                self._identity = info
                with ExitStack() as stack:
                    fd = root
                    for part in parts:
                        fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                        stack.callback(os.close, fd)
                    yield fd
        except OSError as exc:
            raise _safe_error(exc) from exc

    def _same_directory(self, relative, fd):
        with self._directory(relative) as current:
            if not os.path.samestat(os.fstat(current), os.fstat(fd)):
                raise PocketError("unsafe_path", "The destination directory changed during the operation.")

    def list(self, path="", offset=0):
        validate_relative(path, allow_empty=True)
        if type(offset) is not int or offset < 0:
            raise PocketError("invalid_input", "Offset must be a nonnegative integer.")
        entries = []
        has_more = False
        with self._directory(path) as fd, os.scandir(fd) as iterator:
            for index, entry in enumerate(iterator):
                if index < offset:
                    continue
                if len(entries) == 200:
                    has_more = True
                    break
                info = entry.stat(follow_symlinks=False)
                kind = "directory" if stat.S_ISDIR(info.st_mode) else "file"
                if kind == "file" and (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1):
                    kind = "unsupported"
                entries.append({"name": entry.name, "type": kind, "size": info.st_size if kind == "file" else None})
        return {"entries": entries, "path": path, "next_offset": offset + len(entries) if has_more else None}

    def open_read(self, path):
        directory, _, name = validate_relative(path).rpartition("/")
        with self._directory(directory) as fd:
            # O_NONBLOCK prevents a FIFO substitution from blocking an HTTP thread.
            handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            try:
                info = os.fstat(handle)
                _check_regular(info)
                if not os.path.samestat(info, os.stat(name, dir_fd=fd, follow_symlinks=False)):
                    raise PocketError("unsafe_path", "File identity changed during open.")
                self._same_directory(directory, fd)
                return os.fdopen(handle, "rb")
            except BaseException:
                os.close(handle)
                raise

    def upload(self, path, stream, max_bytes=None):
        directory, _, name = validate_relative(path).rpartition("/")
        if self.root != self.context.paths["files"]:
            raise PocketError("unsupported", "Uploads are confined to the private file vault.", 403)
        if not secure_filesystem_available():
            raise PocketError("unsupported", "Secure uploads require descriptor-relative filesystem operations.", 501)
        with maintenance_lease(self.context), FileLock(self.context.paths["locks"] / "upload.lock", timeout=0):
            self.context.ensure_mutable()
            limit = ConfigManager(self.context).get("files")["max_upload_size_mb"] * 1024 * 1024
            if max_bytes is not None:
                if type(max_bytes) is not int or max_bytes < 0:
                    raise PocketError("invalid_input", "Invalid upload limit.")
                limit = min(limit, max_bytes)
            reservation = ReservationStore(self.context)
            owner = "upload-" + uuid.uuid4().hex
            with self._directory(directory) as parent, open_directory(self.context.paths["staging"]) as stage:
                reservation.reserve(owner, limit)
                try:
                    count = self._copy_new(parent, stage, directory, name, owner, stream, limit, reservation)
                finally:
                    reservation.release(owner)
            return {"path": path, "size": count}

    def _copy_new(self, parent, stage, directory, name, owner, stream, limit, reservation):
        try:
            os.stat(name, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise PocketError("conflict", "The destination already exists.", 409)
        handle = os.open(owner, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=stage)
        count = 0
        try:
            with os.fdopen(handle, "wb") as out:
                while True:
                    request = min(256 * 1024, limit - count + 1)
                    chunk = stream.read(request)
                    if not isinstance(chunk, bytes) or len(chunk) > request or len(chunk) + count > limit:
                        raise PocketError("too_large", "The upload exceeds its configured limit.", 413)
                    if not chunk:
                        break
                    reservation.reserve(owner, limit - count)
                    out.write(chunk)
                    count += len(chunk)
                out.flush()
                os.fsync(out.fileno())
                self._same_directory(directory, parent)
                os.link(owner, name, src_dir_fd=stage, dst_dir_fd=parent, follow_symlinks=False)
            os.unlink(owner, dir_fd=stage)
            try:
                os.fsync(parent)
                os.fsync(stage)
            except OSError as exc:
                raise PocketError("durability_uncertain", "Upload was published but directory sync failed.", 503) from exc
            return count
        finally:
            try:
                os.unlink(owner, dir_fd=stage)
            except FileNotFoundError:
                pass

    def delete(self, path):
        directory, _, name = validate_relative(path).rpartition("/")
        if self.root != self.context.paths["files"]:
            raise PocketError("unsupported", "Deletion is confined to the private file vault.", 403)
        if not secure_filesystem_available():
            raise PocketError("unsupported", "Secure deletion requires descriptor-relative filesystem operations.", 501)
        with maintenance_lease(self.context), FileLock(self.context.paths["locks"] / "upload.lock", timeout=0):
            self.context.ensure_mutable()
            with self._directory(directory) as parent:
                info = os.stat(name, dir_fd=parent, follow_symlinks=False)
                self._same_directory(directory, parent)
                if stat.S_ISDIR(info.st_mode):
                    os.rmdir(name, dir_fd=parent)
                else:
                    _check_regular(info)
                    os.unlink(name, dir_fd=parent)
                os.fsync(parent)
            return {"path": path, "deleted": True}
