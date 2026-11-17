"""OS-backed leases. Acquire maintenance, operation, config, then resource locks.

Never upgrade a shared lease or unlink a live lock file. Each acquisition opens
its own file description so independent threads compete like separate processes.
"""

import errno
import math
import os
import time
from pathlib import Path

from core.errors import PocketError
from core.runtime import check_path, check_private

if os.name == "nt":
    import ctypes
    import msvcrt
    from ctypes import wintypes

    class _Overlapped(ctypes.Structure):
        _fields_ = [("Internal", ctypes.c_size_t), ("InternalHigh", ctypes.c_size_t),
                    ("Offset", wintypes.DWORD), ("OffsetHigh", wintypes.DWORD), ("hEvent", wintypes.HANDLE)]

    _kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    _lock = _kernel.LockFileEx
    _lock.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                      ctypes.POINTER(_Overlapped)]
    _lock.restype = wintypes.BOOL
    _unlock = _kernel.UnlockFileEx
    _unlock.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.DWORD, wintypes.DWORD,
                        ctypes.POINTER(_Overlapped)]
    _unlock.restype = wintypes.BOOL
else:
    import fcntl


class FileLock:
    def __init__(self, path, timeout=5, shared=False):
        if not math.isfinite(timeout) or timeout < 0:
            raise ValueError("Lock timeout must be finite and nonnegative.")
        self.path = Path(path)
        self.timeout = timeout
        self.shared = shared
        self._fd = None

    def _try_lock(self):
        if os.name == "nt":
            flags = 1 if self.shared else 3  # FAIL_IMMEDIATELY [+ EXCLUSIVE_LOCK]
            self._overlap = _Overlapped()
            handle = msvcrt.get_osfhandle(self._fd)
            if _lock(handle, flags, 0, 1, 0, ctypes.byref(self._overlap)):
                return True
            err = ctypes.get_last_error()
            if err == 33:  # ERROR_LOCK_VIOLATION
                return False
            raise ctypes.WinError(err)
        flags = fcntl.LOCK_SH if self.shared else fcntl.LOCK_EX
        try:
            fcntl.flock(self._fd, flags | fcntl.LOCK_NB)
            return True
        except OSError as exc:
            if exc.errno in (errno.EACCES, errno.EAGAIN):
                return False
            raise

    def __enter__(self):
        if self._fd is not None:
            raise RuntimeError("A FileLock instance cannot be entered twice.")
        check_private(self.path.parent, directory=True)
        check_path(self.path)
        if self.path.exists():
            check_private(self.path)
        self._fd = os.open(self.path, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            check_private(self.path)
            if not os.path.samestat(self.path.stat(), os.fstat(self._fd)):
                raise PocketError("unsafe_path", "Lock file identity changed.")
            deadline = time.monotonic() + self.timeout
            while not self._try_lock():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise PocketError("busy", "The operation lock is busy. Retry later.", 409)
                time.sleep(min(0.025, remaining))
            return self
        except BaseException:
            os.close(self._fd)
            self._fd = None
            raise

    def __exit__(self, exc_type, exc, tb):
        try:
            if os.name == "nt":
                if not _unlock(msvcrt.get_osfhandle(self._fd), 0, 1, 0, ctypes.byref(self._overlap)):
                    raise ctypes.WinError(ctypes.get_last_error())
            else:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
        finally:
            os.close(self._fd)
            self._fd = None
