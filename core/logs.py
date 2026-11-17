"""Bounded log sinks and display-safe tails."""
from __future__ import annotations
import os
import re
import threading
from pathlib import Path

MAX_LOG_SIZE_BYTES = 1024 * 1024
MAX_LOG_BACKUPS = 2
TAIL_BYTES = 64 * 1024
_ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")
_SECRET = re.compile(r"""(?i)(["']?(?:token|password|secret|authorization|cookie|session|csrf)["']?\s*[:=]\s*["']?)([^\s,;"']+)""")

def redact_secrets(text, secrets=()):
    text = _ANSI.sub("", text)
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", text)
    text = re.sub(r"(?i)(Bearer\s+|--token\s+)\S+", r"\1[REDACTED]", text)
    text = _SECRET.sub(r"\1[REDACTED]", text)
    text = re.sub(r"""pbkdf2:[^\s"']+""", "[REDACTED_HASH]", text)
    for secret in secrets:
        if isinstance(secret, str) and secret:
            text = text.replace(secret, "[REDACTED]")
    return text

def rotate_log_file(path, max_bytes=MAX_LOG_SIZE_BYTES, max_backups=MAX_LOG_BACKUPS):
    if not path.exists() or path.stat().st_size < max_bytes:
        return
    for number in range(max_backups, 0, -1):
        source = path if number == 1 else path.with_name(f"{path.name}.{number - 1}")
        if source.exists():
            os.replace(source, path.with_name(f"{path.name}.{number}"))

def tail_log(path, lines=100, *, secrets=()):
    if type(lines) is not int or not 1 <= lines <= 1000:
        raise ValueError("lines must be an integer from 1 to 1000")
    if path.is_symlink():
        raise ValueError("Symlink logs are not supported")
    try:
        with path.open("rb") as source:
            source.seek(0, 2)
            size = source.tell()
            source.seek(max(0, size - TAIL_BYTES))
            data = source.read(TAIL_BYTES)
    except FileNotFoundError:
        return ""
    text = "\n".join(data.decode("utf-8", errors="replace").splitlines()[-lines:])
    if size > TAIL_BYTES:
        text = "[tail truncated to 64 KiB]\n" + text
    return redact_secrets(text, secrets)

class BoundedLogWriter:
    """Blocking fixed-chunk sink; no unbounded producer queue."""
    def __init__(self, path, *, max_bytes=MAX_LOG_SIZE_BYTES, backups=2):
        if max_bytes < 256 or not 0 <= backups <= 2:
            raise ValueError("Invalid log bounds")
        self.path, self.max_bytes, self.backups = Path(path), max_bytes, backups
        self.dropped_bytes = 0
        self._lock = threading.Lock()

    def write(self, value):
        raw = value.encode("utf-8", "replace") if isinstance(value, str) else bytes(value)
        # Redact before splitting, so a credential cannot straddle chunks.
        accepted = redact_secrets(raw[:TAIL_BYTES].decode("utf-8", "replace")).encode("utf-8")
        self.dropped_bytes += max(0, len(raw) - TAIL_BYTES)
        with self._lock:
            if self.path.is_symlink():
                raise ValueError("Symlink logs are not supported")
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            for offset in range(0, len(accepted), 256):
                chunk = accepted[offset:offset + 256]
                size = self.path.stat().st_size if self.path.exists() else 0
                if size + len(chunk) > self.max_bytes:
                    if self.backups:
                        rotate_log_file(self.path, size, self.backups)
                    else:
                        self.path.write_bytes(b"")
                with self.path.open("ab") as sink:
                    sink.write(chunk)
        return len(raw)

    def flush(self):
        pass

