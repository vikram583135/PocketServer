"""Private, bounded durable state. Constructors never create a database."""
from __future__ import annotations

from contextlib import closing, contextmanager
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time
import uuid

from core.errors import PocketError
from core.locking import FileLock
from core.runtime import atomic_write, check_path, check_private, read_private, sync_directory


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (
 id TEXT PRIMARY KEY, csrf TEXT NOT NULL, authenticated INTEGER NOT NULL,
 generation INTEGER NOT NULL, created REAL NOT NULL, touched REAL NOT NULL,
 expires REAL NOT NULL, reauth REAL NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS operations (
 id TEXT PRIMARY KEY, action TEXT NOT NULL, target TEXT NOT NULL,
 payload TEXT NOT NULL, actor TEXT NOT NULL, phase TEXT NOT NULL,
 created REAL NOT NULL, updated REAL NOT NULL, result TEXT, error TEXT,
 idempotency_key TEXT UNIQUE, fingerprint TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reservations (
 owner TEXT PRIMARY KEY, bytes INTEGER NOT NULL CHECK(bytes>=0), created REAL NOT NULL);
CREATE TABLE IF NOT EXISTS rates (
 bucket TEXT PRIMARY KEY, started REAL NOT NULL, count INTEGER NOT NULL);
"""


class StateStore:
    def __init__(self, context):
        self.context = context
        self.path = context.root / "state.sqlite3"

    def initialize(self):
        self.context.ensure_mutable()
        from core.locking import FileLock
        with FileLock(self.context.root / "locks" / "state-init.lock"):
            if self.path.is_symlink():
                raise PocketError("unsafe_path", "State database cannot be a link.", 503)
            created = not self.path.exists()
            if not created:
                check_private(self.path)
                if not _healthy_state(self.path):
                    raise PocketError("recovery_required", "State schema is invalid; use explicit local state recovery.", 503)
                return
            if created:
                fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(fd)
            try:
                with closing(sqlite3.connect(self.path, timeout=3)) as db, db:
                    if not created and db.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                        raise PocketError("recovery_required", "State database requires local recovery.", 503)
                    if not created:
                        version = db.execute("SELECT version FROM meta").fetchone()
                        if version != (1,):
                            raise PocketError("recovery_required", "Unsupported state schema.", 503)
                    db.executescript(SCHEMA)
                    if created:
                        db.execute("INSERT INTO meta VALUES (1)")
            except sqlite3.Error as exc:
                raise PocketError("recovery_required", "State database requires local recovery.", 503) from exc

    @contextmanager
    def connection(self, *, write=False):
        self.context.ensure_mutable()
        lock = self.context.paths["locks"] / "state-init.lock"
        try:
            check_private(lock)
        except FileNotFoundError as exc:
            raise PocketError("recovery_required", "The state database has not been initialized or requires local recovery.", 503) from exc
        with FileLock(lock, shared=True):
            # Recovery can start after the first check while this caller is
            # waiting for the database lease. Recheck before opening SQLite.
            self.context.check_recovery()
            with self._connection(write=write) as db:
                yield db

    @contextmanager
    def _connection(self, *, write):
        if self.path.is_symlink() or not self.path.is_file():
            raise PocketError("recovery_required", "Initialize or recover the private state database locally.", 503)
        check_private(self.path)
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=3)
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA busy_timeout=3000")
            version = db.execute("SELECT version FROM meta").fetchone()
            if version is None or version[0] != 1:
                raise PocketError("recovery_required", "Unsupported state schema.", 503)
            if write:
                db.execute("BEGIN IMMEDIATE")
            yield db
            if write:
                db.commit()
        except sqlite3.OperationalError as exc:
            if "locked" in str(exc).lower() or "busy" in str(exc).lower():
                raise PocketError("busy", "State is busy; retry shortly.", 409) from exc
            raise PocketError("recovery_required", "State database is unavailable; local recovery is required.", 503) from exc
        except sqlite3.DatabaseError as exc:
            raise PocketError("recovery_required", "State database is invalid; local recovery is required.", 503) from exc
        finally:
            if db is not None:
                db.close()

    def rate_attempt(self, client, now=None):
        """Reserve capacity before hashing; verified successes refund this window."""
        now = time.time() if now is None else now
        client_key = hashlib.sha256(client.encode()).hexdigest()
        with self.connection(write=True) as db:
            db.execute("DELETE FROM rates WHERE started < ?", (now - 60,))
            for bucket, limit in (("global", 20), (client_key, 5)):
                row = db.execute("SELECT count FROM rates WHERE bucket=?", (bucket,)).fetchone()
                if row and row[0] >= limit:
                    raise PocketError("rate_limited", "Try again later.", 429)
            for bucket in ("global", client_key):
                db.execute("INSERT INTO rates VALUES(?,?,1) ON CONFLICT(bucket) DO UPDATE SET count=count+1", (bucket, now))
            return [(bucket, db.execute("SELECT started FROM rates WHERE bucket=?", (bucket,)).fetchone()[0]) for bucket in ("global", client_key)]

    def rate_success(self, reservation):
        with self.connection(write=True) as db:
            for bucket, started in reservation:
                db.execute("UPDATE rates SET count=MAX(0,count-1) WHERE bucket=? AND started=?", (bucket, started))

    def clear_sessions(self):
        with self.connection(write=True) as db:
            db.execute("DELETE FROM sessions")

    def recover(self, supervisor=None, apply=False):
        """Preview or explicitly rebuild corrupt volatile state on an offline runtime."""
        return _DatabaseRecovery(self, supervisor).run(apply=apply)

    def clear_for_restore(self, journal_path):
        """Narrow recovery bypass; caller holds offline restore leases and locks."""
        from core.runtime import check_private, read_private
        journal = Path(journal_path)
        recovery = self.context.root / "recovery"
        if journal.name != "journal.json" or journal.parent.parent != recovery:
            raise PocketError("recovery_required", "Invalid restore journal location.", 503)
        record = json.loads(read_private(journal, 4 * 1024 * 1024))
        if record.get("data_committed") is not True or record.get("phase") == "FINALIZED":
            raise PocketError("recovery_required", "Restore data must be committed before clearing security state.", 503)
        check_private(self.path)
        db = None
        try:
            db = sqlite3.connect(self.path.as_uri() + "?mode=rw", uri=True, timeout=3)
            if db.execute("PRAGMA quick_check").fetchone()[0] != "ok" or db.execute("SELECT version FROM meta").fetchone() != (1,):
                raise PocketError("recovery_required", "State database requires separate local recovery.", 503)
            db.execute("BEGIN IMMEDIATE")
            for table in ("sessions", "rates", "operations", "reservations"):
                db.execute(f"DELETE FROM {table}")
            db.commit()
        except sqlite3.Error as exc:
            raise PocketError("recovery_required", "State reset failed; keep services stopped and retry recovery.", 503) from exc
        finally:
            if db is not None:
                db.close()


class OperationsStore(StateStore):
    @staticmethod
    def _decode(row):
        if row is None:
            return None
        value = dict(row)
        for field in ("payload", "result", "error"):
            value[field] = json.loads(value[field]) if value[field] is not None else None
        value.pop("fingerprint", None)
        value.pop("idempotency_key", None)
        return value

    def enqueue(self, action, target, payload=None, actor="cli", idempotency_key=None):
        payload = payload or {}
        serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        if len(serialized.encode()) > 65536 or len(action) > 64 or len(target) > 128:
            raise PocketError("invalid_input", "Operation is too large.", 400)
        if idempotency_key is not None and (not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 128):
            raise PocketError("invalid_input", "Invalid idempotency key.", 400)
        fingerprint = hashlib.sha256((action + "\0" + target + "\0" + serialized).encode()).hexdigest()
        now = time.time()
        with self.connection(write=True) as db:
            self._prune(db, now)
            if idempotency_key:
                existing = db.execute("SELECT * FROM operations WHERE idempotency_key=?", (idempotency_key,)).fetchone()
                if existing:
                    if existing["fingerprint"] != fingerprint or existing["actor"] != actor:
                        raise PocketError("conflict", "Idempotency key was used for a different request.", 409)
                    return self._decode(existing)
            if db.execute("SELECT count(*) FROM operations WHERE phase='queued'").fetchone()[0] >= 16:
                raise PocketError("busy", "The operation queue is full.", 409)
            if action == "job_run" and db.execute("SELECT count(*) FROM operations WHERE action='job_run' AND phase IN ('queued','running','cancelling')").fetchone()[0] >= 10:
                raise PocketError("busy", "The job admission queue is full.", 409)
            identifier = uuid.uuid4().hex
            db.execute("INSERT INTO operations VALUES(?,?,?,?,?,'queued',?,?,NULL,NULL,?,?)",
                       (identifier, action, target, serialized, actor, now, now, idempotency_key, fingerprint))
            return self._decode(db.execute("SELECT * FROM operations WHERE id=?", (identifier,)).fetchone())

    @staticmethod
    def _prune(db, now):
        db.execute("DELETE FROM operations WHERE phase NOT IN ('queued','running','cancelling') AND updated < ?", (now - 7 * 86400,))
        db.execute("DELETE FROM operations WHERE id IN (SELECT id FROM operations WHERE phase NOT IN ('queued','running','cancelling') ORDER BY updated DESC LIMIT -1 OFFSET 200)")

    def get(self, identifier):
        with self.connection() as db:
            row = db.execute("SELECT * FROM operations WHERE id=?", (identifier,)).fetchone()
            if row is None:
                raise PocketError("not_found", "Operation is no longer available.", 404)
            return self._decode(row)

    def claim_next(self):
        with self.connection(write=True) as db:
            row = db.execute("SELECT * FROM operations WHERE phase='queued' ORDER BY created LIMIT 1").fetchone()
            if row is None:
                return None
            db.execute("UPDATE operations SET phase='running',updated=? WHERE id=? AND phase='queued'", (time.time(), row["id"]))
            return self._decode(db.execute("SELECT * FROM operations WHERE id=?", (row["id"],)).fetchone())

    def finish(self, identifier, result=None, error=None):
        # Keep sanitized, bounded operation results; never persist raw exceptions.
        result_json = json.dumps(result, allow_nan=False, default=str)
        error_json = json.dumps(error, allow_nan=False, default=str)
        if len(result_json.encode()) > 65536:
            result_json = json.dumps({"truncated": True})
        if len(error_json.encode()) > 4096:
            error_json = json.dumps({"code": "operation_failed", "message": "Operation failed."})
        with self.connection(write=True) as db:
            phase = "succeeded"
            if isinstance(result, dict):
                state = result.get("state")
                if state in {"cancelled", "failed", "timed_out", "interrupted"}:
                    phase = state
                if result.get("ok") is False:
                    phase = "failed"
            if error:
                phase = "failed"
            db.execute("UPDATE operations SET phase=?,updated=?,result=?,error=? WHERE id=? AND phase IN ('running','cancelling')",
                       (phase, time.time(), result_json, error_json, identifier))
            self._prune(db, time.time())

    def interrupt_running(self):
        with self.connection(write=True) as db:
            db.execute("UPDATE operations SET phase='interrupted',updated=?,error=? WHERE phase IN ('running','cancelling')",
                       (time.time(), json.dumps({"code": "interrupted", "message": "Controller stopped; operation was not replayed."})))

    def cancel_queued_job(self, identifier):
        with self.connection(write=True) as db:
            row = db.execute("SELECT * FROM operations WHERE id=? AND action='job_run'", (identifier,)).fetchone()
            if row is None:
                raise PocketError("not_found", "No such queued job run.", 404)
            if row["phase"] in {"queued", "cancelled"}:
                db.execute("UPDATE operations SET phase='cancelled',updated=? WHERE id=?", (time.time(), identifier))
                return {"id": identifier, "job_id": row["target"], "state": "cancelled"}
            if row["phase"] in {"running", "cancelling"}:
                db.execute("UPDATE operations SET phase='cancelling',updated=? WHERE id=?", (time.time(), identifier))
            return None


class ReservationStore(StateStore):
    HEADROOM = 250 * 1024 * 1024

    def reserve(self, owner, size, *, free_bytes=None):
        import shutil
        if type(size) is not int or size < 0:
            raise PocketError("invalid_input", "Reservation must use a nonnegative byte count.", 400)
        with self.connection(write=True) as db:
            free = shutil.disk_usage(self.context.root).free if free_bytes is None else free_bytes
            reserved = db.execute("SELECT COALESCE(SUM(bytes),0) FROM reservations WHERE owner!=?", (owner,)).fetchone()[0]
            if size + reserved + self.HEADROOM > free:
                raise PocketError("insufficient_storage", "Insufficient unreserved space including 250 MiB headroom.", 409)
            db.execute("INSERT INTO reservations VALUES(?,?,?) ON CONFLICT(owner) DO UPDATE SET bytes=excluded.bytes", (owner, size, time.time()))
        return size

    def release(self, owner):
        with self.connection(write=True) as db:
            db.execute("DELETE FROM reservations WHERE owner=?", (owner,))

    def total(self):
        with self.connection() as db:
            return db.execute("SELECT COALESCE(SUM(bytes),0) FROM reservations").fetchone()[0]


_DB_MEMBERS = ("state.sqlite3-journal", "state.sqlite3-wal", "state.sqlite3-shm", "state.sqlite3")
_VOLATILE = ["sessions", "operations", "rate-limit counters", "storage reservations"]


def _state_problem(message):
    raise PocketError("recovery_required", message, 503)


def _state_json(obj):
    return (json.dumps(obj, sort_keys=True, allow_nan=False, separators=(",", ":")) + "\n").encode()


def _fingerprint(path):
    """Bind recovery evidence to both the private file identity and its bytes."""
    check_path(path)
    if not path.exists():
        return None
    check_private(path)
    named = path.stat()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as data:
        opened = os.fstat(fd)
        if not os.path.samestat(named, opened):
            _state_problem("A state file changed before it could be inspected.")
        digest = hashlib.sha256()
        for block in iter(lambda: data.read(1024 * 1024), b""):
            digest.update(block)
        last = os.fstat(fd)
        if (not os.path.samestat(path.stat(), opened) or last.st_nlink != 1 or last.st_size != opened.st_size
                or last.st_mtime_ns != opened.st_mtime_ns):
            _state_problem("A state file changed during inspection.")
        return {"file": [opened.st_dev, opened.st_ino], "size": opened.st_size, "sha256": digest.hexdigest()}


def _schema_signature(db):
    return db.execute("SELECT type, name, sql FROM sqlite_master ORDER BY type, name").fetchall()


def _healthy_state(path):
    check_path(path)
    if not path.exists():
        return False
    check_private(path)
    try:
        # immutable avoids SQLite creating a journal or shared-memory file
        # while examining a damaged database, including during preview.
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro&immutable=1", uri=True, timeout=1)) as db:
            db.execute("PRAGMA trusted_schema=OFF")
            db.execute("PRAGMA query_only=ON")
            end = time.monotonic() + 30
            db.set_progress_handler(lambda: int(time.monotonic() >= end), 5000)
            with closing(sqlite3.connect(":memory:")) as comparison:
                comparison.executescript(SCHEMA)
                return (db.execute("PRAGMA quick_check(1)").fetchone() == ("ok",)
                        and db.execute("SELECT version FROM meta LIMIT 2").fetchall() == [(1,)]
                        and _schema_signature(db) == _schema_signature(comparison))
    except sqlite3.DatabaseError:
        return False


def _state_move(source, dest):
    check_path(source)
    check_path(dest)
    if dest.exists():
        _state_problem("A state recovery destination is occupied. Preserve the existing evidence.")
    os.rename(source, dest)
    sync_directory(source.parent)
    if source.parent != dest.parent:
        sync_directory(dest.parent)


class _DatabaseRecovery:
    def __init__(self, store, supervisor):
        from core.backups import BackupManager
        from core.config import ConfigManager
        self.store = store
        self.context = store.context
        self.config = ConfigManager(self.context)
        self.backups = BackupManager(self.context, config=self.config, supervisor=supervisor)
        self.recovery = self.context.paths["recovery"]

    def _journals(self):
        from core.config import _decode
        own = restore = nested = None
        for path in self.context.pending_recovery():
            if path.parent == self.recovery and re.fullmatch(r"state-db-[0-9a-f]{32}\.json", path.name) and own is None:
                record = _decode(read_private(path, 65536))
                self._check_record(path, record)
                own = record
            elif path.parent == self.recovery and path.name == "config-durability.json" and nested is None:
                nested = _decode(read_private(path, 4096))
            elif path.name == "journal.json" and path.parent.parent == self.recovery and restore is None:
                record = self.backups._load_record(path.parent)
                if record["phase"] not in ("DATA_COMMITTED", "FINALIZING") or not record["data_committed"]:
                    _state_problem("Finish the precommit restore rollback before recovering the database.")
                restore = record
            else:
                _state_problem("An unrelated or malformed recovery journal requires its own local recovery procedure.")
        if own:
            expected_parent = own.get("restore")
            if (expected_parent is None) != (restore is None) or restore and expected_parent["id"] != restore["id"]:
                _state_problem("The restore parent differs from the state recovery journal.")
        if nested and (not own or
                nested != {"kind": "config-durability", "phase": "PREPARED", "revision": own["revision"],
                           "original_sha256": own["old_config"], "target_sha256": own["new_config"]}):
            _state_problem("The pending configuration transaction does not belong to this state recovery.")
        return own, restore, nested

    def _check_record(self, path, record):
        if (not isinstance(record, dict) or record.get("kind") != "state-db" or record.get("version") != 1
                or record.get("id") != path.stem or record.get("phase") not in ("PREPARED", "PRESERVING", "PUBLISHING", "SECURING")
                or type(record.get("originals")) is not dict or set(record["originals"]) != set(_DB_MEMBERS)
                or type(record.get("revision")) is not int or type(record.get("auth_generation")) is not int
                or not all(isinstance(record.get(k), str) and re.fullmatch(r"[a-f0-9]{64}", record[k])
                           for k in ("old_config", "new_config"))):
            _state_problem("Invalid database recovery journal.")
        for proof in [record.get("fresh"), *record["originals"].values()]:
            if proof is None:
                continue
            if (type(proof) is not dict or set(proof) != {"size", "file", "sha256"}
                    or type(proof["size"]) is not int or proof["size"] < 0 or type(proof["file"]) is not list
                    or len(proof["file"]) != 2 or not all(type(n) is int and n >= 0 for n in proof["file"])
                    or not isinstance(proof["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", proof["sha256"])):
                _state_problem("Invalid database file identity evidence.")
        if record.get("fresh") is None:
            _state_problem("The journal does not identify the prepared replacement database.")
        parent = record.get("restore")
        if parent is not None and (type(parent) is not dict or set(parent) != {"id", "digest", "revision", "auth_generation", "config_id"}
                or not isinstance(parent["id"], str) or not re.fullmatch(r"restore-[a-f0-9]{32}", parent["id"])
                or not isinstance(parent["digest"], str) or not re.fullmatch(r"[a-f0-9]{64}", parent["digest"])
                or not all(type(parent[k]) is int for k in ("revision", "auth_generation"))
                or type(parent["config_id"]) is not list or len(parent["config_id"]) != 2
                or not all(type(n) is int and n >= 0 for n in parent["config_id"])):
            _state_problem("Invalid parent restore evidence.")

    def _path(self, record, suffix):
        return self.recovery / (record["id"] + suffix)

    def _write(self, record, phase, intent=None):
        record.update(phase=phase, intent=intent)
        atomic_write(self._path(record, ".json"), _state_json(record))

    def _prepare(self, restore):
        from core.config import _encode, _now, validate_config
        cfg = self.config.get_config()
        proof = _fingerprint(self.config.config_path)
        parent = None
        if restore:
            if (restore["new_ids"]["config.json"] != proof["file"] or restore["revision"] != cfg["revision"]
                    or restore["auth_generation"] != cfg["auth"]["auth_generation"]):
                _state_problem("The committed restore configuration is inconsistent with its journal.")
            parent = {"id": restore["id"], "digest": hashlib.sha256(_state_json(restore)).hexdigest(),
                      "revision": cfg["revision"], "auth_generation": cfg["auth"]["auth_generation"],
                      "config_id": proof["file"]}
        original_sha = proof["sha256"]
        cfg["revision"] += 1
        cfg["auth"]["auth_generation"] += 1
        cfg["metadata"]["updated_at"] = _now()
        validate_config(cfg)
        target = _encode(cfg)
        record = {"kind": "state-db", "version": 1, "id": "state-db-" + uuid.uuid4().hex,
                  "revision": cfg["revision"], "auth_generation": cfg["auth"]["auth_generation"],
                  "old_config": original_sha, "new_config": hashlib.sha256(target).hexdigest(), "restore": parent,
                  "originals": {name: _fingerprint(self.context.root / name) for name in _DB_MEMBERS}}
        fresh = self._path(record, ".fresh.sqlite3")
        atomic_write(self._path(record, ".target-config"), target)
        fd = os.open(fresh, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
        os.close(fd)
        with closing(sqlite3.connect(fresh.as_uri() + "?mode=rw", uri=True)) as db, db:
            db.executescript(SCHEMA)
            db.execute("INSERT INTO meta VALUES (1)")
        with fresh.open("r+b") as data:
            os.fsync(data.fileno())
        sync_directory(self.recovery)
        if not _healthy_state(fresh):
            _state_problem("Could not verify the fresh state database.")
        record["fresh"] = _fingerprint(fresh)
        self._write(record, "PREPARED")
        return record

    def _rebuild(self, record):
        for name in _DB_MEMBERS:
            live, saved = self.context.root / name, self._path(record, ".original-" + name)
            expected = record["originals"][name]
            actual, preserved = _fingerprint(live), _fingerprint(saved)
            if name == self.store.path.name and actual == record["fresh"]:
                actual = None  # Already published. Still verify the retained original.
            if expected is None:
                if actual is not None or preserved is not None:
                    _state_problem("An unexpected SQLite file appeared during recovery.")
                continue
            if actual is None and preserved == expected:
                continue
            if actual != expected or preserved is not None:
                _state_problem("A SQLite database or sidecar differs from its registered recovery evidence.")
            self._write(record, "PRESERVING", name)
            _state_move(live, saved)
        source = self._path(record, ".fresh.sqlite3")
        live, staged = _fingerprint(self.store.path), _fingerprint(source)
        if live is None and staged == record["fresh"]:
            self._write(record, "PUBLISHING", self.store.path.name)
            _state_move(source, self.store.path)
        elif live != record["fresh"] or staged is not None:
            _state_problem("Cannot identify the prepared database at its staged or published location.")

    def _secure(self, record, parent, nested):
        from core.config import CONFIG_LIMIT, _decode, validate_config
        candidate = read_private(self._path(record, ".target-config"), CONFIG_LIMIT)
        if hashlib.sha256(candidate).hexdigest() != record["new_config"]:
            _state_problem("The prepared configuration does not match its registered digest.")
        cfg = _decode(candidate)
        validate_config(cfg)
        if cfg["revision"] != record["revision"] or cfg["auth"]["auth_generation"] != record["auth_generation"]:
            _state_problem("The prepared security counters do not match the state recovery journal.")
        live = _fingerprint(self.config.config_path)
        if live is None or live["sha256"] not in (record["old_config"], record["new_config"]):
            _state_problem("Live configuration differs from both registered state recovery generations.")
        if nested:
            sync_directory(self.context.root)
            marker = self.recovery / "config-durability.json"
            marker.unlink()
            sync_directory(marker.parent)
        self._write(record, "SECURING")
        if live["sha256"] == record["old_config"]:
            original = self.config.get_config()
            if original["revision"] + 1 != cfg["revision"] or original["auth"]["auth_generation"] + 1 != cfg["auth"]["auth_generation"]:
                _state_problem("The candidate does not advance the current security counters.")
            self.config._commit(cfg)
        live = _fingerprint(self.config.config_path)
        if live["sha256"] != record["new_config"]:
            _state_problem("The secured configuration does not match its prepared bytes.")
        if parent:
            old = record["restore"]
            original = copy.deepcopy(parent)
            original.update(revision=old["revision"], auth_generation=old["auth_generation"])
            original["new_ids"]["config.json"] = old["config_id"]
            if hashlib.sha256(_state_json(original)).hexdigest() != old["digest"]:
                _state_problem("The parent restore journal changed during database recovery.")
            if (parent["revision"], parent["auth_generation"], parent["new_ids"]["config.json"]) not in (
                    (old["revision"], old["auth_generation"], old["config_id"]),
                    (cfg["revision"], cfg["auth"]["auth_generation"], live["file"])):
                _state_problem("The parent restore security transition has inconsistent evidence.")
            parent.update(revision=cfg["revision"], auth_generation=cfg["auth"]["auth_generation"])
            parent["new_ids"]["config.json"] = live["file"]
            atomic_write(self.recovery / old["id"] / "journal.json", _state_json(parent))
        if _fingerprint(self.store.path) != record["fresh"] or not _healthy_state(self.store.path):
            _state_problem("The reconstructed database failed final verification.")
        self._write(record, "FINALIZED")
        self._path(record, ".target-config").unlink(missing_ok=True)
        sync_directory(self.recovery)

    def run(self, *, apply):
        from core.storage import maintenance_lease
        # The config and stable signing key must predate state reconstruction.
        if not self.config.is_initialized():
            raise PocketError("not_initialized", "Initialize local credentials before repairing state.", 409)
        self.config.get_or_create_secret_key()
        record, parent, nested = self._journals()
        report = {"needed": bool(record) or not _healthy_state(self.store.path), "applied": False,
                  "reinitialized": _VOLATILE}
        if apply is not True or not report["needed"]:
            return report
        locks = self.context.paths["locks"]
        with maintenance_lease(self.context, exclusive=True), FileLock(locks / "operation.lock"), FileLock(self.config.config_lock), FileLock(locks / "state-init.lock"):
            record, parent, nested = self._journals()
            self.backups._check_offline()
            if record is None:
                if _healthy_state(self.store.path):
                    return dict(report, needed=False)
                record = self._prepare(parent)
            self._rebuild(record)
            self._secure(record, parent, nested)
            return dict(report, applied=True, revision=record["revision"], auth_generation=record["auth_generation"],
                        preserved={n: str(self._path(record, ".original-" + n))
                                   for n in _DB_MEMBERS if record["originals"][n] is not None},
                        restore_finalization_pending=parent is not None)
