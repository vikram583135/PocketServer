"""Strict configuration, local credentials, transactional writes and v2 migration."""

from __future__ import annotations

import copy
import datetime as dt
import getpass
import hashlib
import json
import os
import re
import secrets
import sys
import uuid
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from core.errors import PocketError
from core.locking import FileLock
from core.runtime import RuntimeContext, atomic_write, check_path, check_private, private_dir, read_private, sync_directory

SCHEMA_VERSION = 3
PBKDF2_ITERATIONS = 1_000_000
CONFIG_LIMIT = 256 * 1024
ALLOWED_SERVICES = {"web", "api", "ssh", "tunnel"}
VALID_BIND_ADDRESSES = {"127.0.0.1", "0.0.0.0"}
MIN_PORT, MAX_PORT = 1024, 65535
_HASH = re.compile(r"pbkdf2:sha256:([1-9][0-9]{0,7})\$[A-Za-z0-9]{1,64}\$[0-9a-f]{64}")


def get_runtime_paths():
    return RuntimeContext.discover().paths


def _now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_default_config():
    stamp = _now()
    services = {
        name: {"autostart": False, "bind_address": "127.0.0.1", "port": port}
        for name, port in (("web", 8080), ("api", 8081), ("ssh", 8022))
    }
    services["tunnel"] = {"autostart": False, "mode": "quick", "target_service": "web"}
    return {
        "schema_version": 3, "revision": 1,
        "dashboard": {"autostart": False, "port": 8888, "bind_address": "127.0.0.1",
                      "session_lifetime_hours": 8, "session_idle_minutes": 30,
                      "trusted_hosts": ["127.0.0.1", "localhost"], "trusted_origins": []},
        "services": services,
        "auth": {"password_hash": "", "csrf_enabled": True, "initialized": False,
                 "auth_generation": 1, "password_policy_verified": False},
        "files": {"max_upload_size_mb": 50},
        "jobs": {"concurrency": 1, "queue_limit": 10, "default_timeout_seconds": 60, "max_timeout_seconds": 3600},
        "logs": {"max_bytes": 1048576, "backup_count": 2, "total_bytes": 33554432},
        "backups": {"max_count": 5, "max_bytes": 1073741824},
        "operations": {"queue_limit": 16, "retention_count": 200, "retention_days": 7},
        "power": {"wake_policy": "manual"},
        "metadata": {"created_at": stamp, "updated_at": stamp},
    }


def _require(ok, field):
    if not ok:
        raise PocketError("invalid_config", f"Invalid configuration field {field}.")


def _shape(value, template, field):
    _require(type(value) is type(template), field)
    if isinstance(template, dict):
        _require(value.keys() == template.keys(), field)
        for key in template:
            _shape(value[key], template[key], f"{field}.{key}")


def _bounded(value, low, high, field):
    _require(type(value) is int and low <= value <= high, field)


def validate_config(cfg):
    _shape(cfg, get_default_config(), "config")
    _require(cfg["schema_version"] == SCHEMA_VERSION, "schema_version")
    _bounded(cfg["revision"], 1, 2**63 - 1, "revision")
    dash = cfg["dashboard"]
    _require(dash["bind_address"] == "127.0.0.1", "dashboard.bind_address")
    _bounded(dash["session_lifetime_hours"], 1, 24, "dashboard.session_lifetime_hours")
    _bounded(dash["session_idle_minutes"], 1, min(120, 60 * dash["session_lifetime_hours"]), "dashboard.session_idle_minutes")
    hosts = dash["trusted_hosts"]
    _require(0 < len(hosts) <= 2 and all(isinstance(h, str) and h in ("localhost", "127.0.0.1") for h in hosts)
             and len(set(hosts)) == len(hosts), "dashboard.trusted_hosts")
    origins = dash["trusted_origins"]
    _require(len(origins) <= 8 and all(isinstance(o, str) and re.fullmatch(
        r"https?://(?:localhost|127\.0\.0\.1)(?::[1-9][0-9]{0,4})?", o) and
        (o.rsplit(":", 1)[-1].isdigit() is False or int(o.rsplit(":", 1)[-1]) <= 65535) for o in origins)
        and len(set(origins)) == len(origins), "dashboard.trusted_origins")
    ports = set()
    for name, entry in [("dashboard", dash), *[(key, cfg["services"][key]) for key in ("web", "api", "ssh")]]:
        _bounded(entry["port"], MIN_PORT, MAX_PORT, f"{name}.port")
        _require(entry["port"] not in ports, f"{name}.port (duplicate listener port)")
        ports.add(entry["port"])
        _require(entry["bind_address"] in VALID_BIND_ADDRESSES, f"{name}.bind_address")
    tunnel = cfg["services"]["tunnel"]
    _require(not tunnel["autostart"] and tunnel["mode"] == "quick", "tunnel")
    _require(tunnel["target_service"] in ("web", "api"), "tunnel.target_service")
    auth = cfg["auth"]
    _require(auth["csrf_enabled"], "auth.csrf_enabled")
    _bounded(auth["auth_generation"], 1, 2**63 - 1, "auth.auth_generation")
    match = _HASH.fullmatch(auth["password_hash"])
    _require(not auth["password_hash"] or match and int(match.group(1)) <= 5_000_000, "auth.password_hash")
    _require(auth["initialized"] == bool(match), "auth.initialized")
    _require(not auth["password_policy_verified"] or auth["initialized"], "auth.password_policy_verified")
    bounds = {
        "files": {"max_upload_size_mb": (1, 1024)},
        "jobs": {"concurrency": (1, 1), "queue_limit": (1, 10), "default_timeout_seconds": (1, 3600),
                 "max_timeout_seconds": (1, 3600)},
        "logs": {"max_bytes": (1024, 2**26), "backup_count": (1, 16), "total_bytes": (1024, 2**30)},
        "backups": {"max_count": (1, 100), "max_bytes": (1024, 2**36)},
        "operations": {"queue_limit": (1, 16), "retention_count": (1, 200), "retention_days": (1, 7)},
    }
    for section, fields in bounds.items():
        for key, (low, high) in fields.items():
            _bounded(cfg[section][key], low, high, f"{section}.{key}")
    _require(cfg["jobs"]["default_timeout_seconds"] <= cfg["jobs"]["max_timeout_seconds"], "jobs.default_timeout_seconds")
    _require(cfg["logs"]["max_bytes"] <= cfg["logs"]["total_bytes"], "logs.total_bytes")
    _require(cfg["power"]["wake_policy"] in ("manual", "pocketserver-managed"), "power.wake_policy")
    for key, stamp in cfg["metadata"].items():
        try:
            valid = len(stamp) <= 40 and dt.datetime.fromisoformat(stamp).utcoffset() is not None
        except ValueError:
            valid = False
        _require(valid, f"metadata.{key}")


def _decode(data):
    def unique(pairs):
        obj = dict(pairs)
        _require(len(pairs) == len(obj), "(duplicate key)")
        return obj

    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: _require(False, "(non-finite number)"))
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PocketError("invalid_config", "Configuration cannot be decoded as strict JSON.") from exc


def _encode(value):
    return (json.dumps(value, allow_nan=False, indent=2) + "\n").encode("utf-8")


def validate_password(password):
    if type(password) is not str or not 12 <= len(password) <= 128:
        raise PocketError("invalid_password", "Use a password between 12 and 128 characters.")
    return password


def read_password(password_stdin=False):
    if password_stdin:
        line = sys.stdin.readline(131)
        password = line.removesuffix("\n").removesuffix("\r")
    else:
        if not sys.stdin.isatty():
            raise PocketError("invalid_password", "Use --password-stdin when there is no interactive terminal.")
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                password = getpass.getpass("Admin password: ")
                if password != getpass.getpass("Confirm admin password: "):
                    raise PocketError("invalid_password", "Passwords did not match.")
            except getpass.GetPassWarning as exc:
                raise PocketError("invalid_password", "A hidden terminal prompt is unavailable. Use --password-stdin.") from exc
    return validate_password(password)


def _hash(password):
    return generate_password_hash(validate_password(password), method=f"pbkdf2:sha256:{PBKDF2_ITERATIONS}")


class ConfigManager:
    def __init__(self, context=None, config_path=None, secret_path=None):
        # Preserve the original positional (config_path, secret_path) API.
        if context is not None and not isinstance(context, RuntimeContext):
            context, config_path, secret_path = None, context, config_path
        root = Path(config_path).parent if config_path is not None else None
        self.context = context or RuntimeContext.discover(root=root)
        self.config_path = Path(config_path) if config_path is not None else self.context.paths["config_file"]
        self.secret_path = Path(secret_path) if secret_path is not None else self.context.paths["secret_file"]
        for path in (self.config_path, self.secret_path):
            check_path(path)
            if path.parent != self.context.root:
                raise PocketError("unsafe_path", "Keep credentials and configuration in the private runtime root.")
        if self.config_path == self.secret_path:
            raise PocketError("unsafe_path", "Configuration and signing key require distinct files.")
        self.config_lock = self.context.paths["locks"] / "config.lock"

    def get_config(self):
        try:
            check_private(self.context.root, directory=True)
            data = _decode(read_private(self.config_path, CONFIG_LIMIT))
        except FileNotFoundError as exc:
            raise PocketError("not_initialized", "Run local initialization first.", 409) from exc
        if isinstance(data, dict) and "schema_version" not in data and "services" in data:
            raise PocketError("migration_required", "Review and apply the legacy configuration migration locally.", 409)
        validate_config(data)
        return data

    load = get_config

    def get(self, key, default=None):
        return self.get_config().get(key, default)

    def get_service(self, service_id):
        cfg = self.get_config()
        if service_id == "dashboard":
            return cfg["dashboard"]
        if service_id not in ALLOWED_SERVICES:
            raise PocketError("unknown_service", "Unknown managed service.", 404)
        return cfg["services"][service_id]

    def get_or_create_secret_key(self):
        try:
            check_private(self.context.root, directory=True)
            key = read_private(self.secret_path, 64)
        except (FileNotFoundError, PermissionError) as exc:
            raise PocketError("recovery_required", "The existing signing key is missing or unreadable.", 503) from exc
        if not re.fullmatch(rb"[0-9a-fA-F]{64}", key):
            raise PocketError("recovery_required", "The existing signing key is malformed.", 503)
        return key.decode("ascii")

    def is_initialized(self):
        check_path(self.config_path)
        return self.config_path.exists() and self.get_config()["auth"]["initialized"]

    def _commit(self, candidate):
        validate_config(candidate)
        payload = _encode(candidate)
        marker = self.context.paths["recovery"] / "config-durability.json"
        with FileLock(self.context.paths["locks"] / "config-write.lock"):
            original = read_private(self.config_path, CONFIG_LIMIT) if self.config_path.exists() else None
            record = {"kind": "config-durability", "phase": "PREPARED", "revision": candidate["revision"],
                      "original_sha256": hashlib.sha256(original).hexdigest() if original is not None else None,
                      "target_sha256": hashlib.sha256(payload).hexdigest()}
            atomic_write(marker, _encode(record))
            try:
                atomic_write(self.config_path, payload)
            except Exception:
                # If replacement occurred, leave the already durable journal
                # in place even when the filesystem can no longer accept writes.
                present = read_private(self.config_path, CONFIG_LIMIT) if self.config_path.exists() else None
                if present == original:
                    marker.unlink()
                    sync_directory(marker.parent)
                raise
            marker.unlink()
            sync_directory(marker.parent)

    def initialize(self, password):
        validate_password(password)
        self.context.check_recovery()
        self.context.initialize()
        with FileLock(self.config_lock):
            self.context.check_recovery()
            if self.config_path.exists():
                cfg = self.get_config()
                self.get_or_create_secret_key()
                return cfg
            if not self.secret_path.exists():
                atomic_write(self.secret_path, secrets.token_hex(32).encode("ascii"))
            self.get_or_create_secret_key()
            cfg = get_default_config()
            cfg["auth"].update(initialized=True, password_policy_verified=True, password_hash=_hash(password))
            self._commit(cfg)
            return cfg

    def _transaction(self, mutator, expected_revision, *, auth=False):
        from core.storage import maintenance_lease
        if not self.config_path.exists():
            raise PocketError("not_initialized", "Run local initialization first.", 409)
        with maintenance_lease(self.context), FileLock(self.config_lock):
            self.context.check_recovery()
            cfg = self.get_config()
            self.get_or_create_secret_key()
            if expected_revision is not None:
                _bounded(expected_revision, 1, 2**63 - 1, "expected_revision")
                if cfg["revision"] != expected_revision:
                    raise PocketError("conflict", "Configuration changed. Read the current revision and retry.", 409)
            updated = copy.deepcopy(cfg)
            mutator(updated)
            for name in ("revision", "schema_version", "metadata", *(("auth",) if not auth else ())):
                _require(updated.get(name) == cfg[name], name)
            updated["revision"] += 1
            updated["metadata"]["updated_at"] = _now()
            self._commit(updated)
            return updated

    def transaction(self, mutator, expected_revision=None):
        return self._transaction(mutator, expected_revision)

    def update_service(self, service_id, updates, expected_revision=None):
        if service_id not in ALLOWED_SERVICES | {"dashboard"}:
            raise PocketError("unknown_service", "Unknown managed service.", 404)
        if type(updates) is not dict:
            raise PocketError("invalid_config", "Service settings must be an object.")

        def apply(cfg):
            target = cfg["dashboard"] if service_id == "dashboard" else cfg["services"][service_id]
            target.update(updates)

        return self.transaction(apply, expected_revision)

    def set_admin_password(self, password):
        hashed = _hash(password)

        def change(cfg):
            auth = cfg["auth"]
            auth.update(password_hash=hashed, initialized=True, password_policy_verified=True)
            auth["auth_generation"] += 1

        return self._transaction(change, None, auth=True)

    def verify_password(self, password):
        if type(password) is not str or not 12 <= len(password) <= 128:
            return False
        self.context.check_recovery()
        cfg = self.get_config()
        auth = cfg["auth"]
        hashed = auth["password_hash"]
        if not auth["password_policy_verified"] or not check_password_hash(hashed, password):
            return False
        if int(_HASH.fullmatch(hashed).group(1)) < PBKDF2_ITERATIONS:
            try:
                replacement = _hash(password)
                self._transaction(lambda c: c["auth"].update(password_hash=replacement), cfg["revision"], auth=True)
            except PocketError as exc:
                if exc.code == "conflict":
                    return False
                raise
        return True

    def rotate_secret_key(self):
        """First revoke previous sessions, then replace the signing key."""
        from core.storage import maintenance_lease
        with maintenance_lease(self.context), FileLock(self.config_lock):
            self.context.check_recovery()
            cfg = self.get_config()
            cfg["auth"]["auth_generation"] += 1
            cfg["revision"] += 1
            cfg["metadata"]["updated_at"] = _now()
            self._commit(cfg)
            atomic_write(self.secret_path, secrets.token_hex(32).encode("ascii"))

    def _legacy_plan(self, original):
        old = _decode(original)
        _require(type(old) is dict and "schema_version" not in old, "legacy version")
        _require(set(old) == {"dashboard", "services", "auth", "metadata"}, "legacy sections")
        old_services = old["services"]
        _require(type(old_services) is dict and not (old_services.keys() - {
            "web", "api", "ssh", "tunnel", "files", "worker", "git"}), "legacy services")
        _require(all(type(old[k]) is dict for k in ("dashboard", "auth", "metadata")), "legacy sections")
        _require(type(old["metadata"].get("version")) is str and old["metadata"]["version"].startswith("2."),
                 "legacy application version")
        cfg = get_default_config()
        proposed = []
        for key in ("dashboard", "web", "api", "ssh", "tunnel", "files", "worker", "git"):
            entry = old["dashboard"] if key == "dashboard" else old_services.get(key, {})
            _require(type(entry) is dict, f"legacy {key}")
            enabled = entry.get("enabled", False)
            _require(type(enabled) is bool, f"legacy {key}.enabled")
            if enabled and key in ("dashboard", "web", "api", "ssh"):
                proposed.append(key)
            if key in ("dashboard", "web", "api", "ssh"):
                target = cfg["dashboard"] if key == "dashboard" else cfg["services"][key]
                if "port" in entry:
                    target["port"] = entry["port"]
                if key in ("web", "api") and "bind_address" in entry:
                    target["bind_address"] = entry["bind_address"]
            elif key == "files":
                cfg["files"]["max_upload_size_mb"] = entry.get("max_upload_size_mb", 50)
            elif key == "tunnel":
                cfg["services"]["tunnel"]["target_service"] = entry.get("target_service", "web")
        hashed = old["auth"].get("password_hash")
        _require(type(hashed) is str, "legacy auth.password_hash")
        cfg["auth"].update(initialized=bool(hashed), password_hash=hashed)
        if "created_at" in old["metadata"]:
            cfg["metadata"]["created_at"] = old["metadata"]["created_at"]
        validate_config(cfg)
        report = {"source_schema": 2, "target_schema": 3, "proposed_autostart": proposed,
                  "disabled": ["autostart", "tunnel publication", "dashboard login"],
                  "actions": ["Confirm all legacy processes are stopped before applying.",
                              "Set a new password locally, then explicitly enable desired services."],
                  "preserved": ["legacy configuration snapshot", "password hash", "user data"]}
        return cfg, report

    def _prepare_legacy_layout(self):
        # v2 created directories/config with the user's umask. Tighten only
        # known owned objects; never recursively chmod the owner's public data.
        for path in [self.context.root, *self.context.directories(), self.config_path, self.secret_path]:
            check_path(path)
            if not path.exists():
                continue
            directory = path not in (self.config_path, self.secret_path)
            check_private(path, directory=directory, legacy=True)
            if os.name == "posix":
                os.chmod(path, 0o700 if directory else 0o600)
        self.context.initialize()

    def migrate(self, apply=False, *, legacy_stopped=False):
        check_private(self.context.root, directory=True, legacy=True)
        original = read_private(self.config_path, CONFIG_LIMIT, legacy=True)
        cfg, report = self._legacy_plan(original)
        if not apply:
            return report
        if legacy_stopped is not True:
            raise PocketError("legacy_processes", "Confirm all legacy services are stopped, then retry.", 409)
        self._prepare_legacy_layout()
        with FileLock(self.context.paths["locks"] / "maintenance.lock"), FileLock(self.config_lock):
            self.context.check_recovery()
            if read_private(self.config_path, CONFIG_LIMIT) != original:
                raise PocketError("conflict", "Legacy configuration changed. Review migration again.", 409)
            markers = []
            for path in self.context.paths["pids"].iterdir():
                check_private(path, legacy=True)
                markers.append(path.name)
            if self.secret_path.exists():
                self.get_or_create_secret_key()
            elif cfg["auth"]["initialized"]:
                raise PocketError("recovery_required", "Restore the legacy signing key before migration.", 409)
            # Build the complete prepared journal before exposing it in recovery.
            ident = "migration-" + uuid.uuid4().hex
            prepared = self.context.paths["staging"] / ident
            prepared.mkdir(mode=0o700)
            atomic_write(prepared / "legacy-config.json", original)
            private_dir(prepared / "pids")
            live = self.context.paths["recovery"] / ident
            candidate = _encode(cfg)
            record = {"kind": "migration", "phase": "PREPARED", "version": 1,
                      "original_sha256": hashlib.sha256(original).hexdigest(),
                      "target_sha256": hashlib.sha256(candidate).hexdigest(), "markers": markers}
            atomic_write(prepared / "journal.json", _encode(record))
            os.rename(prepared, live)
            sync_directory(live.parent)
            try:
                for name in markers:
                    source = self.context.paths["pids"] / name
                    if os.name == "posix":
                        os.chmod(source, 0o600)
                    os.rename(source, live / "pids" / name)
                sync_directory(live / "pids")
                sync_directory(self.context.paths["pids"])
                if not self.secret_path.exists():
                    atomic_write(self.secret_path, secrets.token_hex(32).encode("ascii"))
                atomic_write(self.config_path, candidate)
                self.get_config()
                atomic_write(live / "journal.json", _encode(dict(record, phase="FINALIZED", result="migrated")))
            except Exception:
                self._rollback_migration(live, record)
                raise
            return dict(report, applied=True, snapshot=str(live / "legacy-config.json"))

    def _rollback_migration(self, directory, record):
        original = read_private(directory / "legacy-config.json", CONFIG_LIMIT)
        current = read_private(self.config_path, CONFIG_LIMIT)
        digest = hashlib.sha256(current).hexdigest()
        if (hashlib.sha256(original).hexdigest() != record.get("original_sha256")
                or digest not in (record.get("original_sha256"), record.get("target_sha256"))):
            raise PocketError("recovery_required", "Migration evidence differs from the stored checksums.", 503)
        markers = record.get("markers")
        if not isinstance(markers, list) or any(not isinstance(name, str) or name in ("", ".", "..")
            or Path(name).name != name or "/" in name or "\\" in name for name in markers):
            raise PocketError("recovery_required", "Invalid migration marker evidence.", 503)
        if current != original:
            atomic_write(self.config_path, original)
        for name in markers:
            saved = directory / "pids" / name
            active = self.context.paths["pids"] / name
            check_path(saved)
            check_path(active)
            if saved.exists() == active.exists():
                raise PocketError("recovery_required", "Migration marker evidence is inconsistent.", 503)
            if saved.exists():
                check_private(saved)
                os.rename(saved, active)
        sync_directory(directory / "pids")
        sync_directory(self.context.paths["pids"])
        atomic_write(directory / "journal.json", _encode(dict(record, phase="FINALIZED", result="rolled_back")))

    def recover(self):
        pending = self.context.pending_recovery()
        if not pending:
            return {"recovered": 0}
        with FileLock(self.context.paths["locks"] / "maintenance.lock"), FileLock(self.config_lock):
            pending = self.context.pending_recovery()
            for path in pending:
                if not path.is_file():
                    raise PocketError("recovery_required", "A recovery journal is missing. Preserve the recovery directory.", 503)
                record = _decode(read_private(path, CONFIG_LIMIT))
                if not isinstance(record, dict):
                    raise PocketError("recovery_required", "Invalid recovery journal.", 503)
                if (path.parent.parent == self.context.paths["recovery"] and path.name == "journal.json"
                        and record.get("kind") == "migration" and record.get("phase") == "PREPARED"):
                    self._rollback_migration(path.parent, record)
                elif path == self.context.paths["recovery"] / "config-durability.json" and record.get("kind") == "config-durability":
                    raw = read_private(self.config_path, CONFIG_LIMIT) if self.config_path.exists() else None
                    digest = hashlib.sha256(raw).hexdigest() if raw is not None else None
                    if record.get("phase") == "PREPARED":
                        if digest not in (record.get("original_sha256"), record.get("target_sha256")):
                            raise PocketError("recovery_required", "Configuration differs from both recorded versions.", 503)
                    elif record.get("phase") == "UNCERTAIN":
                        if self.get_config()["revision"] != record.get("revision"):
                            raise PocketError("recovery_required", "Committed revision differs from its recovery record.", 503)
                    else:
                        raise PocketError("recovery_required", "Unrecognized configuration recovery phase.", 503)
                    if raw is not None:
                        validate_config(_decode(raw))
                    self.get_or_create_secret_key()
                    sync_directory(self.context.root)
                    atomic_write(path, _encode(dict(record, phase="FINALIZED")))
                else:
                    raise PocketError("recovery_required", "This journal requires the matching restore or recovery procedure.", 503)
            return {"recovered": len(pending)}
