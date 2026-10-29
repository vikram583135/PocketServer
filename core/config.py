"""PocketServer Configuration & Secrets Engine.

Deterministic JSON schema validation, atomic file persistence,
PBKDF2-SHA256 password hashing, and session secret generation.
"""

from __future__ import annotations

import copy
import datetime
import json
import os
import secrets
from pathlib import Path
from typing import Any, Dict, Optional

from werkzeug.security import check_password_hash, generate_password_hash

from core.env import ensure_runtime_dirs, get_runtime_paths

VALID_BIND_ADDRESSES = {"127.0.0.1", "0.0.0.0"}
ALLOWED_SERVICES = {"web", "api", "ssh", "git", "files", "worker", "tunnel"}
MIN_PORT = 1024
MAX_PORT = 65535


def get_default_config() -> Dict[str, Any]:
    """Generate a clean, secure default configuration."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    return {
        "dashboard": {
            "enabled": True,
            "port": 8888,
            "bind_address": "127.0.0.1",
            "session_lifetime_hours": 24,
        },
        "services": {
            "web": {
                "enabled": False,
                "port": 8080,
                "bind_address": "127.0.0.1",
            },
            "api": {
                "enabled": False,
                "port": 8081,
                "bind_address": "127.0.0.1",
            },
            "ssh": {
                "enabled": False,
                "port": 8022,
            },
            "git": {
                "enabled": False,
            },
            "files": {
                "enabled": True,
                "max_upload_size_mb": 50,
            },
            "worker": {
                "enabled": False,
            },
            "tunnel": {
                "enabled": False,
                "target_service": "web",
                "custom_domain": "",
                "token": "",
            },
        },
        "auth": {
            "password_hash": "",
            "csrf_enabled": True,
        },
        "metadata": {
            "version": "2.0.0",
            "created_at": now_iso,
            "updated_at": now_iso,
        },
    }


def validate_config(cfg: Dict[str, Any]) -> None:
    """Validate configuration schema, port boundaries, and security rules.

    Raises ValueError with descriptive context if configuration is malformed.
    """
    if not isinstance(cfg, dict):
        raise ValueError("Configuration root must be a dictionary.")

    # 1. Validate Dashboard Settings
    dash = cfg.get("dashboard")
    if not isinstance(dash, dict):
        raise ValueError("Missing or invalid 'dashboard' section.")

    dash_port = dash.get("port")
    if not isinstance(dash_port, int) or not (MIN_PORT <= dash_port <= MAX_PORT):
        raise ValueError(f"Dashboard port must be an integer between {MIN_PORT} and {MAX_PORT}, got: {dash_port}")

    dash_bind = dash.get("bind_address")
    if dash_bind not in VALID_BIND_ADDRESSES:
        raise ValueError(f"Dashboard bind_address must be one of {VALID_BIND_ADDRESSES}, got: {dash_bind}")

    session_hours = dash.get("session_lifetime_hours", 24)
    if not isinstance(session_hours, (int, float)) or session_hours <= 0:
        raise ValueError("Dashboard session_lifetime_hours must be a positive number.")

    # 2. Validate Services
    services = cfg.get("services")
    if not isinstance(services, dict):
        raise ValueError("Missing or invalid 'services' section.")

    for s_id, s_cfg in services.items():
        if s_id not in ALLOWED_SERVICES:
            raise ValueError(f"Unknown service '{s_id}'. Allowed services: {ALLOWED_SERVICES}")
        if not isinstance(s_cfg, dict):
            raise ValueError(f"Service configuration for '{s_id}' must be a dictionary.")

        # Port checks
        if "port" in s_cfg:
            port = s_cfg["port"]
            if not isinstance(port, int) or not (MIN_PORT <= port <= MAX_PORT):
                raise ValueError(f"Service '{s_id}' port must be between {MIN_PORT} and {MAX_PORT}, got: {port}")

        # Bind address checks
        if "bind_address" in s_cfg:
            bind_addr = s_cfg["bind_address"]
            if bind_addr not in VALID_BIND_ADDRESSES:
                raise ValueError(f"Service '{s_id}' bind_address must be one of {VALID_BIND_ADDRESSES}, got: {bind_addr}")

    # Specific tunnel validation
    tunnel_cfg = services.get("tunnel", {})
    target_service = tunnel_cfg.get("target_service", "web")
    if target_service not in {"web", "api"}:
        raise ValueError(f"Tunnel target_service must be 'web' or 'api', got: '{target_service}'")

    # Specific files validation
    files_cfg = services.get("files", {})
    max_upload = files_cfg.get("max_upload_size_mb", 50)
    if not isinstance(max_upload, (int, float)) or not (1 <= max_upload <= 1024):
        raise ValueError(f"files max_upload_size_mb must be between 1 and 1024 MB, got: {max_upload}")

    # 3. Validate Auth
    auth = cfg.get("auth")
    if not isinstance(auth, dict):
        raise ValueError("Missing or invalid 'auth' section.")
    if not isinstance(auth.get("password_hash", ""), str):
        raise ValueError("auth.password_hash must be a string.")


class ConfigManager:
    """Thread-safe and power-failure-resilient configuration manager."""

    def __init__(self, config_path: Optional[Path] = None, secret_path: Optional[Path] = None) -> None:
        ensure_runtime_dirs()
        paths = get_runtime_paths()
        self.config_path = config_path or paths["config_file"]
        self.secret_path = secret_path or paths["secret_file"]
        self._config: Optional[Dict[str, Any]] = None
        self.load()

    def load(self) -> Dict[str, Any]:
        """Load configuration from disk, creating default if missing."""
        if not self.config_path.exists():
            default_cfg = get_default_config()
            self._config = default_cfg
            self.save()
            return copy.deepcopy(self._config)

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            validate_config(data)
            self._config = data
            return copy.deepcopy(self._config)
        except Exception:
            # If config is corrupted, fall back to default but keep backup of corrupt file
            corrupt_backup = self.config_path.with_suffix(".corrupt.json")
            try:
                if self.config_path.exists():
                    os.replace(self.config_path, corrupt_backup)
            except Exception:
                pass
            self._config = get_default_config()
            self.save()
            return copy.deepcopy(self._config)

    def save(self) -> None:
        """Atomically persist configuration to disk (flush + fsync + os.replace)."""
        if self._config is None:
            self._config = get_default_config()

        validate_config(self._config)
        self._config["metadata"]["updated_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

        tmp_path = self.config_path.with_suffix(".tmp")
        self.config_path.parent.mkdir(parents=True, exist_ok=True)

        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(self._config, f, indent=2)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_path, self.config_path)

    def get_config(self) -> Dict[str, Any]:
        """Return a deep copy of the current configuration."""
        if self._config is None:
            self.load()
        return copy.deepcopy(self._config)  # type: ignore

    def get(self, key: str, default: Any = None) -> Any:
        """Get top-level config value."""
        if self._config is None:
            self.load()
        return self._config.get(key, default)  # type: ignore

    def get_service(self, service_id: str) -> Dict[str, Any]:
        """Get configuration dictionary for a specific service."""
        if self._config is None:
            self.load()
        services = self._config.get("services", {})  # type: ignore
        if service_id not in services:
            raise KeyError(f"Service '{service_id}' does not exist in configuration.")
        return copy.deepcopy(services[service_id])

    def update_service(self, service_id: str, updates: Dict[str, Any]) -> None:
        """Update specific parameters of a service and save atomically."""
        if self._config is None:
            self.load()
        services = self._config.setdefault("services", {})  # type: ignore
        if service_id not in ALLOWED_SERVICES:
            raise ValueError(f"Unknown service '{service_id}'. Allowed services: {ALLOWED_SERVICES}")

        target = services.setdefault(service_id, {})
        target.update(updates)
        self.save()

    def set_admin_password(self, plaintext_password: str) -> None:
        """Hash and persist the administrative password using PBKDF2-SHA256."""
        if not plaintext_password or not isinstance(plaintext_password, str):
            raise ValueError("Admin password must be a non-empty string.")
        if len(plaintext_password) < 4:
            raise ValueError("Admin password must be at least 4 characters long.")

        if self._config is None:
            self.load()

        hashed = generate_password_hash(plaintext_password, method="pbkdf2:sha256")
        self._config["auth"]["password_hash"] = hashed  # type: ignore
        self.save()

    def verify_password(self, plaintext_password: str) -> bool:
        """Verify candidate password against stored PBKDF2 hash."""
        if self._config is None:
            self.load()

        stored_hash = self._config.get("auth", {}).get("password_hash", "")  # type: ignore
        if not stored_hash:
            return False

        return check_password_hash(stored_hash, plaintext_password)

    def is_initialized(self) -> bool:
        """Check if administrative password has been configured."""
        if self._config is None:
            self.load()
        hash_val = self._config.get("auth", {}).get("password_hash", "")  # type: ignore
        return bool(hash_val and len(hash_val) > 0)

    def get_or_create_secret_key(self) -> str:
        """Get or generate a secure 32-byte hex secret key for session signing."""
        if self.secret_path.exists():
            try:
                key = self.secret_path.read_text(encoding="utf-8").strip()
                if len(key) >= 32:
                    return key
            except Exception:
                pass

        # Generate new 32-byte (64 hex char) cryptographic key
        new_key = secrets.token_hex(32)
        tmp_secret = self.secret_path.with_suffix(".tmp")
        self.secret_path.parent.mkdir(parents=True, exist_ok=True)

        with open(tmp_secret, "w", encoding="utf-8") as f:
            f.write(new_key)
            f.flush()
            os.fsync(f.fileno())

        os.replace(tmp_secret, self.secret_path)

        try:
            os.chmod(self.secret_path, 0o600)
        except OSError:
            pass

        return new_key

    def reset_to_default(self) -> None:
        """Reset configuration to initial clean defaults."""
        self._config = get_default_config()
        self.save()

