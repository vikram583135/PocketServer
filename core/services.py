"""Allowlisted managed services and trusted installed foreground commands."""
from __future__ import annotations
import http.client
import json
import os
import socket
import sys
from dataclasses import dataclass
from core.env import get_runtime_paths

@dataclass(frozen=True)
class ServiceProfile:
    service_id: str
    name: str
    default_port: int | None
    health_path: str | None = None

    @property
    def expected_bin(self):
        return "sshd" if self.service_id == "ssh" else "python"

    def command_builder(self, cfg, paths):
        return [sys.executable, "-m", "core.service_entry", self.service_id,
                "--root", str(paths["base"])]

    def health_checker(self, host, port):
        return check_http_endpoint(host, port, self.health_path or "/")

SERVICE_PROFILES = {
    "dashboard": ServiceProfile("dashboard", "PocketServer Dashboard", 8888, "/healthz"),
    "web": ServiceProfile("web", "Static Web Server", 8080, "/.well-known/pocketserver-health"),
    "api": ServiceProfile("api", "Micro API", 8081, "/health"),
    "ssh": ServiceProfile("ssh", "Dedicated OpenSSH", 8022),
    "tunnel": ServiceProfile("tunnel", "Explicit Quick Tunnel", None),
    "controller": ServiceProfile("controller", "Operation Controller", None),
}

def validate_service_id(service_id):
    if not isinstance(service_id, str) or service_id not in SERVICE_PROFILES:
        from core.runtime import PocketError
        raise PocketError("invalid_service", "Unknown managed service", status=400)
    return service_id

def service_config(cfg, service_id):
    validate_service_id(service_id)
    if service_id == "dashboard":
        return cfg["dashboard"]
    if service_id == "controller":
        return {"autostart": True}
    return cfg["services"][service_id]

def check_tcp_port(host, port, timeout=0.5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def check_http_endpoint(host, port, path="/", timeout=0.5, *, service_id=None, run_id=None):
    conn = http.client.HTTPConnection(host, port, timeout=timeout)
    try:
        conn.request("GET", path)
        response = conn.getresponse()
        if response.status != 200:
            return False
        data = json.loads(response.read(2049))
        return (isinstance(data, dict) and data.get("service") == service_id
                and isinstance(run_id, str) and data.get("run_id") == run_id)
    except (OSError, ValueError, http.client.HTTPException):
        return False
    finally:
        conn.close()

def seed_default_payloads(context=None):
    """Explicit initialization helper; never called by constructors/status."""
    from core.runtime import RuntimeContext
    context = context or RuntimeContext.discover()
    context.ensure_mutable()
    path = context.paths["www"] / "index.html"
    if not path.exists():
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as target:
            target.write("<!doctype html><meta charset=utf-8><title>PocketServer</title><h1>PocketServer</h1>")

def parse_tunnel_url_from_log(log_path):
    # Historical output cannot establish current publication identity.
    return None

