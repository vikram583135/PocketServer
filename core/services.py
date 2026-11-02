"""PocketServer Service Profiles & Seed Payloads.

Defines service profiles (Web, API, SSH, Git, Tunnel, Worker, Dashboard),
command builders, health check probes, and seeds default HTML/API payloads.
"""

from __future__ import annotations

import argparse
import http.client
import json
import os
import re
import socket
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from urllib.parse import urlparse

from core.env import ensure_runtime_dirs, get_runtime_paths, is_termux

# -----------------------------------------------------------------------------
# Default Payload Templates
# -----------------------------------------------------------------------------

DEFAULT_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>PocketServer — Static Web</title>
  <style>
    :root {
      --bg: #0d1117;
      --card-bg: #161b22;
      --text: #c9d1d9;
      --text-bright: #f0f6fc;
      --accent: #58a6ff;
      --accent-hover: #1f6feb;
      --border: #30363d;
      --green: #238636;
      --green-light: #3fb950;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      padding: 24px 16px;
      display: flex;
      justify-content: center;
      min-height: 100vh;
    }
    .container {
      width: 100%;
      max-width: 680px;
    }
    .badge {
      display: inline-block;
      padding: 4px 12px;
      background: rgba(63, 185, 80, 0.15);
      color: var(--green-light);
      border: 1px solid rgba(63, 185, 80, 0.4);
      border-radius: 999px;
      font-size: 0.82rem;
      font-weight: 600;
      margin-bottom: 16px;
    }
    h1 {
      color: var(--text-bright);
      font-size: 2rem;
      margin-bottom: 8px;
    }
    p.lead {
      font-size: 1.05rem;
      color: #8b949e;
      margin-bottom: 24px;
    }
    .card {
      background: var(--card-bg);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card h2 {
      color: var(--text-bright);
      font-size: 1.25rem;
      margin-bottom: 12px;
    }
    code {
      background: rgba(110, 118, 129, 0.2);
      padding: 2px 6px;
      border-radius: 4px;
      font-family: ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace;
      font-size: 0.9em;
      color: var(--accent);
    }
    ul { list-style: none; }
    li {
      padding: 8px 0;
      border-bottom: 1px solid var(--border);
      display: flex;
      justify-content: space-between;
    }
    li:last-child { border-bottom: none; }
    a.btn {
      display: inline-block;
      background: var(--green);
      color: #ffffff;
      padding: 10px 18px;
      border-radius: 6px;
      text-decoration: none;
      font-weight: 600;
      font-size: 0.95rem;
      margin-top: 8px;
      transition: background 0.15s ease;
    }
    a.btn:hover { background: #2ea043; }
    footer {
      text-align: center;
      color: #8b949e;
      font-size: 0.85rem;
      margin-top: 32px;
    }
  </style>
</head>
<body>
  <div class="container">
    <span class="badge">&#x25CF; Server Online</span>
    <h1>PocketServer</h1>
    <p class="lead">Portable micro-server node powered by Termux &amp; pure Python.</p>

    <div class="card">
      <h2>Static Web Hosting</h2>
      <p>This page is served from your local PocketServer static web root directory:</p>
      <p style="margin-top: 10px;"><code>~/.pocketserver/data/www/index.html</code></p>
      <p style="margin-top: 12px;">You can replace this file with any single-page app, blog, or static HTML/CSS/JS site.</p>
    </div>

    <div class="card">
      <h2>Active Endpoints</h2>
      <ul>
        <li><span>Static Web (this page)</span><code>:8080</code></li>
        <li><span>Micro JSON API</span><code>:8081</code></li>
        <li><span>Management Dashboard</span><code>:8888</code></li>
        <li><span>OpenSSH Server</span><code>:8022</code></li>
      </ul>
      <div style="margin-top: 16px;">
        <a class="btn" href="http://127.0.0.1:8888">Open PocketServer Dashboard &rarr;</a>
      </div>
    </div>

    <footer>
      PocketServer v2.0 &bull; Non-Root Android Micro-Server Engine
    </footer>
  </div>
</body>
</html>
"""

DEFAULT_API_SERVER_PY = """#!/usr/bin/env python3
\"\"\"PocketServer Micro Python API Server.

Pure standard-library HTTP server providing health checks, system telemetry,
and micro-service capabilities with zero external dependencies.
\"\"\"

import argparse
import datetime
import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

START_TIME = datetime.datetime.now(datetime.timezone.utc)

class PocketAPIHandler(BaseHTTPRequestHandler):
    server_version = "PocketServerAPI/2.0"

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        now = datetime.datetime.now(datetime.timezone.utc)
        uptime_seconds = int((now - START_TIME).total_seconds())

        if self.path in ("/", ""):
            self._send_json(200, {
                "service": "PocketServer Micro API",
                "status": "online",
                "version": "2.0.0",
                "uptime_seconds": uptime_seconds,
                "endpoints": [
                    "/",
                    "/health",
                    "/info"
                ]
            })
        elif self.path == "/health":
            self._send_json(200, {
                "status": "ok",
                "timestamp": now.isoformat(),
                "uptime_seconds": uptime_seconds,
                "pid": os.getpid()
            })
        elif self.path == "/info":
            self._send_json(200, {
                "service": "PocketServer Micro API",
                "version": "2.0.0",
                "python_version": sys.version.split()[0],
                "platform": sys.platform,
                "started_at": START_TIME.isoformat()
            })
        else:
            self._send_json(404, {
                "error": "Not Found",
                "path": self.path
            })

    def log_message(self, format, *args):
        # Bounded log formatting to stdout
        sys.stdout.write(f"[{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {self.address_string()} - {format % args}\\n")
        sys.stdout.flush()

def main():
    parser = argparse.ArgumentParser(description="PocketServer Micro API")
    parser.add_argument("--port", type=int, default=8081, help="Port to listen on")
    parser.add_argument("--bind", type=str, default="127.0.0.1", help="Address to bind")
    args = parser.parse_args()

    server_address = (args.bind, args.port)
    httpd = HTTPServer(server_address, PocketAPIHandler)
    print(f"PocketServer Micro API listening on http://{args.bind}:{args.port}")
    sys.stdout.flush()

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\\nShutting down PocketServer Micro API...")
    finally:
        httpd.server_close()

if __name__ == "__main__":
    main()
"""

# -----------------------------------------------------------------------------
# Payload Seeding Function
# -----------------------------------------------------------------------------

def seed_default_payloads() -> None:
    """Auto-seed default index.html and api/server.py if they do not exist."""
    ensure_runtime_dirs()
    paths = get_runtime_paths()

    index_file = paths["www"] / "index.html"
    if not index_file.exists():
        index_file.write_text(DEFAULT_INDEX_HTML, encoding="utf-8")

    api_file = paths["api"] / "server.py"
    if not api_file.exists():
        api_file.write_text(DEFAULT_API_SERVER_PY, encoding="utf-8")
        try:
            os.chmod(api_file, 0o755)
        except OSError:
            pass


# -----------------------------------------------------------------------------
# Health Check Implementations
# -----------------------------------------------------------------------------

def check_tcp_port(host: str, port: int, timeout: float = 1.5) -> bool:
    """Check if a TCP port is open and accepting connections."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_http_endpoint(host: str, port: int, path: str = "/", timeout: float = 2.0) -> bool:
    """Perform a lightweight HTTP GET request to verify service health."""
    try:
        conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.request("GET", path)
        resp = conn.getresponse()
        is_ok = 200 <= resp.status < 400
        conn.close()
        return is_ok
    except Exception:
        return False


# -----------------------------------------------------------------------------
# Service Profile Specifications
# -----------------------------------------------------------------------------

class ServiceProfile:
    """Represents a supervised service profile."""

    def __init__(
        self,
        service_id: str,
        name: str,
        default_port: Optional[int],
        expected_bin: str,
        command_builder: Callable[[Dict[str, Any], Dict[str, Path]], List[str]],
        health_checker: Callable[[str, int], bool],
    ) -> None:
        self.service_id = service_id
        self.name = name
        self.default_port = default_port
        self.expected_bin = expected_bin
        self.command_builder = command_builder
        self.health_checker = health_checker


def _build_web_command(cfg: Dict[str, Any], paths: Dict[str, Path]) -> List[str]:
    service_cfg = cfg.get("services", {}).get("web", {})
    port = service_cfg.get("port", 8080)
    bind_addr = service_cfg.get("bind_address", "127.0.0.1")
    return [
        sys.executable,
        "-m",
        "http.server",
        str(port),
        "--bind",
        str(bind_addr),
        "--directory",
        str(paths["www"]),
    ]


def _build_api_command(cfg: Dict[str, Any], paths: Dict[str, Path]) -> List[str]:
    service_cfg = cfg.get("services", {}).get("api", {})
    port = service_cfg.get("port", 8081)
    bind_addr = service_cfg.get("bind_address", "127.0.0.1")
    server_script = paths["api"] / "server.py"
    return [
        sys.executable,
        str(server_script),
        "--port",
        str(port),
        "--bind",
        str(bind_addr),
    ]


def _build_ssh_command(cfg: Dict[str, Any], paths: Dict[str, Path]) -> List[str]:
    service_cfg = cfg.get("services", {}).get("ssh", {})
    port = service_cfg.get("port", 8022)
    # Termux sshd binary runs in foreground with -D flag for supervisor process tracking
    sshd_bin = "sshd"
    prefix = os.environ.get("PREFIX", "")
    if prefix:
        candidate = Path(prefix) / "bin" / "sshd"
        if candidate.exists():
            sshd_bin = str(candidate)
    return [sshd_bin, "-D", "-p", str(port)]


def _build_tunnel_command(cfg: Dict[str, Any], paths: Dict[str, Path]) -> List[str]:
    tunnel_cfg = cfg.get("services", {}).get("tunnel", {})
    target_service = tunnel_cfg.get("target_service", "web")
    token = tunnel_cfg.get("token", "").strip()

    target_port = 8080
    if target_service == "api":
        target_port = cfg.get("services", {}).get("api", {}).get("port", 8081)
    else:
        target_port = cfg.get("services", {}).get("web", {}).get("port", 8080)

    cloudflared_bin = "cloudflared"
    prefix = os.environ.get("PREFIX", "")
    if prefix:
        candidate = Path(prefix) / "bin" / "cloudflared"
        if candidate.exists():
            cloudflared_bin = str(candidate)

    if token:
        return [cloudflared_bin, "tunnel", "run", "--token", token]
    return [
        cloudflared_bin,
        "tunnel",
        "--url",
        f"http://127.0.0.1:{target_port}",
    ]


def _build_dashboard_command(cfg: Dict[str, Any], paths: Dict[str, Path]) -> List[str]:
    dash_cfg = cfg.get("dashboard", {})
    port = dash_cfg.get("port", 8888)
    bind_addr = dash_cfg.get("bind_address", "127.0.0.1")
    # Will be launched via python -m dashboard.app
    return [
        sys.executable,
        "-m",
        "dashboard.app",
        "--port",
        str(port),
        "--bind",
        str(bind_addr),
    ]


SERVICE_PROFILES: Dict[str, ServiceProfile] = {
    "web": ServiceProfile(
        service_id="web",
        name="Static Web Server",
        default_port=8080,
        expected_bin="python",
        command_builder=_build_web_command,
        health_checker=lambda host, port: check_http_endpoint(host, port, path="/"),
    ),
    "api": ServiceProfile(
        service_id="api",
        name="Micro Python API",
        default_port=8081,
        expected_bin="python",
        command_builder=_build_api_command,
        health_checker=lambda host, port: check_http_endpoint(host, port, path="/health"),
    ),
    "ssh": ServiceProfile(
        service_id="ssh",
        name="OpenSSH Server",
        default_port=8022,
        expected_bin="sshd",
        command_builder=_build_ssh_command,
        health_checker=lambda host, port: check_tcp_port(host, port),
    ),
    "tunnel": ServiceProfile(
        service_id="tunnel",
        name="Cloudflare Tunnel",
        default_port=None,
        expected_bin="cloudflared",
        command_builder=_build_tunnel_command,
        health_checker=lambda host, port: True,  # Monitored via log output
    ),
    "dashboard": ServiceProfile(
        service_id="dashboard",
        name="PocketServer Dashboard",
        default_port=8888,
        expected_bin="python",
        command_builder=_build_dashboard_command,
        health_checker=lambda host, port: check_http_endpoint(host, port, path="/login"),
    ),
}


def parse_tunnel_url_from_log(log_path: Path) -> Optional[str]:
    """Parse quick tunnel URL (e.g. *.trycloudflare.com) from cloudflared logs."""
    if not log_path.exists():
        return None

    try:
        content = log_path.read_text(encoding="utf-8", errors="ignore")
        match = re.search(r"https://[a-zA-Z0-9-]+\.trycloudflare\.com", content)
        if match:
            return match.group(0)
    except Exception:
        pass
    return None

