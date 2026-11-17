"""Real owned loopback sockets exercise server admission, not phone behavior."""
import socket
import threading
import os
import platform

import pytest
from flask import Flask, request

from core.config import ConfigManager
from core.http_services import create_api_app, create_web_app
from core.runtime import RuntimeContext


def test_public_health_has_no_private_information(isolated_runtime, monkeypatch):
    monkeypatch.setenv("POCKETSERVER_RUN_ID", "one-owned-run")
    app = create_api_app(RuntimeContext(isolated_runtime, "mock"))
    response = app.test_client().get("/health")
    assert response.json == {"service": "api", "run_id": "one-owned-run"}
    assert "python" not in response.get_data(as_text=True).lower()


def test_public_static_blocks_dot_components_before_filesystem_access(isolated_runtime):
    app = create_web_app(RuntimeContext(isolated_runtime, "mock"))
    client = app.test_client()
    assert client.get("/.private/key").status_code == 403
    assert client.post("/").status_code == 405
    assert client.open("/", method="OPTIONS").status_code == 405
    assert not isolated_runtime.exists()


@pytest.fixture
def socket_server(monkeypatch):
    # Waitress asks platform.system at import. Python's Windows probe may
    # launch `ver`; retain the no-subprocess test guard and supply host metadata.
    monkeypatch.setattr(platform, "system", lambda: "Windows" if os.name == "nt" else "Linux")
    waitress = pytest.importorskip("waitress")
    app = Flask("bounded-test")

    @app.post("/body")
    def body():
        return {"length": len(request.get_data())}

    channels = {}
    server = waitress.create_server(app, host="127.0.0.1", port=0, map=channels,
                                    max_request_body_size=65536, max_request_header_size=16384,
                                    channel_request_lookahead=0, connection_limit=4, recv_bytes=8192,
                                    asyncore_loop_timeout=0.05, threads=2)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    try:
        yield server.effective_port
    finally:
        for channel in list(channels.values()):
            channel.close()
        server.task_dispatcher.shutdown()
        thread.join(timeout=3)
        assert not thread.is_alive()


def exchange(port, payload):
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        connection.sendall(payload)
        result = bytearray()
        while True:
            chunk = connection.recv(8192)
            if not chunk:
                break
            result.extend(chunk)
        return bytes(result)


def test_listener_rejects_oversized_declared_body_before_spooling(socket_server):
    result = exchange(socket_server, b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n")
    assert result.startswith(b"HTTP/1.1 413")


def test_listener_rejects_oversized_chunked_body(socket_server):
    payload = b"POST /body HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n10001\r\n" + b"x" * 65537 + b"\r\n0\r\n\r\n"
    assert exchange(socket_server, payload).startswith(b"HTTP/1.1 413")


def test_pipeline_cannot_bypass_each_request_body_limit(socket_server):
    first = b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 3\r\n\r\none"
    second = b"POST /body HTTP/1.1\r\nHost: localhost\r\nContent-Length: 65537\r\nConnection: close\r\n\r\n"
    result = exchange(socket_server, first + second)
    assert b"413" in result
