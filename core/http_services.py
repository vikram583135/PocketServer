"""Confined public payloads and the bounded, explicit WSGI deployment."""
from __future__ import annotations

import mimetypes
import os
from pathlib import PurePosixPath
import tempfile

from flask import Flask, jsonify, request, send_file

from core.config import ConfigManager
from core.errors import PocketError
from core.locking import FileLock
from core.runtime import private_dir
from core.state import ReservationStore
from core.storage import FileVault, validate_relative


def configure_listener(app, context, identifier):
    app.config["POCKETSERVER_CONTEXT"] = context
    app.config["POCKETSERVER_SERVICE"] = identifier
    return app


def _marker(identifier):
    return {"service": identifier, "run_id": os.environ.get("POCKETSERVER_RUN_ID", "foreground")}


def _public_factory(context, identifier):
    app = Flask(f"pocketserver_{identifier}", static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=65536, DEBUG=False)
    configure_listener(app, context, identifier)

    @app.after_request
    def headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.errorhandler(PocketError)
    def expected(exc):
        return jsonify(error={"code": exc.code, "message": exc.message}), exc.status
    return app


def create_web_app(context):
    app = _public_factory(context, "web")

    @app.get("/.well-known/pocketserver-health", provide_automatic_options=False)
    def health():
        return jsonify(_marker("web"))

    @app.route("/", defaults={"path": "index.html"}, methods=["GET", "HEAD"], provide_automatic_options=False)
    @app.route("/<path:path>", methods=["GET", "HEAD"], provide_automatic_options=False)
    def static_content(path):
        components = validate_relative(path).split("/")
        if any(part.startswith(".") or part in {"config.json", "secret.key", "state.sqlite3"} for part in components):
            raise PocketError("unsafe_path", "Private files are not public content.", 403)
        stream = FileVault(context, root=context.paths["www"]).open_read(path)
        try:
            response = send_file(stream, download_name=PurePosixPath(path).name,
                                 mimetype=mimetypes.guess_type(path)[0] or "application/octet-stream", conditional=False)
        except Exception:
            stream.close()
            raise
        response.call_on_close(stream.close)
        return response
    return app


def create_api_app(context):
    app = _public_factory(context, "api")

    @app.get("/health", provide_automatic_options=False)
    def health():
        return jsonify(_marker("api"))

    @app.get("/", provide_automatic_options=False)
    def index():
        return jsonify(message="PocketServer example API", endpoints=["/health"])
    return app


def listener_budget(identifier, config):
    if identifier == "dashboard":
        body_limit = (config["files"]["max_upload_size_mb"] + 1) * 1024 * 1024
        connections = 4
    else:
        body_limit, connections = 65536, 16
    # Per channel: body ceiling, one receive/pipeline chunk, parser/header space,
    # bounded output envelope and queue bookkeeping. Staging has its own lease.
    overhead = 2 * 1024 * 1024 + 65536
    # Multipart parsing may spool a second full body while Waitress retains
    # its buffered request. Reserve that separately before any request parsing.
    envelopes = 2 if identifier == "dashboard" else 1
    return body_limit, connections, connections * (envelopes * body_limit + overhead)


def serve_wsgi(app, bind, port):
    context = app.config.get("POCKETSERVER_CONTEXT")
    identifier = app.config.get("POCKETSERVER_SERVICE", "dashboard")
    if context is None:
        raise PocketError("invalid_config", "A listener requires an explicit runtime context.", 400)
    context.ensure_mutable()
    cfg = ConfigManager(context).get_config()
    if bind not in {"127.0.0.1", "0.0.0.0"} or identifier == "dashboard" and bind != "127.0.0.1":
        raise PocketError("invalid_config", "Administration must stay on loopback.", 400)
    try:
        from waitress import create_server
    except ImportError as exc:
        raise PocketError("unsupported", "Install the reviewed offline Waitress wheelhouse.", 503) from exc
    ceiling, connections, budget = listener_budget(identifier, cfg)
    # A foreground invocation cannot replace/release another live listener's
    # reservation, even if it fails to bind to the same endpoint.
    with FileLock(context.paths["locks"] / f"listener-{identifier}.lock", timeout=0):
        reservations = ReservationStore(context)
        owner = f"listener:{identifier}"
        reservations.reserve(owner, budget)
        old_tempdir = tempfile.tempdir
        server = None
        try:
            staging = context.paths["staging"] / f"http-{identifier}"
            private_dir(staging)
            tempfile.tempdir = str(staging)
            server = create_server(app, host=bind, port=port, ipv6=False,
                                   threads=4, connection_limit=connections, backlog=connections,
                                   channel_timeout=30, cleanup_interval=1, recv_bytes=8192,
                                   max_request_header_size=16384, max_request_body_size=ceiling,
                                   inbuf_overflow=65536, outbuf_overflow=65536,
                                   outbuf_high_watermark=1024 * 1024, channel_request_lookahead=0,
                                   expose_tracebacks=False, ident="PocketServer", trusted_proxy=None,
                                   clear_untrusted_proxy_headers=True)
            server.run()
        finally:
            try:
                if server is not None:
                    server.close()
                    server.task_dispatcher.shutdown()
            finally:
                tempfile.tempdir = old_tempdir
                reservations.release(owner)
