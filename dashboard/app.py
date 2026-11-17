"""Loopback-only Flask application factory; no runtime initialization on import."""
from __future__ import annotations

import os
import secrets

from flask import Flask, g, jsonify, request, render_template
from werkzeug.exceptions import HTTPException

from core.application import Application
from core.errors import PocketError
from dashboard.auth import Authentication


def create_app(context=None, *, backend=None, application=None, testing=False):
    service = application or Application(context, backend=backend)
    service.context.ensure_mutable()
    service.config.get_or_create_secret_key()
    settings = service.config.get_config()
    app = Flask(__name__)
    app.config.update(TESTING=testing, MAX_CONTENT_LENGTH=(settings["files"]["max_upload_size_mb"] + 1) * 1024 * 1024,
                      MAX_FORM_MEMORY_SIZE=65536, MAX_FORM_PARTS=4, DEBUG=False)
    app.extensions["pocketserver"] = service
    app.config["POCKETSERVER_CONTEXT"] = service.context
    app.config["POCKETSERVER_SERVICE"] = "dashboard"
    auth = Authentication(service.config, service.context)
    app.extensions["pocketserver_auth"] = auth

    @app.before_request
    def protect():
        g.request_id = secrets.token_hex(12)
        auth.transport()
        if request.is_json and request.content_length is not None and request.content_length > 65536:
            raise PocketError("too_large", "JSON request exceeds 64 KiB.", 413)
        if request.path.startswith("/api/") and request.path != "/api/session":
            auth.load(required=request.path != "/api/login")
            if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
                auth.csrf()

    @app.after_request
    def secure_headers(response):
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Request-ID"] = getattr(g, "request_id", "")
        return response

    @app.errorhandler(PocketError)
    def expected_error(exc):
        return jsonify(ok=False, error={"code": exc.code, "message": exc.message}, request_id=getattr(g, "request_id", "")), exc.status

    @app.errorhandler(HTTPException)
    def http_error(exc):
        return jsonify(ok=False, error={"code": "http_error", "message": "Request rejected."}, request_id=getattr(g, "request_id", "")), exc.code

    @app.errorhandler(Exception)
    def unexpected_error(exc):
        # No traceback, body, credentials or raw exception reach the browser/log.
        app.logger.error("Request failed; diagnostic id=%s type=%s", getattr(g, "request_id", ""), type(exc).__name__)
        return jsonify(ok=False, error={"code": "internal_error", "message": "Request failed; use the diagnostic ID for local inspection."}, request_id=getattr(g, "request_id", "")), 500

    @app.get("/")
    def index():
        return render_template("index.html")

    @app.get("/healthz")
    def health():
        return jsonify(service="dashboard", run_id=os.environ.get("POCKETSERVER_RUN_ID", "foreground"))

    from dashboard.routes import register_routes
    register_routes(app, service, auth)
    return app
