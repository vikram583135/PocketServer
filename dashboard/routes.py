"""Thin validated routes. Executable registration and restore remain local."""
from __future__ import annotations

import json
from pathlib import PurePosixPath

from flask import g, jsonify, request, send_file

from core.errors import PocketError


def body(allowed, required=()):
    if not request.is_json:
        raise PocketError("invalid_input", "Use a JSON object.", 400)
    raw = request.get_data(cache=True)
    if len(raw) > 65536:
        raise PocketError("too_large", "JSON request exceeds 64 KiB.", 413)

    def pairs(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    def invalid_constant(value):
        raise ValueError("nonfinite")
    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=invalid_constant)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PocketError("invalid_input", "Malformed JSON object.", 400) from exc
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise PocketError("invalid_input", "Missing or unexpected request fields.", 400)
    return value


def register_routes(app, service, auth):
    def success(data=None, status=200):
        return jsonify(ok=True, data={} if data is None else data, request_id=g.request_id), status

    def queued(action, target, payload=None):
        op = service.queue(action, target, payload, idempotency_key=request.headers.get("Idempotency-Key"))
        return success({"operation_id": op["id"], "operation": op}, 202)

    def recent():
        auth.load(required=True, recent=True)

    @app.get("/api/session")
    def session():
        data, cookie = auth.bootstrap()
        response, status = success(data)
        if cookie:
            auth.set_cookie(response, cookie)
        return response, status

    @app.post("/api/login")
    def login():
        data, cookie = auth.login(body({"password"}, {"password"})["password"])
        response, status = success(data)
        auth.set_cookie(response, cookie)
        return response, status

    @app.post("/api/logout")
    def logout():
        body(set())
        auth.logout()
        response, status = success()
        response.delete_cookie("pocketserver_session", path="/", httponly=True, samesite="Strict")
        return response, status

    @app.post("/api/reauth")
    def reauth():
        auth.reauthenticate(body({"password"}, {"password"})["password"])
        return success({"recent_auth_seconds": 300})

    @app.get("/api/status")
    def status():
        return success(service.status())

    @app.post("/api/services/<identifier>/<action>")
    def lifecycle(identifier, action):
        body(set())
        if identifier not in {"web", "api", "ssh"} or action not in {"start", "stop", "restart"}:
            raise PocketError("invalid_input", "This lifecycle action is not available through HTTP.", 400)
        return queued(action, identifier)

    @app.patch("/api/services/<identifier>/config")
    def configure(identifier):
        value = body({"port", "bind_address", "autostart", "config_revision"}, {"config_revision"})
        revision = value.pop("config_revision")
        if type(revision) is not int:
            raise PocketError("invalid_input", "An integer configuration revision is required.", 400)
        return success(service.configure_service(identifier, value, revision))

    @app.get("/api/operations/<identifier>")
    def operation(identifier):
        return success(service.operations.get(identifier))

    @app.get("/api/logs/<identifier>")
    def logs(identifier):
        try:
            count = int(request.args.get("lines", "100"))
        except ValueError as exc:
            raise PocketError("invalid_input", "Invalid line count.", 400) from exc
        return success({"text": service.supervisor.get_logs(identifier, lines=count)})

    @app.get("/api/files")
    def files():
        try:
            offset = int(request.args.get("offset", "0"))
        except ValueError as exc:
            raise PocketError("invalid_input", "Invalid listing offset.", 400) from exc
        return success(service.vault.list(request.args.get("path", ""), offset=offset))

    @app.post("/api/files/upload")
    def upload():
        if not request.mimetype == "multipart/form-data" or set(request.files) != {"file"} or len(request.files.getlist("file")) != 1 or len(request.form.getlist("path")) > 1 or set(request.form) - {"path"}:
            raise PocketError("invalid_input", "Upload exactly one file and an optional relative destination.", 400)
        uploaded = request.files["file"]
        destination = request.form.get("path") or uploaded.filename
        return success(service.vault.upload(destination, uploaded.stream), 201)

    @app.get("/api/files/download")
    def download_file():
        path = request.args.get("path", "")
        stream = service.vault.open_read(path)
        try:
            response = send_file(stream, download_name=PurePosixPath(path).name, as_attachment=True, mimetype="application/octet-stream", conditional=False)
        except Exception:
            stream.close()
            raise
        response.call_on_close(stream.close)
        return response

    @app.delete("/api/files")
    def delete_file():
        recent()
        return success(service.vault.delete(request.args.get("path", "")))

    @app.get("/api/git/repos")
    def repos():
        return success({"repos": service.ssh_git.list_repos()})

    @app.post("/api/git/repos")
    def create_repo():
        return success(service.ssh_git.create_repo(body({"name"}, {"name"})["name"]), 201)

    @app.get("/api/ssh/keys")
    def keys():
        return success({"keys": service.ssh_git.list_keys()})

    @app.post("/api/ssh/keys")
    def add_key():
        recent()
        if not service.ssh_git.list_keys():
            raise PocketError("local_enrollment_required", "Enroll the first SSH owner key using the local CLI.", 403)
        value = body({"key", "role", "repositories"}, {"key"})
        return success(service.ssh_git.add_key(value["key"], role=value.get("role", "owner"), repositories=value.get("repositories", [])), 201)

    @app.delete("/api/ssh/keys/<fingerprint>")
    def remove_key(fingerprint):
        recent()
        return success(service.ssh_git.remove_key(fingerprint))

    @app.post("/api/tunnel/start")
    def publish():
        recent()
        value = body({"target_service", "acknowledge_public"}, {"target_service", "acknowledge_public"})
        if value["target_service"] not in {"web", "api"} or value["acknowledge_public"] is not True:
            raise PocketError("invalid_input", "Select web or api and explicitly acknowledge public content.", 400)
        return queued("tunnel_start", value["target_service"], value)

    @app.post("/api/tunnel/stop")
    def revoke():
        body(set())
        return queued("tunnel_stop", "tunnel")

    @app.patch("/api/power-policy")
    def power():
        value = body({"wake_policy", "policy", "config_revision"})
        policy = value.get("wake_policy", value.get("policy"))
        if policy not in {"manual", "pocketserver-managed"}:
            raise PocketError("invalid_input", "Choose manual or pocketserver-managed wake policy.", 400)
        service.config.transaction(lambda cfg: cfg["power"].update(wake_policy=policy), expected_revision=value.get("config_revision"))
        return success({"wake_policy": policy, "config_revision": service.config.get_config()["revision"]})

    @app.get("/api/doctor")
    def doctor():
        from core.doctor import run_diagnostics
        return success(run_diagnostics(context=service.context, supervisor=service.supervisor))

    @app.get("/api/backups")
    def backups():
        return success({"backups": service.backups.list()})

    @app.post("/api/backups")
    def create_backup():
        value = body({"acknowledge_external_writers"}, {"acknowledge_external_writers"})
        if value["acknowledge_external_writers"] is not True:
            raise PocketError("invalid_input", "Confirm external writers are stopped before taking a consistent backup.", 400)
        return queued("backup", "backup", value)

    @app.get("/api/backups/<identifier>/download")
    def download_backup(identifier):
        recent()
        path = service.backups.download(identifier)
        return send_file(path, as_attachment=True, download_name=path.name, mimetype="application/octet-stream", conditional=False)

    @app.delete("/api/backups/<identifier>")
    def delete_backup(identifier):
        recent()
        return success(service.backups.delete(identifier))

    @app.get("/api/jobs")
    def jobs():
        return success({"jobs": service.jobs.list()})

    @app.post("/api/jobs/<identifier>/runs")
    def run_job(identifier):
        value = body({"parameters"})
        if value.get("parameters", {}) != {}:
            raise PocketError("invalid_input", "This release accepts only locally fixed job arguments.", 400)
        # Validate local registration before a queue entry is accepted.
        if identifier not in {job["id"] for job in service.jobs.list()}:
            raise PocketError("not_found", "No such locally registered job.", 404)
        return queued("job_run", identifier, value)

    @app.get("/api/job-runs/<identifier>")
    def job_run(identifier):
        try:
            return success(service.jobs.get_run(identifier))
        except PocketError as exc:
            if exc.code != "not_found":
                raise
            operation = service.operations.get(identifier)
            if operation["action"] != "job_run":
                raise PocketError("not_found", "No such job run.", 404)
            return success({"id": identifier, "job_id": operation["target"], "state": operation["phase"], "error": operation["error"]})

    @app.post("/api/job-runs/<identifier>/cancel")
    def cancel_job(identifier):
        body(set())
        try:
            queued_result = service.operations.cancel_queued_job(identifier)
        except PocketError as exc:
            if exc.code != "not_found":
                raise
            queued_result = None
        if queued_result:
            return success(queued_result)
        try:
            return success(service.jobs.cancel(identifier))
        except PocketError as exc:
            if exc.code != "not_found":
                raise
            op = service.operations.get(identifier)
            if op["action"] != "job_run":
                raise PocketError("not_found", "No such job run.", 404)
            return success({"id": identifier, "state": "cancellation_requested" if op["phase"] == "cancelling" else op["phase"]})
