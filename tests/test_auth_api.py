import pytest
from core.application import Application
from core.runtime import RuntimeContext
from core.supervisor import FakeBackend
from dashboard.app import create_app

ORIGIN = "http://localhost:8888"
PASSWORD = "correct horse battery"

@pytest.fixture
def web(isolated_runtime):
    application = Application(RuntimeContext(isolated_runtime, "mock"), backend=FakeBackend())
    application.initialize(PASSWORD)
    return create_app(application=application, testing=True).test_client(), application

def bootstrap(client):
    response = client.get("/api/session", base_url=ORIGIN)
    assert response.status_code == 200
    return response.json["data"]["csrf_token"]

def login(client):
    old = bootstrap(client)
    response = client.post("/api/login", base_url=ORIGIN, json={"password": PASSWORD}, headers={"Origin": ORIGIN, "X-CSRF-Token": old})
    assert response.status_code == 200
    assert response.json["data"]["csrf_token"] != old
    return response.json["data"]["csrf_token"]

@pytest.mark.parametrize("path", ["/api/status", "/api/files", "/api/git/repos", "/api/ssh/keys", "/api/logs/web", "/api/doctor", "/api/backups", "/api/jobs", "/api/operations/unknown"])
def test_protected_route_matrix(web, path):
    client, _ = web
    assert client.get(path, base_url=ORIGIN).status_code == 401

def test_host_forwarding_origin_and_csrf_matrix(web):
    client, _ = web
    assert client.get("/api/session", base_url="http://evil.example:8888").status_code == 403
    assert client.get("/api/session", base_url=ORIGIN, headers={"X-Forwarded-Host": "localhost:8888"}).status_code == 403
    token = bootstrap(client)
    assert client.post("/api/login", base_url=ORIGIN, json={"password": PASSWORD}, headers={"X-CSRF-Token": token}).status_code == 403
    assert client.post("/api/login", base_url=ORIGIN, json={"password": PASSWORD}, headers={"Origin": ORIGIN}).status_code == 403
    assert client.post("/api/login", base_url=ORIGIN, json={"password": PASSWORD}, headers={"Origin": "https://evil.example", "X-CSRF-Token": token}).status_code == 403

def test_session_rotation_logout_and_generation_revocation(web):
    client, application = web
    token = login(client)
    status = client.get("/api/status", base_url=ORIGIN)
    assert status.status_code == 200
    assert "password_hash" not in status.get_data(as_text=True)
    response = client.post("/api/logout", base_url=ORIGIN, json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": token})
    assert response.status_code == 200
    assert client.get("/api/status", base_url=ORIGIN).status_code == 401
    login(client)
    application.config.set_admin_password("new correct horse battery")
    assert client.get("/api/status", base_url=ORIGIN).status_code == 401

def test_login_rejects_duplicates_and_unknown_fields(web):
    client, _ = web
    token = bootstrap(client)
    headers = {"Origin": ORIGIN, "X-CSRF-Token": token, "Content-Type": "application/json"}
    assert client.post("/api/login", base_url=ORIGIN, data='{"password":"a","password":"b"}', headers=headers).status_code == 400
    assert client.post("/api/login", base_url=ORIGIN, json={"password": PASSWORD, "override": True}, headers=headers).status_code == 400

@pytest.mark.parametrize("target", ["dashboard", "controller", "all", "tunnel", "../web"])
def test_generic_lifecycle_cannot_bypass_publication_or_self_control(web, target):
    client, _ = web
    token = login(client)
    response = client.post(f"/api/services/{target}/start", base_url=ORIGIN, json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": token})
    assert response.status_code in {400, 404}

def test_cookie_security_and_public_health(web):
    client, _ = web
    response = client.get("/api/session", base_url=ORIGIN)
    cookie = response.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Domain=" not in cookie
    health = client.get("/healthz", base_url=ORIGIN)
    assert health.json["service"] == "dashboard"
    assert "frame-ancestors 'none'" in health.headers["Content-Security-Policy"]
    assert health.headers["Cache-Control"] == "no-store"


def test_endpoint_edit_preserves_current_listener_host_policy(web):
    client, application = web
    login(client)
    application.config.update_service("dashboard", {"port": 8899})
    assert client.get("/api/status", base_url=ORIGIN).status_code == 200
    assert client.get("/healthz", base_url="http://localhost:8899").status_code == 403


def test_reauth_expiry_is_enforced_before_publication(web):
    client, application = web
    token = login(client)
    from core.state import StateStore
    with StateStore(application.context).connection(write=True) as db:
        db.execute("UPDATE sessions SET reauth=0")
    response = client.post("/api/tunnel/start", base_url=ORIGIN, json={"target_service": "web", "acknowledge_public": True}, headers={"Origin": ORIGIN, "X-CSRF-Token": token})
    assert response.status_code == 403
    assert response.json["error"]["code"] == "reauth_required"


def test_doctor_route_uses_shared_observation_contract(web):
    client, _ = web
    login(client)
    response = client.get("/api/doctor", base_url=ORIGIN)
    assert response.status_code == 200
    assert response.json["data"]["checks"]


def test_nonascii_csrf_is_rejected_without_server_error(web):
    client, _ = web
    login(client)
    response = client.post("/api/logout", base_url=ORIGIN, json={}, headers={"Origin": ORIGIN, "X-CSRF-Token": "é"})
    assert response.status_code == 403
