"""Server-side expiring sessions, CSRF, same-origin policy and bounded login."""
from __future__ import annotations

import hashlib
import hmac
import secrets
import threading
import time
from urllib.parse import urlsplit

from flask import g, request

from core.errors import PocketError
from core.state import StateStore


COOKIE = "pocketserver_session"


class Authentication:
    def __init__(self, config, context):
        self.config = config
        self.context = context
        self.store = StateStore(context)
        self.hash_slots = threading.BoundedSemaphore(2)
        # The running listener keeps its endpoint until an explicit restart.
        # Persisted endpoint edits must not invalidate its existing Host policy.
        self.transport_settings = dict(config.get_config()["dashboard"])

    def _sign(self, identifier):
        key = self.config.get_or_create_secret_key().encode("ascii")
        return identifier + "." + hmac.new(key, identifier.encode("ascii"), hashlib.sha256).hexdigest()

    def _identifier(self):
        value = request.cookies.get(COOKIE, "")
        if len(value) > 200 or "." not in value:
            return None
        identifier, signature = value.rsplit(".", 1)
        if len(identifier) != 64 or not all(c in "0123456789abcdef" for c in identifier):
            return None
        if not hmac.compare_digest(value.encode("utf-8"), self._sign(identifier).encode("ascii")):
            return None
        return identifier

    def transport(self):
        """Host is checked before bootstrap, authentication, or request parsing."""
        settings = self.transport_settings
        port = settings["port"]
        hosts = set()
        for host in settings["trusted_hosts"]:
            hosts.add(host if ":" in host else f"{host}:{port}")
            if port == 80 and ":" not in host:
                hosts.add(host)
        if request.host.lower() not in {host.lower() for host in hosts}:
            raise PocketError("invalid_host", "Untrusted administration Host.", 403)
        if any(key.lower() == "forwarded" or key.lower().startswith("x-forwarded-") for key in request.headers.keys()):
            raise PocketError("invalid_origin", "Forwarded request headers are not supported.", 403)
        if request.method in {"POST", "PATCH", "PUT", "DELETE"}:
            expected = f"{request.scheme}://{request.host}".lower()
            allowed = {expected, *[v.lower() for v in settings["trusted_origins"]]}
            origin = request.headers.get("Origin")
            if origin is None:
                referer = request.headers.get("Referer", "")
                parsed = urlsplit(referer)
                origin = f"{parsed.scheme}://{parsed.netloc}" if parsed.scheme and parsed.netloc else ""
            if origin.lower() not in allowed:
                raise PocketError("invalid_origin", "A trusted same-origin request is required.", 403)

    def load(self, *, required=False, recent=False):
        settings = self.config.get_config()
        identifier = self._identifier()
        now = time.time()
        current = None
        if identifier:
            with self.store.connection(write=True) as db:
                row = db.execute("SELECT * FROM sessions WHERE id=?", (identifier,)).fetchone()
                if row:
                    idle = settings["dashboard"]["session_idle_minutes"] * 60 if row["authenticated"] else 300
                    if row["generation"] != settings["auth"]["auth_generation"] or row["expires"] <= now or row["touched"] + idle <= now:
                        db.execute("DELETE FROM sessions WHERE id=?", (identifier,))
                    else:
                        current = dict(row)
                        db.execute("UPDATE sessions SET touched=? WHERE id=?", (now, identifier))
        g.owner_session = current
        if required and (not current or not current["authenticated"]):
            raise PocketError("unauthorized", "Sign in to continue.", 401)
        if recent and (not current or current["reauth"] + 300 <= now):
            raise PocketError("reauth_required", "Confirm your password to continue.", 403)
        return current

    def csrf(self):
        current = getattr(g, "owner_session", None)
        token = request.headers.get("X-CSRF-Token", "")
        if not current or not isinstance(token, str) or not hmac.compare_digest(token.encode("utf-8"), current["csrf"].encode("ascii")):
            raise PocketError("csrf_failed", "Refresh the session and retry.", 403)

    def bootstrap(self):
        current = self.load()
        if current:
            return {"csrf_token": current["csrf"], "authenticated": bool(current["authenticated"])}, None
        current = self._new(False)
        return {"csrf_token": current["csrf"], "authenticated": False}, self._sign(current["id"])

    def _new(self, authenticated, old_id=None, generation=None):
        now = time.time()
        settings = self.config.get_config()
        if generation is not None and settings["auth"]["auth_generation"] != generation:
            raise PocketError("invalid_credentials", "Credentials changed; sign in again.", 401)
        identifier = secrets.token_hex(32)
        csrf = secrets.token_urlsafe(32)
        duration = settings["dashboard"]["session_lifetime_hours"] * 3600 if authenticated else 300
        with self.store.connection(write=True) as db:
            db.execute("DELETE FROM sessions WHERE generation!=?", (settings["auth"]["auth_generation"],))
            db.execute("DELETE FROM sessions WHERE expires<=? OR (authenticated=0 AND touched<?)", (now, now - 300))
            db.execute("DELETE FROM sessions WHERE authenticated=1 AND touched<?", (now - settings["dashboard"]["session_idle_minutes"] * 60,))
            if old_id:
                db.execute("DELETE FROM sessions WHERE id=?", (old_id,))
            count = db.execute("SELECT count(*) FROM sessions WHERE authenticated=?", (int(authenticated),)).fetchone()[0]
            if count >= (16 if authenticated else 128):
                raise PocketError("busy", "Session limit reached; retry after expiry.", 429)
            # Store the generation whose password was verified; if a password
            # changes concurrently this record is rejected on its next use.
            db.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?,?,?)", (identifier, csrf, int(authenticated), generation if generation is not None else settings["auth"]["auth_generation"], now, now, now + duration, now if authenticated else 0))
        return {"id": identifier, "csrf": csrf}

    def _password(self, password):
        before = self.config.get_config()["auth"]["auth_generation"]
        if not isinstance(password, str) or not 12 <= len(password) <= 128:
            raise PocketError("invalid_credentials", "Invalid credentials.", 401)
        reservation = self.store.rate_attempt(request.remote_addr or "unknown")
        if not self.hash_slots.acquire(blocking=False):
            raise PocketError("busy", "Authentication is busy; retry shortly.", 429)
        try:
            if not self.config.verify_password(password):
                raise PocketError("invalid_credentials", "Invalid credentials.", 401)
            if self.config.get_config()["auth"]["auth_generation"] != before:
                raise PocketError("invalid_credentials", "Credentials changed; sign in again.", 401)
        finally:
            self.hash_slots.release()
        self.store.rate_success(reservation)
        return before

    def login(self, password):
        current = getattr(g, "owner_session", None)
        generation = self._password(password)
        settings = self.config.get_config()
        if not settings["auth"]["password_policy_verified"]:
            raise PocketError("invalid_credentials", "Credentials require local recovery.", 401)
        new = self._new(True, current["id"] if current else None, generation=generation)
        return {"csrf_token": new["csrf"], "authenticated": True}, self._sign(new["id"])

    def logout(self):
        current = getattr(g, "owner_session", None)
        if current:
            with self.store.connection(write=True) as db:
                db.execute("DELETE FROM sessions WHERE id=?", (current["id"],))

    def reauthenticate(self, password):
        self._password(password)
        with self.store.connection(write=True) as db:
            db.execute("UPDATE sessions SET reauth=? WHERE id=?", (time.time(), g.owner_session["id"]))

    @staticmethod
    def set_cookie(response, value):
        response.set_cookie(COOKIE, value, httponly=True, samesite="Strict", secure=request.is_secure, path="/")
