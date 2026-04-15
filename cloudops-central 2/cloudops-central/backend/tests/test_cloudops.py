"""
CloudOps Central — Test Suite
Covers: config validation, security helpers, auth endpoints, admin endpoints,
        password strength, JWT claims, and audit logging.

Run:
    pip install pytest httpx pytest-asyncio
    pytest tests/ -v
"""
import os
import sys
import pytest
from datetime import timedelta

# ── Point to backend directory ────────────────────────────────────────────────
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# Use an isolated test DB and known credentials for all tests
os.environ["SECRET_KEY"] = "a" * 32
os.environ["ADMIN_PASSWORD"] = "AdminPass1234!"
os.environ["VIEWER_PASSWORD"] = "ViewerPass1234!"

from fastapi.testclient import TestClient


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest.fixture(scope="session")
def app():
    from main import app as _app
    return _app


@pytest.fixture(scope="session")
def client(app):
    return TestClient(app)


@pytest.fixture(scope="session")
def admin_token(client):
    resp = client.post(
        "/auth/token",
        data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture(scope="session")
def viewer_token(client):
    resp = client.post(
        "/auth/token",
        data={"username": "viewer", "password": os.environ["VIEWER_PASSWORD"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


@pytest.fixture
def auth_headers(admin_token):
    return {"Authorization": f"Bearer {admin_token}"}


@pytest.fixture
def viewer_headers(viewer_token):
    return {"Authorization": f"Bearer {viewer_token}"}


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG VALIDATION TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestConfigValidation:

    def test_missing_secret_key_raises(self):
        from core.config import Settings
        s = Settings(secret_key="", admin_password="AdminPass1234!", viewer_password="ViewerPass1234!")
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            s.validate_secret_key()

    def test_placeholder_secret_key_raises(self):
        from core.config import Settings
        s = Settings(
            secret_key="your-secret-key-here-generate-with-python",
            admin_password="AdminPass1234!",
            viewer_password="ViewerPass1234!",
        )
        with pytest.raises(RuntimeError, match="SECRET_KEY"):
            s.validate_secret_key()

    def test_short_secret_key_raises(self):
        from core.config import Settings
        s = Settings(secret_key="tooshort", admin_password="AdminPass1234!", viewer_password="ViewerPass1234!")
        with pytest.raises(RuntimeError, match="32 characters"):
            s.validate_secret_key()

    def test_valid_secret_key_passes(self):
        from core.config import Settings
        s = Settings(secret_key="a" * 32, admin_password="AdminPass1234!", viewer_password="ViewerPass1234!")
        s.validate_secret_key()  # should not raise

    def test_missing_admin_password_raises(self):
        from core.config import Settings
        s = Settings(secret_key="a" * 32, admin_password="", viewer_password="ViewerPass1234!")
        with pytest.raises(RuntimeError, match="ADMIN_PASSWORD"):
            s.validate_default_passwords()

    def test_short_admin_password_raises(self):
        from core.config import Settings
        s = Settings(secret_key="a" * 32, admin_password="Short1!", viewer_password="ViewerPass1234!")
        with pytest.raises(RuntimeError, match="12 characters"):
            s.validate_default_passwords()

    def test_origins_list_parsed_correctly(self):
        from core.config import Settings
        s = Settings(
            secret_key="a" * 32,
            admin_password="AdminPass1234!",
            viewer_password="ViewerPass1234!",
            allowed_origins="http://localhost:3000, http://localhost:8001 , ",
        )
        assert s.origins_list == ["http://localhost:3000", "http://localhost:8001"]


# ══════════════════════════════════════════════════════════════════════════════
# PASSWORD STRENGTH TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestPasswordStrength:

    def test_too_short_raises(self):
        from core.security import validate_password_strength
        with pytest.raises(ValueError, match="12 characters"):
            validate_password_strength("Short1!")

    def test_no_uppercase_raises(self):
        from core.security import validate_password_strength
        with pytest.raises(ValueError, match="uppercase"):
            validate_password_strength("alllowercase123!")

    def test_no_digit_raises(self):
        from core.security import validate_password_strength
        with pytest.raises(ValueError, match="digit"):
            validate_password_strength("NoDigitsHereAtAll!")

    def test_valid_password_passes(self):
        from core.security import validate_password_strength
        validate_password_strength("ValidPass123!")  # should not raise

    def test_minimum_length_boundary(self):
        from core.security import validate_password_strength
        validate_password_strength("A" + "a" * 10 + "1")  # exactly 12 chars


# ══════════════════════════════════════════════════════════════════════════════
# SECURITY / JWT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestJWT:

    def test_token_contains_required_claims(self):
        import jwt as pyjwt
        from core.security import create_access_token
        token = create_access_token({"sub": "testuser"})
        payload = pyjwt.decode(token, "a" * 32, algorithms=["HS256"])
        assert payload["sub"] == "testuser"
        assert payload["typ"] == "access"
        assert "exp" in payload
        assert "iat" in payload
        assert "jti" in payload

    def test_token_jti_is_unique(self):
        import jwt as pyjwt
        from core.security import create_access_token
        t1 = create_access_token({"sub": "user"})
        t2 = create_access_token({"sub": "user"})
        p1 = pyjwt.decode(t1, "a" * 32, algorithms=["HS256"])
        p2 = pyjwt.decode(t2, "a" * 32, algorithms=["HS256"])
        assert p1["jti"] != p2["jti"]

    def test_expired_token_rejected(self, client):
        from core.security import create_access_token
        token = create_access_token({"sub": "admin"}, expires_delta=timedelta(seconds=-1))
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    def test_tampered_token_rejected(self, client):
        resp = client.get("/auth/me", headers={"Authorization": "Bearer invalid.token.here"})
        assert resp.status_code == 401

    def test_missing_token_rejected(self, client):
        resp = client.get("/auth/me")
        assert resp.status_code == 401

    def test_hash_and_verify_password(self):
        from core.security import hash_password, verify_password
        hashed = hash_password("MySecurePass1!")
        assert verify_password("MySecurePass1!", hashed)
        assert not verify_password("WrongPassword1!", hashed)

    def test_wrong_token_type_rejected(self, client):
        """A token with typ != 'access' must be rejected."""
        import jwt as pyjwt
        payload = {
            "sub": "admin",
            "typ": "refresh",   # wrong type
            "iat": 0,
            "exp": 9999999999,
        }
        token = pyjwt.encode(payload, "a" * 32, algorithm="HS256")
        resp = client.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
        assert resp.status_code == 401


# ══════════════════════════════════════════════════════════════════════════════
# AUTH ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAuthEndpoints:

    def test_login_success(self, client):
        resp = client.post(
            "/auth/token",
            data={"username": "admin", "password": os.environ["ADMIN_PASSWORD"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "admin"

    def test_login_wrong_password(self, client):
        resp = client.post(
            "/auth/token",
            data={"username": "admin", "password": "WrongPassword1!"},
        )
        assert resp.status_code == 401

    def test_login_nonexistent_user(self, client):
        resp = client.post(
            "/auth/token",
            data={"username": "ghost", "password": "SomePass1234!"},
        )
        assert resp.status_code == 401

    def test_get_me_returns_no_password(self, client, auth_headers):
        resp = client.get("/auth/me", headers=auth_headers)
        assert resp.status_code == 200
        data = resp.json()
        assert "hashed_password" not in data
        assert data["username"] == "admin"

    def test_update_profile_wrong_current_password(self, client, auth_headers):
        resp = client.put(
            "/auth/profile",
            json={"current_password": "WrongPass1!", "new_password": "NewValidPass1234!"},
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_update_profile_weak_new_password(self, client, auth_headers):
        resp = client.put(
            "/auth/profile",
            json={
                "current_password": os.environ["ADMIN_PASSWORD"],
                "new_password": "weak",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 400

    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"


# ══════════════════════════════════════════════════════════════════════════════
# ADMIN ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAdminEndpoints:

    def test_viewer_cannot_access_admin(self, client, viewer_headers):
        resp = client.get("/admin/users", headers=viewer_headers)
        assert resp.status_code == 403

    def test_unauthenticated_cannot_access_admin(self, client):
        resp = client.get("/admin/users")
        assert resp.status_code == 401

    def test_list_users_hides_passwords(self, client, auth_headers):
        resp = client.get("/admin/users", headers=auth_headers)
        assert resp.status_code == 200
        for user in resp.json()["users"]:
            assert "hashed_password" not in user

    def test_create_user_weak_password_rejected(self, client, auth_headers):
        resp = client.post(
            "/admin/users",
            json={
                "username": "testuser",
                "name": "Test User",
                "email": "test@example.com",
                "password": "weak",
                "role": "viewer",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_create_user_invalid_role_rejected(self, client, auth_headers):
        resp = client.post(
            "/admin/users",
            json={
                "username": "testuser2",
                "name": "Test User",
                "email": "test2@example.com",
                "password": "ValidPass1234!",
                "role": "superadmin",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_create_and_delete_user(self, client, auth_headers):
        resp = client.post(
            "/admin/users",
            json={
                "username": "tempuser",
                "name": "Temp User",
                "email": "temp@example.com",
                "password": "TempPass1234!",
                "role": "viewer",
                "send_welcome": False,
            },
            headers=auth_headers,
        )
        assert resp.status_code == 201

        # Duplicate should fail
        resp2 = client.post(
            "/admin/users",
            json={
                "username": "tempuser",
                "name": "Temp User",
                "email": "temp@example.com",
                "password": "TempPass1234!",
                "role": "viewer",
                "send_welcome": False,
            },
            headers=auth_headers,
        )
        assert resp2.status_code == 409

        # Delete
        resp3 = client.delete("/admin/users/tempuser", headers=auth_headers)
        assert resp3.status_code == 200

    def test_cannot_delete_own_account(self, client, auth_headers):
        resp = client.delete("/admin/users/admin", headers=auth_headers)
        assert resp.status_code == 400

    def test_admin_list_accounts_hides_credentials(self, client, auth_headers):
        resp = client.get("/admin/accounts", headers=auth_headers)
        assert resp.status_code == 200
        for acc in resp.json().get("accounts", []):
            assert "role_arn" not in acc
            assert "client_secret" not in acc
            assert "service_account_key" not in acc

    def test_onboard_account_invalid_id_rejected(self, client, auth_headers):
        resp = client.post(
            "/admin/accounts/onboard",
            json={
                "account_id": "ab",  # too short — must be 3-64 chars
                "name": "Test",
                "region": "us-east-1",
                "env": "DEV",
                "owner": "team",
                "services": ["EC2"],
                "provider": "aws",
                "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_onboard_account_invalid_provider_rejected(self, client, auth_headers):
        resp = client.post(
            "/admin/accounts/onboard",
            json={
                "account_id": "test-account",
                "name": "Test",
                "region": "us-east-1",
                "env": "DEV",
                "owner": "team",
                "services": ["EC2"],
                "provider": "oracle",  # invalid
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_onboard_account_invalid_env_rejected(self, client, auth_headers):
        resp = client.post(
            "/admin/accounts/onboard",
            json={
                "account_id": "test-account",
                "name": "Test",
                "region": "us-east-1",
                "env": "PRODUCTION",  # invalid — must be PROD
                "owner": "team",
                "services": ["EC2"],
                "provider": "aws",
                "role_arn": "arn:aws:iam::123456789012:role/TestRole",
            },
            headers=auth_headers,
        )
        assert resp.status_code == 422

    def test_audit_log_requires_admin(self, client, viewer_headers):
        resp = client.get("/admin/audit", headers=viewer_headers)
        assert resp.status_code == 403

    def test_audit_log_limit_validation(self, client, auth_headers):
        resp = client.get("/admin/audit?limit=9999", headers=auth_headers)
        assert resp.status_code == 400

    def test_smtp_password_not_returned(self, client, auth_headers):
        client.post(
            "/admin/smtp",
            json={
                "host": "smtp.example.com",
                "port": 587,
                "username": "user@example.com",
                "password": "smtp-secret",
                "from_email": "noreply@example.com",
            },
            headers=auth_headers,
        )
        resp = client.get("/admin/smtp", headers=auth_headers)
        assert resp.status_code == 200
        cfg = resp.json().get("config") or {}
        assert "password" not in cfg


# ══════════════════════════════════════════════════════════════════════════════
# ACCOUNTS ENDPOINT TESTS
# ══════════════════════════════════════════════════════════════════════════════

class TestAccountsEndpoints:

    def test_list_accounts_requires_auth(self, client):
        resp = client.get("/accounts")
        assert resp.status_code == 401

    def test_list_accounts_authenticated(self, client, auth_headers):
        resp = client.get("/accounts", headers=auth_headers)
        assert resp.status_code == 200
        assert "accounts" in resp.json()

    def test_get_nonexistent_account(self, client, auth_headers):
        resp = client.get("/accounts/nonexistent-account-xyz", headers=auth_headers)
        assert resp.status_code == 404

    def test_viewer_can_list_accounts(self, client, viewer_headers):
        resp = client.get("/accounts", headers=viewer_headers)
        assert resp.status_code == 200


# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

class TestSystemEndpoints:

    def test_health_check(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "ok"
        assert "timestamp" in body
        assert "version" in body

    def test_providers_endpoint(self, client):
        resp = client.get("/providers")
        assert resp.status_code == 200
        providers = {p["id"] for p in resp.json()["providers"]}
        assert providers == {"aws", "azure", "gcp"}
