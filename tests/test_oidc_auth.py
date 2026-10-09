from __future__ import annotations

import os
import unittest
from unittest.mock import patch, MagicMock
from pathlib import Path
import tempfile
import sqlite3

import app as pulsecheck_app
from core.database import (
    init_db,
    get_db_connection,
    get_authorized_users,
    get_authorized_user_by_id,
    get_authorized_user_by_identifier,
    is_user_authorized,
    add_authorized_user,
    update_authorized_user,
    delete_authorized_user,
    bootstrap_initial_admin,
    save_settings,
    get_settings,
)
from services.backup import (
    export_settings_encrypted,
    import_settings_encrypted,
)
from routes.auth import is_oidc_active, get_active_match_claim


class TestOidcAuthAndUserManagement(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_auth.db"
        self.orig_db_path = pulsecheck_app.DB_PATH

        pulsecheck_app.DB_PATH = self.db_path
        pulsecheck_app.app.config["TESTING"] = True
        pulsecheck_app.app.config["SECRET_KEY"] = "test-secret-key"
        self.client = pulsecheck_app.app.test_client()

        with patch("core.database.get_db_path", return_value=self.db_path):
            init_db()

    def tearDown(self):
        pulsecheck_app.DB_PATH = self.orig_db_path
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

    def test_database_user_crud(self):
        """Test creating, reading, updating, and deleting authorized users in SQLite."""
        with patch("core.database.get_db_path", return_value=self.db_path):
            # Initially empty
            users = get_authorized_users()
            self.assertEqual(len(users), 0)

            # Add user
            user_id = add_authorized_user("alice@example.com", "Alice Smith")
            self.assertIsInstance(user_id, int)
            self.assertTrue(is_user_authorized("alice@example.com"))
            self.assertTrue(is_user_authorized("ALICE@EXAMPLE.COM"))  # Case-insensitive
            self.assertFalse(is_user_authorized("bob@example.com"))

            # Duplicate should fail
            with self.assertRaises(sqlite3.IntegrityError):
                add_authorized_user("alice@example.com", "Duplicate")

            # Update user
            updated = update_authorized_user(user_id, "alice@work.org", "Alice Senior")
            self.assertTrue(updated)
            self.assertTrue(is_user_authorized("alice@work.org"))
            self.assertFalse(is_user_authorized("alice@example.com"))

            # Delete user
            deleted = delete_authorized_user(user_id)
            self.assertTrue(deleted)
            self.assertFalse(is_user_authorized("alice@work.org"))

    def test_initial_admin_bootstrap(self):
        """Test bootstrap_initial_admin seeds admin only if table is empty."""
        with patch("core.database.get_db_path", return_value=self.db_path):
            self.assertTrue(bootstrap_initial_admin("bootstrap_admin@example.com"))
            self.assertTrue(is_user_authorized("bootstrap_admin@example.com"))

            # Second call should return False since table is no longer empty
            self.assertFalse(bootstrap_initial_admin("another_admin@example.com"))
            self.assertFalse(is_user_authorized("another_admin@example.com"))

    def test_backup_and_restore_includes_authorized_users(self):
        """Verify that export_settings_encrypted and import_settings_encrypted preserve authorized_users."""
        with patch("core.database.get_db_path", return_value=self.db_path):
            add_authorized_user("user1@example.com", "User One")
            add_authorized_user("user2@example.com", "User Two")

            encrypted_pkg = export_settings_encrypted("secretpass123")
            self.assertIsInstance(encrypted_pkg, bytes)

            # Clear users table
            conn = get_db_connection()
            conn.execute("DELETE FROM authorized_users")
            conn.commit()
            conn.close()
            self.assertEqual(len(get_authorized_users()), 0)

            # Restore from encrypted backup (mocking trigger_server_restart)
            with patch("services.backup.trigger_server_restart"):
                success, msg, count = import_settings_encrypted(encrypted_pkg, "secretpass123")
                self.assertTrue(success)
                self.assertIn("authorized users", msg)

            restored_users = get_authorized_users()
            self.assertEqual(len(restored_users), 2)
            identifiers = {u["identifier"] for u in restored_users}
            self.assertEqual(identifiers, {"user1@example.com", "user2@example.com"})

    def test_routes_when_oidc_disabled(self):
        """When OIDC is disabled (default), all routes are publicly accessible without authentication."""
        with patch.dict(os.environ, {"PULSECHECK_OIDC_ENABLED": "false"}):
            with patch("core.database.get_db_path", return_value=self.db_path):
                # Public routes
                resp = self.client.get("/")
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/status", resp.headers["Location"])

                resp = self.client.get("/", follow_redirects=True)
                self.assertEqual(resp.status_code, 200)

                resp = self.client.get("/status")
                self.assertEqual(resp.status_code, 200)

                # Protected routes should NOT redirect to login when OIDC is disabled
                resp = self.client.get("/services")
                self.assertEqual(resp.status_code, 200)

                resp = self.client.get("/settings")
                self.assertEqual(resp.status_code, 200)

                resp = self.client.get("/import")
                self.assertEqual(resp.status_code, 200)

    def test_protected_routes_redirect_to_login_when_oidc_enabled(self):
        """When OIDC is enabled, unauthenticated visits to protected routes redirect to /auth/login."""
        with patch.dict(os.environ, {"PULSECHECK_OIDC_ENABLED": "true"}):
            with patch("core.database.get_db_path", return_value=self.db_path):
                # /status remains public!
                resp = self.client.get("/status")
                self.assertEqual(resp.status_code, 200)

                # /services redirects to /auth/login
                resp = self.client.get("/services")
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/auth/login", resp.headers["Location"])

                # /settings redirects to /auth/login
                resp = self.client.get("/settings")
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/auth/login", resp.headers["Location"])

                # /import redirects to /auth/login
                resp = self.client.get("/import")
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/auth/login", resp.headers["Location"])

    def test_authorized_session_allows_protected_routes(self):
        """When authenticated with an authorized identifier in DB, protected routes respond 200."""
        with patch.dict(os.environ, {"PULSECHECK_OIDC_ENABLED": "true"}):
            with patch("core.database.get_db_path", return_value=self.db_path):
                add_authorized_user("admin@pulsecheck.local", "Pulse Admin")

                with self.client.session_transaction() as sess:
                    sess["user"] = {
                        "identifier": "admin@pulsecheck.local",
                        "name": "Pulse Admin",
                        "claim": "email",
                    }

                resp = self.client.get("/services")
                self.assertEqual(resp.status_code, 200)

                resp = self.client.get("/settings")
                self.assertEqual(resp.status_code, 200)

    def test_revoked_session_redirects_to_login(self):
        """If user is deleted from authorized_users, subsequent requests are revoked and redirected."""
        with patch.dict(os.environ, {"PULSECHECK_OIDC_ENABLED": "true"}):
            with patch("core.database.get_db_path", return_value=self.db_path):
                uid = add_authorized_user("revoked@pulsecheck.local", "To Be Revoked")

                with self.client.session_transaction() as sess:
                    sess["user"] = {
                        "identifier": "revoked@pulsecheck.local",
                        "name": "Revoked User",
                        "claim": "email",
                    }

                # Initially 200
                resp = self.client.get("/services")
                self.assertEqual(resp.status_code, 200)

                # Now delete user from DB
                delete_authorized_user(uid)

                # Next access redirects to /auth/login
                resp = self.client.get("/services")
                self.assertEqual(resp.status_code, 302)
                self.assertIn("/auth/login", resp.headers["Location"])

    def test_settings_user_api_crud(self):
        """Test Settings API endpoints /api/settings/users/*."""
        with patch.dict(os.environ, {"PULSECHECK_OIDC_ENABLED": "false"}):
            with patch("core.database.get_db_path", return_value=self.db_path):
                # 1. Add user via API
                resp = self.client.post(
                    "/api/settings/users/add",
                    json={"identifier": "tester@example.com", "display_name": "API Tester"},
                )
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertTrue(data["success"])
                user_id = data["user"]["id"]

                # 2. List users
                resp = self.client.get("/api/settings/users")
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertEqual(len(data["users"]), 1)
                self.assertEqual(data["users"][0]["identifier"], "tester@example.com")

                # 3. Update user
                resp = self.client.post(
                    f"/api/settings/users/{user_id}/update",
                    json={"identifier": "tester2@example.com", "display_name": "Updated Tester"},
                )
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertTrue(data["success"])

                # 4. Delete user
                resp = self.client.post(f"/api/settings/users/{user_id}/delete")
                self.assertEqual(resp.status_code, 200)
                data = resp.get_json()
                self.assertTrue(data["success"])

                # Verify empty
                resp = self.client.get("/api/settings/users")
                data = resp.get_json()
                self.assertEqual(len(data["users"]), 0)


if __name__ == "__main__":
    unittest.main()
