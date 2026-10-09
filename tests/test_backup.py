"""Unit tests for password-protected settings backup export, import, and encryption."""
from __future__ import annotations

import io
import json
import os
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import app as pulsecheck_app
from core.database import init_db, get_db_connection, get_settings, save_settings
from services.backup import (
    export_settings_encrypted,
    import_settings_encrypted,
    trigger_server_restart,
)


class TestSettingsBackup(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = os.path.join(self.temp_dir.name, "test_pulsecheck.db")
        pulsecheck_app.DB_PATH = self.db_path
        pulsecheck_app.app.config["TESTING"] = True
        self.client = pulsecheck_app.app.test_client()
        init_db()

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_export_requires_non_empty_password(self):
        with self.assertRaises(ValueError):
            export_settings_encrypted("")
        with self.assertRaises(ValueError):
            export_settings_encrypted("   ")

    def test_export_and_import_roundtrip_valid_password(self):
        # 1. Seed custom settings
        custom_data = {
            "smtp_host": "smtp.company.org",
            "smtp_port": "465",
            "smtp_username": "alert-user",
            "smtp_password": "super-secret-smtp-password!123",
            "proxy_host": "10.0.0.50",
            "proxy_port": "3128",
            "proxy_password": "proxy-pass-value",
            "remote_source_type": "ssh",
            "remote_source_host": "router.local",
            "known_manufacturer_domains": json.dumps({"custom": "custom.com"}),
        }
        save_settings(custom_data)

        # 2. Export encrypted backup
        password = "MasterPassphrase!456"
        backup_bytes = export_settings_encrypted(password)
        self.assertTrue(len(backup_bytes) > 0)

        # Verify envelope structure
        envelope = json.loads(backup_bytes.decode("utf-8"))
        self.assertEqual(envelope.get("magic"), "PULSECHECK_BACKUP")
        self.assertIn("salt", envelope)
        self.assertIn("nonce", envelope)
        self.assertIn("ciphertext", envelope)

        # Ensure plaintext password is NOT in the envelope
        self.assertNotIn("super-secret-smtp-password!123", backup_bytes.decode("utf-8"))

        # 3. Wipe settings table to simulate restoration on fresh instance
        conn = get_db_connection()
        conn.execute("DELETE FROM settings")
        conn.commit()
        conn.close()

        # Check that settings are reset / empty
        wiped = get_settings()
        self.assertEqual(wiped.get("smtp_host"), "")

        # 4. Import using the correct passphrase
        success, msg, count = import_settings_encrypted(backup_bytes, password)
        self.assertTrue(success)
        self.assertTrue(count >= len(custom_data))

        # 5. Verify restored settings match original values
        restored = get_settings()
        self.assertEqual(restored.get("smtp_host"), "smtp.company.org")
        self.assertEqual(restored.get("smtp_port"), "465")
        self.assertEqual(restored.get("smtp_username"), "alert-user")
        self.assertEqual(restored.get("smtp_password"), "super-secret-smtp-password!123")
        self.assertEqual(restored.get("proxy_host"), "10.0.0.50")
        self.assertEqual(restored.get("proxy_password"), "proxy-pass-value")
        self.assertEqual(restored.get("remote_source_host"), "router.local")
        self.assertEqual(restored.get("known_manufacturer_domains"), json.dumps({"custom": "custom.com"}))

    def test_import_with_wrong_password_fails_and_keeps_existing_data(self):
        save_settings({"smtp_host": "original.example.com"})
        backup_bytes = export_settings_encrypted("CorrectPassword")

        # Mutate local setting
        save_settings({"smtp_host": "modified.example.com"})

        # Try to import with wrong password
        success, msg, count = import_settings_encrypted(backup_bytes, "WrongPassword")
        self.assertFalse(success)
        self.assertIn("Incorrect password", msg)
        self.assertEqual(count, 0)

        # Verify database remained unchanged
        current = get_settings()
        self.assertEqual(current.get("smtp_host"), "modified.example.com")

    def test_import_corrupted_payload_fails_cleanly(self):
        success, msg, count = import_settings_encrypted(b"not-json-content", "any-password")
        self.assertFalse(success)
        self.assertIn("Invalid file format", msg)

        # Valid JSON but missing magic
        bad_json = json.dumps({"foo": "bar"}).encode("utf-8")
        success, msg, count = import_settings_encrypted(bad_json, "any-password")
        self.assertFalse(success)
        self.assertIn("Unrecognized backup file", msg)

    def test_api_backup_export_endpoint(self):
        # 1. Missing password returns 400
        res = self.client.post("/api/settings/backup/export", data={"password": ""})
        self.assertEqual(res.status_code, 400)
        self.assertIn("Password is required", res.get_json()["error"])

        # 2. Valid password returns attachment
        res = self.client.post("/api/settings/backup/export", data={"password": "ExportPassKey123"})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/octet-stream")
        content_disp = res.headers.get("Content-Disposition", "")
        self.assertIn("attachment", content_disp)
        self.assertIn("pulsecheck-settings-", content_disp)
        self.assertIn(".pulsecheck-settings", content_disp)

        # Check payload validity
        data = res.get_data()
        envelope = json.loads(data.decode("utf-8"))
        self.assertEqual(envelope.get("magic"), "PULSECHECK_BACKUP")

    @patch("routes.settings.trigger_server_restart")
    def test_api_backup_import_endpoint(self, mock_restart):
        save_settings({"smtp_host": "export-source.net"})
        backup_bytes = export_settings_encrypted("SecretPass")

        # 1. Missing password
        res = self.client.post(
            "/api/settings/backup/import",
            data={"file": (io.BytesIO(backup_bytes), "test.pulsecheck-settings")},
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 400)

        # 2. Missing file
        res = self.client.post(
            "/api/settings/backup/import",
            data={"password": "SecretPass"},
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 400)

        # 3. Successful import
        res = self.client.post(
            "/api/settings/backup/import",
            data={
                "password": "SecretPass",
                "file": (io.BytesIO(backup_bytes), "pulsecheck-backup.pulsecheck-settings"),
            },
            content_type="multipart/form-data",
        )
        self.assertEqual(res.status_code, 200)
        json_data = res.get_json()
        self.assertTrue(json_data["success"])
        self.assertTrue(json_data["restarting"])
        mock_restart.assert_called_once_with(delay_seconds=1.0)


if __name__ == "__main__":
    unittest.main()
