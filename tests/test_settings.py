import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import app as pulsecheck_app


class SettingsTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = pulsecheck_app.DB_PATH
        pulsecheck_app.DB_PATH = os.path.join(self.temp_dir.name, "pulsecheck.db")
        pulsecheck_app.init_db()
        self.client = pulsecheck_app.app.test_client()

    def tearDown(self):
        pulsecheck_app.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    def test_get_settings_defaults(self):
        settings = pulsecheck_app.get_settings()
        self.assertEqual(settings["smtp_host"], "")
        self.assertEqual(settings["smtp_port"], "587")
        self.assertEqual(settings["smtp_security"], "tls")
        self.assertEqual(settings["smtp_username"], "")
        self.assertEqual(settings["smtp_password"], "")
        self.assertEqual(settings["from_email"], "")
        self.assertEqual(settings["recipient_email"], "")

    def test_save_and_retrieve_settings(self):
        new_settings = {
            "smtp_host": "smtp.mailgun.org",
            "smtp_port": "587",
            "smtp_security": "tls",
            "smtp_username": "postmaster@example.com",
            "smtp_password": "secret-password-123",
            "from_email": "notifications@example.com",
            "recipient_email": "admin@example.com",
        }
        pulsecheck_app.save_settings(new_settings)
        loaded = pulsecheck_app.get_settings()
        for k, v in new_settings.items():
            self.assertEqual(loaded[k], v)

    def test_send_email_validation(self):
        success, msg = pulsecheck_app.send_email("to@example.com", "Test", "Body", settings={})
        self.assertFalse(success)
        self.assertIn("SMTP Host is not configured", msg)

        success, msg = pulsecheck_app.send_email("", "Test", "Body", settings={"smtp_host": "smtp.example.com", "from_email": "from@example.com"})
        self.assertFalse(success)
        self.assertIn("Destination email address is required", msg)

        success, msg = pulsecheck_app.send_email("to@example.com", "Test", "Body", settings={"smtp_host": "smtp.example.com", "from_email": ""})
        self.assertFalse(success)
        self.assertIn("Sender (From) email address is required", msg)

    @patch("smtplib.SMTP")
    def test_send_email_tls_success(self, mock_smtp_class):
        mock_server = MagicMock()
        mock_smtp_class.return_value.__enter__.return_value = mock_server

        settings = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "587",
            "smtp_security": "tls",
            "smtp_username": "user@example.com",
            "smtp_password": "secretpassword",
            "from_email": "from@example.com",
        }
        success, msg = pulsecheck_app.send_email(
            "dest@example.com", "Subject", "Body", settings=settings
        )
        self.assertTrue(success)
        self.assertIn("dest@example.com", msg)
        mock_smtp_class.assert_called_once_with("smtp.example.com", 587, timeout=10)
        mock_server.starttls.assert_called_once()
        mock_server.login.assert_called_once_with("user@example.com", "secretpassword")
        mock_server.send_message.assert_called_once()

    @patch("smtplib.SMTP_SSL")
    def test_send_email_ssl_success(self, mock_smtp_ssl_class):
        mock_server = MagicMock()
        mock_smtp_ssl_class.return_value.__enter__.return_value = mock_server

        settings = {
            "smtp_host": "smtp.example.com",
            "smtp_port": "465",
            "smtp_security": "ssl",
            "smtp_username": "user@example.com",
            "smtp_password": "secretpassword",
            "from_email": "from@example.com",
        }
        success, msg = pulsecheck_app.send_email(
            "dest@example.com", "Subject", "Body", settings=settings
        )
        self.assertTrue(success)
        mock_smtp_ssl_class.assert_called_once()
        mock_server.login.assert_called_once_with("user@example.com", "secretpassword")
        mock_server.send_message.assert_called_once()

    def test_settings_route_get(self):
        response = self.client.get("/settings")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"E-mail &amp; SMTP Settings", response.data)
        self.assertIn(b"STARTTLS", response.data)
        self.assertIn(b"Send Test Email", response.data)

    def test_settings_route_post_save(self):
        response = self.client.post(
            "/settings",
            data={
                "action": "save",
                "smtp_host": "mail.test.com",
                "smtp_port": "587",
                "smtp_security": "tls",
                "smtp_username": "testuser",
                "smtp_password": "testpassword",
                "from_email": "test@test.com",
                "recipient_email": "receiver@test.com",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Settings saved successfully.", response.data)
        saved = pulsecheck_app.get_settings()
        self.assertEqual(saved["smtp_host"], "mail.test.com")
        self.assertEqual(saved["recipient_email"], "receiver@test.com")

    def test_settings_route_preserves_password_when_empty_on_subsequent_save(self):
        # Save initially with password
        pulsecheck_app.save_settings({
            "smtp_host": "mail.test.com",
            "smtp_password": "super-secret-pass",
        })

        # Save again leaving password field blank
        self.client.post(
            "/settings",
            data={
                "action": "save",
                "smtp_host": "mail.newhost.com",
                "smtp_port": "587",
                "smtp_security": "tls",
                "smtp_username": "user",
                "smtp_password": "",
                "from_email": "from@test.com",
                "recipient_email": "to@test.com",
            },
            follow_redirects=True,
        )
        saved = pulsecheck_app.get_settings()
        self.assertEqual(saved["smtp_host"], "mail.newhost.com")
        self.assertEqual(saved["smtp_password"], "super-secret-pass")

    @patch("app.send_email")
    def test_settings_route_post_test_email(self, mock_send_email):
        mock_send_email.return_value = (True, "Test email sent successfully to receiver@test.com.")

        response = self.client.post(
            "/settings",
            data={
                "action": "test",
                "smtp_host": "mail.test.com",
                "smtp_port": "587",
                "smtp_security": "tls",
                "smtp_username": "testuser",
                "smtp_password": "testpassword",
                "from_email": "test@test.com",
                "recipient_email": "receiver@test.com",
            },
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Test email sent successfully to receiver@test.com.", response.data)
        mock_send_email.assert_called_once()

    def test_compute_overall_status(self):
        self.assertEqual(pulsecheck_app.compute_overall_status({}), "none")
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "online", 443: "online"}), "online")
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "offline", 443: "offline"}), "offline")
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "online", 443: "offline"}), "degraded")

    @patch("app.send_email")
    @patch("app.scan_domain")
    def test_check_all_domains_sends_notification_on_state_change(self, mock_scan, mock_send_email):
        mock_send_email.return_value = (True, "Sent")

        # Configure SMTP settings
        pulsecheck_app.save_settings({
            "smtp_host": "smtp.example.com",
            "from_email": "alerts@example.com",
            "recipient_email": "admin@example.com",
        })

        # Add domain and simulate previous check state: online
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, ?)",
            ("service.example", "service", "[80, 443]", 0),
        )
        domain_id = cur.lastrowid
        conn.execute(
            "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (domain_id, 80),
        )
        conn.execute(
            "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (domain_id, 443),
        )
        conn.commit()
        conn.close()

        # Simulate scan_domain changing port 80 to offline during scan
        def simulate_scan(d_id, name, ports, match, explicit_debug=None, url_path=""):
            conn_inner = pulsecheck_app.get_db_connection()
            conn_inner.execute(
                "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 0, 'offline', '2026-09-28 12:10:00 UTC')",
                (d_id, 80),
            )
            conn_inner.execute(
                "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:10:00 UTC')",
                (d_id, 443),
            )
            conn_inner.commit()
            conn_inner.close()

        mock_scan.side_effect = simulate_scan

        changes = pulsecheck_app.check_all_domains()

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["domain"], "service.example")
        self.assertEqual(changes[0]["old_status"], "online")
        self.assertEqual(changes[0]["new_status"], "degraded")
        self.assertIn("Port 80: ONLINE -> OFFLINE", changes[0]["port_changes"])

        # Verify email was dispatched
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args
        to_addr, subject, body = call_args[0][0], call_args[0][1], call_args[0][2]
        self.assertEqual(to_addr, "admin@example.com")
        self.assertIn("State Change Alert", subject)
        self.assertIn("service.example", body)
        self.assertIn("ONLINE -> DEGRADED", body)
        self.assertIn("Port 80: ONLINE -> OFFLINE", body)

    @patch("app.send_email")
    @patch("app.scan_domain")
    def test_check_all_domains_no_notification_when_no_change(self, mock_scan, mock_send_email):
        # Configure SMTP settings
        pulsecheck_app.save_settings({
            "smtp_host": "smtp.example.com",
            "from_email": "alerts@example.com",
            "recipient_email": "admin@example.com",
        })

        # Add domain with existing check state
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, ?)",
            ("stable.example", "stable", "[80]", 0),
        )
        domain_id = cur.lastrowid
        conn.execute(
            "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (domain_id, 80),
        )
        conn.commit()
        conn.close()

        # Simulate scan yielding the same state
        def simulate_scan(d_id, name, ports, match, explicit_debug=None, url_path=""):
            conn_inner = pulsecheck_app.get_db_connection()
            conn_inner.execute(
                "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:10:00 UTC')",
                (d_id, 80),
            )
            conn_inner.commit()
            conn_inner.close()

        mock_scan.side_effect = simulate_scan

        changes = pulsecheck_app.check_all_domains()

        self.assertEqual(changes, [])
        mock_send_email.assert_not_called()


if __name__ == "__main__":
    unittest.main()
