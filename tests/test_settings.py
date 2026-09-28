import io
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

    def test_export_domains_csv(self):
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
            ("domain-a.com", "domain", "/test", 0, "[80, 443]"),
        )
        conn.execute(
            "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
            ("domain-b.com", "other", "", 1, "[8080]"),
        )
        conn.commit()
        conn.close()

        csv_text, count = pulsecheck_app.export_domains_csv()
        self.assertEqual(count, 2)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Domain,Match,URL path,Paused,Ports")
        self.assertIn('domain-a.com,domain,/test,0,"80, 443"', lines)
        self.assertIn("domain-b.com,other,,1,8080", lines)

    @patch("app.scan_domain")
    def test_import_domains_from_csv_success_and_skip_duplicates(self, mock_scan):
        # Seed an existing domain in the database
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
            ("existing.com", "existing", "", 0, "[80]"),
        )
        conn.commit()
        conn.close()

        csv_data = """Domain,Match,URL path,Paused,Ports
newsite.com,newsite,/api,0,"80, 443"
existing.com,existing,,0,80
pausedsite.com,pausedsite,,1,8080
bad site!!,bad,,0,80
"""
        summary = pulsecheck_app.import_domains_from_csv(csv_data)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["imported"], 2)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["invalid"], 1)
        self.assertIn("existing.com", summary["skipped_domains"])
        self.assertIn("newsite.com", summary["imported_domains"])
        self.assertIn("pausedsite.com", summary["imported_domains"])

        # Check newsite.com in DB
        domains = {d["name"]: d for d in pulsecheck_app.domain_list()}
        self.assertEqual(domains["newsite.com"]["match"], "newsite")
        self.assertEqual(domains["newsite.com"]["url_path"], "/api")
        self.assertFalse(domains["newsite.com"]["paused"])
        self.assertEqual(domains["newsite.com"]["ports"], [80, 443])

        # Check pausedsite.com in DB
        self.assertTrue(domains["pausedsite.com"]["paused"])
        self.assertEqual(domains["pausedsite.com"]["ports"], [8080])

    def test_export_route(self):
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
            ("test.org", "test", "", 0, "[443]"),
        )
        conn.commit()
        conn.close()

        response = self.client.get("/import/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=pulsecheck_domains.csv", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["X-Exported-Count"], "1")
        self.assertIn(b"Domain,Match,URL path,Paused,Ports", response.data)
        self.assertIn(b"test.org,test,,0,443", response.data)

    @patch("app.scan_domain")
    def test_import_route_csv_upload(self, mock_scan):
        csv_file_bytes = b"Domain,Match,URL path,Paused,Ports\nuploaded.com,uploaded,,0,80\n"
        data = {
            "csv_file": (io.BytesIO(csv_file_bytes), "domains.csv"),
        }
        response = self.client.post(
            "/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CSV Import complete: 1 imported, 0 skipped", response.data)

        domains = pulsecheck_app.domain_list()
        self.assertTrue(any(d["name"] == "uploaded.com" for d in domains))

    @patch("app.discover_ports")
    @patch("app.scan_domain")
    def test_update_domain_with_empty_ports_skips_scan_and_discovery(self, mock_scan, mock_discover):
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
            ("domain-to-edit.com", "domain", "", 0, "[80, 443]"),
        )
        domain_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Update domain with empty ports string
        pulsecheck_app.update_domain(domain_id, "domain-to-edit.com", "")

        mock_discover.assert_not_called()
        mock_scan.assert_not_called()

        domain = pulsecheck_app.get_domain_by_id(domain_id)
        self.assertEqual(domain["ports"], [])

    @patch("app.discover_ports")
    @patch("app.scan_domain")
    def test_import_domains_from_csv_no_ports_skips_scan_and_discovery(self, mock_scan, mock_discover):
        csv_data = """Domain,Match,URL path,Paused,Ports
noports.com,noports,,0,
"""
        summary = pulsecheck_app.import_domains_from_csv(csv_data)
        self.assertEqual(summary["imported"], 1)
        mock_discover.assert_not_called()
        mock_scan.assert_not_called()

        domain = {d["name"]: d for d in pulsecheck_app.domain_list()}["noports.com"]
        self.assertEqual(domain["ports"], [])

    def test_csv_import_progress_and_cancel(self):
        progress_events = []
        csv_data = """Domain,Match,URL path,Paused,Ports
site1.com,site1,,0,80
site2.com,site2,,0,80
site3.com,site3,,0,80
"""
        def track_progress(info):
            progress_events.append(info)

        # Cancel on record 2
        def cancel_on_second():
            return len(progress_events) >= 2

        with self.assertRaises(pulsecheck_app.ImportCancelled):
            pulsecheck_app.import_domains_from_csv(
                csv_data,
                progress_callback=track_progress,
                cancelled_check=cancel_on_second,
            )

        self.assertGreaterEqual(len(progress_events), 1)
        self.assertEqual(progress_events[0]["index"], 1)
        self.assertEqual(progress_events[0]["total"], 3)

    def test_start_csv_import_route(self):
        csv_bytes = b"Domain,Match,URL path,Paused,Ports\nasync.com,async,,0,80\n"
        response = self.client.post(
            "/import/csv/start",
            data={"csv_file": (io.BytesIO(csv_bytes), "test.csv")},
            content_type="multipart/form-data",
        )
        self.assertEqual(response.status_code, 200)
        json_data = response.get_json()
        self.assertIn("token", json_data)
        self.assertEqual(json_data["status"], "started")

    def test_logo_and_favicon_assets(self):
        static_dir = pulsecheck_app.BASE_DIR / "static"
        self.assertTrue((static_dir / "logo.png").exists(), "logo.png must exist in static/")
        self.assertTrue((static_dir / "favicon.ico").exists(), "favicon.ico must exist in static/")
        self.assertTrue((static_dir / "favicon-32x32.png").exists(), "favicon-32x32.png must exist in static/")
        self.assertTrue((static_dir / "favicon-16x16.png").exists(), "favicon-16x16.png must exist in static/")
        self.assertTrue((static_dir / "apple-touch-icon.png").exists(), "apple-touch-icon.png must exist in static/")

    def test_base_html_renders_logo_and_favicon(self):
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        data = response.data.decode("utf-8")
        self.assertIn('rel="icon" type="image/x-icon" href="/static/favicon.ico"', data)
        self.assertIn('rel="icon" type="image/png" sizes="32x32" href="/static/favicon-32x32.png"', data)
        self.assertIn('class="brand-logo"', data)
        self.assertIn('src="/static/logo.png"', data)
        self.assertIn('alt="PulseCheck Logo"', data)
        self.assertIn('PulseCheck</h1>', data)

    @patch("smtplib.SMTP")
    def test_send_email_includes_logo(self, mock_smtp_class):
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
            "dest@example.com", "Alert Subject", "Test alert text", settings=settings
        )
        self.assertTrue(success)
        mock_server.send_message.assert_called_once()
        sent_msg = mock_server.send_message.call_args[0][0]
        
        # Check that message contains plain text, HTML alternative, and embedded image
        parts = list(sent_msg.walk())
        content_types = [p.get_content_type() for p in parts]
        self.assertIn("text/plain", content_types)
        self.assertIn("text/html", content_types)
        self.assertIn("image/png", content_types)
        
        # Check that the image part has Content-ID <pulsecheck_logo>
        image_parts = [p for p in parts if p.get_content_type() == "image/png"]
        self.assertTrue(len(image_parts) >= 1)
        self.assertEqual(image_parts[0].get("Content-ID"), "<pulsecheck_logo>")


if __name__ == "__main__":
    unittest.main()

