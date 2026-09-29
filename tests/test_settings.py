import io
import os
from pathlib import Path
import sqlite3
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
        self.assertEqual(settings["proxy_host"], "")
        self.assertEqual(settings["proxy_port"], "8080")
        self.assertEqual(settings["proxy_username"], "")
        self.assertEqual(settings["proxy_password"], "")

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
            "INSERT INTO domains (name, match, url_path, comment, paused, ports) VALUES (?, ?, ?, ?, ?, ?)",
            ("domain-a.com", "domain", "/test", "Internal gateway", 0, "[80, 443]"),
        )
        conn.execute(
            "INSERT INTO domains (name, match, url_path, comment, paused, ports) VALUES (?, ?, ?, ?, ?, ?)",
            ("domain-b.com", "other", "", "", 1, "[8080]"),
        )
        conn.commit()
        conn.close()

        csv_text, count = pulsecheck_app.export_domains_csv()
        self.assertEqual(count, 2)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Domain,Match,URL path,Comment,Paused,Proxy,Ports")
        self.assertIn('domain-a.com,domain,/test,Internal gateway,0,0,"80, 443"', lines)
        self.assertIn("domain-b.com,other,,,1,0,8080", lines)

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
        self.assertIn(b"Domain,Match,URL path,Comment,Paused,Proxy,Ports", response.data)
        self.assertIn(b"test.org,test,,,0,0,443", response.data)

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

    def test_comment_schema_migration_preserves_existing_data(self):
        # Create a database with old schema (without comment column)
        temp_dir = tempfile.TemporaryDirectory()
        old_db_path = Path(temp_dir.name) / "old_pulsecheck.db"
        orig_db_path = pulsecheck_app.DB_PATH
        try:
            conn = sqlite3.connect(old_db_path)
            conn.execute(
                """
                CREATE TABLE domains (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    match TEXT NOT NULL DEFAULT '',
                    url_path TEXT NOT NULL DEFAULT '',
                    paused INTEGER NOT NULL DEFAULT 0,
                    ports TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, ?, ?)",
                ("legacy-site.org", "legacy", "/app", 0, "[80, 443]"),
            )
            conn.commit()
            conn.close()

            # Point app DB_PATH to this older database and run init_db()
            pulsecheck_app.DB_PATH = old_db_path
            pulsecheck_app.init_db()

            # Verify that comment column was added
            conn = sqlite3.connect(old_db_path)
            conn.row_factory = sqlite3.Row
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(domains)").fetchall()}
            self.assertIn("comment", cols)

            # Verify existing data is preserved intact
            row = conn.execute("SELECT * FROM domains WHERE name = ?", ("legacy-site.org",)).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row["name"], "legacy-site.org")
            self.assertEqual(row["match"], "legacy")
            self.assertEqual(row["url_path"], "/app")
            self.assertEqual(row["comment"], "")
            conn.close()
        finally:
            pulsecheck_app.DB_PATH = orig_db_path
            temp_dir.cleanup()

    def test_domain_comment_crud(self):
        with patch("app.scan_domain"):
            domain_id = pulsecheck_app.add_domain(
                "comment-test.com",
                comment="Primary internal API server",
            )
            self.assertIsNotNone(domain_id)

            domain = pulsecheck_app.get_domain_by_id(domain_id)
            self.assertEqual(domain["comment"], "Primary internal API server")

            # Update comment
            pulsecheck_app.update_domain(
                domain_id,
                "comment-test.com",
                ports_input="80, 443",
                comment="Updated secondary API server",
            )
            domain = pulsecheck_app.get_domain_by_id(domain_id)
            self.assertEqual(domain["comment"], "Updated secondary API server")

    def test_domain_comment_web_ui(self):
        with patch("app.scan_domain"):
            # Add domain via web POST
            resp = self.client.post(
                "/domains/add",
                data={
                    "name": "web-comment.org",
                    "match": "web",
                    "url_path": "",
                    "comment": "Customer billing system",
                },
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)

            # Check domain list page displays comment in tooltip and badge
            list_resp = self.client.get("/domains")
            self.assertEqual(list_resp.status_code, 200)
            html = list_resp.data.decode("utf-8")
            self.assertIn('class="domain-comment-badge"', html)
            self.assertIn('Customer billing system', html)
            self.assertIn('class="tooltip-bubble"', html)

            # Check edit page contains the comment
            domain = next(d for d in pulsecheck_app.domain_list() if d["name"] == "web-comment.org")
            edit_get = self.client.get(f"/domains/{domain['id']}/edit")
            self.assertEqual(edit_get.status_code, 200)
            self.assertIn('value="Customer billing system"', edit_get.data.decode("utf-8"))

            # Update comment via edit page POST
            edit_post = self.client.post(
                f"/domains/{domain['id']}/edit",
                data={
                    "name": "web-comment.org",
                    "match": "web",
                    "url_path": "",
                    "comment": "Modified billing system",
                    "ports": "80",
                },
                follow_redirects=True,
            )
            self.assertEqual(edit_post.status_code, 200)
            updated = pulsecheck_app.get_domain_by_id(domain["id"])
            self.assertEqual(updated["comment"], "Modified billing system")

    def test_csv_import_with_comment_column(self):
        with patch("app.scan_domain"):
            # Import CSV containing a Comment column
            csv_with_comment = "Domain,Match,URL path,Comment,Paused,Ports\nimported-comment.io,imported,,Cloud load balancer,0,80\n"
            summary = pulsecheck_app.import_domains_from_csv(csv_with_comment)
            self.assertEqual(summary["imported"], 1)

            domain = next(d for d in pulsecheck_app.domain_list() if d["name"] == "imported-comment.io")
            self.assertEqual(domain["comment"], "Cloud load balancer")

            # Import CSV without a Comment column (legacy format)
            legacy_csv = "Domain,Match,URL path,Paused,Ports\nlegacy-no-comment.io,legacy,,0,80\n"
            summary2 = pulsecheck_app.import_domains_from_csv(legacy_csv)
            self.assertEqual(summary2["imported"], 1)
            domain2 = next(d for d in pulsecheck_app.domain_list() if d["name"] == "legacy-no-comment.io")
            self.assertEqual(domain2["comment"], "")

            # Import headerless 6-column CSV
            headerless_csv = "headerless-comment.io,headerless,,Direct node,0,80\n"
            summary3 = pulsecheck_app.import_domains_from_csv(headerless_csv)
            self.assertEqual(summary3["imported"], 1)
            domain3 = next(d for d in pulsecheck_app.domain_list() if d["name"] == "headerless-comment.io")
            self.assertEqual(domain3["comment"], "Direct node")

            # Round-trip export then import into clean db
            exported_csv, count = pulsecheck_app.export_domains_csv()
            self.assertEqual(count, 3)
            # Clear domains and import the exported CSV
            conn = pulsecheck_app.get_db_connection()
            conn.execute("DELETE FROM domains")
            conn.commit()
            conn.close()
            summary_rt = pulsecheck_app.import_domains_from_csv(exported_csv)
            self.assertEqual(summary_rt["imported"], 3)
            reimported = {d["name"]: d for d in pulsecheck_app.domain_list()}
            self.assertEqual(reimported["imported-comment.io"]["comment"], "Cloud load balancer")
            self.assertEqual(reimported["headerless-comment.io"]["comment"], "Direct node")
            self.assertEqual(reimported["legacy-no-comment.io"]["comment"], "")

    def test_domains_filter_query_params_prefill(self):
        with patch("app.scan_domain"):
            pulsecheck_app.add_domain("alpha.com")
        resp = self.client.get("/domains?filter_domain=alpha&filter_match=alp&filter_path=/test&filter_paused=active&filter_ports=443")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn('value="alpha"', html)
        self.assertIn('value="alp"', html)
        self.assertIn('value="/test"', html)
        self.assertIn('value="active" selected', html)
        self.assertIn('value="443"', html)

    def test_edit_domain_maintains_filter_return_to(self):
        with patch("app.scan_domain"):
            domain_id = pulsecheck_app.add_domain("filter-preserve.com")
            return_url = "/domains?filter_domain=filter-preserve&filter_paused=active"

            # 1. GET edit page with return_to (properly URL-encoded)
            import html as html_lib
            import urllib.parse
            encoded_return = urllib.parse.quote(return_url)
            get_resp = self.client.get(f"/domains/{domain_id}/edit?return_to={encoded_return}")
            self.assertEqual(get_resp.status_code, 200)
            html = get_resp.data.decode("utf-8")
            self.assertIn(f'value="{html_lib.escape(return_url)}"', html)
            self.assertIn(f'href="{html_lib.escape(return_url)}"', html)

            # 2. POST save changes and verify redirect back to return_url
            post_resp = self.client.post(
                f"/domains/{domain_id}/edit",
                data={
                    "name": "filter-preserve.com",
                    "match": "filter-preserve",
                    "url_path": "",
                    "comment": "Preserved comment",
                    "ports": "80, 443",
                    "return_to": return_url,
                },
                follow_redirects=False,
            )
            self.assertEqual(post_resp.status_code, 302)
            self.assertEqual(post_resp.location, return_url)

            # 3. Disallow untrusted return_to
            unsafe_resp = self.client.post(
                f"/domains/{domain_id}/edit",
                data={
                    "name": "filter-preserve.com",
                    "match": "filter-preserve",
                    "return_to": "https://attacker.com/phish",
                },
                follow_redirects=False,
            )
            self.assertEqual(unsafe_resp.status_code, 302)
            self.assertEqual(unsafe_resp.location, "/domains")

    def test_pulsecheck_host_and_port_env(self):
        # Test notification URL uses DEFAULT_HOSTNAME without port, with HTTP by default
        with patch.object(pulsecheck_app, "DEFAULT_HOSTNAME", "monitor.internal.org"):
            with patch.dict(os.environ, {"PULSECHECK_HOSTNAME": "monitor.internal.org", "PULSECHECK_SSL": "FALSE"}):
                with patch("app.send_email") as mock_email, patch("app.get_settings") as mock_settings:
                    mock_settings.return_value = {
                        "smtp_host": "smtp.example.com",
                        "recipient_email": "admin@test.com",
                    }
                    mock_email.return_value = (True, "OK")
                    pulsecheck_app.send_state_change_notification(
                        [{"domain": "test.com", "old_status": "online", "new_status": "offline", "port_changes": []}]
                    )
                    mock_email.assert_called_once()
                    body = mock_email.call_args[0][2]
                    html_body = mock_email.call_args[1].get("html_body", "")
                    self.assertIn("http://monitor.internal.org/status", body)
                    self.assertIn("http://monitor.internal.org/status", html_body)

        # Test notification URL with PULSECHECK_SSL=TRUE creates HTTPS without port
        with patch.dict(os.environ, {"PULSECHECK_HOSTNAME": "secure.internal.org", "PULSECHECK_SSL": "TRUE"}):
            with patch("app.send_email") as mock_email, patch("app.get_settings") as mock_settings:
                mock_settings.return_value = {
                    "smtp_host": "smtp.example.com",
                    "recipient_email": "admin@test.com",
                }
                mock_email.return_value = (True, "OK")
                pulsecheck_app.send_state_change_notification(
                    [{"domain": "test.com", "old_status": "online", "new_status": "offline", "port_changes": []}]
                )
                body = mock_email.call_args[0][2]
                html_body = mock_email.call_args[1].get("html_body", "")
                self.assertIn("https://secure.internal.org/status", body)
                self.assertIn("https://secure.internal.org/status", html_body)

        # Test environment variable fallback in app for IP, HOSTNAME, and SSL
        with patch.dict(os.environ, {
            "PULSECHECK_IP": "10.0.0.50",
            "PULSECHECK_HOSTNAME": "node1.cluster.local",
            "PULSECHECK_SSL": "true",
            "PULSECHECK_PORT": "8888",
        }):
            ip = os.getenv("PULSECHECK_IP", "0.0.0.0")
            hostname = os.getenv("PULSECHECK_HOSTNAME", "127.0.0.1")
            scheme = pulsecheck_app.get_url_scheme()
            base_url = pulsecheck_app.get_base_url()
            status_url = pulsecheck_app.get_status_url()
            self.assertEqual(ip, "10.0.0.50")
            self.assertEqual(hostname, "node1.cluster.local")
            self.assertEqual(scheme, "https")
            self.assertEqual(base_url, "https://node1.cluster.local")
            self.assertEqual(status_url, "https://node1.cluster.local/status")

    def test_status_page_local_server_time(self):
        utc_ts = "2026-09-29 07:00:00 UTC"
        # Test custom server timezone (e.g. Africa/Johannesburg UTC+2)
        with patch.dict(os.environ, {"PULSECHECK_TIMEZONE": "Africa/Johannesburg"}):
            formatted = pulsecheck_app.format_local_time(utc_ts)
            self.assertEqual(formatted, "2026-09-29 09:00:00 SAST")

        # Test another timezone (e.g. America/New_York UTC-4 in daylight savings)
        with patch.dict(os.environ, {"PULSECHECK_TIMEZONE": "America/New_York"}):
            formatted_ny = pulsecheck_app.format_local_time(utc_ts)
            self.assertEqual(formatted_ny, "2026-09-29 03:00:00 EDT")

        # Verify on /status page with multiple ports, the latest check is picked
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, 0)",
                  ("multiport.org", "multi", "[80, 443]"))
        d_id = c.lastrowid
        # Port 80 checked earlier, Port 443 checked later
        c.execute("INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, 80, 1, 'online', '2026-09-29 06:00:00 UTC')", (d_id,))
        c.execute("INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, 443, 1, 'online', '2026-09-29 07:00:00 UTC')", (d_id,))
        conn.commit()
        conn.close()

        with patch.dict(os.environ, {"PULSECHECK_TIMEZONE": "Africa/Johannesburg"}):
            resp = self.client.get("/status")
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode("utf-8")
            # Should display the latest check 07:00 UTC converted to 09:00 SAST
            self.assertIn("2026-09-29 09:00:00 SAST", html)

            # Verify get_current_local_time_str uses local system time
            current_local = pulsecheck_app.get_current_local_time_str()
            self.assertTrue(current_local.endswith(" SAST"))

            # Verify notification email contains local system time in Scan completed
            with patch("app.send_email") as mock_email, patch("app.get_settings") as mock_settings:
                mock_settings.return_value = {"smtp_host": "smtp.example.com", "recipient_email": "admin@test.com"}
                mock_email.return_value = (True, "OK")
                pulsecheck_app.send_state_change_notification(
                    [{"domain": "multiport.org", "old_status": "online", "new_status": "offline", "port_changes": []}]
                )
                body = mock_email.call_args[0][2]
                self.assertIn("Scan Completed:", body)
                self.assertIn("SAST", body)
                self.assertNotIn("UTC", body)

    def test_ssl_legacy_fallback_and_handshake_handling(self):
        import ssl
        # 1. Test helper detection
        handshake_err = ssl.SSLError(1, "[SSL: SSLV3_ALERT_HANDSHAKE_FAILURE] sslv3 alert handshake failure (_ssl.c:1006)")
        self.assertTrue(pulsecheck_app.is_ssl_handshake_failure(handshake_err))

        reneg_err = ssl.SSLError(1, "[SSL: UNSAFE_LEGACY_RENEGOTIATION_DISABLED] unsafe legacy renegotiation disabled")
        self.assertTrue(pulsecheck_app.is_ssl_handshake_failure(reneg_err))

        wrapped_err = Exception("wrapped")
        wrapped_err.__cause__ = handshake_err
        self.assertTrue(pulsecheck_app.is_ssl_handshake_failure(wrapped_err))

        other_err = ssl.SSLError(1, "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed")
        self.assertFalse(pulsecheck_app.is_ssl_handshake_failure(other_err))
        self.assertFalse(pulsecheck_app.is_ssl_handshake_failure(OSError("connection refused")))

        # 2. Test create_ssl_context
        std_ctx = pulsecheck_app.create_ssl_context(legacy=False)
        self.assertFalse(std_ctx.check_hostname)
        self.assertEqual(std_ctx.verify_mode, ssl.CERT_NONE)

        legacy_ctx = pulsecheck_app.create_ssl_context(legacy=True)
        op_legacy = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        self.assertTrue(legacy_ctx.options & op_legacy)

        # 3. Test fetch_response retries with legacy SSL upon handshake failure
        class FakeResponse:
            def __init__(self, status, body):
                self.status = status
                self._body = body
            def read(self, size):
                return self._body
            def getheader(self, name):
                return None

        attempts = []
        class FakeHTTPSConnection:
            def __init__(self, host, port, **kwargs):
                self.ctx = kwargs.get("context")

            def request(self, method, path, headers):
                attempts.append(self.ctx)
                if len(attempts) == 1:
                    raise handshake_err

            def getresponse(self):
                return FakeResponse(200, b"legacy device online")

            def close(self):
                pass

        with patch("app.http.client.HTTPSConnection", FakeHTTPSConnection):
            body, code, url = pulsecheck_app.fetch_response("legacy.local", 443, "https")
            self.assertEqual(code, 200)
            self.assertEqual(body, b"legacy device online")
            self.assertEqual(len(attempts), 2)
            # Second attempt used legacy SSL context
            self.assertTrue(attempts[1].options & op_legacy)

        # 4. Test scan_domain records online status
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO domains (name, match, ports) VALUES ('cam.local', 'legacy device', '[443]')")
        d_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPSConnection", FakeHTTPSConnection):
            attempts.clear()
            pulsecheck_app.scan_domain(d_id, "cam.local", [443], match="legacy device")

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE domain_id = ? AND port = 443 ORDER BY id DESC LIMIT 1", (d_id,)).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "online")
        self.assertEqual(row[1], 1)

    def test_gzip_content_encoding_decompression(self):
        import gzip

        original_text = (b"<html><body><h1>PulseCheck Monitoring Target</h1>" + b"<p>Repeating block</p>" * 200 + b"</body></html>")
        compressed_full = gzip.compress(original_text)
        # Truncate compressed stream to simulate reading only partial response
        compressed_partial = compressed_full[:120]

        # 1. Test helper with full and partial gzip
        decomp_full = pulsecheck_app.decompress_gzip_payload(compressed_full)
        self.assertEqual(decomp_full, original_text)

        decomp_partial = pulsecheck_app.decompress_gzip_payload(compressed_partial)
        self.assertIn(b"PulseCheck Monitoring Target", decomp_partial)

        # 2. Test socket helper
        socket_data = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Encoding: gzip\r\n\r\n" + compressed_partial
        decomp_socket = pulsecheck_app.decompress_socket_response_if_gzip(socket_data)
        self.assertIn(b"PulseCheck Monitoring Target", decomp_socket)

        # 3. Test fetch_response with Content-Encoding: gzip
        class FakeGzipResponse:
            def __init__(self, body, encoding="gzip"):
                self.status = 200
                self._body = body
                self._encoding = encoding

            def read(self, size):
                return self._body

            def getheader(self, name):
                if name.lower() == "content-encoding":
                    return self._encoding
                return None

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                pass
            def request(self, method, path, headers):
                pass
            def getresponse(self):
                return FakeGzipResponse(compressed_partial, "gzip")
            def close(self):
                pass

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            body, code, url = pulsecheck_app.fetch_response("gzip-site.local", 80, "http")
            self.assertEqual(code, 200)
            self.assertIn(b"PulseCheck Monitoring Target", body)

        # 4. Test scan_domain matches decompressed keyword and sets status to online
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO domains (name, match, ports) VALUES ('gzip-scan.local', 'Monitoring Target', '[80]')")
        d_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            pulsecheck_app.scan_domain(d_id, "gzip-scan.local", [80], match="Monitoring Target")

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE domain_id = ? AND port = 80 ORDER BY id DESC LIMIT 1", (d_id,)).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "online")
        self.assertEqual(row[1], 1)

    def test_scan_domain_with_retries(self):
        # 1. Success on first attempt: no sleep, exactly 1 call
        sleep_calls = []
        scan_calls = []

        def mock_scan_success(*args, **kwargs):
            scan_calls.append(args)
            return {80: "online"}

        with patch("app.scan_domain", side_effect=mock_scan_success), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_domain_with_retries(
                {"id": 1, "name": "ok.local", "ports": [80], "match": ""},
                max_retries=3,
                retry_interval=10,
            )
        self.assertEqual(result, {80: "online"})
        self.assertEqual(len(scan_calls), 1)
        self.assertEqual(len(sleep_calls), 0)

        # 2. Failure then success on 2nd retry: 2 sleeps of 10s, 3 scan calls
        sleep_calls.clear()
        scan_calls.clear()
        attempts_responses = [{80: "offline"}, {80: "offline"}, {80: "online"}]

        def mock_scan_flaky(*args, **kwargs):
            scan_calls.append(args)
            return attempts_responses.pop(0)

        with patch("app.scan_domain", side_effect=mock_scan_flaky), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_domain_with_retries(
                {"id": 2, "name": "flaky.local", "ports": [80], "match": ""},
                max_retries=3,
                retry_interval=10,
            )
        self.assertEqual(result, {80: "online"})
        self.assertEqual(len(scan_calls), 3)
        self.assertEqual(sleep_calls, [10, 10])

        # 3. Persistent failure: 3 retries (4 calls total), 3 sleeps of 10s
        sleep_calls.clear()
        scan_calls.clear()

        def mock_scan_fail(*args, **kwargs):
            scan_calls.append(args)
            return {80: "offline"}

        with patch("app.scan_domain", side_effect=mock_scan_fail), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_domain_with_retries(
                {"id": 3, "name": "down.local", "ports": [80], "match": ""},
                max_retries=3,
                retry_interval=10,
            )
        self.assertEqual(result, {80: "offline"})
        self.assertEqual(len(scan_calls), 4)
        self.assertEqual(sleep_calls, [10, 10, 10])

    def test_check_all_domains_parallel_execution(self):
        import threading
        # Insert 6 domains into DB
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        for i in range(1, 7):
            c.execute("INSERT INTO domains (name, ports) VALUES (?, '[80]')", (f"dom{i}.local",))
        conn.commit()
        conn.close()

        scanned_domains = []
        lock = threading.Lock()

        def mock_scan_retries(domain, max_retries=3, retry_interval=10, explicit_debug=None):
            with lock:
                scanned_domains.append(domain["name"])
            return {80: "online"}

        with patch("app.scan_domain_with_retries", side_effect=mock_scan_retries):
            pulsecheck_app.check_all_domains(workers=5, max_retries=3, retry_interval=0)

        self.assertEqual(len(scanned_domains), 6)
        self.assertEqual(set(scanned_domains), {f"dom{i}.local" for i in range(1, 7)})

    def test_proxy_settings_storage_and_password_preservation(self):
        new_settings = {
            "proxy_host": "proxy.corp.internal",
            "proxy_port": "3128",
            "proxy_username": "proxyuser",
            "proxy_password": "supersecretpassword",
        }
        pulsecheck_app.save_settings(new_settings)
        loaded = pulsecheck_app.get_settings()
        self.assertEqual(loaded["proxy_host"], "proxy.corp.internal")
        self.assertEqual(loaded["proxy_port"], "3128")
        self.assertEqual(loaded["proxy_username"], "proxyuser")
        self.assertEqual(loaded["proxy_password"], "supersecretpassword")

        # Test web route preserving password when left blank
        response = self.client.post("/settings", data={
            "action": "save",
            "proxy_host": "proxy-updated.internal",
            "proxy_port": "8080",
            "proxy_username": "newuser",
            "proxy_password": "",  # Empty should preserve existing
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        reloaded = pulsecheck_app.get_settings()
        self.assertEqual(reloaded["proxy_host"], "proxy-updated.internal")
        self.assertEqual(reloaded["proxy_password"], "supersecretpassword")

    @patch("app.scan_domain")
    def test_domain_use_proxy_database_field_and_edit(self, mock_scan):
        # 1. Add domain with use_proxy default (False)
        domain_id = pulsecheck_app.add_domain("plain.example", paused=True)
        d = pulsecheck_app.get_domain_by_id(domain_id)
        self.assertFalse(d["use_proxy"])

        # 2. Update domain with use_proxy=True
        pulsecheck_app.update_domain(domain_id, "plain.example", "80, 443", paused=True, use_proxy=True)
        d_updated = pulsecheck_app.get_domain_by_id(domain_id)
        self.assertTrue(d_updated["use_proxy"])

        # 3. Edit via web route POST
        response = self.client.post(f"/domains/{domain_id}/edit", data={
            "name": "plain.example",
            "match": "plain",
            "url_path": "",
            "comment": "Testing proxy",
            "ports": "80",
            "use_proxy": "on",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        d_web = pulsecheck_app.get_domain_by_id(domain_id)
        self.assertTrue(d_web["use_proxy"])

        # 4. Turn use_proxy off via web route POST (checkbox omitted)
        response = self.client.post(f"/domains/{domain_id}/edit", data={
            "name": "plain.example",
            "match": "plain",
            "url_path": "",
            "comment": "Testing proxy",
            "ports": "80",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        d_web_off = pulsecheck_app.get_domain_by_id(domain_id)
        self.assertFalse(d_web_off["use_proxy"])

    @patch("app.scan_domain")
    def test_csv_import_and_export_with_proxy_indicator(self, mock_scan):
        # Import CSV containing Proxy column
        csv_data = """Domain,Match,URL path,Comment,Paused,Proxy,Ports
proxied.example,proxied,/health,Gateway,0,1,"80, 443"
direct.example,direct,,Direct site,0,0,8080
"""
        summary = pulsecheck_app.import_domains_from_csv(csv_data)
        self.assertEqual(summary["imported"], 2)

        domains = {d["name"]: d for d in pulsecheck_app.domain_list()}
        self.assertTrue(domains["proxied.example"]["use_proxy"])
        self.assertFalse(domains["direct.example"]["use_proxy"])

        # Export and verify the Proxy column
        csv_text, count = pulsecheck_app.export_domains_csv()
        self.assertEqual(count, 2)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Domain,Match,URL path,Comment,Paused,Proxy,Ports")
        self.assertIn('proxied.example,proxied,/health,Gateway,0,1,"80, 443"', lines)
        self.assertIn("direct.example,direct,,Direct site,0,0,8080", lines)

    def test_fetch_response_http_uses_proxy_server(self):
        class FakeResponse:
            status = 200
            def read(self, size):
                return b"proxied http content"
            def getheader(self, name):
                return None

        connection_log = {}

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                connection_log["host"] = host
                connection_log["port"] = port

            def request(self, method, url, headers=None):
                connection_log["method"] = method
                connection_log["url"] = url
                connection_log["headers"] = headers or {}

            def getresponse(self):
                return FakeResponse()

            def close(self):
                connection_log["closed"] = True

        proxy_cfg = {
            "proxy_host": "10.0.0.50",
            "proxy_port": "8080",
            "proxy_username": "agent",
            "proxy_password": "secret",
        }

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            body, code, url = pulsecheck_app.fetch_response(
                "internal.example",
                80,
                "http",
                url_path="/status",
                use_proxy=True,
                proxy_settings=proxy_cfg,
            )

        self.assertEqual(body, b"proxied http content")
        self.assertEqual(code, 200)
        self.assertEqual(connection_log["host"], "10.0.0.50")
        self.assertEqual(connection_log["port"], 8080)
        self.assertEqual(connection_log["method"], "GET")
        self.assertEqual(connection_log["url"], "http://internal.example/status")
        self.assertEqual(connection_log["headers"]["Host"], "internal.example")
        self.assertIn("Proxy-Authorization", connection_log["headers"])
        self.assertTrue(connection_log["headers"]["Proxy-Authorization"].startswith("Basic "))

    def test_fetch_response_https_uses_proxy_tunnel(self):
        class FakeResponse:
            status = 200
            def read(self, size):
                return b"proxied https content"
            def getheader(self, name):
                return None

        tunnel_log = {}

        class FakeHTTPSConnection:
            def __init__(self, host, port, **kwargs):
                tunnel_log["host"] = host
                tunnel_log["port"] = port

            def set_tunnel(self, target_host, port=None, headers=None):
                tunnel_log["target_host"] = target_host
                tunnel_log["target_port"] = port
                tunnel_log["tunnel_headers"] = headers or {}

            def request(self, method, path, headers=None):
                tunnel_log["method"] = method
                tunnel_log["path"] = path
                tunnel_log["headers"] = headers or {}

            def getresponse(self):
                return FakeResponse()

            def close(self):
                tunnel_log["closed"] = True

        proxy_cfg = {
            "proxy_host": "proxy.mycorp.com",
            "proxy_port": "3128",
            "proxy_username": "myuser",
            "proxy_password": "mypassword",
        }

        with patch("app.http.client.HTTPSConnection", FakeHTTPSConnection):
            body, code, url = pulsecheck_app.fetch_response(
                "secure.example",
                443,
                "https",
                url_path="/api/data",
                use_proxy=True,
                proxy_settings=proxy_cfg,
            )

        self.assertEqual(body, b"proxied https content")
        self.assertEqual(code, 200)
        self.assertEqual(tunnel_log["host"], "proxy.mycorp.com")
        self.assertEqual(tunnel_log["port"], 3128)
        self.assertEqual(tunnel_log["target_host"], "secure.example")
        self.assertEqual(tunnel_log["target_port"], 443)
        self.assertIn("Proxy-Authorization", tunnel_log["tunnel_headers"])
        self.assertEqual(tunnel_log["method"], "GET")
        self.assertEqual(tunnel_log["path"], "/api/data")
        self.assertEqual(tunnel_log["headers"]["Host"], "secure.example")

    def test_fetch_response_requires_proxy_host_when_use_proxy_true(self):
        with self.assertRaises(OSError) as ctx:
            pulsecheck_app.fetch_response(
                "target.example",
                80,
                "http",
                use_proxy=True,
                proxy_settings={"proxy_host": ""},
            )
        self.assertIn("requires proxy access", str(ctx.exception))

    @patch("app.fetch_socket_response")
    @patch("app.fetch_response")
    def test_scan_domain_uses_proxy_and_skips_socket_fallback(self, mock_fetch, mock_socket):
        # Configure domain in DB with use_proxy=1
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO domains (name, match, ports, use_proxy) VALUES (?, ?, ?, 1)",
            ("proxied-host.local", "mismatch-token", "[80]"),
        )
        domain_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Simulate fetch_response returning content that does NOT match -> status will be offline/degraded
        mock_fetch.return_value = (b"some response", 200, "http://proxied-host.local:80/")

        pulsecheck_app.scan_domain(domain_id, "proxied-host.local", [80], match="mismatch-token")

        # Verify fetch_response was called with use_proxy=True
        mock_fetch.assert_called_once()
        self.assertTrue(mock_fetch.call_args.kwargs.get("use_proxy"))

        # Verify direct socket fallback was NOT attempted
        mock_socket.assert_not_called()

    def test_fetch_response_concatenates_headers_to_body(self):
        class FakeResponse:
            status = 200
            headers = {"Server": "CustomEdge/1.0", "X-App-Status": "healthy"}
            def read(self, size):
                return b"<html><body>Hello World</body></html>"
            def getheader(self, name):
                return self.headers.get(name)

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                pass
            def request(self, method, path, headers=None):
                pass
            def getresponse(self):
                return FakeResponse()
            def close(self):
                pass

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            body, code, url = pulsecheck_app.fetch_response("test-headers.local", 80, "http")

        self.assertEqual(code, 200)
        # Headers should be at the front of the body
        self.assertTrue(body.startswith(b"Server: CustomEdge/1.0"))
        self.assertIn(b"X-App-Status: healthy", body)
        self.assertIn(b"<html><body>Hello World</body></html>", body)

    def test_fetch_response_gzip_decompresses_body_then_concatenates_headers(self):
        import gzip
        raw_html = b"<html><body>Decompressed Secret Content</body></html>"
        compressed_body = gzip.compress(raw_html)

        class FakeGzipResponseWithHeaders:
            status = 200
            headers = {
                "Content-Encoding": "gzip",
                "Content-Type": "text/html",
                "X-Custom-Header": "EdgeV2",
            }
            def read(self, size):
                return compressed_body
            def getheader(self, name):
                for k, v in self.headers.items():
                    if k.lower() == name.lower():
                        return v
                return None

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                pass
            def request(self, method, path, headers=None):
                pass
            def getresponse(self):
                return FakeGzipResponseWithHeaders()
            def close(self):
                pass

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            body, code, url = pulsecheck_app.fetch_response("gzip-headers.local", 80, "http")

        self.assertEqual(code, 200)
        # Verify headers are at the front
        self.assertTrue(body.startswith(b"Content-Encoding: gzip") or b"X-Custom-Header: EdgeV2" in body)
        self.assertIn(b"X-Custom-Header: EdgeV2", body)
        # Verify body was decompressed
        self.assertIn(b"Decompressed Secret Content", body)

    def test_scan_domain_matches_token_in_headers(self):
        class FakeResponseWithHeaderToken:
            status = 200
            headers = {"X-Cluster-Node": "WorkerNode77"}
            def read(self, size):
                return b"generic body without token"
            def getheader(self, name):
                return self.headers.get(name)

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                pass
            def request(self, method, path, headers=None):
                pass
            def getresponse(self):
                return FakeResponseWithHeaderToken()
            def close(self):
                pass

        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO domains (name, match, ports) VALUES ('header-match.local', 'WorkerNode77', '[80]')")
        domain_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            pulsecheck_app.scan_domain(domain_id, "header-match.local", [80], match="WorkerNode77")

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE domain_id = ? AND port = 80", (domain_id,)).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "online")
        self.assertEqual(row["is_online"], 1)

    def test_status_page_domain_and_match_truncation_and_hover_box(self):
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        long_domain = "really-long-subdomain-12345.production.api.internal-cloud-network.company.com"
        long_match = "Corporate Authentication Portal - Cluster Edge Node 42"
        c.execute(
            "INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, 0)",
            (long_domain, long_match, "[443]"),
        )
        d_id = c.lastrowid
        c.execute(
            "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, 443, 1, 'online', '2026-09-29 08:00:00 UTC')",
            (d_id,),
        )
        conn.commit()
        conn.close()

        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Verify cell-truncate-wrapper, truncate-text, and cell-hover-box are rendered
        self.assertIn("cell-truncate-wrapper", html)
        self.assertIn("truncate-text", html)
        self.assertIn("cell-hover-box", html)
        self.assertIn(long_domain, html)
        self.assertIn(long_match, html)
        self.assertIn('<span class="hover-box-label">Domain</span>', html)
        self.assertIn('<span class="hover-box-label">Match</span>', html)
        self.assertIn("cell-ports-wrapper", html)
        self.assertIn("status-ports-inline", html)
        self.assertIn("cell-hover-box-ports", html)
        self.assertIn("Monitored Ports", html)

    def test_status_page_proxy_indicator_badge(self):
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO domains (name, match, ports, paused, use_proxy) VALUES (?, ?, ?, 0, 1)",
            ("proxied-service.internal", "proxytoken", "[8080]"),
        )
        d_id = c.lastrowid
        c.execute(
            "INSERT INTO port_checks (domain_id, port, is_online, status, checked_at) VALUES (?, 8080, 1, 'online', '2026-09-29 08:00:00 UTC')",
            (d_id,),
        )
        conn.commit()
        conn.close()

        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Verify proxy badge appears on status page
        self.assertIn('class="badge badge-proxy"', html)
        self.assertIn('title="Accessed via Proxy Server">Proxy</span>', html)
        self.assertIn("Proxy Server", html)

    def test_status_page_many_ports_truncation_and_hover_list(self):
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        ports_list = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9000, 9443]
        c.execute(
            "INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, 0)",
            ("manyports.example", "cluster", str(ports_list)),
        )
        d_id = c.lastrowid
        for p in ports_list:
            c.execute(
                "INSERT INTO port_checks (domain_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, 1, 'online', 25, '2026-09-29 08:30:00 UTC')",
                (d_id, p),
            )
        conn.commit()
        conn.close()

        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # Verify all 10 ports appear in the hover list
        self.assertIn("Monitored Ports (10)", html)
        for p in ports_list:
            self.assertIn(f">{p}</strong>", html)


if __name__ == "__main__":
    unittest.main()






