from datetime import datetime, timezone
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
        self.original_mfg_icons = pulsecheck_app.MANUFACTURER_ICONS_DIR
        self.original_svc_icons = pulsecheck_app.SERVICE_ICONS_DIR
        pulsecheck_app.DB_PATH = Path(self.temp_dir.name) / "pulsecheck.db"
        pulsecheck_app.MANUFACTURER_ICONS_DIR = Path(self.temp_dir.name) / "manufacturer_icons"
        pulsecheck_app.MANUFACTURER_ICONS_DIR.mkdir(parents=True, exist_ok=True)
        pulsecheck_app.SERVICE_ICONS_DIR = Path(self.temp_dir.name) / "service_icons"
        pulsecheck_app.SERVICE_ICONS_DIR.mkdir(parents=True, exist_ok=True)
        pulsecheck_app.init_db()
        self.client = pulsecheck_app.app.test_client()

    def tearDown(self):
        pulsecheck_app.DB_PATH = self.original_db
        pulsecheck_app.MANUFACTURER_ICONS_DIR = self.original_mfg_icons
        pulsecheck_app.SERVICE_ICONS_DIR = self.original_svc_icons
        try:
            self.temp_dir.cleanup()
        except Exception:
            pass

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
        # Offline overrides degraded and online (worst to best)
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "online", 443: "offline"}), "offline")
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "degraded", 443: "offline"}), "offline")
        self.assertEqual(pulsecheck_app.compute_overall_status({80: "online", 443: "degraded"}), "degraded")

    @patch("app.send_email")
    @patch("app.scan_service")
    def test_check_all_services_sends_notification_on_state_change(self, mock_scan, mock_send_email):
        mock_send_email.return_value = (True, "Sent")

        # Configure SMTP settings
        pulsecheck_app.save_settings({
            "smtp_host": "smtp.example.com",
            "from_email": "alerts@example.com",
            "recipient_email": "admin@example.com",
        })

        # Add service and simulate previous check state: online
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, ?)",
            ("service.example", '[{"port": 80, "protocol": "http", "match": "service"}, {"port": 443, "protocol": "https", "match": "service"}]', 0),
        )
        service_id = conn.execute("SELECT id FROM services WHERE name = ?", ("service.example",)).fetchone()["id"]
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (service_id, 80),
        )
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (service_id, 443),
        )
        conn.commit()
        conn.close()

        # Simulate scan_service changing port 80 to offline during scan (offline overrides online -> service is offline)
        def simulate_scan(d_id, name, ports, match=None, explicit_debug=None, url_path="", **kwargs):
            conn_inner = pulsecheck_app.get_db_connection()
            conn_inner.execute(
                "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 0, 'offline', '2026-09-28 12:10:00 UTC')",
                (d_id, 80),
            )
            conn_inner.execute(
                "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:10:00 UTC')",
                (d_id, 443),
            )
            conn_inner.commit()
            conn_inner.close()
            return {80: "offline", 443: "online"}

        mock_scan.side_effect = simulate_scan

        changes = pulsecheck_app.check_all_services(max_retries=0)

        self.assertEqual(len(changes), 1)
        self.assertEqual(changes[0]["service"], "service.example")
        self.assertEqual(changes[0]["old_status"], "online")
        self.assertEqual(changes[0]["new_status"], "offline")
        self.assertIn("Port 80: ONLINE -> OFFLINE", changes[0]["port_changes"])

        # Verify email was dispatched
        mock_send_email.assert_called_once()
        call_args = mock_send_email.call_args
        to_addr, subject, body = call_args[0][0], call_args[0][1], call_args[0][2]
        self.assertEqual(to_addr, "admin@example.com")
        self.assertIn("State Change Alert", subject)
        self.assertIn("service.example", body)
        self.assertIn("ONLINE -> OFFLINE", body)
        self.assertIn("Port 80: ONLINE -> OFFLINE", body)

    @patch("app.send_email")
    @patch("app.scan_service")
    def test_check_all_services_no_notification_when_no_change(self, mock_scan, mock_send_email):
        # Configure SMTP settings
        pulsecheck_app.save_settings({
            "smtp_host": "smtp.example.com",
            "from_email": "alerts@example.com",
            "recipient_email": "admin@example.com",
        })

        # Add service with existing check state
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, ?)",
            ("stable.example", '[{"port": 80, "protocol": "http", "match": "stable"}]', 0),
        )
        service_id = conn.execute("SELECT id FROM services WHERE name = ?", ("stable.example",)).fetchone()["id"]
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:00:00 UTC')",
            (service_id, 80),
        )
        conn.commit()
        conn.close()

        # Simulate scan yielding the same state
        def simulate_scan(d_id, name, ports, match, explicit_debug=None, url_path="", **kwargs):
            conn_inner = pulsecheck_app.get_db_connection()
            conn_inner.execute(
                "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, ?, 1, 'online', '2026-09-28 12:10:00 UTC')",
                (d_id, 80),
            )
            conn_inner.commit()
            conn_inner.close()
            return {80: "online"}

        mock_scan.side_effect = simulate_scan

        changes = pulsecheck_app.check_all_services()

        self.assertEqual(changes, [])
        mock_send_email.assert_not_called()

    def test_export_services_csv(self):
        conn = pulsecheck_app.get_db_connection()
        p_a = pulsecheck_app.port_protocol_to_json([
            {"port": 80, "protocol": "", "match": "service", "url_path": "/test"},
            {"port": 443, "protocol": "", "match": "service", "url_path": "/test"},
        ])
        p_b = pulsecheck_app.port_protocol_to_json([
            {"port": 8080, "protocol": "", "match": "other", "url_path": ""},
        ])
        conn.execute(
            "INSERT INTO services (name, comment, paused, port_protocol) VALUES (?, ?, ?, ?)",
            ("service-a.com", "Internal gateway", 0, p_a),
        )
        conn.execute(
            "INSERT INTO services (name, comment, paused, port_protocol) VALUES (?, ?, ?, ?)",
            ("service-b.com", "", 1, p_b),
        )
        conn.commit()
        conn.close()

        csv_text, count = pulsecheck_app.export_services_csv()
        self.assertEqual(count, 2)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response")
        self.assertIn('service-a.com,Internal gateway,0,0,,"80, 443",web,/test,service,,', lines)
        self.assertIn("service-b.com,,1,0,,8080,web,,other,,", lines)

    @patch("app.scan_service")
    def test_import_services_from_csv_success_and_skip_duplicates(self, mock_scan):
        # Seed an existing service in the database
        conn = pulsecheck_app.get_db_connection()
        p_exist = pulsecheck_app.port_protocol_to_json([{"port": 80, "protocol": "", "match": "existing", "url_path": ""}])
        conn.execute(
            "INSERT INTO services (name, paused, port_protocol) VALUES (?, 0, ?)",
            ("existing.com", p_exist),
        )
        conn.commit()
        conn.close()

        csv_data = """Service,Match,URL path,Paused,Ports
newsite.com,newsite,/api,0,"80, 443"
existing.com,existing,,0,80
pausedsite.com,pausedsite,,1,8080
bad site!!,bad,,0,80
"""
        summary = pulsecheck_app.import_services_from_csv(csv_data)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["imported"], 2)
        self.assertEqual(summary["skipped"], 1)
        self.assertEqual(summary["invalid"], 1)
        self.assertIn("existing.com", summary["skipped_services"])
        self.assertIn("newsite.com", summary["imported_services"])
        self.assertIn("pausedsite.com", summary["imported_services"])

        # Check newsite.com in DB
        services = {d["name"]: d for d in pulsecheck_app.service_list()}
        self.assertEqual(services["newsite.com"]["match"], "newsite")
        self.assertEqual(services["newsite.com"]["url_path"], "/api")
        self.assertFalse(services["newsite.com"]["paused"])
        self.assertEqual(services["newsite.com"]["ports"], [80, 443])

        # Check pausedsite.com in DB
        self.assertTrue(services["pausedsite.com"]["paused"])
        self.assertEqual(services["pausedsite.com"]["ports"], [8080])

    def test_export_route(self):
        conn = pulsecheck_app.get_db_connection()
        p_data = pulsecheck_app.port_protocol_to_json([
            {"port": 443, "protocol": "", "match": "test", "url_path": ""},
        ])
        conn.execute(
            "INSERT INTO services (name, paused, port_protocol) VALUES (?, 0, ?)",
            ("test.org", p_data),
        )
        conn.commit()
        conn.close()

        response = self.client.get("/import/export")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content_type, "text/csv; charset=utf-8")
        self.assertIn("attachment; filename=pulsecheck_services.csv", response.headers["Content-Disposition"])
        self.assertEqual(response.headers["X-Exported-Count"], "1")
        self.assertIn(b"Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response", response.data)
        self.assertIn(b"test.org,,0,0,,443,web,,test,,", response.data)

    @patch("app.scan_service")
    def test_import_route_csv_upload(self, mock_scan):
        csv_file_bytes = b"Service,Match,URL path,Paused,Ports\nuploaded.com,uploaded,,0,80\n"
        data = {
            "csv_file": (io.BytesIO(csv_file_bytes), "services.csv"),
        }
        response = self.client.post(
            "/import",
            data=data,
            content_type="multipart/form-data",
            follow_redirects=True,
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CSV Import complete: 1 imported, 0 skipped", response.data)

        services = pulsecheck_app.service_list()
        self.assertTrue(any(d["name"] == "uploaded.com" for d in services))

    @patch("app.discover_ports")
    @patch("app.scan_service")
    def test_update_service_with_empty_ports_skips_scan_and_discovery(self, mock_scan, mock_discover):
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO services (name, paused, port_protocol) VALUES (?, ?, ?)",
            ("service-to-edit.com", 0, '[{"port": 80, "protocol": "http", "match": "service", "url_path": ""}, {"port": 443, "protocol": "https", "match": "service", "url_path": ""}]'),
        )
        service_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Update service with empty ports string
        pulsecheck_app.update_service(service_id, "service-to-edit.com", "")

        mock_discover.assert_not_called()
        mock_scan.assert_not_called()

        service = pulsecheck_app.get_service_by_id(service_id)
        self.assertEqual(service["ports"], [])

    @patch("app.discover_ports")
    @patch("app.scan_service")
    def test_import_services_from_csv_no_ports_skips_scan_and_discovery(self, mock_scan, mock_discover):
        csv_data = """Service,Match,URL path,Paused,Ports
noports.com,noports,,0,
"""
        summary = pulsecheck_app.import_services_from_csv(csv_data)
        self.assertEqual(summary["imported"], 1)
        mock_discover.assert_not_called()
        mock_scan.assert_not_called()

        service = {d["name"]: d for d in pulsecheck_app.service_list()}["noports.com"]
        self.assertEqual(service["ports"], [])

    def test_csv_import_progress_and_cancel(self):
        progress_events = []
        csv_data = """Service,Match,URL path,Paused,Ports
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
            pulsecheck_app.import_services_from_csv(
                csv_data,
                progress_callback=track_progress,
                cancelled_check=cancel_on_second,
            )

        self.assertGreaterEqual(len(progress_events), 1)
        self.assertEqual(progress_events[0]["index"], 1)
        self.assertEqual(progress_events[0]["total"], 3)

    def test_start_csv_import_route(self):
        csv_bytes = b"Service,Match,URL path,Paused,Ports\nasync.com,async,,0,80\n"
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
        self.assertTrue((static_dir / "logo.gif").exists(), "logo.gif must exist in static/")
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
        self.assertIn('src="/static/logo.gif"', data)
        self.assertIn('alt="PulseCheck Logo"', data)
        self.assertIn('PulseCheck</h1>', data)
        self.assertIn('class="brand-version"', data)
        self.assertIn(f"v{pulsecheck_app.APP_VERSION}", data)

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
        
        # Check that HTML includes version number near PulseCheck
        html_part = [p for p in parts if p.get_content_type() == "text/html"][0]
        html_content = html_part.get_content()
        self.assertIn(f"v{pulsecheck_app.APP_VERSION}", html_content)

        # Check that the image part has Content-ID <pulsecheck_logo>
        image_parts = [p for p in parts if p.get_content_type() == "image/png"]
        self.assertTrue(len(image_parts) >= 1)
        self.assertEqual(image_parts[0].get("Content-ID"), "<pulsecheck_logo>")


    def test_service_comment_crud(self):
        with patch("app.discover_ports", return_value=[80]), patch("app.scan_service"):
            service_id = pulsecheck_app.add_service(
                "comment-test.com",
                comment="Primary internal API server",
            )
            self.assertIsNotNone(service_id)

            service = pulsecheck_app.get_service_by_id(service_id)
            self.assertEqual(service["comment"], "Primary internal API server")

            # Update comment
            pulsecheck_app.update_service(
                service_id,
                "comment-test.com",
                ports_input="80, 443",
                comment="Updated secondary API server",
            )
            service = pulsecheck_app.get_service_by_id(service_id)
            self.assertEqual(service["comment"], "Updated secondary API server")

    def test_service_comment_web_ui(self):
        with patch("app.scan_service"):
            # Add service via web POST
            resp = self.client.post(
                "/services/add",
                data={
                    "name": "web-comment.org",
                    "match": "web",
                    "url_path": "",
                    "comment": "Customer billing system",
                },
                follow_redirects=True,
            )
            self.assertEqual(resp.status_code, 200)

            # Check service list page displays comment in tooltip and badge
            list_resp = self.client.get("/services")
            self.assertEqual(list_resp.status_code, 200)
            html = list_resp.data.decode("utf-8")
            self.assertIn('class="service-comment-badge"', html)
            self.assertIn('Customer billing system', html)
            self.assertIn('class="tooltip-bubble"', html)

            # Check edit page contains the comment
            service = next(d for d in pulsecheck_app.service_list() if d["name"] == "web-comment.org")
            edit_get = self.client.get(f"/services/{service['id']}/edit")
            self.assertEqual(edit_get.status_code, 200)
            self.assertIn('value="Customer billing system"', edit_get.data.decode("utf-8"))

            # Update comment via edit page POST
            edit_post = self.client.post(
                f"/services/{service['id']}/edit",
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
            updated = pulsecheck_app.get_service_by_id(service["id"])
            self.assertEqual(updated["comment"], "Modified billing system")

    def test_csv_import_with_comment_column(self):
        with patch("app.scan_service"):
            # Import CSV containing a Comment column
            csv_with_comment = "Service,Match,URL path,Comment,Paused,Ports\nimported-comment.io,imported,,Cloud load balancer,0,80\n"
            summary = pulsecheck_app.import_services_from_csv(csv_with_comment)
            self.assertEqual(summary["imported"], 1)

            service = next(d for d in pulsecheck_app.service_list() if d["name"] == "imported-comment.io")
            self.assertEqual(service["comment"], "Cloud load balancer")

            # Import CSV without a Comment column (legacy format)
            legacy_csv = "Service,Match,URL path,Paused,Ports\nlegacy-no-comment.io,legacy,,0,80\n"
            summary2 = pulsecheck_app.import_services_from_csv(legacy_csv)
            self.assertEqual(summary2["imported"], 1)
            service2 = next(d for d in pulsecheck_app.service_list() if d["name"] == "legacy-no-comment.io")
            self.assertEqual(service2["comment"], "")

            # Import headerless 6-column CSV
            headerless_csv = "headerless-comment.io,headerless,,Direct node,0,80\n"
            summary3 = pulsecheck_app.import_services_from_csv(headerless_csv)
            self.assertEqual(summary3["imported"], 1)
            service3 = next(d for d in pulsecheck_app.service_list() if d["name"] == "headerless-comment.io")
            self.assertEqual(service3["comment"], "Direct node")

            # Round-trip export then import into clean db
            exported_csv, count = pulsecheck_app.export_services_csv()
            self.assertEqual(count, 3)
            # Clear services and import the exported CSV
            conn = pulsecheck_app.get_db_connection()
            conn.execute("DELETE FROM services")
            conn.commit()
            conn.close()
            summary_rt = pulsecheck_app.import_services_from_csv(exported_csv)
            self.assertEqual(summary_rt["imported"], 3)
            reimported = {d["name"]: d for d in pulsecheck_app.service_list()}
            self.assertEqual(reimported["imported-comment.io"]["comment"], "Cloud load balancer")
            self.assertEqual(reimported["headerless-comment.io"]["comment"], "Direct node")
            self.assertEqual(reimported["legacy-no-comment.io"]["comment"], "")

    def test_services_filter_query_params_prefill(self):
        with patch("app.discover_ports", return_value=[80]), patch("app.scan_service"):
            pulsecheck_app.add_service("alpha.com")
        resp = self.client.get("/services?filter_service=alpha&filter_paused=active&filter_ports=443")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn('value="alpha"', html)
        self.assertIn('value="active" selected', html)
        self.assertIn('value="443"', html)

    def test_edit_service_maintains_filter_return_to(self):
        with patch("app.discover_ports", return_value=[80, 443]), patch("app.scan_service"):
            service_id = pulsecheck_app.add_service("filter-preserve.com")
            return_url = "/services?filter_service=filter-preserve&filter_paused=active"

            # 1. GET edit page with return_to (properly URL-encoded)
            import html as html_lib
            import urllib.parse
            encoded_return = urllib.parse.quote(return_url)
            get_resp = self.client.get(f"/services/{service_id}/edit?return_to={encoded_return}")
            self.assertEqual(get_resp.status_code, 200)
            html = get_resp.data.decode("utf-8")
            self.assertIn(f'value="{html_lib.escape(return_url)}"', html)
            self.assertIn(f'href="{html_lib.escape(return_url)}"', html)

            # 2. POST save changes and verify redirect back to return_url
            post_resp = self.client.post(
                f"/services/{service_id}/edit",
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
                f"/services/{service_id}/edit",
                data={
                    "name": "filter-preserve.com",
                    "match": "filter-preserve",
                    "return_to": "https://attacker.com/phish",
                },
                follow_redirects=False,
            )
            self.assertEqual(unsafe_resp.status_code, 302)
            self.assertEqual(unsafe_resp.location, "/services")

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
                        [{"service": "test.com", "old_status": "online", "new_status": "offline", "port_changes": []}]
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
                    [{"service": "test.com", "old_status": "online", "new_status": "offline", "port_changes": []}]
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
        c.execute("INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, 0)",
                  ("multiport.org", '[{"port": 80, "protocol": "http", "match": "multi"}, {"port": 443, "protocol": "https", "match": "multi"}]'))
        d_id = c.lastrowid
        # Port 80 checked earlier, Port 443 checked later
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 80, 1, 'online', '2026-09-29 06:00:00 UTC')", (d_id,))
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 443, 1, 'online', '2026-09-29 07:00:00 UTC')", (d_id,))
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
                    [{"service": "multiport.org", "old_status": "online", "new_status": "offline", "port_changes": []}]
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

        # 4. Test scan_service records online status
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO services (name, port_protocol) VALUES ('cam.local', '[{\"port\": 443, \"protocol\": \"https\", \"match\": \"legacy device\"}]')")
        d_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPSConnection", FakeHTTPSConnection):
            attempts.clear()
            pulsecheck_app.scan_service(d_id, "cam.local", [{"port": 443, "protocol": "https", "match": "legacy device"}])

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE service_id = ? AND port = 443 ORDER BY id DESC LIMIT 1", (d_id,)).fetchone()
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

        # 4. Test scan_service matches decompressed keyword and sets status to online
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO services (name, port_protocol) VALUES ('gzip-scan.local', '[{\"port\": 80, \"protocol\": \"http\", \"match\": \"Monitoring Target\"}]')")
        d_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            pulsecheck_app.scan_service(d_id, "gzip-scan.local", [{"port": 80, "protocol": "http", "match": "Monitoring Target"}])

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE service_id = ? AND port = 80 ORDER BY id DESC LIMIT 1", (d_id,)).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row[0], "online")
        self.assertEqual(row[1], 1)

    def test_scan_service_with_retries(self):
        # 1. Success on first attempt: no sleep, exactly 1 call
        sleep_calls = []
        scan_calls = []

        def mock_scan_success(*args, **kwargs):
            scan_calls.append(args)
            return {80: "online"}

        with patch("app.scan_service", side_effect=mock_scan_success), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_service_with_retries(
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

        with patch("app.scan_service", side_effect=mock_scan_flaky), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_service_with_retries(
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

        with patch("app.scan_service", side_effect=mock_scan_fail), patch("time.sleep", side_effect=sleep_calls.append):
            result = pulsecheck_app.scan_service_with_retries(
                {"id": 3, "name": "down.local", "ports": [80], "match": ""},
                max_retries=3,
                retry_interval=10,
            )
        self.assertEqual(result, {80: "offline"})
        self.assertEqual(len(scan_calls), 4)
        self.assertEqual(sleep_calls, [10, 10, 10])

    def test_check_all_services_parallel_execution(self):
        import threading
        # Insert 6 services into DB
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        for i in range(1, 7):
            c.execute("INSERT INTO services (name, port_protocol) VALUES (?, '[80]')", (f"dom{i}.local",))
        conn.commit()
        conn.close()

        scanned_services = []
        lock = threading.Lock()

        def mock_scan_retries(service, max_retries=3, retry_interval=10, explicit_debug=None):
            with lock:
                scanned_services.append(service["name"])
            return {80: "online"}

        with patch("app.scan_service_with_retries", side_effect=mock_scan_retries):
            pulsecheck_app.check_all_services(workers=5, max_retries=3, retry_interval=0)

        self.assertEqual(len(scanned_services), 6)
        self.assertEqual(set(scanned_services), {f"dom{i}.local" for i in range(1, 7)})

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

    @patch("app.scan_service")
    def test_service_use_proxy_database_field_and_edit(self, mock_scan):
        # 1. Add service with use_proxy default (False)
        service_id = pulsecheck_app.add_service("plain.example", paused=True)
        d = pulsecheck_app.get_service_by_id(service_id)
        self.assertFalse(d["use_proxy"])

        # 2. Update service with use_proxy=True
        pulsecheck_app.update_service(service_id, "plain.example", "80, 443", paused=True, use_proxy=True)
        d_updated = pulsecheck_app.get_service_by_id(service_id)
        self.assertTrue(d_updated["use_proxy"])

        # 3. Edit via web route POST
        response = self.client.post(f"/services/{service_id}/edit", data={
            "name": "plain.example",
            "match": "plain",
            "url_path": "",
            "comment": "Testing proxy",
            "ports": "80",
            "use_proxy": "on",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        d_web = pulsecheck_app.get_service_by_id(service_id)
        self.assertTrue(d_web["use_proxy"])

        # 4. Turn use_proxy off via web route POST (checkbox omitted)
        response = self.client.post(f"/services/{service_id}/edit", data={
            "name": "plain.example",
            "match": "plain",
            "url_path": "",
            "comment": "Testing proxy",
            "ports": "80",
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        d_web_off = pulsecheck_app.get_service_by_id(service_id)
        self.assertFalse(d_web_off["use_proxy"])

    @patch("app.scan_service")
    def test_csv_import_and_export_with_proxy_indicator(self, mock_scan):
        # Import CSV containing Proxy column
        csv_data = """Service,Match,URL path,Comment,Paused,Proxy,Ports
proxied.example,proxied,/health,Gateway,0,1,"80, 443"
direct.example,direct,,Direct site,0,0,8080
"""
        summary = pulsecheck_app.import_services_from_csv(csv_data)
        self.assertEqual(summary["imported"], 2)

        services = {d["name"]: d for d in pulsecheck_app.service_list()}
        self.assertTrue(services["proxied.example"]["use_proxy"])
        self.assertFalse(services["direct.example"]["use_proxy"])

        # Export and verify the Proxy column
        csv_text, count = pulsecheck_app.export_services_csv()
        self.assertEqual(count, 2)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response")
        self.assertIn('proxied.example,Gateway,0,1,,"80, 443",web,/health,proxied,,', lines)
        self.assertIn("direct.example,Direct site,0,0,,8080,web,,direct,,", lines)

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

    @patch("app.fetch_tcp_response")
    @patch("app.fetch_response")
    def test_scan_service_uses_proxy_and_skips_tcp_fallback(self, mock_fetch, mock_tcp):
        # Configure service in DB with use_proxy=1
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO services (name, port_protocol, use_proxy) VALUES (?, ?, 1)",
            ("proxied-host.local", '[{"port": 80, "protocol": "http", "match": "mismatch-token"}]'),
        )
        service_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Simulate fetch_response returning content that does NOT match -> status will be offline/degraded
        mock_fetch.return_value = (b"some response", 200, "http://proxied-host.local:80/")

        pulsecheck_app.scan_service(service_id, "proxied-host.local", [{"port": 80, "protocol": "http", "match": "mismatch-token"}])

        # Verify fetch_response was called with use_proxy=True
        mock_fetch.assert_called_once()
        self.assertTrue(mock_fetch.call_args.kwargs.get("use_proxy"))

        # Verify direct TCP fallback was NOT attempted
        mock_tcp.assert_not_called()

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

    def test_scan_service_matches_token_in_headers(self):
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
        c.execute("INSERT INTO services (name, port_protocol) VALUES ('header-match.local', '[{\"port\": 80, \"protocol\": \"http\", \"match\": \"WorkerNode77\"}]')")
        service_id = c.lastrowid
        conn.commit()
        conn.close()

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            pulsecheck_app.scan_service(service_id, "header-match.local", [{"port": 80, "protocol": "http", "match": "WorkerNode77"}])

        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status, is_online FROM port_checks WHERE service_id = ? AND port = 80", (service_id,)).fetchone()
        conn.close()

        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "online")
        self.assertEqual(row["is_online"], 1)

    def test_status_page_service_and_match_truncation_and_hover_box(self):
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        long_service = "really-long-subdomain-12345.production.api.internal-cloud-network.company.com"
        long_match = "Corporate Authentication Portal - Cluster Edge Node 42"
        ports_json = pulsecheck_app.port_protocol_to_json([{"port": 443, "protocol": "https", "match": long_match, "url_path": ""}])
        c.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, 0)",
            (long_service, ports_json),
        )
        d_id = c.lastrowid
        c.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 443, 1, 'online', '2026-09-29 08:00:00 UTC')",
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
        self.assertIn(long_service, html)
        self.assertIn(long_match, html)
        self.assertIn('<span class="hover-box-label">Service</span>', html)
        self.assertIn("cell-status-wrapper", html)
        self.assertIn("status-hover-box-ports", html)
        self.assertIn("Monitored Ports", html)

    def test_status_page_proxy_indicator_badge(self):
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute(
            "INSERT INTO services (name, port_protocol, paused, use_proxy) VALUES (?, ?, 0, 1)",
            ("proxied-service.internal", '[{"port": 8080, "protocol": "http", "match": "proxytoken"}]'),
        )
        d_id = c.lastrowid
        c.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 8080, 1, 'online', '2026-09-29 08:00:00 UTC')",
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
        port_protocol_val = pulsecheck_app.port_protocol_to_json([{"port": p, "protocol": "http", "match": "cluster"} for p in ports_list])
        c.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, 0)",
            ("manyports.example", port_protocol_val),
        )
        d_id = c.lastrowid
        for p in ports_list:
            c.execute(
                "INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, 1, 'online', 25, '2026-09-29 08:30:00 UTC')",
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
            self.assertIn(f">{p}:", html)

    def test_import_and_export_tabbed_page_rendering(self):
        resp = self.client.get("/import")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # 1. Verify navigation menu item is renamed to "Import & Export"
        self.assertIn(">Import &amp; Export<", html)

        # 2. Verify all 3 tab buttons exist
        self.assertIn("Quick Text Block Import", html)
        self.assertIn("CSV File Import", html)
        self.assertIn("CSV Export", html)

        # 3. Verify all 3 tab panels exist with their IDs
        self.assertIn('id="panel-text"', html)
        self.assertIn('id="panel-csv-import"', html)
        self.assertIn('id="panel-csv-export"', html)

        # 4. Verify primary forms and buttons are preserved
        self.assertIn('id="import-form"', html)
        self.assertIn('id="csv-import-form"', html)
        self.assertIn('id="btn-export-csv"', html)
        self.assertIn('id="import-overlay"', html)

    def test_settings_tabbed_page_rendering(self):
        resp = self.client.get("/settings")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # 1. Verify both tab buttons exist
        self.assertIn("E-mail &amp; SMTP Settings", html)
        self.assertIn("HTTP Proxy Server", html)

        # 2. Verify both tab panels exist with their IDs
        self.assertIn('id="panel-smtp"', html)
        self.assertIn('id="panel-proxy"', html)

        # 3. Verify SMTP fields exist
        self.assertIn('id="smtp_host"', html)
        self.assertIn('id="smtp_port"', html)
        self.assertIn('id="smtp_security"', html)
        self.assertIn('id="smtp_username"', html)
        self.assertIn('id="smtp_password"', html)
        self.assertIn('id="from_email"', html)
        self.assertIn('id="recipient_email"', html)

        # 4. Verify Proxy fields exist
        self.assertIn('id="proxy_host"', html)
        self.assertIn('id="proxy_port"', html)
        self.assertIn('id="proxy_username"', html)
        self.assertIn('id="proxy_password"', html)

        # 5. Verify action buttons
        self.assertIn("Save Settings", html)
        self.assertIn("Send Test Email", html)

    def test_notification_email_body_logo_and_status_colors(self):
        with patch("app.send_email") as mock_email, patch("app.get_settings") as mock_settings:
            mock_settings.return_value = {
                "smtp_host": "smtp.example.com",
                "recipient_email": "alerts@test.com",
            }
            mock_email.return_value = (True, "OK")

            changes = [
                {
                    "service": "srv-down.com",
                    "old_status": "online",
                    "new_status": "offline",
                    "port_changes": ["Port 80: ONLINE -> OFFLINE"],
                },
                {
                    "service": "srv-degraded.com",
                    "old_status": "online",
                    "new_status": "degraded",
                    "port_changes": ["Port 443: ONLINE -> OFFLINE"],
                },
                {
                    "service": "srv-up.com",
                    "old_status": "offline",
                    "new_status": "online",
                    "port_changes": ["Port 80: OFFLINE -> ONLINE"],
                },
            ]

            success, msg = pulsecheck_app.send_state_change_notification(changes)
            self.assertTrue(success)
            mock_email.assert_called_once()

            call_args = mock_email.call_args
            to_addr = call_args[0][0]
            subject = call_args[0][1]
            body = call_args[0][2]
            html_body = call_args[1].get("html_body", "")

            self.assertEqual(to_addr, "alerts@test.com")
            self.assertIn("3 services updated", subject)

            # Check plain-text body format
            self.assertIn("• Service: srv-down.com [OFFLINE]", body)
            self.assertIn("• Service: srv-degraded.com [DEGRADED]", body)
            self.assertIn("• Service: srv-up.com [ONLINE]", body)

            # Check HTML logo size (constrained to 28x28)
            self.assertIn('width="28" height="28"', html_body)
            self.assertIn('max-width: 28px', html_body)
            self.assertIn('max-height: 28px', html_body)

            # Check status badge colors: RED=OFFLINE, ORANGE=DEGRADED, GREEN=ONLINE
            # OFFLINE should use red (#dc2626)
            self.assertIn('background-color: #dc2626; color: #ffffff; vertical-align: middle;">OFFLINE</span>', html_body)
            # DEGRADED should use orange (#ea580c)
            self.assertIn('background-color: #ea580c; color: #ffffff; vertical-align: middle;">DEGRADED</span>', html_body)
            # ONLINE should use green (#16a34a)
            self.assertIn('background-color: #16a34a; color: #ffffff; vertical-align: middle;">ONLINE</span>', html_body)

            # Service name and status badge should be grouped together in the card header
            self.assertIn('srv-down.com</strong>\n    <span style="display: inline-block;', html_body)

            # Check that version number is displayed in plain text and HTML header
            self.assertIn(f"PulseCheck v{pulsecheck_app.APP_VERSION}", body)
            self.assertIn(f"v{pulsecheck_app.APP_VERSION}", html_body)
            self.assertIn(f'PulseCheck</span>\n            <span style="display: inline-block; margin-left: 8px; font-size: 11px;', html_body)

    def test_version_number_display_and_config(self):
        # Verify app version exists and is non-empty
        self.assertTrue(hasattr(pulsecheck_app, "APP_VERSION"))
        self.assertTrue(pulsecheck_app.APP_VERSION)

        # Check template context processor provides version
        with pulsecheck_app.app.test_request_context():
            context = pulsecheck_app.inject_version()
            self.assertEqual(context.get("app_version"), pulsecheck_app.APP_VERSION)
            self.assertEqual(context.get("version"), pulsecheck_app.APP_VERSION)

        # Check web UI status page renders version badge
        response = self.client.get("/status")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")
        self.assertIn(f'<span class="brand-version">v{pulsecheck_app.APP_VERSION}</span>', html)

        # Check services and settings pages also render version badge via base template
        for path in ("/services", "/settings", "/import"):
            resp = self.client.get(path)
            self.assertEqual(resp.status_code, 200)
            self.assertIn(f'<span class="brand-version">v{pulsecheck_app.APP_VERSION}</span>', resp.data.decode("utf-8"))

    def test_status_header_meta_and_overall_status_indicators(self):
        # 1. Fresh database with no services
        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")
        self.assertIn("status-header-panel", html)
        self.assertIn("status-header-meta", html)
        self.assertIn("countdown-display", html)
        self.assertIn("NO SERVICES", html)

        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        # Service 1: No ports listed -> MUST BE IGNORED
        c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('noports.internal', '[]', 0)")

        # Service 2: Port 80 online
        c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('alpha.online.net', '[{\"port\": 80, \"protocol\": \"http\", \"match\": \"alpha\"}]', 0)")
        s2_id = c.lastrowid
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 80, 1, 'online', '2026-09-30 12:00:00 UTC')", (s2_id,))

        # Service 3: Port 443 online
        c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('beta.online.net', '[{\"port\": 443, \"protocol\": \"https\", \"match\": \"beta\"}]', 0)")
        s3_id = c.lastrowid
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 443, 1, 'online', '2026-09-30 12:05:00 UTC')", (s3_id,))
        conn.commit()
        conn.close()

        # Record a scan completed timestamp in settings
        pulsecheck_app.record_scan_completed(datetime(2026, 9, 30, 12, 10, 0, tzinfo=timezone.utc))

        with patch.dict(os.environ, {"PULSECHECK_TIMEZONE": "Africa/Johannesburg"}):
            # All monitored services are online -> GREEN "ALL ONLINE"
            resp = self.client.get("/status")
            self.assertEqual(resp.status_code, 200)
            html = resp.data.decode("utf-8")
            self.assertIn("ALL ONLINE", html)
            self.assertIn("overall-status-icon online", html)
            # Local timezone timestamp (12:10 UTC -> 14:10 SAST)
            self.assertIn("2026-09-30 14:10:00 SAST", html)

            # Verify colorized filter pills and counters
            self.assertIn("pill-all", html)
            self.assertIn("pill-online", html)
            self.assertIn("pill-degraded", html)
            self.assertIn("pill-offline", html)

            # Add Service 4: Degraded (port 80 online, port 8080 degraded with match failure)
            conn = pulsecheck_app.get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('gamma.mixed.net', '[{\"port\": 80, \"protocol\": \"http\", \"match\": \"gamma\"}, {\"port\": 8080, \"protocol\": \"http\", \"match\": \"gamma\"}]', 0)")
            s4_id = c.lastrowid
            c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 80, 1, 'online', '2026-09-30 12:15:00 UTC')", (s4_id,))
            c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 8080, 1, 'degraded', '2026-09-30 12:15:00 UTC')", (s4_id,))
            conn.commit()
            conn.close()

            # Some degraded, none offline -> ORANGE "SOME DEGRADED"
            resp_deg = self.client.get("/status")
            html_deg = resp_deg.data.decode("utf-8")
            self.assertIn("SOME DEGRADED", html_deg)
            self.assertIn("overall-status-icon degraded", html_deg)

            # Add Service 5: Offline (port 9000 offline)
            conn = pulsecheck_app.get_db_connection()
            c = conn.cursor()
            c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('delta.down.net', '[{\"port\": 9000, \"protocol\": \"http\", \"match\": \"delta\"}]', 0)")
            s5_id = c.lastrowid
            c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 9000, 0, 'offline', '2026-09-30 12:20:00 UTC')", (s5_id,))
            conn.commit()
            conn.close()

            # Now an offline service exists -> RED "SOME OFFLINE"
            resp_off = self.client.get("/status")
            html_off = resp_off.data.decode("utf-8")
            self.assertIn("SOME OFFLINE", html_off)
            self.assertIn("overall-status-icon offline", html_off)

    def test_status_check_state_api(self):
        # Set up a known scan completion time
        pulsecheck_app.record_scan_completed(datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc))

        with patch.dict(os.environ, {"PULSECHECK_TIMEZONE": "UTC"}):
            resp = self.client.get("/status/check-state")
            self.assertEqual(resp.status_code, 200)
            data = resp.get_json()
            self.assertIn("2026-09-30 10:00:00 UTC", data["last_check_formatted"])
            self.assertIsNotNone(data["last_check_timestamp"])
            self.assertIsInstance(data["next_check_seconds"], int)
            self.assertIn("is_scanning", data)
            self.assertIn("overall_status", data)
            self.assertIn("overall_label", data)

    def test_check_all_services_records_scan_completed(self):
        # Verify check_all_services invokes record_scan_completed and resets IS_SCANNING
        with patch("app.scan_service_with_retries") as mock_scan:
            mock_scan.return_value = {}
            pulsecheck_app.check_all_services()

        self.assertFalse(pulsecheck_app.IS_SCANNING)
        last_check = pulsecheck_app.get_last_scheduled_check()
        self.assertIsNotNone(last_check["timestamp"])
        self.assertNotEqual(last_check["formatted"], "Never")


    def test_notification_port_details_colorized_and_icmp(self):
        """Verify:
        1) Port Details in notification HTML body are colorized red (#dc2626), orange (#ea580c), and green (#16a34a).
        2) ICMP Ping probe (portless) is formatted without a port number and is colorized red or green.
        """
        pulsecheck_app.save_settings({
            "smtp_host": "smtp.example.com",
            "from_email": "alerts@test.com",
            "recipient_email": "admin@test.com",
        })

        changes = [
            {
                "service": "mixed-node.example.com",
                "old_status": "online",
                "new_status": "degraded",
                "port_changes": [
                    "Port 80: ONLINE -> OFFLINE",
                    "Port 443: ONLINE -> DEGRADED",
                    "Port 8080: OFFLINE -> ONLINE",
                    "ICMP Ping: ONLINE -> OFFLINE",
                ],
            }
        ]

        with patch("app.send_email") as mock_email:
            mock_email.return_value = (True, "Sent")
            success, msg = pulsecheck_app.send_state_change_notification(changes)
            self.assertTrue(success)
            mock_email.assert_called_once()

            call_args = mock_email.call_args
            body = call_args[0][2]
            html_body = call_args[1].get("html_body", "")

            # Verify plain text contains port changes and ICMP Ping
            self.assertIn("Port Details:", body)
            self.assertIn("Port 80: ONLINE -> OFFLINE", body)
            self.assertIn("Port 443: ONLINE -> DEGRADED", body)
            self.assertIn("Port 8080: OFFLINE -> ONLINE", body)
            self.assertIn("ICMP Ping: ONLINE -> OFFLINE", body)

            # Verify HTML body contains Port Details with colored text
            self.assertIn("Port Details:", html_body)
            # Port 80: ONLINE (green #16a34a) -> OFFLINE (red #dc2626)
            self.assertIn("<strong style='color: #1e293b;'>Port 80:</strong>", html_body)
            self.assertIn("<strong style='color: #16a34a;'>ONLINE</strong> &rarr; <strong style='color: #dc2626;'>OFFLINE</strong>", html_body)

            # Port 443: ONLINE (green #16a34a) -> DEGRADED (orange #ea580c)
            self.assertIn("<strong style='color: #1e293b;'>Port 443:</strong>", html_body)
            self.assertIn("<strong style='color: #16a34a;'>ONLINE</strong> &rarr; <strong style='color: #ea580c;'>DEGRADED</strong>", html_body)

            # Port 8080: OFFLINE (red #dc2626) -> ONLINE (green #16a34a)
            self.assertIn("<strong style='color: #1e293b;'>Port 8080:</strong>", html_body)
            self.assertIn("<strong style='color: #dc2626;'>OFFLINE</strong> &rarr; <strong style='color: #16a34a;'>ONLINE</strong>", html_body)

            # ICMP Ping: ONLINE (green #16a34a) -> OFFLINE (red #dc2626)
            self.assertIn("<strong style='color: #1e293b;'>ICMP Ping:</strong>", html_body)
            self.assertIn("<strong style='color: #16a34a;'>ONLINE</strong> &rarr; <strong style='color: #dc2626;'>OFFLINE</strong>", html_body)


    def test_status_page_offline_overrides_degraded(self):
        """Verify that on the Status page, a service with 2 or more ports/probes
        where 1 is OFFLINE and another is DEGRADED is marked OFFLINE at the service level.
        """
        conn = pulsecheck_app.get_db_connection()
        c = conn.cursor()
        c.execute("INSERT INTO services (name, port_protocol, paused) VALUES ('offline-overrides.example', '[{\"port\": 80, \"protocol\": \"http\", \"match\": \"test\"}, {\"port\": 443, \"protocol\": \"https\", \"match\": \"test\"}]', 0)")
        s_id = c.lastrowid
        # Port 80 is degraded, Port 443 is offline
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 80, 1, 'degraded', '2026-10-01 10:00:00 UTC')", (s_id,))
        c.execute("INSERT INTO port_checks (service_id, port, is_online, status, checked_at) VALUES (?, 443, 0, 'offline', '2026-10-01 10:00:00 UTC')", (s_id,))
        conn.commit()
        conn.close()

        resp = self.client.get("/status")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        # The row for offline-overrides.example must have data-status="offline"
        self.assertIn('data-service="offline-overrides.example"  data-status="offline"', html)


    def test_icon_management_mappings_crud_and_reset(self):
        # 1. Get default mappings
        res = self.client.get("/api/settings/icons/mappings")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertIn("cisco", data["known_manufacturer_domains"])
        self.assertIn("routerboard", data["manufacturer_name_aliases"])
        self.assertIn("shenzhen", data["regional_prefixes"])
        self.assertIn("bitwarden", data["known_service_domains"])
        self.assertTrue(len(data["html_content_icon_mappings"]) > 0)

        # 2. Save custom mapping
        custom_mfg = {"testbrand": "testbrand.com"}
        save_res = self.client.post(
            "/api/settings/icons/mappings/save",
            json={"type": "known_manufacturer_domains", "data": custom_mfg},
        )
        self.assertEqual(save_res.status_code, 200)
        self.assertTrue(save_res.get_json()["success"])

        # Verify saved in getter
        updated_mfg = pulsecheck_app.get_known_manufacturer_domains()
        self.assertEqual(updated_mfg.get("testbrand"), "testbrand.com")

        # Save custom aliases
        custom_alias = {"my-router": "RouterCorp"}
        save_alias_res = self.client.post(
            "/api/settings/icons/mappings/save",
            json={"type": "manufacturer_name_aliases", "data": custom_alias},
        )
        self.assertEqual(save_alias_res.status_code, 200)
        self.assertTrue(save_alias_res.get_json()["success"])
        updated_aliases = pulsecheck_app.get_manufacturer_name_aliases()
        self.assertEqual(updated_aliases.get("my-router"), "RouterCorp")
        self.assertEqual(pulsecheck_app.slugify_manufacturer("my-router"), "routercorp")

        # 3. Reset mapping to defaults
        reset_res = self.client.post(
            "/api/settings/icons/mappings/reset",
            json={"type": "known_manufacturer_domains"},
        )
        self.assertEqual(reset_res.status_code, 200)
        self.assertTrue(reset_res.get_json()["success"])
        reset_mfg = pulsecheck_app.get_known_manufacturer_domains()
        self.assertIn("cisco", reset_mfg)
        self.assertNotIn("testbrand", reset_mfg)

        reset_alias_res = self.client.post(
            "/api/settings/icons/mappings/reset",
            json={"type": "manufacturer_name_aliases"},
        )
        self.assertEqual(reset_alias_res.status_code, 200)
        self.assertTrue(reset_alias_res.get_json()["success"])
        reset_aliases = pulsecheck_app.get_manufacturer_name_aliases()
        self.assertIn("routerboard", reset_aliases)
        self.assertNotIn("my-router", reset_aliases)

    def test_icon_management_file_operations(self):
        # Create a mock icon file in MANUFACTURER_ICONS_DIR
        test_file = pulsecheck_app.MANUFACTURER_ICONS_DIR / "dummy_test_mfg.png"
        test_file.write_bytes(b"\x89PNG\r\n\x1a\n" + b"x" * 100)

        # List icons
        res = self.client.get("/api/settings/icons/list?category=manufacturer")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        filenames = [i["filename"] for i in data["icons"]]
        self.assertIn("dummy_test_mfg.png", filenames)

        # Test path traversal prevention on delete-one
        bad_del = self.client.post(
            "/api/settings/icons/delete-one",
            json={"category": "manufacturer", "filename": "../somefile.txt"},
        )
        self.assertEqual(bad_del.status_code, 400)

        # Test single delete
        del_res = self.client.post(
            "/api/settings/icons/delete-one",
            json={"category": "manufacturer", "filename": "dummy_test_mfg.png"},
        )
        self.assertEqual(del_res.status_code, 200)
        self.assertFalse(test_file.exists())

    def test_icon_management_regeneration_and_status(self):
        # Get status endpoint
        res = self.client.get("/api/settings/icons/status")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("manufacturer", data)
        self.assertIn("service", data)

        # Trigger regeneration
        regen_res = self.client.post(
            "/api/settings/icons/regenerate",
            json={"category": "manufacturer"},
        )
        self.assertEqual(regen_res.status_code, 200)
        self.assertTrue(regen_res.get_json()["success"])

        # Second trigger should mark queued
        queue_res = self.client.post(
            "/api/settings/icons/regenerate",
            json={"category": "manufacturer"},
        )
        self.assertEqual(queue_res.status_code, 200)
        q_data = queue_res.get_json()
        self.assertTrue(q_data["success"])
        # Either queued or completed fast
        self.assertIn(q_data["queued"], (True, False))


if __name__ == "__main__":
    unittest.main()



