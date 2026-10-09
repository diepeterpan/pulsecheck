import io
import os
import tempfile
import unittest
from unittest.mock import patch

import app as pulsecheck_app


class ImportFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = pulsecheck_app.DB_PATH
        pulsecheck_app.DB_PATH = os.path.join(self.temp_dir.name, "pulsecheck.db")
        pulsecheck_app.init_db()

    def tearDown(self):
        pulsecheck_app.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    @patch("app.discover_ports", return_value=[80, 443])
    def test_import_skips_duplicate_names_and_tracks_summary(self, mock_discover):
        pulsecheck_app.add_service("example.com")

        result = pulsecheck_app.import_service_names([
            "example.com",
            "example.org",
            "mail.example.org",
        ])

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(len(pulsecheck_app.service_list()), 3)

    def test_paused_services_are_not_scanned_or_shown_in_status(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, ?)",
            ("paused.example", '[{"port": 443, "protocol": "", "match": "paused", "url_path": ""}]', 1),
        )
        service_id = cursor.lastrowid
        conn.commit()
        conn.close()

        with patch("app.fetch_response") as fetch:
            pulsecheck_app.scan_service(service_id, "paused.example", [443], "paused")
        fetch.assert_not_called()
        self.assertEqual(pulsecheck_app.get_status_rows(), [])

    def test_update_service_preserves_paused_when_not_specified(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol, paused) VALUES (?, ?, ?)",
            ("paused.example", '[{"port": 443, "protocol": "", "match": "paused", "url_path": ""}]', 1),
        )
        service_id = cursor.lastrowid
        conn.commit()
        conn.close()

        with patch("app.scan_service"):
            pulsecheck_app.update_service(service_id, "paused.example", "443")

        self.assertTrue(pulsecheck_app.get_service_by_id(service_id)["paused"])

    def test_scan_classifies_server_response_against_match(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol) VALUES (?, ?)",
            ("acme.example", '[{"port": 80, "protocol": "http", "match": "acme"}, {"port": 443, "protocol": "http", "match": "acme"}, {"port": 22, "protocol": "http", "match": "acme"}]'),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        responses = [
            (b"acme service", 200, "http://acme.example:80/"),
            (b"other service", 200, "http://acme.example:443/"),
            (b"other HTTPS service", 200, "https://acme.example:443/"),
            (b"", 0, "http://acme.example:22/"),
        ]
        with patch("app.fetch_response", side_effect=responses), patch(
            "app.fetch_tcp_response", side_effect=[b"", b""]
        ):
            pulsecheck_app.scan_service(service_id, "acme.example", [{"port": 80, "protocol": "http"}, {"port": 443, "protocol": "http"}, {"port": 22, "protocol": "http"}], "acme")

        conn = pulsecheck_app.get_db_connection()
        statuses = [row["status"] for row in conn.execute(
            "SELECT status FROM port_checks WHERE service_id = ? ORDER BY port",
            (service_id,),
        ).fetchall()]
        conn.close()
        self.assertEqual(statuses, ["offline", "online", "degraded"])

    def test_scan_attempts_https_after_http_timeout(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol) VALUES (?, ?)",
            ("acme.example", '[{"port": 443, "protocol": "http", "match": "acme"}]'),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        with patch(
            "app.fetch_response",
            side_effect=[
                TimeoutError("HTTP timed out"),
                (b"acme HTTPS service", 200, "https://acme.example:443/"),
            ],
        ) as fetch:
            pulsecheck_app.scan_service(service_id, "acme.example", [{"port": 443, "protocol": "http"}], "acme")

        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(fetch.call_args_list[1].args[2], "https")
        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE service_id = ?",
            (service_id,),
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "online")

    def test_scan_uses_tcp_fallback_when_http_and_https_do_not_match(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol) VALUES (?, ?)",
            ("acme.example", '[{"port": 443, "protocol": "tcp", "match": "acme"}]'),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        with patch("app.fetch_tcp_response", return_value=b"acme tcp service"):
            pulsecheck_app.scan_service(service_id, "acme.example", [{"port": 443, "protocol": "tcp"}], "acme")

        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE service_id = ?",
            (service_id,),
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "online")

    def test_scan_uses_tcp_ssl_fallback_when_plain_tcp_fails(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, port_protocol) VALUES (?, ?)",
            ("acme.example", '[{"port": 443, "protocol": "tcp-ssl", "match": "acme"}]'),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        with patch(
            "app.fetch_tcp_ssl_response", return_value=b"acme TCP SSL service"
        ):
            pulsecheck_app.scan_service(service_id, "acme.example", [{"port": 443, "protocol": "tcp-ssl"}], "acme")

        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE service_id = ?",
            (service_id,),
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "online")

    def test_fetch_response_follows_redirect_before_returning_body(self):
        class FakeResponse:
            def __init__(self, status, body, location=None):
                self.status = status
                self._body = body
                self._location = location

            def read(self, size):
                return self._body

            def getheader(self, name):
                return self._location if name == "Location" else None

        class FakeHTTPConnection:
            responses = [
                FakeResponse(302, b"", "/health"),
                FakeResponse(200, b"acme service"),
            ]

            def __init__(self, host, port, **kwargs):
                pass

            def request(self, method, path, headers):
                pass

            def getresponse(self):
                return self.responses.pop(0)

            def close(self):
                pass

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            response, status_code, final_url = pulsecheck_app.fetch_response(
                "acme.example", 80, "http"
            )

        self.assertEqual(response, b"acme service")
        self.assertEqual(status_code, 200)
        self.assertEqual(final_url, "http://acme.example:80/health")

    def test_url_path_validation(self):
        self.assertEqual(pulsecheck_app.normalize_url_path("/test/test.asp"), "/test/test.asp")
        self.assertEqual(pulsecheck_app.normalize_url_path("/test?value=1"), "/test?value=1")
        self.assertEqual(pulsecheck_app.normalize_url_path("/test/test.asp?foo=bar&baz=1"), "/test/test.asp?foo=bar&baz=1")
        self.assertEqual(pulsecheck_app.normalize_url_path("?value=1"), "/?value=1")
        self.assertEqual(pulsecheck_app.normalize_url_path("/?value=1"), "/?value=1")
        self.assertEqual(pulsecheck_app.normalize_url_path(""), "")
        for invalid_path in ("test.asp", "/test path", "https://example.com/test", "//example.com/test", "/test#fragment", "/test?value=1#fragment"):
            with self.subTest(invalid_path=invalid_path):
                with self.assertRaises(ValueError):
                    pulsecheck_app.normalize_url_path(invalid_path)

    def test_format_local_time_converts_stored_utc_timestamp(self):
        formatted = pulsecheck_app.format_local_time("2026-09-24 12:00:00 UTC")
        self.assertTrue(formatted.startswith("2026-09-24 "))
        self.assertRegex(formatted, r"^2026-09-24 \d{2}:\d{2}:\d{2} .+$")

    def test_fetch_response_starts_with_configured_url_path(self):
        class FakeResponse:
            status = 200

            def read(self, size):
                return b"acme service"

            def getheader(self, name):
                return None

        class FakeHTTPConnection:
            last_request_path = None

            def __init__(self, host, port, **kwargs):
                pass

            def request(self, method, path, headers):
                FakeHTTPConnection.last_request_path = path

            def getresponse(self):
                return FakeResponse()

            def close(self):
                pass

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection):
            pulsecheck_app.fetch_response("acme.example", 80, "http", "/test/test.asp?token=123")

        self.assertEqual(FakeHTTPConnection.last_request_path, "/test/test.asp?token=123")

    def test_fetch_response_logs_errors_before_close_only_in_debug_mode(self):
        events = []

        class FakeHTTPConnection:
            def __init__(self, host, port, **kwargs):
                pass

            def request(self, method, path, headers):
                raise OSError("connection reset")

            def close(self):
                events.append("close")

        with patch("app.http.client.HTTPConnection", FakeHTTPConnection), patch(
            "builtins.print", side_effect=lambda *args: events.append(args[0])
        ):
            with self.assertRaisesRegex(OSError, "connection reset"):
                pulsecheck_app.fetch_response("acme.example", 80, "http", explicit_debug=True)

        self.assertIn("error=OSError('connection reset')", events[0])
        self.assertEqual(events[1], "close")

        events.clear()
        with patch("app.http.client.HTTPConnection", FakeHTTPConnection), patch(
            "builtins.print", side_effect=lambda *args: events.append(args[0])
        ) as debug_print:
            with self.assertRaisesRegex(OSError, "connection reset"):
                pulsecheck_app.fetch_response("acme.example", 80, "http")

        debug_print.assert_not_called()
        self.assertEqual(events, ["close"])

    def test_quick_text_import_triggers_discovery_and_scans(self):
        with patch("app.discover_ports", return_value=[{"port": 80, "protocol": "http"}]) as mock_disc, \
             patch("app.diagnose_service_ports", return_value={"ports": [{"port": 80, "status": "online", "protocol": "http"}]}) as mock_diag, \
             patch("app.trigger_discovery_async") as mock_sched, \
             patch("app.trigger_service_icon_resolution_async") as mock_icon, \
             patch("app.scan_service") as mock_scan:

            summary = pulsecheck_app.import_service_names(["new-quick-service.internal"])

            self.assertEqual(summary["imported"], 1)
            mock_disc.assert_called_once()
            self.assertEqual(mock_disc.call_args[0][0], "new-quick-service.internal")
            mock_diag.assert_called_once()
            mock_sched.assert_called_once_with(mock_sched.call_args[0][0], "new-quick-service.internal")
            mock_icon.assert_called_once_with("new-quick-service.internal")
            mock_scan.assert_called_once()

    def test_csv_password_encryption_and_decryption_helpers(self):
        raw_pwd = "MySuperSecretPassword#123"
        key = "CorrectHorseBatteryStaple"

        token = pulsecheck_app.encrypt_csv_password(raw_pwd, key)
        self.assertTrue(token.startswith("ENC:v1:"))
        self.assertTrue(pulsecheck_app.has_encrypted_csv_fields(f"Service,HTTP Password\nfoo,{token}"))

        # Decrypt with correct key
        decrypted = pulsecheck_app.decrypt_csv_password(token, key)
        self.assertEqual(decrypted, raw_pwd)

        # Decrypt with incorrect key raises EncryptedPasswordError
        with self.assertRaises(pulsecheck_app.EncryptedPasswordError):
            pulsecheck_app.decrypt_csv_password(token, "WrongPassword")

        # Empty password handling
        self.assertEqual(pulsecheck_app.encrypt_csv_password("", key), "")
        self.assertEqual(pulsecheck_app.decrypt_csv_password("", key), "")

    @patch("app.trigger_service_icon_resolution_async")
    @patch("app.trigger_discovery_async")
    @patch("app.scan_service")
    def test_csv_export_and_import_with_encrypted_passwords(self, mock_scan, mock_disc, mock_icon):
        # 1. Insert service with HTTP Basic Auth credentials
        conn = pulsecheck_app.get_db_connection()
        p_json = pulsecheck_app.port_protocol_to_json([{"port": 443, "protocol": "https", "match": "api", "url_path": "/"}])
        conn.execute(
            "INSERT INTO services (name, comment, paused, use_proxy, request_type, port_protocol, http_username, http_password) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            ("secure-api.internal", "Auth Service", 0, 0, "web", p_json, "admin_user", "SecretPass!"),
        )
        conn.commit()
        conn.close()

        # 2. Export with encryption password
        export_csv, count = pulsecheck_app.export_services_csv(encryption_password="ExportKey456")
        self.assertEqual(count, 1)
        self.assertIn("admin_user", export_csv)
        self.assertIn("ENC:v1:", export_csv)
        self.assertNotIn("SecretPass!", export_csv)

        # Check has_encrypted_csv_fields detects it
        self.assertTrue(pulsecheck_app.has_encrypted_csv_fields(export_csv))

        # 3. Clear services in DB
        conn = pulsecheck_app.get_db_connection()
        conn.execute("DELETE FROM services")
        conn.commit()
        conn.close()

        # 4. Import without password fails / raises EncryptedPasswordError
        with self.assertRaises(pulsecheck_app.EncryptedPasswordError):
            pulsecheck_app.import_services_from_csv(export_csv, decryption_password="")

        # 5. Import with wrong password fails / raises EncryptedPasswordError
        with self.assertRaises(pulsecheck_app.EncryptedPasswordError):
            pulsecheck_app.import_services_from_csv(export_csv, decryption_password="WrongKey")

        # 6. Import with correct password succeeds
        res = pulsecheck_app.import_services_from_csv(export_csv, decryption_password="ExportKey456")
        self.assertEqual(res["imported"], 1)

        svcs = pulsecheck_app.service_list()
        self.assertEqual(len(svcs), 1)
        imported_svc = svcs[0]
        self.assertEqual(imported_svc["name"], "secure-api.internal")
        self.assertEqual(imported_svc["http_username"], "admin_user")
        self.assertEqual(imported_svc["http_password"], "SecretPass!")

    def test_start_csv_import_endpoint_with_special_character_password(self):
        c = pulsecheck_app.app.test_client()
        csv_text = "Service,HTTP Username,HTTP Password\nspecial.local,user," + pulsecheck_app.encrypt_csv_password("mySecret", "@Password456") + "\n"
        data = {
            "csv_file": (io.BytesIO(csv_text.encode("utf-8")), "special.csv"),
            "decryption_password": "@Password456",
        }
        res = c.post("/import/csv/start", data=data)
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.get_json()["status"], "started")

    @patch("app.trigger_service_icon_resolution_async")
    @patch("app.trigger_discovery_async")
    @patch("app.scan_service")
    def test_csv_import_legacy_formats_backwards_compatible(self, mock_scan, mock_disc, mock_icon):
        # 11 columns legacy format (no auth columns)
        legacy_csv = """Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response
legacy-1.local,Test 1,0,0,http,80,web,/status,ok,,
"""
        res = pulsecheck_app.import_services_from_csv(legacy_csv)
        self.assertEqual(res["imported"], 1)
        svc = pulsecheck_app.service_list()[0]
        self.assertEqual(svc["name"], "legacy-1.local")
        self.assertEqual(svc["http_username"], "")
        self.assertEqual(svc["http_password"], "")


if __name__ == "__main__":
    unittest.main()

