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

    def test_import_skips_duplicate_names_and_tracks_summary(self):
        pulsecheck_app.add_domain("example.com")

        result = pulsecheck_app.import_domain_names([
            "example.com",
            "example.org",
            "mail.example.org",
        ])

        self.assertEqual(result["total"], 3)
        self.assertEqual(result["imported"], 2)
        self.assertEqual(result["skipped"], 1)
        self.assertEqual(len(pulsecheck_app.domain_list()), 3)

    def test_paused_domains_are_not_scanned_or_shown_in_status(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, ports, paused) VALUES (?, ?, ?, ?)",
            ("paused.example", "paused", "[443]", 1),
        )
        domain_id = cursor.lastrowid
        conn.commit()
        conn.close()

        with patch("app.fetch_response") as fetch:
            pulsecheck_app.scan_domain(domain_id, "paused.example", [443], "paused")
        fetch.assert_not_called()
        self.assertEqual(pulsecheck_app.get_status_rows(), [])

    def test_update_domain_preserves_paused_when_not_specified(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, url_path, ports, paused) VALUES (?, ?, ?, ?, ?)",
            ("paused.example", "paused", "", "[443]", 1),
        )
        domain_id = cursor.lastrowid
        conn.commit()
        conn.close()

        with patch("app.scan_domain"):
            pulsecheck_app.update_domain(domain_id, "paused.example", "443")

        self.assertTrue(pulsecheck_app.get_domain_by_id(domain_id)["paused"])

    def test_scan_classifies_server_response_against_match(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, ports) VALUES (?, ?, ?)",
            ("acme.example", "acme", "[80, 443, 22]"),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()

        responses = [
            (b"acme service", 200, "http://acme.example:80/"),
            (b"other service", 200, "http://acme.example:443/"),
            (b"other HTTPS service", 200, "https://acme.example:443/"),
            (b"", 0, "http://acme.example:22/"),
        ]
        with patch("app.fetch_response", side_effect=responses), patch(
            "app.fetch_socket_response", side_effect=[b"", b""]
        ):
            pulsecheck_app.scan_domain(domain_id, "acme.example", [80, 443, 22], "acme")

        conn = pulsecheck_app.get_db_connection()
        statuses = [row["status"] for row in conn.execute(
            "SELECT status FROM port_checks WHERE domain_id = ? ORDER BY port",
            (domain_id,),
        ).fetchall()]
        conn.close()
        self.assertEqual(statuses, ["offline", "online", "degraded"])

    def test_scan_attempts_https_after_http_timeout(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, ports) VALUES (?, ?, ?)",
            ("acme.example", "acme", "[443]"),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()

        with patch(
            "app.fetch_response",
            side_effect=[
                TimeoutError("HTTP timed out"),
                (b"acme HTTPS service", 200, "https://acme.example:443/"),
            ],
        ) as fetch:
            pulsecheck_app.scan_domain(domain_id, "acme.example", [443], "acme")

        self.assertEqual(fetch.call_count, 2)
        self.assertEqual(fetch.call_args_list[1].args[2], "https")
        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE domain_id = ?",
            (domain_id,),
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "online")

    def test_scan_uses_socket_fallback_when_http_and_https_do_not_match(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, ports) VALUES (?, ?, ?)",
            ("acme.example", "acme", "[443]"),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()

        with patch(
            "app.fetch_response",
            side_effect=[
                (b"other HTTP service", 200, "http://acme.example:443/"),
                (b"other HTTPS service", 200, "https://acme.example:443/"),
            ],
        ), patch("app.fetch_socket_response", return_value=b"acme socket service"):
            pulsecheck_app.scan_domain(domain_id, "acme.example", [443], "acme")

        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE domain_id = ?",
            (domain_id,),
        ).fetchone()["status"]
        conn.close()
        self.assertEqual(status, "online")

    def test_scan_uses_ssl_socket_fallback_when_plain_socket_fails(self):
        conn = pulsecheck_app.get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, ports) VALUES (?, ?, ?)",
            ("acme.example", "acme", "[443]"),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()

        with patch(
            "app.fetch_response",
            side_effect=[
                (b"other HTTP service", 200, "http://acme.example:443/"),
                (b"other HTTPS service", 200, "https://acme.example:443/"),
            ],
        ), patch("app.fetch_socket_response", side_effect=OSError("plain socket failed")), patch(
            "app.fetch_socket_ssl_response", return_value=b"acme SSL socket service"
        ):
            pulsecheck_app.scan_domain(domain_id, "acme.example", [443], "acme")

        conn = pulsecheck_app.get_db_connection()
        status = conn.execute(
            "SELECT status FROM port_checks WHERE domain_id = ?",
            (domain_id,),
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
        self.assertEqual(pulsecheck_app.normalize_url_path(""), "")
        for invalid_path in ("test.asp", "/test path", "/test?value=1", "https://example.com/test"):
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
            pulsecheck_app.fetch_response("acme.example", 80, "http", "/test/test.asp")

        self.assertEqual(FakeHTTPConnection.last_request_path, "/test/test.asp")

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


if __name__ == "__main__":
    unittest.main()
