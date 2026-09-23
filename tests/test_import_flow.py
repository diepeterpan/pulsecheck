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


if __name__ == "__main__":
    unittest.main()
