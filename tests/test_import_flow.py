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

        class FakeConnection:
            def __init__(self, response):
                self.response = response

            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc_value, traceback):
                return False

            def sendall(self, data):
                pass

            def recv(self, size):
                return self.response

        class FakeSSLContext:
            check_hostname = True
            verify_mode = None

            def wrap_socket(self, connection, server_hostname):
                return connection

        responses = [
            b"HTTP/1.0 200 OK\r\n\r\nacme service",
            b"HTTP/1.0 200 OK\r\n\r\nother service",
            b"HTTP/1.0 200 OK\r\n\r\nother HTTPS service",
            b"",
        ]
        with patch(
            "app.socket.create_connection",
            side_effect=[FakeConnection(response) for response in responses],
        ), patch("app.ssl.create_default_context", return_value=FakeSSLContext()):
            pulsecheck_app.scan_domain(domain_id, "acme.example", [80, 443, 22], "acme")

        conn = pulsecheck_app.get_db_connection()
        statuses = [row["status"] for row in conn.execute(
            "SELECT status FROM port_checks WHERE domain_id = ? ORDER BY port",
            (domain_id,),
        ).fetchall()]
        conn.close()
        self.assertEqual(statuses, ["offline", "online", "degraded"])


if __name__ == "__main__":
    unittest.main()
