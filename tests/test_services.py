import io
import json
import os
import socket
import tempfile
import unittest
from unittest.mock import patch

import app as pulsecheck_app



class ServiceTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.original_db = pulsecheck_app.DB_PATH
        pulsecheck_app.DB_PATH = os.path.join(self.temp_dir.name, "pulsecheck.db")
        pulsecheck_app.init_db()
        self.client = pulsecheck_app.app.test_client()

    def tearDown(self):
        pulsecheck_app.DB_PATH = self.original_db
        self.temp_dir.cleanup()

    def test_normalize_service(self):
        self.assertEqual(pulsecheck_app.normalize_service("HTTP://Service.Example.COM/"), "service.example.com")
        self.assertEqual(pulsecheck_app.normalize_service("https://api.internal:8080/path"), "api.internal:8080")
        with self.assertRaises(ValueError):
            pulsecheck_app.normalize_service("   ")

    @patch("app.scan_service")
    @patch("app.discover_ports", return_value=[80, 443])
    def test_service_crud_lifecycle(self, mock_discover, mock_scan):
        # 1. Add service
        service_id = pulsecheck_app.add_service(
            name="auth.service.local",
            match="auth",
            url_path="/status",
            comment="Authentication microservice",
            use_proxy=True,
        )
        self.assertIsNotNone(service_id)
        self.assertTrue(pulsecheck_app.service_exists("auth.service.local"))

        # 2. Get service by ID
        service = pulsecheck_app.get_service_by_id(service_id)
        self.assertIsNotNone(service)
        self.assertEqual(service["name"], "auth.service.local")
        self.assertEqual(service["match"], "auth")
        self.assertEqual(service["url_path"], "/status")
        self.assertEqual(service["comment"], "Authentication microservice")
        self.assertTrue(service["use_proxy"])

        # 4. Update service
        pulsecheck_app.update_service(
            service_id=service_id,
            name="auth-v2.service.local",
            ports_input="8080, 8443",
            match="auth-v2",
            url_path="/healthz",
            paused=True,
            comment="Updated auth microservice",
            use_proxy=False,
        )
        updated = pulsecheck_app.get_service_by_id(service_id)
        self.assertEqual(updated["name"], "auth-v2.service.local")
        self.assertEqual(updated["match"], "auth-v2")
        self.assertEqual(updated["url_path"], "/healthz")
        self.assertTrue(updated["paused"])
        self.assertEqual(updated["ports"], [8080, 8443])
        self.assertFalse(updated["use_proxy"])

        # 5. Delete service
        pulsecheck_app.delete_service(service_id)
        self.assertIsNone(pulsecheck_app.get_service_by_id(service_id))

    @patch("app.scan_service")
    @patch("app.discover_ports", return_value=[80, 443])
    def test_services_web_routes(self, mock_discover, mock_scan):
        # GET /services
        resp = self.client.get("/services")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Services", resp.data)
        self.assertIn(b"Add New Service", resp.data)

        # POST /services/add
        add_resp = self.client.post(
            "/services/add",
            data={
                "name": "portal.service.local",
                "match": "portal",
                "url_path": "/health",
                "comment": "Internal Web Portal",
                "use_proxy": "1",
            },
            follow_redirects=True,
        )
        self.assertEqual(add_resp.status_code, 200)
        self.assertIn(b"Added service portal.service.local.", add_resp.data)

        services = pulsecheck_app.service_list()
        portal = next(s for s in services if s["name"] == "portal.service.local")
        self.assertIsNotNone(portal)
        self.assertEqual(portal["comment"], "Internal Web Portal")

        # GET /services/<id>/edit
        edit_resp = self.client.get(f"/services/{portal['id']}/edit")
        self.assertEqual(edit_resp.status_code, 200)
        self.assertIn(b"Edit Service", edit_resp.data)
        self.assertIn(b"portal.service.local", edit_resp.data)

        # POST /services/<id>/edit
        edit_post = self.client.post(
            f"/services/{portal['id']}/edit",
            data={
                "name": "portal.service.local",
                "match": "portal",
                "url_path": "/health",
                "comment": "Main Portal Gateway",
                "ports": "80, 443",
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_post.status_code, 200)
        self.assertIn(b"Updated service portal.service.local.", edit_post.data)

        # POST /services/bulk-ports
        bulk_resp = self.client.post(
            "/services/bulk-ports",
            data={
                "service_ids": [str(portal["id"])],
                "port_action": "add",
                "ports": "9000",
            },
            follow_redirects=True,
        )
        self.assertEqual(bulk_resp.status_code, 200)
        updated_portal = pulsecheck_app.get_service_by_id(portal["id"])
        self.assertIn(9000, updated_portal["ports"])

        # GET /services/export.csv
        export_resp = self.client.get("/services/export.csv")
        self.assertEqual(export_resp.status_code, 200)
        self.assertIn("attachment; filename=pulsecheck_services.csv", export_resp.headers["Content-Disposition"])
        self.assertIn(b"Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response", export_resp.data)
        self.assertIn(b"portal.service.local", export_resp.data)

        # POST /services/<id>/delete
        delete_resp = self.client.post(f"/services/{portal['id']}/delete", follow_redirects=True)
        self.assertEqual(delete_resp.status_code, 200)
        self.assertIn(b"Deleted service portal.service.local.", delete_resp.data)

    @patch("app.scan_service")
    def test_import_services_from_csv(self, mock_scan):
        csv_data = """Service,Match,URL path,Comment,Paused,Proxy,Ports
db.service.local,db,,Primary Database,0,0,"5432"
cache.service.local,cache,,Redis Cache,1,0,"6379"
invalid service host,,,,,
"""
        summary = pulsecheck_app.import_services_from_csv(csv_data)
        self.assertEqual(summary["total"], 3)
        self.assertEqual(summary["imported"], 2)
        self.assertEqual(summary["invalid"], 1)
        self.assertIn("db.service.local", summary["imported_services"])
        self.assertIn("cache.service.local", summary["imported_services"])

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        self.assertIn("db.service.local", services)
        self.assertEqual(services["db.service.local"]["ports"], [5432])
        self.assertEqual(services["cache.service.local"]["ports"], [6379])
        self.assertTrue(services["cache.service.local"]["paused"])

    @patch("app.scan_service")
    @patch("app.discover_ports", return_value=[80, 443])
    def test_edit_service_layout_and_elements(self, mock_discover, mock_scan):
        service_id = pulsecheck_app.add_service(
            name="test-ui.service.local",
            match="welcome",
        )
        response = self.client.get(f"/services/{service_id}/edit")
        self.assertEqual(response.status_code, 200)
        html = response.data.decode("utf-8")

        # 2-column layout and cards
        self.assertIn("edit-service-layout", html)
        self.assertIn("tab-main-card", html)
        self.assertIn("edit-test-card", html)

        # Form fields present and not excessively wide
        self.assertIn('id="name"', html)
        self.assertIn('class="port-row-match"', html)
        self.assertIn('id="ports"', html)
        self.assertIn('id="paused"', html)
        self.assertIn('id="use_proxy"', html)

        # Live Test button and diagnostics panel
        self.assertIn('id="btn-live-test"', html)
        self.assertIn("Test Probes", html)
        self.assertIn('id="diag-placeholder"', html)
        self.assertIn('id="btn-placeholder-test"', html)
        self.assertIn('id="diag-tabs-nav"', html)
        self.assertIn('id="diag-tabs-content"', html)

    @patch("app.fetch_response")
    def test_diagnose_service_ports(self, mock_fetch):
        # Port 80 returns match (ONLINE), Port 8080 returns no match (DEGRADED)
        def side_effect(service_name, port, scheme, url_path="", **kwargs):
            if port == 80:
                return b"HTTP/1.1 200 OK\r\n\r\nHello Welcome to PulseCheck", 200, f"http://{service_name}:{port}/"
            elif port == 8080:
                return b"HTTP/1.1 200 OK\r\n\r\nApache Server at other.host", 200, f"http://{service_name}:{port}/"
            raise ConnectionRefusedError("Connection refused")

        mock_fetch.side_effect = side_effect

        results = pulsecheck_app.diagnose_service_ports(
            service_name="web.service.local",
            ports=[80, 8080, 9999],
            match="Welcome",
        )

        self.assertTrue(results["success"])
        self.assertEqual(results["service_name"], "web.service.local")
        self.assertEqual(results["overall_status"], "offline")
        self.assertEqual(len(results["ports"]), 3)

        # Port 80 checks
        p80 = next(p for p in results["ports"] if p["port"] == 80)
        self.assertEqual(p80["status"], "online")
        self.assertEqual(p80["status_code"], 200)
        self.assertTrue(p80["match_found"])
        self.assertEqual(p80["match_count"], 1)
        self.assertIn("Welcome to PulseCheck", p80["response_snippet"])
        self.assertGreater(p80["duration_ms"], 0)
        self.assertEqual(p80["retries"], 0)
        self.assertTrue(p80["timestamp"])

        # Port 8080 checks
        p8080 = next(p for p in results["ports"] if p["port"] == 8080)
        self.assertEqual(p8080["status"], "degraded")
        self.assertEqual(p8080["status_code"], 200)
        self.assertFalse(p8080["match_found"])

        # Port 9999 checks
        p9999 = next(p for p in results["ports"] if p["port"] == 9999)
        self.assertEqual(p9999["status"], "offline")
        self.assertFalse(p9999["match_found"])
        self.assertIn("Connection refused", p9999["error"])

    @patch("app.fetch_response")
    @patch("app.discover_ports", return_value=[80])
    @patch("app.scan_service")
    def test_service_test_endpoint_live_values(self, mock_scan, mock_discover, mock_fetch):
        service_id = pulsecheck_app.add_service(
            name="srv.internal",
            match="original",
        )
        mock_fetch.return_value = (b"HTTP/1.1 200 OK\r\n\r\nCustom Match Found Here", 200, "http://srv.internal:8080/")

        # Test with modified live values in JSON payload (not saved yet in DB)
        post_data = {
            "name": "srv.internal",
            "match": "Custom Match",
            "ports": "8080",
            "url_path": "/api/v1/health",
            "use_proxy": False,
        }
        resp = self.client.post(f"/services/{service_id}/test", json=post_data)
        self.assertEqual(resp.status_code, 200)
        json_data = resp.get_json()

        self.assertTrue(json_data["success"])
        self.assertEqual(json_data["overall_status"], "online")
        self.assertEqual(len(json_data["ports"]), 1)
        self.assertEqual(json_data["ports"][0]["port"], 8080)
        self.assertTrue(json_data["ports"][0]["match_found"])
        self.assertEqual(json_data["ports"][0]["match_count"], 1)

        # Test 404 on non-existent service ID
        resp_404 = self.client.post("/services/999999/test", json=post_data)
        self.assertEqual(resp_404.status_code, 404)

        # Test 400 on empty ports
        bad_data = {"name": "srv.internal", "ports": ""}
        resp_400 = self.client.post(f"/services/{service_id}/test", json=bad_data)
        self.assertEqual(resp_400.status_code, 400)

    @patch("app.fetch_response")
    @patch("app.scan_service")
    def test_add_service_page_layout_and_probing(self, mock_scan, mock_fetch):
        # 1. GET /services/add renders dedicated 2-column layout with diagnostics
        resp = self.client.get("/services/add")
        self.assertEqual(resp.status_code, 200)
        html = resp.data.decode("utf-8")

        self.assertIn("Add New Service", html)
        self.assertIn("edit-service-layout", html)
        self.assertIn("tab-main-card", html)
        self.assertIn("edit-test-card", html)
        self.assertIn('id="ports-json-hidden"', html)
        self.assertIn('id="btn-add-port"', html)
        self.assertIn('id="btn-live-test"', html)
        self.assertIn("Test Probes", html)
        self.assertIn('id="diag-placeholder"', html)
        self.assertIn('id="btn-placeholder-test"', html)

        # 2. POST /services/test probes live values for new unsaved service
        mock_fetch.return_value = (b"HTTP/1.1 200 OK\r\n\r\nFresh Service Response", 200, "http://new-srv.local:80/")
        test_payload = {
            "name": "new-srv.local",
            "ports": "80, 443",
            "match": "",  # Empty match should trigger derive_match
            "url_path": "",
            "use_proxy": False,
        }
        test_resp = self.client.post("/services/test", json=test_payload)
        self.assertEqual(test_resp.status_code, 200)
        test_data = test_resp.get_json()
        self.assertTrue(test_data["success"])
        self.assertEqual(len(test_data["ports"]), 2)
        # Verify derived match token ('new') was used
        self.assertEqual(test_data["ports"][0]["match_token"], "new")

        # 3. POST /services/add creates service with custom ports and redirects to /services
        add_post = self.client.post(
            "/services/add",
            data={
                "name": "new-srv.local",
                "match": "Fresh",
                "ports": "80, 443, 8080",
                "url_path": "/status",
                "comment": "New microservice entry",
            },
            follow_redirects=True,
        )
        self.assertEqual(add_post.status_code, 200)
        self.assertIn(b"Added service new-srv.local.", add_post.data)

        # Verify created in DB with explicit ports
        services = pulsecheck_app.service_list()
        created = next((s for s in services if s["name"] == "new-srv.local"), None)
        self.assertIsNotNone(created)
        self.assertEqual(created["ports"], [80, 443, 8080])
        self.assertEqual(created["match"], "fresh")
        self.assertEqual(created["comment"], "New microservice entry")

    @patch("app.scan_service")
    def test_service_protocol_crud_and_status_badge(self, mock_scan):
        # 1. Add service with UDP protocol
        service_id = pulsecheck_app.add_service(
            name="dns.service.local",
            ports=[53],
            match="dns",
            protocol="udp",
        )
        self.assertIsNotNone(service_id)
        srv = pulsecheck_app.get_service_by_id(service_id)
        self.assertEqual(srv["protocol"], "udp")

        # 2. Update service with UDP SSL (DTLS) protocol
        pulsecheck_app.update_service(
            service_id=service_id,
            name="dns.service.local",
            ports_input="53, 853",
            protocol="udp-ssl",
        )
        srv = pulsecheck_app.get_service_by_id(service_id)
        self.assertEqual(srv["protocol"], "udp-ssl")

        # 3. Verify protocol selection in edit page
        edit_resp = self.client.get(f"/services/{service_id}/edit")
        self.assertEqual(edit_resp.status_code, 200)
        self.assertIn(b'value="udp-ssl" selected', edit_resp.data)
        self.assertIn(b'value="icmp-ping"', edit_resp.data)
        self.assertNotIn(b'<option value="icmp-ping"', edit_resp.data)

        add_resp = self.client.get("/services/add")
        self.assertEqual(add_resp.status_code, 200)
        self.assertNotIn(b'<option value="icmp-ping"', add_resp.data)
        self.assertIn(b'id="icmp-enabled"', add_resp.data)

        # 4. Status rows include protocol and status page renders distinct badge
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (service_id, 53, 1, "online", 5, "2026-10-01 12:00:00"),
        )
        conn.commit()
        conn.close()

        status_rows = pulsecheck_app.get_status_rows()
        dns_row = next((r for r in status_rows if r["id"] == service_id), None)
        self.assertIsNotNone(dns_row)
        self.assertEqual(dns_row["protocol"], "udp-ssl")

        # GET /status renders PORT:PROTOCOL pill in status-item, status-hover-box-ports, without purple badge
        status_page_resp = self.client.get("/status")
        self.assertEqual(status_page_resp.status_code, 200)
        self.assertIn(b"53:UDPSSL", status_page_resp.data)
        self.assertIn(b"status-hover-box-ports", status_page_resp.data)
        self.assertNotIn(b"badge-protocol", status_page_resp.data)
        self.assertNotIn(b"#7c3aed", status_page_resp.data)

    @patch("app.fetch_udp_response")
    @patch("app.fetch_udp_ssl_response")
    @patch("app.fetch_icmp_ping_response")
    def test_diagnostic_probing_additional_protocols(self, mock_icmp, mock_udp_ssl, mock_udp):
        # 1. Preferred protocol UDP
        mock_udp.return_value = b"UDP-DNS-OK"
        res_udp = pulsecheck_app.diagnose_service_ports(
            service_name="dns.example",
            ports=[53],
            match="DNS",
            preferred_protocol="udp",
        )
        self.assertTrue(res_udp["success"])
        self.assertEqual(res_udp["overall_status"], "online")
        self.assertEqual(res_udp["ports"][0]["protocol"], "udp")
        self.assertEqual(res_udp["discovered_protocol"], "udp")
        self.assertTrue(res_udp["ports"][0]["match_found"])

        # 2. Preferred protocol UDP SSL (DTLS)
        mock_udp_ssl.return_value = b"DTLS-HANDSHAKE-OK"
        res_dtls = pulsecheck_app.diagnose_service_ports(
            service_name="vpn.example",
            ports=[4433],
            match="HANDSHAKE",
            preferred_protocol="udp-ssl",
        )
        self.assertTrue(res_dtls["success"])
        self.assertEqual(res_dtls["overall_status"], "online")
        self.assertEqual(res_dtls["ports"][0]["protocol"], "udp-ssl")
        self.assertEqual(res_dtls["discovered_protocol"], "udp-ssl")

        # 3. Preferred protocol ICMP Ping
        mock_icmp.return_value = (True, 12, "64 bytes from router.example: bytes=64 icmp_seq=1 ttl=64 time=12 ms")
        res_icmp = pulsecheck_app.diagnose_service_ports(
            service_name="router.example",
            ports=[1],
            match="ttl=64",
            preferred_protocol="icmp-ping",
        )
        self.assertTrue(res_icmp["success"])
        self.assertEqual(res_icmp["overall_status"], "online")
        self.assertEqual(res_icmp["ports"][0]["protocol"], "icmp-ping")
        self.assertEqual(res_icmp["discovered_protocol"], "icmp-ping")

    def test_scan_service_skips_ports_without_protocol(self):
        # Service created with a port that has no protocol
        conn = pulsecheck_app.get_db_connection()
        cur = conn.execute(
            "INSERT INTO services (name, port_protocol) VALUES (?, ?)",
            ("unconfigured.service.local", '[{"port": 5000, "protocol": "", "match": "payload", "url_path": ""}]'),
        )
        conn.commit()
        service_id = cur.lastrowid
        conn.close()

        # Run scan_service on port without protocol -> must be skipped
        statuses = pulsecheck_app.scan_service(service_id, "unconfigured.service.local", [{"port": 5000, "protocol": ""}], "payload")
        self.assertEqual(statuses.get(5000), "skipped")

        # Verify check row in database has status = 'skipped'
        conn = pulsecheck_app.get_db_connection()
        check_row = conn.execute(
            "SELECT status, is_online FROM port_checks WHERE service_id = ? AND port = 5000 ORDER BY id DESC LIMIT 1",
            (service_id,),
        ).fetchone()
        conn.close()
        self.assertIsNotNone(check_row)
        self.assertEqual(check_row["status"], "skipped")
        self.assertEqual(check_row["is_online"], 0)

        # However, ICMP (portless) must NOT be skipped even if protocol is empty or None
        with patch("app.fetch_icmp_ping_response", return_value=(True, 15, "bytes=64 time=15ms")):
            icmp_statuses = pulsecheck_app.scan_service(service_id, "unconfigured.service.local", [{"port": None, "protocol": ""}], "")
            self.assertEqual(icmp_statuses.get("icmp"), "online")

    @patch("app.scan_service")
    def test_csv_export_and_import_with_protocol(self, mock_scan):
        # 1. Add services with various protocols
        pulsecheck_app.add_service(
            name="dns-server.local",
            ports=[53],
            match="dns",
            protocol="udp",
        )
        pulsecheck_app.add_service(
            name="vpn-gateway.local",
            ports=[4433],
            match="vpn",
            protocol="udp-ssl",
        )
        pulsecheck_app.add_service(
            name="core-router.local",
            ports=[1],
            match="router",
            protocol="icmp-ping",
        )

        # 2. Export CSV and check Protocol column
        csv_text, count = pulsecheck_app.export_services_csv()
        self.assertEqual(count, 3)
        lines = [line.strip() for line in csv_text.strip().splitlines()]
        self.assertEqual(lines[0], "Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response")
        self.assertIn("dns-server.local,,0,0,udp,53,web,,dns,,", lines)
        self.assertIn("vpn-gateway.local,,0,0,udp-ssl,4433,web,,vpn,,", lines)
        self.assertIn("core-router.local,,0,0,icmp-ping,1,web,,router,,", lines)

        # 3. Clean DB and import the CSV
        conn = pulsecheck_app.get_db_connection()
        conn.execute("DELETE FROM services")
        conn.commit()
        conn.close()

        summary = pulsecheck_app.import_services_from_csv(csv_text)
        self.assertEqual(summary["imported"], 3)

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        self.assertEqual(services["dns-server.local"]["protocol"], "udp")
        self.assertEqual(services["vpn-gateway.local"]["protocol"], "udp-ssl")
        self.assertEqual(services["core-router.local"]["protocol"], "icmp-ping")

    @patch("app.fetch_icmp_ping_response")
    def test_icmp_probe_matches_bytes_equals_only(self, mock_icmp):
        """ICMP Ping does not do a user captured Match on the result; if the result contains 'bytes=' the protocol is considered online; if not, it's offline."""
        service_id = pulsecheck_app.add_service(
            name="router.ping.test",
            ports=[None],
            match="DO_NOT_MATCH_ME",
            protocol="icmp-ping",
        )

        # 1. Output contains 'bytes=' -> status is online despite mismatching user token
        mock_icmp.return_value = (True, 15, "Reply from 192.168.1.1: bytes=32 time=15ms TTL=64")
        pulsecheck_app.scan_service(
            service_id=service_id,
            service_name="router.ping.test",
            ports=[{"port": None, "protocol": "icmp-ping"}],
            match="DO_NOT_MATCH_ME",
        )
        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status FROM port_checks WHERE service_id = ? AND port IS NULL ORDER BY id DESC LIMIT 1", (service_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "online")

        # In diagnose_service_ports: status is online, match_token is ignored/empty, match_found is False
        diag = pulsecheck_app.diagnose_service_ports(
            service_name="router.ping.test",
            ports=[{"port": None, "protocol": "icmp-ping"}],
            match="DO_NOT_MATCH_ME",
        )
        self.assertEqual(diag["overall_status"], "online")
        self.assertFalse(diag["ports"][0]["match_found"])
        self.assertEqual(diag["ports"][0]["match_token"], "")

        # 2. Output does NOT contain 'bytes=' -> status is offline even if user match string matches error text
        mock_icmp.return_value = (False, 2000, "Request timed out for router.ping.test")
        pulsecheck_app.scan_service(
            service_id=service_id,
            service_name="router.ping.test",
            ports=[{"port": None, "protocol": "icmp-ping"}],
            match="timed out",
        )
        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT status FROM port_checks WHERE service_id = ? AND port IS NULL ORDER BY id DESC LIMIT 1", (service_id,)).fetchone()
        conn.close()
        self.assertIsNotNone(row)
        self.assertEqual(row["status"], "offline")

        diag_fail = pulsecheck_app.diagnose_service_ports(
            service_name="router.ping.test",
            ports=[{"port": None, "protocol": "icmp-ping"}],
            match="timed out",
        )
        self.assertEqual(diag_fail["overall_status"], "offline")
        self.assertFalse(diag_fail["ports"][0]["match_found"])

    @patch("app.scan_service")
    def test_edit_service_without_ports_does_not_default_80_443_and_saves_icmp(self, mock_scan):
        """When editing a service with no TCP/UDP ports, it should not default to 80/443, and ICMP checkbox should save and load correctly."""
        import json
        # 1. Add service via web form with ICMP enabled and empty ports
        add_resp = self.client.post("/services/add", data={
            "name": "switch.local",
            "ports_json": "[]",
            "icmp_enabled": "icmp-ping",
        }, follow_redirects=True)
        self.assertEqual(add_resp.status_code, 200)

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        self.assertIn("switch.local", services)
        srv = services["switch.local"]
        # Should have exactly 1 port entry: the portless ICMP entry
        self.assertEqual(len(srv["ports"]), 1)
        self.assertIsNone(srv["ports"][0]["port"])
        self.assertEqual(srv["ports"][0]["protocol"], "icmp-ping")

        # 2. GET edit page: verify ICMP checkbox is checked and NO 80/443 default rows
        edit_resp = self.client.get(f"/services/{srv['id']}/edit")
        self.assertEqual(edit_resp.status_code, 200)
        edit_html = edit_resp.data.decode("utf-8")
        # Checkbox should be checked
        self.assertIn('id="icmp-enabled"', edit_html)
        self.assertIn('checked', edit_html)
        # Should NOT contain port 80 or 443 rows in the table
        self.assertNotIn('value="80"', edit_html)
        self.assertNotIn('value="443"', edit_html)

        # 3. Save edit with ICMP checked and no ports
        save_resp = self.client.post(f"/services/{srv['id']}/edit", data={
            "name": "switch.local",
            "ports_json": "[]",
            "icmp_enabled": "icmp-ping",
        }, follow_redirects=True)
        self.assertEqual(save_resp.status_code, 200)

        srv_after = pulsecheck_app.get_service_by_id(srv["id"])
        self.assertEqual(len(srv_after["ports"]), 1)
        self.assertIsNone(srv_after["ports"][0]["port"])
        self.assertEqual(srv_after["ports"][0]["protocol"], "icmp-ping")

        # 4. Load edit page again: still checked, still no 80/443
        edit_resp2 = self.client.get(f"/services/{srv['id']}/edit")
        edit_html2 = edit_resp2.data.decode("utf-8")
        self.assertIn('id="icmp-enabled"', edit_html2)
        self.assertIn('checked', edit_html2)
        self.assertNotIn('value="80"', edit_html2)
        self.assertNotIn('value="443"', edit_html2)

        # 5. Edit and uncheck ICMP, add port 8080
        uncheck_resp = self.client.post(f"/services/{srv['id']}/edit", data={
            "name": "switch.local",
            "ports_json": json.dumps([{"port": 8080, "protocol": "http"}]),
            # icmp_enabled omitted (unchecked in browser)
        }, follow_redirects=True)
        self.assertEqual(uncheck_resp.status_code, 200)

        srv_unchecked = pulsecheck_app.get_service_by_id(srv["id"])
        self.assertEqual(len(srv_unchecked["ports"]), 1)
        self.assertEqual(srv_unchecked["ports"][0]["port"], 8080)

        # 6. Load edit page again: ICMP checkbox is now unchecked, 8080 is present
        edit_resp3 = self.client.get(f"/services/{srv['id']}/edit")
        edit_html3 = edit_resp3.data.decode("utf-8")
        self.assertIn('value="8080"', edit_html3)
        # Checkbox should NOT be checked
        self.assertNotIn('id="icmp-enabled" name="icmp_enabled" value="icmp-ping"\n              checked', edit_html3)

    @patch("app.scan_service")
    def test_services_table_port_protocol_format_and_status_icmp_isolation(self, mock_scan):
        """1) On /services, protocol badge next to service name is removed.
        2) PORTS column shows PORT:PROTOCOL in black with single space, ICMP has no PORT: prefix.
        3) On /status, when only ICMP is selected, only ICMP is displayed in MONITORED PORTS,
           even if historical checks exist for ports 80 and 443.
        """
        # Service 1: ICMP only, with historical checks on 80 and 443 in DB
        s1_id = pulsecheck_app.add_service(
            name="cam.icmp.only",
            ports=[None],
            match="cam",
            protocol="icmp-ping",
        )
        # Service 2: Multi-port HTTP, HTTPS, and ICMP
        s2_id = pulsecheck_app.add_service(
            name="web.multi.port",
            ports=[
                {"port": 80, "protocol": "http"},
                {"port": 443, "protocol": "https"},
                {"port": None, "protocol": "icmp-ping"},
            ],
            match="web",
        )

        # Insert historical checks for s1: ports 80, 443, and NULL
        conn = pulsecheck_app.get_db_connection()
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (s1_id, 80, 1, "online", 10, "2026-10-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (s1_id, 443, 1, "online", 15, "2026-10-01 10:00:00"),
        )
        conn.execute(
            "INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at) VALUES (?, ?, ?, ?, ?, ?)",
            (s1_id, None, 1, "online", 5, "2026-10-01 10:00:00"),
        )
        conn.commit()
        conn.close()

        # Service 3: No ports and no ICMP
        s3_id = pulsecheck_app.add_service(
            name="dummy.no.ports",
            ports=[],
            match="none",
        )

        # Check get_status_rows() for s1: must ONLY have 1 row for ICMP (port=None), no rows for 80 or 443
        status_rows = pulsecheck_app.get_status_rows()
        s1_rows = [r for r in status_rows if r["id"] == s1_id]
        self.assertEqual(len(s1_rows), 1)
        self.assertIsNone(s1_rows[0]["port"])
        self.assertEqual(s1_rows[0]["protocol"], "icmp-ping")
        self.assertTrue(s1_rows[0]["has_ports"])

        # Check get_status_rows() for s3: has_ports is False
        s3_rows = [r for r in status_rows if r["id"] == s3_id]
        self.assertEqual(len(s3_rows), 1)
        self.assertFalse(s3_rows[0]["has_ports"])

        # Check /status page HTML: Monitored Ports must NOT show 80 or 443 for cam.icmp.only
        status_resp = self.client.get("/status")
        self.assertEqual(status_resp.status_code, 200)
        status_html = status_resp.data.decode("utf-8")
        self.assertIn("cam.icmp.only", status_html)

        # Service with no ports must have data-status="none", NONE in monitored ports, and blank status
        self.assertIn('data-service="dummy.no.ports"  data-status="none"', status_html)
        self.assertIn('>NONE</span>', status_html)

        # Check /services page HTML:
        services_resp = self.client.get("/services")
        self.assertEqual(services_resp.status_code, 200)
        services_html = services_resp.data.decode("utf-8")

        # 1. No protocol badge next to service names on /services
        self.assertNotIn('class="badge badge-protocol"', services_html)

        # 2. PORTS column formatting:
        # ICMP only: 'ICMP' without 'PORT:' or prefix, using non-bold service-ports-text
        self.assertIn('>ICMP</span>', services_html)
        # Multi-port: displays first port with ellipsis '80:HTTP ...'
        self.assertIn('>80:HTTP ...</span>', services_html)
        self.assertIn('service-ports-text', services_html)
        # Hover box displays full list and count, but NO extra bottom row
        self.assertIn('Configured Ports (3)', services_html)
        self.assertIn('cell-hover-box-ports', services_html)
        self.assertIn('services-hover-box-ports', services_html)
        self.assertIn('port-proto-pill', services_html)
        self.assertIn('>80:HTTP</span>', services_html)
        self.assertIn('>443:HTTPS</span>', services_html)
        self.assertNotIn('hover-port-meta', services_html)

        # Test helper directly
        self.assertEqual(pulsecheck_app.format_ports_column([{"port": None, "protocol": "icmp-ping"}]), "ICMP")
        self.assertEqual(
            pulsecheck_app.format_ports_column([
                {"port": 80, "protocol": "http"},
                {"port": 443, "protocol": "https"},
                {"port": None, "protocol": "icmp-ping"},
            ]),
            "80:HTTP 443:HTTPS ICMP",
        )

    def test_service_without_match_ports_or_icmp(self):
        # 1. Add service via web route with empty match, no ports, no ICMP
        resp = self.client.post(
            "/services/add",
            data={
                "name": "barebones.example.com",
                "match": "",
                "url_path": "",
                "comment": "Empty test service",
                "ports_json": "[]",
                "ports": "",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        # Retrieve and verify database record
        conn = pulsecheck_app.get_db_connection()
        row = conn.execute("SELECT * FROM services WHERE name = 'barebones.example.com'").fetchone()
        conn.close()
        self.assertIsNotNone(row)
        svc_dict = pulsecheck_app.get_service_by_id(row["id"])
        self.assertEqual(svc_dict["match"], "")
        parsed = pulsecheck_app.parse_port_protocol(row["port_protocol"])
        self.assertEqual(parsed, [])

        # 2. Verify on /services list page
        services_resp = self.client.get("/services")
        self.assertEqual(services_resp.status_code, 200)
        services_html = services_resp.data.decode("utf-8")
        self.assertIn("barebones.example.com", services_html)
        self.assertIn("None detected", services_html)

        # 3. Edit service to change name/comment but still keep empty match, empty ports, no ICMP
        edit_resp = self.client.post(
            f"/services/{row['id']}/edit",
            data={
                "name": "barebones-updated.example.com",
                "match": "",
                "url_path": "",
                "comment": "Still empty",
                "ports_json": "[]",
                "ports": "",
            },
            follow_redirects=True,
        )
        self.assertEqual(edit_resp.status_code, 200)
        updated = pulsecheck_app.get_service_by_id(row["id"])
        self.assertEqual(updated["name"], "barebones-updated.example.com")
        self.assertEqual(updated["match"], "")
        self.assertEqual(updated["ports"], [])


    def test_bulk_ports_preserve_protocols_and_default_autodetect(self):
        """Verify:
        1) Adding ports defaults new ports to auto-detect protocol ('') while keeping existing ports' protocols.
        2) Deleting ports preserves the protocols of all remaining ports and probes (e.g. ICMP).
        """
        # Create service with distinct protocols: 80 -> http, 443 -> https, 8443 -> https, and ICMP probe
        initial_ports = [
            {"port": 80, "protocol": "http"},
            {"port": 443, "protocol": "https"},
            {"port": 8443, "protocol": "https"},
            {"port": None, "protocol": "icmp-ping"},
        ]
        conn = pulsecheck_app.get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO services (name, comment, paused, use_proxy, port_protocol) VALUES (?, ?, ?, ?, ?)",
            (
                "multi-proto.example.com",
                "Bulk port test service",
                0,
                0,
                pulsecheck_app.port_protocol_to_json(initial_ports),
            ),
        )
        service_id = cur.lastrowid
        conn.commit()
        conn.close()

        # Step 1: Bulk Add port 8080 and 9090
        resp = self.client.post(
            "/services/bulk-ports",
            data={
                "service_ids": [str(service_id)],
                "port_action": "add",
                "ports": "8080, 9090",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp.status_code, 200)

        svc = pulsecheck_app.get_service_by_id(service_id)
        ports_dict = {p.get("port"): p.get("protocol") for p in svc["ports"]}

        # Existing ports retain their configured protocols
        self.assertEqual(ports_dict.get(80), "http")
        self.assertEqual(ports_dict.get(443), "https")
        self.assertEqual(ports_dict.get(8443), "https")
        self.assertEqual(ports_dict.get(None), "icmp-ping")

        # Newly added ports default to auto-detect ('')
        self.assertIn(8080, ports_dict)
        self.assertEqual(ports_dict.get(8080), "")
        self.assertIn(9090, ports_dict)
        self.assertEqual(ports_dict.get(9090), "")

        # Step 2: Bulk Delete port 443 and 8080
        resp_del = self.client.post(
            "/services/bulk-ports",
            data={
                "service_ids": [str(service_id)],
                "port_action": "remove",
                "ports": "443, 8080",
            },
            follow_redirects=True,
        )
        self.assertEqual(resp_del.status_code, 200)

        svc_after = pulsecheck_app.get_service_by_id(service_id)
        ports_after_dict = {p.get("port"): p.get("protocol") for p in svc_after["ports"]}

        # Removed ports are absent
        self.assertNotIn(443, ports_after_dict)
        self.assertNotIn(8080, ports_after_dict)

        # Remaining ports preserved their protocols exactly
        self.assertEqual(ports_after_dict.get(80), "http")
        self.assertEqual(ports_after_dict.get(8443), "https")
        self.assertEqual(ports_after_dict.get(9090), "")
        self.assertEqual(ports_after_dict.get(None), "icmp-ping")


    @patch("app.scan_service")
    def test_csv_import_and_export_with_per_port_protocols_and_icmp(self, mock_scan):
        """Verify:
        1) Importing CSV with per-port protocols and portless 'icmp' correctly parses into PortEntry items.
        2) Exporting CSV outputs matching per-port protocols in Protocol and 'icmp' in Ports.
        """
        csv_input = """Service,Match,URL path,Comment,Paused,Proxy,Protocol,Ports
hybrid-import.example,welcome,/health,Hybrid Test,0,1,"http, https, icmp-ping","80, 443, icmp"
router-import.example,router,,Router Test,0,0,icmp-ping,icmp
"""
        summary = pulsecheck_app.import_services_from_csv(csv_input)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["imported"], 2)

        # Verify parsed representation in DB
        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        hybrid = services["hybrid-import.example"]
        ports_dict = {p.get("port"): p.get("protocol") for p in hybrid["ports"]}
        self.assertEqual(ports_dict.get(80), "http")
        self.assertEqual(ports_dict.get(443), "https")
        self.assertEqual(ports_dict.get(None), "icmp-ping")

        router = services["router-import.example"]
        self.assertEqual(len(router["ports"]), 1)
        self.assertIsNone(router["ports"][0].get("port"))
        self.assertEqual(router["ports"][0].get("protocol"), "icmp-ping")

        # Verify Export CSV output
        export_csv, count = pulsecheck_app.export_services_csv()
        self.assertGreaterEqual(count, 2)
        self.assertIn('hybrid-import.example,Hybrid Test,0,1,"http, https, icmp-ping","80, 443, icmp",web,/health,welcome,,', export_csv)
        self.assertIn("router-import.example,Router Test,0,0,icmp-ping,icmp,web,,,,", export_csv)

    def test_hex_byte_helpers(self):
        # parse_hex_bytes valid
        self.assertEqual(pulsecheck_app.parse_hex_bytes("48 65 6c 6c 6f"), b"Hello")
        self.assertEqual(pulsecheck_app.parse_hex_bytes("0x48 0x65, 0x6C"), b"Hel")
        self.assertEqual(pulsecheck_app.parse_hex_bytes(""), b"")
        self.assertEqual(pulsecheck_app.parse_hex_bytes(None), b"")
        # parse_hex_bytes invalid
        with self.assertRaises(ValueError):
            pulsecheck_app.parse_hex_bytes("48 zz 6c")
        with self.assertRaises(ValueError):
            pulsecheck_app.parse_hex_bytes("485")

        # format_hex_bytes
        self.assertEqual(pulsecheck_app.format_hex_bytes("48 65 6c 6c 6f"), "48 65 6C 6C 6F")
        self.assertEqual(pulsecheck_app.format_hex_bytes(b"Hello"), "48 65 6C 6C 6F")
        self.assertEqual(pulsecheck_app.format_hex_bytes(""), "")

    def test_custom_request_probing(self):
        # Test scan_service with custom request type over TCP
        conn = pulsecheck_app.get_db_connection()
        p_data = pulsecheck_app.port_protocol_to_json([{
            "port": 9000,
            "protocol": "tcp",
            "request_type": "custom",
            "request_payload": "01 02 03",
            "response_payload": "04 05",
        }])
        cursor = conn.execute(
            "INSERT INTO services (name, request_type, port_protocol) VALUES (?, 'custom', ?)",
            ("custom.service.local", p_data),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        # Mock fetch_tcp_response returning bytes containing b"\x04\x05"
        with patch("app.fetch_tcp_response", return_value=b"\x00\x04\x05\x09") as mock_tcp:
            pulsecheck_app.scan_service(
                service_id,
                "custom.service.local",
                [{
                    "port": 9000,
                    "protocol": "tcp",
                    "request_type": "custom",
                    "request_payload": "01 02 03",
                    "response_payload": "04 05",
                }]
            )
            # Verify fetch_tcp_response was called with custom_request_bytes=b"\x01\x02\x03"
            mock_tcp.assert_called_once_with("custom.service.local", 9000, "", custom_request_bytes=b"\x01\x02\x03")

        conn = pulsecheck_app.get_db_connection()
        check = conn.execute("SELECT status FROM port_checks WHERE service_id = ? AND port = 9000", (service_id,)).fetchone()
        conn.close()
        self.assertEqual(check["status"], "online")

    def test_custom_request_clears_opposite_fields_in_port_json(self):
        # Custom request should clear match and url_path
        port_entry = {
            "port": 8080,
            "protocol": "tcp",
            "request_type": "custom",
            "match": "some_token",
            "url_path": "/some_path",
            "request_payload": "aa bb",
            "response_payload": "cc dd",
        }
        json_str = pulsecheck_app.port_protocol_to_json([port_entry])
        parsed = json.loads(json_str)[0]
        self.assertEqual(parsed["request_type"], "custom")
        self.assertEqual(parsed["match"], "")
        self.assertEqual(parsed["url_path"], "")
        self.assertEqual(parsed["request_payload"], "AA BB")
        self.assertEqual(parsed["response_payload"], "CC DD")

        # WEB request should clear request_payload and response_payload
        web_entry = {
            "port": 80,
            "protocol": "http",
            "request_type": "web",
            "match": "token",
            "url_path": "/path",
            "request_payload": "aa bb",
            "response_payload": "cc dd",
        }
        json_web = pulsecheck_app.port_protocol_to_json([web_entry])
        parsed_web = json.loads(json_web)[0]
        self.assertEqual(parsed_web["request_type"], "web")
        self.assertEqual(parsed_web["match"], "token")
        self.assertEqual(parsed_web["url_path"], "/path")
        self.assertEqual(parsed_web["request_payload"], "")
        self.assertEqual(parsed_web["response_payload"], "")

    @patch("app.discover_ports", return_value=[{"port": 80, "protocol": "http"}])
    @patch("app.scan_service")
    def test_quick_text_import_defaults_to_web(self, mock_scan, mock_discover):
        summary = pulsecheck_app.import_service_names(["new-quick-service.local"])
        self.assertEqual(summary["imported"], 1)

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        svc = services["new-quick-service.local"]
        self.assertEqual(svc["request_type"], "web")
        self.assertEqual(len(svc["ports"]), 1)
        self.assertEqual(svc["ports"][0]["request_type"], "web")

    @patch("app.discover_ports", return_value=[{"port": 80, "protocol": ""}, {"port": 443, "protocol": ""}, {"port": 8080, "protocol": ""}, {"port": 9000, "protocol": ""}])
    @patch("app.diagnose_service_ports")
    @patch("app.scan_service")
    def test_quick_text_import_diagnoses_and_saves_online_protocols_only(self, mock_scan, mock_diag, mock_discover):
        # Port 80: online with http -> saved
        # Port 443: online with ssl-handshake -> normalized to https and saved
        # Port 8080: degraded with http -> NOT saved (strictly online rule)
        # Port 9000: offline -> NOT saved
        mock_diag.return_value = {
            "success": True,
            "ports": [
                {"port": 80, "status": "online", "protocol": "http"},
                {"port": 443, "status": "online", "protocol": "ssl-handshake"},
                {"port": 8080, "status": "degraded", "protocol": "http"},
                {"port": 9000, "status": "offline", "protocol": "tcp"},
            ],
        }

        summary = pulsecheck_app.import_service_names(["diag-service.local"])
        self.assertEqual(summary["imported"], 1)

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        svc = services["diag-service.local"]
        ports_by_num = {p["port"]: p for p in svc["ports"]}

        self.assertEqual(ports_by_num[80]["protocol"], "http")
        self.assertEqual(ports_by_num[443]["protocol"], "https")
        self.assertEqual(ports_by_num[8080]["protocol"], "")
        self.assertEqual(ports_by_num[9000]["protocol"], "")

        # Verify scan_service was called with the updated entries
        mock_scan.assert_called_once()
        passed_entries = mock_scan.call_args[0][2]
        scan_ports_by_num = {p["port"]: p for p in passed_entries}
        self.assertEqual(scan_ports_by_num[80]["protocol"], "http")
        self.assertEqual(scan_ports_by_num[443]["protocol"], "https")
        self.assertEqual(scan_ports_by_num[8080]["protocol"], "")
        self.assertEqual(scan_ports_by_num[9000]["protocol"], "")

    @patch("app.discover_ports", return_value=[{"port": 80, "protocol": ""}])
    @patch("app.diagnose_service_ports")
    def test_quick_text_import_cancelled_during_diagnostics_aborts_before_db_insert(self, mock_diag, mock_discover):
        cancelled_flag = [False]

        def fake_diagnose(*args, **kwargs):
            cancelled_flag[0] = True
            return {"success": True, "ports": [{"port": 80, "status": "online", "protocol": "http"}]}

        mock_diag.side_effect = fake_diagnose

        with self.assertRaises(pulsecheck_app.ImportCancelled):
            pulsecheck_app.import_service_names(
                ["cancelled-service.local"],
                cancelled_check=lambda: cancelled_flag[0],
            )

        # Service must not exist in DB because cancellation checked right after diagnostics
        self.assertFalse(pulsecheck_app.service_exists("cancelled-service.local"))

    @patch("app.trigger_service_icon_resolution_async")
    @patch("app.discover_ports", return_value=[{"port": 80, "protocol": ""}])
    @patch("app.diagnose_service_ports", return_value={"success": True, "ports": [{"port": 80, "status": "online", "protocol": "http"}]})
    @patch("app.scan_service")
    def test_quick_text_import_triggers_service_icon_resolution(self, mock_scan, mock_diag, mock_discover, mock_icon):
        summary = pulsecheck_app.import_service_names(["icon-imported.service.local"])
        self.assertEqual(summary["imported"], 1)
        mock_icon.assert_called_once_with("icon-imported.service.local")

    @patch("app.scan_service")
    def test_csv_import_export_custom_requests(self, mock_scan):
        csv_content = """Service,Comment,Paused,Proxy,Protocol,Ports,Request Type,URL path,Match,Request,Response
custom-app.local,Test Custom,0,0,tcp,9999,custom,,,01 02 03,04 05
"""
        summary = pulsecheck_app.import_services_from_csv(csv_content)
        self.assertEqual(summary["imported"], 1)

        services = {s["name"]: s for s in pulsecheck_app.service_list()}
        svc = services["custom-app.local"]
        port_entry = svc["ports"][0]
        self.assertEqual(port_entry["request_type"], "custom")
        self.assertEqual(port_entry["request_payload"], "01 02 03")
        self.assertEqual(port_entry["response_payload"], "04 05")
        self.assertEqual(port_entry["match"], "")
        self.assertEqual(port_entry["url_path"], "")

        # Export and verify roundtrip
        exported, _ = pulsecheck_app.export_services_csv()
        self.assertIn("custom-app.local,Test Custom,0,0,tcp,9999,custom,,,01 02 03,04 05", exported)


if __name__ == "__main__":
    unittest.main()


