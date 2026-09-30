import io
import os
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
        self.assertIn(b"Service,Match,URL path,Comment,Paused,Proxy,Ports", export_resp.data)
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
        self.assertIn('id="match"', html)
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
        self.assertEqual(results["overall_status"], "degraded")
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
        self.assertIn('value="80, 443"', html)  # Pre-filled default ports
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


if __name__ == "__main__":
    unittest.main()
