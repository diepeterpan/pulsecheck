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

        # 3. Verify sync with domains compatibility view/table
        domain_copy = pulsecheck_app.get_domain_by_id(service_id)
        self.assertIsNotNone(domain_copy)
        self.assertEqual(domain_copy["name"], "auth.service.local")

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
        self.assertIsNone(pulsecheck_app.get_domain_by_id(service_id))

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


if __name__ == "__main__":
    unittest.main()
