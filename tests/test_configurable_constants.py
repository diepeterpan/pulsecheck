import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import app as pulsecheck_app
from core.config import (
    DEFAULT_COMMON_PORTS,
    DEFAULT_HTTPS_PORTS,
    DEFAULT_SCAN_INTERVAL_MINUTES,
    DEFAULT_HISTORY_RETENTION_DAYS,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_CORPORATE_SUFFIXES,
    DEFAULT_IGNORED_ICON_HASHES,
    DEFAULT_DANGEROUS_REMOTE_COMMAND_PATTERNS,
    get_common_ports,
    get_https_ports,
    get_scan_interval_minutes,
    get_history_retention_days,
    get_scan_workers,
    get_maclookup_api_key,
)
from services.icons import (
    get_corporate_suffixes,
    get_ignored_icon_hashes,
    slugify_manufacturer,
    is_godaddy_or_parked_icon,
)
from routes.settings import (
    get_dangerous_remote_patterns,
    is_safe_remote_command,
)
from services.scanner import discover_ports


class ConfigurableConstantsTests(unittest.TestCase):
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

    def test_default_getters_match_defined_constants(self):
        self.assertEqual(get_common_ports(), DEFAULT_COMMON_PORTS)
        self.assertEqual(get_https_ports(), set(DEFAULT_HTTPS_PORTS))
        self.assertEqual(get_scan_interval_minutes(), DEFAULT_SCAN_INTERVAL_MINUTES)
        self.assertEqual(get_history_retention_days(), DEFAULT_HISTORY_RETENTION_DAYS)
        self.assertEqual(get_scan_workers(), DEFAULT_SCAN_WORKERS)
        self.assertEqual(get_maclookup_api_key(), "")
        self.assertEqual(get_corporate_suffixes(), DEFAULT_CORPORATE_SUFFIXES)
        self.assertEqual(get_ignored_icon_hashes(), set(DEFAULT_IGNORED_ICON_HASHES))
        for p in DEFAULT_DANGEROUS_REMOTE_COMMAND_PATTERNS:
            self.assertIn(p, get_dangerous_remote_patterns())

    def test_scanner_settings_api_get_save_and_reset(self):
        # 1. GET initial settings
        resp = self.client.get("/api/settings/scanner")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["common_ports"], DEFAULT_COMMON_PORTS)
        self.assertEqual(data["scan_interval_minutes"], 10)

        # 2. POST save custom scanner settings
        custom_payload = {
            "common_ports": [80, 443, 8006, 9443],
            "https_ports": [443, 8443, 9443],
            "scan_interval_minutes": 5,
            "history_retention_days": 60,
            "scan_workers": 25,
            "maclookup_api_key": "custom-api-token-xyz",
        }
        with patch("routes.settings.reschedule_scan_job") as mock_resched:
            save_resp = self.client.post(
                "/api/settings/scanner/save",
                data=json.dumps(custom_payload),
                content_type="application/json",
            )
            self.assertEqual(save_resp.status_code, 200)
            self.assertTrue(save_resp.get_json()["success"])
            mock_resched.assert_called_once_with(5)

        # 3. Verify getters reflect custom settings
        self.assertEqual(get_common_ports(), [80, 443, 8006, 9443])
        self.assertEqual(get_https_ports(), {443, 8443, 9443})
        self.assertEqual(get_scan_interval_minutes(), 5)
        self.assertEqual(get_history_retention_days(), 60)
        self.assertEqual(get_scan_workers(), 25)
        self.assertEqual(get_maclookup_api_key(), "custom-api-token-xyz")

        # 4. Reset common_ports only
        reset_ports_resp = self.client.post(
            "/api/settings/scanner/reset",
            data=json.dumps({"target": "common_ports"}),
            content_type="application/json",
        )
        self.assertEqual(reset_ports_resp.status_code, 200)
        self.assertEqual(get_common_ports(), DEFAULT_COMMON_PORTS)
        # Verify others remained unchanged
        self.assertEqual(get_scan_interval_minutes(), 5)
        self.assertEqual(get_https_ports(), {443, 8443, 9443})

        # 5. Reset all
        reset_all_resp = self.client.post(
            "/api/settings/scanner/reset",
            data=json.dumps({"target": "all"}),
            content_type="application/json",
        )
        self.assertEqual(reset_all_resp.status_code, 200)
        self.assertEqual(get_common_ports(), DEFAULT_COMMON_PORTS)
        self.assertEqual(get_https_ports(), set(DEFAULT_HTTPS_PORTS))
        self.assertEqual(get_scan_interval_minutes(), DEFAULT_SCAN_INTERVAL_MINUTES)
        self.assertEqual(get_history_retention_days(), DEFAULT_HISTORY_RETENTION_DAYS)
        self.assertEqual(get_scan_workers(), DEFAULT_SCAN_WORKERS)

    def test_corporate_suffixes_dynamic_normalization(self):
        # Slugify with default suffixes strips 'inc', 'ltd', 'corp'
        self.assertEqual(slugify_manufacturer("Acme Electronics Inc"), "acme_electronics")

        # Save custom suffixes including 'sp z o o'
        custom_suffixes = list(DEFAULT_CORPORATE_SUFFIXES) + ["sp z o o", "holding"]
        save_resp = self.client.post(
            "/api/settings/icons/mappings/save",
            data=json.dumps({"type": "corporate_suffixes", "data": custom_suffixes}),
            content_type="application/json",
        )
        self.assertEqual(save_resp.status_code, 200)
        self.assertTrue(save_resp.get_json()["success"])

        # Verify slugify strips the new custom suffix
        self.assertEqual(slugify_manufacturer("Polskie Technologie SP Z O O"), "polskie_technologie")
        self.assertEqual(slugify_manufacturer("Global Venture Holding"), "global_venture")

        # Reset corporate suffixes
        reset_resp = self.client.post(
            "/api/settings/icons/mappings/reset",
            data=json.dumps({"type": "corporate_suffixes"}),
            content_type="application/json",
        )
        self.assertEqual(reset_resp.status_code, 200)
        self.assertEqual(get_corporate_suffixes(), DEFAULT_CORPORATE_SUFFIXES)

    def test_ignored_icon_hashes_blacklist(self):
        import hashlib
        # Create test payloads (>= 50 bytes)
        payload_default = b"GoDaddy Parked Domain Favicon" * 5
        # Compute md5 of custom payload
        custom_payload = b"Custom Parked Domain Placeholder Content" * 5
        custom_hash = hashlib.md5(custom_payload).hexdigest().lower()

        # Initially custom payload should not be flagged as parked
        self.assertFalse(is_godaddy_or_parked_icon(custom_payload))

        # Save custom ignored hash
        custom_hashes = list(DEFAULT_IGNORED_ICON_HASHES) + [custom_hash]
        save_resp = self.client.post(
            "/api/settings/icons/mappings/save",
            data=json.dumps({"type": "ignored_icon_hashes", "data": custom_hashes}),
            content_type="application/json",
        )
        self.assertEqual(save_resp.status_code, 200)

        # Now the custom payload should be recognized as parked / ignored
        self.assertTrue(is_godaddy_or_parked_icon(custom_payload))

        # Reset ignored hashes
        reset_resp = self.client.post(
            "/api/settings/icons/mappings/reset",
            data=json.dumps({"type": "ignored_icon_hashes"}),
            content_type="application/json",
        )
        self.assertEqual(reset_resp.status_code, 200)
        self.assertFalse(is_godaddy_or_parked_icon(custom_payload))

    def test_remote_source_safety_patterns(self):
        # Baseline check: safe command is permitted
        is_safe, msg = is_safe_remote_command("docker ps --format '{{.Names}}'")
        self.assertTrue(is_safe)
        # Baseline check: destructive commands prohibited
        is_safe, msg = is_safe_remote_command("rm -rf /var/log")
        self.assertFalse(is_safe)
        is_safe, msg = is_safe_remote_command("mkfs.ext4 /dev/sda1")
        self.assertFalse(is_safe)

        # Save a new custom pattern: disallow 'curl -O' and 'wget'
        save_resp = self.client.post(
            "/api/settings/remote-source/safety/save",
            data=json.dumps({"patterns": [r"\bwget\b", r"\bcurl\s+-O\b"]}),
            content_type="application/json",
        )
        self.assertEqual(save_resp.status_code, 200)

        # Custom patterns should now block matching commands
        is_safe, msg = is_safe_remote_command("wget http://example.com/script.sh")
        self.assertFalse(is_safe)
        is_safe, msg = is_safe_remote_command("curl -O http://example.com/payload")
        self.assertFalse(is_safe)
        is_safe, msg = is_safe_remote_command("curl -s http://example.com/health")
        self.assertTrue(is_safe)

        # Reset safety patterns
        reset_resp = self.client.post(
            "/api/settings/remote-source/safety/reset",
            content_type="application/json",
        )
        self.assertEqual(reset_resp.status_code, 200)

        # wget should be allowed again, but baseline rm -rf must still be blocked!
        is_safe, msg = is_safe_remote_command("wget http://example.com/script.sh")
        self.assertTrue(is_safe)
        is_safe, msg = is_safe_remote_command("rm -rf /")
        self.assertFalse(is_safe)

    def test_discover_ports_uses_dynamic_common_ports(self):
        # Configure custom common ports
        custom_ports = [19999, 29999]
        self.client.post(
            "/api/settings/scanner/save",
            data=json.dumps({"common_ports": custom_ports}),
            content_type="application/json",
        )

        probed_ports = []

        def fake_create_connection(address, timeout=None):
            host, port = address
            probed_ports.append(port)
            raise OSError("Connection refused")

        with patch("socket.create_connection", side_effect=fake_create_connection):
            res = discover_ports("192.168.1.50")
            self.assertEqual(res, [])
            self.assertEqual(probed_ports, [19999, 29999])


if __name__ == "__main__":
    unittest.main()
