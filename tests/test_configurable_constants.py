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
    DEFAULT_MAC_ARP_PRIMING_ENABLED,
    DEFAULT_MAC_NETBIOS_ENABLED,
    DEFAULT_MAC_SNMP_ENABLED,
    DEFAULT_MAC_SNMP_COMMUNITY,
    DEFAULT_REPLACE_LOOPBACK_IP_ENABLED,
    DEFAULT_SERVER_LAN_IP_OVERRIDE,
    get_mac_arp_priming_enabled,
    get_mac_netbios_enabled,
    get_mac_snmp_enabled,
    get_mac_snmp_community,
    get_replace_loopback_ip_enabled,
    get_server_lan_ip_override,
)
from core.database import save_settings
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
from services.scheduler import (
    _normalize_mac,
    _build_netbios_query,
    _parse_netbios_response,
    _build_snmp_get_request,
    _parse_snmp_response_mac,
    _resolve_mac,
    _asn1_encode_tlv,
    _asn1_encode_int,
    _build_dns_a_query,
    _parse_dns_a_response,
    _query_direct_dns_a_record,
    _get_host_primary_lan_ip,
    _is_local_host_ip,
    _get_host_local_mac,
    _resolve_ip,
)


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

    def test_mac_discovery_getters_and_settings_persistence(self):
        # 1. Defaults
        self.assertTrue(get_mac_arp_priming_enabled())
        self.assertTrue(get_mac_netbios_enabled())
        self.assertTrue(get_mac_snmp_enabled())
        self.assertEqual(get_mac_snmp_community(), "public")

        # 2. Modify settings
        save_settings({
            "mac_arp_priming_enabled": "0",
            "mac_netbios_enabled": "0",
            "mac_snmp_enabled": "1",
            "mac_snmp_community": "mycommunity",
        })

        self.assertFalse(get_mac_arp_priming_enabled())
        self.assertFalse(get_mac_netbios_enabled())
        self.assertTrue(get_mac_snmp_enabled())
        self.assertEqual(get_mac_snmp_community(), "mycommunity")

    def test_mac_discovery_api_roundtrip(self):
        # 1. Check GET returns default values
        resp = self.client.get("/api/settings/scanner")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertTrue(data["mac_arp_priming_enabled"])
        self.assertTrue(data["mac_netbios_enabled"])
        self.assertTrue(data["mac_snmp_enabled"])
        self.assertEqual(data["mac_snmp_community"], "public")

        # 2. Save custom values via POST /save
        save_resp = self.client.post(
            "/api/settings/scanner/save",
            data=json.dumps({
                "mac_arp_priming_enabled": 0,
                "mac_netbios_enabled": 1,
                "mac_snmp_enabled": 0,
                "mac_snmp_community": "secret-comm",
            }),
            content_type="application/json",
        )
        self.assertEqual(save_resp.status_code, 200)
        self.assertTrue(save_resp.get_json()["success"])

        # Check GET reflects saved values
        get_resp = self.client.get("/api/settings/scanner")
        saved_data = get_resp.get_json()
        self.assertFalse(saved_data["mac_arp_priming_enabled"])
        self.assertTrue(saved_data["mac_netbios_enabled"])
        self.assertFalse(saved_data["mac_snmp_enabled"])
        self.assertEqual(saved_data["mac_snmp_community"], "secret-comm")

        # 3. Reset via POST /reset target='mac_discovery'
        reset_resp = self.client.post(
            "/api/settings/scanner/reset",
            data=json.dumps({"target": "mac_discovery"}),
            content_type="application/json",
        )
        self.assertEqual(reset_resp.status_code, 200)
        reset_data = reset_resp.get_json()
        self.assertTrue(reset_data["success"])
        self.assertTrue(reset_data["mac_arp_priming_enabled"])
        self.assertTrue(reset_data["mac_netbios_enabled"])
        self.assertTrue(reset_data["mac_snmp_enabled"])
        self.assertEqual(reset_data["mac_snmp_community"], "public")

    def test_netbios_packet_encode_and_decode(self):
        query = _build_netbios_query(0x4321)
        self.assertEqual(len(query), 50)

        # Build simulated NBSTAT response
        import struct
        resp_buf = bytearray(struct.pack(">HHHHHH", 0x4321, 0x8400, 0, 1, 0, 0))
        resp_buf.extend(b"\xC0\x0C")  # compressed name
        resp_buf.extend(struct.pack(">HHIH", 0x0021, 0x0001, 0, 25))  # RR
        resp_buf.append(1)  # num_names
        resp_buf.extend(b"STORAGE         \x00\x00")
        resp_buf.extend(bytes([0x00, 0x11, 0x32, 0xAA, 0xBB, 0xCC]))

        mac = _parse_netbios_response(bytes(resp_buf), 0x4321)
        self.assertEqual(mac, "00:11:32:AA:BB:CC")

        # Malformed packet returns None
        self.assertIsNone(_parse_netbios_response(b"short", 0x4321))
        self.assertIsNone(_parse_netbios_response(b"\x00" * 40, 0x4321))

    def test_snmp_packet_encode_and_decode(self):
        req = _build_snmp_get_request(community="public", req_id=0x9999)
        self.assertTrue(len(req) > 0)

        # Build simulated SNMP response with MAC 00:0C:29:11:22:33
        oid_bytes = bytes([0x2B, 6, 1, 2, 1, 2, 2, 1, 6, 1])
        mock_mac = bytes([0x00, 0x0C, 0x29, 0x11, 0x22, 0x33])
        vb_oid = _asn1_encode_tlv(0x06, oid_bytes)
        vb_val = _asn1_encode_tlv(0x04, mock_mac)
        vb = _asn1_encode_tlv(0x30, vb_oid + vb_val)
        vbl = _asn1_encode_tlv(0x30, vb)
        pdu = _asn1_encode_tlv(0xA2, _asn1_encode_int(0x9999) + _asn1_encode_int(0) + _asn1_encode_int(0) + vbl)
        resp = _asn1_encode_tlv(0x30, _asn1_encode_int(1) + _asn1_encode_tlv(0x04, b"public") + pdu)

        mac = _parse_snmp_response_mac(resp)
        self.assertEqual(mac, "00:0C:29:11:22:33")

        # Corrupted packet returns None
        self.assertIsNone(_parse_snmp_response_mac(b""))
        self.assertIsNone(_parse_snmp_response_mac(b"\x30\x02\x00\x00"))

    def test_resolve_mac_tiered_fallback_order(self):
        test_ip = "192.168.10.88"

        # Tier 1 hit: Instant /proc/net/arp
        with patch("services.scheduler._read_proc_arp", return_value="AA:BB:CC:DD:EE:01") as m_arp, \
             patch("services.scheduler._prime_arp_cache") as m_prime, \
             patch("services.scheduler._query_cli_arp") as m_cli, \
             patch("services.scheduler._query_netbios_mac") as m_nb, \
             patch("services.scheduler._query_snmp_mac") as m_snmp:
            res = _resolve_mac(test_ip)
            self.assertEqual(res, "AA:BB:CC:DD:EE:01")
            m_arp.assert_called_once_with(test_ip)
            m_prime.assert_not_called()
            m_cli.assert_not_called()
            m_nb.assert_not_called()
            m_snmp.assert_not_called()

        # Tier 2 hit: Priming triggers kernel cache
        with patch("services.scheduler._read_proc_arp", side_effect=[None, "AA:BB:CC:DD:EE:02"]) as m_arp, \
             patch("services.scheduler._prime_arp_cache") as m_prime, \
             patch("services.scheduler._query_cli_arp") as m_cli:
            res = _resolve_mac(test_ip)
            self.assertEqual(res, "AA:BB:CC:DD:EE:02")
            m_prime.assert_called_once_with(test_ip)
            self.assertEqual(m_arp.call_count, 2)
            m_cli.assert_not_called()

        # Tier 3 hit: CLI fallback
        with patch("services.scheduler._read_proc_arp", return_value=None), \
             patch("services.scheduler._prime_arp_cache"), \
             patch("services.scheduler._query_cli_arp", return_value="AA:BB:CC:DD:EE:03") as m_cli, \
             patch("services.scheduler._query_netbios_mac") as m_nb:
            res = _resolve_mac(test_ip)
            self.assertEqual(res, "AA:BB:CC:DD:EE:03")
            m_cli.assert_called_once_with(test_ip)
            m_nb.assert_not_called()

        # Tier 4 hit: Cross-VLAN NetBIOS
        with patch("services.scheduler._read_proc_arp", return_value=None), \
             patch("services.scheduler._prime_arp_cache"), \
             patch("services.scheduler._query_cli_arp", return_value=None), \
             patch("services.scheduler._query_netbios_mac", return_value="AA:BB:CC:DD:EE:04") as m_nb, \
             patch("services.scheduler._query_snmp_mac") as m_snmp:
            res = _resolve_mac(test_ip)
            self.assertEqual(res, "AA:BB:CC:DD:EE:04")
            m_nb.assert_called_once_with(test_ip)
            m_snmp.assert_not_called()

        # Tier 5 hit: Cross-VLAN SNMP
        with patch("services.scheduler._read_proc_arp", return_value=None), \
             patch("services.scheduler._prime_arp_cache"), \
             patch("services.scheduler._query_cli_arp", return_value=None), \
             patch("services.scheduler._query_netbios_mac", return_value=None), \
             patch("services.scheduler._query_snmp_mac", return_value="AA:BB:CC:DD:EE:05") as m_snmp:
            res = _resolve_mac(test_ip)
            self.assertEqual(res, "AA:BB:CC:DD:EE:05")
            m_snmp.assert_called_once_with(test_ip, "public")

        # Disabled toggles are respected
        save_settings({
            "mac_arp_priming_enabled": "0",
            "mac_netbios_enabled": "0",
            "mac_snmp_enabled": "0",
        })
        with patch("services.scheduler._read_proc_arp", return_value=None), \
             patch("services.scheduler._prime_arp_cache") as m_prime, \
             patch("services.scheduler._query_cli_arp", return_value=None), \
             patch("services.scheduler._query_netbios_mac") as m_nb, \
             patch("services.scheduler._query_snmp_mac") as m_snmp:
            res = _resolve_mac(test_ip)
            self.assertIsNone(res)
            m_prime.assert_not_called()
            m_nb.assert_not_called()
            m_snmp.assert_not_called()

    def test_dns_query_and_response_parsing(self):
        import struct, socket
        # 1. Query building
        q = _build_dns_a_query("andregaming.galleon.co.za", trans_id=0x4321)
        self.assertIsNotNone(q)
        self.assertTrue(len(q) > 12)
        tid = struct.unpack(">H", q[:2])[0]
        self.assertEqual(tid, 0x4321)

        # 2. Parse response with direct A record
        resp = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("10.0.0.50")
        ip = _parse_dns_a_response(resp, expected_trans_id=0x4321)
        self.assertEqual(ip, "10.0.0.50")

        # 3. Parse response with CNAME then A record
        cname_ans = b"\xc0\x0c" + struct.pack(">HHIH", 5, 1, 300, 6) + b"\x03foo\xc0\x0c"
        a_ans = b"\xc0\x1f" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("10.0.0.75")
        resp_cname = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 2, 0, 0) + q[12:] + cname_ans + a_ans
        ip_cname = _parse_dns_a_response(resp_cname, expected_trans_id=0x4321)
        self.assertEqual(ip_cname, "10.0.0.75")

        # 4. Response with loopback IP is ignored
        resp_loopback = struct.pack(">HHHHHH", 0x4321, 0x8180, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("127.0.1.1")
        self.assertIsNone(_parse_dns_a_response(resp_loopback, expected_trans_id=0x4321))

        # 5. Response with error flags returns None
        resp_err = struct.pack(">HHHHHH", 0x4321, 0x8183, 1, 0, 0, 0) + q[12:]
        self.assertIsNone(_parse_dns_a_response(resp_err, expected_trans_id=0x4321))

    def test_direct_dns_query_function(self):
        with patch("services.scheduler._get_resolv_nameservers", return_value=["10.0.0.2"]):
            with patch("socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock_cls.return_value = mock_sock
                import struct, socket
                q = _build_dns_a_query("myhost.lan", trans_id=0x1234)
                valid_resp = struct.pack(">HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + q[12:] + b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 300, 4) + socket.inet_aton("10.0.0.111")
                mock_sock.recvfrom.return_value = (valid_resp, ("10.0.0.2", 53))

                resolved = _query_direct_dns_a_record("myhost.lan")
                self.assertEqual(resolved, "10.0.0.111")
                mock_sock.sendto.assert_called_once()

    def test_host_primary_lan_ip_detection(self):
        # Override takes precedence
        with patch("core.config.get_server_lan_ip_override", return_value="10.0.0.99"):
            self.assertEqual(_get_host_primary_lan_ip(), "10.0.0.99")

        # Fallback probe
        with patch("core.config.get_server_lan_ip_override", return_value=""):
            with patch("socket.socket") as mock_sock_cls:
                mock_sock = MagicMock()
                mock_sock_cls.return_value = mock_sock
                mock_sock.getsockname.return_value = ("10.0.0.231", 53530)
                self.assertEqual(_get_host_primary_lan_ip(), "10.0.0.231")

    def test_resolve_ip_loopback_substitution(self):
        # Normal remote IP passes through unchanged
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("10.0.0.121", 80))]):
            self.assertEqual(_resolve_ip("remote.lan"), "10.0.0.121")

        # Loopback resolution for FQDN with direct DNS hit
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.1.1", 80))]), \
             patch("services.scheduler._query_direct_dns_a_record", return_value="10.0.0.26"):
            self.assertEqual(_resolve_ip("andregaming.galleon.co.za"), "10.0.0.26")

        # Loopback resolution for localhost (or direct DNS miss) falls back to host primary LAN IP
        with patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.0.1", 80))]), \
             patch("services.scheduler._query_direct_dns_a_record", return_value=None), \
             patch("services.scheduler._get_host_primary_lan_ip", return_value="10.0.0.231"):
            self.assertEqual(_resolve_ip("localhost"), "10.0.0.231")

        # When feature is disabled, returns loopback as-is
        with patch("core.config.get_replace_loopback_ip_enabled", return_value=False), \
             patch("socket.getaddrinfo", return_value=[(None, None, None, None, ("127.0.1.1", 80))]):
            self.assertEqual(_resolve_ip("andregaming.galleon.co.za"), "127.0.1.1")

    def test_resolve_mac_tier_0_local_host(self):
        local_ip = "10.0.0.231"
        # When IP is identified as local host, returns host physical MAC directly
        with patch("services.scheduler._is_local_host_ip", return_value=True), \
             patch("services.scheduler._get_host_local_mac", return_value="04:D9:F5:D7:7D:89") as m_local, \
             patch("services.scheduler._read_proc_arp") as m_arp:
            res = _resolve_mac(local_ip)
            self.assertEqual(res, "04:D9:F5:D7:7D:89")
            m_local.assert_called_once_with(local_ip)
            m_arp.assert_not_called()

    def test_scanner_settings_api_loopback_controls(self):
        client = pulsecheck_app.app.test_client()

        # 1. GET scanner settings includes loopback fields
        res = client.get("/api/settings/scanner")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertIn("replace_loopback_ip_enabled", data)
        self.assertIn("server_lan_ip_override", data)
        self.assertIn("detected_host_lan_ip", data)

        # 2. POST save scanner settings updates loopback fields
        save_res = client.post("/api/settings/scanner/save", json={
            "replace_loopback_ip_enabled": 0,
            "server_lan_ip_override": "192.168.1.200",
        })
        self.assertEqual(save_res.status_code, 200)
        self.assertFalse(get_replace_loopback_ip_enabled())
        self.assertEqual(get_server_lan_ip_override(), "192.168.1.200")

        # 3. POST reset scanner settings with target='loopback_ip'
        reset_res = client.post("/api/settings/scanner/reset", json={"target": "loopback_ip"})
        self.assertEqual(reset_res.status_code, 200)
        reset_data = reset_res.get_json()
        self.assertTrue(reset_data["replace_loopback_ip_enabled"])
        self.assertEqual(reset_data["server_lan_ip_override"], "")
        self.assertTrue(get_replace_loopback_ip_enabled())


if __name__ == "__main__":
    unittest.main()
