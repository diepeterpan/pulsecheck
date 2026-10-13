from __future__ import annotations

import io
import json
import os
import re
import socket
import struct
import subprocess
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler

from core.config import (
    DEFAULT_SCAN_WORKERS,
    DEFAULT_SCAN_RETRIES,
    DEFAULT_SCAN_RETRY_INTERVAL,
    EXPLICIT_DEBUG,
    LINE_PROFILER_ENABLED,
    get_scan_interval_minutes,
    get_maclookup_api_key,
)
import core.config as config_mod
from core.database import (
    get_db_connection,
    service_list,
    record_scan_completed,
    get_last_scheduled_check,
    get_status_rows,
    compute_overall_status,
    clear_latest_port_checks,
    get_service_web_url,
)
from services.notifications import send_state_change_notification
from services.icons import (
    get_manufacturer_icon_url,
    get_manufacturer_name_aliases,
    resolve_and_cache_manufacturer_icon,
    resolve_missing_service_icons,
)

GLOBAL_SCHEDULER: BackgroundScheduler | None = None
IS_SCANNING: bool = False
IS_SCANNING_LOCK = threading.Lock()
SCAN_RUN_COUNT: int = 0
INITIAL_SCAN_COMPLETED: bool = False
STARTUP_SCAN_PENDING: bool = False
MACLOOKUP_API_KEY = os.getenv("PULSECHECK_MACLOOKUP_API_KEY", "")
_MAC_LOOKUP_LOCK = threading.Lock()   # serialise API calls; one at a time


def _get_app_attr(name: str, default=None):
    """Retrieve attribute from app module if imported/patched there."""
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


def is_initial_scan_active() -> bool:
    """Return True if system is starting up and performing its very first scan."""
    global INITIAL_SCAN_COMPLETED, STARTUP_SCAN_PENDING, SCAN_RUN_COUNT, IS_SCANNING
    init_done = _get_app_attr("INITIAL_SCAN_COMPLETED", INITIAL_SCAN_COMPLETED)
    if init_done:
        return False
    scan_count = _get_app_attr("SCAN_RUN_COUNT", SCAN_RUN_COUNT)
    if scan_count > 0:
        return False
    startup_pending = _get_app_attr("STARTUP_SCAN_PENDING", STARTUP_SCAN_PENDING)
    is_scanning = _get_app_attr("IS_SCANNING", IS_SCANNING)
    return bool(startup_pending or is_scanning)


# ── Network discovery ─────────────────────────────────────────────────────────

def _resolve_ip(hostname: str) -> str | None:
    """Return the first IPv4/IPv6 address for hostname, or None."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError):
        return None


def _normalize_mac(raw_mac: str | None) -> str | None:
    """Validate and normalize MAC address string to XX:XX:XX:XX:XX:XX format."""
    if not raw_mac or not isinstance(raw_mac, str):
        return None
    cleaned = raw_mac.strip().upper().replace("-", ":")
    if re.match(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", cleaned):
        if cleaned not in ("00:00:00:00:00:00", "FF:FF:FF:FF:FF:FF"):
            return cleaned
    return None


def _read_proc_arp(ip: str) -> str | None:
    """Look up MAC address directly from /proc/net/arp table without spawning child processes."""
    arp_path = Path("/proc/net/arp")
    if not arp_path.is_file():
        return None
    try:
        with open(arp_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    flags = parts[2]
                    hw_addr = parts[3]
                    if flags != "0x0":
                        return _normalize_mac(hw_addr)
    except Exception:
        pass
    return None


def _prime_arp_cache(ip: str) -> None:
    """Trigger the Linux kernel ARP subsystem by sending a single unprivileged UDP packet."""
    try:
        socket.inet_aton(ip)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(0.05)
        sock.sendto(b"\x00", (ip, 53530))
        sock.close()
    except Exception:
        pass
    time.sleep(0.025)


def _query_cli_arp(ip: str) -> str | None:
    """Query local neighbour table via 'ip neigh', 'arping', or 'arp -n' CLI utilities."""
    # 1. 'ip neigh show <ip>'
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=1,
        )
        for token in result.stdout.split():
            mac = _normalize_mac(token)
            if mac:
                return mac
    except Exception:
        pass

    # 2. 'arping -c 1 -w 1 <ip>'
    try:
        result = subprocess.run(
            ["arping", "-c", "1", "-w", "1", ip],
            capture_output=True, text=True, timeout=1.5,
        )
        for line in result.stdout.splitlines():
            m = re.search(r"\[([0-9a-fA-F:]{17})\]", line)
            if m:
                mac = _normalize_mac(m.group(1))
                if mac:
                    return mac
            m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", line)
            if m:
                mac = _normalize_mac(m.group(0))
                if mac:
                    return mac
    except Exception:
        pass

    # 3. 'arp -n <ip>'
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True, text=True, timeout=1,
        )
        m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", result.stdout)
        if m:
            return _normalize_mac(m.group(0))
    except Exception:
        pass

    return None


def _build_netbios_query(trans_id: int = 0x1337) -> bytes:
    """Build an RFC 1002 NBSTAT wildcard query packet."""
    header = struct.pack(">HHHHHH", trans_id, 0x0000, 1, 0, 0, 0)
    raw_name = b"*" + b" " * 15
    encoded_name = bytearray([32])
    for b in raw_name:
        encoded_name.append(0x41 + (b >> 4))
        encoded_name.append(0x41 + (b & 0x0F))
    encoded_name.append(0x00)
    qtype_qclass = struct.pack(">HH", 0x0021, 0x0001)
    return header + bytes(encoded_name) + qtype_qclass


def _parse_netbios_response(resp: bytes, expected_trans_id: int | None = 0x1337) -> str | None:
    """Extract MAC address from RFC 1002 NBSTAT response."""
    try:
        if len(resp) < 31:
            return None
        trans_id, flags, questions, answerrrs, _, _ = struct.unpack(">HHHHHH", resp[:12])
        if expected_trans_id is not None and trans_id != expected_trans_id:
            return None
        if answerrrs < 1:
            return None
        idx = 12
        while idx < len(resp):
            length = resp[idx]
            if length == 0:
                idx += 1
                break
            elif (length & 0xC0) == 0xC0:
                idx += 2
                break
            else:
                idx += 1 + length
        if idx + 10 > len(resp):
            return None
        rr_type, rr_class, ttl, rdlength = struct.unpack(">HHIH", resp[idx : idx + 10])
        idx += 10
        if rr_type != 0x0021 or idx + rdlength > len(resp):
            return None
        num_names = resp[idx]
        unit_id_offset = idx + 1 + (num_names * 18)
        if unit_id_offset + 6 <= idx + rdlength:
            mac_bytes = resp[unit_id_offset : unit_id_offset + 6]
            return _normalize_mac(":".join(f"{b:02X}" for b in mac_bytes))
    except Exception:
        pass
    return None


def _query_netbios_mac(ip: str, timeout: float = 0.3) -> str | None:
    """Send RFC 1002 NBSTAT wildcard query to UDP port 137 and extract MAC."""
    try:
        socket.inet_aton(ip)
    except OSError:
        return None

    trans_id = 0x1337
    packet = _build_netbios_query(trans_id)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 137))
        resp, _ = sock.recvfrom(1024)
        return _parse_netbios_response(resp, trans_id)
    except (OSError, socket.timeout):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _asn1_encode_length(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    elif length < 256:
        return bytes([0x81, length])
    else:
        return bytes([0x82, (length >> 8) & 0xFF, length & 0xFF])


def _asn1_encode_tlv(tag: int, value: bytes) -> bytes:
    return bytes([tag]) + _asn1_encode_length(len(value)) + value


def _asn1_encode_int(val: int) -> bytes:
    if val == 0:
        return b"\x02\x01\x00"
    raw = []
    v = val
    while v > 0:
        raw.append(v & 0xFF)
        v >>= 8
    if raw[-1] & 0x80:
        raw.append(0)
    raw.reverse()
    val_bytes = bytes(raw)
    return b"\x02" + _asn1_encode_length(len(val_bytes)) + val_bytes


def _build_snmp_get_request(community: str = "public", req_id: int = 0x1337) -> bytes:
    """Build an SNMP v2c GET PDU for IF-MIB ifPhysAddress.1 (1.3.6.1.2.1.2.2.1.6.1)."""
    oid_bytes = bytes([0x2B, 6, 1, 2, 1, 2, 2, 1, 6, 1])
    varbind_oid = _asn1_encode_tlv(0x06, oid_bytes)
    varbind_val = _asn1_encode_tlv(0x05, b"")
    varbind = _asn1_encode_tlv(0x30, varbind_oid + varbind_val)
    varbind_list = _asn1_encode_tlv(0x30, varbind)
    pdu = _asn1_encode_tlv(0xA0, _asn1_encode_int(req_id) + _asn1_encode_int(0) + _asn1_encode_int(0) + varbind_list)
    version_tlv = _asn1_encode_int(1)
    comm_tlv = _asn1_encode_tlv(0x04, (community or "public").encode("utf-8"))
    return _asn1_encode_tlv(0x30, version_tlv + comm_tlv + pdu)


def _parse_asn1_tlv(data: bytes, offset: int = 0) -> tuple[int, bytes, int]:
    if offset >= len(data):
        raise ValueError("Offset out of bounds")
    tag = data[offset]
    offset += 1
    if offset >= len(data):
        raise ValueError("Truncated TLV header")
    len_byte = data[offset]
    offset += 1
    if len_byte < 128:
        length = len_byte
    elif len_byte == 0x81:
        if offset >= len(data):
            raise ValueError("Truncated length byte")
        length = data[offset]
        offset += 1
    elif len_byte == 0x82:
        if offset + 1 >= len(data):
            raise ValueError("Truncated length bytes")
        length = (data[offset] << 8) | data[offset + 1]
        offset += 2
    else:
        raise ValueError("Unsupported length format")
    if offset + length > len(data):
        raise ValueError("TLV value exceeds packet length")
    return tag, data[offset : offset + length], offset + length


def _parse_snmp_response_mac(resp: bytes) -> str | None:
    """Extract MAC address from SNMP v2c GetResponse PDU."""
    try:
        tag, seq_val, _ = _parse_asn1_tlv(resp, 0)
        if tag != 0x30:
            return None
        # version
        _, _, off = _parse_asn1_tlv(seq_val, 0)
        # community
        _, _, off = _parse_asn1_tlv(seq_val, off)
        # PDU
        pdu_tag, pdu_val, _ = _parse_asn1_tlv(seq_val, off)
        if pdu_tag != 0xA2:
            return None
        # req_id
        _, _, pdu_off = _parse_asn1_tlv(pdu_val, 0)
        # error status
        _, err_val, pdu_off = _parse_asn1_tlv(pdu_val, pdu_off)
        if err_val != b"\x00":
            return None
        # error index
        _, _, pdu_off = _parse_asn1_tlv(pdu_val, pdu_off)
        # varbind list
        vbl_tag, vbl_val, _ = _parse_asn1_tlv(pdu_val, pdu_off)
        if vbl_tag != 0x30:
            return None
        # varbind 1
        vb_tag, vb_val, _ = _parse_asn1_tlv(vbl_val, 0)
        if vb_tag != 0x30:
            return None
        # OID
        _, _, vb_off = _parse_asn1_tlv(vb_val, 0)
        # Value
        val_tag, val_val, _ = _parse_asn1_tlv(vb_val, vb_off)
        if val_tag == 0x04 and len(val_val) == 6:
            return _normalize_mac(":".join(f"{b:02X}" for b in val_val))
    except Exception:
        pass
    return None


def _query_snmp_mac(ip: str, community: str = "public", timeout: float = 0.3) -> str | None:
    """Send SNMP v2c GET query for IF-MIB ifPhysAddress.1 to UDP port 161 and extract MAC."""
    try:
        socket.inet_aton(ip)
    except OSError:
        return None

    packet = _build_snmp_get_request(community=community, req_id=0x1337)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(packet, (ip, 161))
        resp, _ = sock.recvfrom(1024)
        return _parse_snmp_response_mac(resp)
    except (OSError, socket.timeout):
        return None
    finally:
        if sock:
            try:
                sock.close()
            except Exception:
                pass


def _resolve_mac(ip: str) -> str | None:
    """
    Look up MAC address for ip using a 5-tier hybrid discovery pipeline:
    Tier 1: Instant /proc/net/arp in-memory cache (<1ms)
    Tier 2: Active local ARP priming via UDP probe if enabled (~25ms)
    Tier 3: Local CLI fallback ('ip neigh', 'arping', 'arp -n') (~35ms)
    Tier 4: Cross-VLAN NetBIOS NBSTAT query (UDP 137) if enabled (~60ms)
    Tier 5: Cross-VLAN SNMP query (UDP 161) if enabled (~80ms)
    """
    if not ip or not isinstance(ip, str):
        return None
    ip = ip.strip()

    # Tier 1: Instant /proc/net/arp check
    mac = _read_proc_arp(ip)
    if mac:
        return mac

    # Tier 2: Active Local ARP Priming (if enabled)
    from core.config import (
        get_mac_arp_priming_enabled,
        get_mac_netbios_enabled,
        get_mac_snmp_enabled,
        get_mac_snmp_community,
    )
    if get_mac_arp_priming_enabled():
        _prime_arp_cache(ip)
        mac = _read_proc_arp(ip)
        if mac:
            return mac

    # Tier 3: CLI fallback
    mac = _query_cli_arp(ip)
    if mac:
        return mac

    # Tier 4: Cross-VLAN NetBIOS NBSTAT (UDP 137)
    if get_mac_netbios_enabled():
        mac = _query_netbios_mac(ip)
        if mac:
            return mac

    # Tier 5: Device SNMP IF-MIB (UDP 161)
    if get_mac_snmp_enabled():
        community = get_mac_snmp_community()
        mac = _query_snmp_mac(ip, community)
        if mac:
            return mac

    return None


def _lookup_manufacturer(mac: str) -> str:
    """
    Query maclookup.app for the NIC manufacturer.
    Returns the vendor string, or "NONE" on failure.
    Throttled: holds _MAC_LOOKUP_LOCK + sleeps 1 s between calls.
    """
    global MACLOOKUP_API_KEY
    get_key_fn = _get_app_attr("get_maclookup_api_key", get_maclookup_api_key)
    current_api_key = get_key_fn() if callable(get_key_fn) else _get_app_attr("MACLOOKUP_API_KEY", MACLOOKUP_API_KEY)
    with _MAC_LOOKUP_LOCK:
        try:
            url = f"https://api.maclookup.app/v2/macs/{mac}"
            headers = {}
            if current_api_key:
                headers["Authorization"] = f"Bearer {current_api_key}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                vendor = (data.get("company") or "").strip()
                if not vendor:
                    return "NONE"
                v_lower = vendor.lower()
                aliases = get_manufacturer_name_aliases()
                for alias_key, canon_name in aliases.items():
                    if alias_key == v_lower or alias_key in v_lower:
                        return canon_name
                return vendor
        except Exception:
            return "NONE"
        finally:
            time.sleep(1)


def _update_discovery_fields(service_id: int, ip, mac, manufacturer):
    """Persist the three discovery fields for one service."""
    try:
        conn = get_db_connection()
        conn.execute(
            "UPDATE services SET discovered_ip=?, discovered_mac=?, "
            "discovered_manufacturer=? WHERE id=?",
            (ip, mac, manufacturer, service_id),
        )
        conn.commit()
        conn.close()
    except Exception as exc:
        print(f"[Discovery] DB update error: {exc}")


def discover_network_info_for_service(service_id: int, hostname: str, prev_mac: str | None = None):
    """
    Full discovery pipeline for one service:
      1. Resolve hostname -> IP
      2. Resolve IP -> MAC (ARP)
      3. Lookup MAC -> Manufacturer (API, throttled, skip if MAC unchanged)
    """
    ip = _resolve_ip(hostname)
    if not ip:
        _update_discovery_fields(service_id, None, None, None)
        return

    mac = _resolve_mac(ip)
    if not mac:
        _update_discovery_fields(service_id, ip, None, None)
        return

    # Skip API if MAC is the same as last run
    if prev_mac and prev_mac.upper() == mac.upper():
        # Update IP (may have changed), keep manufacturer as-is
        conn = get_db_connection()
        conn.execute(
            "UPDATE services SET discovered_ip=? WHERE id=?",
            (ip, service_id),
        )
        conn.commit()
        conn.close()
        return

    manufacturer = _lookup_manufacturer(mac)
    _update_discovery_fields(service_id, ip, mac, manufacturer)
    if manufacturer and manufacturer != "NONE":
        try:
            resolve_and_cache_manufacturer_icon(manufacturer)
        except Exception:
            pass


def run_discovery_for_all_services():
    """
    Hourly scheduled job.
    Runs up to 5 services in parallel (IP+MAC lookup).
    MAC -> manufacturer calls are serialised via _MAC_LOOKUP_LOCK.
    """
    rows = []
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT id, name, discovered_mac FROM services"
        ).fetchall()
        conn.close()
    except Exception as exc:
        print(f"[Discovery] DB read error: {exc}")
        return

    def _run_one(row):
        discover_network_info_for_service(
            row["id"], row["name"], row["discovered_mac"]
        )

    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(_run_one, row) for row in rows]
        for f in futures:
            try:
                f.result()
            except Exception as exc:
                print(f"[Discovery] Worker error: {exc}")


def trigger_discovery_async(service_id: int, hostname: str, prev_mac: str | None = None):
    """Fire-and-forget discovery for a single service."""
    t = threading.Thread(
        target=discover_network_info_for_service,
        args=(service_id, hostname, prev_mac),
        daemon=True,
    )
    t.start()


def resolve_missing_manufacturers_and_icons():
    """
    Task run on startup and every 12 hours:
    1. Resolve manufacturer names for services with a MAC address but no valid manufacturer name.
    2. Resolve/fetch manufacturer icons for any stored manufacturer lacking a local cached icon.
    """
    print("[MfgJob] Starting scheduled check for missing manufacturers and icons...")
    # --- Part 1: Resolve missing manufacturer names ---
    try:
        conn = get_db_connection()
        missing_mfg_services = conn.execute(
            "SELECT id, name, discovered_mac, discovered_manufacturer "
            "FROM services "
            "WHERE discovered_mac IS NOT NULL "
            "  AND trim(discovered_mac) != '' "
            "  AND (discovered_manufacturer IS NULL OR trim(discovered_manufacturer) = '' OR upper(trim(discovered_manufacturer)) = 'NONE')"
        ).fetchall()
        conn.close()

        if missing_mfg_services:
            print(f"[MfgJob] Found {len(missing_mfg_services)} service(s) needing manufacturer resolution.")
            for svc in missing_mfg_services:
                svc_id = svc["id"]
                mac = svc["discovered_mac"]
                try:
                    mfg = _lookup_manufacturer(mac)
                    if mfg and mfg.strip().upper() != "NONE":
                        conn = get_db_connection()
                        conn.execute(
                            "UPDATE services SET discovered_manufacturer = ? WHERE id = ?",
                            (mfg, svc_id),
                        )
                        conn.commit()
                        conn.close()
                        print(f"[MfgJob] Resolved manufacturer for '{svc['name']}' (ID {svc_id}, MAC {mac}) -> {mfg}")
                        # Immediately attempt to cache the icon as well
                        try:
                            resolve_and_cache_manufacturer_icon(mfg)
                        except Exception as icon_err:
                            print(f"[MfgJob] Error caching icon for {mfg}: {icon_err}")
                    else:
                        print(f"[MfgJob] Could not resolve manufacturer for MAC {mac} ('{svc['name']}')")
                except Exception as lookup_err:
                    print(f"[MfgJob] Error looking up MAC {mac} for service ID {svc_id}: {lookup_err}")
        else:
            print("[MfgJob] All services with MAC addresses already have resolved manufacturers.")
    except Exception as exc:
        print(f"[MfgJob] Database error checking missing manufacturers: {exc}")

    # --- Part 2: Resolve missing manufacturer icons ---
    try:
        conn = get_db_connection()
        mfg_rows = conn.execute(
            "SELECT DISTINCT discovered_manufacturer "
            "FROM services "
            "WHERE discovered_manufacturer IS NOT NULL "
            "  AND trim(discovered_manufacturer) != '' "
            "  AND upper(trim(discovered_manufacturer)) != 'NONE'"
        ).fetchall()
        conn.close()

        for row in mfg_rows:
            mfg = row["discovered_manufacturer"].strip()
            # Check if icon already exists on disk
            if not get_manufacturer_icon_url(mfg):
                print(f"[MfgJob] Missing icon for manufacturer '{mfg}', attempting to resolve...")
                try:
                    icon_url = resolve_and_cache_manufacturer_icon(mfg)
                    if icon_url:
                        print(f"[MfgJob] Successfully cached icon for '{mfg}': {icon_url}")
                    else:
                        print(f"[MfgJob] Could not find/download icon for '{mfg}'")
                except Exception as icon_err:
                    print(f"[MfgJob] Error fetching icon for '{mfg}: {icon_err}")
    except Exception as exc:
        print(f"[MfgJob] Database error checking manufacturer icons: {exc}")

    print("[MfgJob] Scheduled check for missing manufacturers and icons completed.")


def get_service_snapshots() -> dict[int, dict]:
    rows = get_status_rows()
    services_map: dict[int, dict] = {}
    for row in rows:
        s_id = row["id"]
        if s_id not in services_map:
            services_map[s_id] = {
                "id": s_id,
                "name": row["name"],
                "service": row["name"],
                "discovered_ip": row.get("discovered_ip"),
                "discovered_mac": row.get("discovered_mac"),
                "discovered_manufacturer": row.get("discovered_manufacturer"),
                "has_checks": False,
                "ports": row.get("ports") or [],
                "port_statuses": {},
            }
        if row["checked_at"] is not None:
            services_map[s_id]["has_checks"] = True
            port_key = row["port"] if row["port"] is not None else "icmp"
            services_map[s_id]["port_statuses"][port_key] = row["status"]

    for s_id, s_data in services_map.items():
        s_data["overall_status"] = compute_overall_status(s_data["port_statuses"])

    return services_map


# ── Profiler Helpers ──────────────────────────────────────────────────────────

def dump_line_profiler_stats(output_file: str | None = None, disable: bool = False):
    """Print line-by-line profiler timing report to terminal and optionally dump to .lprof file."""
    profiler = getattr(config_mod, "GLOBAL_LINE_PROFILER", None)
    if profiler is None:
        return

    print("\n" + "=" * 80)
    print(" [LINE PROFILER STATS] Scan Cycle Timing Analysis")
    print("=" * 80)
    try:
        profiler.print_stats()
    except Exception as exc:
        print(f"[LineProfiler] Failed to print stats: {exc}")

    if output_file or os.getenv("PULSECHECK_PROFILE_OUT"):
        dump_path = output_file or os.getenv("PULSECHECK_PROFILE_OUT", "pulsecheck_scan.lprof")
        try:
            profiler.dump_stats(dump_path)
            print(f"[LineProfiler] Saved raw profile binary to: {dump_path}")
        except Exception as exc:
            print(f"[LineProfiler] Failed saving {dump_path}: {exc}")
    print("=" * 80 + "\n")

    if disable:
        try:
            profiler.disable()
        except Exception:
            pass


def get_line_profiler_stats_text() -> str:
    """Return formatted text output of current LineProfiler timings."""
    profiler = getattr(config_mod, "GLOBAL_LINE_PROFILER", None)
    if profiler is None:
        return "Line profiler is not active.\nStart PulseCheck with option 3 (Line-Profiler) or set PULSECHECK_PROFILE=1."
    buf = io.StringIO()
    try:
        profiler.print_stats(stream=buf)
        output = buf.getvalue()
        if not output.strip():
            return "No profiling stats captured yet. Scan cycles or visits to /status will generate data."
        return output
    except Exception as exc:
        return f"Error extracting profiler stats: {exc}"


def enable_line_profiling():
    """Initialize and enable line_profiler across scan and probe functions."""
    try:
        from line_profiler import LineProfiler
    except ImportError:
        print("[LineProfiler] Error: 'line_profiler' package is not installed. Run: pip install line-profiler")
        return False

    lp = LineProfiler()
    app_mod = sys.modules.get("app")

    from services.scanner import scan_service, scan_service_with_retries, fetch_response
    functions_to_profile = [
        check_all_services,
        scan_service_with_retries,
        scan_service,
        fetch_response,
        get_status_rows,
    ]
    if app_mod and hasattr(app_mod, "status"):
        functions_to_profile.append(getattr(app_mod, "status"))

    for fn in functions_to_profile:
        target_fn = getattr(fn, "__wrapped__", fn)
        lp.add_function(target_fn)

    lp.enable()
    config_mod.GLOBAL_LINE_PROFILER = lp
    config_mod.LINE_PROFILER_ENABLED = True
    if app_mod:
        setattr(app_mod, "GLOBAL_LINE_PROFILER", lp)
        setattr(app_mod, "LINE_PROFILER_ENABLED", True)

    import atexit
    import builtins
    builtins.__dict__["profile"] = lp

    def _teardown_profiler():
        try:
            lp.disable()
        except Exception:
            pass

    atexit.register(_teardown_profiler)
    return True


# ── Scanning & Scheduler ──────────────────────────────────────────────────────

@profile
def check_all_services(
    workers: int | None = None,
    max_retries: int | None = None,
    retry_interval: int | None = None,
) -> list[dict]:
    global IS_SCANNING
    app_mod = sys.modules.get("app")

    # Update scanning state
    scanning_lock = _get_app_attr("IS_SCANNING_LOCK", IS_SCANNING_LOCK)
    with scanning_lock:
        IS_SCANNING = True
        STARTUP_SCAN_PENDING = False
        if app_mod:
            app_mod.IS_SCANNING = True
            app_mod.STARTUP_SCAN_PENDING = False

    try:
        num_workers = DEFAULT_SCAN_WORKERS if workers is None else max(1, workers)
        retries = DEFAULT_SCAN_RETRIES if max_retries is None else max_retries
        interval = DEFAULT_SCAN_RETRY_INTERVAL if retry_interval is None else retry_interval

        before_snapshots = get_service_snapshots()
        active_services = [
            service for service in service_list()
            if not service.get("paused") and any(
                p.get("port") is None
                or (p.get("protocol") or "").strip().lower() in ("icmp", "icmp-ping")
                or bool((p.get("protocol") or "").strip())
                or bool((service.get("protocol") or "").strip())
                for p in (service.get("ports") or [])
            )
        ]

        if active_services:
            max_workers = min(num_workers, len(active_services))
            from services.scanner import scan_service_with_retries
            scan_worker = _get_app_attr("scan_service_with_retries", scan_service_with_retries)

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = [
                    executor.submit(
                        scan_worker,
                        service,
                        max_retries=retries,
                        retry_interval=interval,
                    )
                    for service in active_services
                ]
                for future in futures:
                    try:
                        future.result()
                    except Exception as exc:
                        print(f"[PulseCheck Scan Error] Service scan thread error: {exc}")

        global SCAN_RUN_COUNT
        SCAN_RUN_COUNT = _get_app_attr("SCAN_RUN_COUNT", SCAN_RUN_COUNT) + 1
        if app_mod:
            app_mod.SCAN_RUN_COUNT = SCAN_RUN_COUNT

        after_snapshots = get_service_snapshots()
        changes = []

        # State change notifications are only evaluated from the 2nd check_all_services run onwards
        if SCAN_RUN_COUNT >= 2:
            for service_id, after_info in after_snapshots.items():
                before_info = before_snapshots.get(service_id)
                if not before_info or not before_info.get("has_checks"):
                    continue

                old_overall = before_info.get("overall_status")
                new_overall = after_info.get("overall_status")
                if not old_overall or not new_overall:
                    continue

                port_changes = []
                for port, new_status in after_info.get("port_statuses", {}).items():
                    old_status = before_info.get("port_statuses", {}).get(port)
                    if old_status and new_status and old_status != new_status:
                        if port in ("icmp", None):
                            port_changes.append(f"ICMP Ping: {old_status.upper()} -> {new_status.upper()}")
                        else:
                            port_changes.append(f"Port {port}: {old_status.upper()} -> {new_status.upper()}")

                if old_overall != new_overall or port_changes:
                    svc_ports = after_info.get("ports") or []
                    web_url = get_service_web_url(after_info["name"], svc_ports)
                    changes.append({
                        "service": after_info["name"],
                        "old_status": old_overall,
                        "new_status": new_overall,
                        "port_changes": port_changes,
                        "web_url": web_url,
                        "discovered_ip": after_info.get("discovered_ip"),
                        "discovered_mac": after_info.get("discovered_mac"),
                        "discovered_manufacturer": after_info.get("discovered_manufacturer"),
                    })

            if changes:
                send_notification_fn = _get_app_attr("send_state_change_notification", send_state_change_notification)
                send_notification_fn(changes)

        return changes
    finally:
        with scanning_lock:
            IS_SCANNING = False
            if app_mod:
                app_mod.IS_SCANNING = False
        global INITIAL_SCAN_COMPLETED
        INITIAL_SCAN_COMPLETED = True
        if app_mod:
            app_mod.INITIAL_SCAN_COMPLETED = True
        record_scan_completed()
        if getattr(config_mod, "LINE_PROFILER_ENABLED", False) and getattr(config_mod, "GLOBAL_LINE_PROFILER", None) is not None:
            dump_line_profiler_stats()


def get_scan_schedule_info() -> dict:
    global GLOBAL_SCHEDULER, IS_SCANNING
    scheduler = _get_app_attr("GLOBAL_SCHEDULER", GLOBAL_SCHEDULER)
    now_utc = datetime.now(timezone.utc)
    scan_int_min = _get_app_attr("get_scan_interval_minutes", get_scan_interval_minutes)()
    interval_seconds = max(1, scan_int_min) * 60

    next_dt = None
    if scheduler:
        try:
            job = scheduler.get_job("pulsecheck_scan")
            if job and job.next_run_time:
                next_dt = job.next_run_time
        except Exception:
            pass

    if next_dt is None:
        last_check = get_last_scheduled_check()
        if last_check["timestamp"]:
            candidate = datetime.fromtimestamp(last_check["timestamp"], tz=timezone.utc) + timedelta(seconds=interval_seconds)
            if candidate > now_utc:
                next_dt = candidate
        if next_dt is None:
            next_dt = now_utc + timedelta(seconds=interval_seconds)

    if next_dt.tzinfo is None:
        next_dt = next_dt.replace(tzinfo=timezone.utc)

    seconds_remaining = max(0, int((next_dt - now_utc).total_seconds()))

    is_scanning = False
    scanning_lock = _get_app_attr("IS_SCANNING_LOCK", IS_SCANNING_LOCK)
    with scanning_lock:
        is_scanning = _get_app_attr("IS_SCANNING", IS_SCANNING)

    return {
        "next_scan_utc": next_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
        "next_check_iso": next_dt.isoformat(),
        "next_check_timestamp": next_dt.timestamp(),
        "seconds_remaining": seconds_remaining,
        "interval_seconds": interval_seconds,
        "is_scanning": is_scanning,
        "is_initial_scan": is_initial_scan_active(),
    }



def run_background_tasks():
    global GLOBAL_SCHEDULER, SCAN_RUN_COUNT, INITIAL_SCAN_COMPLETED, STARTUP_SCAN_PENDING
    clear_fn = _get_app_attr("clear_latest_port_checks", clear_latest_port_checks)
    clear_fn()
    SCAN_RUN_COUNT = 0
    INITIAL_SCAN_COMPLETED = False
    STARTUP_SCAN_PENDING = True
    app_mod = sys.modules.get("app")
    if app_mod:
        app_mod.SCAN_RUN_COUNT = 0
        app_mod.INITIAL_SCAN_COMPLETED = False
        app_mod.STARTUP_SCAN_PENDING = True

    scheduler = BackgroundScheduler(daemon=True)
    scan_int_min = _get_app_attr("get_scan_interval_minutes", get_scan_interval_minutes)()
    scheduler.add_job(
        check_all_services,
        "interval",
        minutes=max(1, scan_int_min),
        id="pulsecheck_scan",
        next_run_time=datetime.now(),
    )
    scheduler.add_job(
        run_discovery_for_all_services,
        "interval",
        hours=1,
        id="pulsecheck_discovery",
        next_run_time=datetime.now(),
    )
    scheduler.add_job(
        resolve_missing_manufacturers_and_icons,
        "interval",
        hours=12,
        id="pulsecheck_manufacturer_and_icon_sync",
        next_run_time=datetime.now(),
    )
    scheduler.start()
    GLOBAL_SCHEDULER = scheduler

    app_mod = sys.modules.get("app")
    if app_mod:
        app_mod.GLOBAL_SCHEDULER = scheduler

    # One-time startup task for missing service product icons (no recurring schedule)
    threading.Thread(
        target=resolve_missing_service_icons,
        name="StartupServiceIconResolver",
        daemon=True,
    ).start()

    return scheduler


def reschedule_scan_job(interval_minutes: int) -> bool:
    """Reschedule the background recurring scan job to a new interval in minutes."""
    global GLOBAL_SCHEDULER
    sched = _get_app_attr("GLOBAL_SCHEDULER", GLOBAL_SCHEDULER)
    if sched and sched.running:
        try:
            sched.reschedule_job(
                "pulsecheck_scan",
                trigger="interval",
                minutes=max(1, int(interval_minutes)),
            )
            return True
        except Exception as exc:
            print(f"[Scheduler] Failed to reschedule scan job: {exc}")
    return False
