from __future__ import annotations

import io
import json
import os
import re
import socket
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
)
import core.config as config_mod
from core.database import (
    get_db_connection,
    service_list,
    record_scan_completed,
    get_last_scheduled_check,
    get_status_rows,
    compute_overall_status,
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

MACLOOKUP_API_KEY = os.getenv("PULSECHECK_MACLOOKUP_API_KEY", "")
_MAC_LOOKUP_LOCK = threading.Lock()   # serialise API calls; one at a time


def _get_app_attr(name: str, default=None):
    """Retrieve attribute from app module if imported/patched there."""
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


# ── Network discovery ─────────────────────────────────────────────────────────

def _resolve_ip(hostname: str) -> str | None:
    """Return the first IPv4/IPv6 address for hostname, or None."""
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        return infos[0][4][0] if infos else None
    except (socket.gaierror, OSError):
        return None


def _resolve_mac(ip: str) -> str | None:
    """
    Look up MAC address for ip from the local ARP/neighbour cache.
    Works for same-LAN hosts; returns None for remote hosts.
    Checks /proc/net/arp first, then falls back to 'ip neigh' and 'arp -n'.
    """
    # 1. Direct file lookup in /proc/net/arp
    arp_path = Path("/proc/net/arp")
    if arp_path.is_file():
        try:
            with open(arp_path, "r", encoding="utf-8", errors="ignore") as f:
                # Skip header line: IP address HW type Flags HW address Mask Device
                lines = f.readlines()
                for line in lines[1:]:
                    parts = line.split()
                    if len(parts) >= 4 and parts[0] == ip:
                        flags = parts[2]
                        hw_addr = parts[3]
                        # Flags 0x0 indicates incomplete/failed ARP entry
                        if flags != "0x0" and re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", hw_addr):
                            if hw_addr != "00:00:00:00:00:00":
                                return hw_addr.upper()
        except Exception:
            pass

    # 2. CLI fallback: 'ip neigh'
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", ip],
            capture_output=True, text=True, timeout=3,
        )
        for token in result.stdout.split():
            if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", token):
                return token.upper()
    except Exception:
        pass

    # 3. CLI fallback: 'arp -n'
    try:
        result = subprocess.run(
            ["arp", "-n", ip],
            capture_output=True, text=True, timeout=3,
        )
        m = re.search(r"([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", result.stdout)
        if m:
            return m.group(0).upper()
    except Exception:
        pass
    return None


def _lookup_manufacturer(mac: str) -> str:
    """
    Query maclookup.app for the NIC manufacturer.
    Returns the vendor string, or "NONE" on failure.
    Throttled: holds _MAC_LOOKUP_LOCK + sleeps 1 s between calls.
    """
    global MACLOOKUP_API_KEY
    current_api_key = _get_app_attr("MACLOOKUP_API_KEY", MACLOOKUP_API_KEY)
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
                "has_checks": False,
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
        if app_mod:
            app_mod.IS_SCANNING = True

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

        after_snapshots = get_service_snapshots()
        changes = []

        for service_id, after_info in after_snapshots.items():
            before_info = before_snapshots.get(service_id)
            if not before_info or not before_info["has_checks"]:
                continue

            port_changes = []
            for port, new_status in after_info["port_statuses"].items():
                old_status = before_info["port_statuses"].get(port)
                if old_status and old_status != new_status:
                    if port in ("icmp", None):
                        port_changes.append(f"ICMP Ping: {old_status.upper()} -> {new_status.upper()}")
                    else:
                        port_changes.append(f"Port {port}: {old_status.upper()} -> {new_status.upper()}")

            if before_info["overall_status"] != after_info["overall_status"] or port_changes:
                changes.append({
                    "service": after_info["name"],
                    "old_status": before_info["overall_status"],
                    "new_status": after_info["overall_status"],
                    "port_changes": port_changes,
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
        record_scan_completed()
        if getattr(config_mod, "LINE_PROFILER_ENABLED", False) and getattr(config_mod, "GLOBAL_LINE_PROFILER", None) is not None:
            dump_line_profiler_stats()


def get_scan_schedule_info() -> dict:
    global GLOBAL_SCHEDULER, IS_SCANNING
    scheduler = _get_app_attr("GLOBAL_SCHEDULER", GLOBAL_SCHEDULER)
    now_utc = datetime.now(timezone.utc)
    interval_seconds = 600

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
    }



def run_background_tasks():
    global GLOBAL_SCHEDULER
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(check_all_services, "interval", minutes=10, id="pulsecheck_scan")
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
