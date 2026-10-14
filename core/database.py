"""Database connection, migration, and data access functions."""
from __future__ import annotations

import functools
import json
import os
import re
import sqlite3
import sys
import uuid
from datetime import datetime, timezone, timedelta
from urllib.parse import urlsplit
from zoneinfo import ZoneInfo

from core.config import (
    DEFAULT_HISTORY_RETENTION_DAYS,
    DEFAULT_SETTINGS,
)
import core.config


def get_db_path():
    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, "DB_PATH"):
        return app_mod.DB_PATH
    return core.config.DB_PATH


def get_db_connection():
    conn = sqlite3.connect(get_db_path(), timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


def parse_hex_bytes(value: str | bytes | None) -> bytes:
    """Parse a hex byte string into raw bytes.
    Accepts space-separated, comma/colon-separated, or contiguous hex characters (e.g. '01 02 A3 FF', '0x01, 0x02', or '0102a3ff').
    Raises ValueError on invalid hex input."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    raw_str = str(value).strip()
    if not raw_str:
        return b""
    tokens = [t for t in re.split(r"[\s,:]+", raw_str) if t]
    cleaned_parts = []
    for t in tokens:
        if t.lower().startswith("0x"):
            t = t[2:]
        if len(t) == 1:
            t = "0" + t
        cleaned_parts.append(t)
    cleaned = "".join(cleaned_parts)
    if not cleaned:
        return b""
    if len(cleaned) % 2 != 0:
        raise ValueError("Hex string must have an even number of characters (two hex digits per byte).")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise ValueError(f"Invalid hexadecimal string: {exc}")


def format_hex_bytes(data: bytes | str | None) -> str:
    """Format raw bytes or a hex string into uppercase space-separated hex bytes (e.g. '01 02 A3 FF')."""
    if not data:
        return ""
    if isinstance(data, str):
        try:
            raw = parse_hex_bytes(data)
        except ValueError:
            return data.strip()
    else:
        raw = data
    return " ".join(f"{b:02X}" for b in raw)


def normalize_service(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned.replace("http://", "", 1)
    if cleaned.startswith("https://"):
        cleaned = cleaned.replace("https://", "", 1)
    cleaned = cleaned.split("/")[0].strip().strip(".")
    if not cleaned:
        raise ValueError("Service name cannot be empty.")
    return cleaned


def derive_match(service_name: str) -> str:
    first_label = normalize_service(service_name).split(".", 1)[0]
    return first_label.split("-", 1)[0]


def normalize_url_path(value: str | None) -> str:
    path = (value or "").strip()
    if not path:
        return ""
    if path.startswith("?"):
        path = "/" + path
    if not path.startswith("/") or any(character.isspace() for character in path):
        raise ValueError("URL path must start with '/' and contain no spaces.")
    parsed = urlsplit(path)
    if parsed.scheme or parsed.netloc:
        raise ValueError("URL path must contain only a path and optional query, without full URL or host.")
    if parsed.fragment:
        raise ValueError("URL path must not contain a fragment ('#').")
    return path


def get_server_timezone():
    tz_name = (os.getenv("PULSECHECK_TIMEZONE") or os.getenv("TZ") or "").strip()
    if tz_name:
        try:
            return ZoneInfo(tz_name)
        except Exception:
            pass
    return datetime.now().astimezone().tzinfo


def get_current_local_time_str() -> str:
    now = datetime.now(get_server_timezone())
    tz_label = now.strftime("%Z")
    if tz_label:
        return now.strftime("%Y-%m-%d %H:%M:%S") + f" {tz_label}"
    return now.strftime("%Y-%m-%d %H:%M:%S")


def parse_iso_or_utc_datetime(val_str: str | None) -> datetime | None:
    if not val_str:
        return None
    val_clean = str(val_str).strip()
    try:
        return datetime.fromisoformat(val_clean.replace("Z", "+00:00"))
    except ValueError:
        pass

    for fmt in ("%Y-%m-%d %H:%M:%S %Z", "%Y-%m-%d %H:%M:%S UTC", "%Y-%m-%d %H:%M:%S"):
        try:
            dt = datetime.strptime(val_clean, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            pass
    return None


@functools.lru_cache(maxsize=1024)
def _cached_format_local_time(val_str: str, target_tz: timezone | ZoneInfo | None) -> str:
    parsed = parse_iso_or_utc_datetime(val_str)
    if parsed is None:
        return val_str

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    local_dt = parsed.astimezone(target_tz)
    tz_label = local_dt.strftime("%Z")
    if tz_label:
        return local_dt.strftime("%Y-%m-%d %H:%M:%S") + f" {tz_label}"
    return local_dt.strftime("%Y-%m-%d %H:%M:%S")




def format_local_time(value: str | None) -> str | None:
    if not value:
        return None
    val_str = str(value).strip()
    target_tz = get_server_timezone()
    return _cached_format_local_time(val_str, target_tz)


class PortEntry(dict):
    """Represents a monitored port with its protocol, match string, URL path,
    request type (http vs custom), and custom hex request/response payloads.
    Inherits from dict so that p['port'], p['protocol'], p['match'], p['url_path'],
    p['request_type'], p['request_payload'], p['response_payload'],
    and JSON serialization work seamlessly.
    Provides equality with integers and dicts so that tests and legacy code comparing
    ports to lists of ints continue to work."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "port" not in self:
            self["port"] = None
        if "protocol" not in self:
            self["protocol"] = ""
        if "request_type" not in self:
            self["request_type"] = "web"
        if "match" not in self:
            self["match"] = ""
        if "url_path" not in self:
            self["url_path"] = ""
        if "request_payload" not in self:
            self["request_payload"] = ""
        if "response_payload" not in self:
            self["response_payload"] = ""

    @property
    def port(self):
        return self.get("port")

    @property
    def protocol(self):
        return self.get("protocol")

    @property
    def request_type(self):
        return self.get("request_type") or "web"

    @property
    def match(self):
        return self.get("match")

    @property
    def url_path(self):
        return self.get("url_path")

    @property
    def request_payload(self):
        return self.get("request_payload")

    @property
    def response_payload(self):
        return self.get("response_payload")

    def __eq__(self, other):
        if isinstance(other, int):
            return self.get("port") == other
        if isinstance(other, dict):
            return self.get("port") == other.get("port") and (self.get("protocol") or "").strip().lower() == (other.get("protocol") or "").strip().lower()
        if other is None:
            return self.get("port") is None
        if isinstance(other, str):
            if other.isdigit():
                return self.get("port") == int(other)
            if other.lower() in ("icmp", "icmp-ping"):
                return self.get("port") is None or self.get("protocol") in ("icmp", "icmp-ping")
        return super().__eq__(other)

    def __hash__(self):
        return hash(self.get("port"))

    def __int__(self):
        p = self.get("port")
        return int(p) if p is not None else 0

    def __repr__(self):
        return (
            f"PortEntry(port={self.get('port')!r}, protocol={self.get('protocol')!r}, "
            f"request_type={self.get('request_type')!r}, match={self.get('match')!r}, url_path={self.get('url_path')!r}, "
            f"request_payload={self.get('request_payload')!r}, response_payload={self.get('response_payload')!r})"
        )


def parse_port_protocol(value) -> list[PortEntry]:
    """Parse the port_protocol column from the DB into a list of PortEntry dicts.
    Handles both the new object format and legacy plain-integer format gracefully."""
    if isinstance(value, list):
        raw = value
    else:
        try:
            raw = json.loads(value or "[]")
        except (json.JSONDecodeError, TypeError):
            return []
    result = []
    for item in raw:
        if isinstance(item, int):
            result.append(PortEntry({"port": item, "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""}))
        elif isinstance(item, dict):
            port_val = item.get("port")
            proto_val = (item.get("protocol") or "").strip().lower()
            rtype_val = (item.get("request_type") or "web").strip().lower()
            if rtype_val not in ("web", "custom"):
                rtype_val = "web"
            match_val = (item.get("match") or "").strip()
            url_path_val = (item.get("url_path") or "").strip()
            req_payload_val = format_hex_bytes(item.get("request_payload") or "")
            resp_payload_val = format_hex_bytes(item.get("response_payload") or "")
            if rtype_val == "custom":
                match_val = ""
                url_path_val = ""
            else:
                req_payload_val = ""
                resp_payload_val = ""
            result.append(PortEntry({
                "port": port_val,
                "protocol": proto_val,
                "request_type": rtype_val,
                "match": match_val,
                "url_path": url_path_val,
                "request_payload": req_payload_val,
                "response_payload": resp_payload_val,
            }))
        elif isinstance(item, str):
            if item.isdigit():
                result.append(PortEntry({"port": int(item), "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""}))
            elif item.lower() in ("icmp", "icmp-ping"):
                result.append(PortEntry({"port": None, "protocol": "icmp-ping", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""}))
    return result



def port_protocol_to_json(ports) -> str:
    """Serialise a list of port dicts back to JSON for DB storage.
    Handles list[dict], list[int], or strings gracefully."""
    normalized = []
    if isinstance(ports, str):
        try:
            ports = json.loads(ports)
        except Exception:
            ports = []
    for p in (ports or []):
        if isinstance(p, dict):
            proto_val = (p.get("protocol") or "").strip().lower()
            rtype = (p.get("request_type") or "web").strip().lower()
            if rtype not in ("web", "custom"):
                rtype = "web"
            match_val = (p.get("match") or "").strip()
            url_path_val = (p.get("url_path") or "").strip()
            req_payload_val = format_hex_bytes(p.get("request_payload") or "")
            resp_payload_val = format_hex_bytes(p.get("response_payload") or "")
            if rtype == "custom":
                match_val = ""
                url_path_val = ""
            else:
                req_payload_val = ""
                resp_payload_val = ""
            normalized.append({
                "port": p.get("port"),
                "protocol": proto_val,
                "request_type": rtype,
                "match": match_val,
                "url_path": url_path_val,
                "request_payload": req_payload_val,
                "response_payload": resp_payload_val,
            })
        elif isinstance(p, int):
            normalized.append({"port": p, "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})
        elif isinstance(p, str):
            if p.isdigit():
                normalized.append({"port": int(p), "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})
            elif p.strip().lower() in ("icmp", "icmp-ping"):
                normalized.append({"port": None, "protocol": "icmp-ping", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})
    return json.dumps(normalized)


def get_service_web_url(service_name: str | None, ports: list | None) -> str | None:
    """Return normalized web URL for the first HTTP or HTTPS port with request_type 'web', or None.
    Normalized format: protocol://servicename:port/urlpath (omits standard ports 80 for http, 443 for https)."""
    if not service_name or not ports:
        return None
    clean_name = str(service_name).strip()
    if not clean_name:
        return None

    # Parse ports if passed as json string
    if isinstance(ports, str):
        ports = parse_port_protocol(ports)

    for p in ports:
        if not isinstance(p, dict):
            continue
        proto = (p.get("protocol") or "").strip().lower()
        req_type = (p.get("request_type") or "web").strip().lower()
        if proto in ("http", "https") and req_type == "web":
            port_val = p.get("port")
            raw_path = (p.get("url_path") or "").strip()
            if raw_path and not raw_path.startswith("/"):
                raw_path = "/" + raw_path

            # Format host and port
            if (proto == "http" and port_val == 80) or (proto == "https" and port_val == 443) or port_val is None:
                netloc = clean_name
            else:
                netloc = f"{clean_name}:{port_val}"

            return f"{proto}://{netloc}{raw_path}"

    return None


def compute_overall_status(port_statuses: dict[int | str, str]) -> str:
    """Compute service-level overall status based on ports/probes status.
    Precedence (worst to best):
    1. If any port/probe is OFFLINE -> service is OFFLINE
    2. Else if any port/probe is DEGRADED -> service is DEGRADED
    3. Else if all are ONLINE -> service is ONLINE
    """
    if not port_statuses:
        return "none"
    statuses = [s for s in port_statuses.values() if s != "skipped"]
    if not statuses:
        return "none"
    if any(s == "offline" for s in statuses):
        return "offline"
    if any(s == "degraded" for s in statuses):
        return "degraded"
    if all(s == "online" for s in statuses):
        return "online"
    return "offline"


def service_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, comment, paused, use_proxy, request_type, port_protocol, created_at, "
        "discovered_ip, discovered_mac, discovered_manufacturer, http_username, http_password FROM services ORDER BY name ASC"
    ).fetchall()

    check_rows = conn.execute(
        "SELECT service_id, port, is_online, status FROM latest_port_checks"
    ).fetchall()
    conn.close()

    checks_by_service: dict[int, dict] = {}
    for c in check_rows:
        s_id = c["service_id"]
        if s_id not in checks_by_service:
            checks_by_service[s_id] = {}
        port_key = c["port"] if c["port"] is not None else "icmp"
        st = c["status"] or ("online" if c["is_online"] else "offline")
        checks_by_service[s_id][port_key] = st

    services = []
    for row in rows:
        parsed_ports = parse_port_protocol(row["port_protocol"])
        protos = [p.get("protocol") for p in parsed_ports if p.get("protocol")]
        proto = protos[0] if protos else ""

        captured_paths = [str(p["url_path"]).strip() for p in parsed_ports if p.get("url_path") and str(p["url_path"]).strip()]
        captured_matches = [str(p["match"]).strip() for p in parsed_ports if p.get("match") and str(p["match"]).strip()]
        first_port_match = captured_matches[0] if captured_matches else ""
        first_port_path = captured_paths[0] if captured_paths else ""

        has_auth = bool((row["http_username"] and str(row["http_username"]).strip()) or (row["http_password"] and str(row["http_password"]).strip()))
        has_path = bool(captured_paths)
        has_match = bool(captured_matches)

        port_statuses = checks_by_service.get(row["id"], {})
        overall_status = compute_overall_status(port_statuses)

        services.append({
            "id": row["id"],
            "name": row["name"],
            "match": first_port_match,
            "url_path": first_port_path,
            "has_auth": has_auth,
            "has_path": has_path,
            "captured_paths": captured_paths,
            "has_match": has_match,
            "captured_matches": captured_matches,
            "overall_status": overall_status,
            "comment": row["comment"] or "",
            "paused": bool(row["paused"]),
            "use_proxy": bool(row["use_proxy"]),
            "request_type": row["request_type"] or "web",
            "protocol": proto,
            "port_protocol": parsed_ports,
            "ports": parsed_ports,
            "created_at": row["created_at"],
            "discovered_ip": row["discovered_ip"],
            "discovered_mac": row["discovered_mac"],
            "discovered_manufacturer": row["discovered_manufacturer"],
            "http_username": row["http_username"] or "",
            "http_password": row["http_password"] or "",
        })
    return services


def get_service_by_id(service_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, comment, paused, use_proxy, request_type, port_protocol, created_at, "
        "discovered_ip, discovered_mac, discovered_manufacturer, http_username, http_password FROM services WHERE id = ?",
        (service_id,),
    ).fetchone()
    check_rows = conn.execute(
        "SELECT port, is_online, status FROM latest_port_checks WHERE service_id = ?",
        (service_id,),
    ).fetchall()
    conn.close()
    if row is None:
        return None
    parsed_ports = parse_port_protocol(row["port_protocol"])
    protos = [p.get("protocol") for p in parsed_ports if p.get("protocol")]
    proto = protos[0] if protos else ""

    captured_paths = [str(p["url_path"]).strip() for p in parsed_ports if p.get("url_path") and str(p["url_path"]).strip()]
    captured_matches = [str(p["match"]).strip() for p in parsed_ports if p.get("match") and str(p["match"]).strip()]
    first_port_match = captured_matches[0] if captured_matches else ""
    first_port_path = captured_paths[0] if captured_paths else ""

    has_auth = bool((row["http_username"] and str(row["http_username"]).strip()) or (row["http_password"] and str(row["http_password"]).strip()))
    has_path = bool(captured_paths)
    has_match = bool(captured_matches)

    port_statuses = {}
    for c in check_rows:
        port_key = c["port"] if c["port"] is not None else "icmp"
        port_statuses[port_key] = c["status"] or ("online" if c["is_online"] else "offline")
    overall_status = compute_overall_status(port_statuses)

    return {
        "id": row["id"],
        "name": row["name"],
        "match": first_port_match,
        "url_path": first_port_path,
        "has_auth": has_auth,
        "has_path": has_path,
        "captured_paths": captured_paths,
        "has_match": has_match,
        "captured_matches": captured_matches,
        "overall_status": overall_status,
        "comment": row["comment"] or "",
        "paused": bool(row["paused"]),
        "use_proxy": bool(row["use_proxy"]),
        "request_type": row["request_type"] or "web",
        "protocol": proto,
        "port_protocol": parsed_ports,
        "ports": parsed_ports,
        "created_at": row["created_at"],
        "discovered_ip": row["discovered_ip"],
        "discovered_mac": row["discovered_mac"],
        "discovered_manufacturer": row["discovered_manufacturer"],
        "http_username": row["http_username"] or "",
        "http_password": row["http_password"] or "",
    }


def service_exists(service_name: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM services WHERE name = ?",
        (service_name,),
    ).fetchone()
    conn.close()
    return row is not None


def store_port_check(service_id: int, port: int | None, status: str, response_ms: int | None):
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z")
    is_online_val = 1 if status == "online" else 0
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            service_id,
            port,
            is_online_val,
            status,
            response_ms,
            now_str,
        ),
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO latest_port_checks (service_id, port, is_online, status, last_response_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            service_id,
            port,
            is_online_val,
            status,
            response_ms,
            now_str,
        ),
    )
    conn.commit()
    conn.close()


def clear_latest_port_checks() -> int:
    """Clear all records from latest_port_checks table on application start."""
    try:
        conn = get_db_connection()
        cur = conn.execute("DELETE FROM latest_port_checks")
        deleted_count = cur.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    except Exception:
        return 0


def prune_historical_port_checks(retention_days: int | None = None) -> int:
    """Prune rows from historical port_checks older than retention_days.
    Does not touch latest_port_checks which holds current active statuses."""
    days = DEFAULT_HISTORY_RETENTION_DAYS if retention_days is None else retention_days
    if days is None or days <= 0:
        return 0
    try:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        cutoff_iso = cutoff_dt.isoformat()
        conn = get_db_connection()
        cur = conn.execute(
            "DELETE FROM port_checks WHERE checked_at < ? OR (checked_at LIKE '%T%' AND checked_at < ?)",
            (cutoff_str, cutoff_iso),
        )
        deleted_count = cur.rowcount
        conn.commit()
        conn.close()
        return deleted_count
    except Exception:
        return 0


def get_service_check_history(
    service_id: int,
    hours: float | None = 12,
    from_date: str | None = None,
    to_date: str | None = None,
    limit: int = 1000,
) -> dict | None:
    """Retrieve historical status check records for a given service.

    Records are returned in descending date order (newest first).
    """
    service = get_service_by_id(service_id)
    if not service:
        return None

    ports_map = {}
    for p in service.get("port_protocol") or []:
        port_num = p.get("port")
        proto = (p.get("protocol") or ("icmp" if port_num is None else "http")).lower()
        ports_map[port_num] = {
            "protocol": proto,
            "label": "ICMP Ping" if port_num is None else f"{port_num} ({proto.upper()})",
            "url_path": p.get("url_path") or "",
            "match": p.get("match") or "",
        }

    where_clauses = ["service_id = ?"]
    params: list = [service_id]

    if from_date or to_date:
        if from_date:
            f_clean = str(from_date).strip().replace("T", " ")
            if len(f_clean) == 16:
                f_clean += ":00"
            where_clauses.append("(checked_at >= ? OR (checked_at LIKE '%T%' AND checked_at >= ?))")
            params.extend([f_clean, f_clean.replace(" ", "T")])
        if to_date:
            t_clean = str(to_date).strip().replace("T", " ")
            if len(t_clean) == 16:
                t_clean += ":59"
            where_clauses.append("(checked_at <= ? OR (checked_at LIKE '%T%' AND checked_at <= ?))")
            params.extend([t_clean + " UTC", t_clean.replace(" ", "T")])
    elif hours is not None and hours > 0:
        cutoff_dt = datetime.now(timezone.utc) - timedelta(hours=float(hours))
        cutoff_str = cutoff_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        cutoff_iso = cutoff_dt.isoformat()
        where_clauses.append("(checked_at >= ? OR (checked_at LIKE '%T%' AND checked_at >= ?))")
        params.extend([cutoff_str, cutoff_iso])

    where_sql = " AND ".join(where_clauses)
    query = f"""
        SELECT id, service_id, port, is_online, status, last_response_ms, checked_at
        FROM port_checks
        WHERE {where_sql}
        ORDER BY checked_at DESC, id DESC
        LIMIT ?
    """
    params.append(limit)

    conn = get_db_connection()
    rows = conn.execute(query, tuple(params)).fetchall()
    conn.close()

    records = []
    for r in rows:
        port_val = r["port"]
        port_info = ports_map.get(port_val, {})
        proto = port_info.get("protocol") or ("icmp" if port_val is None else "tcp")
        display_target = port_info.get("label") or ("ICMP Ping" if port_val is None else f"{port_val} ({proto.upper()})")
        checked_raw = r["checked_at"]
        checked_local = format_local_time(checked_raw) or checked_raw

        records.append({
            "id": r["id"],
            "port": port_val,
            "protocol": proto,
            "display_target": display_target,
            "status": r["status"] or ("online" if r["is_online"] else "offline"),
            "is_online": bool(r["is_online"]),
            "last_response_ms": r["last_response_ms"],
            "checked_at": checked_raw,
            "checked_at_local": checked_local,
        })

    return {
        "service_id": service["id"],
        "service_name": service["name"],
        "discovered_ip": service.get("discovered_ip") or "",
        "range_hours": hours,
        "total_count": len(records),
        "records": records,
    }


def record_scan_completed(completed_at: datetime | None = None) -> None:
    if completed_at is None:
        completed_at = datetime.now(timezone.utc)
    iso_val = completed_at.isoformat()
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES ('last_scan_completed_at', ?)",
            (iso_val,),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


def get_last_scheduled_check() -> dict:
    last_iso = None
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'last_scan_completed_at'").fetchone()
        if row and row["value"]:
            last_iso = row["value"]
        if not last_iso:
            max_row = conn.execute("SELECT MAX(checked_at) AS max_checked FROM port_checks").fetchone()
            if max_row and max_row["max_checked"]:
                last_iso = max_row["max_checked"]
        conn.close()
    except Exception:
        pass

    if not last_iso:
        return {"raw": None, "formatted": "Never", "timestamp": None}

    local_str = format_local_time(last_iso) or last_iso
    dt = parse_iso_or_utc_datetime(last_iso)
    ts = dt.timestamp() if dt else None

    return {
        "raw": last_iso,
        "formatted": local_str,
        "timestamp": ts,
    }



def get_settings() -> dict[str, str]:
    conn = get_db_connection()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    conn.close()
    settings = dict(DEFAULT_SETTINGS)
    for row in rows:
        settings[row["key"]] = row["value"]
    return settings


def save_settings(new_settings: dict[str, str]) -> None:
    allowed_extra_keys = {
        "known_manufacturer_domains",
        "manufacturer_name_aliases",
        "regional_prefixes",
        "known_service_domains",
        "html_content_icon_mappings",
        "common_ports",
        "https_ports",
        "scan_interval_minutes",
        "history_retention_days",
        "scan_workers",
        "maclookup_api_key",
        "ignored_icon_hashes",
        "corporate_suffixes",
        "dangerous_remote_patterns",
        "mac_arp_priming_enabled",
        "mac_netbios_enabled",
        "mac_snmp_enabled",
        "mac_snmp_community",
        "replace_loopback_ip_enabled",
        "server_lan_ip_override",
    }
    conn = get_db_connection()
    for key, value in new_settings.items():
        if key in DEFAULT_SETTINGS or key in allowed_extra_keys:
            val_to_save = str(value) if key in ("smtp_password", "proxy_password", "remote_source_password", "remote_source_key", "maclookup_api_key") else str(value).strip()
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, val_to_save),
            )
    conn.commit()
    conn.close()


def normalize_apprise_url(url: str) -> str:
    """Normalize raw webhook/service URLs to Apprise compatible URL formats where applicable."""
    if not url:
        return ""
    u = url.strip()
    # Discord direct incoming webhook URL: https://discord.com/api/webhooks/<id>/<token>
    discord_m = re.match(
        r"^https?://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/(\d+)/([A-Za-z0-9_\-]+)/?$",
        u,
    )
    if discord_m:
        return f"discord://{discord_m.group(1)}/{discord_m.group(2)}"
    # Slack direct incoming webhook URL: https://hooks.slack.com/services/T.../B.../X...
    slack_m = re.match(
        r"^https?://hooks\.slack\.com/services/([A-Za-z0-9]+)/([A-Za-z0-9]+)/([A-Za-z0-9]+)/?$",
        u,
    )
    if slack_m:
        return f"slack://{slack_m.group(1)}/{slack_m.group(2)}/{slack_m.group(3)}"
    return u


def detect_apprise_service(url: str) -> str:
    """Detect service type name from Apprise URL scheme for UI display and icons."""
    normalized = normalize_apprise_url(url)
    scheme = normalized.split("://", 1)[0].lower() if "://" in normalized else ""
    if scheme in ("discord",):
        return "discord"
    if scheme in ("tgram", "telegram"):
        return "telegram"
    if scheme in ("slack",):
        return "slack"
    if scheme in ("pover", "pushover"):
        return "pushover"
    if scheme in ("ntfy", "ntfys"):
        return "ntfy"
    if scheme in ("gotify", "gotifys"):
        return "gotify"
    if scheme in ("msteams", "teams"):
        return "teams"
    if scheme in ("matrix", "matrixs"):
        return "matrix"
    if scheme in ("json", "jsons", "http", "https"):
        return "webhook"
    return scheme or "custom"


def get_apprise_channels() -> list[dict]:
    """Retrieve the list of configured Apprise notification channels."""
    settings = get_settings()
    raw = settings.get("notification_apprise_channels", "[]")
    try:
        channels = json.loads(raw)
        if isinstance(channels, list):
            return channels
    except Exception:
        pass
    return []


def save_apprise_channels(channels: list[dict]) -> None:
    """Save the list of Apprise notification channels into settings."""
    save_settings({"notification_apprise_channels": json.dumps(channels)})


def add_apprise_channel(
    name: str,
    url: str,
    enabled: bool = True,
    notify_on_degraded: bool = True,
    notify_on_offline: bool = True,
    notify_on_recovery: bool = True,
) -> tuple[bool, str, dict | None]:
    """Add a new Apprise notification channel with syntax validation."""
    name = (name or "").strip()
    raw_url = (url or "").strip()
    if not raw_url:
        return False, "Target notification URL is required.", None
    norm_url = normalize_apprise_url(raw_url)

    # Validate with Apprise
    try:
        import apprise
        ap = apprise.Apprise()
        if not ap.add(norm_url):
            return False, f"Invalid or unsupported notification URL format for Apprise: '{raw_url}'", None
    except Exception as exc:
        return False, f"Apprise validation error: {exc}", None

    service = detect_apprise_service(norm_url)
    channel_id = uuid.uuid4().hex[:12]
    new_channel = {
        "id": channel_id,
        "name": name or f"{service.capitalize()} Alert",
        "url": norm_url,
        "service": service,
        "enabled": bool(enabled),
        "notify_on_degraded": bool(notify_on_degraded),
        "notify_on_offline": bool(notify_on_offline),
        "notify_on_recovery": bool(notify_on_recovery),
        "created_at": get_current_local_time_str(),
    }
    channels = get_apprise_channels()
    channels.append(new_channel)
    save_apprise_channels(channels)
    return True, f"Notification channel '{new_channel['name']}' added successfully.", new_channel


def delete_apprise_channel(channel_id: str) -> bool:
    """Delete an Apprise notification channel by ID."""
    channels = get_apprise_channels()
    filtered = [c for c in channels if str(c.get("id")) != str(channel_id)]
    if len(filtered) != len(channels):
        save_apprise_channels(filtered)
        return True
    return False


def toggle_apprise_channel(channel_id: str, enabled: bool | None = None) -> bool:
    """Toggle or set the enabled state of an Apprise notification channel."""
    channels = get_apprise_channels()
    updated = False
    for c in channels:
        if str(c.get("id")) == str(channel_id):
            if enabled is None:
                c["enabled"] = not c.get("enabled", True)
            else:
                c["enabled"] = bool(enabled)
            updated = True
            break
    if updated:
        save_apprise_channels(channels)
        return True
    return False


def get_authorized_users() -> list[sqlite3.Row]:
    conn = get_db_connection()
    rows = conn.execute("SELECT id, identifier, display_name, created_at, updated_at FROM authorized_users ORDER BY id ASC").fetchall()
    conn.close()
    return rows


def get_authorized_user_by_id(user_id: int) -> sqlite3.Row | None:
    conn = get_db_connection()
    row = conn.execute("SELECT id, identifier, display_name, created_at, updated_at FROM authorized_users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    return row


def get_authorized_user_by_identifier(identifier: str) -> sqlite3.Row | None:
    if not identifier:
        return None
    conn = get_db_connection()
    row = conn.execute("SELECT id, identifier, display_name, created_at, updated_at FROM authorized_users WHERE LOWER(identifier) = LOWER(?)", (identifier.strip(),)).fetchone()
    conn.close()
    return row


def is_user_authorized(identifier: str) -> bool:
    if not identifier:
        return False
    conn = get_db_connection()
    row = conn.execute("SELECT 1 FROM authorized_users WHERE LOWER(identifier) = LOWER(?)", (identifier.strip(),)).fetchone()
    conn.close()
    return row is not None


def add_authorized_user(identifier: str, display_name: str = "") -> int:
    ident = (identifier or "").strip()
    if not ident:
        raise ValueError("User identifier cannot be empty.")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "INSERT INTO authorized_users (identifier, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
            (ident, (display_name or "").strip(), now_str, now_str),
        )
        user_id = cur.lastrowid
        conn.commit()
        return user_id
    finally:
        conn.close()


def update_authorized_user(user_id: int, identifier: str, display_name: str = "") -> bool:
    ident = (identifier or "").strip()
    if not ident:
        raise ValueError("User identifier cannot be empty.")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    conn = get_db_connection()
    try:
        cur = conn.execute(
            "UPDATE authorized_users SET identifier = ?, display_name = ?, updated_at = ? WHERE id = ?",
            (ident, (display_name or "").strip(), now_str, user_id),
        )
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def delete_authorized_user(user_id: int) -> bool:
    conn = get_db_connection()
    try:
        cur = conn.execute("DELETE FROM authorized_users WHERE id = ?", (user_id,))
        conn.commit()
        return cur.rowcount > 0
    finally:
        conn.close()


def bootstrap_initial_admin(admin_identifier: str = "") -> bool:
    admin_ident = (admin_identifier or os.getenv("PULSECHECK_OIDC_INITIAL_ADMIN") or getattr(core.config, "OIDC_INITIAL_ADMIN", "") or "").strip()
    if not admin_ident:
        return False
    conn = get_db_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM authorized_users").fetchone()[0]
        if count == 0:
            now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            conn.execute(
                "INSERT INTO authorized_users (identifier, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                (admin_ident, "Initial Administrator", now_str, now_str),
            )
            conn.commit()
            print(f"[OIDC] Initial admin bootstrapped: '{admin_ident}'")
            return True
        return False
    finally:
        conn.close()



def get_status_rows():
    conn = get_db_connection()
    check_rows = conn.execute(
        """
        SELECT service_id, port, is_online, status, last_response_ms, checked_at
        FROM latest_port_checks
        """
    ).fetchall()

    latest_checks = {}
    for c in check_rows:
        latest_checks[(c["service_id"], c["port"])] = c

    service_rows = conn.execute(
        """
        SELECT id, name, comment, paused, use_proxy, port_protocol,
               discovered_ip, discovered_mac, discovered_manufacturer
        FROM services
        WHERE paused = 0
        ORDER BY name ASC
        """
    ).fetchall()
    conn.close()

    result = []
    for s in service_rows:
        ports_list: list[dict] = parse_port_protocol(s["port_protocol"])
        disc_ip = s["discovered_ip"]
        disc_mac = s["discovered_mac"]
        disc_mfg = s["discovered_manufacturer"]

        if not ports_list:
            result.append({
                "id": s["id"],
                "name": s["name"],
                "match": "",
                "ports": ports_list,
                "has_ports": False,
                "use_proxy": bool(s["use_proxy"]),
                "protocol": "",
                "port": None,
                "is_online": False,
                "status": None,
                "last_response_ms": None,
                "checked_at": None,
                "checked_at_local": "",
                "discovered_ip": disc_ip,
                "discovered_mac": disc_mac,
                "discovered_manufacturer": disc_mfg,
            })
            continue

        for p in ports_list:
            port_val = p.get("port")
            check = latest_checks.get((s["id"], port_val))
            if port_val is None:
                port_protocol = "icmp-ping"
            else:
                port_protocol = p.get("protocol") or "http"

            if check:
                is_online = bool(check["is_online"])
                status = check["status"] or ("online" if is_online else "offline")
                last_response_ms = check["last_response_ms"]
                checked_at = check["checked_at"]
                checked_at_local = format_local_time(checked_at)
            else:
                is_online = False
                status = None
                last_response_ms = None
                checked_at = None
                checked_at_local = ""

            result.append({
                "id": s["id"],
                "name": s["name"],
                "match": p.get("match", "") if port_val is not None else "",
                "url_path": p.get("url_path", "") if port_val is not None else "",
                "ports": ports_list,
                "has_ports": True,
                "use_proxy": bool(s["use_proxy"]),
                "protocol": port_protocol,
                "port": port_val,
                "is_online": is_online,
                "status": status,
                "last_response_ms": last_response_ms,
                "checked_at": checked_at,
                "checked_at_local": checked_at_local,
                "discovered_ip": disc_ip,
                "discovered_mac": disc_mac,
                "discovered_manufacturer": disc_mfg,
            })
    return result


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS services (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            comment TEXT NOT NULL DEFAULT '',
            paused INTEGER NOT NULL DEFAULT 0,
            use_proxy INTEGER NOT NULL DEFAULT 0,
            request_type TEXT NOT NULL DEFAULT 'web',
            port_protocol TEXT NOT NULL DEFAULT '[]',
            discovered_ip TEXT DEFAULT NULL,
            discovered_mac TEXT DEFAULT NULL,
            discovered_manufacturer TEXT DEFAULT NULL,
            http_username TEXT NOT NULL DEFAULT '',
            http_password TEXT NOT NULL DEFAULT '',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS port_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service_id INTEGER NOT NULL,
            port INTEGER,
            is_online INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'offline',
            last_response_ms INTEGER,
            checked_at TEXT NOT NULL,
            FOREIGN KEY(service_id) REFERENCES services(id)
        )
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_port_checks_service_port_checked
        ON port_checks(service_id, port, checked_at DESC)
        """
    )

    conn.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_port_checks_service_checked
        ON port_checks(service_id, checked_at DESC)
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS latest_port_checks (
            service_id INTEGER NOT NULL,
            port INTEGER,
            is_online INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'offline',
            last_response_ms INTEGER,
            checked_at TEXT NOT NULL,
            PRIMARY KEY (service_id, port),
            FOREIGN KEY(service_id) REFERENCES services(id)
        )
        """
    )

    conn.execute(
        """
        CREATE TRIGGER IF NOT EXISTS trg_port_checks_maintain_latest
        AFTER INSERT ON port_checks
        FOR EACH ROW
        BEGIN
            INSERT OR REPLACE INTO latest_port_checks (service_id, port, is_online, status, last_response_ms, checked_at)
            VALUES (NEW.service_id, NEW.port, NEW.is_online, NEW.status, NEW.last_response_ms, NEW.checked_at);
        END
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS authorized_users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            identifier TEXT NOT NULL UNIQUE COLLATE NOCASE,
            display_name TEXT DEFAULT '',
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        )
        """
    )



    conn.commit()
    conn.close()

    try:
        initial_admin = (os.getenv("PULSECHECK_OIDC_INITIAL_ADMIN") or getattr(core.config, "OIDC_INITIAL_ADMIN", "") or "").strip()
        if initial_admin:
            bootstrap_initial_admin(initial_admin)
    except Exception as _boot_err:
        print(f"[OIDC] Warning bootstrapping initial admin during init_db: {_boot_err}", file=sys.stderr)

    try:
        prune_historical_port_checks()
    except Exception:
        pass

