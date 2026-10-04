from __future__ import annotations

import base64
import csv
import gzip
import http.client
import io
import json
import os
import re
import sqlite3
import socket
import smtplib
import ssl
import struct
import subprocess
import sys
import threading
import time
import uuid
import warnings
import zlib
from datetime import datetime, timezone, timedelta
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urljoin, urlsplit
import urllib.request
from zoneinfo import ZoneInfo

from concurrent.futures import ThreadPoolExecutor
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, Response, flash, jsonify, redirect, render_template, request, send_from_directory, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("PULSECHECK_DB_PATH", str(BASE_DIR / "pulsecheck.db")))
MANUFACTURER_ICONS_DIR = DB_PATH.parent / "manufacturer_icons"
MANUFACTURER_ICONS_DIR.mkdir(parents=True, exist_ok=True)
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 587, 993, 995, 8080, 8443, 8444, 3306, 5432, 27017, 3000, 9000]
HTTPS_PORTS = {443, 8443, 8444}
DEFAULT_PORT = int(os.getenv("PULSECHECK_PORT", "8182"))
DEFAULT_IP = os.getenv("PULSECHECK_IP", os.getenv("PULSECHECK_HOST", "0.0.0.0"))
DEFAULT_HOSTNAME = os.getenv("PULSECHECK_HOSTNAME", "127.0.0.1")
DEFAULT_SSL = os.getenv("PULSECHECK_SSL", "FALSE").strip().lower() in ("true", "1", "yes")
DEFAULT_SCAN_WORKERS = int(os.getenv("PULSECHECK_SCAN_WORKERS", "5"))
DEFAULT_SCAN_RETRIES = int(os.getenv("PULSECHECK_SCAN_RETRIES", "6"))
DEFAULT_SCAN_RETRY_INTERVAL = int(os.getenv("PULSECHECK_SCAN_RETRY_INTERVAL", "5"))
EXPLICIT_DEBUG = False
APP_VERSION = os.getenv("PULSECHECK_VERSION", "1.1.3")
__version__ = APP_VERSION


def get_url_scheme() -> str:
    ssl_env = os.getenv("PULSECHECK_SSL")
    if ssl_env is not None:
        return "https" if ssl_env.strip().lower() in ("true", "1", "yes") else "http"
    return "https" if DEFAULT_SSL else "http"


def get_base_url() -> str:
    scheme = get_url_scheme()
    hostname = os.getenv("PULSECHECK_HOSTNAME") or DEFAULT_HOSTNAME
    return f"{scheme}://{hostname}"


def get_status_url() -> str:
    return f"{get_base_url()}/status"


app = Flask(__name__)
app.config["SECRET_KEY"] = "pulsecheck-local-dev"
app.config["TEMPLATES_AUTO_RELOAD"] = True


@app.context_processor
def inject_version():
    return {
        "app_version": APP_VERSION,
        "version": APP_VERSION,
        "get_manufacturer_icon_url": get_manufacturer_icon_url,
    }


inject_globals = inject_version
IMPORT_STATE = {}
IMPORT_LOCK = threading.Lock()
GLOBAL_SCHEDULER = None
IS_SCANNING = False
IS_SCANNING_LOCK = threading.Lock()


class ImportCancelled(Exception):
    pass


def get_db_connection():
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row
    return conn


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
            port_protocol TEXT NOT NULL DEFAULT '[]',
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
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        )
        """
    )

    # Clean up obsolete port_checks rows for ports no longer configured on services
    try:
        service_rows = conn.execute("SELECT id, port_protocol FROM services").fetchall()
        for s in service_rows:
            p_list = parse_port_protocol(s["port_protocol"])
            cfg_ports = {p.get("port") for p in p_list}
            if None not in cfg_ports:
                conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NULL", (s["id"],))
            num_ports = [p["port"] for p in p_list if p.get("port") is not None]
            if num_ports:
                ph = ", ".join("?" for _ in num_ports)
                conn.execute(f"DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({ph})", (s["id"], *num_ports))
            else:
                conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL", (s["id"],))
    except Exception:
        pass

    # Remove obsolete match and url_path columns from services table if they still exist
    try:
        service_cols = [c[1] for c in conn.execute("PRAGMA table_info(services)").fetchall()]
        if "match" in service_cols or "url_path" in service_cols:
            rows_to_migrate = conn.execute("SELECT id, name, comment, paused, use_proxy, port_protocol, created_at, " +
                                           ("match" if "match" in service_cols else "'' AS match") + ", " +
                                           ("url_path" if "url_path" in service_cols else "'' AS url_path") +
                                           " FROM services").fetchall()
            # First ensure any unmigrated service-level match/url_path are copied to ports
            for row in rows_to_migrate:
                raw_ports = parse_port_protocol(row["port_protocol"])
                if not raw_ports:
                    continue
                changed = False
                srv_match = (row["match"] or "").strip()
                srv_url_path = (row["url_path"] or "").strip()
                for p in raw_ports:
                    if p.get("port") is None:
                        if p.get("match") != "" or p.get("url_path") != "":
                            p["match"] = ""
                            p["url_path"] = ""
                            changed = True
                        continue
                    if not p.get("match") and srv_match:
                        p["match"] = srv_match
                        changed = True
                    if not p.get("url_path") and srv_url_path:
                        p["url_path"] = srv_url_path
                        changed = True
                if changed:
                    conn.execute(
                        "UPDATE services SET port_protocol = ? WHERE id = ?",
                        (port_protocol_to_json(raw_ports), row["id"]),
                    )

            # Recreate services table without match and url_path
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute(
                """
                CREATE TABLE services_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL UNIQUE,
                    comment TEXT NOT NULL DEFAULT '',
                    paused INTEGER NOT NULL DEFAULT 0,
                    use_proxy INTEGER NOT NULL DEFAULT 0,
                    port_protocol TEXT NOT NULL DEFAULT '[]',
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
                )
                """
            )
            conn.execute(
                """
                INSERT INTO services_new (id, name, comment, paused, use_proxy, port_protocol, created_at)
                SELECT id, name, comment, paused, use_proxy, port_protocol, created_at FROM services
                """
            )
            conn.execute("DROP TABLE services")
            conn.execute("ALTER TABLE services_new RENAME TO services")
            conn.execute("PRAGMA foreign_keys = ON")
    except Exception:
        pass

    # Migration: add network-discovery columns
    try:
        svc_cols = [c[1] for c in conn.execute("PRAGMA table_info(services)").fetchall()]
        if "discovered_ip" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_ip TEXT DEFAULT NULL")
        if "discovered_mac" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_mac TEXT DEFAULT NULL")
        if "discovered_manufacturer" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_manufacturer TEXT DEFAULT NULL")
    except Exception:
        pass

    conn.commit()
    conn.close()


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


def format_local_time(value: str | None) -> str | None:
    if not value:
        return None
    val_str = str(value).strip()
    target_tz = get_server_timezone()

    parsed = None
    try:
        parsed = datetime.fromisoformat(val_str.replace("Z", "+00:00"))
    except ValueError:
        pass

    if parsed is None:
        try:
            if val_str.endswith(" UTC"):
                parsed = datetime.strptime(val_str[:-4].strip(), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            else:
                parsed = datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S %Z")
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    if parsed is None:
        try:
            parsed = datetime.strptime(val_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            pass

    if parsed is None:
        return val_str

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)

    local_dt = parsed.astimezone(target_tz)
    tz_label = local_dt.strftime("%Z")
    if tz_label:
        return local_dt.strftime("%Y-%m-%d %H:%M:%S") + f" {tz_label}"
    return local_dt.strftime("%Y-%m-%d %H:%M:%S")


class PortEntry(dict):
    """Represents a monitored port with its protocol, match string, and URL path.
    Inherits from dict so that p['port'], p['protocol'], p['match'], p['url_path'],
    and JSON serialization work seamlessly.
    Provides equality with integers and dicts so that tests and legacy code comparing
    ports to lists of ints continue to work."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if "port" not in self:
            self["port"] = None
        if "protocol" not in self:
            self["protocol"] = ""
        if "match" not in self:
            self["match"] = ""
        if "url_path" not in self:
            self["url_path"] = ""

    @property
    def port(self):
        return self.get("port")

    @property
    def protocol(self):
        return self.get("protocol")

    @property
    def match(self):
        return self.get("match")

    @property
    def url_path(self):
        return self.get("url_path")

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
        return f"PortEntry(port={self.get('port')!r}, protocol={self.get('protocol')!r}, match={self.get('match')!r}, url_path={self.get('url_path')!r})"


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
            result.append(PortEntry({"port": item, "protocol": "", "match": "", "url_path": ""}))
        elif isinstance(item, dict):
            port_val = item.get("port")
            proto_val = (item.get("protocol") or "").strip().lower()
            match_val = (item.get("match") or "").strip()
            url_path_val = (item.get("url_path") or "").strip()
            result.append(PortEntry({
                "port": port_val,
                "protocol": proto_val,
                "match": match_val,
                "url_path": url_path_val,
            }))
        elif isinstance(item, str):
            if item.isdigit():
                result.append(PortEntry({"port": int(item), "protocol": "", "match": "", "url_path": ""}))
            elif item.lower() in ("icmp", "icmp-ping"):
                result.append(PortEntry({"port": None, "protocol": "icmp-ping", "match": "", "url_path": ""}))
    return result


def port_numbers(ports: list[dict]) -> list[int]:
    """Return sorted list of numeric port numbers, excluding ICMP (port=None) entries."""
    return sorted({int(p["port"]) for p in ports if p.get("port") is not None})


def has_icmp(ports: list[dict]) -> bool:
    """Return True if ports list contains an ICMP (portless) probe entry."""
    return any(p.get("port") is None and p.get("protocol") in ("icmp-ping", "icmp") for p in ports)


def get_port_protocol(ports: list[dict], port_num: int) -> str:
    """Return the configured protocol for a specific port number, or empty string."""
    for p in ports:
        if p.get("port") == port_num:
            return (p.get("protocol") or "").strip().lower()
    return ""


def port_protocol_to_json(ports) -> str:
    """Serialise a list of {port, protocol, match, url_path} dicts back to JSON for DB storage.
    Handles list[dict], list[int], or strings gracefully."""
    normalized = []
    if isinstance(ports, str):
        try:
            ports = json.loads(ports)
        except Exception:
            ports = parse_diagnostic_ports(ports)
    for p in (ports or []):
        if isinstance(p, dict):
            normalized.append({
                "port": p.get("port"),
                "protocol": (p.get("protocol") or "").strip().lower(),
                "match": (p.get("match") or "").strip(),
                "url_path": (p.get("url_path") or "").strip(),
            })
        elif isinstance(p, int):
            normalized.append({"port": p, "protocol": "", "match": "", "url_path": ""})
        elif isinstance(p, str):
            if p.isdigit():
                normalized.append({"port": int(p), "protocol": "", "match": "", "url_path": ""})
            elif p.strip().lower() in ("icmp", "icmp-ping"):
                normalized.append({"port": None, "protocol": "icmp-ping", "match": "", "url_path": ""})
    return json.dumps(normalized)


def service_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, comment, paused, use_proxy, port_protocol, created_at, "
        "discovered_ip, discovered_mac, discovered_manufacturer FROM services ORDER BY name ASC"
    ).fetchall()
    conn.close()
    services = []
    for row in rows:
        parsed_ports = parse_port_protocol(row["port_protocol"])
        protos = [p.get("protocol") for p in parsed_ports if p.get("protocol")]
        proto = protos[0] if protos else ""
        first_port_match = next((p.get("match", "") for p in parsed_ports if p.get("port") is not None and p.get("match")), "")
        first_port_path = next((p.get("url_path", "") for p in parsed_ports if p.get("port") is not None and p.get("url_path")), "")
        services.append({
            "id": row["id"],
            "name": row["name"],
            "match": first_port_match,
            "url_path": first_port_path,
            "comment": row["comment"] if "comment" in row.keys() else "",
            "paused": bool(row["paused"]),
            "use_proxy": bool(row["use_proxy"]) if "use_proxy" in row.keys() else False,
            "protocol": proto,
            "port_protocol": parsed_ports,
            "ports": parsed_ports,
            "created_at": row["created_at"],
            "discovered_ip": row["discovered_ip"] if "discovered_ip" in row.keys() else None,
            "discovered_mac": row["discovered_mac"] if "discovered_mac" in row.keys() else None,
            "discovered_manufacturer": row["discovered_manufacturer"] if "discovered_manufacturer" in row.keys() else None,
        })
    return services


def get_service_by_id(service_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, comment, paused, use_proxy, port_protocol, created_at, "
        "discovered_ip, discovered_mac, discovered_manufacturer FROM services WHERE id = ?",
        (service_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    parsed_ports = parse_port_protocol(row["port_protocol"])
    protos = [p.get("protocol") for p in parsed_ports if p.get("protocol")]
    proto = protos[0] if protos else ""
    first_port_match = next((p.get("match", "") for p in parsed_ports if p.get("port") is not None and p.get("match")), "")
    first_port_path = next((p.get("url_path", "") for p in parsed_ports if p.get("port") is not None and p.get("url_path")), "")
    return {
        "id": row["id"],
        "name": row["name"],
        "match": first_port_match,
        "url_path": first_port_path,
        "comment": row["comment"] if "comment" in row.keys() else "",
        "paused": bool(row["paused"]),
        "use_proxy": bool(row["use_proxy"]) if "use_proxy" in row.keys() else False,
        "protocol": proto,
        "port_protocol": parsed_ports,
        "ports": parsed_ports,
        "created_at": row["created_at"],
        "discovered_ip": row["discovered_ip"] if "discovered_ip" in row.keys() else None,
        "discovered_mac": row["discovered_mac"] if "discovered_mac" in row.keys() else None,
        "discovered_manufacturer": row["discovered_manufacturer"] if "discovered_manufacturer" in row.keys() else None,
    }


def service_exists(service_name: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM services WHERE name = ?",
        (service_name,),
    ).fetchone()
    conn.close()
    return row is not None


def discover_ports(service_name: str, progress_callback=None, cancelled_check=None) -> list[dict]:
    """Probe COMMON_PORTS and return a list of {port, protocol} dicts for open ports."""
    found = []
    for port in COMMON_PORTS:
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")
        if progress_callback is not None:
            progress_callback({
                "service": service_name,
                "port": port,
                "message": f"Testing port {port} for {service_name}",
            })
        try:
            with socket.create_connection((service_name, port), timeout=1.5):
                found.append({"port": port, "protocol": ""})
        except (socket.timeout, socket.gaierror, OSError):
            continue
    return found


def store_port_check(service_id: int, port: int | None, status: str, response_ms: int | None):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO port_checks (service_id, port, is_online, status, last_response_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            service_id,
            port,
            1 if status == "online" else 0,
            status,
            response_ms,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        ),
    )
    conn.commit()
    conn.close()


def create_ssl_context(legacy: bool = False) -> ssl.SSLContext:
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    if legacy:
        op_legacy = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
        context.options |= op_legacy
        try:
            context.set_ciphers("ALL:@SECLEVEL=0")
        except Exception:
            pass
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                if hasattr(ssl, "TLSVersion"):
                    context.minimum_version = ssl.TLSVersion.MINIMUM_SUPPORTED
                    max_v = getattr(ssl.TLSVersion, "TLSv1_1", getattr(ssl.TLSVersion, "TLSv1", None))
                    if max_v is not None:
                        context.maximum_version = max_v
            except Exception:
                pass
    return context


def is_ssl_handshake_failure(exc: Exception) -> bool:
    if isinstance(exc, ssl.SSLError):
        err_str = str(exc).upper()
        return (
            "SSLV3_ALERT_HANDSHAKE_FAILURE" in err_str
            or "HANDSHAKE_FAILURE" in err_str
            or "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in err_str
            or "NO_PROTOCOLS_AVAILABLE" in err_str
        )
    cause = getattr(exc, "__cause__", None)
    if isinstance(cause, ssl.SSLError):
        err_str = str(cause).upper()
        return (
            "SSLV3_ALERT_HANDSHAKE_FAILURE" in err_str
            or "HANDSHAKE_FAILURE" in err_str
            or "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in err_str
            or "NO_PROTOCOLS_AVAILABLE" in err_str
        )
    context = getattr(exc, "__context__", None)
    if isinstance(context, ssl.SSLError):
        err_str = str(context).upper()
        return (
            "SSLV3_ALERT_HANDSHAKE_FAILURE" in err_str
            or "HANDSHAKE_FAILURE" in err_str
            or "UNSAFE_LEGACY_RENEGOTIATION_DISABLED" in err_str
            or "NO_PROTOCOLS_AVAILABLE" in err_str
        )
    return False


def decompress_gzip_payload(data: bytes) -> bytes:
    if not data or not isinstance(data, (bytes, bytearray)):
        return data
    try:
        return gzip.decompress(data)
    except Exception:
        pass
    try:
        decompressor = zlib.decompressobj(wbits=31)
        decompressed = decompressor.decompress(data)
        try:
            decompressed += decompressor.flush()
        except Exception:
            pass
        if decompressed:
            return decompressed
    except Exception:
        pass
    return data


def decompress_socket_response_if_gzip(data: bytes) -> bytes:
    if not data or not isinstance(data, (bytes, bytearray)):
        return data
    if b"\r\n\r\n" in data:
        header_part, body_part = data.split(b"\r\n\r\n", 1)
        if re.search(rb"(?i)content-encoding:\s*gzip", header_part):
            decompressed_body = decompress_gzip_payload(body_part)
            return header_part + b"\r\n\r\n" + decompressed_body
    return data


def format_response_headers(response) -> bytes:
    if response is None:
        return b""
    headers_obj = getattr(response, "headers", None) or getattr(response, "msg", None)
    if headers_obj is not None:
        if hasattr(headers_obj, "as_bytes"):
            try:
                raw = headers_obj.as_bytes()
                if raw:
                    if not (raw.endswith(b"\r\n\r\n") or raw.endswith(b"\n\n")):
                        raw = raw.rstrip(b"\r\n") + b"\r\n\r\n"
                    return raw
            except Exception:
                pass
        if hasattr(headers_obj, "items"):
            try:
                lines = [f"{k}: {v}".encode("latin1", errors="replace") for k, v in headers_obj.items()]
                if lines:
                    return b"\r\n".join(lines) + b"\r\n\r\n"
            except Exception:
                pass
        if isinstance(headers_obj, (bytes, bytearray)):
            raw = bytes(headers_obj)
            if raw and not (raw.endswith(b"\r\n\r\n") or raw.endswith(b"\n\n")):
                raw = raw.rstrip(b"\r\n") + b"\r\n\r\n"
            return raw
        if isinstance(headers_obj, str):
            raw = headers_obj.encode("latin1", errors="replace")
            if raw and not (raw.endswith(b"\r\n\r\n") or raw.endswith(b"\n\n")):
                raw = raw.rstrip(b"\r\n") + b"\r\n\r\n"
            return raw

    if hasattr(response, "getheaders") and callable(response.getheaders):
        try:
            h_list = response.getheaders()
            if h_list:
                lines = [f"{k}: {v}".encode("latin1", errors="replace") for k, v in h_list]
                return b"\r\n".join(lines) + b"\r\n\r\n"
        except Exception:
            pass

    if hasattr(response, "_headers") and isinstance(response._headers, dict):
        try:
            lines = [f"{k}: {v}".encode("latin1", errors="replace") for k, v in response._headers.items()]
            if lines:
                return b"\r\n".join(lines) + b"\r\n\r\n"
        except Exception:
            pass

    return b""


def fetch_response(
    service_name: str,
    port: int,
    scheme: str,
    url_path: str = "",
    max_redirects: int = 5,
    explicit_debug: bool = False,
    allow_legacy_ssl: bool = False,
    use_proxy: bool = False,
    proxy_settings: dict[str, str] | None = None,
):
    current_url = f"{scheme}://{service_name}:{port}{url_path or '/'}"
    ssl_context = create_ssl_context(legacy=allow_legacy_ssl)

    proxy_host = ""
    proxy_port = 8080
    proxy_auth_header = None
    if use_proxy:
        cfg = get_settings() if proxy_settings is None else proxy_settings
        raw_host = (cfg.get("proxy_host") or "").strip()
        if raw_host:
            if "://" in raw_host:
                parsed_proxy = urlsplit(raw_host)
                proxy_host = parsed_proxy.hostname or raw_host
                if parsed_proxy.port:
                    proxy_port = parsed_proxy.port
            elif ":" in raw_host and not raw_host.startswith("["):
                parts = raw_host.split(":", 1)
                proxy_host = parts[0].strip()
                try:
                    proxy_port = int(parts[1].strip())
                except ValueError:
                    pass
            else:
                proxy_host = raw_host
        if not proxy_host:
            raise OSError(f"Service '{service_name}' requires proxy access, but no HTTP proxy host is configured in settings.")
        if cfg.get("proxy_port") and proxy_port == 8080:
            try:
                proxy_port = int(str(cfg.get("proxy_port")).strip())
            except ValueError:
                pass
        p_user = (cfg.get("proxy_username") or "").strip()
        p_pass = cfg.get("proxy_password") or ""
        if p_user:
            creds = f"{p_user}:{p_pass}"
            proxy_auth_header = f"Basic {base64.b64encode(creds.encode('latin1')).decode('ascii')}"

    for redirect_count in range(max_redirects + 1):
        parsed = urlsplit(current_url)
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_kwargs = {"timeout": 2}
        error = None
        should_retry_legacy = False

        if use_proxy:
            if parsed.scheme == "https":
                connection_kwargs["context"] = ssl_context
                connection = http.client.HTTPSConnection(proxy_host, proxy_port, **connection_kwargs)
                tunnel_headers = {}
                if proxy_auth_header:
                    tunnel_headers["Proxy-Authorization"] = proxy_auth_header
                connection.set_tunnel(parsed.hostname, target_port, headers=tunnel_headers)
            else:
                connection = http.client.HTTPConnection(proxy_host, proxy_port, **connection_kwargs)
        else:
            connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
            if parsed.scheme == "https":
                connection_kwargs["context"] = ssl_context
            connection = connection_class(parsed.hostname, target_port, **connection_kwargs)

        try:
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += f"?{parsed.query}"

            if use_proxy and parsed.scheme == "http":
                host_hdr = parsed.hostname if target_port == 80 else f"{parsed.hostname}:{target_port}"
                req_headers = {"Host": host_hdr, "Connection": "close"}
                if proxy_auth_header:
                    req_headers["Proxy-Authorization"] = proxy_auth_header
                proxy_target_url = f"http://{host_hdr}{request_path}"
                connection.request("GET", proxy_target_url, headers=req_headers)
            else:
                host_hdr = parsed.hostname if (target_port == 443 if parsed.scheme == "https" else target_port == 80) else f"{parsed.hostname}:{target_port}"
                req_headers = {"Host": host_hdr, "Connection": "close"}
                connection.request("GET", request_path, headers=req_headers)

            response = connection.getresponse()
            body = response.read(16384)
            status_code = response.status
            location = response.getheader("Location")
            content_encoding = (response.getheader("Content-Encoding") or "").lower()
            if "gzip" in content_encoding:
                body = decompress_gzip_payload(body)
            header_bytes = format_response_headers(response)
            if header_bytes:
                body = header_bytes + body
            if explicit_debug:
                proxy_info = f" proxy={proxy_host}:{proxy_port}" if use_proxy else ""
                print(
                    f"[DEBUG scan fetchresponse] protocol={parsed.scheme} service={service_name} port={port}{proxy_info} "
                    f"status={status_code} current_url={current_url} legacy_ssl={allow_legacy_ssl} "
                    f"body={body[:16384]!r}"
                )
        except Exception as exc:
            error = exc
            if parsed.scheme == "https" and not allow_legacy_ssl and is_ssl_handshake_failure(exc):
                should_retry_legacy = True
            else:
                raise
        finally:
            if explicit_debug and error is not None:
                proxy_info = f" proxy={proxy_host}:{proxy_port}" if use_proxy else ""
                if should_retry_legacy:
                    print(
                        f"[DEBUG scan fetchresponse] protocol=https service={parsed.hostname} port={target_port}{proxy_info} "
                        f"handshake failed ({error}); retrying with older TLS versions..."
                    )
                else:
                    print(
                        f"[DEBUG scan fetchresponse] protocol={parsed.scheme} service={parsed.hostname} "
                        f"port={target_port}{proxy_info} error={error!r}"
                    )
            connection.close()

        if should_retry_legacy:
            return fetch_response(
                service_name,
                port,
                scheme,
                url_path,
                max_redirects=max_redirects,
                explicit_debug=explicit_debug,
                allow_legacy_ssl=True,
                use_proxy=use_proxy,
                proxy_settings=proxy_settings,
            )

        if status_code not in {301, 302, 303, 307, 308} or not location:
            return body, status_code, current_url
        if redirect_count == max_redirects:
            return body, status_code, current_url
        current_url = urljoin(current_url, location)

    return b"", 0, current_url


def fetch_socket_response(service_name: str, port: int, url_path: str = ""):
    with socket.create_connection((service_name, port), timeout=2) as connection:
        connection.sendall(
            f"GET {url_path or '/'} HTTP/1.0\r\nHost: {service_name}\r\nConnection: close\r\n\r\n".encode()
        )
        return decompress_socket_response_if_gzip(connection.recv(16384))


def fetch_socket_ssl_response(service_name: str, port: int, url_path: str = "", allow_legacy_ssl: bool = False):
    context = create_ssl_context(legacy=allow_legacy_ssl)
    try:
        with socket.create_connection((service_name, port), timeout=2) as raw_connection:
            with context.wrap_socket(raw_connection, server_hostname=service_name) as connection:
                connection.sendall(
                    f"GET {url_path or '/'} HTTP/1.0\r\nHost: {service_name}\r\nConnection: close\r\n\r\n".encode()
                )
                return decompress_socket_response_if_gzip(connection.recv(16384))
    except Exception as exc:
        if not allow_legacy_ssl and is_ssl_handshake_failure(exc):
            return fetch_socket_ssl_response(service_name, port, url_path=url_path, allow_legacy_ssl=True)
        raise


def format_protocol_label(protocol: str | None) -> str:
    if not protocol:
        return ""
    p = str(protocol).strip().lower()
    mapping = {
        "http": "HTTP",
        "https": "HTTPS",
        "socket": "SOCKET",
        "socket-ssl": "SOCKET SSL",
        "udp": "UDP",
        "udp-ssl": "UDP SSL",
        "icmp": "ICMP PING",
        "icmp-ping": "ICMP PING",
        "ssl-handshake": "SSL HANDSHAKE",
    }
    return mapping.get(p, p.upper())


def format_ports_column(ports: list[dict] | None) -> str:
    """Format ports for Services table PORTS column: PORT:PROTOCOL in black,
    space-separated, with ICMP having no PORT: prefix.
    """
    if not ports:
        return ""
    items = []
    for p in ports:
        port_val = p.get("port")
        proto_val = (p.get("protocol") or "").strip().upper()
        if port_val is None or proto_val in ("ICMP", "ICMP-PING"):
            items.append("ICMP")
        elif proto_val:
            items.append(f"{port_val}:{proto_val}")
        else:
            items.append(str(port_val))
    return " ".join(items)


app.jinja_env.filters["protocol_label"] = format_protocol_label
app.jinja_env.globals["format_protocol_label"] = format_protocol_label
app.jinja_env.filters["format_ports_column"] = format_ports_column
app.jinja_env.globals["format_ports_column"] = format_ports_column


def fetch_udp_response(service_name: str, port: int, url_path: str = "", timeout: float = 2.0) -> bytes:
    addr_info = socket.getaddrinfo(service_name, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not addr_info:
        raise OSError(f"Could not resolve {service_name}")
    family, socktype, proto, canonname, sockaddr = addr_info[0]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        probe = f"GET {url_path or '/'} HTTP/1.0\r\nHost: {service_name}\r\n\r\n".encode()
        sock.send(probe)
        data = sock.recv(16384)
        return decompress_socket_response_if_gzip(data)


def build_dtls_client_hello(service_name: str = "") -> bytes:
    dtls_ver = b"\xfe\xfd"  # DTLS 1.2
    body = dtls_ver
    body += struct.pack("!I", int(time.time())) + os.urandom(28)
    body += b"\x00"  # session id len 0
    body += b"\x00"  # cookie len 0
    ciphers = b"\xc0\x2f\xc0\x30\xc0\x2b\xc0\x2c\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a"
    body += struct.pack("!H", len(ciphers)) + ciphers
    body += b"\x01\x00"  # compression: 1 (null)

    exts = b""
    if service_name and not service_name.replace(".", "").isdigit():
        host_bytes = service_name.encode("utf-8")
        sni_entry = b"\x00" + struct.pack("!H", len(host_bytes)) + host_bytes
        sni_data = struct.pack("!H", len(sni_entry)) + sni_entry
        exts += struct.pack("!H", 0) + struct.pack("!H", len(sni_data)) + sni_data

    groups = b"\x00\x1d\x00\x17\x00\x18"
    exts += struct.pack("!H", 10) + struct.pack("!H", len(groups) + 2) + struct.pack("!H", len(groups)) + groups

    if exts:
        body += struct.pack("!H", len(exts)) + exts

    hs_len = len(body)
    hs_hdr = bytes([1]) + struct.pack("!I", hs_len)[1:] + struct.pack("!H", 0) + struct.pack("!I", 0)[1:] + struct.pack("!I", hs_len)[1:]
    hs_msg = hs_hdr + body

    rec_hdr = bytes([22]) + dtls_ver + struct.pack("!H", 0) + struct.pack("!Q", 0)[2:] + struct.pack("!H", len(hs_msg))
    return rec_hdr + hs_msg


def fetch_udp_ssl_response(service_name: str, port: int, url_path: str = "", timeout: float = 2.0) -> bytes:
    addr_info = socket.getaddrinfo(service_name, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not addr_info:
        raise OSError(f"Could not resolve {service_name}")
    family, socktype, proto, canonname, sockaddr = addr_info[0]
    packet = build_dtls_client_hello(service_name)
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        sock.send(packet)
        data = sock.recv(16384)
        return data


def fetch_icmp_ping_response(service_name: str, timeout: float = 2.0) -> tuple[bool, int, str]:
    t0 = time.monotonic()
    # Method 1: unprivileged DGRAM ICMP socket (RFC 4987 / macOS & Linux)
    try:
        addr_info = socket.getaddrinfo(service_name, None, socket.AF_INET, socket.SOCK_DGRAM)
        if addr_info:
            target_ip = addr_info[0][4][0]
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as s:
                s.settimeout(timeout)
                ident = os.getpid() & 0xFFFF
                packet = struct.pack("!BBHHH", 8, 0, 0, ident, 1) + b"PulseCheckPing"
                s.sendto(packet, (target_ip, 0))
                resp, _ = s.recvfrom(1024)
                latency_ms = max(1, int((time.monotonic() - t0) * 1000))
                snippet = f"ICMP Echo Reply from {target_ip}: bytes={len(resp)} time={latency_ms}ms"
                return True, latency_ms, snippet
    except Exception:
        pass

    # Method 2: System ping CLI fallback (macOS, Linux, etc.)
    try:
        is_mac = sys.platform == "darwin"
        timeout_arg = ["-W", str(int(timeout * 1000))] if is_mac else ["-W", str(max(1, int(timeout)))]
        cmd = ["ping", "-c", "1", *timeout_arg, service_name]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 1.0)
        latency_ms = max(1, int((time.monotonic() - t0) * 1000))
        if proc.returncode == 0:
            out = proc.stdout.strip() or f"ICMP Ping successful ({service_name})"
            m = re.search(r'(\d+)\s+bytes\s+from', out, re.IGNORECASE)
            byte_count = m.group(1) if m else "64"
            if "bytes=" not in out.lower():
                out = f"bytes={byte_count} | {out}"
            return True, latency_ms, out
        else:
            err = proc.stderr.strip() or proc.stdout.strip() or f"Ping failed with exit code {proc.returncode}"
            return False, latency_ms, err
    except Exception as exc:
        latency_ms = max(1, int((time.monotonic() - t0) * 1000))
        return False, latency_ms, str(exc)


def scan_service(
    service_id: int,
    service_name: str,
    ports,
    match: str = "",
    explicit_debug: bool | None = None,
    url_path: str = "",
    use_proxy: bool | None = None,
    protocol: str | None = None,
    **kwargs,
):
    """Probe each port/protocol entry in `ports` and store results.

    `ports` is now a list[dict] with keys {port, protocol}. Port may be None
    for ICMP (portless) probes. Discovered protocols are written back to the
    ports JSON for entries that had protocol = "" (auto-detect).
    """
    service = get_service_by_id(service_id)
    if service is not None and service["paused"]:
        return {}
    if use_proxy is None:
        use_proxy = bool(service["use_proxy"]) if service and "use_proxy" in service else False
    proxy_settings = get_settings() if use_proxy else None
    debug_enabled = EXPLICIT_DEBUG if explicit_debug is None else explicit_debug

    # Normalise ports to list[dict]
    if not isinstance(ports, list):
        ports = parse_port_protocol(ports)
    elif ports and isinstance(ports[0], int):
        ports = [{"port": p, "protocol": ""} for p in ports]

    # Make a mutable copy so we can write discovered protocols back
    ports = [dict(p) for p in ports]

    port_statuses: dict = {}
    for port_entry in ports:
        port = port_entry.get("port")  # None for ICMP
        # Per-port preferred protocol; fall back to legacy service-level protocol arg
        per_port_pref = (port_entry.get("protocol") or "").strip().lower()
        if not per_port_pref and protocol is not None:
            per_port_pref = (protocol or "").strip().lower()
        if not per_port_pref and service:
            per_port_pref = (service.get("protocol") or "").strip().lower()

        start = time.monotonic()
        status = "offline"
        response_ms = None
        # --- Ports without protocol are skipped (except ICMP) ---
        if port is not None and not per_port_pref:
            status = "skipped"
            response_ms = None
            store_port_check(service_id, port, status, response_ms)
            port_statuses[port] = status
            continue

        port_match = port_entry.get("match", "") if port_entry.get("match") is not None else ""
        if not port_match and match:
            port_match = match
        port_url_path = port_entry.get("url_path", "") if port_entry.get("url_path") is not None else ""
        if not port_url_path and url_path:
            port_url_path = url_path

        protocol_used = per_port_pref or ("icmp-ping" if port is None else "http")
        match_bytes = port_match.lower().encode() if port_match else b""
        url_path = port_url_path

        # --- ICMP (portless) ---
        if port is None or per_port_pref in ("icmp", "icmp-ping"):
            try:
                ping_ok, ping_lat, ping_output = fetch_icmp_ping_response(service_name)
                response_ms = ping_lat
                protocol_used = "icmp-ping"
                if ping_ok and "bytes=" in (ping_output or "").lower():
                    status = "online"
                else:
                    status = "offline"
            except Exception:
                status = "offline"
            store_port_check(service_id, None, status, response_ms)
            port_statuses["icmp"] = status
            if not per_port_pref:
                port_entry["protocol"] = protocol_used
            continue

        # --- UDP ---
        if per_port_pref == "udp":
            try:
                udp_resp = fetch_udp_response(service_name, port, url_path)
                response_ms = int((time.monotonic() - start) * 1000)
                if debug_enabled:
                    print(f"[DEBUG scan] protocol=udp service={service_name} port={port} match={match!r} response={udp_resp[:16384]!r}")
                if udp_resp and match_bytes and match_bytes in udp_resp.lower():
                    status = "online"
                elif udp_resp and not match_bytes:
                    status = "online"
                elif udp_resp:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                status = "offline"

        # --- UDP-SSL / DTLS ---
        elif per_port_pref in ("udp-ssl", "dtls"):
            try:
                udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path)
                response_ms = int((time.monotonic() - start) * 1000)
                if debug_enabled:
                    print(f"[DEBUG scan] protocol=udp-ssl service={service_name} port={port} match={match!r} response={udp_ssl_resp[:16384]!r}")
                if udp_ssl_resp and match_bytes and match_bytes in udp_ssl_resp.lower():
                    status = "online"
                elif udp_ssl_resp and not match_bytes:
                    status = "online"
                elif udp_ssl_resp:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                status = "offline"

        # --- SOCKET (plain TCP) ---
        elif per_port_pref == "socket":
            try:
                socket_response = fetch_socket_response(service_name, port, url_path)
                response_ms = int((time.monotonic() - start) * 1000)
                if socket_response and match_bytes and match_bytes in socket_response.lower():
                    status = "online"
                elif socket_response and not match_bytes:
                    status = "online"
                elif socket_response:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                status = "offline"

        # --- SOCKET-SSL ---
        elif per_port_pref == "socket-ssl":
            try:
                ssl_socket_response = fetch_socket_ssl_response(service_name, port, url_path)
                response_ms = int((time.monotonic() - start) * 1000)
                if ssl_socket_response and match_bytes and match_bytes in ssl_socket_response.lower():
                    status = "online"
                elif ssl_socket_response and not match_bytes:
                    status = "online"
                elif ssl_socket_response:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    response_ms = int((time.monotonic() - start) * 1000)
                else:
                    status = "offline"

        # --- HTTPS (explicit) ---
        elif per_port_pref == "https":
            try:
                https_response, status_code, final_url = fetch_response(
                    service_name, port, "https", url_path,
                    explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                )
                response_ms = int((time.monotonic() - start) * 1000)
                if https_response and match_bytes and match_bytes in https_response.lower():
                    status = "online"
                elif https_response and not match_bytes and status_code and 200 <= status_code < 400:
                    status = "online"
                elif https_response:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    response_ms = int((time.monotonic() - start) * 1000)
                else:
                    status = "offline"

        else:
            # Auto-detect cascade (or per_port_pref == "http")
            response = b""
            status_code = None
            final_url = f"http://{service_name}:{port}{url_path or '/'}"
            try:
                response, status_code, final_url = fetch_response(
                    service_name, port, "http", url_path,
                    explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                )
                response_ms = int((time.monotonic() - start) * 1000)
                protocol_used = "http"
                if debug_enabled:
                    print(f"[DEBUG scan] protocol=http service={service_name} port={port} status={status_code} url={final_url} match={match!r} proxy={use_proxy} response={response[:16384]!r}")
            except (socket.timeout, socket.gaierror, OSError, http.client.HTTPException) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    protocol_used = "http"
                    response_ms = int((time.monotonic() - start) * 1000)
                response = b""

            if response and match_bytes and match_bytes in response.lower():
                status = "online"
                protocol_used = "http"
            elif response and not match_bytes and status_code and 200 <= status_code < 400:
                status = "online"
                protocol_used = "http"
            elif status == "online":
                protocol_used = "http"
            elif port in HTTPS_PORTS:
                try:
                    https_response, status_code, final_url = fetch_response(
                        service_name, port, "https", url_path,
                        explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                    )
                    response_ms = int((time.monotonic() - start) * 1000)
                    if debug_enabled:
                        print(f"[DEBUG scan] protocol=https service={service_name} port={port} status={status_code} url={final_url} match={match!r} proxy={use_proxy} response={https_response[:16384]!r}")
                    if https_response and match_bytes and match_bytes in https_response.lower():
                        status = "online"
                        protocol_used = "https"
                    elif https_response and not match_bytes:
                        status = "online"
                        protocol_used = "https"
                    elif https_response:
                        status = "degraded"
                        protocol_used = "https"
                except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                    if is_ssl_handshake_failure(exc):
                        status = "online"
                        protocol_used = "https"
                        response_ms = int((time.monotonic() - start) * 1000)
                if status == "offline" and port in HTTPS_PORTS:
                    status = "degraded"
            elif response:
                status = "degraded"
                protocol_used = "http"

            # Socket fallbacks if not online and not using proxy
            if not per_port_pref and status != "online" and not use_proxy:
                try:
                    socket_response = fetch_socket_response(service_name, port, url_path)
                    response_ms = int((time.monotonic() - start) * 1000)
                    if socket_response and match_bytes and match_bytes in socket_response.lower():
                        status = "online"
                        protocol_used = "socket"
                    elif socket_response and not match_bytes:
                        status = "online"
                        protocol_used = "socket"
                    elif socket_response and status == "offline":
                        status = "degraded"
                        protocol_used = "socket"
                except (socket.timeout, socket.gaierror, OSError):
                    try:
                        ssl_socket_response = fetch_socket_ssl_response(service_name, port, url_path)
                        response_ms = int((time.monotonic() - start) * 1000)
                        if ssl_socket_response and match_bytes and match_bytes in ssl_socket_response.lower():
                            status = "online"
                            protocol_used = "socket-ssl"
                        elif ssl_socket_response and not match_bytes:
                            status = "online"
                            protocol_used = "socket-ssl"
                        elif ssl_socket_response and status == "offline":
                            status = "degraded"
                            protocol_used = "socket-ssl"
                    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                        if is_ssl_handshake_failure(exc):
                            status = "online"
                            protocol_used = "socket-ssl"
                            response_ms = int((time.monotonic() - start) * 1000)

            # UDP fallbacks if not online and not using proxy
            if not per_port_pref and status != "online" and not use_proxy:
                try:
                    udp_resp = fetch_udp_response(service_name, port, url_path)
                    response_ms = int((time.monotonic() - start) * 1000)
                    if udp_resp and match_bytes and match_bytes in udp_resp.lower():
                        status = "online"
                        protocol_used = "udp"
                    elif udp_resp and not match_bytes:
                        status = "online"
                        protocol_used = "udp"
                    elif udp_resp and status == "offline":
                        status = "degraded"
                        protocol_used = "udp"
                except (socket.timeout, socket.gaierror, OSError):
                    try:
                        udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path)
                        response_ms = int((time.monotonic() - start) * 1000)
                        if udp_ssl_resp and match_bytes and match_bytes in udp_ssl_resp.lower():
                            status = "online"
                            protocol_used = "udp-ssl"
                        elif udp_ssl_resp and not match_bytes:
                            status = "online"
                            protocol_used = "udp-ssl"
                        elif udp_ssl_resp and status == "offline":
                            status = "degraded"
                            protocol_used = "udp-ssl"
                    except (socket.timeout, socket.gaierror, OSError):
                        pass

        # Write discovered protocol back to this port entry (auto-detect only)
        if not per_port_pref and protocol_used and status in ("online", "degraded"):
            port_entry["protocol"] = protocol_used

        store_port_check(service_id, port, status, response_ms)
        port_statuses[port] = status

    # Persist updated port protocols back to DB
    try:
        conn = get_db_connection()
        conn.execute("UPDATE services SET port_protocol = ? WHERE id = ?", (port_protocol_to_json(ports), service_id))
        conn.commit()
        conn.close()
    except Exception as exc:
        if debug_enabled:
            print(f"[DEBUG scan] Failed saving per-port protocols: {exc}")

    return port_statuses


def probe_single_port_diagnostics(
    service_name: str,
    port: int,
    match_str: str,
    url_path: str = "",
    use_proxy: bool = False,
    proxy_settings: dict[str, str] | None = None,
    debug_enabled: bool = False,
    preferred_protocol: str = "",
) -> dict:
    t0 = time.monotonic()
    status = "offline"
    status_code = None
    status_text = ""
    protocol_used = preferred_protocol or "http"
    response_bytes = b""
    error_message = None
    retries = 0
    final_url = f"http://{service_name}:{port}{url_path or '/'}"
    now_str = get_current_local_time_str()
    match_bytes = match_str.lower().encode() if match_str else b""

    pref = (preferred_protocol or "").strip().lower()

    if pref == "udp":
        protocol_used = "udp"
        try:
            udp_resp = fetch_udp_response(service_name, port, url_path)
            response_bytes = udp_resp
            status_text = "UDP datagram response"
            if udp_resp and match_bytes and match_bytes in udp_resp.lower():
                status = "online"
            elif udp_resp and not match_bytes:
                status = "online"
            elif udp_resp:
                status = "degraded"
        except (socket.timeout, socket.gaierror, OSError) as exc:
            error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    elif pref in ("udp-ssl", "dtls"):
        protocol_used = "udp-ssl"
        try:
            udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path)
            response_bytes = udp_ssl_resp
            status_text = "UDP SSL (DTLS) response"
            if udp_ssl_resp and match_bytes and match_bytes in udp_ssl_resp.lower():
                status = "online"
            elif udp_ssl_resp and not match_bytes:
                status = "online"
            elif udp_ssl_resp:
                status = "degraded"
        except (socket.timeout, socket.gaierror, OSError) as exc:
            error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    elif pref in ("icmp", "icmp-ping"):
        protocol_used = "icmp-ping"
        try:
            ping_ok, ping_lat, ping_output = fetch_icmp_ping_response(service_name)
            response_bytes = (ping_output or "").encode("utf-8")
            if ping_ok and "bytes=" in (ping_output or "").lower():
                status = "online"
                status_text = f"ICMP Ping response ({ping_lat}ms)"
            else:
                status = "offline"
                error_message = ping_output or "Ping failed (no bytes= in response)"
                status_text = error_message
        except Exception as exc:
            status = "offline"
            error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    elif pref == "socket":
        protocol_used = "socket"
        try:
            sock_resp = fetch_socket_response(service_name, port, url_path)
            response_bytes = sock_resp
            status_text = "Socket HTTP/1.0 response"
            if sock_resp and match_bytes and match_bytes in sock_resp.lower():
                status = "online"
            elif sock_resp and not match_bytes:
                status = "online"
            elif sock_resp:
                status = "degraded"
        except (socket.timeout, socket.gaierror, OSError) as exc:
            error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    elif pref == "socket-ssl":
        protocol_used = "socket-ssl"
        try:
            ssl_sock_resp = fetch_socket_ssl_response(service_name, port, url_path)
            response_bytes = ssl_sock_resp
            status_text = "Socket SSL HTTP/1.0 response"
            if ssl_sock_resp and match_bytes and match_bytes in ssl_sock_resp.lower():
                status = "online"
            elif ssl_sock_resp and not match_bytes:
                status = "online"
            elif ssl_sock_resp:
                status = "degraded"
        except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
            if is_ssl_handshake_failure(exc):
                status = "online"
                status_text = "SSL Handshake (treated as online)"
            else:
                error_message = str(exc) or exc.__class__.__name__
                status_text = error_message
    elif pref == "https":
        protocol_used = "https"
        try:
            https_response, https_code, https_url = fetch_response(
                service_name,
                port,
                "https",
                url_path,
                explicit_debug=debug_enabled,
                use_proxy=use_proxy,
                proxy_settings=proxy_settings,
            )
            status_code = https_code
            status_text = f"HTTPS {https_code}"
            final_url = https_url
            response_bytes = https_response
            if https_response and match_bytes and match_bytes in https_response.lower():
                status = "online"
            elif https_response and not match_bytes and 200 <= https_code < 400:
                status = "online"
            elif https_response:
                status = "degraded"
        except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, http.client.HTTPException) as exc:
            if is_ssl_handshake_failure(exc):
                status = "online"
                status_text = "SSL Handshake (treated as online)"
            elif isinstance(exc, socket.timeout):
                error_message = "HTTPS connection timed out (2.0s limit reached)"
            elif isinstance(exc, ConnectionRefusedError):
                error_message = f"HTTPS connection refused on port {port}"
            else:
                error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    else:
        # Default / cascade: either pref == "http" or pref is empty ("auto-detect")
        try:
            response_bytes, status_code, final_url = fetch_response(
                service_name,
                port,
                "http",
                url_path,
                explicit_debug=debug_enabled,
                use_proxy=use_proxy,
                proxy_settings=proxy_settings,
            )
            protocol_used = "http"
            status_text = f"HTTP {status_code}"
        except (socket.timeout, socket.gaierror, OSError, http.client.HTTPException) as exc:
            if is_ssl_handshake_failure(exc):
                status = "online"
                status_text = "SSL Handshake detected (treated as online)"
                protocol_used = "ssl-handshake"
            elif isinstance(exc, socket.gaierror):
                error_message = f"DNS resolution failed: {exc}"
            elif isinstance(exc, socket.timeout):
                error_message = "Connection timed out (2.0s limit reached)"
            elif isinstance(exc, ConnectionRefusedError):
                error_message = f"Connection refused on port {port}"
            else:
                error_message = str(exc) or exc.__class__.__name__

        # Match evaluation on HTTP response
        if response_bytes and match_bytes and match_bytes in response_bytes.lower():
            status = "online"
        elif response_bytes and not match_bytes and status_code and 200 <= status_code < 400:
            status = "online"
        elif status == "online":
            pass
        elif port in HTTPS_PORTS:
            retries += 1
            try:
                https_response, https_code, https_url = fetch_response(
                    service_name,
                    port,
                    "https",
                    url_path,
                    explicit_debug=debug_enabled,
                    use_proxy=use_proxy,
                    proxy_settings=proxy_settings,
                )
                protocol_used = "https"
                status_code = https_code
                status_text = f"HTTPS {https_code}"
                final_url = https_url
                response_bytes = https_response
                if https_response and match_bytes and match_bytes in https_response.lower():
                    status = "online"
                elif https_response and not match_bytes:
                    status = "online"
                elif https_response:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, http.client.HTTPException) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    status_text = "SSL Handshake (treated as online)"
                    protocol_used = "https"
                elif not error_message:
                    error_message = str(exc) or exc.__class__.__name__
            if status == "offline" and port in HTTPS_PORTS:
                status = "degraded"
        elif response_bytes:
            status = "degraded"

        # Socket fallbacks if not online and not using proxy
        if not pref and status != "online" and not use_proxy:
            try:
                retries += 1
                sock_resp = fetch_socket_response(service_name, port, url_path)
                protocol_used = "socket"
                response_bytes = sock_resp
                status_text = "Socket HTTP/1.0 response"
                if sock_resp and match_bytes and match_bytes in sock_resp.lower():
                    status = "online"
                elif sock_resp and not match_bytes:
                    status = "online"
                elif sock_resp and status == "offline":
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                try:
                    retries += 1
                    ssl_sock_resp = fetch_socket_ssl_response(service_name, port, url_path)
                    protocol_used = "socket-ssl"
                    response_bytes = ssl_sock_resp
                    status_text = "Socket SSL HTTP/1.0 response"
                    if ssl_sock_resp and match_bytes and match_bytes in ssl_sock_resp.lower():
                        status = "online"
                    elif ssl_sock_resp and not match_bytes:
                        status = "online"
                    elif ssl_sock_resp and status == "offline":
                        status = "degraded"
                except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                    if is_ssl_handshake_failure(exc):
                        status = "online"
                        status_text = "SSL Handshake (treated as online)"
                        protocol_used = "socket-ssl"
                    elif not error_message:
                        error_message = str(exc) or exc.__class__.__name__

        # UDP fallback
        if not pref and status != "online" and not use_proxy:
            try:
                retries += 1
                udp_resp = fetch_udp_response(service_name, port, url_path)
                protocol_used = "udp"
                response_bytes = udp_resp
                status_text = "UDP datagram response"
                if udp_resp and match_bytes and match_bytes in udp_resp.lower():
                    status = "online"
                elif udp_resp and not match_bytes:
                    status = "online"
                elif udp_resp and status == "offline":
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError) as exc:
                if not error_message:
                    error_message = str(exc) or exc.__class__.__name__

        # UDP SSL (DTLS) fallback
        if not pref and status != "online" and not use_proxy:
            try:
                retries += 1
                udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path)
                protocol_used = "udp-ssl"
                response_bytes = udp_ssl_resp
                status_text = "UDP SSL (DTLS) response"
                if udp_ssl_resp and match_bytes and match_bytes in udp_ssl_resp.lower():
                    status = "online"
                elif udp_ssl_resp and not match_bytes:
                    status = "online"
                elif udp_ssl_resp and status == "offline":
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError) as exc:
                if not error_message:
                    error_message = str(exc) or exc.__class__.__name__

        # (ICMP is probed separately as a portless probe, so no port fallback)

    duration_ms = max(1, int((time.monotonic() - t0) * 1000))

    snippet_text = ""
    if response_bytes:
        snippet_text = response_bytes[:4096].decode("utf-8", errors="replace")

    match_found = False
    match_count = 0
    if protocol_used == "icmp-ping":
        match_token = ""
    else:
        match_token = match_str
        if match_str and snippet_text:
            lower_snip = snippet_text.lower()
            lower_match = match_str.lower()
            if lower_match in lower_snip:
                match_found = True
                match_count = lower_snip.count(lower_match)

    return {
        "port": port,
        "status": status,
        "status_code": status_code,
        "status_text": status_text or (error_message if error_message else "No response"),
        "protocol": protocol_used,
        "final_url": final_url,
        "duration_ms": duration_ms,
        "retries": retries,
        "match_token": match_token,
        "match_found": match_found,
        "match_count": match_count,
        "response_snippet": snippet_text,
        "error": error_message if (status == "offline" or not snippet_text) else None,
        "timestamp": now_str,
    }


def parse_diagnostic_ports(ports_input) -> list[dict]:
    """Parse ports input into list[{port, protocol, match, url_path}] dicts.
    Accepts:
      - list[dict] with 'port', 'protocol', 'match', 'url_path' keys
      - list[int] (legacy, protocol defaults to '')
      - JSON string: '[{"port":80,"protocol":"http","match":"","url_path":""}]' or '[80,443]'
      - comma/space separated string: '80, 443'
      - 'icmp' or 'icmp-ping' as a token -> {port: None, protocol: 'icmp-ping'}
    """
    def _to_dict(val):
        if isinstance(val, dict):
            return {
                "port": val.get("port"),
                "protocol": (val.get("protocol") or "").strip().lower(),
                "match": (val.get("match") or "").strip(),
                "url_path": (val.get("url_path") or "").strip(),
            }
        if isinstance(val, int):
            return {"port": val, "protocol": "", "match": "", "url_path": ""}
        return None

    if isinstance(ports_input, (list, tuple, set)):
        result = []
        seen_ports = set()
        for p in ports_input:
            d = _to_dict(p)
            if d is not None:
                port_val = d["port"]
                if port_val is None:
                    if "icmp" not in seen_ports:
                        seen_ports.add("icmp")
                        result.append(d)
                elif 1 <= int(port_val) <= 65535 and int(port_val) not in seen_ports:
                    seen_ports.add(int(port_val))
                    result.append(d)
        return result

    if not ports_input:
        return []

    str_val = str(ports_input).strip()
    # Try JSON decode first
    if (str_val.startswith("[") and str_val.endswith("]")) or (str_val.startswith("{") and str_val.endswith("}")):
        try:
            loaded = json.loads(str_val)
            if isinstance(loaded, list):
                return parse_diagnostic_ports(loaded)
        except json.JSONDecodeError:
            pass

    # Comma/space separated string (may include 'icmp')
    parts = re.split(r"[,\s]+", str_val)
    result = []
    seen_ports = set()
    for part in parts:
        cleaned = part.strip().lower()
        if not cleaned:
            continue
        if cleaned in ("icmp", "icmp-ping"):
            if "icmp" not in seen_ports:
                seen_ports.add("icmp")
                result.append({"port": None, "protocol": "icmp-ping", "match": "", "url_path": ""})
            continue
        try:
            val = int(cleaned)
            if 1 <= val <= 65535 and val not in seen_ports:
                seen_ports.add(val)
                result.append({"port": val, "protocol": "", "match": "", "url_path": ""})
        except ValueError:
            pass
    return result


def diagnose_service_ports(
    service_name: str,
    ports: list | str,
    match: str = "",
    url_path: str = "",
    use_proxy: bool = False,
    explicit_debug: bool | None = None,
    preferred_protocol: str = "",
    port_protocols: list[dict] | None = None,
) -> dict:
    """Probe each port with its own protocol and return diagnostic results.

    `ports` can be list[dict] (per-port protocol), list[int] (legacy), or a string.
    `preferred_protocol` is a fallback for any port that has no per-port protocol set.
    `port_protocols` is a list[{port, protocol}] that overrides individual port protocols
     (used when calling from the test route with a fresh port table).
    """
    parsed_ports = parse_diagnostic_ports(ports)

    debug_enabled = EXPLICIT_DEBUG if explicit_debug is None else explicit_debug
    proxy_settings = get_settings() if use_proxy else None
    now_str = get_current_local_time_str()
    match_str = (match or "").strip()

    # Separate numeric ports from ICMP
    tcp_udp_ports = [p for p in parsed_ports if p["port"] is not None]
    icmp_entries = [p for p in parsed_ports if p["port"] is None]

    if not tcp_udp_ports and not icmp_entries:
        return {
            "success": False,
            "error": "No valid ports specified to test.",
            "ports": [],
            "overall_status": "offline",
            "timestamp": now_str,
            "discovered_protocol": "",
        }

    # Helper to resolve per-port protocol
    def resolve_proto(port_entry: dict) -> str:
        p = port_entry.get("protocol") or ""
        if not p and port_protocols:
            for override in port_protocols:
                if override.get("port") == port_entry.get("port"):
                    p = override.get("protocol") or ""
                    break
        return p.strip().lower() if p else preferred_protocol.strip().lower()

    # Submit TCP/UDP probes in parallel
    port_diagnostics = []
    results_by_port = {}
    if tcp_udp_ports:
        max_workers = min(len(tcp_udp_ports), 8)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(
                    probe_single_port_diagnostics,
                    service_name,
                    port_entry["port"],
                    port_entry.get("match") if port_entry.get("match") is not None and port_entry.get("match") != "" else match_str,
                    port_entry.get("url_path") if port_entry.get("url_path") is not None and port_entry.get("url_path") != "" else url_path,
                    use_proxy,
                    proxy_settings,
                    debug_enabled,
                    resolve_proto(port_entry),
                ): port_entry["port"]
                for port_entry in tcp_udp_ports
            }
            for future in futures:
                res = future.result()
                results_by_port[res["port"]] = res

        port_diagnostics = [results_by_port[p["port"]] for p in tcp_udp_ports if p["port"] in results_by_port]

    # ICMP probes (sequential, usually just one)
    icmp_diagnostics = []
    for _ in icmp_entries:
        t0 = time.monotonic()
        try:
            ping_ok, ping_lat, ping_output = fetch_icmp_ping_response(service_name)
            is_success = ping_ok and ("bytes=" in (ping_output or "").lower())
            status = "online" if is_success else "offline"
            icmp_diagnostics.append({
                "port": None,
                "status": status,
                "status_code": None,
                "status_text": f"ICMP Ping response ({ping_lat}ms)" if is_success else (ping_output or "Ping failed"),
                "protocol": "icmp-ping",
                "final_url": service_name,
                "duration_ms": max(1, int((time.monotonic() - t0) * 1000)),
                "retries": 0,
                "match_token": "",
                "match_found": False,
                "match_count": 0,
                "response_snippet": ping_output or "",
                "error": None if is_success else (ping_output or "No bytes= in ping response"),
                "timestamp": now_str,
            })
        except Exception as exc:
            icmp_diagnostics.append({
                "port": None,
                "status": "offline",
                "status_code": None,
                "status_text": str(exc),
                "protocol": "icmp-ping",
                "final_url": service_name,
                "duration_ms": max(1, int((time.monotonic() - t0) * 1000)),
                "retries": 0,
                "match_token": "",
                "match_found": False,
                "match_count": 0,
                "response_snippet": "",
                "error": str(exc),
                "timestamp": now_str,
            })

    all_diagnostics = port_diagnostics + icmp_diagnostics
    statuses_dict = {i: p["status"] for i, p in enumerate(all_diagnostics)}
    overall_status = compute_overall_status(statuses_dict)
    if overall_status == "none":
        overall_status = "offline"

    discovered_protocol = ""
    for p in all_diagnostics:
        if p["status"] == "online" and p.get("protocol"):
            discovered_protocol = p["protocol"]
            break
    if not discovered_protocol:
        for p in all_diagnostics:
            if p["status"] == "degraded" and p.get("protocol"):
                discovered_protocol = p["protocol"]
                break
    if not discovered_protocol and all_diagnostics:
        discovered_protocol = all_diagnostics[0].get("protocol", "")

    return {
        "success": True,
        "service_name": service_name,
        "overall_status": overall_status,
        "timestamp": now_str,
        "ports": all_diagnostics,
        "discovered_protocol": discovered_protocol,
    }


def sync_service_ports(service_id: int, service_name: str, detected_ports: list | None = None):
    """Sync port list to DB (list[dict] or list[int]) and trigger a scan."""
    if detected_ports is not None:
        raw = detected_ports
    else:
        raw = discover_ports(service_name)
    # Normalise to list[dict]
    if raw and isinstance(raw[0], int):
        ports = [{"port": p, "protocol": ""} for p in raw]
    else:
        ports = [dict(p) for p in raw]
    conn = get_db_connection()
    conn.execute(
        "UPDATE services SET port_protocol = ? WHERE id = ?",
        (port_protocol_to_json(ports), service_id),
    )
    conn.commit()
    conn.close()
    service = get_service_by_id(service_id)
    scan_service(
        service_id,
        service_name,
        ports,
        service["match"] if service else derive_match(service_name),
        url_path=service["url_path"] if service else "",
    )


def add_service(
    service_name: str | None = None,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool = False,
    comment: str = "",
    use_proxy: bool = False,
    name: str | None = None,
    ports: list | str | None = None,
    icmp_enabled: bool | None = None,
    protocol: str = "",
    port_protocol: list | str | None = None,
):
    """Add a new service. `ports` or `port_protocol` may be a JSON string, a list[dict], or a list[int]."""
    target_name = service_name if service_name is not None else name
    if not target_name:
        raise ValueError("Service name cannot be empty.")
    normalized = normalize_service(target_name)
    if service_exists(normalized):
        return None
    service_match = (match if match is not None else derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    target_ports = port_protocol if port_protocol is not None else ports
    detected: list[dict] = []
    if target_ports is not None and target_ports != "" and target_ports != []:
        detected = parse_diagnostic_ports(target_ports)
    elif target_ports is None and not paused:
        detected = parse_diagnostic_ports(discover_ports(normalized))
    clean_proto = (protocol or "").strip().lower()
    if clean_proto:
        if clean_proto in ("icmp", "icmp-ping"):
            if not detected:
                icmp_enabled = True
            else:
                for p in detected:
                    if p.get("port") is not None and not p.get("protocol"):
                        p["protocol"] = clean_proto
        else:
            for p in detected:
                if p.get("port") is not None and not p.get("protocol"):
                    p["protocol"] = clean_proto
    # Add / remove ICMP entry if requested
    if icmp_enabled is not None:
        detected = [p for p in detected if p.get("port") is not None]  # remove any stale ICMP
        if icmp_enabled:
            detected.append({"port": None, "protocol": "icmp-ping"})
    for p in detected:
        if p.get("port") is not None:
            if not p.get("match") and service_match:
                p["match"] = service_match
            if not p.get("url_path") and normalized_path:
                p["url_path"] = normalized_path
        else:
            p["match"] = ""
            p["url_path"] = ""

    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO services (name, comment, paused, use_proxy, port_protocol) VALUES (?, ?, ?, ?, ?)",
        (normalized, (comment or "").strip(), int(paused), int(use_proxy), port_protocol_to_json(detected)),
    )
    conn.commit()
    service_id = cursor.lastrowid
    conn.close()
    if detected and not paused:
        scan_service(service_id, normalized, detected, service_match, url_path=normalized_path, use_proxy=use_proxy)
    return service_id



def import_service_names(service_names, progress_callback=None, cancelled_check=None):
    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "duplicates": [],
        "invalid": [],
    }

    entries = [str(value).strip() for value in service_names if str(value).strip()]
    total = len(entries)
    for index, value in enumerate(entries, start=1):
        summary["total"] += 1
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")
        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "service": value,
                "port": None,
                "status": "checking",
                "message": f"Checking service {index} of {total}: {value}",
            })
        try:
            normalized = normalize_service(value)
        except ValueError:
            summary["invalid"].append(value)
            summary["skipped"] += 1
            continue

        if service_exists(normalized):
            summary["duplicates"].append(normalized)
            summary["skipped"] += 1
            continue

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "service": normalized,
                "port": None,
                "status": "scanning",
                "message": f"Scanning ports for {normalized}",
            })

        detected = discover_ports(
            normalized,
            progress_callback=lambda info, s=normalized: progress_callback({
                "index": index,
                "total": total,
                "service": s,
                "port": info["port"],
                "status": "port",
                "message": info["message"],
            }) if progress_callback else None,
            cancelled_check=cancelled_check,
        )

        derived = derive_match(normalized)
        detected_entries = parse_diagnostic_ports(detected)
        for p in detected_entries:
            if p.get("port") is not None:
                p["match"] = derived
                p["url_path"] = ""
            else:
                p["match"] = ""
                p["url_path"] = ""

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, paused, port_protocol) VALUES (?, 0, ?)",
            (normalized, port_protocol_to_json(detected_entries)),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()
        trigger_discovery_async(service_id, normalized)
        scan_service(service_id, normalized, detected_entries, derived, url_path="")
        summary["imported"] += 1

    return summary


def parse_csv_ports(value: str) -> list[dict] | None:
    """Parse a CSV ports field into list[dict] with port+protocol keys.
    Accepts positional protocols via parse_csv_port_protocols()."""
    clean = (value or "").strip().strip("[]()")
    if not clean:
        return None
    result = []
    for part in re.split(r"[,;]+", clean):
        cleaned = part.strip().lower()
        if not cleaned:
            continue
        if cleaned in ("icmp", "icmp-ping"):
            result.append({"port": None, "protocol": "icmp-ping"})
            continue
        try:
            p = int(cleaned)
            if 1 <= p <= 65535:
                result.append({"port": p, "protocol": ""})
        except ValueError:
            pass
    return result or None


def apply_csv_protocols(port_list: list[dict], protocols_str: str) -> list[dict]:
    """Zip a port list with a comma-separated protocol string by position."""
    proto_parts = [p.strip().lower() for p in re.split(r"[,;]+", protocols_str or "") if p.strip()]
    result = [dict(p) for p in port_list]
    for i, port_entry in enumerate(result):
        if i < len(proto_parts) and proto_parts[i]:
            result[i]["protocol"] = proto_parts[i]
    return result


def export_services_csv() -> tuple[str, int]:
    services = service_list()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Service", "Comment", "Paused", "Proxy", "Protocol", "Ports", "URL path", "Match"])
    for s in services:
        ports_list: list[dict] = s["ports"]  # list[dict] with port & protocol & match & url_path
        # Separate ICMP from TCP/UDP ports
        tcp_ports = [p for p in ports_list if p.get("port") is not None]
        icmp_present = any(p.get("port") is None for p in ports_list)
        ordered_ports = list(tcp_ports)
        if icmp_present:
            ordered_ports.append({"port": None, "protocol": "icmp-ping", "match": "", "url_path": ""})

        port_nums = [str(p["port"]) if p.get("port") is not None else "icmp" for p in ordered_ports]
        port_protos = [p.get("protocol") or ("icmp-ping" if p.get("port") is None else "") for p in ordered_ports]
        port_matches = [p.get("match") or "" for p in ordered_ports]
        port_url_paths = [p.get("url_path") or "" for p in ordered_ports]

        distinct_protos = {pr for pr in port_protos if pr}
        if len(distinct_protos) == 1:
            proto_str = list(distinct_protos)[0]
        elif len(distinct_protos) > 1:
            proto_str = ", ".join(port_protos)
        else:
            proto_str = s.get("protocol") or ""

        tcp_matches = [p.get("match") or "" for p in tcp_ports]
        tcp_url_paths = [p.get("url_path") or "" for p in tcp_ports]

        non_empty_matches = [m for m in tcp_matches if m]
        if not non_empty_matches:
            match_str = ""
        elif len(set(tcp_matches)) == 1:
            match_str = tcp_matches[0]
        else:
            match_str = ", ".join(port_matches)

        non_empty_paths = [p for p in tcp_url_paths if p]
        if not non_empty_paths:
            path_str = ""
        elif len(set(tcp_url_paths)) == 1:
            path_str = tcp_url_paths[0]
        else:
            path_str = ", ".join(port_url_paths)

        writer.writerow([
            s["name"],
            s.get("comment", "") or "",
            "1" if s["paused"] else "0",
            "1" if s.get("use_proxy") else "0",
            proto_str,
            ", ".join(port_nums),
            path_str,
            match_str,
        ])
    return output.getvalue(), len(services)


def import_services_from_csv(
    csv_content: str,
    progress_callback=None,
    cancelled_check=None,
) -> dict:
    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "invalid": 0,
        "imported_services": [],
        "skipped_services": [],
        "invalid_rows": [],
    }

    raw_rows = [r for r in csv.reader(io.StringIO(csv_content)) if r and any(cell.strip() for cell in r)]
    if not raw_rows:
        return summary

    header = None
    col_map = {}
    data_rows = []

    first_cells = [c.strip().lower() for c in raw_rows[0]]
    if any(h in first_cells for h in ("service", "service name", "name")):
        header = first_cells
        for idx, col in enumerate(header):
            if col in ("service", "service name", "name"):
                col_map["service"] = idx
            elif col in ("match", "service match"):
                col_map["match"] = idx
            elif col in ("url path", "url_path", "path", "url"):
                col_map["url_path"] = idx
            elif col in ("comment", "comments", "note", "notes"):
                col_map["comment"] = idx
            elif col in ("paused", "is_paused"):
                col_map["paused"] = idx
            elif col in ("proxy", "use_proxy", "use proxy", "is_proxy", "proxy server", "proxy_server"):
                col_map["proxy"] = idx
            elif col in ("protocol", "proto", "service protocol"):
                col_map["protocol"] = idx  # legacy: single protocol for all ports
            elif col in ("ports", "port", "monitored ports"):
                col_map["ports"] = idx
            elif col in ("port protocols", "port_protocols", "protocols", "port protocol"):
                col_map["port_protocols"] = idx  # new: per-port protocol list
        data_rows = raw_rows[1:]
    else:
        first_len = len(raw_rows[0])
        if first_len >= 8:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "proxy": 5, "protocol": 6, "ports": 7}
        elif first_len == 7:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "proxy": 5, "ports": 6}
        elif first_len == 6:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "ports": 5}
        else:
            col_map = {"service": 0, "match": 1, "url_path": 2, "paused": 3, "ports": 4}
        data_rows = raw_rows

    total_records = len(data_rows)

    for index, row in enumerate(data_rows, start=1):
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")

        summary["total"] += 1
        s_idx = col_map.get("service", 0)
        service_val = row[s_idx].strip() if s_idx < len(row) else ""

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total_records,
                "service": service_val or f"Record {index}",
                "status": "processing",
                "message": f"Processing record {index} of {total_records}: {service_val}",
            })

        if not service_val or any(c.isspace() for c in service_val):
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid service '{service_val}'")
            continue

        try:
            normalized = normalize_service(service_val)
        except ValueError:
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid service '{service_val}'")
            continue

        if service_exists(normalized):
            summary["skipped"] += 1
            summary["skipped_services"].append(normalized)
            continue

        m_idx = col_map.get("match", -1)
        match_val = row[m_idx].strip() if m_idx != -1 and m_idx < len(row) else ""
        if not match_val:
            match_val = derive_match(normalized)

        u_idx = col_map.get("url_path", -1)
        url_raw = row[u_idx].strip() if u_idx != -1 and u_idx < len(row) else ""
        try:
            url_path_val = normalize_url_path(url_raw)
        except ValueError:
            url_path_val = ""

        c_idx = col_map.get("comment", -1)
        comment_val = row[c_idx].strip() if c_idx != -1 and c_idx < len(row) else ""

        p_idx = col_map.get("paused", -1)
        paused_raw = row[p_idx].strip().lower() if p_idx != -1 and p_idx < len(row) else "0"
        paused_val = paused_raw in ("1", "true", "yes", "t", "y")

        prx_idx = col_map.get("proxy", -1)
        proxy_raw = row[prx_idx].strip().lower() if prx_idx != -1 and prx_idx < len(row) else "0"
        proxy_val = proxy_raw in ("1", "true", "yes", "t", "y")

        prto_idx = col_map.get("protocol", -1)
        protocol_val = row[prto_idx].strip().lower() if prto_idx != -1 and prto_idx < len(row) else ""

        pts_idx = col_map.get("ports", -1)
        ports_raw = row[pts_idx].strip() if pts_idx != -1 and pts_idx < len(row) else ""
        ports_val = parse_csv_ports(ports_raw) or []

        # Apply per-port protocols: prefer 'port_protocols' column, fall back to legacy 'protocol'
        pproto_idx = col_map.get("port_protocols", -1)
        if pproto_idx != -1 and pproto_idx < len(row) and row[pproto_idx].strip():
            ports_val = apply_csv_protocols(ports_val, row[pproto_idx].strip())
        elif protocol_val:
            if "," in protocol_val or ";" in protocol_val:
                ports_val = apply_csv_protocols(ports_val, protocol_val)
            else:
                ports_val = [{"port": p["port"], "protocol": protocol_val if p.get("port") is not None else "icmp-ping"} for p in ports_val]

        # Apply positional per-port match and url_path
        m_idx = col_map.get("match", -1)
        matches_raw = row[m_idx].strip() if m_idx != -1 and m_idx < len(row) else ""
        match_parts = [m.strip() for m in re.split(r"[,;]+", matches_raw)] if matches_raw else []

        u_idx = col_map.get("url_path", -1)
        paths_raw = row[u_idx].strip() if u_idx != -1 and u_idx < len(row) else ""
        path_parts = [p.strip() for p in re.split(r"[,;]+", paths_raw)] if paths_raw else []

        for i, p in enumerate(ports_val):
            if p.get("port") is None:
                p["match"] = ""
                p["url_path"] = ""
            else:
                if len(match_parts) == 1:
                    p["match"] = match_parts[0]
                elif i < len(match_parts):
                    p["match"] = match_parts[i]
                else:
                    p["match"] = ""

                if len(path_parts) == 1:
                    p["url_path"] = path_parts[0]
                elif i < len(path_parts):
                    p["url_path"] = path_parts[i]
                else:
                    p["url_path"] = ""

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, comment, paused, use_proxy, port_protocol) VALUES (?, ?, ?, ?, ?)",
            (normalized, comment_val, int(paused_val), int(proxy_val), port_protocol_to_json(ports_val)),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()
        trigger_discovery_async(service_id, normalized)

        if not paused_val and ports_val:
            if progress_callback is not None:
                port_nums_str = ", ".join(str(p["port"]) if p.get("port") is not None else "icmp" for p in ports_val)
                progress_callback({
                    "index": index,
                    "total": total_records,
                    "service": normalized,
                    "status": "scanning",
                    "message": f"Scanning ports for {normalized} ({port_nums_str})",
                })
            scan_service(service_id, normalized, ports_val, "", url_path="", use_proxy=proxy_val)

        summary["imported"] += 1
        summary["imported_services"].append(normalized)

    return summary


def update_service(
    service_id: int,
    name: str,
    ports_input,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool | None = None,
    comment: str | None = None,
    use_proxy: bool | None = None,
    icmp_enabled: bool | None = None,
    protocol: str | None = None,
):
    """Update a service. `ports_input` can be:
      - A JSON string from the new port table form: '[{"port":80,"protocol":"http"},...]'
      - A plain comma-separated string: '80, 443' (legacy, protocol defaults to '')
      - A list[dict] already parsed
    `icmp_enabled` adds/removes the portless ICMP entry.
    """
    normalized = normalize_service(name)
    service_match = (match if match is not None else derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    existing_service = None
    if paused is None or comment is None or use_proxy is None:
        existing_service = get_service_by_id(service_id)

    if paused is None:
        paused = existing_service["paused"] if existing_service else False

    if use_proxy is None:
        use_proxy_val = existing_service["use_proxy"] if existing_service and "use_proxy" in existing_service else False
    else:
        use_proxy_val = bool(use_proxy)

    if comment is None:
        comment_val = existing_service["comment"] if existing_service and "comment" in existing_service.keys() else ""
    else:
        comment_val = str(comment).strip()

    # Parse incoming ports to list[dict]
    parsed_ports = parse_diagnostic_ports(ports_input) if ports_input else []
    had_icmp_in_input = any(p.get("port") is None for p in parsed_ports)
    incoming_ports = [p for p in parsed_ports if p.get("port") is not None]

    if protocol is not None:
        clean_proto = (protocol or "").strip().lower()
        if clean_proto in ("icmp", "icmp-ping"):
            if not incoming_ports:
                icmp_enabled = True
            else:
                for p in incoming_ports:
                    if p.get("port") is not None and not p.get("protocol"):
                        p["protocol"] = clean_proto
        elif clean_proto:
            for p in incoming_ports:
                if p.get("port") is not None and not p.get("protocol"):
                    p["protocol"] = clean_proto

    # Handle ICMP
    if icmp_enabled is None:
        if had_icmp_in_input:
            icmp_enabled = True
        else:
            # Preserve existing ICMP setting
            if existing_service is None:
                existing_service = get_service_by_id(service_id)
            if existing_service:
                existing_ports = existing_service.get("ports") or []
                icmp_enabled = any(p.get("port") is None for p in existing_ports)
            else:
                icmp_enabled = False

    if icmp_enabled:
        incoming_ports.append({"port": None, "protocol": "icmp-ping"})

    for p in incoming_ports:
        if p.get("port") is not None:
            if not p.get("match") and service_match:
                p["match"] = service_match
            if not p.get("url_path") and normalized_path:
                p["url_path"] = normalized_path
        else:
            p["match"] = ""
            p["url_path"] = ""

    conn = get_db_connection()
    conn.execute(
        "UPDATE services SET name = ?, comment = ?, paused = ?, use_proxy = ?, port_protocol = ? WHERE id = ?",
        (
            normalized,
            comment_val,
            int(paused),
            int(use_proxy_val),
            port_protocol_to_json(incoming_ports),
            service_id,
        ),
    )
    # Clean up obsolete port_checks for removed ports
    configured_ports = {p.get("port") for p in incoming_ports}
    if None not in configured_ports:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NULL", (service_id,))
    numeric_ports = [p["port"] for p in incoming_ports if p.get("port") is not None]
    if numeric_ports:
        placeholders = ", ".join("?" for _ in numeric_ports)
        conn.execute(f"DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({placeholders})", (service_id, *numeric_ports))
    else:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL", (service_id,))
    conn.commit()
    conn.close()
    if incoming_ports and not paused:
        scan_service(service_id, normalized, incoming_ports, service_match, url_path=normalized_path, use_proxy=use_proxy_val)



def parse_port_values(ports_input: str):
    values = []
    raw_parts = ports_input.replace(",", "\n").splitlines()
    for part in raw_parts:
        value = part.strip()
        if not value:
            continue
        try:
            port = int(value)
        except ValueError:
            raise ValueError(f"Invalid port value '{value}'")
        if not 1 <= port <= 65535:
            raise ValueError(f"Port must be between 1 and 65535: {port}")
        values.append(port)
    return sorted(set(values))


def bulk_update_ports(service_ids, action: str, ports_input: str):
    """Add or remove ports for the selected services.
    - When adding ports: defaults new ports to auto-detect protocol ('') without modifying existing ports.
    - When deleting ports: removes only the specified ports and preserves the protocols of all remaining ports and probes (e.g. ICMP).
    """
    new_port_nums = parse_port_values(ports_input)  # returns list[int]
    if not service_ids:
        raise ValueError("Select at least one service.")
    if action not in {"add", "remove"}:
        raise ValueError("Choose whether to add or remove ports.")
    if not new_port_nums:
        raise ValueError("Enter at least one port.")

    conn = get_db_connection()
    placeholders = ", ".join("?" for _ in service_ids)
    rows = conn.execute(
        f"SELECT id, port_protocol FROM services WHERE id IN ({placeholders})",
        tuple(service_ids),
    ).fetchall()
    found_ids = {row["id"] for row in rows}
    if found_ids != set(service_ids):
        conn.close()
        raise ValueError("One or more selected services no longer exists.")

    for row in rows:
        current_ports: list[dict] = parse_port_protocol(row["port_protocol"])  # list[dict]
        current_port_nums = {p["port"] for p in current_ports if p.get("port") is not None}
        if action == "add":
            for pnum in new_port_nums:
                if pnum not in current_port_nums:
                    # New ports default to auto-detect protocol ("")
                    current_ports.append({"port": pnum, "protocol": ""})
                    current_port_nums.add(pnum)
        else:
            # When deleting a port, preserve the protocols and configuration of all remaining ports
            current_ports = [p for p in current_ports if p.get("port") not in set(new_port_nums)]
        conn.execute(
            "UPDATE services SET port_protocol = ? WHERE id = ?",
            (port_protocol_to_json(current_ports), row["id"]),
        )
        if action == "remove":
            port_placeholders = ", ".join("?" for _ in new_port_nums)
            conn.execute(
                f"DELETE FROM port_checks WHERE service_id = ? AND port IN ({port_placeholders})",
                (row["id"], *new_port_nums),
            )
    conn.commit()
    conn.close()


def delete_service(service_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM port_checks WHERE service_id = ?", (service_id,))
    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()


def get_status_rows():
    conn = get_db_connection()
    check_rows = conn.execute(
        """
        WITH latest AS (
            SELECT service_id, port, is_online, status, last_response_ms, checked_at,
                   ROW_NUMBER() OVER (PARTITION BY service_id, port ORDER BY checked_at DESC) AS rn
            FROM port_checks
        )
        SELECT service_id, port, is_online, status, last_response_ms, checked_at
        FROM latest
        WHERE rn = 1
        """
    ).fetchall()

    latest_checks = {}
    for c in check_rows:
        latest_checks[(c["service_id"], c["port"])] = c

    service_rows = conn.execute(
        """
        SELECT id, name, comment, paused, use_proxy, port_protocol
        FROM services
        WHERE paused = 0
        ORDER BY name ASC
        """
    ).fetchall()
    conn.close()

    result = []
    for s in service_rows:
        ports_list: list[dict] = parse_port_protocol(s["port_protocol"])
        if not ports_list:
            result.append({
                "id": s["id"],
                "name": s["name"],
                "match": "",
                "ports": ports_list,
                "has_ports": False,
                "use_proxy": bool(s["use_proxy"]) if "use_proxy" in s.keys() else False,
                "protocol": "",
                "port": None,
                "is_online": False,
                "status": None,
                "last_response_ms": None,
                "checked_at": None,
                "checked_at_local": "",
            })
            continue

        for p in ports_list:
            port_val = p.get("port")  # int or None
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
                "use_proxy": bool(s["use_proxy"]) if "use_proxy" in s.keys() else False,
                "protocol": port_protocol,
                "port": port_val,
                "is_online": is_online,
                "status": status,
                "last_response_ms": last_response_ms,
                "checked_at": checked_at,
                "checked_at_local": checked_at_local,
            })
    return result



DEFAULT_SETTINGS = {
    "smtp_host": "",
    "smtp_port": "587",
    "smtp_security": "tls",
    "smtp_username": "",
    "smtp_password": "",
    "from_email": "",
    "recipient_email": "",
    "proxy_host": "",
    "proxy_port": "8080",
    "proxy_username": "",
    "proxy_password": "",
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
    conn = get_db_connection()
    for key, value in new_settings.items():
        if key in DEFAULT_SETTINGS:
            val_to_save = str(value) if key in ("smtp_password", "proxy_password") else str(value).strip()
            conn.execute(
                "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                (key, val_to_save),
            )
    conn.commit()
    conn.close()


def send_email(
    to_email: str,
    subject: str,
    body: str,
    settings: dict[str, str] | None = None,
    timeout: int = 10,
    html_body: str | None = None,
    logo_path: str | Path | None = None,
) -> tuple[bool, str]:
    cfg = get_settings() if settings is None else settings
    smtp_host = cfg.get("smtp_host", "").strip()
    smtp_port_raw = cfg.get("smtp_port", "587").strip()
    smtp_security = cfg.get("smtp_security", "tls").strip().lower()
    smtp_username = cfg.get("smtp_username", "").strip()
    smtp_password = cfg.get("smtp_password", "")
    from_email = cfg.get("from_email", "").strip() or smtp_username

    if not smtp_host:
        return False, "SMTP Host is not configured."
    if not to_email:
        return False, "Destination email address is required."
    if not from_email:
        return False, "Sender (From) email address is required."

    try:
        smtp_port = int(smtp_port_raw)
    except ValueError:
        return False, f"Invalid SMTP Port: {smtp_port_raw}"

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_email
    msg["To"] = to_email
    msg.set_content(body)

    email_logo_path = BASE_DIR / "static" / "logo-email.png"
    actual_logo_path = Path(logo_path) if logo_path else (email_logo_path if email_logo_path.exists() else (BASE_DIR / "static" / "logo.png"))

    if not html_body:
        escaped_lines = [
            f"<p style='margin: 4px 0;'>{line}</p>" if line.strip() else "<div style='height: 8px;'></div>"
            for line in body.splitlines()
        ]
        content_html = "\n".join(escaped_lines)
        html_body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
</head>
<body style="margin: 0; padding: 24px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f7fb; color: #1d2433;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #d6dbeb; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);">
    <div style="background: #0f172a; padding: 16px 24px;">
      <table cellpadding="0" cellspacing="0" border="0" style="vertical-align: middle;">
        <tr>
          <td width="28" style="width: 28px; vertical-align: middle; padding-right: 10px;">
            <img src="cid:pulsecheck_logo" alt="PulseCheck Logo" width="28" height="28" style="display: block; width: 28px !important; height: 28px !important; max-width: 28px !important; max-height: 28px !important; border-radius: 6px;" />
          </td>
          <td style="vertical-align: middle;">
            <span style="color: #ffffff; font-size: 18px; font-weight: 700; letter-spacing: -0.3px; vertical-align: middle;">PulseCheck</span>
            <span style="display: inline-block; margin-left: 8px; font-size: 11px; font-weight: 600; color: #94a3b8; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); padding: 2px 6px; border-radius: 4px; vertical-align: middle;">v{APP_VERSION}</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding: 24px; font-size: 15px; line-height: 1.6; color: #1d2433;">
      {content_html}
    </div>
    <div style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center; line-height: 1.5;">
      PulseCheck v{APP_VERSION}
      <a href="https://github.com/diepeterpan/pulsecheck" target="_blank" rel="noopener noreferrer" style="display: inline-block; vertical-align: baseline; margin-left: 6px; margin-right: 8px; color: #64748b; text-decoration: none;" title="PulseCheck on GitHub">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="display: inline-block; vertical-align: -1px;">
          <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
        </svg>
      </a>
      Network &amp; Service Monitoring
    </div>
  </div>
</body>
</html>"""

    msg.add_alternative(html_body, subtype="html")

    if actual_logo_path and actual_logo_path.exists():
        try:
            # Constrain image byte dimensions to max 64x64 so email clients (e.g. Outlook) never render it huge
            try:
                from PIL import Image
                import io
                with Image.open(actual_logo_path) as pil_img:
                    if pil_img.width > 64 or pil_img.height > 64:
                        pil_img.thumbnail((64, 64), Image.Resampling.LANCZOS)
                        buf = io.BytesIO()
                        pil_img.save(buf, format="PNG", optimize=True)
                        logo_bytes = buf.getvalue()
                    else:
                        with open(actual_logo_path, "rb") as f:
                            logo_bytes = f.read()
            except Exception:
                with open(actual_logo_path, "rb") as f:
                    logo_bytes = f.read()

            msg.get_payload()[-1].add_related(
                logo_bytes,
                maintype="image",
                subtype="png",
                cid="<pulsecheck_logo>",
            )
        except Exception:
            pass

    try:
        if smtp_security == "ssl":
            ssl_context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=timeout, context=ssl_context) as server:
                if smtp_username:
                    server.login(smtp_username, smtp_password)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=timeout) as server:
                if smtp_security == "tls":
                    ssl_context = ssl.create_default_context()
                    server.starttls(context=ssl_context)
                if smtp_username:
                    server.login(smtp_username, smtp_password)
                server.send_message(msg)
        return True, f"Test email sent successfully to {to_email}."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


@app.route("/")
def index():
    return redirect(url_for("status"))


def create_import_session(service_names):
    token = uuid.uuid4().hex
    with IMPORT_LOCK:
        IMPORT_STATE[token] = {
            "status": "queued",
            "token": token,
            "index": 0,
            "total": len([line for line in service_names if str(line).strip()]),
            "service": None,
            "port": None,
            "message": "Preparing import",
            "cancelled": False,
            "summary": None,
            "finished": False,
            "error": None,
        }
    thread = threading.Thread(
        target=run_import_worker,
        args=(token, service_names),
        daemon=True,
    )
    thread.start()
    return token


def update_import_state(token, **updates):
    state = IMPORT_STATE.setdefault(token, {"status": "queued"})
    state.update(updates)
    return state


def run_import_worker(token, service_names):
    state = IMPORT_STATE.get(token)
    if state is None:
        return

    def progress(info):
        st = IMPORT_STATE.get(token)
        if not st:
            return
        st["status"] = info.get("status", st["status"])
        st["index"] = info.get("index", st.get("index", 0))
        st["total"] = info.get("total", st.get("total", 0))
        srv_name = info.get("service")
        st["service"] = srv_name
        st["port"] = info.get("port")
        st["message"] = info.get("message", st.get("message", "Working"))

    def cancelled_check():
        st = IMPORT_STATE.get(token)
        return bool(st and st.get("cancelled"))

    state["status"] = "running"
    try:
        summary = import_service_names(
            service_names,
            progress_callback=progress,
            cancelled_check=cancelled_check,
        )
        state["status"] = "complete"
        state["summary"] = summary
    except ImportCancelled:
        state["status"] = "cancelled"
        state["summary"] = {"cancelled": True}
    except Exception as exc:  # pragma: no cover
        state["status"] = "error"
        state["error"] = str(exc)
    finally:
        state["finished"] = True
        state["port"] = None
        state["message"] = "Import finished" if state["status"] == "complete" else state["status"]


def create_csv_import_session(csv_content: str):
    token = uuid.uuid4().hex
    raw_rows = [r for r in csv.reader(io.StringIO(csv_content)) if r and any(cell.strip() for cell in r)]
    first_cells = [c.strip().lower() for c in raw_rows[0]] if raw_rows else []
    has_header = any(h in first_cells for h in ("service", "service name", "name"))
    total_records = max(len(raw_rows) - 1, 0) if has_header else len(raw_rows)

    with IMPORT_LOCK:
        IMPORT_STATE[token] = {
            "status": "queued",
            "token": token,
            "index": 0,
            "total": total_records,
            "service": None,
            "port": None,
            "message": "Preparing CSV import",
            "cancelled": False,
            "summary": None,
            "finished": False,
            "error": None,
        }
    thread = threading.Thread(
        target=run_csv_import_worker,
        args=(token, csv_content),
        daemon=True,
    )
    thread.start()
    return token


def run_csv_import_worker(token, csv_content):
    state = IMPORT_STATE.get(token)
    if state is None:
        return

    def progress(info):
        st = IMPORT_STATE.get(token)
        if not st:
            return
        st["status"] = info.get("status", st["status"])
        st["index"] = info.get("index", st.get("index", 0))
        st["total"] = info.get("total", st.get("total", 0))
        srv_name = info.get("service")
        st["service"] = srv_name
        st["port"] = info.get("port")
        st["message"] = info.get("message", st.get("message", "Working"))

    def cancelled_check():
        st = IMPORT_STATE.get(token)
        return bool(st and st.get("cancelled"))

    state["status"] = "running"
    try:
        summary = import_services_from_csv(
            csv_content,
            progress_callback=progress,
            cancelled_check=cancelled_check,
        )
        state["status"] = "complete"
        state["summary"] = summary
    except ImportCancelled:
        state["status"] = "cancelled"
        state["summary"] = {"cancelled": True}
    except Exception as exc:  # pragma: no cover
        state["status"] = "error"
        state["error"] = str(exc)
    finally:
        state["finished"] = True
        state["port"] = None
        state["message"] = "Import finished" if state["status"] == "complete" else state["status"]


@app.route("/import", methods=["GET", "POST"])
def handle_import():
    if request.method == "POST":
        # Check if CSV file was uploaded
        if "csv_file" in request.files and request.files["csv_file"].filename:
            file = request.files["csv_file"]
            try:
                content = file.read().decode("utf-8", errors="replace")
                summary = import_services_from_csv(content)
                flash(
                    f"CSV Import complete: {summary['imported']} imported, {summary['skipped']} skipped (already in database), {summary['invalid']} invalid (Total rows: {summary['total']}).",
                    "success" if summary["imported"] > 0 else "message",
                )
            except Exception as exc:
                flash(f"Error processing CSV file: {exc}", "error")
            return redirect(url_for("handle_import"))

        raw_text = request.form.get("services") or ""
        items = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not items:
            flash("No service names or CSV file were supplied.", "error")
            return redirect(url_for("handle_import"))

        summary = import_service_names(items)
        flash(
            f"Imported {summary['imported']} services; skipped {summary['skipped']} duplicate or invalid entries.",
            "success",
        )
        return redirect(url_for("services"))

    items = service_list()
    return render_template("import.html", service_count=len(items), services=items)


@app.route("/import/export", methods=["GET"])
@app.route("/services/export.csv", methods=["GET"])
def export_services_route():
    csv_content, count = export_services_csv()
    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=pulsecheck_services.csv"
    response.headers["X-Exported-Count"] = str(count)
    return response


@app.route("/import/start", methods=["POST"])
def start_import():
    raw_text = request.form.get("services") or ""
    items = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not items:
        return {"error": "No service names were supplied."}, 400

    token = create_import_session(items)
    return {"token": token, "status": "started"}


@app.route("/import/csv/start", methods=["POST"])
def start_csv_import():
    if "csv_file" not in request.files or not request.files["csv_file"].filename:
        return {"error": "No CSV file provided."}, 400
    file = request.files["csv_file"]
    content = file.read().decode("utf-8", errors="replace")
    if not content.strip():
        return {"error": "CSV file is empty."}, 400

    token = create_csv_import_session(content)
    return {"token": token, "status": "started"}


@app.route("/import/<token>/status")
def import_status(token):
    state = IMPORT_STATE.get(token)
    if not state:
        return {"status": "not_found"}, 404
    srv_name = state.get("service")
    response = {
        "status": state.get("status"),
        "index": state.get("index", 0),
        "total": state.get("total", 0),
        "service": srv_name,
        "port": state.get("port"),
        "message": state.get("message", "Working"),
        "cancelled": state.get("cancelled", False),
        "finished": state.get("finished", False),
        "summary": state.get("summary"),
        "error": state.get("error"),
    }
    return response


@app.route("/import/<token>/cancel", methods=["POST"])
def cancel_import(token):
    state = IMPORT_STATE.get(token)
    if not state:
        return {"status": "not_found"}, 404
    state["cancelled"] = True
    state["status"] = "cancel_requested"
    state["message"] = "Cancelling import..."
    return {"status": "cancel_requested"}


@app.route("/services")
def services():
    items = service_list()
    return render_template("services.html", services=items)


@app.route("/services/add", methods=["GET", "POST"])
def add_service_route():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        comment = request.form.get("comment", "").strip()
        url_path = request.form.get("url_path", "").strip()
        # New: per-port protocol JSON from hidden field, or legacy plain text
        ports_json_input = request.form.get("ports_json", "").strip()
        ports_input = ports_json_input or request.form.get("ports", "").strip()
        icmp_raw = request.form.get("icmp_enabled")
        icmp_enabled = icmp_raw in ("on", "1", "true", "icmp-ping", "icmp")
        paused = request.form.get("paused") == "on" or request.form.get("paused") == "1"
        use_proxy = request.form.get("use_proxy") == "on" or request.form.get("use_proxy") == "1"
        if not name:
            flash("A service name is required.")
            return redirect(url_for("add_service_route"))
        try:
            result = add_service(
                name=name,
                match=match,
                url_path=url_path,
                comment=comment,
                paused=paused,
                use_proxy=use_proxy,
                ports=ports_input if ports_input else [],
                icmp_enabled=icmp_enabled,
            )
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("add_service_route"))
        if result is None:
            flash("That service already exists.")
            return redirect(url_for("services"))
        trigger_discovery_async(result, normalize_service(name))
        flash(f"Added service {name}.")
        return redirect(url_for("services"))

    return render_template("add_service.html")


@app.route("/services/bulk-ports", methods=["POST"])
def bulk_ports_route():
    raw_ids = request.form.getlist("service_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    try:
        service_ids = sorted({int(value) for value in raw_ids})
        bulk_update_ports(
            service_ids,
            request.form.get("port_action", ""),
            request.form.get("ports", ""),
        )
    except (TypeError, ValueError) as exc:
        flash(str(exc))
        return redirect(return_to or url_for("services"))
    flash("Updated ports for the selected services.")
    return redirect(return_to or url_for("services"))


@app.route("/services/bulk-delete", methods=["POST"])
def bulk_delete_route():
    raw_ids = request.form.getlist("service_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    try:
        service_ids = sorted({int(value) for value in raw_ids})
    except ValueError:
        flash("Invalid service selection.")
        return redirect(return_to or url_for("services"))
    if not service_ids:
        flash("Select at least one service to delete.")
        return redirect(return_to or url_for("services"))

    deleted = 0
    for service_id in service_ids:
        if get_service_by_id(service_id) is not None:
            delete_service(service_id)
            deleted += 1
    flash(f"Deleted {deleted} selected service{'s' if deleted != 1 else ''}.")
    return redirect(return_to or url_for("services"))


@app.route("/services/<int:service_id>/edit", methods=["GET", "POST"])
def edit_service(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        flash("Service not found.")
        return redirect(url_for("services"))

    return_to = request.args.get("return_to") or request.form.get("return_to") or ""
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        url_path = request.form.get("url_path", "")
        comment = request.form.get("comment", "").strip()
        # New: per-port protocol JSON from hidden field, or legacy plain text
        ports_json_input = request.form.get("ports_json", "").strip()
        ports_input = ports_json_input or request.form.get("ports", "")
        icmp_raw = request.form.get("icmp_enabled")
        icmp_enabled = icmp_raw in ("on", "1", "true", "icmp-ping", "icmp")
        paused = request.form.get("paused") == "on"
        use_proxy = request.form.get("use_proxy") == "on" or request.form.get("use_proxy") == "1"
        old_name = service["name"]
        try:
            update_service(service_id, name, ports_input, match, url_path, paused, comment=comment, use_proxy=use_proxy, icmp_enabled=icmp_enabled)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("edit_service", service_id=service_id, return_to=return_to))
        if normalize_service(name) != old_name:
            svc = get_service_by_id(service_id)
            trigger_discovery_async(service_id, normalize_service(name),
                                    prev_mac=svc.get("discovered_mac") if svc else None)
        flash(f"Updated service {name}.")
        return redirect(return_to or url_for("services"))

    return render_template("edit_service.html", service=service, return_to=return_to)


@app.route("/services/<int:service_id>/test", methods=["POST"])
def test_service_edit_route(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        return jsonify({"success": False, "error": "Service not found."}), 404

    data = request.get_json(silent=True) or request.form

    service_name = (data.get("name") or data.get("service_name") or service["name"]).strip()
    match = data.get("match") if "match" in data else service["match"]
    url_path = data.get("url_path") if "url_path" in data else service.get("url_path", "")

    raw_proxy = data.get("use_proxy")
    if raw_proxy is not None:
        use_proxy = raw_proxy is True or str(raw_proxy).lower() in ("true", "1", "on")
    else:
        use_proxy = bool(service.get("use_proxy"))

    # Accept ports as per-port protocol list (new format) or legacy
    ports_input = data.get("ports")
    icmp_raw = data.get("icmp_enabled")
    icmp_enabled = icmp_raw is True or str(icmp_raw).lower() in ("true", "1", "on", "icmp-ping", "icmp") if icmp_raw is not None else False

    if ports_input is None:
        ports = list(service["ports"])  # list[dict] from DB
    else:
        ports = parse_diagnostic_ports(ports_input)

    # Append ICMP entry if requested
    if icmp_enabled and not any(p.get("port") is None for p in ports):
        ports.append({"port": None, "protocol": "icmp-ping"})

    if not service_name:
        return jsonify({"success": False, "error": "Service name cannot be empty."}), 400
    if not ports:
        return jsonify({"success": False, "error": "No valid ports specified to test."}), 400

    results = diagnose_service_ports(
        service_name=service_name,
        ports=ports,
        match=match or "",
        url_path=url_path or "",
        use_proxy=use_proxy,
    )
    return jsonify(results)


@app.route("/services/test", methods=["POST"])
def test_service_generic_route():
    data = request.get_json(silent=True) or request.form
    service_name = (data.get("name") or data.get("service_name") or "").strip()
    match = (data.get("match") or "").strip()
    url_path = data.get("url_path") or ""
    raw_proxy = data.get("use_proxy")
    use_proxy = raw_proxy is True or str(raw_proxy).lower() in ("true", "1", "on")
    ports_input = data.get("ports") or ""
    ports = parse_diagnostic_ports(ports_input)
    icmp_raw = data.get("icmp_enabled")
    icmp_enabled = icmp_raw is True or str(icmp_raw).lower() in ("true", "1", "on", "icmp-ping", "icmp") if icmp_raw is not None else False
    if icmp_enabled:
        if not any(p.get("port") is None for p in ports):
            ports.append({"port": None, "protocol": "icmp-ping"})

    if not service_name:
        return jsonify({"success": False, "error": "Service name cannot be empty."}), 400
    if not ports:
        return jsonify({"success": False, "error": "No valid ports specified to test."}), 400

    match_to_use = match or derive_match(service_name)
    results = diagnose_service_ports(
        service_name=service_name,
        ports=ports,
        match=match_to_use,
        url_path=url_path,
        use_proxy=use_proxy,
    )
    return jsonify(results)


@app.route("/services/<int:service_id>/delete", methods=["POST"])
def delete_service_route(service_id):
    service = get_service_by_id(service_id)
    return_to = request.form.get("return_to") or request.args.get("return_to") or ""
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    if service is not None:
        delete_service(service_id)
        flash(f"Deleted service {service['name']}.")
    return redirect(return_to or url_for("services"))


@app.route("/services/<int:service_id>/rescan", methods=["POST"])
def rescan_service_route(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        flash("Service not found.")
        return redirect(url_for("services"))
    scan_service(
        service_id,
        service["name"],
        service["ports"],
        service["match"],
        url_path=service["url_path"],
        use_proxy=service.get("use_proxy", False),
    )
    flash(f"Rescanned {service['name']}.")
    return redirect(url_for("status"))


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


def compute_system_overall_status(status_rows: list[dict] | None = None) -> dict:
    if status_rows is None:
        status_rows = get_status_rows()

    grouped: dict[str, list[dict]] = {}
    for row in status_rows:
        grouped.setdefault(row["name"], []).append(row)

    services_with_ports = 0
    online_services = 0
    degraded_services = 0
    offline_services = 0

    for name, entries in grouped.items():
        first_entry = entries[0]
        # "Ignore services without any ports listed."
        ports_list = first_entry.get("ports") or []
        if not ports_list:
            continue

        valid_ports = [entry for entry in entries if entry.get("status") is not None and (entry.get("port") is not None or any(p.get("port") is None for p in ports_list))]
        if not valid_ports:
            # Ports listed, but no scan records exist yet
            offline_services += 1
            services_with_ports += 1
            continue

        active_ports = [e for e in valid_ports if e.get("status") != "skipped"]
        if not active_ports:
            # All ports are skipped/no protocol
            continue

        services_with_ports += 1
        online_count = sum(1 for e in active_ports if e.get("status") == "online")
        degraded_count = sum(1 for e in active_ports if e.get("status") == "degraded")
        offline_count = sum(1 for e in active_ports if e.get("status") == "offline")

        if online_count == len(active_ports):
            online_services += 1
        elif offline_count == len(active_ports):
            offline_services += 1
        else:
            degraded_services += 1

    if services_with_ports == 0:
        return {
            "status": "none",
            "label": "NO SERVICES",
            "badge_class": "none",
            "color": "#64748b",
            "counts": {"online": 0, "degraded": 0, "offline": 0, "total": 0},
            "tooltip": "No monitored services with ports configured.",
        }

    # Precedence:
    # 1. Any service offline -> SOME OFFLINE (red)
    # 2. Any service degraded -> SOME DEGRADED (orange)
    # 3. All services online -> ALL ONLINE (green)
    if offline_services > 0:
        return {
            "status": "offline",
            "label": "SOME OFFLINE",
            "badge_class": "offline",
            "color": "#dc2626",
            "counts": {"online": online_services, "degraded": degraded_services, "offline": offline_services, "total": services_with_ports},
            "tooltip": f"{offline_services} offline, {degraded_services} degraded, {online_services} online ({services_with_ports} total)",
        }
    elif degraded_services > 0:
        return {
            "status": "degraded",
            "label": "SOME DEGRADED",
            "badge_class": "degraded",
            "color": "#ea580c",
            "counts": {"online": online_services, "degraded": degraded_services, "offline": offline_services, "total": services_with_ports},
            "tooltip": f"{degraded_services} degraded, {online_services} online ({services_with_ports} total)",
        }
    else:
        return {
            "status": "online",
            "label": "ALL ONLINE",
            "badge_class": "online",
            "color": "#16a34a",
            "counts": {"online": online_services, "degraded": 0, "offline": 0, "total": services_with_ports},
            "tooltip": f"All {online_services} monitored services are online",
        }


def get_scan_schedule_info() -> dict:
    global GLOBAL_SCHEDULER, IS_SCANNING
    now_utc = datetime.now(timezone.utc)
    interval_seconds = 600

    next_dt = None
    if GLOBAL_SCHEDULER:
        try:
            job = GLOBAL_SCHEDULER.get_job("pulsecheck_scan")
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
    with IS_SCANNING_LOCK:
        is_scanning = IS_SCANNING

    return {
        "next_check_iso": next_dt.isoformat(),
        "next_check_timestamp": next_dt.timestamp(),
        "seconds_remaining": seconds_remaining,
        "interval_seconds": interval_seconds,
        "is_scanning": is_scanning,
    }


@app.route("/status/check-state")
def status_check_state():
    last_check = get_last_scheduled_check()
    schedule_info = get_scan_schedule_info()
    rows = get_status_rows()
    overall = compute_system_overall_status(rows)
    return jsonify({
        "last_check_formatted": last_check["formatted"],
        "last_check_timestamp": last_check["timestamp"],
        "next_check_seconds": schedule_info["seconds_remaining"],
        "next_check_timestamp": schedule_info["next_check_timestamp"],
        "is_scanning": schedule_info["is_scanning"],
        "overall_status": overall["status"],
        "overall_label": overall["label"],
    })


@app.route("/status")
def status():
    rows = get_status_rows()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["name"], []).append(row)
    last_check = get_last_scheduled_check()
    schedule_info = get_scan_schedule_info()
    overall_status = compute_system_overall_status(rows)
    return render_template(
        "status.html",
        grouped=grouped,
        last_check=last_check,
        schedule_info=schedule_info,
        overall_status=overall_status,
    )


@app.route("/settings", methods=["GET", "POST"])
def settings_route():
    current_settings = get_settings()
    if request.method == "POST":
        action = request.form.get("action", "save")
        updated = {
            "smtp_host": request.form.get("smtp_host", "").strip(),
            "smtp_port": request.form.get("smtp_port", "587").strip(),
            "smtp_security": request.form.get("smtp_security", "tls").strip(),
            "smtp_username": request.form.get("smtp_username", "").strip(),
            "smtp_password": request.form.get("smtp_password", ""),
            "from_email": request.form.get("from_email", "").strip(),
            "recipient_email": request.form.get("recipient_email", "").strip(),
            "proxy_host": request.form.get("proxy_host", "").strip(),
            "proxy_port": request.form.get("proxy_port", "8080").strip(),
            "proxy_username": request.form.get("proxy_username", "").strip(),
            "proxy_password": request.form.get("proxy_password", ""),
        }
        if not updated["smtp_password"] and current_settings.get("smtp_password"):
            updated["smtp_password"] = current_settings["smtp_password"]
        if not updated["proxy_password"] and current_settings.get("proxy_password"):
            updated["proxy_password"] = current_settings["proxy_password"]

        save_settings(updated)

        if action == "test":
            dest = updated["recipient_email"]
            if not dest:
                flash("Destination email address is required to send a test message.", "error")
            else:
                now_str = get_current_local_time_str()
                test_body = (
                    f"Hello from PulseCheck v{APP_VERSION}!\n\n"
                    "This is a test notification confirming that your SMTP settings and destination "
                    "email address are configured properly.\n\n"
                    f"Timestamp: {now_str}\n"
                    f"SMTP Host: {updated['smtp_host']}:{updated['smtp_port']} ({updated['smtp_security'].upper()})\n"
                    f"Sender: {updated['from_email']}\n"
                    f"Recipient: {dest}\n"
                )
                success, msg = send_email(
                    dest,
                    "[PulseCheck] SMTP Test Message",
                    test_body,
                    settings=updated,
                )
                flash(msg, "success" if success else "error")
        else:
            flash("Settings saved successfully.", "success")

        return redirect(url_for("settings_route"))

    return render_template("settings.html", settings=current_settings)


# ── Network discovery ─────────────────────────────────────────────────────────
MACLOOKUP_API_KEY = os.getenv("PULSECHECK_MACLOOKUP_API_KEY", "")
_MAC_LOOKUP_LOCK = threading.Lock()   # serialise API calls; one at a time


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
    Checks /host/proc/net/arp (Docker mount) and /proc/net/arp first,
    then falls back to 'ip neigh' and 'arp -n'.
    """
    # 1. Direct file lookup in /host/proc/net/arp or /proc/net/arp
    for arp_path in (Path("/host/proc/net/arp"), Path("/proc/net/arp")):
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
            capture_output=True, text=True, timeout=3
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
            capture_output=True, text=True, timeout=3
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
    with _MAC_LOOKUP_LOCK:
        try:
            url = f"https://api.maclookup.app/v2/macs/{mac}"
            headers = {}
            if MACLOOKUP_API_KEY:
                headers["Authorization"] = f"Bearer {MACLOOKUP_API_KEY}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
                vendor = (data.get("company") or "").strip()
                return vendor if vendor else "NONE"
        except Exception:
            return "NONE"
        finally:
            time.sleep(1)   # 1 s gap between any two API calls


def slugify_manufacturer(name: str) -> str:
    """Normalize a manufacturer name into a safe filesystem slug."""
    s = (name or "").lower().strip()
    # Strip common corporate suffixes
    s = re.sub(r"\b(inc|incorporated|corp|corporation|llc|ltd|limited|co|gmbh|sa|bv|s\.p\.a|s\.a|n\.v)\b\.?", "", s)
    # Remove punctuation / special characters
    s = re.sub(r"[^\w\s-]", "", s)
    # Collapse whitespace into underscores
    s = re.sub(r"[\s-]+", "_", s).strip("_")
    return s or "unknown"


def get_manufacturer_icon_url(manufacturer: str | None) -> str | None:
    """Return local cached URL for manufacturer icon if it exists on disk."""
    if not manufacturer or manufacturer.strip().upper() in ("", "NONE"):
        return None
    slug = slugify_manufacturer(manufacturer)
    for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
        icon_path = MANUFACTURER_ICONS_DIR / f"{slug}{ext}"
        if icon_path.is_file() and icon_path.stat().st_size > 0:
            return f"/static/manufacturer-icons/{slug}{ext}"
    return None


@app.route("/static/manufacturer-icons/<path:filename>")
def serve_manufacturer_icon(filename):
    """Serve manufacturer logos cached on disk."""
    return send_from_directory(MANUFACTURER_ICONS_DIR, filename)


# Well-known hardware & networking manufacturers to official domains
_KNOWN_MANUFACTURER_DOMAINS = {
    "apple": "apple.com",
    "dell": "dell.com",
    "intel": "intel.com",
    "cisco": "cisco.com",
    "ubiquiti": "ui.com",
    "hewlett packard": "hp.com",
    "hp": "hp.com",
    "synology": "synology.com",
    "asustek": "asus.com",
    "asus": "asus.com",
    "raspberry pi": "raspberrypi.com",
    "tp-link": "tp-link.com",
    "tplink": "tp-link.com",
    "netgear": "netgear.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "samsung": "samsung.com",
    "sony": "sony.com",
    "lg": "lg.com",
    "lenovo": "lenovo.com",
    "huawei": "huawei.com",
    "d-link": "dlink.com",
    "dlink": "dlink.com",
    "super micro": "supermicro.com",
    "supermicro": "supermicro.com",
    "qnap": "qnap.com",
    "mikrotik": "mikrotik.com",
    "fortinet": "fortinet.com",
    "palo alto": "paloaltonetworks.com",
    "juniper": "juniper.net",
    "aruba": "arubanetworks.com",
    "espressif": "espressif.com",
    "realtek": "realtek.com",
    "broadcom": "broadcom.com",
    "avm": "avm.de",
    "sonos": "sonos.com",
    "brother": "brother.com",
    "canon": "canon.com",
    "epson": "epson.com",
    "xerox": "xerox.com",
}


def resolve_and_cache_manufacturer_icon(manufacturer: str) -> str | None:
    """
    Find, download, and cache an icon for the manufacturer in MANUFACTURER_ICONS_DIR.
    Checks disk cache first to prevent repeated internet requests.
    """
    if not manufacturer or manufacturer.strip().upper() in ("", "NONE"):
        return None

    slug = slugify_manufacturer(manufacturer)
    dest_path = MANUFACTURER_ICONS_DIR / f"{slug}.png"

    # 1. Disk Cache hit
    if dest_path.is_file() and dest_path.stat().st_size > 0:
        return f"/static/manufacturer-icons/{slug}.png"

    # Determine domain to check
    m_lower = manufacturer.lower()
    domain = None
    for key, dom in _KNOWN_MANUFACTURER_DOMAINS.items():
        if key in m_lower:
            domain = dom
            break

    if not domain:
        # Heuristic: use first word or clean slug + .com
        clean_first = slug.split("_")[0]
        if clean_first and len(clean_first) > 2:
            domain = f"{clean_first}.com"

    icon_bytes = None

    # Step A: Google Favicon service
    if domain:
        try:
            fav_url = f"https://www.google.com/s2/favicons?domain={domain}&sz=64"
            req = urllib.request.Request(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = resp.read()
                # Ensure it's non-trivial (>100 bytes)
                if len(data) > 100:
                    icon_bytes = data
        except Exception:
            pass

    # Step B: Direct website probe (favicon.ico / common logo paths / HTML parse)
    if not icon_bytes and domain:
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        direct_candidates = [
            f"https://www.{domain}/imgs/{domain.split('.')[0]}_logo.png",
            f"https://www.{domain}/images/logo.png",
            f"https://www.{domain}/favicon.ico",
            f"https://{domain}/favicon.ico",
        ]
        for candidate_url in direct_candidates:
            try:
                req = urllib.request.Request(candidate_url, headers={"User-Agent": ua})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    data = resp.read()
                    ctype = resp.headers.get("Content-Type", "")
                    if len(data) > 100 and ("image" in ctype or candidate_url.endswith((".png", ".ico", ".jpg", ".svg"))):
                        icon_bytes = data
                        break
            except Exception:
                continue

        # If direct paths failed, try fetching root homepage to extract link rel="icon" or img src="*logo*"
        if not icon_bytes:
            try:
                home_url = f"https://www.{domain}/"
                req = urllib.request.Request(home_url, headers={"User-Agent": ua})
                with urllib.request.urlopen(req, timeout=4) as resp:
                    html = resp.read().decode("utf-8", errors="ignore")
                found_links = re.findall(r'<link[^>]+rel=[\"\'](?:shortcut )?icon[\"\'][^>]+href=[\"\']([^\"\']+)[\"\']', html, re.I)
                found_logos = re.findall(r'<img[^>]+src=[\"\']([^\"\']*(?:logo|icon)[^\"\']*)[\"\']', html, re.I)
                for relative_or_abs in (found_links + found_logos):
                    target = urljoin(home_url, relative_or_abs)
                    try:
                        t_req = urllib.request.Request(target, headers={"User-Agent": ua})
                        with urllib.request.urlopen(t_req, timeout=4) as t_resp:
                            t_data = t_resp.read()
                            if len(t_data) > 100:
                                icon_bytes = t_data
                                break
                    except Exception:
                        continue
                    if icon_bytes:
                        break
            except Exception:
                pass

    # Step C: Wikimedia pageimages fallback if direct probe didn't yield anything
    if not icon_bytes:
        try:
            # Query clean name on Wikipedia
            query_title = manufacturer.split(",")[0].strip()
            wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=pageimages&format=json&titles={urllib.parse.quote(query_title)}&pithumbsize=64"
            req = urllib.request.Request(wiki_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"})
            with urllib.request.urlopen(req, timeout=4) as resp:
                data = json.loads(resp.read().decode())
                pages = data.get("query", {}).get("pages", {})
                thumb_url = None
                for p in pages.values():
                    if "thumbnail" in p and "source" in p["thumbnail"]:
                        thumb_url = p["thumbnail"]["source"]
                        break
                if thumb_url:
                    img_req = urllib.request.Request(thumb_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"})
                    with urllib.request.urlopen(img_req, timeout=4) as img_resp:
                        img_data = img_resp.read()
                        if len(img_data) > 100:
                            icon_bytes = img_data
        except Exception:
            pass

    # Save to disk cache if an icon was obtained
    if icon_bytes:
        try:
            with open(dest_path, "wb") as f:
                f.write(icon_bytes)
            return f"/static/manufacturer-icons/{slug}.png"
        except Exception as exc:
            print(f"[IconCache] Failed to write {dest_path}: {exc}")

    return None


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

    Efficiency rules:
    - No IP  -> clear all three fields; stop.
    - No MAC -> store IP, clear MAC + manufacturer; stop.
    - MAC unchanged vs prev_mac -> skip API call; keep stored manufacturer.
    - MAC present but API fails -> store MAC + "NONE".
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
    scheduler.start()
    GLOBAL_SCHEDULER = scheduler
    return scheduler


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


def send_state_change_notification(changes: list[dict]) -> tuple[bool, str]:
    if not changes:
        return False, "No changes to notify."

    settings = get_settings()
    recipient = settings.get("recipient_email", "").strip()
    if not recipient:
        return False, "No recipient email configured."
    if not settings.get("smtp_host", "").strip():
        return False, "SMTP host not configured."

    count = len(changes)
    subject = f"[PulseCheck] State Change Alert: {count} service{'s' if count > 1 else ''} updated"
    now_str = get_current_local_time_str()

    lines = [
        f"PulseCheck v{APP_VERSION} Service State Change Alert",
        "=====================================",
        f"Scan Completed: {now_str}",
        "",
        f"The following {count} service{'s have' if count > 1 else ' has'} changed state since the previous scan:",
        "",
    ]

    for item in changes:
        target_name = item.get("service") or item.get("name")
        old_st = (item.get("old_status") or "").upper()
        new_st = (item.get("new_status") or "").upper()
        lines.append(f"• Service: {target_name} [{new_st}]")
        lines.append(f"  Overall Status: {old_st} -> {new_st}")
        if item.get("port_changes"):
            lines.append("  Port Details:")
            for p_change in item["port_changes"]:
                lines.append(f"    - {p_change}")
        lines.append("")

    lines.append("---")
    lines.append(f"View live status at: {get_status_url()}")
    lines.append(f"PulseCheck v{APP_VERSION} (https://github.com/diepeterpan/pulsecheck) - Network & Service Monitoring")

    body = "\n".join(lines)

    def get_status_badge_color(status_str: str) -> str:
        st = (status_str or "").strip().upper()
        if st in ("ONLINE", "UP"):
            return "#16a34a"  # Green
        elif st in ("OFFLINE", "DOWN"):
            return "#dc2626"  # Red
        elif st in ("DEGRADED", "PARTIAL"):
            return "#ea580c"  # Orange
        return "#64748b"      # Neutral slate

    def format_port_change_html(p_change: str) -> str:
        # Handles "Port <num>: <OLD> -> <NEW>" or "ICMP Ping: <OLD> -> <NEW>"
        # Also handles arbitrary strings
        if ":" in p_change and "->" in p_change:
            prefix, rest = p_change.split(":", 1)
            parts = rest.split("->")
            if len(parts) == 2:
                old_part = parts[0].strip()
                new_part = parts[1].strip()
                old_c = get_status_badge_color(old_part)
                new_c = get_status_badge_color(new_part)
                return (
                    f"<strong style='color: #1e293b;'>{prefix.strip()}:</strong> "
                    f"<strong style='color: {old_c};'>{old_part}</strong> &rarr; "
                    f"<strong style='color: {new_c};'>{new_part}</strong>"
                )
        return p_change

    cards_html = []
    for item in changes:
        target_name = item.get("service") or item.get("name")
        old_st = (item.get("old_status") or "").upper()
        new_st = (item.get("new_status") or "").upper()
        badge_color = get_status_badge_color(new_st)
        old_color = get_status_badge_color(old_st)
        ports_html = ""
        if item.get("port_changes"):
            p_items = "".join(f"<li style='margin: 4px 0;'>{format_port_change_html(str(p))}</li>" for p in item["port_changes"])
            ports_html = f"<div style='margin-top: 10px; padding-top: 8px; border-top: 1px dashed #e2e8f0; font-size: 13px; color: #475569;'><strong style='color: #334155;'>Port Details:</strong><ul style='margin: 4px 0 0 18px; padding: 0;'>{p_items}</ul></div>"
        cards_html.append(
            f"""<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; background: #ffffff;">
  <div style="margin-bottom: 6px;">
    <strong style="font-size: 16px; color: #0f172a; margin-right: 8px; vertical-align: middle;">{target_name}</strong>
    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background-color: {badge_color}; color: #ffffff; vertical-align: middle;">{new_st}</span>
  </div>
  <div style="font-size: 13px; color: #475569;">Status changed from <strong style="color: {old_color};">{old_st}</strong> to <strong style="color: {badge_color};">{new_st}</strong></div>
  {ports_html}
</div>"""
        )

    service_cards_str = "\n".join(cards_html)
    html_body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
</head>
<body style="margin: 0; padding: 24px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f7fb; color: #1d2433;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #d6dbeb; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);">
    <div style="background: #0f172a; padding: 16px 24px;">
      <table cellpadding="0" cellspacing="0" border="0" style="vertical-align: middle;">
        <tr>
          <td width="28" style="width: 28px; vertical-align: middle; padding-right: 10px;">
            <img src="cid:pulsecheck_logo" alt="PulseCheck Logo" width="28" height="28" style="display: block; width: 28px !important; height: 28px !important; max-width: 28px !important; max-height: 28px !important; border-radius: 6px;" />
          </td>
          <td style="vertical-align: middle;">
            <span style="color: #ffffff; font-size: 18px; font-weight: 700; letter-spacing: -0.3px; vertical-align: middle;">PulseCheck</span>
            <span style="display: inline-block; margin-left: 8px; font-size: 11px; font-weight: 600; color: #94a3b8; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); padding: 2px 6px; border-radius: 4px; vertical-align: middle;">v{APP_VERSION}</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding: 24px;">
      <h2 style="margin: 0 0 8px 0; font-size: 18px; color: #0f172a;">Service State Change Alert</h2>
      <p style="margin: 0 0 16px 0; font-size: 13px; color: #64748b;">Scan completed: {now_str}</p>
      <p style="margin: 0 0 16px 0; font-size: 14px; color: #334155;">The following <strong>{count}</strong> service{'s have' if count > 1 else ' has'} changed state since the previous scan:</p>
      {service_cards_str}
      <div style="margin-top: 20px; text-align: center;">
        <a href="{get_status_url()}" style="display: inline-block; background: #1145d6; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; font-size: 14px;">View Live Status</a>
      </div>
    </div>
    <div style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center; line-height: 1.5;">
      PulseCheck v{APP_VERSION}
      <a href="https://github.com/diepeterpan/pulsecheck" target="_blank" rel="noopener noreferrer" style="display: inline-block; vertical-align: baseline; margin-left: 6px; margin-right: 8px; color: #64748b; text-decoration: none;" title="PulseCheck on GitHub">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="display: inline-block; vertical-align: -1px;">
          <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
        </svg>
      </a>
      Network &amp; Service Monitoring
    </div>
  </div>
</body>
</html>"""

    try:
        success, msg = send_email(recipient, subject, body, settings=settings, html_body=html_body)
        if not success:
            print(f"[PulseCheck Alert Error] Failed to send state change notification: {msg}")
        return success, msg
    except Exception as exc:
        print(f"[PulseCheck Alert Error] Exception sending state change notification: {exc}")
        return False, str(exc)


@app.route("/preview/email")
def preview_email():
    """Renders a sample state change alert email for preview and screenshot capture."""
    sample_changes = [
        {
            "name": "bitwarden.dummy.net",
            "old_status": "online",
            "new_status": "offline",
            "port_changes": [
                "Port 443: ONLINE -> OFFLINE",
                "Port 80: ONLINE -> OFFLINE",
            ],
        },
        {
            "name": "beszel-lenovo.dummy.net",
            "old_status": "online",
            "new_status": "degraded",
            "port_changes": [
                "Port 8080: ONLINE -> DEGRADED (Socket timeout)",
            ],
        },
        {
            "name": "nextcloud.dummy.net",
            "old_status": "offline",
            "new_status": "online",
            "port_changes": [
                "Port 443: OFFLINE -> ONLINE (HTTP 200 OK)",
            ],
        },
    ]

    count = len(sample_changes)
    now_str = get_current_local_time_str()

    def get_status_badge_color(status_str: str) -> str:
        st = (status_str or "").strip().upper()
        if st in ("ONLINE", "UP"):
            return "#16a34a"  # Green
        elif st in ("OFFLINE", "DOWN"):
            return "#dc2626"  # Red
        elif st in ("DEGRADED", "PARTIAL"):
            return "#ea580c"  # Orange
        return "#64748b"

    def format_port_change_html(p_change: str) -> str:
        if ":" in p_change and "->" in p_change:
            prefix, rest = p_change.split(":", 1)
            parts = rest.split("->")
            if len(parts) == 2:
                old_part = parts[0].strip()
                new_part = parts[1].strip()
                old_c = get_status_badge_color(old_part)
                new_c = get_status_badge_color(new_part)
                return (
                    f"<strong style='color: #1e293b;'>{prefix.strip()}:</strong> "
                    f"<strong style='color: {old_c};'>{old_part}</strong> &rarr; "
                    f"<strong style='color: {new_c};'>{new_part}</strong>"
                )
        return p_change

    cards_html = []
    for item in sample_changes:
        target_name = item.get("name")
        old_st = (item.get("old_status") or "").upper()
        new_st = (item.get("new_status") or "").upper()
        badge_color = get_status_badge_color(new_st)
        old_color = get_status_badge_color(old_st)
        ports_html = ""
        if item.get("port_changes"):
            p_items = "".join(f"<li style='margin: 4px 0;'>{format_port_change_html(str(p))}</li>" for p in item["port_changes"])
            ports_html = f"<div style='margin-top: 10px; padding-top: 8px; border-top: 1px dashed #e2e8f0; font-size: 13px; color: #475569;'><strong style='color: #334155;'>Port Details:</strong><ul style='margin: 4px 0 0 18px; padding: 0;'>{p_items}</ul></div>"
        cards_html.append(
            f"""<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; background: #ffffff;">
  <div style="margin-bottom: 6px;">
    <strong style="font-size: 16px; color: #0f172a; margin-right: 8px; vertical-align: middle;">{target_name}</strong>
    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background-color: {badge_color}; color: #ffffff; vertical-align: middle;">{new_st}</span>
  </div>
  <div style="font-size: 13px; color: #475569;">Status changed from <strong style="color: {old_color};">{old_st}</strong> to <strong style="color: {badge_color};">{new_st}</strong></div>
  {ports_html}
</div>"""
        )

    service_cards_str = "\n".join(cards_html)
    logo_src = url_for("static", filename="logo.png")

    html_body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>PulseCheck Alert Preview</title>
</head>
<body style="margin: 0; padding: 32px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; color: #1d2433;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #d6dbeb; overflow: hidden; box-shadow: 0 4px 16px rgba(0, 0, 0, 0.06);">
    <div style="background: #0f172a; padding: 16px 24px;">
      <table cellpadding="0" cellspacing="0" border="0" style="vertical-align: middle;">
        <tr>
          <td width="28" style="width: 28px; vertical-align: middle; padding-right: 10px;">
            <img src="{logo_src}" alt="PulseCheck Logo" width="28" height="28" style="display: block; width: 28px !important; height: 28px !important; max-width: 28px !important; max-height: 28px !important; border-radius: 6px;" />
          </td>
          <td style="vertical-align: middle;">
            <span style="color: #ffffff; font-size: 18px; font-weight: 700; letter-spacing: -0.3px; vertical-align: middle;">PulseCheck</span>
            <span style="display: inline-block; margin-left: 8px; font-size: 11px; font-weight: 600; color: #94a3b8; background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.15); padding: 2px 6px; border-radius: 4px; vertical-align: middle;">v{APP_VERSION}</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding: 24px;">
      <h2 style="margin: 0 0 8px 0; font-size: 18px; color: #0f172a;">Service State Change Alert</h2>
      <p style="margin: 0 0 16px 0; font-size: 13px; color: #64748b;">Scan completed: {now_str}</p>
      <p style="margin: 0 0 16px 0; font-size: 14px; color: #334155;">The following <strong>{count}</strong> services have changed state since the previous scan:</p>
      {service_cards_str}
      <div style="margin-top: 20px; text-align: center;">
        <a href="{get_status_url()}" style="display: inline-block; background: #1145d6; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; font-size: 14px;">View Live Status</a>
      </div>
    </div>
    <div style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center; line-height: 1.5;">
      PulseCheck v{APP_VERSION}
      <a href="https://github.com/diepeterpan/pulsecheck" target="_blank" rel="noopener noreferrer" style="display: inline-block; vertical-align: baseline; margin-left: 6px; margin-right: 8px; color: #64748b; text-decoration: none;" title="PulseCheck on GitHub">
        <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor" style="display: inline-block; vertical-align: -1px;">
          <path fill-rule="evenodd" clip-rule="evenodd" d="M12 2C6.477 2 2 6.484 2 12.017c0 4.425 2.865 8.18 6.839 9.504.5.092.682-.217.682-.483 0-.237-.008-.868-.013-1.703-2.782.605-3.369-1.343-3.369-1.343-.454-1.158-1.11-1.466-1.11-1.466-.908-.62.069-.608.069-.608 1.003.07 1.53 1.032 1.53 1.032.892 1.53 2.341 1.088 2.91.832.092-.647.35-1.088.636-1.338-2.22-.253-4.555-1.113-4.555-4.951 0-1.093.39-1.988 1.029-2.688-.103-.253-.446-1.272.098-2.65 0 0 .84-.27 2.75 1.026A9.564 9.564 0 0112 6.844c.85.004 1.705.115 2.504.337 1.909-1.296 2.747-1.027 2.747-1.027.546 1.379.202 2.398.1 2.651.64.7 1.028 1.595 1.028 2.688 0 3.848-2.339 4.695-4.566 4.943.359.309.678.92.678 1.855 0 1.338-.012 2.419-.012 2.747 0 .268.18.58.688.482A10.019 10.019 0 0022 12.017C22 6.484 17.522 2 12 2z"/>
        </svg>
      </a>
      Network &amp; Service Monitoring
    </div>
  </div>
</body>
</html>"""
    return Response(html_body, mimetype="text/html")


def scan_service_with_retries(
    service: dict,
    max_retries: int = DEFAULT_SCAN_RETRIES,
    retry_interval: int = DEFAULT_SCAN_RETRY_INTERVAL,
    explicit_debug: bool | None = None,
) -> dict[int, str]:
    debug_enabled = EXPLICIT_DEBUG if explicit_debug is None else explicit_debug
    port_statuses: dict[int, str] = {}
    scanner = getattr(sys.modules[__name__], "scan_service", scan_service)

    for attempt in range(max_retries + 1):
        try:
            res = scanner(
                service["id"],
                service["name"],
                service["ports"],
                service["match"],
                explicit_debug=debug_enabled,
                url_path=service.get("url_path", ""),
                use_proxy=service.get("use_proxy", False),
                protocol=service.get("protocol", ""),
            )
            port_statuses = res if isinstance(res, dict) else {}
            overall = compute_overall_status(port_statuses)
            if overall == "online" or not port_statuses:
                return port_statuses
            if attempt < max_retries:
                if debug_enabled:
                    print(
                        f"[DEBUG scan retry] Service {service['name']} overall status is {overall}. "
                        f"Retrying ({attempt + 1}/{max_retries}) in {retry_interval}s..."
                    )
                time.sleep(retry_interval)
        except Exception as exc:
            if debug_enabled:
                print(
                    f"[DEBUG scan retry] Exception scanning {service['name']} on attempt {attempt + 1}: {exc}"
                )
            if attempt < max_retries:
                time.sleep(retry_interval)
    return port_statuses


def check_all_services(
    workers: int | None = None,
    max_retries: int | None = None,
    retry_interval: int | None = None,
) -> list[dict]:
    global IS_SCANNING
    with IS_SCANNING_LOCK:
        IS_SCANNING = True

    try:
        num_workers = DEFAULT_SCAN_WORKERS if workers is None else max(1, workers)
        retries = DEFAULT_SCAN_RETRIES if max_retries is None else max_retries
        interval = DEFAULT_SCAN_RETRY_INTERVAL if retry_interval is None else retry_interval

        before_snapshots = get_service_snapshots()
        active_services = [service for service in service_list() if not service.get("paused")]

        if active_services:
            max_workers = min(num_workers, len(active_services))
            scan_worker = getattr(sys.modules[__name__], "scan_service_with_retries", scan_service_with_retries)

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
            send_state_change_notification(changes)

        return changes
    finally:
        with IS_SCANNING_LOCK:
            IS_SCANNING = False
        record_scan_completed()


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Start web app")
        print("2. Start web with Explicit debugging")
        print("3. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            print(f"Starting web application on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            app.run(host=DEFAULT_IP, port=DEFAULT_PORT, debug=False)
            break

        elif choice == "2":
            global EXPLICIT_DEBUG
            EXPLICIT_DEBUG = True
            print(f"Starting web application with explicit debugging on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            app.run(host=DEFAULT_IP, port=DEFAULT_PORT, debug=False)
            break

        elif choice == "3":
            print("Exiting PulseCheck.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    init_db()
    scheduler = run_background_tasks()
    try:
        if os.getenv("PULSECHECK_HEADLESS", "").lower() in ("1", "true", "yes") or not sys.stdin.isatty():
            print(f"Starting web application on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            app.run(host=DEFAULT_IP, port=DEFAULT_PORT, debug=False)
        else:
            cli_menu()
    finally:
        scheduler.shutdown(wait=False)
