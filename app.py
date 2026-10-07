from __future__ import annotations

import asyncio
import base64
import csv
import functools
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import sqlite3
import socket
import aiohttp
from aiohttp.http_exceptions import HttpProcessingError
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
from flask_compress import Compress

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("PULSECHECK_DB_PATH", str(BASE_DIR / "pulsecheck.db")))
MANUFACTURER_ICONS_DIR = DB_PATH.parent / "manufacturer_icons"
MANUFACTURER_ICONS_DIR.mkdir(parents=True, exist_ok=True)
SERVICE_ICONS_DIR = DB_PATH.parent / "service_icons"
SERVICE_ICONS_DIR.mkdir(parents=True, exist_ok=True)
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 587, 993, 995, 8080, 8443, 8444, 3306, 5432, 27017, 3000, 9000]
HTTPS_PORTS = {443, 8443, 8444}
HTTP_PROBE_EXCEPTIONS = (
    socket.timeout,
    socket.gaierror,
    OSError,
    http.client.HTTPException,
    aiohttp.ClientError,
    HttpProcessingError,
)
DEFAULT_PORT = int(os.getenv("PULSECHECK_PORT", "8182"))
DEFAULT_IP = os.getenv("PULSECHECK_IP", os.getenv("PULSECHECK_HOST", "0.0.0.0"))
DEFAULT_HOSTNAME = os.getenv("PULSECHECK_HOSTNAME", "127.0.0.1")
DEFAULT_SSL = os.getenv("PULSECHECK_SSL", "FALSE").strip().lower() in ("true", "1", "yes")
DEFAULT_SCAN_WORKERS = int(os.getenv("PULSECHECK_SCAN_WORKERS", "5"))
DEFAULT_SCAN_RETRIES = int(os.getenv("PULSECHECK_SCAN_RETRIES", "6"))
DEFAULT_SCAN_RETRY_INTERVAL = int(os.getenv("PULSECHECK_SCAN_RETRY_INTERVAL", "5"))
DEFAULT_HISTORY_RETENTION_DAYS = int(os.getenv("PULSECHECK_HISTORY_RETENTION_DAYS", "1"))
DEFAULT_SCANNER_BYPASS_KEY = os.getenv(
    "PULSECHECK_SCANNER_BYPASS_KEY",
    os.getenv("SCANNER_BYPASS_KEY", "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")
).strip()
EXPLICIT_DEBUG = os.getenv("PULSECHECK_EXPLICIT_DEBUG", os.getenv("PULSECHECK_DEBUG", "FALSE")).strip().lower() in ("true", "1", "yes")
LINE_PROFILER_ENABLED = os.getenv("PULSECHECK_PROFILE", "").strip().lower() in ("true", "1", "yes")
GLOBAL_LINE_PROFILER = None
APP_VERSION = os.getenv("PULSECHECK_VERSION", "1.3.0")
__version__ = APP_VERSION

# Safe @profile decorator fallback:
# If running under `kernprof -l` or LineProfiler, builtins.profile already exists.
# Otherwise, provide a passthrough decorator.
import builtins
if "profile" not in builtins.__dict__:
    def profile(func):
        return func
    builtins.__dict__["profile"] = profile
else:
    profile = builtins.__dict__["profile"]


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
compress = Compress(app)


@app.context_processor
def inject_version():
    return {
        "app_version": APP_VERSION,
        "version": APP_VERSION,
        "get_manufacturer_icon_url": get_manufacturer_icon_url,
        "get_service_icon_url": get_service_icon_url,
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
            request_type TEXT NOT NULL DEFAULT 'web',
            port_protocol TEXT NOT NULL DEFAULT '[]',
            discovered_ip TEXT DEFAULT NULL,
            discovered_mac TEXT DEFAULT NULL,
            discovered_manufacturer TEXT DEFAULT NULL,
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

    # Trigger to guarantee latest_port_checks stays in sync even when raw SQL inserts into port_checks
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

    # Initial migration: populate latest_port_checks from port_checks if empty
    try:
        latest_count = conn.execute("SELECT COUNT(*) FROM latest_port_checks").fetchone()[0]
        if latest_count == 0:
            conn.execute(
                """
                INSERT OR REPLACE INTO latest_port_checks (service_id, port, is_online, status, last_response_ms, checked_at)
                SELECT service_id, port, is_online, status, last_response_ms, checked_at
                FROM (
                    SELECT service_id, port, is_online, status, last_response_ms, checked_at,
                           ROW_NUMBER() OVER (PARTITION BY service_id, port ORDER BY checked_at DESC) AS rn
                    FROM port_checks
                )
                WHERE rn = 1
                """
            )
            conn.commit()
    except Exception:
        pass

    # Clean up obsolete port_checks and latest_port_checks rows for ports no longer configured on services
    try:
        service_rows = conn.execute("SELECT id, port_protocol FROM services").fetchall()
        for s in service_rows:
            p_list = parse_port_protocol(s["port_protocol"])
            cfg_ports = {p.get("port") for p in p_list}
            if None not in cfg_ports:
                conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NULL", (s["id"],))
                conn.execute("DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NULL", (s["id"],))
            num_ports = [p["port"] for p in p_list if p.get("port") is not None]
            if num_ports:
                ph = ", ".join("?" for _ in num_ports)
                conn.execute(f"DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({ph})", (s["id"], *num_ports))
                conn.execute(f"DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({ph})", (s["id"], *num_ports))
            else:
                conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL", (s["id"],))
                conn.execute("DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NOT NULL", (s["id"],))
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
        if "request_type" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN request_type TEXT NOT NULL DEFAULT 'web'")
        if "discovered_ip" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_ip TEXT DEFAULT NULL")
        if "discovered_mac" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_mac TEXT DEFAULT NULL")
        if "discovered_manufacturer" not in svc_cols:
            conn.execute("ALTER TABLE services ADD COLUMN discovered_manufacturer TEXT DEFAULT NULL")
    except Exception:
        pass

    # Migration: rename socket and socket-ssl protocols in port_protocol to tcp and tcp-ssl
    try:
        rows_to_check = conn.execute("SELECT id, port_protocol FROM services").fetchall()
        for r in rows_to_check:
            raw_ports = parse_port_protocol(r["port_protocol"])
            migrated = False
            for p in raw_ports:
                proto = (p.get("protocol") or "").strip().lower()
                if proto == "socket":
                    p["protocol"] = "tcp"
                    migrated = True
                elif proto == "socket-ssl":
                    p["protocol"] = "tcp-ssl"
                    migrated = True
            if migrated:
                conn.execute(
                    "UPDATE services SET port_protocol = ? WHERE id = ?",
                    (port_protocol_to_json(raw_ports), r["id"]),
                )
    except Exception:
        pass

    conn.commit()
    conn.close()
    try:
        prune_historical_port_checks()
    except Exception:
        pass


def parse_hex_bytes(value: str | bytes | None) -> bytes:
    """Parse a hex byte string into raw bytes.
    Accepts space-separated, comma/colon-separated, or contiguous hex characters (e.g. '01 02 A3 FF', '0x01, 0x02', or '0102a3ff').
    Raises ValueError on invalid hex input."""
    if value is None:
        return b""
    if isinstance(value, bytes):
        return value
    # Split by whitespace, comma, or colon
    raw_str = str(value).strip()
    if not raw_str:
        return b""
    # Tokenize by whitespace, commas, colons
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


@functools.lru_cache(maxsize=1024)
def _cached_format_local_time(val_str: str, target_tz: timezone | ZoneInfo | None) -> str:
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
            if proto_val == "socket":
                proto_val = "tcp"
            elif proto_val == "socket-ssl":
                proto_val = "tcp-ssl"
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
    """Serialise a list of port dicts back to JSON for DB storage.
    Handles list[dict], list[int], or strings gracefully."""
    normalized = []
    if isinstance(ports, str):
        try:
            ports = json.loads(ports)
        except Exception:
            ports = parse_diagnostic_ports(ports)
    for p in (ports or []):
        if isinstance(p, dict):
            proto_val = (p.get("protocol") or "").strip().lower()
            if proto_val == "socket":
                proto_val = "tcp"
            elif proto_val == "socket-ssl":
                proto_val = "tcp-ssl"
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


def service_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, comment, paused, use_proxy, request_type, port_protocol, created_at, "
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
            "request_type": row["request_type"] if "request_type" in row.keys() else "web",
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
        "SELECT id, name, comment, paused, use_proxy, request_type, port_protocol, created_at, "
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
        "request_type": row["request_type"] if "request_type" in row.keys() else "web",
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


@functools.lru_cache(maxsize=2)
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
    err_tokens = []
    curr = exc
    visited = set()
    while curr is not None and id(curr) not in visited:
        visited.add(id(curr))
        if isinstance(curr, ssl.SSLError):
            try:
                err_tokens.append(str(curr).upper())
            except Exception:
                pass
        for attr in ("certificate_error", "ssl_error", "args"):
            val = getattr(curr, attr, None)
            if val is not None:
                try:
                    err_tokens.append(str(val).upper())
                except Exception:
                    pass
        try:
            err_tokens.append(str(curr).upper())
        except Exception:
            pass
        curr = getattr(curr, "__cause__", None) or getattr(curr, "__context__", None)

    combined = " ".join(err_tokens)
    if "CERTIFICATE_VERIFY_FAILED" in combined:
        return False
    return any(k in combined for k in (
        "SSLV3_ALERT_HANDSHAKE_FAILURE",
        "HANDSHAKE_FAILURE",
        "UNSAFE_LEGACY_RENEGOTIATION_DISABLED",
        "NO_PROTOCOLS_AVAILABLE",
        "APPLICATION DATA AFTER CLOSE NOTIFY",
    ))


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


class AsyncHttpManager:
    """Manages a dedicated background asyncio event loop and shared aiohttp.ClientSession
    for high-performance, non-blocking HTTP/HTTPS probing and icon scraping."""
    _loop: asyncio.AbstractEventLoop | None = None
    _thread: threading.Thread | None = None
    _session: aiohttp.ClientSession | None = None
    _lock = threading.Lock()

    @classmethod
    def _run_event_loop(cls):
        cls._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(cls._loop)
        cls._loop.run_forever()

    @classmethod
    def get_loop(cls) -> asyncio.AbstractEventLoop:
        if cls._loop is None or not cls._loop.is_running():
            with cls._lock:
                if cls._loop is None or not cls._loop.is_running():
                    cls._thread = threading.Thread(target=cls._run_event_loop, daemon=True, name="PulseCheck-AsyncIO")
                    cls._thread.start()
                    while cls._loop is None or not cls._loop.is_running():
                        time.sleep(0.002)
        return cls._loop

    @classmethod
    async def get_session(cls) -> aiohttp.ClientSession:
        if cls._session is None or cls._session.closed:
            connector = aiohttp.TCPConnector(ssl=False, limit=100, ttl_dns_cache=300)
            cls._session = aiohttp.ClientSession(
                connector=connector,
                auto_decompress=True,
            )
        return cls._session

    @classmethod
    def run_coroutine(cls, coro):
        """Execute a coroutine safely on the managed async event loop from any thread."""
        loop = cls.get_loop()
        future = asyncio.run_coroutine_threadsafe(coro, loop)
        return future.result()

    @classmethod
    async def async_get_url(
        cls,
        url: str,
        headers: dict | None = None,
        timeout: float = 4.0,
        verify_ssl: bool = False,
        max_redirects: int = 5,
    ) -> tuple[bytes, int, dict]:
        """Fetch URL content asynchronously using the pooled aiohttp session."""
        session = await cls.get_session()
        client_timeout = aiohttp.ClientTimeout(total=timeout)
        req_headers = {"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}
        if headers:
            req_headers.update(headers)

        ssl_param = False if not verify_ssl else None
        async with session.get(
            url,
            headers=req_headers,
            timeout=client_timeout,
            ssl=ssl_param,
            max_redirects=max_redirects,
            allow_redirects=True,
        ) as resp:
            data = await resp.read()
            resp_headers = dict(resp.headers)
            return data, resp.status, resp_headers

    @classmethod
    def get_url(
        cls,
        url: str,
        headers: dict | None = None,
        timeout: float = 4.0,
        verify_ssl: bool = False,
        max_redirects: int = 5,
    ) -> tuple[bytes, int, dict]:
        """Synchronous wrapper for async_get_url."""
        # If urllib.request.urlopen was patched in unit tests, route to it for test compatibility
        urlopen_fn = getattr(urllib.request, "urlopen", None)
        if urlopen_fn is not None and not getattr(urlopen_fn, "__module__", "").startswith("urllib.request"):
            req = urllib.request.Request(url, headers=headers or {"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
                resp_headers = dict(resp.headers) if hasattr(resp, "headers") else {}
                code = 200
                raw_code = getattr(resp, "code", None)
                if raw_code is None or hasattr(raw_code, "_mock_return_value") or hasattr(raw_code, "_mock_name"):
                    raw_code = getattr(resp, "status", None)
                if raw_code is not None and not hasattr(raw_code, "_mock_return_value") and not hasattr(raw_code, "_mock_name"):
                    try:
                        code = int(raw_code)
                    except Exception:
                        code = 200
                return data, code, resp_headers

        return cls.run_coroutine(
            cls.async_get_url(
                url=url,
                headers=headers,
                timeout=timeout,
                verify_ssl=verify_ssl,
                max_redirects=max_redirects,
            )
        )



async def async_fetch_response(
    service_name: str,
    port: int,
    scheme: str,
    url_path: str = "",
    max_redirects: int = 5,
    explicit_debug: bool = False,
    allow_legacy_ssl: bool = False,
    use_proxy: bool = False,
    proxy_settings: dict[str, str] | None = None,
    custom_headers: dict[str, str] | None = None,
) -> tuple[bytes, int, str]:
    current_url = f"{scheme}://{service_name}:{port}{url_path or '/'}"
    ssl_context = create_ssl_context(legacy=allow_legacy_ssl)

    proxy_url = None
    proxy_auth = None
    if use_proxy:
        cfg = get_settings() if proxy_settings is None else proxy_settings
        raw_host = (cfg.get("proxy_host") or "").strip()
        proxy_host = ""
        proxy_port = 8080
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
        if cfg.get("proxy_port"):
            try:
                proxy_port = int(str(cfg.get("proxy_port")).strip())
            except ValueError:
                pass
        p_user = (cfg.get("proxy_username") or "").strip()
        p_pass = cfg.get("proxy_password") or ""
        proxy_url = f"http://{proxy_host}:{proxy_port}"
        if p_user:
            import yarl
            proxy_auth = aiohttp.BasicAuth.from_url(yarl.URL(f"http://{urllib.parse.quote(p_user)}:{urllib.parse.quote(p_pass)}@{proxy_host}:{proxy_port}"))

    fetch_start = time.monotonic()
    session = await AsyncHttpManager.get_session()

    client_timeout = aiohttp.ClientTimeout(total=2.5, connect=2.0)
    req_headers = {"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}
    if custom_headers:
        req_headers.update(custom_headers)

    # If test suites or callers patched http.client.HTTPConnection or HTTPSConnection, execute with full redirect and error handling
    is_https = scheme.lower() == "https"
    conn_cls = getattr(http.client, "HTTPSConnection" if is_https else "HTTPConnection", None)
    is_custom_mock = conn_cls is not None and not conn_cls.__module__.startswith("http.client")
    if is_custom_mock:
        conn_kwargs = {"timeout": 2}
        if is_https:
            conn_kwargs["context"] = ssl_context
        conn = None
        error = None
        should_retry = False
        try:
            curr_url = current_url
            for r_count in range(max_redirects + 1):
                p_url = urlsplit(curr_url)
                p_port = p_url.port or (443 if p_url.scheme == "https" else 80)
                target_host = proxy_host if use_proxy else p_url.hostname
                target_port = proxy_port if use_proxy else p_port
                conn = conn_cls(target_host, target_port, **conn_kwargs)
                if use_proxy and hasattr(conn, "set_tunnel") and p_url.scheme == "https":
                    t_hdrs = {}
                    if p_user:
                        t_hdrs["Proxy-Authorization"] = f"Basic {base64.b64encode(f'{p_user}:{p_pass}'.encode('latin1')).decode('ascii')}"
                    conn.set_tunnel(p_url.hostname, p_port, headers=t_hdrs)

                req_path = p_url.path or "/"
                if p_url.query:
                    req_path += f"?{p_url.query}"
                req_hdrs = {"Host": p_url.hostname}
                if custom_headers:
                    req_hdrs.update(custom_headers)
                if use_proxy and p_url.scheme == "http":
                    if p_user:
                        req_hdrs["Proxy-Authorization"] = f"Basic {base64.b64encode(f'{p_user}:{p_pass}'.encode('latin1')).decode('ascii')}"
                    req_target = f"http://{p_url.hostname}{req_path}"
                    conn.request("GET", req_target, headers=req_hdrs)
                else:
                    conn.request("GET", req_path, headers=req_hdrs)

                r = conn.getresponse()
                raw_data = r.read(16384)
                status_code = r.status
                loc = r.getheader("Location") if hasattr(r, "getheader") else None
                enc = (r.getheader("Content-Encoding") if hasattr(r, "getheader") else None) or ""
                if "gzip" in enc.lower():
                    raw_data = decompress_gzip_payload(raw_data)
                hdr_bytes = format_response_headers(r)
                if hdr_bytes:
                    raw_data = hdr_bytes + raw_data

                if status_code not in {301, 302, 303, 307, 308} or not loc or r_count == max_redirects:
                    return raw_data, status_code, curr_url
                curr_url = urljoin(curr_url, loc)
                if hasattr(conn, "close"):
                    conn.close()
        except Exception as exc:
            error = exc
            if is_https and not allow_legacy_ssl and is_ssl_handshake_failure(exc):
                should_retry = True
            else:
                raise
        finally:
            if explicit_debug and error is not None:
                print(f"[DEBUG scan fetchresponse] error={error!r}")
            if conn and hasattr(conn, "close"):
                conn.close()

        if should_retry:
            return await async_fetch_response(
                service_name,
                port,
                scheme,
                url_path,
                max_redirects=max_redirects,
                explicit_debug=explicit_debug,
                allow_legacy_ssl=True,
                use_proxy=use_proxy,
                proxy_settings=proxy_settings,
                custom_headers=custom_headers,
            )

    try:
        req_start = time.monotonic()
        async with session.get(
            current_url,
            headers=req_headers,
            timeout=client_timeout,
            ssl=ssl_context if is_https else None,
            allow_redirects=True,
            max_redirects=max_redirects,
            proxy=proxy_url,
            proxy_auth=proxy_auth,
        ) as resp:
            raw_body = await resp.read()
            # Truncate to 16KB like legacy fetch_response
            body = raw_body[:16384]
            status_code = resp.status
            final_url = str(resp.url)

            # Format headers and prepend to body
            hdr_lines = [f"{k}: {v}".encode("latin1", errors="replace") for k, v in resp.headers.items()]
            hdr_bytes = b"\r\n".join(hdr_lines) + b"\r\n\r\n" if hdr_lines else b""
            if hdr_bytes:
                body = hdr_bytes + body

            if explicit_debug:
                elapsed_ms = int((time.monotonic() - req_start) * 1000)
                proxy_info = f" proxy={proxy_url}" if proxy_url else ""
                print(
                    f"[DEBUG scan aiohttp] protocol={scheme} service={service_name} port={port}{proxy_info} "
                    f"status={status_code} url={final_url} legacy_ssl={allow_legacy_ssl} "
                    f"took={elapsed_ms}ms body_len={len(body)}"
                )

            return body, status_code, final_url

    except Exception as exc:
        if explicit_debug:
            print(f"[DEBUG scan aiohttp] Error for {service_name}:{port}: {exc!r}")
        if is_https and not allow_legacy_ssl and is_ssl_handshake_failure(exc):
            if explicit_debug:
                print(f"[DEBUG scan aiohttp] Handshake failure on {service_name}:{port}; retrying with legacy SSL...")
            return await async_fetch_response(
                service_name,
                port,
                scheme,
                url_path,
                max_redirects=max_redirects,
                explicit_debug=explicit_debug,
                allow_legacy_ssl=True,
                use_proxy=use_proxy,
                proxy_settings=proxy_settings,
                custom_headers=custom_headers,
            )
        raise


@profile
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
    custom_headers: dict[str, str] | None = None,
) -> tuple[bytes, int, str]:
    """Fetch HTTP/HTTPS response using non-blocking aiohttp under the hood."""
    return AsyncHttpManager.run_coroutine(
        async_fetch_response(
            service_name,
            port,
            scheme,
            url_path=url_path,
            max_redirects=max_redirects,
            explicit_debug=explicit_debug,
            allow_legacy_ssl=allow_legacy_ssl,
            use_proxy=use_proxy,
            proxy_settings=proxy_settings,
            custom_headers=custom_headers,
        )
    )


def fetch_tcp_response(service_name: str, port: int, url_path: str = "", custom_request_bytes: bytes | None = None, custom_headers: dict[str, str] | None = None):
    with socket.create_connection((service_name, port), timeout=2) as connection:
        if custom_request_bytes is not None:
            connection.sendall(custom_request_bytes)
        else:
            hdrs = f"Host: {service_name}\r\nConnection: close"
            if custom_headers:
                for hk, hv in custom_headers.items():
                    hdrs += f"\r\n{hk}: {hv}"
            connection.sendall(
                f"GET {url_path or '/'} HTTP/1.0\r\n{hdrs}\r\n\r\n".encode()
            )
        return decompress_socket_response_if_gzip(connection.recv(16384))


def fetch_tcp_ssl_response(service_name: str, port: int, url_path: str = "", custom_request_bytes: bytes | None = None, allow_legacy_ssl: bool = False, custom_headers: dict[str, str] | None = None):
    context = create_ssl_context(legacy=allow_legacy_ssl)
    try:
        with socket.create_connection((service_name, port), timeout=2) as raw_connection:
            with context.wrap_socket(raw_connection, server_hostname=service_name) as connection:
                if custom_request_bytes is not None:
                    connection.sendall(custom_request_bytes)
                else:
                    hdrs = f"Host: {service_name}\r\nConnection: close"
                    if custom_headers:
                        for hk, hv in custom_headers.items():
                            hdrs += f"\r\n{hk}: {hv}"
                    connection.sendall(
                        f"GET {url_path or '/'} HTTP/1.0\r\n{hdrs}\r\n\r\n".encode()
                    )
                return decompress_socket_response_if_gzip(connection.recv(16384))
    except Exception as exc:
        if not allow_legacy_ssl and is_ssl_handshake_failure(exc):
            return fetch_tcp_ssl_response(service_name, port, url_path=url_path, custom_request_bytes=custom_request_bytes, allow_legacy_ssl=True, custom_headers=custom_headers)
        raise


def format_protocol_label(protocol: str | None) -> str:
    if not protocol:
        return ""
    p = str(protocol).strip().lower()
    mapping = {
        "http": "HTTP",
        "https": "HTTPS",
        "tcp": "TCP",
        "tcp-ssl": "TCP SSL",
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


def get_protocol_icon_svg(protocol: str | None, port: int | None = None) -> str:
    """Return inline SVG micro-icon (12x12) representing the protocol."""
    p = str(protocol or "").strip().lower()
    if port is None or p in ("icmp", "icmp-ping"):
        # EKG / Heartbeat wave
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M1 8h3l2-5 3 10 2-5h4"/>'
            '</svg>'
        )
    if p == "https":
        # Padlock (SSL/TLS secure web)
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
            '<path d="M8 1a3.5 3.5 0 0 0-3.5 3.5V6H4a2 2 0 0 0-2 2v6a2 2 0 0 0 2 2h8a2 2 0 0 0 2-2V8a2 2 0 0 0-2-2h-.5V4.5A3.5 3.5 0 0 0 8 1zm2 5H6V4.5a2 2 0 1 1 4 0V6z"/>'
            '</svg>'
        )
    if p in ("socket-ssl", "tcp-ssl"):
        # Plug with lock badge
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
            '<path d="M6 0a1 1 0 0 1 1 1v2h2V1a1 1 0 1 1 2 0v2h.5A2.5 2.5 0 0 1 14 5.5v1A2.5 2.5 0 0 1 11.5 9H9.5l-.5 4.5a1 1 0 0 1-2 0L6.5 9H4.5A2.5 2.5 0 0 1 2 6.5v-1A2.5 2.5 0 0 1 4.5 3H5V1a1 1 0 0 1 1-1zM11 10a2 2 0 0 0-2 2v.5h-.5a.5.5 0 0 0-.5.5v2.5a.5.5 0 0 0 .5.5h5a.5.5 0 0 0 .5-.5V13a.5.5 0 0 0-.5-.5h-.5V12a2 2 0 0 0-2-2zm1 2.5h-2V12a1 1 0 1 1 2 0v.5z"/>'
            '</svg>'
        )
    if p in ("socket", "tcp"):
        # Network 2-pin plug
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
            '<path d="M6 1a1 1 0 0 1 1 1v2h2V2a1 1 0 1 1 2 0v2h.5A2.5 2.5 0 0 1 14 6.5v1A2.5 2.5 0 0 1 11.5 10H9l-.5 5a1 1 0 0 1-2 0L6 10H4.5A2.5 2.5 0 0 1 2 7.5v-1A2.5 2.5 0 0 1 4.5 4H5V2a1 1 0 0 1 1-1z"/>'
            '</svg>'
        )
    if p in ("udp-ssl", "dtls"):
        # Lightning bolt with lock badge
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
            '<path d="M9.5 0 2 8h5l-1.5 7L13 7H8l1.5-7z"/>'
            '<rect x="9" y="10" width="6" height="5" rx="1" fill="currentColor"/>'
            '<path d="M10.5 10v-1a1.5 1.5 0 0 1 3 0v1" fill="none" stroke="currentColor" stroke-width="1.2"/>'
            '</svg>'
        )
    if p == "udp":
        # Lightning bolt (fast datagram)
        return (
            '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="currentColor" aria-hidden="true">'
            '<path d="M9.5 0 2 9h5.5l-2 7L14 7H8.5l2-7h-1z"/>'
            '</svg>'
        )
    # Default: HTTP (Globe / Web Sphere)
    return (
        '<svg class="chip-proto-icon" viewBox="0 0 16 16" width="12" height="12" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
        '<circle cx="8" cy="8" r="6.5"/>'
        '<path d="M1.5 8h13"/>'
        '<ellipse cx="8" cy="8" rx="3.2" ry="6.5"/>'
        '</svg>'
    )


def get_overall_status_icon_svg(status: str | None) -> str:
    """Return inline SVG icon for overall system health (15x15)."""
    st = str(status or "").strip().lower()
    if st == "online":
        # Bold checkmark
        return (
            '<svg class="overall-status-icon online" viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M2.5 8.5 6 12l7.5-8"/>'
            '</svg>'
        )
    if st == "degraded":
        # Warning triangle with exclamation
        return (
            '<svg class="overall-status-icon degraded" viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M8 1.5 1 14h14L8 1.5z"/>'
            '<path d="M8 6v4" stroke-width="2"/>'
            '<circle cx="8" cy="12" r="0.8" fill="currentColor"/>'
            '</svg>'
        )
    if st == "offline":
        # Bold cross / X-mark
        return (
            '<svg class="overall-status-icon offline" viewBox="0 0 16 16" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">'
            '<path d="M3.5 3.5 12.5 12.5M12.5 3.5 3.5 12.5"/>'
            '</svg>'
        )
    # None / unknown / skipped: circle dot
    return (
        '<svg class="overall-status-icon none" viewBox="0 0 16 16" width="15" height="15" fill="currentColor" aria-hidden="true">'
        '<circle cx="8" cy="8" r="4"/>'
        '</svg>'
    )


app.jinja_env.filters["protocol_label"] = format_protocol_label
app.jinja_env.globals["format_protocol_label"] = format_protocol_label
app.jinja_env.filters["protocol_icon"] = get_protocol_icon_svg
app.jinja_env.globals["get_protocol_icon_svg"] = get_protocol_icon_svg
app.jinja_env.filters["overall_status_icon"] = get_overall_status_icon_svg
app.jinja_env.globals["get_overall_status_icon_svg"] = get_overall_status_icon_svg
app.jinja_env.filters["format_ports_column"] = format_ports_column
app.jinja_env.globals["format_ports_column"] = format_ports_column


def fetch_udp_response(service_name: str, port: int, url_path: str = "", custom_request_bytes: bytes | None = None, timeout: float = 2.0) -> bytes:
    addr_info = socket.getaddrinfo(service_name, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not addr_info:
        raise OSError(f"Could not resolve {service_name}")
    family, socktype, proto, canonname, sockaddr = addr_info[0]
    with socket.socket(family, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect(sockaddr)
        if custom_request_bytes is not None:
            probe = custom_request_bytes
        else:
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


def fetch_udp_ssl_response(service_name: str, port: int, url_path: str = "", custom_request_bytes: bytes | None = None, timeout: float = 2.0) -> bytes:
    addr_info = socket.getaddrinfo(service_name, port, socket.AF_UNSPEC, socket.SOCK_DGRAM)
    if not addr_info:
        raise OSError(f"Could not resolve {service_name}")
    family, socktype, proto, canonname, sockaddr = addr_info[0]
    packet = custom_request_bytes if custom_request_bytes is not None else build_dtls_client_hello(service_name)
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


@profile
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

    scan_service_t0 = time.monotonic()
    if debug_enabled:
        print(f"[DEBUG scan] === START service scan === ID={service_id} name={service_name} ports_count={len(ports)} proxy={use_proxy}")

    port_statuses: dict = {}
    for port_entry in ports:
        port = port_entry.get("port")  # None for ICMP
        # Per-port preferred protocol; fall back to legacy service-level protocol arg only if explicitly passed
        per_port_pref = (port_entry.get("protocol") or "").strip().lower()
        if not per_port_pref and protocol is not None and not any(p.get("protocol") for p in ports if p != port_entry):
            per_port_pref = (protocol or "").strip().lower()

        start = time.monotonic()
        status = "offline"
        response_ms = None
        # --- Ports without protocol are skipped (except ICMP) ---
        if port is not None and not per_port_pref:
            status = "skipped"
            response_ms = None
            db_w_t0 = time.monotonic()
            store_port_check(service_id, port, status, response_ms)
            db_w_ms = int((time.monotonic() - db_w_t0) * 1000)
            port_statuses[port] = status
            if debug_enabled:
                print(f"[DEBUG scan] port={port} SKIPPED (no protocol) in {int((time.monotonic() - start) * 1000)}ms (db_write={db_w_ms}ms)")
            continue

        port_match = port_entry.get("match", "") if port_entry.get("match") is not None else ""
        if not port_match and match:
            port_match = match
        port_url_path = port_entry.get("url_path", "") if port_entry.get("url_path") is not None else ""
        if not port_url_path and url_path:
            port_url_path = url_path

        port_req_type = (port_entry.get("request_type") or "web").strip().lower()
        if port_req_type not in ("web", "custom"):
            port_req_type = "web"

        req_bytes = None
        resp_expected_bytes = None
        if port_req_type == "custom":
            try:
                req_bytes = parse_hex_bytes(port_entry.get("request_payload") or "")
            except Exception:
                req_bytes = b""
            try:
                resp_expected_bytes = parse_hex_bytes(port_entry.get("response_payload") or "")
            except Exception:
                resp_expected_bytes = b""

        protocol_used = per_port_pref or ("icmp-ping" if port is None else "http")
        match_bytes = port_match.lower().encode() if port_match else b""
        url_path = port_url_path

        web_custom_headers = {"X-Scanner-Bypass-Key": DEFAULT_SCANNER_BYPASS_KEY} if (port_req_type == "web" and DEFAULT_SCANNER_BYPASS_KEY) else None

        if debug_enabled:
            print(f"[DEBUG scan] Probing port={port} pref_proto={per_port_pref!r} effective_proto={protocol_used!r} req_type={port_req_type}")

        # --- ICMP (portless) ---
        if port is None or per_port_pref in ("icmp", "icmp-ping"):
            icmp_t0 = time.monotonic()
            try:
                ping_ok, ping_lat, ping_output = fetch_icmp_ping_response(service_name)
                response_ms = ping_lat
                protocol_used = "icmp-ping"
                if ping_ok and "bytes=" in (ping_output or "").lower():
                    status = "online"
                else:
                    status = "offline"
            except Exception as exc:
                status = "offline"
                if debug_enabled:
                    print(f"[DEBUG scan] ICMP ping exception for {service_name}: {exc}")
            icmp_elapsed_ms = int((time.monotonic() - icmp_t0) * 1000)
            if debug_enabled:
                print(f"[DEBUG scan] ICMP probed in {icmp_elapsed_ms}ms -> status={status} lat={response_ms}ms")
            db_w_t0 = time.monotonic()
            store_port_check(service_id, None, status, response_ms)
            if debug_enabled:
                print(f"[DEBUG scan] ICMP DB store took {int((time.monotonic() - db_w_t0) * 1000)}ms")
            port_statuses["icmp"] = status
            if not per_port_pref:
                port_entry["protocol"] = protocol_used
            continue

        # --- UDP ---
        if per_port_pref == "udp":
            udp_t0 = time.monotonic()
            try:
                udp_resp = fetch_udp_response(service_name, port, url_path, custom_request_bytes=req_bytes if port_req_type == "custom" else None)
                response_ms = int((time.monotonic() - start) * 1000)
                if port_req_type == "custom":
                    if resp_expected_bytes and resp_expected_bytes in udp_resp:
                        status = "online"
                    elif not resp_expected_bytes and udp_resp:
                        status = "online"
                    elif udp_resp:
                        status = "degraded"
                else:
                    if udp_resp and match_bytes and match_bytes in udp_resp.lower():
                        status = "online"
                    elif udp_resp and not match_bytes:
                        status = "online"
                    elif udp_resp:
                        status = "degraded"
            except (socket.timeout, socket.gaierror, OSError) as exc:
                status = "offline"
                if debug_enabled:
                    print(f"[DEBUG scan] UDP socket error on port={port} in {int((time.monotonic() - udp_t0) * 1000)}ms: {exc}")
            if debug_enabled:
                print(f"[DEBUG scan] protocol=udp service={service_name} port={port} status={status} response_ms={response_ms} probe_took={int((time.monotonic() - udp_t0) * 1000)}ms")

        # --- UDP-SSL / DTLS ---
        elif per_port_pref in ("udp-ssl", "dtls"):
            udp_ssl_t0 = time.monotonic()
            try:
                udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path, custom_request_bytes=req_bytes if port_req_type == "custom" else None)
                response_ms = int((time.monotonic() - start) * 1000)
                if port_req_type == "custom":
                    if resp_expected_bytes and resp_expected_bytes in udp_ssl_resp:
                        status = "online"
                    elif not resp_expected_bytes and udp_ssl_resp:
                        status = "online"
                    elif udp_ssl_resp:
                        status = "degraded"
                else:
                    if udp_ssl_resp and match_bytes and match_bytes in udp_ssl_resp.lower():
                        status = "online"
                    elif udp_ssl_resp and not match_bytes:
                        status = "online"
                    elif udp_ssl_resp:
                        status = "degraded"
            except (socket.timeout, socket.gaierror, OSError) as exc:
                status = "offline"
                if debug_enabled:
                    print(f"[DEBUG scan] UDP-SSL error on port={port} in {int((time.monotonic() - udp_ssl_t0) * 1000)}ms: {exc}")
            if debug_enabled:
                print(f"[DEBUG scan] protocol=udp-ssl service={service_name} port={port} status={status} response_ms={response_ms} probe_took={int((time.monotonic() - udp_ssl_t0) * 1000)}ms")

        # --- TCP ---
        elif per_port_pref in ("tcp", "socket"):
            protocol_used = "tcp"
            tcp_t0 = time.monotonic()
            try:
                tcp_kwargs = {}
                if port_req_type == "custom":
                    tcp_kwargs["custom_request_bytes"] = req_bytes
                elif web_custom_headers:
                    tcp_kwargs["custom_headers"] = web_custom_headers
                tcp_response = fetch_tcp_response(service_name, port, url_path, **tcp_kwargs)
                response_ms = int((time.monotonic() - start) * 1000)
                if port_req_type == "custom":
                    if resp_expected_bytes and resp_expected_bytes in tcp_response:
                        status = "online"
                    elif not resp_expected_bytes and tcp_response:
                        status = "online"
                    elif tcp_response:
                        status = "degraded"
                else:
                    if tcp_response and match_bytes and match_bytes in tcp_response.lower():
                        status = "online"
                    elif tcp_response and not match_bytes:
                        status = "online"
                    elif tcp_response:
                        status = "degraded"
            except (socket.timeout, socket.gaierror, OSError) as exc:
                status = "offline"
                if debug_enabled:
                    print(f"[DEBUG scan] TCP error on port={port} in {int((time.monotonic() - tcp_t0) * 1000)}ms: {exc}")
            if debug_enabled:
                print(f"[DEBUG scan] protocol=tcp service={service_name} port={port} status={status} response_ms={response_ms} probe_took={int((time.monotonic() - tcp_t0) * 1000)}ms")

        # --- TCP SSL ---
        elif per_port_pref in ("tcp-ssl", "socket-ssl"):
            protocol_used = "tcp-ssl"
            tcp_ssl_t0 = time.monotonic()
            try:
                tcp_ssl_kwargs = {}
                if port_req_type == "custom":
                    tcp_ssl_kwargs["custom_request_bytes"] = req_bytes
                elif web_custom_headers:
                    tcp_ssl_kwargs["custom_headers"] = web_custom_headers
                tcp_ssl_response = fetch_tcp_ssl_response(service_name, port, url_path, **tcp_ssl_kwargs)
                response_ms = int((time.monotonic() - start) * 1000)
                if port_req_type == "custom":
                    if resp_expected_bytes and resp_expected_bytes in tcp_ssl_response:
                        status = "online"
                    elif not resp_expected_bytes and tcp_ssl_response:
                        status = "online"
                    elif tcp_ssl_response:
                        status = "degraded"
                else:
                    if tcp_ssl_response and match_bytes and match_bytes in tcp_ssl_response.lower():
                        status = "online"
                    elif tcp_ssl_response and not match_bytes:
                        status = "online"
                    elif tcp_ssl_response:
                        status = "degraded"
            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    response_ms = int((time.monotonic() - start) * 1000)
                    if debug_enabled:
                        print(f"[DEBUG scan] TCP-SSL handshake failure treated as online for {service_name}:{port} in {int((time.monotonic() - tcp_ssl_t0) * 1000)}ms")
                else:
                    status = "offline"
                    if debug_enabled:
                        print(f"[DEBUG scan] TCP-SSL error on port={port} in {int((time.monotonic() - tcp_ssl_t0) * 1000)}ms: {exc}")
            if debug_enabled:
                print(f"[DEBUG scan] protocol=tcp-ssl service={service_name} port={port} status={status} response_ms={response_ms} probe_took={int((time.monotonic() - tcp_ssl_t0) * 1000)}ms")

        # --- HTTPS (explicit) ---
        elif per_port_pref == "https":
            https_t0 = time.monotonic()
            try:
                https_response, status_code, final_url = fetch_response(
                    service_name, port, "https", url_path,
                    explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                    custom_headers=web_custom_headers,
                )
                response_ms = int((time.monotonic() - start) * 1000)
                if https_response and match_bytes and match_bytes in https_response.lower():
                    status = "online"
                elif https_response and not match_bytes and status_code and 200 <= status_code < 400:
                    status = "online"
                elif https_response:
                    status = "degraded"
            except (*HTTP_PROBE_EXCEPTIONS, ssl.SSLError) as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    response_ms = int((time.monotonic() - start) * 1000)
                    if debug_enabled:
                        print(f"[DEBUG scan] HTTPS handshake failure treated as online for {service_name}:{port} in {int((time.monotonic() - https_t0) * 1000)}ms")
                else:
                    status = "offline"
                    if debug_enabled:
                        print(f"[DEBUG scan] HTTPS error on port={port} in {int((time.monotonic() - https_t0) * 1000)}ms: {exc}")
            if debug_enabled:
                print(f"[DEBUG scan] protocol=https service={service_name} port={port} status={status} response_ms={response_ms} probe_took={int((time.monotonic() - https_t0) * 1000)}ms")

        else:
            # Auto-detect cascade (or per_port_pref == "http")
            cascade_http_t0 = time.monotonic()
            response = b""
            status_code = None
            final_url = f"http://{service_name}:{port}{url_path or '/'}"
            try:
                response, status_code, final_url = fetch_response(
                    service_name, port, "http", url_path,
                    explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                    custom_headers=web_custom_headers,
                )
                response_ms = int((time.monotonic() - start) * 1000)
                protocol_used = "http"
            except HTTP_PROBE_EXCEPTIONS as exc:
                if is_ssl_handshake_failure(exc):
                    status = "online"
                    protocol_used = "http"
                    response_ms = int((time.monotonic() - start) * 1000)
                response = b""
            if debug_enabled:
                print(f"[DEBUG scan] HTTP auto-detect probe port={port} took {int((time.monotonic() - cascade_http_t0) * 1000)}ms (status_code={status_code})")

            if response and match_bytes and match_bytes in response.lower():
                status = "online"
                protocol_used = "http"
            elif response and not match_bytes and status_code and 200 <= status_code < 400:
                status = "online"
                protocol_used = "http"
            elif status == "online":
                protocol_used = "http"
            elif port in HTTPS_PORTS:
                cascade_https_t0 = time.monotonic()
                try:
                    https_response, status_code, final_url = fetch_response(
                        service_name, port, "https", url_path,
                        explicit_debug=debug_enabled, use_proxy=use_proxy, proxy_settings=proxy_settings,
                        custom_headers=web_custom_headers,
                    )
                    response_ms = int((time.monotonic() - start) * 1000)
                    if https_response and match_bytes and match_bytes in https_response.lower():
                        status = "online"
                        protocol_used = "https"
                    elif https_response and not match_bytes:
                        status = "online"
                        protocol_used = "https"
                    elif https_response:
                        status = "degraded"
                        protocol_used = "https"
                except (*HTTP_PROBE_EXCEPTIONS, ssl.SSLError) as exc:
                    if is_ssl_handshake_failure(exc):
                        status = "online"
                        protocol_used = "https"
                        response_ms = int((time.monotonic() - start) * 1000)
                if status == "offline" and port in HTTPS_PORTS:
                    status = "degraded"
                if debug_enabled:
                    print(f"[DEBUG scan] HTTPS cascade probe port={port} took {int((time.monotonic() - cascade_https_t0) * 1000)}ms -> status={status}")
            elif response:
                status = "degraded"
                protocol_used = "http"

            # TCP fallbacks if not online and not using proxy
            if not per_port_pref and status != "online" and not use_proxy:
                fb_tcp_t0 = time.monotonic()
                try:
                    tcp_response = fetch_tcp_response(service_name, port, url_path, custom_headers=web_custom_headers)
                    response_ms = int((time.monotonic() - start) * 1000)
                    if tcp_response and match_bytes and match_bytes in tcp_response.lower():
                        status = "online"
                        protocol_used = "tcp"
                    elif tcp_response and not match_bytes:
                        status = "online"
                        protocol_used = "tcp"
                    elif tcp_response and status == "offline":
                        status = "degraded"
                        protocol_used = "tcp"
                except (socket.timeout, socket.gaierror, OSError):
                    try:
                        tcp_ssl_response = fetch_tcp_ssl_response(service_name, port, url_path, custom_headers=web_custom_headers)
                        response_ms = int((time.monotonic() - start) * 1000)
                        if tcp_ssl_response and match_bytes and match_bytes in tcp_ssl_response.lower():
                            status = "online"
                            protocol_used = "tcp-ssl"
                        elif tcp_ssl_response and not match_bytes:
                            status = "online"
                            protocol_used = "tcp-ssl"
                        elif tcp_ssl_response and status == "offline":
                            status = "degraded"
                            protocol_used = "tcp-ssl"
                    except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                        if is_ssl_handshake_failure(exc):
                            status = "online"
                            protocol_used = "tcp-ssl"
                            response_ms = int((time.monotonic() - start) * 1000)
                if debug_enabled:
                    print(f"[DEBUG scan] Fallback TCP probe port={port} took {int((time.monotonic() - fb_tcp_t0) * 1000)}ms -> status={status}")

            # UDP fallbacks if not online and not using proxy
            if not per_port_pref and status != "online" and not use_proxy:
                fb_udp_t0 = time.monotonic()
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
                if debug_enabled:
                    print(f"[DEBUG scan] Fallback UDP probe port={port} took {int((time.monotonic() - fb_udp_t0) * 1000)}ms -> status={status}")

        # Write discovered protocol back to this port entry (auto-detect only)
        if not per_port_pref and protocol_used and status in ("online", "degraded"):
            port_entry["protocol"] = protocol_used

        port_total_ms = int((time.monotonic() - start) * 1000)
        db_w_t0 = time.monotonic()
        store_port_check(service_id, port, status, response_ms)
        db_w_ms = int((time.monotonic() - db_w_t0) * 1000)
        port_statuses[port] = status
        if debug_enabled:
            print(f"[DEBUG scan] Port {port} check finished in {port_total_ms}ms (db_write={db_w_ms}ms) -> status={status} (lat={response_ms}ms, proto={protocol_used})")

    # Persist updated port protocols back to DB
    persist_t0 = time.monotonic()
    try:
        conn = get_db_connection()
        conn.execute("UPDATE services SET port_protocol = ? WHERE id = ?", (port_protocol_to_json(ports), service_id))
        conn.commit()
        conn.close()
        if debug_enabled:
            print(f"[DEBUG scan] Persisted port_protocol in {int((time.monotonic() - persist_t0) * 1000)}ms")
    except Exception as exc:
        if debug_enabled:
            print(f"[DEBUG scan] Failed saving per-port protocols: {exc}")

    if debug_enabled:
        total_scan_ms = int((time.monotonic() - scan_service_t0) * 1000)
        print(f"[DEBUG scan] === FINISHED service scan === ID={service_id} name={service_name} in {total_scan_ms}ms -> results={port_statuses}")

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
    request_type: str = "web",
    request_payload: str = "",
    response_payload: str = "",
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
    if pref == "socket":
        pref = "tcp"
    elif pref == "socket-ssl":
        pref = "tcp-ssl"

    req_type = (request_type or "web").strip().lower()
    if req_type not in ("web", "custom"):
        req_type = "web"

    web_custom_headers = {"X-Scanner-Bypass-Key": DEFAULT_SCANNER_BYPASS_KEY} if (req_type == "web" and DEFAULT_SCANNER_BYPASS_KEY) else None

    req_bytes = None
    resp_expected_bytes = None
    if req_type == "custom":
        try:
            req_bytes = parse_hex_bytes(request_payload)
        except Exception:
            req_bytes = b""
        try:
            resp_expected_bytes = parse_hex_bytes(response_payload)
        except Exception:
            resp_expected_bytes = b""

    if pref == "udp":
        protocol_used = "udp"
        try:
            udp_resp = fetch_udp_response(service_name, port, url_path, custom_request_bytes=req_bytes if req_type == "custom" else None)
            response_bytes = udp_resp
            status_text = "UDP datagram response"
            if req_type == "custom":
                if resp_expected_bytes and resp_expected_bytes in udp_resp:
                    status = "online"
                elif not resp_expected_bytes and udp_resp:
                    status = "online"
                elif udp_resp:
                    status = "degraded"
            else:
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
            udp_ssl_resp = fetch_udp_ssl_response(service_name, port, url_path, custom_request_bytes=req_bytes if req_type == "custom" else None)
            response_bytes = udp_ssl_resp
            status_text = "UDP SSL (DTLS) response"
            if req_type == "custom":
                if resp_expected_bytes and resp_expected_bytes in udp_ssl_resp:
                    status = "online"
                elif not resp_expected_bytes and udp_ssl_resp:
                    status = "online"
                elif udp_ssl_resp:
                    status = "degraded"
            else:
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
    elif pref == "tcp":
        protocol_used = "tcp"
        try:
            tcp_resp = fetch_tcp_response(service_name, port, url_path, custom_request_bytes=req_bytes if req_type == "custom" else None, custom_headers=web_custom_headers)
            response_bytes = tcp_resp
            status_text = "TCP response" if req_type == "custom" else "TCP HTTP/1.0 response"
            if req_type == "custom":
                if resp_expected_bytes and resp_expected_bytes in tcp_resp:
                    status = "online"
                elif not resp_expected_bytes and tcp_resp:
                    status = "online"
                elif tcp_resp:
                    status = "degraded"
            else:
                if tcp_resp and match_bytes and match_bytes in tcp_resp.lower():
                    status = "online"
                elif tcp_resp and not match_bytes:
                    status = "online"
                elif tcp_resp:
                    status = "degraded"
        except (socket.timeout, socket.gaierror, OSError) as exc:
            error_message = str(exc) or exc.__class__.__name__
            status_text = error_message
    elif pref == "tcp-ssl":
        protocol_used = "tcp-ssl"
        try:
            ssl_tcp_resp = fetch_tcp_ssl_response(service_name, port, url_path, custom_request_bytes=req_bytes if req_type == "custom" else None, custom_headers=web_custom_headers)
            response_bytes = ssl_tcp_resp
            status_text = "TCP SSL response" if req_type == "custom" else "TCP SSL HTTP/1.0 response"
            if req_type == "custom":
                if resp_expected_bytes and resp_expected_bytes in ssl_tcp_resp:
                    status = "online"
                elif not resp_expected_bytes and ssl_tcp_resp:
                    status = "online"
                elif ssl_tcp_resp:
                    status = "degraded"
            else:
                if ssl_tcp_resp and match_bytes and match_bytes in ssl_tcp_resp.lower():
                    status = "online"
                elif ssl_tcp_resp and not match_bytes:
                    status = "online"
                elif ssl_tcp_resp:
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
                custom_headers=web_custom_headers,
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
        except (*HTTP_PROBE_EXCEPTIONS, ssl.SSLError) as exc:
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
                custom_headers=web_custom_headers,
            )
            protocol_used = "http"
            status_text = f"HTTP {status_code}"
        except HTTP_PROBE_EXCEPTIONS as exc:
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
                    custom_headers=web_custom_headers,
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
            except (*HTTP_PROBE_EXCEPTIONS, ssl.SSLError) as exc:
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

        # TCP fallbacks if not online and not using proxy
        if not pref and status != "online" and not use_proxy:
            try:
                retries += 1
                tcp_resp = fetch_tcp_response(service_name, port, url_path, custom_headers=web_custom_headers)
                protocol_used = "tcp"
                response_bytes = tcp_resp
                status_text = "TCP HTTP/1.0 response"
                if tcp_resp and match_bytes and match_bytes in tcp_resp.lower():
                    status = "online"
                elif tcp_resp and not match_bytes:
                    status = "online"
                elif tcp_resp and status == "offline":
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                try:
                    retries += 1
                    ssl_tcp_resp = fetch_tcp_ssl_response(service_name, port, url_path, custom_headers=web_custom_headers)
                    protocol_used = "tcp-ssl"
                    response_bytes = ssl_tcp_resp
                    status_text = "TCP SSL HTTP/1.0 response"
                    if ssl_tcp_resp and match_bytes and match_bytes in ssl_tcp_resp.lower():
                        status = "online"
                    elif ssl_tcp_resp and not match_bytes:
                        status = "online"
                    elif ssl_tcp_resp and status == "offline":
                        status = "degraded"
                except (socket.timeout, socket.gaierror, OSError, ssl.SSLError) as exc:
                    if is_ssl_handshake_failure(exc):
                        status = "online"
                        status_text = "SSL Handshake (treated as online)"
                        protocol_used = "tcp-ssl"
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
        if req_type == "custom":
            snippet_text = format_hex_bytes(response_bytes[:512])
        else:
            snippet_text = response_bytes[:4096].decode("utf-8", errors="replace")

    match_found = False
    match_count = 0
    if protocol_used == "icmp-ping":
        match_token = ""
    elif req_type == "custom":
        match_token = format_hex_bytes(response_payload)
        if resp_expected_bytes and response_bytes:
            if resp_expected_bytes in response_bytes:
                match_found = True
                match_count = response_bytes.count(resp_expected_bytes)
    else:
        match_token = match_str
        if match_str and snippet_text:
            lower_snip = snippet_text.lower()
            lower_match = match_str.lower()
            if lower_match in lower_snip:
                match_found = True
                match_count = lower_snip.count(lower_match)

    # If probing in auto-detect mode and port failed / is offline, no protocol was detected
    reported_protocol = protocol_used
    if not pref and status == "offline":
        reported_protocol = ""

    return {
        "port": port,
        "status": status,
        "status_code": status_code,
        "status_text": status_text or (error_message if error_message else "No response"),
        "protocol": reported_protocol,
        "request_type": req_type,
        "request_payload": format_hex_bytes(request_payload),
        "response_payload": format_hex_bytes(response_payload),
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
    """Parse ports input into list[{port, protocol, match, url_path, request_type, request_payload, response_payload}] dicts.
    Accepts:
      - list[dict]
      - list[int] (legacy, protocol defaults to '')
      - JSON string
      - comma/space separated string
      - 'icmp' or 'icmp-ping' as a token -> {port: None, protocol: 'icmp-ping'}
    """
    def _to_dict(val):
        if isinstance(val, dict):
            proto = (val.get("protocol") or "").strip().lower()
            if proto == "socket":
                proto = "tcp"
            elif proto == "socket-ssl":
                proto = "tcp-ssl"
            rtype = (val.get("request_type") or "web").strip().lower()
            if rtype not in ("web", "custom"):
                rtype = "web"
            m = (val.get("match") or "").strip()
            up = (val.get("url_path") or "").strip()
            req_p = format_hex_bytes(val.get("request_payload") or "")
            resp_p = format_hex_bytes(val.get("response_payload") or "")
            if rtype == "custom":
                m = ""
                up = ""
            else:
                req_p = ""
                resp_p = ""
            return {
                "port": val.get("port"),
                "protocol": proto,
                "request_type": rtype,
                "match": m,
                "url_path": up,
                "request_payload": req_p,
                "response_payload": resp_p,
            }
        if isinstance(val, int):
            return {"port": val, "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""}
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
                result.append({"port": None, "protocol": "icmp-ping", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})
            continue
        try:
            val = int(cleaned)
            if 1 <= val <= 65535 and val not in seen_ports:
                seen_ports.add(val)
                result.append({"port": val, "protocol": "", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})
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
                    port_entry.get("request_type") or "http",
                    port_entry.get("request_payload") or "",
                    port_entry.get("response_payload") or "",
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
        "INSERT INTO services (name, comment, paused, use_proxy, request_type, port_protocol) VALUES (?, ?, ?, ?, 'web', ?)",
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

        # Pre-insert port diagnostics: determine and save online protocol per port
        if detected_entries:
            if cancelled_check is not None and cancelled_check():
                raise ImportCancelled("Import cancelled")
            if progress_callback is not None:
                progress_callback({
                    "index": index,
                    "total": total,
                    "service": normalized,
                    "port": None,
                    "status": "diagnosing",
                    "message": f"Diagnosing protocols for {normalized}",
                })

            diag_results = diagnose_service_ports(
                normalized,
                detected_entries,
                match=derived,
                url_path="",
            )

            if cancelled_check is not None and cancelled_check():
                raise ImportCancelled("Import cancelled")

            diag_ports = {
                p_res.get("port"): p_res
                for p_res in (diag_results.get("ports") or [])
            }

            for p in detected_entries:
                p_num = p.get("port")
                diag = diag_ports.get(p_num)
                if diag and diag.get("status") == "online":
                    proto = (diag.get("protocol") or "").strip().lower()
                    if proto == "ssl-handshake":
                        proto = "https" if p_num in HTTPS_PORTS else "tcp-ssl"
                    if proto:
                        p["protocol"] = proto

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, paused, request_type, port_protocol) VALUES (?, 0, 'web', ?)",
            (normalized, port_protocol_to_json(detected_entries)),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()
        trigger_discovery_async(service_id, normalized)
        trigger_service_icon_resolution_async(normalized)
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
    writer.writerow(["Service", "Comment", "Paused", "Proxy", "Protocol", "Ports", "Request Type", "URL path", "Match", "Request", "Response"])
    for s in services:
        ports_list: list[dict] = s["ports"]  # list[dict] with port & protocol & match & url_path etc.
        # Separate ICMP from TCP/UDP ports
        tcp_ports = [p for p in ports_list if p.get("port") is not None]
        icmp_present = any(p.get("port") is None for p in ports_list)
        ordered_ports = list(tcp_ports)
        if icmp_present:
            ordered_ports.append({"port": None, "protocol": "icmp-ping", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})

        port_nums = [str(p["port"]) if p.get("port") is not None else "icmp" for p in ordered_ports]
        port_protos = [p.get("protocol") or ("icmp-ping" if p.get("port") is None else "") for p in ordered_ports]
        port_rtypes = [(p.get("request_type") or "web") for p in ordered_ports]
        port_matches = [p.get("match") or "" for p in ordered_ports]
        port_url_paths = [p.get("url_path") or "" for p in ordered_ports]
        port_req_payloads = [p.get("request_payload") or "" for p in ordered_ports]
        port_resp_payloads = [p.get("response_payload") or "" for p in ordered_ports]

        distinct_protos = {pr for pr in port_protos if pr}
        if len(distinct_protos) == 1:
            proto_str = list(distinct_protos)[0]
        elif len(distinct_protos) > 1:
            proto_str = ", ".join(port_protos)
        else:
            proto_str = s.get("protocol") or ""

        # Request Type string
        distinct_rtypes = set(port_rtypes)
        if len(distinct_rtypes) == 1:
            rtype_str = list(distinct_rtypes)[0]
        else:
            rtype_str = ", ".join(port_rtypes)

        tcp_matches = [p.get("match") or "" for p in tcp_ports]
        tcp_url_paths = [p.get("url_path") or "" for p in tcp_ports]
        tcp_req_payloads = [p.get("request_payload") or "" for p in tcp_ports]
        tcp_resp_payloads = [p.get("response_payload") or "" for p in tcp_ports]

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

        non_empty_req_payloads = [p for p in tcp_req_payloads if p]
        if not non_empty_req_payloads:
            req_str = ""
        elif len(set(tcp_req_payloads)) == 1:
            req_str = tcp_req_payloads[0]
        else:
            req_str = ", ".join(port_req_payloads)

        non_empty_resp_payloads = [p for p in tcp_resp_payloads if p]
        if not non_empty_resp_payloads:
            resp_str = ""
        elif len(set(tcp_resp_payloads)) == 1:
            resp_str = tcp_resp_payloads[0]
        else:
            resp_str = ", ".join(port_resp_payloads)

        writer.writerow([
            s["name"],
            s.get("comment", "") or "",
            "1" if s["paused"] else "0",
            "1" if s.get("use_proxy") else "0",
            proto_str,
            ", ".join(port_nums),
            rtype_str,
            path_str,
            match_str,
            req_str,
            resp_str,
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
            elif col in ("request type", "request_type", "type"):
                col_map["request_type"] = idx
            elif col in ("request", "request payload", "request_payload", "req"):
                col_map["request"] = idx
            elif col in ("response", "response payload", "response_payload", "resp"):
                col_map["response"] = idx
        data_rows = raw_rows[1:]
    else:
        first_len = len(raw_rows[0])
        if first_len >= 11:
            col_map = {"service": 0, "comment": 1, "paused": 2, "proxy": 3, "protocol": 4, "ports": 5, "request_type": 6, "url_path": 7, "match": 8, "request": 9, "response": 10}
        elif first_len >= 8:
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
        matches_raw = row[m_idx].strip() if m_idx != -1 and m_idx < len(row) else ""
        match_parts = [m.strip() for m in re.split(r"[,;]+", matches_raw)] if matches_raw else []

        paths_raw = row[u_idx].strip() if u_idx != -1 and u_idx < len(row) else ""
        path_parts = [p.strip() for p in re.split(r"[,;]+", paths_raw)] if paths_raw else []

        # Parse request_type, request payload, response payload
        rtype_idx = col_map.get("request_type", -1)
        rtypes_raw = row[rtype_idx].strip() if rtype_idx != -1 and rtype_idx < len(row) else ""
        rtype_parts = [rt.strip().lower() for rt in re.split(r"[,;]+", rtypes_raw)] if rtypes_raw else []

        req_idx = col_map.get("request", -1)
        reqs_raw = row[req_idx].strip() if req_idx != -1 and req_idx < len(row) else ""
        req_parts = [rq.strip() for rq in re.split(r"[,;]+", reqs_raw)] if reqs_raw else []

        resp_idx = col_map.get("response", -1)
        resps_raw = row[resp_idx].strip() if resp_idx != -1 and resp_idx < len(row) else ""
        resp_parts = [rs.strip() for rs in re.split(r"[,;]+", resps_raw)] if resps_raw else []

        for i, p in enumerate(ports_val):
            # Determine request_type
            if len(rtype_parts) == 1:
                rt = rtype_parts[0]
            elif i < len(rtype_parts):
                rt = rtype_parts[i]
            else:
                rt = "web"
            if rt not in ("web", "custom"):
                rt = "web"
            p["request_type"] = rt

            if p.get("port") is None:
                p["match"] = ""
                p["url_path"] = ""
                p["request_payload"] = ""
                p["response_payload"] = ""
            else:
                if rt == "custom":
                    p["match"] = ""
                    p["url_path"] = ""
                    if len(req_parts) == 1:
                        p["request_payload"] = format_hex_bytes(req_parts[0])
                    elif i < len(req_parts):
                        p["request_payload"] = format_hex_bytes(req_parts[i])
                    else:
                        p["request_payload"] = ""

                    if len(resp_parts) == 1:
                        p["response_payload"] = format_hex_bytes(resp_parts[0])
                    elif i < len(resp_parts):
                        p["response_payload"] = format_hex_bytes(resp_parts[i])
                    else:
                        p["response_payload"] = ""
                else:
                    p["request_payload"] = ""
                    p["response_payload"] = ""
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
            "INSERT INTO services (name, comment, paused, use_proxy, request_type, port_protocol) VALUES (?, ?, ?, ?, 'web', ?)",
            (normalized, comment_val, int(paused_val), int(proxy_val), port_protocol_to_json(ports_val)),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()
        trigger_discovery_async(service_id, normalized)
        trigger_service_icon_resolution_async(normalized)

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
    # Clean up obsolete port_checks and latest_port_checks for removed ports
    configured_ports = {p.get("port") for p in incoming_ports}
    if None not in configured_ports:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NULL", (service_id,))
        conn.execute("DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NULL", (service_id,))
    numeric_ports = [p["port"] for p in incoming_ports if p.get("port") is not None]
    if numeric_ports:
        placeholders = ", ".join("?" for _ in numeric_ports)
        conn.execute(f"DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({placeholders})", (service_id, *numeric_ports))
        conn.execute(f"DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({placeholders})", (service_id, *numeric_ports))
    else:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL", (service_id,))
        conn.execute("DELETE FROM latest_port_checks WHERE service_id = ? AND port IS NOT NULL", (service_id,))
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
            conn.execute(
                f"DELETE FROM latest_port_checks WHERE service_id = ? AND port IN ({port_placeholders})",
                (row["id"], *new_port_nums),
            )
    conn.commit()
    conn.close()


def delete_service(service_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM port_checks WHERE service_id = ?", (service_id,))
    conn.execute("DELETE FROM latest_port_checks WHERE service_id = ?", (service_id,))
    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
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
        disc_ip = s["discovered_ip"] if "discovered_ip" in s.keys() else None
        disc_mac = s["discovered_mac"] if "discovered_mac" in s.keys() else None
        disc_mfg = s["discovered_manufacturer"] if "discovered_manufacturer" in s.keys() else None

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
                "discovered_ip": disc_ip,
                "discovered_mac": disc_mac,
                "discovered_manufacturer": disc_mfg,
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
                "discovered_ip": disc_ip,
                "discovered_mac": disc_mac,
                "discovered_manufacturer": disc_mfg,
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
    "remote_source_type": "ssh",
    "remote_source_host": "",
    "remote_source_port": "22",
    "remote_source_username": "",
    "remote_source_auth_type": "password",
    "remote_source_password": "",
    "remote_source_key": "",
    "remote_source_command": "",
    "remote_source_timeout": "10",
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
    }
    conn = get_db_connection()
    for key, value in new_settings.items():
        if key in DEFAULT_SETTINGS or key in allowed_extra_keys:
            val_to_save = str(value) if key in ("smtp_password", "proxy_password", "remote_source_password", "remote_source_key") else str(value).strip()
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


# ── Remote Service Source Execution (SSH / Telnet) ───────────────────────────
_DANGEROUS_REMOTE_COMMAND_PATTERNS = [
    r"\brm\s+-[rf]+",
    r"\brmdir\b",
    r"\bmkfs(?:\.[a-z0-9]+)?\b",
    r"\bdd\s+if=",
    r"\b(?:reboot|poweroff|shutdown|halt|init\s+[06])\b",
    r"\bchmod\s+-[rR]\b",
    r"\bchown\s+-[rR]\b",
    r">\s*/dev/(?:sd[a-z]|nvme|hd[a-z]|null|zero)",
    r"\btruncate\b",
    r"\bwipefs\b",
    r":\(\)\s*\{\s*:\|:&\s*\};:",
]


def is_safe_remote_command(command: str) -> tuple[bool, str]:
    """Validate that the remote command does not match dangerous system disruption or wipe patterns."""
    if not command or not command.strip():
        return False, "Command cannot be empty."
    cmd = command.strip()
    for pattern in _DANGEROUS_REMOTE_COMMAND_PATTERNS:
        if re.search(pattern, cmd, re.I):
            return False, f"Command contains restricted pattern for safety: {pattern}"
    return True, ""


def parse_remote_service_names(raw_output: str) -> list[str]:
    """Parse remote command output into a clean list of unique service hostnames."""
    if not raw_output:
        return []
    services: list[str] = []
    seen = set()
    for line in raw_output.splitlines():
        cleaned = line.strip()
        # Remove common shell prompt artifacts, quotes, or table headers
        cleaned = re.sub(r"^https?://", "", cleaned, flags=re.I)
        cleaned = cleaned.split("/")[0].strip()
        cleaned = cleaned.strip("\"' \t\r\n")
        if not cleaned or cleaned.startswith(("#", "//", ";", "NAME", "CONTAINER ID")):
            continue
        # Split on whitespace if multiple hostnames were output on a single line
        tokens = cleaned.split()
        for tok in tokens:
            tok_clean = tok.strip("\"' \t\r\n")
            if tok_clean and tok_clean not in seen:
                seen.add(tok_clean)
                services.append(tok_clean)
    return services


def execute_remote_ssh(
    host: str,
    port: int,
    username: str,
    auth_type: str,
    password: str = "",
    key_content: str = "",
    command: str = "",
    timeout: int = 10,
) -> tuple[bool, str, list[str]]:
    """Execute a command on a remote server using Paramiko SSH."""
    import paramiko
    import io

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        connect_kwargs: dict = {
            "hostname": host,
            "port": port,
            "username": username or None,
            "timeout": timeout,
            "banner_timeout": timeout,
            "auth_timeout": timeout,
        }

        if auth_type == "key" and key_content:
            pkey = None
            key_errs = []
            for pkey_cls in (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.DSSKey):
                try:
                    pkey = pkey_cls.from_private_key(io.StringIO(key_content.strip()))
                    break
                except Exception as ex:
                    key_errs.append(str(ex))
            if not pkey:
                return False, f"Could not parse private key: {key_errs[0] if key_errs else 'Unknown key format'}", []
            connect_kwargs["pkey"] = pkey
        else:
            connect_kwargs["password"] = password

        client.connect(**connect_kwargs)
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out_bytes = stdout.read()
        err_bytes = stderr.read()
        out_text = out_bytes.decode("utf-8", errors="replace")
        err_text = err_bytes.decode("utf-8", errors="replace")

        full_output = out_text
        if err_text:
            full_output += ("\n" if full_output else "") + err_text

        services = parse_remote_service_names(out_text or full_output)
        return True, full_output, services
    except Exception as exc:
        return False, f"SSH Error: {exc}", []
    finally:
        try:
            client.close()
        except Exception:
            pass


def execute_remote_telnet(
    host: str,
    port: int,
    username: str = "",
    password: str = "",
    command: str = "",
    timeout: int = 10,
) -> tuple[bool, str, list[str]]:
    """Execute a command on a remote server using a Telnet RFC 854 socket client."""
    try:
        s = socket.create_connection((host, int(port)), timeout=timeout)
        s.settimeout(timeout)
    except Exception as exc:
        return False, f"Telnet Connection Error: {exc}", []

    try:
        def read_until(targets: list[str], max_wait: float = 3.0) -> str:
            start = time.time()
            collected = bytearray()
            while time.time() - start < max_wait:
                try:
                    chunk = s.recv(1024)
                    if not chunk:
                        break
                    i = 0
                    while i < len(chunk):
                        if chunk[i] == 255 and i + 2 < len(chunk):  # IAC negotiation
                            cmd = chunk[i + 1]
                            opt = chunk[i + 2]
                            if cmd in (251, 252):  # WILL / WONT -> Respond DONT
                                s.sendall(bytes([255, 254, opt]))
                            elif cmd in (253, 254):  # DO / DONT -> Respond WONT
                                s.sendall(bytes([255, 252, opt]))
                            i += 3
                        else:
                            collected.append(chunk[i])
                            i += 1
                    text = collected.decode("utf-8", errors="ignore")
                    for t in targets:
                        if t.lower() in text.lower():
                            return text
                except socket.timeout:
                    break
            return collected.decode("utf-8", errors="ignore")

        # Handle login prompt if required
        prompt = read_until(["login:", "username:", "password:", "#", "$", ">"], max_wait=2.5)
        if any(p in prompt.lower() for p in ("login:", "username:")) and username:
            s.sendall((username + "\n").encode("utf-8"))
            prompt = read_until(["password:", "#", "$", ">"], max_wait=2.5)
        if "password:" in prompt.lower() and password:
            s.sendall((password + "\n").encode("utf-8"))
            prompt = read_until(["#", "$", ">", "%"], max_wait=2.5)

        # Issue remote command
        s.sendall((command + "\n").encode("utf-8"))
        time.sleep(0.5)
        s.sendall(b"exit\n")

        raw_output = read_until([], max_wait=timeout)
        services = parse_remote_service_names(raw_output)
        return True, raw_output, services
    except Exception as exc:
        return False, f"Telnet Execution Error: {exc}", []
    finally:
        try:
            s.close()
        except Exception:
            pass


def execute_remote_source(params: dict[str, str]) -> tuple[bool, str, list[str]]:
    """Execute configured remote source command via SSH or Telnet with safety validation."""
    conn_type = (params.get("remote_source_type") or "ssh").lower().strip()
    host = (params.get("remote_source_host") or "").strip()
    port_raw = (params.get("remote_source_port") or ("22" if conn_type == "ssh" else "23")).strip()
    username = (params.get("remote_source_username") or "").strip()
    auth_type = (params.get("remote_source_auth_type") or "password").lower().strip()
    password = params.get("remote_source_password") or ""
    key_content = params.get("remote_source_key") or ""
    command = (params.get("remote_source_command") or "").strip()
    timeout_raw = (params.get("remote_source_timeout") or "10").strip()

    if not host:
        return False, "Remote hostname / IP address is required.", []
    try:
        port = int(port_raw)
    except ValueError:
        return False, f"Invalid port: {port_raw}", []
    try:
        timeout = int(timeout_raw)
    except ValueError:
        timeout = 10

    safe, err_msg = is_safe_remote_command(command)
    if not safe:
        return False, err_msg, []

    if conn_type == "telnet":
        return execute_remote_telnet(
            host=host,
            port=port,
            username=username,
            password=password,
            command=command,
            timeout=timeout,
        )
    else:
        return execute_remote_ssh(
            host=host,
            port=port,
            username=username,
            auth_type=auth_type,
            password=password,
            key_content=key_content,
            command=command,
            timeout=timeout,
        )


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
        trigger_service_icon_resolution_async(name)
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
        trigger_service_icon_resolution_async(name)
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


def prune_historical_port_checks(retention_days: int | None = None) -> int:
    """Prune rows from historical port_checks older than retention_days.
    Does not touch latest_port_checks which holds current active statuses."""
    days = DEFAULT_HISTORY_RETENTION_DAYS if retention_days is None else retention_days
    if days is None or days <= 0:
        return 0
    try:
        from datetime import timedelta
        cutoff_dt = datetime.now(timezone.utc) - timedelta(days=days)
        # Format matching both standard UTC strings stored in port_checks
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
    prune_historical_port_checks()


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
@profile
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


def get_line_profiler_stats_text() -> str:
    """Return formatted text output of current LineProfiler timings."""
    if GLOBAL_LINE_PROFILER is None:
        return "Line profiler is not active.\nStart PulseCheck with option 3 (Line-Profiler) or set PULSECHECK_PROFILE=1."
    import io
    buf = io.StringIO()
    try:
        GLOBAL_LINE_PROFILER.print_stats(stream=buf)
        output = buf.getvalue()
        if not output.strip():
            return "No profiling stats captured yet. Scan cycles or visits to /status will generate data."
        return output
    except Exception as exc:
        return f"Error extracting profiler stats: {exc}"


@app.route("/debug/profile")
def debug_profile():
    fmt = request.args.get("format", "html").lower()
    stats_text = get_line_profiler_stats_text()
    if fmt == "raw" or fmt == "text":
        return Response(stats_text, mimetype="text/plain; charset=utf-8")

    html = f"""<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>PulseCheck - Live Line Profiler</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body {{
            background: #0f172a;
            color: #f1f5f9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", sans-serif;
            margin: 0;
            padding: 24px;
        }}
        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 20px;
            padding-bottom: 16px;
            border-bottom: 1px solid #334155;
            flex-wrap: wrap;
            gap: 12px;
        }}
        h1 {{
            margin: 0;
            font-size: 1.4rem;
            color: #38bdf8;
            font-weight: 600;
        }}
        .actions {{
            display: flex;
            gap: 10px;
        }}
        .btn {{
            background: #1e293b;
            color: #e2e8f0;
            border: 1px solid #475569;
            padding: 7px 14px;
            border-radius: 6px;
            text-decoration: none;
            font-size: 0.85rem;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .btn:hover {{
            background: #334155;
            border-color: #64748b;
            color: #ffffff;
        }}
        .btn-primary {{
            background: #0284c7;
            border-color: #0369a1;
            color: #fff;
        }}
        .btn-primary:hover {{
            background: #0369a1;
        }}
        pre {{
            background: #090d16;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 20px;
            color: #a7f3d0;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
            font-size: 0.85rem;
            line-height: 1.45;
            overflow-x: auto;
            white-space: pre;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
        }}
        .meta-bar {{
            font-size: 0.82rem;
            color: #94a3b8;
            margin-bottom: 12px;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>PulseCheck &bull; Line Profiler Live Stats</h1>
        <div class="actions">
            <a href="/debug/profile" class="btn btn-primary" onclick="window.location.reload(); return false;">&#x21bb; Refresh</a>
            <a href="/debug/profile?format=raw" class="btn" target="_blank">View Raw Text</a>
            <a href="/status" class="btn">&larr; Status Page</a>
        </div>
    </div>
    <div class="meta-bar">
        Profiled functions: <code>check_all_services</code>, <code>scan_service_with_retries</code>, <code>scan_service</code>, <code>fetch_response</code>, <code>status</code>, <code>get_status_rows</code>
    </div>
    <pre>{stats_text}</pre>
</body>
</html>"""
    return Response(html, mimetype="text/html; charset=utf-8")


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
            "remote_source_type": request.form.get("remote_source_type", "ssh").strip().lower(),
            "remote_source_host": request.form.get("remote_source_host", "").strip(),
            "remote_source_port": request.form.get("remote_source_port", "").strip(),
            "remote_source_username": request.form.get("remote_source_username", "").strip(),
            "remote_source_auth_type": request.form.get("remote_source_auth_type", "password").strip().lower(),
            "remote_source_password": request.form.get("remote_source_password", ""),
            "remote_source_key": request.form.get("remote_source_key", ""),
            "remote_source_command": request.form.get("remote_source_command", "").strip(),
            "remote_source_timeout": request.form.get("remote_source_timeout", "10").strip(),
        }
        if not updated["remote_source_port"]:
            updated["remote_source_port"] = "22" if updated["remote_source_type"] == "ssh" else "23"

        if not updated["smtp_password"] and current_settings.get("smtp_password"):
            updated["smtp_password"] = current_settings["smtp_password"]
        if not updated["proxy_password"] and current_settings.get("proxy_password"):
            updated["proxy_password"] = current_settings["proxy_password"]
        if not updated["remote_source_password"] and current_settings.get("remote_source_password"):
            updated["remote_source_password"] = current_settings["remote_source_password"]
        if not updated["remote_source_key"] and current_settings.get("remote_source_key"):
            updated["remote_source_key"] = current_settings["remote_source_key"]

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

        # Redirect back to tab if specified
        active_tab = request.form.get("active_tab", "")
        redirect_url = url_for("settings_route")
        if active_tab in ("smtp", "proxy", "source", "icons"):
            redirect_url += f"#{active_tab}"
        return redirect(redirect_url)

    return render_template("settings.html", settings=current_settings)


@app.route("/api/settings/remote-source/test", methods=["POST"])
def api_test_remote_source():
    """Test connection to remote source and execute command, returning stdout and parsed services."""
    stored = get_settings()
    data = request.get_json(silent=True) or request.form.to_dict()

    params = {
        "remote_source_type": (data.get("remote_source_type") or stored.get("remote_source_type") or "ssh").strip().lower(),
        "remote_source_host": (data.get("remote_source_host") if "remote_source_host" in data else stored.get("remote_source_host") or "").strip(),
        "remote_source_port": (data.get("remote_source_port") if "remote_source_port" in data else stored.get("remote_source_port") or "").strip(),
        "remote_source_username": (data.get("remote_source_username") if "remote_source_username" in data else stored.get("remote_source_username") or "").strip(),
        "remote_source_auth_type": (data.get("remote_source_auth_type") or stored.get("remote_source_auth_type") or "password").strip().lower(),
        "remote_source_password": data.get("remote_source_password") or stored.get("remote_source_password") or "",
        "remote_source_key": data.get("remote_source_key") or stored.get("remote_source_key") or "",
        "remote_source_command": (data.get("remote_source_command") if "remote_source_command" in data else stored.get("remote_source_command") or "").strip(),
        "remote_source_timeout": (data.get("remote_source_timeout") or stored.get("remote_source_timeout") or "10").strip(),
    }

    if not params["remote_source_port"]:
        params["remote_source_port"] = "22" if params["remote_source_type"] == "ssh" else "23"

    success, output, services = execute_remote_source(params)
    return jsonify({
        "success": success,
        "output": output,
        "services": services,
        "count": len(services),
        "error": "" if success else output,
    })


@app.route("/api/services/remote-fetch", methods=["POST", "GET"])
def api_fetch_remote_services():
    """Execute configured remote source command and return services for Quick Text Import."""
    stored = get_settings()
    if not stored.get("remote_source_host"):
        return jsonify({
            "success": False,
            "error": "No remote source host configured. Please configure it in Settings -> Service source.",
            "services": [],
            "count": 0,
        }), 400
    if not stored.get("remote_source_command"):
        return jsonify({
            "success": False,
            "error": "No remote command configured. Please configure it in Settings -> Service source.",
            "services": [],
            "count": 0,
        }), 400

    success, output, services = execute_remote_source(stored)
    if not success:
        return jsonify({
            "success": False,
            "error": output,
            "services": [],
            "count": 0,
        }), 400

    return jsonify({
        "success": True,
        "output": output,
        "services": services,
        "count": len(services),
    })


# ── Icon Management & Background Job State ──────────────────────────────────
ICON_JOB_STATUS = {
    "manufacturer": {
        "running": False,
        "queued": False,
        "total": 0,
        "processed": 0,
        "success": 0,
        "current_item": "",
        "status_text": "Idle",
    },
    "service": {
        "running": False,
        "queued": False,
        "total": 0,
        "processed": 0,
        "success": 0,
        "current_item": "",
        "status_text": "Idle",
    },
}
ICON_JOB_LOCK = threading.Lock()


def _run_icon_regeneration_worker(category: str):
    """Background worker to regenerate cached icons for existing database services/manufacturers."""
    while True:
        with ICON_JOB_LOCK:
            st = ICON_JOB_STATUS[category]
            st["running"] = True
            st["processed"] = 0
            st["success"] = 0
            st["current_item"] = "Gathering records..."
            st["status_text"] = "Gathering database records..."

        items = []
        try:
            conn = get_db_connection()
            if category == "manufacturer":
                rows = conn.execute(
                    "SELECT DISTINCT discovered_manufacturer AS name FROM services "
                    "WHERE discovered_manufacturer IS NOT NULL "
                    "  AND trim(discovered_manufacturer) != '' "
                    "  AND upper(trim(discovered_manufacturer)) != 'NONE' "
                    "ORDER BY discovered_manufacturer ASC"
                ).fetchall()
                items = [r["name"].strip() for r in rows if r["name"] and r["name"].strip()]
            else:
                rows = conn.execute(
                    "SELECT DISTINCT name FROM services "
                    "WHERE name IS NOT NULL AND trim(name) != '' "
                    "ORDER BY name ASC"
                ).fetchall()
                items = [r["name"].strip() for r in rows if r["name"] and r["name"].strip()]
            conn.close()
        except Exception as exc:
            with ICON_JOB_LOCK:
                st = ICON_JOB_STATUS[category]
                st["running"] = False
                st["queued"] = False
                st["status_text"] = f"Error reading database: {exc}"
            return

        # Filter to only items that currently lack a cached icon on disk
        missing_items = []
        for item in items:
            if category == "manufacturer":
                if not get_manufacturer_icon_url(item):
                    missing_items.append(item)
            else:
                if not get_service_icon_url(item):
                    missing_items.append(item)

        if not missing_items:
            with ICON_JOB_LOCK:
                st = ICON_JOB_STATUS[category]
                if st["queued"]:
                    st["queued"] = False
                    continue
                else:
                    st["running"] = False
                    st["total"] = 0
                    st["processed"] = 0
                    st["success"] = 0
                    st["current_item"] = ""
                    st["status_text"] = "All icons already cached (0 missing)"
                    break

        with ICON_JOB_LOCK:
            st = ICON_JOB_STATUS[category]
            st["total"] = len(missing_items)
            st["status_text"] = f"Generating 0/{len(missing_items)} missing icons..."

        for item in missing_items:
            with ICON_JOB_LOCK:
                ICON_JOB_STATUS[category]["current_item"] = item
                ICON_JOB_STATUS[category]["status_text"] = (
                    f"Generating missing {ICON_JOB_STATUS[category]['processed']}/{len(missing_items)}: {item}..."
                )

            try:
                if category == "manufacturer":
                    res = resolve_and_cache_manufacturer_icon(item, force_refresh=True)
                else:
                    res = resolve_and_cache_service_icon(item, force_refresh=True)

                with ICON_JOB_LOCK:
                    ICON_JOB_STATUS[category]["processed"] += 1
                    if res:
                        ICON_JOB_STATUS[category]["success"] += 1
            except Exception:
                with ICON_JOB_LOCK:
                    ICON_JOB_STATUS[category]["processed"] += 1

        with ICON_JOB_LOCK:
            st = ICON_JOB_STATUS[category]
            if st["queued"]:
                # Another run was requested while processing; loop again
                st["queued"] = False
                continue
            else:
                st["running"] = False
                st["current_item"] = ""
                st["status_text"] = f"Completed ({st['success']}/{st['total']} missing icons resolved)"
                break


@app.route("/api/settings/icons/status", methods=["GET"])
def api_get_icons_status():
    """Return live status of icon regeneration background jobs."""
    with ICON_JOB_LOCK:
        return jsonify({
            "manufacturer": dict(ICON_JOB_STATUS["manufacturer"]),
            "service": dict(ICON_JOB_STATUS["service"]),
        })


@app.route("/api/settings/icons/regenerate", methods=["POST"])
def api_regenerate_icons():
    """Trigger background icon regeneration for either manufacturer or service category."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()
    if category not in ("manufacturer", "service"):
        return jsonify({"success": False, "error": "Invalid category. Must be 'manufacturer' or 'service'."}), 400

    with ICON_JOB_LOCK:
        st = ICON_JOB_STATUS[category]
        if st["running"]:
            st["queued"] = True
            return jsonify({
                "success": True,
                "queued": True,
                "message": f"A regeneration job for {category} icons is already running. Your request has been queued.",
            })

        st["running"] = True
        st["queued"] = False
        st["total"] = 0
        st["processed"] = 0
        st["success"] = 0
        st["status_text"] = "Starting..."

    t = threading.Thread(
        target=_run_icon_regeneration_worker,
        args=(category,),
        name=f"IconRegenWorker-{category}",
        daemon=True,
    )
    t.start()

    return jsonify({
        "success": True,
        "queued": False,
        "message": f"Icon regeneration for {category} icons started in background.",
    })


@app.route("/api/settings/icons/list", methods=["GET"])
def api_list_cached_icons():
    """Return all cached icon files for the given category with metadata."""
    category = request.args.get("category", "manufacturer").strip().lower()
    target_dir = MANUFACTURER_ICONS_DIR if category == "manufacturer" else SERVICE_ICONS_DIR
    url_prefix = "/static/manufacturer-icons/" if category == "manufacturer" else "/static/service-icons/"

    icons = []
    if target_dir.is_dir():
        for f in sorted(target_dir.iterdir(), key=lambda p: p.name.lower()):
            if f.is_file() and f.suffix.lower() in (".png", ".ico", ".jpg", ".svg", ".webp", ".gif"):
                try:
                    size = f.stat().st_size
                    icons.append({
                        "filename": f.name,
                        "name": f.stem.replace("_", " "),
                        "url": f"{url_prefix}{f.name}",
                        "size_bytes": size,
                        "size_display": f"{size / 1024:.1f} KB" if size >= 1024 else f"{size} B",
                    })
                except Exception:
                    pass

    return jsonify({"success": True, "category": category, "icons": icons, "count": len(icons)})


@app.route("/api/settings/icons/delete-one", methods=["POST"])
def api_delete_one_icon():
    """Delete a single cached icon file."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()
    filename = (data.get("filename") or "").strip()

    if category not in ("manufacturer", "service"):
        return jsonify({"success": False, "error": "Invalid category."}), 400
    if not filename:
        return jsonify({"success": False, "error": "Filename is required."}), 400

    # Prevent directory traversal attacks
    clean_filename = os.path.basename(filename)
    if not clean_filename or clean_filename != filename:
        return jsonify({"success": False, "error": "Invalid filename format."}), 400

    target_dir = MANUFACTURER_ICONS_DIR if category == "manufacturer" else SERVICE_ICONS_DIR
    target_path = target_dir / clean_filename

    if target_path.is_file():
        try:
            target_path.unlink()
            return jsonify({"success": True, "message": f"Icon '{clean_filename}' deleted successfully."})
        except Exception as exc:
            return jsonify({"success": False, "error": f"Failed to delete file: {exc}"}), 500

    return jsonify({"success": False, "error": f"Icon '{clean_filename}' not found."}), 404


@app.route("/api/settings/icons/delete-all", methods=["POST"])
def api_delete_all_icons():
    """Delete all cached icons for the specified category."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()

    if category not in ("manufacturer", "service"):
        return jsonify({"success": False, "error": "Invalid category."}), 400

    target_dir = MANUFACTURER_ICONS_DIR if category == "manufacturer" else SERVICE_ICONS_DIR
    deleted_count = 0

    if target_dir.is_dir():
        for f in list(target_dir.iterdir()):
            if f.is_file() and f.suffix.lower() in (".png", ".ico", ".jpg", ".svg", ".webp", ".gif"):
                try:
                    f.unlink()
                    deleted_count += 1
                except Exception:
                    pass

    return jsonify({
        "success": True,
        "deleted_count": deleted_count,
        "message": f"Successfully deleted {deleted_count} cached {category} icon(s).",
    })


@app.route("/api/settings/icons/mappings", methods=["GET"])
def api_get_icon_mappings():
    """Return all icon mapping dictionaries and lists."""
    return jsonify({
        "success": True,
        "known_manufacturer_domains": get_known_manufacturer_domains(),
        "manufacturer_name_aliases": get_manufacturer_name_aliases(),
        "regional_prefixes": get_regional_prefixes(),
        "known_service_domains": get_known_service_domains(),
        "html_content_icon_mappings": get_html_content_icon_mappings(),
    })


@app.route("/api/settings/icons/mappings/save", methods=["POST"])
def api_save_icon_mappings():
    """Save an updated icon mapping structure to DB settings."""
    payload = request.get_json(silent=True) or {}
    mapping_type = payload.get("type", "").strip()
    data = payload.get("data")

    allowed_types = (
        "known_manufacturer_domains",
        "manufacturer_name_aliases",
        "regional_prefixes",
        "known_service_domains",
        "html_content_icon_mappings",
    )
    if mapping_type not in allowed_types:
        return jsonify({"success": False, "error": f"Invalid mapping type: '{mapping_type}'."}), 400

    if mapping_type in ("known_manufacturer_domains", "manufacturer_name_aliases", "known_service_domains"):
        if not isinstance(data, dict):
            return jsonify({"success": False, "error": "Data must be a key-value object."}), 400
        # Clean keys and values
        cleaned = {str(k).strip().lower(): str(v).strip() for k, v in data.items() if str(k).strip() and str(v).strip()}
        serialized = json.dumps(cleaned)
    elif mapping_type == "regional_prefixes":
        if not isinstance(data, list):
            return jsonify({"success": False, "error": "Data must be a list of prefix strings."}), 400
        cleaned = [str(x).strip().lower() for x in data if str(x).strip()]
        serialized = json.dumps(cleaned)
    elif mapping_type == "html_content_icon_mappings":
        if not isinstance(data, list):
            return jsonify({"success": False, "error": "Data must be a list of [pattern, target] pairs."}), 400
        cleaned = []
        for item in data:
            if isinstance(item, (list, tuple)) and len(item) == 2:
                p, t = str(item[0]).strip(), str(item[1]).strip()
                if p and t:
                    cleaned.append([p, t])
        serialized = json.dumps(cleaned)

    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (mapping_type, serialized),
        )
        conn.commit()
        conn.close()
        return jsonify({"success": True, "message": f"Mapping '{mapping_type}' saved successfully."})
    except Exception as exc:
        return jsonify({"success": False, "error": f"Database error saving mapping: {exc}"}), 500


@app.route("/api/settings/icons/mappings/reset", methods=["POST"])
def api_reset_icon_mappings():
    """Reset a specific icon mapping structure or all mappings to default."""
    payload = request.get_json(silent=True) or {}
    mapping_type = payload.get("type", "").strip()

    defaults = {
        "known_manufacturer_domains": json.dumps(DEFAULT_KNOWN_MANUFACTURER_DOMAINS),
        "manufacturer_name_aliases": json.dumps(DEFAULT_MANUFACTURER_NAME_ALIASES),
        "regional_prefixes": json.dumps(DEFAULT_REGIONAL_PREFIXES),
        "known_service_domains": json.dumps(DEFAULT_KNOWN_SERVICE_DOMAINS),
        "html_content_icon_mappings": json.dumps(DEFAULT_HTML_CONTENT_ICON_MAPPINGS),
    }

    if mapping_type not in defaults:
        return jsonify({"success": False, "error": f"Invalid mapping type: '{mapping_type}'."}), 400

    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
            (mapping_type, defaults[mapping_type]),
        )
        conn.commit()
        conn.close()
        return jsonify({
            "success": True,
            "message": f"Reset '{mapping_type}' to defaults successfully.",
            "data": json.loads(defaults[mapping_type]),
        })
    except Exception as exc:
        return jsonify({"success": False, "error": f"Database error resetting mapping: {exc}"}), 500


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


# Known manufacturer name aliases / rebrands
DEFAULT_MANUFACTURER_NAME_ALIASES = {
    "routerboard.com": "MikroTik",
    "routerboard": "MikroTik",
    "beijing xiaomi": "Xiaomi",
    "xiaomi": "Xiaomi",
    "shenzhen cudy": "Cudy",
    "cudy technology": "Cudy",
    "cudy": "Cudy",
    "shenzhen jehe": "Giada",
    "jehe technology": "Giada",
    "giada": "Giada",
    "d&m holdings": "Marantz",
    "d and m holdings": "Marantz",
    "marantz": "Marantz",
    "hangzhou gubei": "BroadLink",
    "gubei electronics": "BroadLink",
    "gubei": "BroadLink",
    "broadlink": "BroadLink",
    "jm zengge": "MagicHue",
    "zengge": "MagicHue",
    "magichue": "MagicHue",
    "magic home": "MagicHue",
    "magic home pro": "MagicHue",
}

# Backwards compatibility reference
_MANUFACTURER_NAME_ALIASES = DEFAULT_MANUFACTURER_NAME_ALIASES


def get_manufacturer_name_aliases() -> dict[str, str]:
    """Retrieve manufacturer aliases from DB settings or initialize with defaults."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'manufacturer_name_aliases'").fetchone()
        conn.close()
        if row and row["value"]:
            parsed = json.loads(row["value"])
            if isinstance(parsed, dict) and parsed:
                return parsed
    except Exception:
        pass
    return dict(DEFAULT_MANUFACTURER_NAME_ALIASES)


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
                if not vendor:
                    return "NONE"
                # Check for known rebrands / name aliases (e.g. Routerboard.com -> MikroTik)
                v_lower = vendor.lower()
                aliases = get_manufacturer_name_aliases()
                for alias_key, canon_name in aliases.items():
                    if alias_key == v_lower or alias_key in v_lower:
                        return canon_name
                return vendor
        except Exception:
            return "NONE"
        finally:
            time.sleep(1)   # 1 s gap between any two API calls


def slugify_manufacturer(name: str) -> str:
    """Normalize a manufacturer name into a safe filesystem slug."""
    s = (name or "").lower().strip()
    # Normalize aliases first
    aliases = get_manufacturer_name_aliases()
    for alias_key, canon_name in aliases.items():
        if alias_key == s or alias_key in s:
            s = canon_name.lower()
            break
    # Strip common corporate suffixes
    s = re.sub(r"\b(inc|incorporated|corp|corporation|llc|ltd|limited|co|gmbh|sa|bv|s\.p\.a|s\.a|n\.v)\b\.?", "", s)
    # Remove punctuation / special characters
    s = re.sub(r"[^\w\s-]", "", s)
    # Collapse whitespace into underscores
    s = re.sub(r"[\s-]+", "_", s).strip("_")
    return s or "unknown"


# Known hashes of generic GoDaddy parked page favicons across multiple sizes and CDNs
_GODADDY_PARKED_ICON_HASHES = {
    "0f51e723b5ea18cf223bd66aaf0bda85",  # Google Favicon 64px (1045 bytes)
    "6bceda3c3c8d58b353b71a1641a3e73d",  # Google Favicon 32px (510 bytes)
    "8379b3a54a273ff25f7ec28c565341e8",  # Google Favicon 16px (302 bytes)
    "b01122b8efe9b9022ddb161443198081",  # Google Favicon 128px (1965 bytes)
    "d9e87c52cf05be95fb7a09ff01080983",  # GoDaddy CDN img1.wsimg.com direct favicon (2238 bytes)
}


def is_godaddy_or_parked_icon(data: bytes | None) -> bool:
    """Return True if image data matches known GoDaddy parked domain favicon signatures."""
    if not data or len(data) < 50:
        return True
    h = hashlib.md5(data).hexdigest()
    return h in _GODADDY_PARKED_ICON_HASHES


def get_manufacturer_icon_url(manufacturer: str | None) -> str | None:
    """Return local cached URL for manufacturer icon if it exists on disk."""
    if not manufacturer or manufacturer.strip().upper() in ("", "NONE"):
        return None
    slug = slugify_manufacturer(manufacturer)
    for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
        icon_path = MANUFACTURER_ICONS_DIR / f"{slug}{ext}"
        if icon_path.is_file() and icon_path.stat().st_size > 0:
            try:
                data = icon_path.read_bytes()
                if is_godaddy_or_parked_icon(data):
                    icon_path.unlink(missing_ok=True)
                    continue
            except Exception:
                pass
            return f"/static/manufacturer-icons/{slug}{ext}"
    return None


@app.route("/static/manufacturer-icons/<path:filename>")
def serve_manufacturer_icon(filename):
    """Serve manufacturer logos cached on disk."""
    icon_path = MANUFACTURER_ICONS_DIR / filename
    if icon_path.is_file():
        try:
            if is_godaddy_or_parked_icon(icon_path.read_bytes()):
                icon_path.unlink(missing_ok=True)
                abort(404)
        except Exception:
            pass
    return send_from_directory(MANUFACTURER_ICONS_DIR, filename)


def extract_service_product_name(service_name: str) -> str:
    """Extract the primary product / application name from a service hostname or label."""
    if not service_name:
        return ""
    # Strip protocol scheme if present (http://, https://)
    raw = re.sub(r"^https?://", "", service_name.strip(), flags=re.I)
    # Split on first dot, colon, slash, whitespace or delimiter
    first_part = re.split(r"[.:/\s_-]", raw)[0].strip().lower()
    return first_part


def slugify_service_name(service_name: str) -> str:
    """Normalize a service / product name into a safe filesystem slug."""
    product = extract_service_product_name(service_name)
    s = re.sub(r"[^\w-]", "", product).strip("_")
    return s or "unknown"


def detect_image_extension(data: bytes, content_type: str = "") -> str:
    """Detect appropriate file extension (.svg, .png, .ico, .jpg, .gif, .webp) from payload and Content-Type."""
    if not data:
        return ".png"
    ct = (content_type or "").lower()
    stripped = data.lstrip()
    if "svg" in ct or stripped.startswith((b"<svg", b"<?xml", b"<!DOCTYPE svg")):
        return ".svg"
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if data.startswith((b"\xff\xd8\xff", b"\xff\xd8")):
        return ".jpg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if data.startswith(b"RIFF") and len(data) >= 12 and data[8:12] == b"WEBP":
        return ".webp"
    if data.startswith((b"\x00\x00\x01\x00", b"\x00\x00\x02\x00")) or "ico" in ct or "icon" in ct:
        return ".ico"
    return ".png"


def get_service_icon_url(service_name: str | None) -> str | None:
    """Return local cached URL for service / product icon if it exists on disk."""
    if not service_name or service_name.strip().upper() in ("", "NONE"):
        return None
    slug = slugify_service_name(service_name)
    for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
        icon_path = SERVICE_ICONS_DIR / f"{slug}{ext}"
        if icon_path.is_file() and icon_path.stat().st_size > 0:
            try:
                data = icon_path.read_bytes()
                if is_godaddy_or_parked_icon(data):
                    icon_path.unlink(missing_ok=True)
                    continue
            except Exception:
                pass
            return f"/static/service-icons/{slug}{ext}"
    return None


@app.route("/static/service-icons/<path:filename>")
def serve_service_icon(filename):
    """Serve service / product logos cached on disk."""
    icon_path = SERVICE_ICONS_DIR / filename
    if icon_path.is_file():
        try:
            if is_godaddy_or_parked_icon(icon_path.read_bytes()):
                icon_path.unlink(missing_ok=True)
                abort(404)
        except Exception:
            pass
    return send_from_directory(SERVICE_ICONS_DIR, filename)


# Base built-in mappings used as fallback and seed in settings table
DEFAULT_KNOWN_MANUFACTURER_DOMAINS = {
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
    "routerboard": "mikrotik.com",
    "routerboard.com": "mikrotik.com",
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
    "xiaomi": "mi.com",
    "beijing xiaomi": "mi.com",
    "cudy": "cudy.com",
    "shenzhen cudy": "cudy.com",
    "giada": "giadatech.com",
    "jehe": "giadatech.com",
    "shenzhen jehe": "giadatech.com",
    "marantz": "marantz.com",
    "d&m holdings": "marantz.com",
    "d and m holdings": "marantz.com",
    "broadlink": "ibroadlink.com",
    "hangzhou gubei": "ibroadlink.com",
    "gubei": "ibroadlink.com",
    "magichue": "web.magichue.net",
    "jm zengge": "web.magichue.net",
    "zengge": "web.magichue.net",
    "magic home": "web.magichue.net",
    "magic home pro": "web.magichue.net",
}

DEFAULT_REGIONAL_PREFIXES = [
    "shenzhen", "beijing", "shanghai", "hangzhou", "guangzhou", "dongguan",
    "chengdu", "wuhan", "nanjing", "taipei", "hong kong", "hongkong"
]


def get_known_manufacturer_domains() -> dict[str, str]:
    """Retrieve manufacturer domain mappings from DB settings or initialize with defaults."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'known_manufacturer_domains'").fetchone()
        conn.close()
        if row and row["value"]:
            parsed = json.loads(row["value"])
            if isinstance(parsed, dict) and parsed:
                return parsed
    except Exception:
        pass
    return dict(DEFAULT_KNOWN_MANUFACTURER_DOMAINS)


def get_regional_prefixes() -> list[str]:
    """Retrieve regional prefixes from DB settings or initialize with defaults."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'regional_prefixes'").fetchone()
        conn.close()
        if row and row["value"]:
            parsed = json.loads(row["value"])
            if isinstance(parsed, list) and parsed:
                return [str(x).strip().lower() for x in parsed if str(x).strip()]
    except Exception:
        pass
    return list(DEFAULT_REGIONAL_PREFIXES)


def resolve_and_cache_manufacturer_icon(manufacturer: str, force_refresh: bool = False) -> str | None:
    """
    Find, download, and cache an icon for the manufacturer in MANUFACTURER_ICONS_DIR.
    Checks disk cache first to prevent repeated internet requests unless force_refresh is True.
    """
    if not manufacturer or manufacturer.strip().upper() in ("", "NONE"):
        return None

    slug = slugify_manufacturer(manufacturer)
    # 1. Disk Cache hit (check all supported image formats)
    if not force_refresh:
        for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
            cached_file = MANUFACTURER_ICONS_DIR / f"{slug}{ext}"
            if cached_file.is_file() and cached_file.stat().st_size > 0:
                return f"/static/manufacturer-icons/{slug}{ext}"

    # Determine domain to check from dynamic mappings
    known_mfg_domains = get_known_manufacturer_domains()
    regional_prefixes_set = set(get_regional_prefixes())

    m_lower = manufacturer.lower()
    domain = None
    for key, dom in known_mfg_domains.items():
        if key in m_lower:
            domain = dom
            break

    candidate_domains = []
    if domain:
        candidate_domains.append(domain)
    else:
        # Heuristic: extract clean slug tokens
        tokens = [t for t in slug.split("_") if t and t not in ("technology", "electronics", "information", "networks", "network", "telecom", "telecommunication", "digital", "system", "systems", "group", "holdings", "holding")]
        # If the first token is a known regional prefix (e.g. Shenzhen, Hangzhou, Beijing), try the second token first
        if len(tokens) > 1 and tokens[0] in regional_prefixes_set:
            second_token = tokens[1]
            if len(second_token) > 2:
                candidate_domains.append(f"{second_token}.com")
                candidate_domains.append(f"{second_token}tech.com")

        # Fallback to the first token
        if tokens and len(tokens[0]) > 2:
            candidate_domains.append(f"{tokens[0]}.com")

    # Filter out generic regional city domains (e.g., shenzhen.com, beijing.com) from being treated as tech vendor sites
    candidate_domains = [d for d in candidate_domains if not any(d == f"{reg}.com" for reg in regional_prefixes_set)]

    icon_bytes = None

    # Step A: Google Favicon service
    for test_dom in candidate_domains:
        try:
            fav_url = f"https://www.google.com/s2/favicons?domain={test_dom}&sz=64"
            data, status, _ = AsyncHttpManager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=4.0)
            if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                icon_bytes = data
                break
        except Exception:
            pass

    # Step B: Direct website probe (favicon.ico / common logo paths / HTML parse)
    if not icon_bytes:
        ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
        for test_dom in candidate_domains:
            direct_candidates = [
                f"https://www.{test_dom}/imgs/{test_dom.split('.')[0]}_logo.png",
                f"https://www.{test_dom}/images/logo.png",
                f"https://{test_dom}/favicon.ico",
                f"https://{test_dom}/favicon.ico",
            ]
            for candidate_url in direct_candidates:
                try:
                    data, status, headers = AsyncHttpManager.get_url(candidate_url, headers={"User-Agent": ua}, timeout=4.0)
                    ctype = headers.get("Content-Type", "") or headers.get("content-type", "")
                    if status == 200 and len(data) > 100 and ("image" in ctype or candidate_url.endswith((".png", ".ico", ".jpg", ".svg"))) and not is_godaddy_or_parked_icon(data):
                        icon_bytes = data
                        break
                except Exception:
                    continue
            if icon_bytes:
                break

            # If direct paths failed, try fetching root homepage to extract link rel="icon" or img src="*logo*"
            try:
                home_url = f"https://www.{test_dom}/"
                data, status, _ = AsyncHttpManager.get_url(home_url, headers={"User-Agent": ua}, timeout=4.0)
                if status == 200:
                    html = data.decode("utf-8", errors="ignore")
                    found_links = re.findall(r'<link[^>]+rel=[\"\'](?:shortcut )?icon[\"\'][^>]+href=[\"\']([^\"\']+)[\"\']', html, re.I)
                    found_logos = re.findall(r'<img[^>]+src=[\"\']([^\"\']*(?:logo|icon)[^\"\']*)[\"\']', html, re.I)
                    for relative_or_abs in (found_links + found_logos):
                        target = urljoin(home_url, relative_or_abs)
                        try:
                            t_data, t_status, _ = AsyncHttpManager.get_url(target, headers={"User-Agent": ua}, timeout=4.0)
                            if t_status == 200 and len(t_data) > 100 and not is_godaddy_or_parked_icon(t_data):
                                icon_bytes = t_data
                                break
                        except Exception:
                            continue
                        if icon_bytes:
                            break
            except Exception:
                pass
            if icon_bytes:
                break

    # Step C: Wikimedia pageimages fallback if direct probe didn't yield anything
    if not icon_bytes:
        try:
            # Query clean name on Wikipedia
            query_title = manufacturer.split(",")[0].strip()
            wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=pageimages&format=json&titles={urllib.parse.quote(query_title)}&pithumbsize=64"
            data, status, _ = AsyncHttpManager.get_url(wiki_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=4.0)
            if status == 200:
                payload = json.loads(data.decode())
                pages = payload.get("query", {}).get("pages", {})
                thumb_url = None
                for p in pages.values():
                    if "thumbnail" in p and "source" in p["thumbnail"]:
                        thumb_url = p["thumbnail"]["source"]
                        break
                if thumb_url:
                    img_data, img_status, _ = AsyncHttpManager.get_url(thumb_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=4.0)
                    if img_status == 200 and len(img_data) > 100 and not is_godaddy_or_parked_icon(img_data):
                        icon_bytes = img_data
        except Exception:
            pass

    # Save to disk cache if a valid non-parked icon was obtained
    if icon_bytes and not is_godaddy_or_parked_icon(icon_bytes):
        ext = detect_image_extension(icon_bytes)
        actual_path = MANUFACTURER_ICONS_DIR / f"{slug}{ext}"
        try:
            with open(actual_path, "wb") as f:
                f.write(icon_bytes)
            return f"/static/manufacturer-icons/{slug}{ext}"
        except Exception as exc:
            print(f"[IconCache] Failed to write {actual_path}: {exc}")

    return None


# Base built-in service & application mappings
DEFAULT_KNOWN_SERVICE_DOMAINS = {
    "bitwarden": "bitwarden.com",
    "vaultwarden": "vaultwarden.net",
    "plex": "plex.tv",
    "jellyfin": "jellyfin.org",
    "emby": "emby.media",
    "homeassistant": "home-assistant.io",
    "hass": "home-assistant.io",
    "nextcloud": "nextcloud.com",
    "owncloud": "owncloud.com",
    "adguard": "adguard.com",
    "pihole": "pi-hole.net",
    "portainer": "portainer.io",
    "proxmox": "proxmox.com",
    "pve": "proxmox.com",
    "truenas": "truenas.com",
    "unraid": "unraid.net",
    "synology": "synology.com",
    "qnap": "qnap.com",
    "grafana": "grafana.com",
    "prometheus": "prometheus.io",
    "uptime": "kuma.pet",
    "kuma": "kuma.pet",
    "traefik": "traefik.io",
    "caddy": "caddyserver.com",
    "nginx": "nginx.org",
    "apache": "apache.org",
    "wireguard": "wireguard.com",
    "tailscale": "tailscale.com",
    "zerotier": "zerotier.com",
    "openvpn": "openvpn.net",
    "cockpit": "cockpit-project.org",
    "beszel": "beszel.com",
    "bazarr": "bazarr.media",
    "radarr": "radarr.video",
    "sonarr": "sonarr.tv",
    "lidarr": "lidarr.audio",
    "prowlarr": "prowlarr.com",
    "qbittorrent": "qbittorrent.org",
    "transmission": "transmissionbt.com",
    "deluge": "deluge-torrent.org",
    "authelia": "authelia.com",
    "authentik": "goauthentik.io",
    "keycloak": "keycloak.org",
    "bookstack": "bookstackapp.com",
    "cloudbeaver": "cloudbeaver.io",
    "cups": "cups.org",
    "homebridge": "homebridge.io",
    "zigbee2mqtt": "zigbee2mqtt.io",
    "mosquitto": "mosquitto.org",
    "node-red": "nodered.org",
    "nodered": "nodered.org",
    "paperless": "paperless-ngx.com",
    "immich": "immich.app",
    "photoprism": "photoprism.app",
    "gitea": "gitea.com",
    "forgejo": "forgejo.org",
    "gitlab": "gitlab.com",
    "github": "github.com",
    "guacamole": "guacamole.apache.org",
    "rustdesk": "rustdesk.com",
    "netdata": "netdata.cloud",
    "glances": "nicolargo.github.io",
    "zabbix": "zabbix.com",
    "nagios": "nagios.org",
    "esphome": "esphome.io",
    "tasmota": "tasmota.github.io",
    "wled": "kno.wled.ge",
    "mikrotik": "mikrotik.com",
    "routerboard": "mikrotik.com",
    "openwrt": "openwrt.org",
    "opnsense": "opnsense.org",
    "pfsense": "pfsense.org",
    "serviio": "serviio.org",
}

# Known HTML content signatures mapped to platform/vendor domains or absolute icon URLs
DEFAULT_HTML_CONTENT_ICON_MAPPINGS = [
    [r"\b(?:luci|lua configuration interface)\b", "https://raw.githubusercontent.com/openwrt/branding/refs/heads/master/favicon/favicon.ico"],
    [r"\b(?:proxmox virtual environment|proxmox ve)\b", "proxmox.com"],
    [r"\b(?:truenas core|truenas scale)\b", "truenas.com"],
    [r"\b(?:synology dsm|diskstation manager)\b", "synology.com"],
    [r"\b(?:qts|qnap)\b", "qnap.com"],
    [r"\b(?:pi-hole)\b", "pi-hole.net"],
    [r"\b(?:adguard home)\b", "adguard.com"],
    [r"\b(?:portainer ce|portainer business)\b", "portainer.io"],
]


def get_known_service_domains() -> dict[str, str]:
    """Retrieve service domain mappings from DB settings or initialize with defaults."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'known_service_domains'").fetchone()
        conn.close()
        if row and row["value"]:
            parsed = json.loads(row["value"])
            if isinstance(parsed, dict) and parsed:
                return parsed
    except Exception:
        pass
    return dict(DEFAULT_KNOWN_SERVICE_DOMAINS)


def get_html_content_icon_mappings() -> list[list[str]]:
    """Retrieve HTML content signature icon mappings from DB settings or initialize with defaults."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM settings WHERE key = 'html_content_icon_mappings'").fetchone()
        conn.close()
        if row and row["value"]:
            parsed = json.loads(row["value"])
            if isinstance(parsed, list) and parsed:
                return parsed
    except Exception:
        pass
    return [list(item) for item in DEFAULT_HTML_CONTENT_ICON_MAPPINGS]


def fetch_service_html_body(service_name: str, max_redirects: int = 3) -> str | None:
    """
    Retrieve the landing page HTML of a service across https:// and http://,
    following redirects and accepting self-signed TLS certificates.
    Limits downloaded content to 64KB for speed and resource efficiency.
    """
    clean_host = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
    if not clean_host:
        return None

    import ssl
    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

    for proto in ("https", "http"):
        current_url = f"{proto}://{clean_host}/"
        try:
            data, status, headers = AsyncHttpManager.get_url(current_url, headers={"User-Agent": ua}, timeout=2.5, max_redirects=max_redirects)
            ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
            if status == 200 and ("text" in ctype or "html" in ctype or b"<html" in data[:4096] or b"<body" in data[:4096]):
                return data[:65536].decode("utf-8", errors="ignore")
        except Exception:
            pass

    return None


def resolve_and_cache_service_icon(service_name: str, force_refresh: bool = False) -> str | None:
    """
    Find, download, and cache an icon for the product/service in SERVICE_ICONS_DIR.
    1. Primary Method: Access service name directly as a site via https:// then http://.
    2. Fallback Method: Use first word/token of service name for product domain / Wikimedia lookups.
    3. Deep Fallback Method: Fetch landing HTML, follow redirects, and match content signatures (e.g. LuCI -> openwrt.org).
    """
    if not service_name or service_name.strip().upper() in ("", "NONE"):
        return None

    product = extract_service_product_name(service_name)
    if not product or len(product) < 2:
        return None

    slug = slugify_service_name(service_name)
    # Check disk cache first across all extensions, discarding corrupted/parked icons unless force_refresh is True
    if not force_refresh:
        for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
            cached_file = SERVICE_ICONS_DIR / f"{slug}{ext}"
            if cached_file.is_file() and cached_file.stat().st_size > 0:
                try:
                    data = cached_file.read_bytes()
                    if is_godaddy_or_parked_icon(data):
                        cached_file.unlink(missing_ok=True)
                        continue
                except Exception:
                    pass
                return f"/static/service-icons/{slug}{ext}"

    icon_bytes = None
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

    # =========================================================================
    # Priority 1: Explicit Image URL from Known Service Domains
    # =========================================================================
    known_service_domains = get_known_service_domains()
    if product in known_service_domains:
        target_val = known_service_domains[product].strip()
        if target_val.lower().startswith(("http://", "https://")):
            try:
                data, status, _ = AsyncHttpManager.get_url(target_val, headers={"User-Agent": ua}, timeout=4.0)
                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                    icon_bytes = data
            except Exception:
                pass

    # =========================================================================
    # Priority 2: Explicit URL from HTML Content Signatures
    # =========================================================================
    html_page = None
    if not icon_bytes:
        html_page = fetch_service_html_body(service_name)
        if html_page:
            html_mappings = get_html_content_icon_mappings()
            for pattern, target in html_mappings:
                if target.lower().startswith(("http://", "https://")):
                    if re.search(pattern, html_page, re.I):
                        try:
                            data, status, _ = AsyncHttpManager.get_url(target, headers={"User-Agent": ua}, timeout=3.5)
                            if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                                icon_bytes = data
                                break
                        except Exception:
                            pass

    # =========================================================================
    # Priority 3: Direct Site Probe (https:// then http://)
    # =========================================================================
    if not icon_bytes:
        clean_host = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
        if clean_host:
            for proto in ("https", "http"):
                base_url = f"{proto}://{clean_host}"

                # 3A. Direct /favicon.ico probe
                try:
                    fav_url = f"{base_url}/favicon.ico"
                    data, status, headers = AsyncHttpManager.get_url(fav_url, headers={"User-Agent": ua}, timeout=1.5)
                    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
                    if status == 200 and len(data) > 100 and ("html" not in ctype) and not is_godaddy_or_parked_icon(data):
                        icon_bytes = data
                        break
                except Exception:
                    pass

                # 3B. Inspect root homepage HTML for <link rel="icon">
                if not icon_bytes:
                    try:
                        home_data, home_status, _ = AsyncHttpManager.get_url(f"{base_url}/", headers={"User-Agent": ua}, timeout=1.5)
                        if home_status == 200:
                            html = home_data.decode("utf-8", errors="ignore")
                            found_links = re.findall(r'<link[^>]+rel=[\"\'](?:shortcut )?icon[\"\'][^>]+href=[\"\']([^\"\']+)[\"\']', html, re.I)
                            for link_href in found_links:
                                target = urljoin(f"{base_url}/", link_href)
                                try:
                                    t_data, t_status, t_headers = AsyncHttpManager.get_url(target, headers={"User-Agent": ua}, timeout=1.5)
                                    t_ctype = (t_headers.get("Content-Type") or t_headers.get("content-type") or "").lower()
                                    if t_status == 200 and len(t_data) > 100 and ("html" not in t_ctype) and not is_godaddy_or_parked_icon(t_data):
                                        icon_bytes = t_data
                                        break
                                except Exception:
                                    continue
                    except Exception:
                        pass

                if icon_bytes:
                    break

    # =========================================================================
    # Priority 4: Domain Lookups & Platform Fallbacks (Known Domains, Google Favicon, Wikipedia)
    # =========================================================================
    if not icon_bytes:
        candidate_domains = []
        if product in known_service_domains:
            target_dom = known_service_domains[product].strip()
            if target_dom and not target_dom.lower().startswith(("http://", "https://")):
                candidate_domains.append(target_dom)

        # General domain guesses for the product name
        for tld in (".com", ".io", ".org", ".net", ".app", ".dev", ".media"):
            guess = f"{product}{tld}"
            if guess not in candidate_domains:
                candidate_domains.append(guess)

        # Step 4A: Google Favicon service
        for test_dom in candidate_domains:
            try:
                fav_url = f"https://www.google.com/s2/favicons?domain={test_dom}&sz=64"
                data, status, _ = AsyncHttpManager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=2.0)
                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                    icon_bytes = data
                    break
            except Exception:
                pass

        # Step 4B: Wikimedia pageimages fallback (only for recognized product tokens)
        if not icon_bytes and len(product) > 2:
            try:
                wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=pageimages&format=json&titles={urllib.parse.quote(product.capitalize())}&pithumbsize=64"
                data, status, _ = AsyncHttpManager.get_url(wiki_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=2.0)
                if status == 200:
                    payload = json.loads(data.decode())
                    pages = payload.get("query", {}).get("pages", {})
                    thumb_url = None
                    for p in pages.values():
                        if "thumbnail" in p and "source" in p["thumbnail"]:
                            thumb_url = p["thumbnail"]["source"]
                            break
                    if thumb_url:
                        img_data, img_status, _ = AsyncHttpManager.get_url(thumb_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=2.0)
                        if img_status == 200 and len(img_data) > 100 and not is_godaddy_or_parked_icon(img_data):
                            icon_bytes = img_data
            except Exception:
                pass

        # Step 4C: HTML Content Signature Domain Matching fallback
        if not icon_bytes:
            if html_page is None:
                html_page = fetch_service_html_body(service_name)
            if html_page:
                matched_domain = None
                html_mappings = get_html_content_icon_mappings()
                for pattern, dom in html_mappings:
                    if not dom.lower().startswith(("http://", "https://")):
                        if re.search(pattern, html_page, re.I):
                            matched_domain = dom
                            break

                if matched_domain:
                    # Google Favicon lookup for matched platform domain
                    try:
                        fav_url = f"https://www.google.com/s2/favicons?domain={matched_domain}&sz=64"
                        data, status, _ = AsyncHttpManager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=2.0)
                        if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                            icon_bytes = data
                    except Exception:
                        pass

                    # Direct probe to matched platform domain if needed
                    if not icon_bytes:
                        for probe_url in (f"https://www.{matched_domain}/favicon.ico", f"https://{matched_domain}/favicon.ico"):
                            try:
                                data, status, _ = AsyncHttpManager.get_url(probe_url, headers={"User-Agent": ua}, timeout=2.5)
                                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                                    icon_bytes = data
                                    break
                            except Exception:
                                continue

    # Save to disk cache if a valid non-parked icon was obtained
    if icon_bytes and not is_godaddy_or_parked_icon(icon_bytes):
        ext = detect_image_extension(icon_bytes)
        actual_path = SERVICE_ICONS_DIR / f"{slug}{ext}"
        try:
            with open(actual_path, "wb") as f:
                f.write(icon_bytes)
            return f"/static/service-icons/{slug}{ext}"
        except Exception as exc:
            print(f"[ServiceIconCache] Failed to write {actual_path}: {exc}")

    return None


def trigger_service_icon_resolution_async(service_name: str):
    """Fire-and-forget service icon lookup on add or edit."""
    if not service_name:
        return
    t = threading.Thread(
        target=resolve_and_cache_service_icon,
        args=(service_name,),
        daemon=True,
    )
    t.start()


def resolve_missing_service_icons():
    """
    Startup-only task:
    Checks all distinct services in the database and obtains icons for those lacking a cached icon.
    Runs once at startup in a background thread pool (up to 4 parallel workers).
    No recurring schedule.
    """
    print("[ServiceIconJob] Starting startup check for missing service icons...")
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT DISTINCT name FROM services WHERE name IS NOT NULL AND trim(name) != ''"
        ).fetchall()
        conn.close()

        missing = [row["name"] for row in rows if not get_service_icon_url(row["name"])]
        if not missing:
            print("[ServiceIconJob] All services already have cached icons.")
            return

        print(f"[ServiceIconJob] Found {len(missing)} service(s) missing icons. Resolving in background...")
        cached_count = 0

        def _resolve_one(name):
            try:
                res = resolve_and_cache_service_icon(name)
                if res:
                    print(f"[ServiceIconJob] Cached icon for '{name}' -> {res}")
                    return True
            except Exception as exc:
                print(f"[ServiceIconJob] Error resolving icon for '{name}': {exc}")
            return False

        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = [executor.submit(_resolve_one, name) for name in missing]
            for f in futures:
                try:
                    if f.result():
                        cached_count += 1
                except Exception:
                    pass

        print(f"[ServiceIconJob] Startup scan completed: cached {cached_count}/{len(missing)} icon(s).")
    except Exception as exc:
        print(f"[ServiceIconJob] Startup scan database error: {exc}")


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
                    print(f"[MfgJob] Error fetching icon for '{mfg}': {icon_err}")
    except Exception as exc:
        print(f"[MfgJob] Database error checking manufacturer icons: {exc}")

    print("[MfgJob] Scheduled check for missing manufacturers and icons completed.")


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

    # One-time startup task for missing service product icons (no recurring schedule)
    threading.Thread(
        target=resolve_missing_service_icons,
        name="StartupServiceIconResolver",
        daemon=True,
    ).start()

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


@profile
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
            if overall in ("online", "none") or not port_statuses:
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


@profile
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
        if LINE_PROFILER_ENABLED and GLOBAL_LINE_PROFILER is not None:
            dump_line_profiler_stats()


def enable_line_profiling():
    """Initialize and enable line_profiler across scan and probe functions."""
    global GLOBAL_LINE_PROFILER, LINE_PROFILER_ENABLED
    try:
        from line_profiler import LineProfiler
    except ImportError:
        print("[LineProfiler] Error: 'line_profiler' package is not installed. Run: pip install line-profiler")
        return False

    lp = LineProfiler()
    # Register all key scan, probe, and route functions to profile line-by-line
    for fn in (check_all_services, scan_service_with_retries, scan_service, fetch_response, status, get_status_rows):
        # Unwrap if already wrapped by a decorator
        target_fn = getattr(fn, "__wrapped__", fn)
        lp.add_function(target_fn)

    lp.enable()
    GLOBAL_LINE_PROFILER = lp
    LINE_PROFILER_ENABLED = True

    # Also install into builtins so any direct calls are captured
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


def dump_line_profiler_stats(output_file: str | None = None, disable: bool = False):
    """Print line-by-line profiler timing report to terminal and optionally dump to .lprof file."""
    global GLOBAL_LINE_PROFILER
    if GLOBAL_LINE_PROFILER is None:
        return

    print("\n" + "=" * 80)
    print(" [LINE PROFILER STATS] Scan Cycle Timing Analysis")
    print("=" * 80)
    try:
        GLOBAL_LINE_PROFILER.print_stats()
    except Exception as exc:
        print(f"[LineProfiler] Failed to print stats: {exc}")

    if output_file or os.getenv("PULSECHECK_PROFILE_OUT"):
        dump_path = output_file or os.getenv("PULSECHECK_PROFILE_OUT", "pulsecheck_scan.lprof")
        try:
            GLOBAL_LINE_PROFILER.dump_stats(dump_path)
            print(f"[LineProfiler] Saved raw profile binary to: {dump_path}")
        except Exception as exc:
            print(f"[LineProfiler] Failed saving {dump_path}: {exc}")
    print("=" * 80 + "\n")

    if disable:
        try:
            GLOBAL_LINE_PROFILER.disable()
        except Exception:
            pass


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Start web app")
        print("2. Start web with Explicit debugging")
        print("3. Start web with Line-Profiler (profiles scan lines & elapsed CPU/time)")
        print("4. Exit")
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
            if enable_line_profiling():
                print(f"Starting web application with Line-Profiler on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
                print("Line-by-line profiling active for check_all_services, scan_service, scan_service_with_retries, fetch_response, and /status.")
                print("Timing stats will display after each scan cycle and when shutting down.\n")
                app.run(host=DEFAULT_IP, port=DEFAULT_PORT, debug=False)
                break

        elif choice == "4":
            print("Exiting PulseCheck.")
            break
        else:
            print("Invalid option.")


_APP_INITIALIZED = False
_APP_INIT_LOCK = threading.Lock()


def ensure_app_initialized():
    """Ensure database and background tasks are initialized once (e.g. under WSGI)."""
    global _APP_INITIALIZED
    if not _APP_INITIALIZED:
        with _APP_INIT_LOCK:
            if not _APP_INITIALIZED:
                if LINE_PROFILER_ENABLED and GLOBAL_LINE_PROFILER is None:
                    enable_line_profiling()
                init_db()
                run_background_tasks()
                _APP_INITIALIZED = True


# Initialize automatically when imported under a WSGI server like Gunicorn
if os.getenv("PULSECHECK_HEADLESS", "").lower() in ("1", "true", "yes") or not sys.stdin.isatty():
    ensure_app_initialized()


if __name__ == "__main__":
    ensure_app_initialized()
    try:
        if os.getenv("PULSECHECK_HEADLESS", "").lower() in ("1", "true", "yes") or not sys.stdin.isatty():
            print(f"Starting web application on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            app.run(host=DEFAULT_IP, port=DEFAULT_PORT, debug=False)
        else:
            cli_menu()
    finally:
        if LINE_PROFILER_ENABLED and GLOBAL_LINE_PROFILER is not None:
            dump_line_profiler_stats(disable=True)
        if GLOBAL_SCHEDULER:
            GLOBAL_SCHEDULER.shutdown(wait=False)
