from __future__ import annotations

import csv
import http.client
import io
import json
import os
import re
import sqlite3
import socket
import smtplib
import ssl
import sys
import threading
import time
import uuid
from datetime import datetime, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, Response, flash, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.getenv("PULSECHECK_DB_PATH", str(BASE_DIR / "pulsecheck.db")))
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 587, 993, 995, 8080, 8443, 8444, 3306, 5432, 27017, 3000, 9000]
HTTPS_PORTS = {443, 8443, 8444}
DEFAULT_PORT = int(os.getenv("PULSECHECK_PORT", "8182"))
EXPLICIT_DEBUG = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "pulsecheck-local-dev"
app.config["TEMPLATES_AUTO_RELOAD"] = True
IMPORT_STATE = {}
IMPORT_LOCK = threading.Lock()


class ImportCancelled(Exception):
    pass


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS domains (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            match TEXT NOT NULL DEFAULT '',
            url_path TEXT NOT NULL DEFAULT '',
            comment TEXT NOT NULL DEFAULT '',
            paused INTEGER NOT NULL DEFAULT 0,
            ports TEXT NOT NULL DEFAULT '[]',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS port_checks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain_id INTEGER NOT NULL,
            port INTEGER NOT NULL,
            is_online INTEGER NOT NULL,
            status TEXT NOT NULL DEFAULT 'offline',
            last_response_ms INTEGER,
            checked_at TEXT NOT NULL,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
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
    domain_columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
    if "match" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN match TEXT NOT NULL DEFAULT ''")
    if "url_path" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN url_path TEXT NOT NULL DEFAULT ''")
    if "comment" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN comment TEXT NOT NULL DEFAULT ''")
    if "paused" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN paused INTEGER NOT NULL DEFAULT 0")
    conn.execute(
        "UPDATE domains SET match = lower(substr(name, 1, instr(name || '.', '.') - 1)) "
        "WHERE match = ''"
    )
    rows = conn.execute("SELECT id, name FROM domains WHERE match LIKE '%-%'").fetchall()
    for row in rows:
        conn.execute("UPDATE domains SET match = ? WHERE id = ?", (derive_match(row["name"]), row["id"]))
    port_check_columns = {row["name"] for row in conn.execute("PRAGMA table_info(port_checks)")}
    if "status" not in port_check_columns:
        conn.execute("ALTER TABLE port_checks ADD COLUMN status TEXT NOT NULL DEFAULT 'offline'")
    conn.execute("UPDATE port_checks SET status = 'online' WHERE status = 'offline' AND is_online = 1")
    conn.commit()
    conn.close()


def normalize_domain(value: str) -> str:
    cleaned = value.strip().lower()
    if cleaned.startswith("http://"):
        cleaned = cleaned.replace("http://", "", 1)
    if cleaned.startswith("https://"):
        cleaned = cleaned.replace("https://", "", 1)
    cleaned = cleaned.split("/")[0].strip().strip(".")
    if not cleaned:
        raise ValueError("Domain name cannot be empty.")
    return cleaned


def derive_match(domain_name: str) -> str:
    first_label = normalize_domain(domain_name).split(".", 1)[0]
    return first_label.split("-", 1)[0]


def normalize_url_path(value: str | None) -> str:
    path = (value or "").strip()
    if not path:
        return ""
    if not path.startswith("/") or any(character.isspace() for character in path):
        raise ValueError("URL path must start with '/' and contain no spaces.")
    if "?" in path or "#" in path or "://" in path:
        raise ValueError("URL path must contain only a path, without query, fragment, or full URL.")
    return path


def format_local_time(value: str | None) -> str | None:
    if not value:
        return None
    try:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S %Z").replace(tzinfo=timezone.utc)
    except ValueError:
        parsed = datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")


def parse_ports(value):
    values = json.loads(value or "[]")
    return sorted({int(port) for port in values})


def domain_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, match, url_path, comment, paused, ports, created_at FROM domains ORDER BY name ASC"
    ).fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "match": row["match"],
            "url_path": row["url_path"],
            "comment": row["comment"] if "comment" in row.keys() else "",
            "paused": bool(row["paused"]),
            "ports": parse_ports(row["ports"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_domain_by_id(domain_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, match, url_path, comment, paused, ports, created_at FROM domains WHERE id = ?",
        (domain_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
        "match": row["match"],
        "url_path": row["url_path"],
        "comment": row["comment"] if "comment" in row.keys() else "",
        "paused": bool(row["paused"]),
        "ports": parse_ports(row["ports"]),
        "created_at": row["created_at"],
    }


def domain_exists(domain_name: str):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id FROM domains WHERE name = ?",
        (domain_name,),
    ).fetchone()
    conn.close()
    return row is not None


def discover_ports(domain_name: str, progress_callback=None, cancelled_check=None):
    found_ports = []
    for port in COMMON_PORTS:
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")
        if progress_callback is not None:
            progress_callback({
                "domain": domain_name,
                "port": port,
                "message": f"Testing port {port} for {domain_name}",
            })
        try:
            with socket.create_connection((domain_name, port), timeout=1.5):
                found_ports.append(port)
        except (socket.timeout, socket.gaierror, OSError):
            continue
    return sorted(found_ports)


def store_port_check(domain_id: int, port: int, status: str, response_ms: int | None):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO port_checks (domain_id, port, is_online, status, last_response_ms, checked_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            domain_id,
            port,
            1 if status == "online" else 0,
            status,
            response_ms,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        ),
    )
    conn.commit()
    conn.close()


def fetch_response(
    domain_name: str,
    port: int,
    scheme: str,
    url_path: str = "",
    max_redirects: int = 5,
    explicit_debug: bool = False,
):
    current_url = f"{scheme}://{domain_name}:{port}{url_path or '/'}"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    for redirect_count in range(max_redirects + 1):
        parsed = urlsplit(current_url)
        target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
        connection_class = http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        connection_kwargs = {"timeout": 2}
        if parsed.scheme == "https":
            connection_kwargs["context"] = ssl_context
        connection = connection_class(parsed.hostname, target_port, **connection_kwargs)
        error = None
        try:
            request_path = parsed.path or "/"
            if parsed.query:
                request_path += f"?{parsed.query}"
            connection.request(
                "GET",
                request_path,
                headers={"Host": parsed.hostname, "Connection": "close"},
            )
            response = connection.getresponse()
            body = response.read(16384)
            status_code = response.status
            location = response.getheader("Location")
            if explicit_debug:
                print(
                    f"[DEBUG scan fetchresponse] protocol=http domain={domain_name} port={port} "
                    f"status={status_code} current_url={current_url} "
                    f"body={body[:16384]!r}"
                )
        except Exception as exc:
            error = exc
            raise
        finally:
            if explicit_debug and error is not None:
                print(
                    f"[DEBUG scan fetchresponse] protocol={parsed.scheme} domain={parsed.hostname} "
                    f"port={target_port} error={error!r}"
                )
            connection.close()

        if status_code not in {301, 302, 303, 307, 308} or not location:
            return body, status_code, current_url
        if redirect_count == max_redirects:
            return body, status_code, current_url
        current_url = urljoin(current_url, location)

    return b"", 0, current_url


def fetch_socket_response(domain_name: str, port: int, url_path: str = ""):
    with socket.create_connection((domain_name, port), timeout=2) as connection:
        connection.sendall(
            f"GET {url_path or '/'} HTTP/1.0\r\nHost: {domain_name}\r\nConnection: close\r\n\r\n".encode()
        )
        return connection.recv(16384)


def fetch_socket_ssl_response(domain_name: str, port: int, url_path: str = ""):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((domain_name, port), timeout=2) as raw_connection:
        with context.wrap_socket(raw_connection, server_hostname=domain_name) as connection:
            connection.sendall(
                f"GET {url_path or '/'} HTTP/1.0\r\nHost: {domain_name}\r\nConnection: close\r\n\r\n".encode()
            )
            return connection.recv(16384)


def scan_domain(domain_id: int, domain_name: str, ports, match: str = "", explicit_debug: bool | None = None, url_path: str = ""):
    domain = get_domain_by_id(domain_id)
    if domain is not None and domain["paused"]:
        return
    debug_enabled = EXPLICIT_DEBUG if explicit_debug is None else explicit_debug
    if not isinstance(ports, list):
        ports = parse_ports(ports)
    for port in ports:
        start = time.monotonic()
        status = "offline"
        response_ms = None
        response = b""
        try:
            response, status_code, final_url = fetch_response(
                domain_name, port, "http", url_path, explicit_debug=debug_enabled
            )
            response_ms = int((time.monotonic() - start) * 1000)
            if debug_enabled:
                print(
                    f"[DEBUG scan] protocol=http domain={domain_name} port={port} "
                    f"status={status_code} url={final_url} match={match!r} "
                    f"response={response[:16384]!r}"
                )
        except (socket.timeout, socket.gaierror, OSError, http.client.HTTPException):
            response = b""

        if debug_enabled and response:
            print(
                f"[DEBUG scan response] protocol=http domain={domain_name} port={port} "
                f"response={response[:16384]!r}"
            )

        match_bytes = match.lower().encode()
        if response and match_bytes in response.lower():
            status = "online"
        elif port in HTTPS_PORTS:
            try:
                https_response, status_code, final_url = fetch_response(
                    domain_name, port, "https", url_path, explicit_debug=debug_enabled
                )
                response_ms = int((time.monotonic() - start) * 1000)
                if debug_enabled:
                    print(
                        f"[DEBUG scan] protocol=https domain={domain_name} port={port} "
                        f"status={status_code} url={final_url} match={match!r} "
                        f"response={https_response[:16384]!r}"
                    )
                if https_response and match_bytes in https_response.lower():
                    status = "online"
                elif https_response:
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError, ssl.SSLError, http.client.HTTPException):
                pass
            if status == "offline":
                status = "degraded"
        elif response:
            status = "degraded"

        if status != "online":
            try:
                socket_response = fetch_socket_response(domain_name, port, url_path)
                response_ms = int((time.monotonic() - start) * 1000)
                if debug_enabled:
                    print(
                        f"[DEBUG scan] protocol=socket domain={domain_name} port={port} "
                        f"match={match!r} response={socket_response[:16384]!r}"
                    )
                if socket_response and match_bytes in socket_response.lower():
                    status = "online"
                elif socket_response and status == "offline":
                    status = "degraded"
            except (socket.timeout, socket.gaierror, OSError):
                try:
                    ssl_socket_response = fetch_socket_ssl_response(domain_name, port, url_path)
                    response_ms = int((time.monotonic() - start) * 1000)
                    if debug_enabled:
                        print(
                            f"[DEBUG scan] protocol=socket-ssl domain={domain_name} port={port} "
                            f"match={match!r} response={ssl_socket_response[:16384]!r}"
                        )
                    if ssl_socket_response and match_bytes in ssl_socket_response.lower():
                        status = "online"
                    elif ssl_socket_response and status == "offline":
                        status = "degraded"
                except (socket.timeout, socket.gaierror, OSError, ssl.SSLError):
                    pass
        store_port_check(domain_id, port, status, response_ms)


def sync_domain_ports(domain_id: int, domain_name: str, detected_ports: list[int] | None = None):
    ports = detected_ports if detected_ports is not None else discover_ports(domain_name)
    conn = get_db_connection()
    conn.execute(
        "UPDATE domains SET ports = ? WHERE id = ?",
        (json.dumps(sorted({int(port) for port in ports})), domain_id),
    )
    conn.commit()
    conn.close()
    domain = get_domain_by_id(domain_id)
    scan_domain(
        domain_id,
        domain_name,
        ports,
        domain["match"] if domain else derive_match(domain_name),
        url_path=domain["url_path"] if domain else "",
    )


def add_domain(
    domain_name: str,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool = False,
    comment: str = "",
):
    normalized = normalize_domain(domain_name)
    if domain_exists(normalized):
        return None
    domain_match = (match or derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    detected = []
    if not paused:
        detected = discover_ports(normalized)
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO domains (name, match, url_path, comment, paused, ports) VALUES (?, ?, ?, ?, ?, ?)",
        (normalized, domain_match, normalized_path, (comment or "").strip(), int(paused), json.dumps(detected)),
    )
    conn.commit()
    domain_id = cursor.lastrowid
    conn.close()
    if detected and not paused:
        scan_domain(domain_id, normalized, detected, domain_match, url_path=normalized_path)
    return domain_id


def import_domain_names(domain_names, progress_callback=None, cancelled_check=None):
    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "duplicates": [],
        "invalid": [],
    }

    entries = [str(value).strip() for value in domain_names if str(value).strip()]
    total = len(entries)
    for index, value in enumerate(entries, start=1):
        summary["total"] += 1
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")
        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "domain": value,
                "port": None,
                "status": "checking",
                "message": f"Checking domain {index} of {total}: {value}",
            })
        try:
            normalized = normalize_domain(value)
        except ValueError:
            summary["invalid"].append(value)
            summary["skipped"] += 1
            continue

        if domain_exists(normalized):
            summary["duplicates"].append(normalized)
            summary["skipped"] += 1
            continue

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "domain": normalized,
                "port": None,
                "status": "scanning",
                "message": f"Scanning ports for {normalized}",
            })

        detected = discover_ports(
            normalized,
            progress_callback=lambda info, domain=normalized: progress_callback({
                "index": index,
                "total": total,
                "domain": domain,
                "port": info["port"],
                "status": "port",
                "message": info["message"],
            }) if progress_callback else None,
            cancelled_check=cancelled_check,
        )

        conn = get_db_connection()
        cursor = conn.execute(
                "INSERT INTO domains (name, match, url_path, paused, ports) VALUES (?, ?, ?, 0, ?)",
                (normalized, derive_match(normalized), "", json.dumps(detected)),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()
        scan_domain(domain_id, normalized, detected, derive_match(normalized), url_path="")
        summary["imported"] += 1

    return summary


def parse_csv_ports(value: str) -> list[int] | None:
    clean = (value or "").strip().strip("[]()")
    if not clean:
        return None
    ports = []
    for part in re.split(r"[,;\s]+", clean):
        if part.strip():
            try:
                p = int(part.strip())
                if 1 <= p <= 65535:
                    ports.append(p)
            except ValueError:
                pass
    return sorted(set(ports)) if ports else None


def export_domains_csv() -> tuple[str, int]:
    domains = domain_list()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Domain", "Match", "URL path", "Paused", "Ports"])
    for d in domains:
        ports_str = ", ".join(str(p) for p in d["ports"])
        writer.writerow([
            d["name"],
            d["match"],
            d["url_path"],
            "1" if d["paused"] else "0",
            ports_str,
        ])
    return output.getvalue(), len(domains)


def import_domains_from_csv(
    csv_content: str,
    progress_callback=None,
    cancelled_check=None,
) -> dict:
    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "invalid": 0,
        "imported_domains": [],
        "skipped_domains": [],
        "invalid_rows": [],
    }

    raw_rows = [r for r in csv.reader(io.StringIO(csv_content)) if r and any(cell.strip() for cell in r)]
    if not raw_rows:
        return summary

    header = None
    col_map = {}
    data_rows = []

    first_cells = [c.strip().lower() for c in raw_rows[0]]
    if any(h in first_cells for h in ("domain", "domain name", "name")):
        header = first_cells
        for idx, col in enumerate(header):
            if col in ("domain", "domain name", "name"):
                col_map["domain"] = idx
            elif col in ("match", "domain match"):
                col_map["match"] = idx
            elif col in ("url path", "url_path", "path", "url"):
                col_map["url_path"] = idx
            elif col in ("comment", "comments", "note", "notes"):
                col_map["comment"] = idx
            elif col in ("paused", "is_paused"):
                col_map["paused"] = idx
            elif col in ("ports", "port", "monitored ports"):
                col_map["ports"] = idx
        data_rows = raw_rows[1:]
    else:
        col_map = {"domain": 0, "match": 1, "url_path": 2, "paused": 3, "ports": 4}
        data_rows = raw_rows

    total_records = len(data_rows)

    for index, row in enumerate(data_rows, start=1):
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled("Import cancelled")

        summary["total"] += 1
        d_idx = col_map.get("domain", 0)
        domain_val = row[d_idx].strip() if d_idx < len(row) else ""

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total_records,
                "domain": domain_val or f"Record {index}",
                "status": "processing",
                "message": f"Processing record {index} of {total_records}: {domain_val}",
            })

        if not domain_val or any(c.isspace() for c in domain_val):
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid domain '{domain_val}'")
            continue

        try:
            normalized = normalize_domain(domain_val)
        except ValueError:
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid domain '{domain_val}'")
            continue

        if domain_exists(normalized):
            summary["skipped"] += 1
            summary["skipped_domains"].append(normalized)
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

        pts_idx = col_map.get("ports", -1)
        ports_raw = row[pts_idx].strip() if pts_idx != -1 and pts_idx < len(row) else ""
        ports_val = parse_csv_ports(ports_raw) or []

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO domains (name, match, url_path, comment, paused, ports) VALUES (?, ?, ?, ?, ?, ?)",
            (normalized, match_val, url_path_val, comment_val, int(paused_val), json.dumps(ports_val)),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()

        if not paused_val and ports_val:
            if progress_callback is not None:
                progress_callback({
                    "index": index,
                    "total": total_records,
                    "domain": normalized,
                    "status": "scanning",
                    "message": f"Scanning ports for {normalized} ({', '.join(str(p) for p in ports_val)})",
                })
            scan_domain(domain_id, normalized, ports_val, match_val, url_path=url_path_val)

        summary["imported"] += 1
        summary["imported_domains"].append(normalized)

    return summary


def update_domain(
    domain_id: int,
    name: str,
    ports_input: str,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool | None = None,
    comment: str | None = None,
):
    normalized = normalize_domain(name)
    domain_match = (match or derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    existing_domain = None
    if paused is None or comment is None:
        existing_domain = get_domain_by_id(domain_id)

    if paused is None:
        paused = existing_domain["paused"] if existing_domain else False

    if comment is None:
        comment_val = existing_domain["comment"] if existing_domain and "comment" in existing_domain.keys() else ""
    else:
        comment_val = str(comment).strip()

    incoming_ports = []
    if ports_input:
        raw_parts = ports_input.replace(",", "\n").splitlines()
        for part in raw_parts:
            value = part.strip()
            if not value:
                continue
            try:
                incoming_ports.append(int(value))
            except ValueError:
                raise ValueError(f"Invalid port value '{value}'")
    conn = get_db_connection()
    conn.execute(
        "UPDATE domains SET name = ?, match = ?, url_path = ?, comment = ?, paused = ?, ports = ? WHERE id = ?",
        (
            normalized,
            domain_match,
            normalized_path,
            comment_val,
            int(paused),
            json.dumps(sorted({int(port) for port in incoming_ports})),
            domain_id,
        ),
    )
    conn.commit()
    conn.close()
    if incoming_ports and not paused:
        scan_domain(domain_id, normalized, incoming_ports, domain_match, url_path=normalized_path)


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


def bulk_update_ports(domain_ids, action: str, ports_input: str):
    ports = parse_port_values(ports_input)
    if not domain_ids:
        raise ValueError("Select at least one domain.")
    if action not in {"add", "remove"}:
        raise ValueError("Choose whether to add or remove ports.")
    if not ports:
        raise ValueError("Enter at least one port.")

    conn = get_db_connection()
    placeholders = ", ".join("?" for _ in domain_ids)
    rows = conn.execute(
        f"SELECT id, ports FROM domains WHERE id IN ({placeholders})",
        tuple(domain_ids),
    ).fetchall()
    found_ids = {row["id"] for row in rows}
    if found_ids != set(domain_ids):
        conn.close()
        raise ValueError("One or more selected domains no longer exists.")

    for row in rows:
        current_ports = set(parse_ports(row["ports"]))
        if action == "add":
            updated_ports = current_ports.union(ports)
        else:
            updated_ports = current_ports.difference(ports)
        conn.execute(
            "UPDATE domains SET ports = ? WHERE id = ?",
            (json.dumps(sorted(updated_ports)), row["id"]),
        )
        if action == "remove":
            port_placeholders = ", ".join("?" for _ in ports)
            conn.execute(
                f"DELETE FROM port_checks WHERE domain_id = ? AND port IN ({port_placeholders})",
                (row["id"], *ports),
            )
    conn.commit()
    conn.close()


def delete_domain(domain_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM port_checks WHERE domain_id = ?", (domain_id,))
    conn.execute("DELETE FROM domains WHERE id = ?", (domain_id,))
    conn.commit()
    conn.close()


def get_status_rows():
    conn = get_db_connection()
    rows = conn.execute(
        """
        WITH latest AS (
            SELECT domain_id, port, is_online, status, last_response_ms, checked_at,
                   ROW_NUMBER() OVER (PARTITION BY domain_id, port ORDER BY checked_at DESC) AS rn
            FROM port_checks
        )
         SELECT d.id, d.name, d.match, d.ports, latest.port, latest.is_online,
             COALESCE(latest.status, CASE WHEN latest.is_online = 1 THEN 'online' ELSE 'offline' END) AS status,
             latest.last_response_ms, latest.checked_at
        FROM domains d
        LEFT JOIN latest ON latest.domain_id = d.id AND latest.rn = 1 AND instr(d.ports, port) > 0
        WHERE d.paused = 0
        ORDER BY d.name, latest.port
        """
    ).fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            "id": row["id"],
            "name": row["name"],
            "match": row["match"],
            "ports": parse_ports(row["ports"]),
            "port": row["port"],
            "is_online": bool(row["is_online"]),
            "status": row["status"],
            "last_response_ms": row["last_response_ms"],
            "checked_at": row["checked_at"],
            "checked_at_local": format_local_time(row["checked_at"]),
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
            val_to_save = str(value) if key == "smtp_password" else str(value).strip()
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

    actual_logo_path = Path(logo_path) if logo_path else (BASE_DIR / "static" / "logo.png")

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
    <div style="background: #0f172a; padding: 18px 24px;">
      <table cellpadding="0" cellspacing="0" border="0" style="vertical-align: middle;">
        <tr>
          <td style="vertical-align: middle; padding-right: 12px;">
            <img src="cid:pulsecheck_logo" alt="PulseCheck Logo" width="36" height="36" style="display: block; border-radius: 8px;" />
          </td>
          <td style="vertical-align: middle;">
            <span style="color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: -0.5px;">PulseCheck</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding: 24px; font-size: 15px; line-height: 1.6; color: #1d2433;">
      {content_html}
    </div>
    <div style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center;">
      PulseCheck &bull; Network &amp; Domain Monitoring
    </div>
  </div>
</body>
</html>"""

    msg.add_alternative(html_body, subtype="html")

    if actual_logo_path and actual_logo_path.exists():
        try:
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


def create_import_session(domain_names):
    token = uuid.uuid4().hex
    with IMPORT_LOCK:
        IMPORT_STATE[token] = {
            "status": "queued",
            "token": token,
            "index": 0,
            "total": len([line for line in domain_names if str(line).strip()]),
            "domain": None,
            "port": None,
            "message": "Preparing import",
            "cancelled": False,
            "summary": None,
            "finished": False,
            "error": None,
        }
    thread = threading.Thread(
        target=run_import_worker,
        args=(token, domain_names),
        daemon=True,
    )
    thread.start()
    return token


def update_import_state(token, **updates):
    state = IMPORT_STATE.setdefault(token, {"status": "queued"})
    state.update(updates)
    return state


def run_import_worker(token, domain_names):
    state = IMPORT_STATE.get(token)
    if state is None:
        return

    def progress(info):
        state = IMPORT_STATE.get(token)
        if not state:
            return
        state["status"] = info.get("status", state["status"])
        state["index"] = info.get("index", state.get("index", 0))
        state["total"] = info.get("total", state.get("total", 0))
        state["domain"] = info.get("domain", state.get("domain"))
        state["port"] = info.get("port")
        state["message"] = info.get("message", state.get("message", "Working"))

    def cancelled_check():
        state = IMPORT_STATE.get(token)
        return bool(state and state.get("cancelled"))

    state["status"] = "running"
    try:
        summary = import_domain_names(
            domain_names,
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
    has_header = any(h in first_cells for h in ("domain", "domain name", "name"))
    total_records = max(len(raw_rows) - 1, 0) if has_header else len(raw_rows)

    with IMPORT_LOCK:
        IMPORT_STATE[token] = {
            "status": "queued",
            "token": token,
            "index": 0,
            "total": total_records,
            "domain": None,
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
        st["domain"] = info.get("domain", st.get("domain"))
        st["port"] = info.get("port")
        st["message"] = info.get("message", st.get("message", "Working"))

    def cancelled_check():
        st = IMPORT_STATE.get(token)
        return bool(st and st.get("cancelled"))

    state["status"] = "running"
    try:
        summary = import_domains_from_csv(
            csv_content,
            progress_callback=progress,
            cancelled_check=cancelled_check,
        )
        state["status"] = "complete"
        state["summary"] = summary
    except ImportCancelled:
        state["status"] = "cancelled"
        state["summary"] = {"cancelled": True}
    except Exception as exc:
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
                summary = import_domains_from_csv(content)
                flash(
                    f"CSV Import complete: {summary['imported']} imported, {summary['skipped']} skipped (already in database), {summary['invalid']} invalid (Total rows: {summary['total']}).",
                    "success" if summary["imported"] > 0 else "message",
                )
            except Exception as exc:
                flash(f"Error processing CSV file: {exc}", "error")
            return redirect(url_for("handle_import"))

        raw_text = request.form.get("domains", "")
        items = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not items:
            flash("No domain names or CSV file were supplied.", "error")
            return redirect(url_for("handle_import"))

        summary = import_domain_names(items)
        flash(
            f"Imported {summary['imported']} domains; skipped {summary['skipped']} duplicate or invalid entries.",
            "success",
        )
        return redirect(url_for("domains"))

    domains = domain_list()
    return render_template("import.html", domain_count=len(domains))


@app.route("/import/export", methods=["GET"])
@app.route("/domains/export.csv", methods=["GET"])
def export_domains_route():
    csv_content, count = export_domains_csv()
    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=pulsecheck_domains.csv"
    response.headers["X-Exported-Count"] = str(count)
    return response


@app.route("/import/start", methods=["POST"])
def start_import():
    raw_text = request.form.get("domains", "")
    items = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not items:
        return {"error": "No domain names were supplied."}, 400

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
    response = {
        "status": state.get("status"),
        "index": state.get("index", 0),
        "total": state.get("total", 0),
        "domain": state.get("domain"),
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


@app.route("/domains")
def domains():
    return render_template("domains.html", domains=domain_list())


@app.route("/domains/add", methods=["GET", "POST"])
def add_domain_route():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        comment = request.form.get("comment", "").strip()
        if not name:
            flash("A domain name is required.")
            return redirect(url_for("add_domain_route"))
        try:
            result = add_domain(name, match or None, request.form.get("url_path", ""), comment=comment)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("add_domain_route"))
        if result is None:
            flash("That domain already exists.")
            return redirect(url_for("domains"))
        flash(f"Added domain {name}.")
        return redirect(url_for("domains"))
    return render_template("domains.html", domains=domain_list(), add_mode=True)


@app.route("/domains/bulk-ports", methods=["POST"])
def bulk_ports_route():
    raw_ids = request.form.getlist("domain_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (return_to.startswith("/domains") or return_to.startswith("domains")):
        return_to = ""
    try:
        domain_ids = sorted({int(value) for value in raw_ids})
        bulk_update_ports(
            domain_ids,
            request.form.get("port_action", ""),
            request.form.get("ports", ""),
        )
    except (TypeError, ValueError) as exc:
        flash(str(exc))
        return redirect(return_to or url_for("domains"))
    flash("Updated ports for the selected domains.")
    return redirect(return_to or url_for("domains"))


@app.route("/domains/bulk-delete", methods=["POST"])
def bulk_delete_route():
    raw_ids = request.form.getlist("domain_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (return_to.startswith("/domains") or return_to.startswith("domains")):
        return_to = ""
    try:
        domain_ids = sorted({int(value) for value in raw_ids})
    except ValueError:
        flash("Invalid domain selection.")
        return redirect(return_to or url_for("domains"))
    if not domain_ids:
        flash("Select at least one domain to delete.")
        return redirect(return_to or url_for("domains"))

    deleted = 0
    for domain_id in domain_ids:
        if get_domain_by_id(domain_id) is not None:
            delete_domain(domain_id)
            deleted += 1
    flash(f"Deleted {deleted} selected domain{'s' if deleted != 1 else ''}.")
    return redirect(return_to or url_for("domains"))


@app.route("/domains/<int:domain_id>/edit", methods=["GET", "POST"])
def edit_domain(domain_id):
    domain = get_domain_by_id(domain_id)
    if domain is None:
        flash("Domain not found.")
        return redirect(url_for("domains"))

    return_to = request.args.get("return_to") or request.form.get("return_to") or ""
    if not (return_to.startswith("/domains") or return_to.startswith("domains")):
        return_to = ""

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        url_path = request.form.get("url_path", "")
        comment = request.form.get("comment", "").strip()
        ports_input = request.form.get("ports", "")
        paused = request.form.get("paused") == "on"
        try:
            update_domain(domain_id, name, ports_input, match or None, url_path, paused, comment=comment)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("edit_domain", domain_id=domain_id, return_to=return_to))
        flash(f"Updated domain {name}.")
        return redirect(return_to or url_for("domains"))

    return render_template("edit_domain.html", domain=domain, return_to=return_to)


@app.route("/domains/<int:domain_id>/delete", methods=["POST"])
def delete_domain_route(domain_id):
    domain = get_domain_by_id(domain_id)
    return_to = request.form.get("return_to") or request.args.get("return_to") or ""
    if not (return_to.startswith("/domains") or return_to.startswith("domains")):
        return_to = ""
    if domain is not None:
        delete_domain(domain_id)
        flash(f"Deleted domain {domain['name']}.")
    return redirect(return_to or url_for("domains"))


@app.route("/domains/<int:domain_id>/rescan", methods=["POST"])
def rescan_domain_route(domain_id):
    domain = get_domain_by_id(domain_id)
    if domain is None:
        flash("Domain not found.")
        return redirect(url_for("domains"))
    scan_domain(domain_id, domain["name"], domain["ports"], domain["match"], url_path=domain["url_path"])
    flash(f"Rescanned {domain['name']}.")
    return redirect(url_for("status"))


@app.route("/status")
def status():
    rows = get_status_rows()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["name"], []).append(row)
    return render_template("status.html", grouped=grouped)


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
        }
        if not updated["smtp_password"] and current_settings.get("smtp_password"):
            updated["smtp_password"] = current_settings["smtp_password"]

        save_settings(updated)

        if action == "test":
            dest = updated["recipient_email"]
            if not dest:
                flash("Destination email address is required to send a test message.", "error")
            else:
                now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                test_body = (
                    "Hello from PulseCheck!\n\n"
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


def run_background_tasks():
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(check_all_domains, "interval", minutes=10, id="pulsecheck_scan")
    scheduler.start()
    return scheduler


def compute_overall_status(port_statuses: dict[int, str]) -> str:
    if not port_statuses:
        return "none"
    statuses = list(port_statuses.values())
    if all(s == "online" for s in statuses):
        return "online"
    if all(s == "offline" for s in statuses):
        return "offline"
    return "degraded"


def get_domain_snapshots() -> dict[int, dict]:
    rows = get_status_rows()
    domains: dict[int, dict] = {}
    for row in rows:
        d_id = row["id"]
        if d_id not in domains:
            domains[d_id] = {
                "id": d_id,
                "name": row["name"],
                "has_checks": False,
                "port_statuses": {},
            }
        if row["port"] is not None and row["checked_at"] is not None:
            domains[d_id]["has_checks"] = True
            domains[d_id]["port_statuses"][row["port"]] = row["status"]

    for d_id, d_data in domains.items():
        d_data["overall_status"] = compute_overall_status(d_data["port_statuses"])

    return domains


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
    subject = f"[PulseCheck] State Change Alert: {count} domain{'s' if count > 1 else ''} updated"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines = [
        "PulseCheck Domain State Change Alert",
        "====================================",
        f"Scan Completed: {now_str}",
        "",
        f"The following {count} domain{'s have' if count > 1 else ' has'} changed state since the previous scan:",
        "",
    ]

    for item in changes:
        lines.append(f"• Domain: {item['domain']}")
        lines.append(f"  Overall Status: {item['old_status'].upper()} -> {item['new_status'].upper()}")
        if item.get("port_changes"):
            lines.append("  Port Details:")
            for p_change in item["port_changes"]:
                lines.append(f"    - {p_change}")
        lines.append("")

    lines.append("---")
    lines.append(f"View live status at: http://127.0.0.1:{DEFAULT_PORT}/status")

    body = "\n".join(lines)

    cards_html = []
    for item in changes:
        old_st = item["old_status"].upper()
        new_st = item["new_status"].upper()
        badge_color = "#059669" if new_st == "UP" else ("#dc2626" if new_st == "DOWN" else "#d97706")
        ports_html = ""
        if item.get("port_changes"):
            p_items = "".join(f"<li style='margin: 2px 0;'>{p}</li>" for p in item["port_changes"])
            ports_html = f"<div style='margin-top: 8px; font-size: 13px; color: #475569;'><strong>Port Details:</strong><ul style='margin: 4px 0 0 18px; padding: 0;'>{p_items}</ul></div>"
        cards_html.append(
            f"""<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; background: #ffffff;">
  <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
    <strong style="font-size: 16px; color: #0f172a;">{item['domain']}</strong>
    <span style="display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; background: {badge_color}; color: #ffffff;">{new_st}</span>
  </div>
  <div style="font-size: 14px; color: #334155;">Status changed from <strong>{old_st}</strong> to <strong>{new_st}</strong></div>
  {ports_html}
</div>"""
        )

    domain_cards_str = "\n".join(cards_html)
    html_body = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>{subject}</title>
</head>
<body style="margin: 0; padding: 24px 16px; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f5f7fb; color: #1d2433;">
  <div style="max-width: 600px; margin: 0 auto; background: #ffffff; border-radius: 12px; border: 1px solid #d6dbeb; overflow: hidden; box-shadow: 0 4px 12px rgba(0, 0, 0, 0.05);">
    <div style="background: #0f172a; padding: 18px 24px;">
      <table cellpadding="0" cellspacing="0" border="0" style="vertical-align: middle;">
        <tr>
          <td style="vertical-align: middle; padding-right: 12px;">
            <img src="cid:pulsecheck_logo" alt="PulseCheck Logo" width="36" height="36" style="display: block; border-radius: 8px;" />
          </td>
          <td style="vertical-align: middle;">
            <span style="color: #ffffff; font-size: 20px; font-weight: 700; letter-spacing: -0.5px;">PulseCheck</span>
          </td>
        </tr>
      </table>
    </div>
    <div style="padding: 24px;">
      <h2 style="margin: 0 0 8px 0; font-size: 18px; color: #0f172a;">Domain State Change Alert</h2>
      <p style="margin: 0 0 16px 0; font-size: 13px; color: #64748b;">Scan completed: {now_str}</p>
      <p style="margin: 0 0 16px 0; font-size: 14px; color: #334155;">The following <strong>{count}</strong> domain{'s have' if count > 1 else ' has'} changed state since the previous scan:</p>
      {domain_cards_str}
      <div style="margin-top: 20px; text-align: center;">
        <a href="http://127.0.0.1:{DEFAULT_PORT}/status" style="display: inline-block; background: #1145d6; color: #ffffff; text-decoration: none; padding: 10px 20px; border-radius: 6px; font-weight: 600; font-size: 14px;">View Live Status</a>
      </div>
    </div>
    <div style="background: #f8fafc; padding: 14px 24px; border-top: 1px solid #e2e8f0; font-size: 12px; color: #64748b; text-align: center;">
      PulseCheck &bull; Network &amp; Domain Monitoring
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


def check_all_domains() -> list[dict]:
    before_snapshots = get_domain_snapshots()

    for domain in domain_list():
        if not domain["paused"]:
            scan_domain(domain["id"], domain["name"], domain["ports"], domain["match"], url_path=domain["url_path"])

    after_snapshots = get_domain_snapshots()
    changes = []

    for domain_id, after_info in after_snapshots.items():
        before_info = before_snapshots.get(domain_id)
        if not before_info or not before_info["has_checks"]:
            continue

        port_changes = []
        for port, new_status in after_info["port_statuses"].items():
            old_status = before_info["port_statuses"].get(port)
            if old_status and old_status != new_status:
                port_changes.append(f"Port {port}: {old_status.upper()} -> {new_status.upper()}")

        if before_info["overall_status"] != after_info["overall_status"] or port_changes:
            changes.append({
                "domain": after_info["name"],
                "old_status": before_info["overall_status"],
                "new_status": after_info["overall_status"],
                "port_changes": port_changes,
            })

    if changes:
        send_state_change_notification(changes)

    return changes


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Import domain list")
        print("2. Maintain domains")
        print("3. View status")
        print("4. Email & SMTP settings")
        print("5. Start web app")
        print("6. Start web with Explicit debugging")
        print("7. Exit")
        choice = input("Select an option: ").strip()

        if choice == "1":
            print("Enter one domain per line. Leave the line blank to finish.")
            values = []
            while True:
                item = input("domain> ")
                if not item.strip():
                    break
                values.append(item)
            for value in values:
                try:
                    normalized = normalize_domain(value)
                    if add_domain(normalized) is None:
                        print(f"Skipped duplicate: {normalized}")
                    else:
                        print(f"Imported {normalized}")
                except ValueError:
                    print(f"Skipped invalid domain: {value}")

        elif choice == "2":
            entries = domain_list()
            if not entries:
                print("No domains saved yet.")
                continue
            print("Saved domains:")
            for entry in entries:
                ports = ", ".join(str(port) for port in entry["ports"]) or "none"
                comment_suffix = f" ({entry['comment']})" if entry.get("comment") else ""
                print(f"- {entry['id']}: {entry['name']} [{ports}]{comment_suffix}")

            selection = input("Enter domain id to edit, or 'd' to delete, or blank to return: ").strip()
            if not selection:
                continue
            if selection.lower() == "d":
                domain_id = input("Delete which id? ").strip()
                try:
                    delete_domain(int(domain_id))
                    print("Domain deleted.")
                except ValueError:
                    print("Invalid id")
                continue
            try:
                domain_id = int(selection)
            except ValueError:
                print("Invalid selection")
                continue
            domain = get_domain_by_id(domain_id)
            if domain is None:
                print("Domain not found.")
                continue
            new_name = input(f"New domain name [{domain['name']}]: ").strip() or domain["name"]
            ports_value = input(f"Ports [{', '.join(str(port) for port in domain['ports'])}] : ").strip()
            comment_input = input(f"Comment [{domain.get('comment', '')}]: ").strip()
            comment_val = comment_input if comment_input else domain.get("comment", "")
            try:
                update_domain(domain_id, new_name, ports_value, comment=comment_val)
                print("Domain updated.")
            except ValueError as exc:
                print(f"Update failed: {exc}")

        elif choice == "3":
            rows = get_status_rows()
            if not rows:
                print("No domain status data yet.")
                continue
            for row in rows:
                port_label = "-" if row["port"] is None else str(row["port"])
                state = "ONLINE" if row["is_online"] else "OFFLINE"
                last_success = "never"
                if row["is_online"]:
                    last_success = row["checked_at"]
                print(f"{row['name']} port {port_label}: {state}; last success: {last_success}")

        elif choice == "4":
            settings = get_settings()
            print("\nCurrent Email & SMTP Settings:")
            print(f"- SMTP Host: {settings['smtp_host'] or '(not set)'}")
            print(f"- SMTP Port: {settings['smtp_port']}")
            print(f"- Security: {settings['smtp_security']}")
            print(f"- Username: {settings['smtp_username'] or '(not set)'}")
            print(f"- Password: {'********' if settings['smtp_password'] else '(not set)'}")
            print(f"- Sender (From): {settings['from_email'] or '(not set)'}")
            print(f"- Destination Email: {settings['recipient_email'] or '(not set)'}")
            print("\nOptions: [e]dit settings, [t]est email, or press Enter to return.")
            sub_choice = input("Select: ").strip().lower()
            if sub_choice == "e":
                host = input(f"SMTP Host [{settings['smtp_host']}]: ").strip()
                port = input(f"SMTP Port [{settings['smtp_port']}]: ").strip()
                security = input(f"Security (tls/ssl/none) [{settings['smtp_security']}]: ").strip().lower()
                username = input(f"Username [{settings['smtp_username']}]: ").strip()
                pwd = input("Password (leave blank to keep current): ").strip()
                from_addr = input(f"From Email [{settings['from_email']}]: ").strip()
                dest_addr = input(f"Destination Email [{settings['recipient_email']}]: ").strip()

                updated = {
                    "smtp_host": host or settings["smtp_host"],
                    "smtp_port": port or settings["smtp_port"],
                    "smtp_security": security if security in ("tls", "ssl", "none") else settings["smtp_security"],
                    "smtp_username": username or settings["smtp_username"],
                    "smtp_password": pwd if pwd else settings["smtp_password"],
                    "from_email": from_addr or settings["from_email"],
                    "recipient_email": dest_addr or settings["recipient_email"],
                }
                save_settings(updated)
                print("Settings updated successfully.")
            elif sub_choice == "t":
                dest = settings["recipient_email"]
                if not dest:
                    dest = input("Enter destination email for test: ").strip()
                if dest:
                    print(f"Sending test email to {dest}...")
                    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                    success, msg = send_email(
                        dest,
                        "[PulseCheck] SMTP Test Message",
                        f"Hello from PulseCheck CLI!\n\nThis is a test message verifying SMTP configuration.\n\nTimestamp: {now_str}",
                        settings=settings,
                    )
                    print(msg)
                else:
                    print("No destination email provided.")

        elif choice == "5":
            print(f"Starting web application on http://127.0.0.1:{DEFAULT_PORT}")
            app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
            break

        elif choice == "6":
            global EXPLICIT_DEBUG
            EXPLICIT_DEBUG = True
            print(f"Starting web application with explicit debugging on http://127.0.0.1:{DEFAULT_PORT}")
            app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
            break

        elif choice == "7":
            print("Exiting PulseCheck.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    init_db()
    scheduler = run_background_tasks()
    try:
        if os.getenv("PULSECHECK_HEADLESS", "").lower() in ("1", "true", "yes") or not sys.stdin.isatty():
            print(f"Starting web application on http://0.0.0.0:{DEFAULT_PORT}")
            app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
        else:
            cli_menu()
    finally:
        scheduler.shutdown(wait=False)
