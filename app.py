from __future__ import annotations

import json
import http.client
import os
import sqlite3
import socket
import ssl
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, flash, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "pulsecheck.db"
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 587, 993, 995, 8080, 8443, 8444, 3306, 5432, 27017, 3000, 9000]
HTTPS_PORTS = {443, 8443, 8444}
DEFAULT_PORT = int(os.getenv("PULSECHECK_PORT", "8182"))
EXPLICIT_DEBUG = False

app = Flask(__name__)
app.config["SECRET_KEY"] = "pulsecheck-local-dev"
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
    domain_columns = {row["name"] for row in conn.execute("PRAGMA table_info(domains)")}
    if "match" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN match TEXT NOT NULL DEFAULT ''")
    if "url_path" not in domain_columns:
        conn.execute("ALTER TABLE domains ADD COLUMN url_path TEXT NOT NULL DEFAULT ''")
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
        "SELECT id, name, match, url_path, ports, created_at FROM domains ORDER BY name ASC"
    ).fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "match": row["match"],
            "url_path": row["url_path"],
            "ports": parse_ports(row["ports"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_domain_by_id(domain_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, match, url_path, ports, created_at FROM domains WHERE id = ?",
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


def add_domain(domain_name: str, match: str | None = None, url_path: str | None = None):
    normalized = normalize_domain(domain_name)
    if domain_exists(normalized):
        return None
    domain_match = (match or derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    detected = discover_ports(normalized)
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO domains (name, match, url_path, ports) VALUES (?, ?, ?, ?)",
        (normalized, domain_match, normalized_path, json.dumps(detected)),
    )
    conn.commit()
    domain_id = cursor.lastrowid
    conn.close()
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
            "INSERT INTO domains (name, match, url_path, ports) VALUES (?, ?, ?, ?)",
            (normalized, derive_match(normalized), "", json.dumps(detected)),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()
        scan_domain(domain_id, normalized, detected, derive_match(normalized), url_path="")
        summary["imported"] += 1

    return summary


def update_domain(domain_id: int, name: str, ports_input: str, match: str | None = None, url_path: str | None = None):
    normalized = normalize_domain(name)
    domain_match = (match or derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
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
    if not incoming_ports:
        incoming_ports = discover_ports(normalized)
    conn = get_db_connection()
    conn.execute(
        "UPDATE domains SET name = ?, match = ?, url_path = ?, ports = ? WHERE id = ?",
        (normalized, domain_match, normalized_path, json.dumps(sorted({int(port) for port in incoming_ports})), domain_id),
    )
    conn.commit()
    conn.close()
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
        LEFT JOIN latest ON latest.domain_id = d.id AND latest.rn = 1
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


@app.route("/")
def index():
    domains = domain_list()
    return render_template("index.html", domains=domains)


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


@app.route("/import", methods=["GET", "POST"])
def handle_import():
    if request.method == "POST":
        raw_text = request.form.get("domains", "")
        items = [line.strip() for line in raw_text.splitlines() if line.strip()]
        if not items:
            flash("No domain names were supplied.")
            return redirect(url_for("handle_import"))

        summary = import_domain_names(items)
        flash(
            f"Imported {summary['imported']} domains; skipped {summary['skipped']} duplicate or invalid entries."
        )
        return redirect(url_for("domains"))
    return render_template("import.html")


@app.route("/import/start", methods=["POST"])
def start_import():
    raw_text = request.form.get("domains", "")
    items = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not items:
        return {"error": "No domain names were supplied."}, 400

    token = create_import_session(items)
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
        if not name:
            flash("A domain name is required.")
            return redirect(url_for("add_domain_route"))
        try:
            result = add_domain(name, match or None, request.form.get("url_path", ""))
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
    try:
        domain_ids = sorted({int(value) for value in raw_ids})
        bulk_update_ports(
            domain_ids,
            request.form.get("port_action", ""),
            request.form.get("ports", ""),
        )
    except (TypeError, ValueError) as exc:
        flash(str(exc))
        return redirect(url_for("domains"))
    flash("Updated ports for the selected domains.")
    return redirect(url_for("domains"))


@app.route("/domains/bulk-delete", methods=["POST"])
def bulk_delete_route():
    raw_ids = request.form.getlist("domain_ids")
    try:
        domain_ids = sorted({int(value) for value in raw_ids})
    except ValueError:
        flash("Invalid domain selection.")
        return redirect(url_for("domains"))
    if not domain_ids:
        flash("Select at least one domain to delete.")
        return redirect(url_for("domains"))

    deleted = 0
    for domain_id in domain_ids:
        if get_domain_by_id(domain_id) is not None:
            delete_domain(domain_id)
            deleted += 1
    flash(f"Deleted {deleted} selected domain{'s' if deleted != 1 else ''}.")
    return redirect(url_for("domains"))


@app.route("/domains/<int:domain_id>/edit", methods=["GET", "POST"])
def edit_domain(domain_id):
    domain = get_domain_by_id(domain_id)
    if domain is None:
        flash("Domain not found.")
        return redirect(url_for("domains"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        url_path = request.form.get("url_path", "")
        ports_input = request.form.get("ports", "")
        try:
            update_domain(domain_id, name, ports_input, match or None, url_path)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("edit_domain", domain_id=domain_id))
        flash(f"Updated domain {name}.")
        return redirect(url_for("domains"))

    return render_template("edit_domain.html", domain=domain)


@app.route("/domains/<int:domain_id>/delete", methods=["POST"])
def delete_domain_route(domain_id):
    domain = get_domain_by_id(domain_id)
    if domain is not None:
        delete_domain(domain_id)
        flash(f"Deleted domain {domain['name']}.")
    return redirect(url_for("domains"))


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


def run_background_tasks():
    scheduler = BackgroundScheduler(daemon=True)
    scheduler.add_job(check_all_domains, "interval", minutes=10, id="pulsecheck_scan")
    scheduler.start()
    return scheduler


def check_all_domains():
    for domain in domain_list():
        scan_domain(domain["id"], domain["name"], domain["ports"], domain["match"], url_path=domain["url_path"])


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Import domain list")
        print("2. Maintain domains")
        print("3. View status")
        print("4. Start web app")
        print("5. Start web with Explicit debugging")
        print("6. Exit")
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
                print(f"- {entry['id']}: {entry['name']} [{ports}]")

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
            try:
                update_domain(domain_id, new_name, ports_value)
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
            print(f"Starting web application on http://127.0.0.1:{DEFAULT_PORT}")
            app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
            break

        elif choice == "5":
            global EXPLICIT_DEBUG
            EXPLICIT_DEBUG = True
            print(f"Starting web application with explicit debugging on http://127.0.0.1:{DEFAULT_PORT}")
            app.run(host="0.0.0.0", port=DEFAULT_PORT, debug=False)
            break

        elif choice == "6":
            print("Exiting PulseCheck.")
            break
        else:
            print("Invalid option.")


if __name__ == "__main__":
    init_db()
    scheduler = run_background_tasks()
    try:
        cli_menu()
    finally:
        scheduler.shutdown(wait=False)
