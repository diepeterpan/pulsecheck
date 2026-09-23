from __future__ import annotations

import json
import os
import sqlite3
import socket
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask, flash, redirect, render_template, request, url_for

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "pulsecheck.db"
COMMON_PORTS = [80, 443, 22, 21, 25, 53, 110, 143, 587, 993, 995, 8080, 8443, 8444, 3306, 5432, 27017, 3000, 9000]
DEFAULT_PORT = int(os.getenv("PULSECHECK_PORT", "8182"))

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
            last_response_ms INTEGER,
            checked_at TEXT NOT NULL,
            FOREIGN KEY(domain_id) REFERENCES domains(id)
        )
        """
    )
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


def parse_ports(value):
    values = json.loads(value or "[]")
    return sorted({int(port) for port in values})


def domain_list():
    conn = get_db_connection()
    rows = conn.execute(
        "SELECT id, name, ports, created_at FROM domains ORDER BY name ASC"
    ).fetchall()
    conn.close()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "ports": parse_ports(row["ports"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def get_domain_by_id(domain_id):
    conn = get_db_connection()
    row = conn.execute(
        "SELECT id, name, ports, created_at FROM domains WHERE id = ?",
        (domain_id,),
    ).fetchone()
    conn.close()
    if row is None:
        return None
    return {
        "id": row["id"],
        "name": row["name"],
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


def store_port_check(domain_id: int, port: int, is_online: bool, response_ms: int | None):
    conn = get_db_connection()
    conn.execute(
        """
        INSERT INTO port_checks (domain_id, port, is_online, last_response_ms, checked_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (
            domain_id,
            port,
            1 if is_online else 0,
            response_ms,
            datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S %Z"),
        ),
    )
    conn.commit()
    conn.close()


def scan_domain(domain_id: int, domain_name: str, ports):
    if not isinstance(ports, list):
        ports = parse_ports(ports)
    for port in ports:
        start = time.monotonic()
        online = False
        response_ms = None
        try:
            with socket.create_connection((domain_name, port), timeout=2):
                online = True
                response_ms = int((time.monotonic() - start) * 1000)
        except (socket.timeout, socket.gaierror, OSError):
            online = False
            response_ms = None
        store_port_check(domain_id, port, online, response_ms)


def sync_domain_ports(domain_id: int, domain_name: str, detected_ports: list[int] | None = None):
    ports = detected_ports if detected_ports is not None else discover_ports(domain_name)
    conn = get_db_connection()
    conn.execute(
        "UPDATE domains SET ports = ? WHERE id = ?",
        (json.dumps(sorted({int(port) for port in ports})), domain_id),
    )
    conn.commit()
    conn.close()
    scan_domain(domain_id, domain_name, ports)


def add_domain(domain_name: str):
    normalized = normalize_domain(domain_name)
    if domain_exists(normalized):
        return None
    detected = discover_ports(normalized)
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO domains (name, ports) VALUES (?, ?)",
        (normalized, json.dumps(detected)),
    )
    conn.commit()
    domain_id = cursor.lastrowid
    conn.close()
    scan_domain(domain_id, normalized, detected)
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
            "INSERT INTO domains (name, ports) VALUES (?, ?)",
            (normalized, json.dumps(detected)),
        )
        conn.commit()
        domain_id = cursor.lastrowid
        conn.close()
        scan_domain(domain_id, normalized, detected)
        summary["imported"] += 1

    return summary


def update_domain(domain_id: int, name: str, ports_input: str):
    normalized = normalize_domain(name)
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
        "UPDATE domains SET name = ?, ports = ? WHERE id = ?",
        (normalized, json.dumps(sorted({int(port) for port in incoming_ports})), domain_id),
    )
    conn.commit()
    conn.close()
    scan_domain(domain_id, normalized, incoming_ports)


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
            SELECT domain_id, port, is_online, last_response_ms, checked_at,
                   ROW_NUMBER() OVER (PARTITION BY domain_id, port ORDER BY checked_at DESC) AS rn
            FROM port_checks
        )
        SELECT d.id, d.name, d.ports, latest.port, latest.is_online, latest.last_response_ms, latest.checked_at
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
            "ports": parse_ports(row["ports"]),
            "port": row["port"],
            "is_online": bool(row["is_online"]),
            "last_response_ms": row["last_response_ms"],
            "checked_at": row["checked_at"],
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
        if not name:
            flash("A domain name is required.")
            return redirect(url_for("add_domain_route"))
        try:
            result = add_domain(name)
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("add_domain_route"))
        if result is None:
            flash("That domain already exists.")
            return redirect(url_for("domains"))
        flash(f"Added domain {name}.")
        return redirect(url_for("domains"))
    return render_template("domains.html", domains=domain_list(), add_mode=True)


@app.route("/domains/<int:domain_id>/edit", methods=["GET", "POST"])
def edit_domain(domain_id):
    domain = get_domain_by_id(domain_id)
    if domain is None:
        flash("Domain not found.")
        return redirect(url_for("domains"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        ports_input = request.form.get("ports", "")
        try:
            update_domain(domain_id, name, ports_input)
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
    scan_domain(domain_id, domain["name"], domain["ports"])
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
        scan_domain(domain["id"], domain["name"], domain["ports"])


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Import domain list")
        print("2. Maintain domains")
        print("3. View status")
        print("4. Start web app")
        print("5. Exit")
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
