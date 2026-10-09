from __future__ import annotations

import csv
import io
import re
import sys
import threading
import uuid

from flask import (
    Blueprint,
    Response,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)

from core.database import service_list
from services.importer import (
    ImportCancelled,
    EncryptedPasswordError,
    export_services_csv,
    import_service_names,
    import_services_from_csv,
    has_encrypted_csv_fields,
)
from routes.auth import login_required

import_bp = Blueprint("import_bp", __name__)

IMPORT_STATE: dict = {}
IMPORT_LOCK = threading.Lock()


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


def create_csv_import_session(csv_content: str, decryption_password: str = ""):
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
        args=(token, csv_content, decryption_password),
        daemon=True,
    )
    thread.start()
    return token


def run_csv_import_worker(token, csv_content, decryption_password=""):
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
            decryption_password=decryption_password,
        )
        state["status"] = "complete"
        state["summary"] = summary
    except ImportCancelled:
        state["status"] = "cancelled"
        state["summary"] = {"cancelled": True}
    except EncryptedPasswordError as exc:
        state["status"] = "error"
        state["error"] = str(exc)
    except Exception as exc:  # pragma: no cover
        state["status"] = "error"
        state["error"] = str(exc)
    finally:
        state["finished"] = True
        state["port"] = None
        state["message"] = "Import finished" if state["status"] == "complete" else state["status"]


@import_bp.route("/import", methods=["GET", "POST"], endpoint="handle_import")
@login_required
def handle_import():
    if request.method == "POST":
        # Check if CSV file was uploaded
        if "csv_file" in request.files and request.files["csv_file"].filename:
            file = request.files["csv_file"]
            decryption_pass = request.form.get("decryption_password") or ""
            try:
                content = file.read().decode("utf-8", errors="replace")
                summary = import_services_from_csv(content, decryption_password=decryption_pass)
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


@import_bp.route("/import/export", methods=["GET", "POST"], endpoint="export_services_route")
@import_bp.route("/services/export.csv", methods=["GET", "POST"])
@login_required
def export_services_route():
    enc_pass = request.values.get("encryption_password") or ""
    csv_content, count = export_services_csv(encryption_password=enc_pass)
    response = Response(csv_content, mimetype="text/csv")
    response.headers["Content-Disposition"] = "attachment; filename=pulsecheck_services.csv"
    response.headers["X-Exported-Count"] = str(count)
    return response


@import_bp.route("/import/csv/check-encrypted", methods=["POST"], endpoint="check_encrypted_csv")
@login_required
def check_encrypted_csv():
    if "csv_file" not in request.files or not request.files["csv_file"].filename:
        return {"error": "No CSV file provided."}, 400
    file = request.files["csv_file"]
    content = file.read().decode("utf-8", errors="replace")
    is_enc = has_encrypted_csv_fields(content)
    return {"encrypted": is_enc}


@import_bp.route("/import/start", methods=["POST"], endpoint="start_import")
@login_required
def start_import():
    raw_text = request.form.get("services") or ""
    items = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not items:
        return {"error": "No service names were supplied."}, 400

    token = create_import_session(items)
    return {"token": token, "status": "started"}


@import_bp.route("/import/csv/start", methods=["POST"], endpoint="start_csv_import")
@login_required
def start_csv_import():
    if "csv_file" not in request.files or not request.files["csv_file"].filename:
        return {"error": "No CSV file provided."}, 400
    file = request.files["csv_file"]
    decryption_pass = request.form.get("decryption_password") or ""
    content = file.read().decode("utf-8", errors="replace")
    if not content.strip():
        return {"error": "CSV file is empty."}, 400

    # Quick pre-validation: if encrypted fields exist and password is provided, test decryption
    if has_encrypted_csv_fields(content):
        if not decryption_pass:
            return {"error": "Decryption password required for this protected CSV file."}, 400
        # Test first encrypted field to fail fast before queueing
        try:
            tokens = re.findall(r"ENC:v1:[A-Za-z0-9+/=]+", content)
            if tokens:
                from services.importer import decrypt_csv_password
                decrypt_csv_password(tokens[0], decryption_pass)
        except EncryptedPasswordError:
            return {"error": "Incorrect decryption password. Please check your password and try again."}, 400
        except Exception as exc:
            return {"error": f"Failed to decrypt password: {exc}"}, 400

    token = create_csv_import_session(content, decryption_password=decryption_pass)
    return {"token": token, "status": "started"}


@import_bp.route("/import/<token>/status", endpoint="import_status")
@login_required
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


@import_bp.route("/import/<token>/cancel", methods=["POST"], endpoint="cancel_import")
@login_required
def cancel_import(token):
    state = IMPORT_STATE.get(token)
    if not state:
        return {"status": "not_found"}, 404
    state["cancelled"] = True
    state["status"] = "cancel_requested"
    state["message"] = "Cancelling import..."
    return {"status": "cancel_requested"}
