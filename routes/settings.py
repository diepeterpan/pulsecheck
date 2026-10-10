from __future__ import annotations

import io
import json
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path

from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from core.config import (
    APP_VERSION,
    MANUFACTURER_ICONS_DIR,
    SERVICE_ICONS_DIR,
)
from core.database import (
    get_db_connection,
    get_settings,
    save_settings,
    get_current_local_time_str,
    get_authorized_users,
    get_authorized_user_by_id,
    get_authorized_user_by_identifier,
    add_authorized_user,
    update_authorized_user,
    delete_authorized_user,
)
from routes.auth import login_required, is_oidc_active, get_active_match_claim
from services.backup import (
    export_settings_encrypted,
    import_settings_encrypted,
    trigger_server_restart,
)
from services.notifications import send_email
from services.icons import (
    get_manufacturer_icons_dir,
    get_service_icons_dir,
    DEFAULT_KNOWN_MANUFACTURER_DOMAINS,
    DEFAULT_KNOWN_SERVICE_DOMAINS,
    DEFAULT_HTML_CONTENT_ICON_MAPPINGS,
    DEFAULT_REGIONAL_PREFIXES,
    DEFAULT_MANUFACTURER_NAME_ALIASES,
    get_manufacturer_name_aliases,
    get_manufacturer_icon_url,
    get_service_icon_url,
    get_known_manufacturer_domains,
    get_regional_prefixes,
    resolve_and_cache_manufacturer_icon,
    get_known_service_domains,
    get_html_content_icon_mappings,
    resolve_and_cache_service_icon,
)

settings_bp = Blueprint("settings_bp", __name__)


def _get_app_attr(name: str, default=None):
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


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


def _run_icon_regeneration_worker(category: str, force: bool = False, exclude_paused: bool = False):
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
                query = (
                    "SELECT DISTINCT name FROM services "
                    "WHERE name IS NOT NULL AND trim(name) != '' "
                )
                if exclude_paused:
                    query += " AND (paused IS NULL OR paused = 0) "
                query += "ORDER BY name ASC"
                rows = conn.execute(query).fetchall()
                items = [r["name"].strip() for r in rows if r["name"] and r["name"].strip()]
            conn.close()
        except Exception as exc:
            with ICON_JOB_LOCK:
                st = ICON_JOB_STATUS[category]
                st["running"] = False
                st["queued"] = False
                st["status_text"] = f"Error reading database: {exc}"
            return

        target_items = []
        fn_get_mfg_url = _get_app_attr("get_manufacturer_icon_url", get_manufacturer_icon_url)
        fn_get_svc_url = _get_app_attr("get_service_icon_url", get_service_icon_url)
        fn_resolve_mfg = _get_app_attr("resolve_and_cache_manufacturer_icon", resolve_and_cache_manufacturer_icon)
        fn_resolve_svc = _get_app_attr("resolve_and_cache_service_icon", resolve_and_cache_service_icon)

        for item in items:
            if force:
                target_items.append(item)
            elif category == "manufacturer":
                if not fn_get_mfg_url(item):
                    target_items.append(item)
            else:
                if not fn_get_svc_url(item):
                    target_items.append(item)

        if not target_items:
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
                    st["status_text"] = "All icons already cached (0 to process)"
                    break

        with ICON_JOB_LOCK:
            st = ICON_JOB_STATUS[category]
            st["total"] = len(target_items)
            st["status_text"] = f"Generating 0/{len(target_items)} icons..."

        for item in target_items:
            with ICON_JOB_LOCK:
                ICON_JOB_STATUS[category]["current_item"] = item
                ICON_JOB_STATUS[category]["status_text"] = (
                    f"Processing {ICON_JOB_STATUS[category]['processed']}/{len(target_items)}: {item}..."
                )

            try:
                if category == "manufacturer":
                    res = fn_resolve_mfg(item, force_refresh=True)
                else:
                    res = fn_resolve_svc(item, force_refresh=True)

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
                st["queued"] = False
                continue
            else:
                st["running"] = False
                st["current_item"] = ""
                st["status_text"] = f"Completed ({st['success']}/{st['total']} icons resolved)"
                break


@settings_bp.route("/settings", methods=["GET", "POST"], endpoint="settings_route")
@login_required
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
            "oidc_match_claim": request.form.get("oidc_match_claim", current_settings.get("oidc_match_claim", "email")).strip() or "email",
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
                fn_send = _get_app_attr("send_email", send_email)
                success, msg = fn_send(
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
        if active_tab in ("smtp", "proxy", "source", "icons", "backup", "users"):
            redirect_url += f"#{active_tab}"
        return redirect(redirect_url)

    authorized_users = get_authorized_users()
    from core.config import OIDC_ISSUER, get_oidc_callback_url
    issuer_url = os.getenv("PULSECHECK_OIDC_ISSUER") or OIDC_ISSUER or ""
    return render_template(
        "settings.html",
        settings=current_settings,
        authorized_users=authorized_users,
        oidc_active=is_oidc_active(),
        oidc_issuer=issuer_url,
        oidc_callback_url=get_oidc_callback_url(),
        match_claim=get_active_match_claim(),
    )


@settings_bp.route("/api/settings/remote-source/test", methods=["POST"], endpoint="api_test_remote_source")
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


@settings_bp.route("/api/services/remote-fetch", methods=["POST", "GET"], endpoint="api_fetch_remote_services")
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


@settings_bp.route("/api/settings/icons/status", methods=["GET"], endpoint="api_get_icons_status")
def api_get_icons_status():
    """Return live status of icon regeneration background jobs."""
    with ICON_JOB_LOCK:
        return jsonify({
            "manufacturer": dict(ICON_JOB_STATUS["manufacturer"]),
            "service": dict(ICON_JOB_STATUS["service"]),
        })


@settings_bp.route("/api/settings/icons/regenerate", methods=["POST"], endpoint="api_regenerate_icons")
def api_regenerate_icons():
    """Trigger background icon regeneration for either manufacturer or service category."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()
    force = bool(data.get("force", False))
    exclude_paused = bool(data.get("exclude_paused", False))
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
        args=(category, force, exclude_paused),
        name=f"IconRegenWorker-{category}",
        daemon=True,
    )
    t.start()

    return jsonify({
        "success": True,
        "queued": False,
        "message": f"Icon regeneration for {category} icons started in background.",
    })


@settings_bp.route("/api/settings/icons/list", methods=["GET"], endpoint="api_list_cached_icons")
def api_list_cached_icons():
    """Return all cached icon files for the given category with metadata."""
    category = request.args.get("category", "manufacturer").strip().lower()
    target_dir = get_manufacturer_icons_dir() if category == "manufacturer" else get_service_icons_dir()
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


@settings_bp.route("/api/settings/icons/delete-one", methods=["POST"], endpoint="api_delete_one_icon")
def api_delete_one_icon():
    """Delete a single cached icon file."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()
    filename = (data.get("filename") or "").strip()

    if category not in ("manufacturer", "service"):
        return jsonify({"success": False, "error": "Invalid category."}), 400
    if not filename:
        return jsonify({"success": False, "error": "Filename is required."}), 400

    clean_filename = os.path.basename(filename)
    if not clean_filename or clean_filename != filename:
        return jsonify({"success": False, "error": "Invalid filename format."}), 400

    target_dir = get_manufacturer_icons_dir() if category == "manufacturer" else get_service_icons_dir()
    target_path = target_dir / clean_filename

    if target_path.is_file():
        try:
            target_path.unlink()
            return jsonify({"success": True, "message": f"Icon '{clean_filename}' deleted successfully."})
        except Exception as exc:
            return jsonify({"success": False, "error": f"Failed to delete file: {exc}"}), 500

    return jsonify({"success": False, "error": f"Icon '{clean_filename}' not found."}), 404


@settings_bp.route("/api/settings/icons/delete-all", methods=["POST"], endpoint="api_delete_all_icons")
def api_delete_all_icons():
    """Delete all cached icons for the specified category."""
    data = request.get_json(silent=True) or request.form.to_dict()
    category = (data.get("category") or "manufacturer").strip().lower()

    if category not in ("manufacturer", "service"):
        return jsonify({"success": False, "error": "Invalid category."}), 400

    target_dir = get_manufacturer_icons_dir() if category == "manufacturer" else get_service_icons_dir()
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


@settings_bp.route("/api/settings/icons/mappings", methods=["GET"], endpoint="api_get_icon_mappings")
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


@settings_bp.route("/api/settings/icons/mappings/save", methods=["POST"], endpoint="api_save_icon_mappings")
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


@settings_bp.route("/api/settings/icons/mappings/reset", methods=["POST"], endpoint="api_reset_icon_mappings")
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


@settings_bp.route("/api/settings/backup/export", methods=["POST"], endpoint="api_backup_export")
@login_required
def api_backup_export():
    """Export encrypted settings package as a downloadable attachment."""
    from flask import Response
    from datetime import datetime

    password = request.form.get("password") or ""
    if not password.strip():
        # Also check JSON body if posted as application/json
        data = request.get_json(silent=True) or {}
        password = data.get("password", "")

    if not password or not str(password).strip():
        return jsonify({"success": False, "error": "Password is required to export settings."}), 400

    try:
        encrypted_bytes = export_settings_encrypted(password.strip())
        now_tag = datetime.now().strftime("%Y%m%d-%H%M%S")
        filename = f"pulsecheck-settings-{now_tag}.pulsecheck-settings"

        return Response(
            encrypted_bytes,
            mimetype="application/octet-stream",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "Content-Type": "application/octet-stream",
            },
        )
    except Exception as exc:
        return jsonify({"success": False, "error": f"Failed to export settings: {exc}"}), 500


@settings_bp.route("/api/settings/backup/import", methods=["POST"], endpoint="api_backup_import")
@login_required
def api_backup_import():
    """Import encrypted settings package and trigger graceful server restart."""
    password = request.form.get("password") or ""
    if not password.strip():
        return jsonify({"success": False, "error": "Decryption password is required."}), 400

    uploaded_file = request.files.get("file")
    if not uploaded_file:
        return jsonify({"success": False, "error": "No settings backup file was uploaded."}), 400

    try:
        content_bytes = uploaded_file.read()
    except Exception as exc:
        return jsonify({"success": False, "error": f"Could not read uploaded file: {exc}"}), 400

    if not content_bytes:
        return jsonify({"success": False, "error": "Uploaded file is empty."}), 400

    success, message, count = import_settings_encrypted(content_bytes, password.strip())
    if not success:
        return jsonify({"success": False, "error": message}), 400

    # Trigger graceful restart after 1.0 second delay to allow response delivery
    trigger_server_restart(delay_seconds=1.0)

    return jsonify({
        "success": True,
        "message": f"{message} PulseCheck is restarting to apply changes...",
        "count": count,
        "restarting": True,
    })


# ── Authorized Users CRUD Endpoints ─────────────────────────────────────────

@settings_bp.route("/api/settings/users", methods=["GET"], endpoint="api_list_users")
@login_required
def api_list_users():
    users = get_authorized_users()
    return jsonify({
        "success": True,
        "users": [
            {
                "id": u["id"],
                "identifier": u["identifier"],
                "display_name": u["display_name"] or "",
                "created_at": u["created_at"],
                "updated_at": u["updated_at"],
            }
            for u in users
        ],
    })


@settings_bp.route("/api/settings/users/add", methods=["POST"], endpoint="api_add_user")
@login_required
def api_add_user():
    data = request.get_json(silent=True) or request.form
    identifier = (data.get("identifier") or "").strip()
    display_name = (data.get("display_name") or "").strip()

    if not identifier:
        return jsonify({"success": False, "error": "User identifier (e.g. email or username) is required."}), 400

    if get_authorized_user_by_identifier(identifier) is not None:
        return jsonify({"success": False, "error": f"A user with identifier '{identifier}' already exists."}), 400

    try:
        user_id = add_authorized_user(identifier, display_name)
        return jsonify({
            "success": True,
            "message": f"User '{identifier}' added successfully.",
            "user": {
                "id": user_id,
                "identifier": identifier,
                "display_name": display_name,
            },
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@settings_bp.route("/api/settings/users/<int:user_id>/update", methods=["POST"], endpoint="api_update_user")
@login_required
def api_update_user(user_id):
    existing = get_authorized_user_by_id(user_id)
    if not existing:
        return jsonify({"success": False, "error": "User not found."}), 404

    data = request.get_json(silent=True) or request.form
    identifier = (data.get("identifier") or "").strip()
    display_name = (data.get("display_name") or "").strip()

    if not identifier:
        return jsonify({"success": False, "error": "User identifier cannot be empty."}), 400

    conflict = get_authorized_user_by_identifier(identifier)
    if conflict and conflict["id"] != user_id:
        return jsonify({"success": False, "error": f"Another user already has identifier '{identifier}'."}), 400

    try:
        updated = update_authorized_user(user_id, identifier, display_name)
        if not updated:
            return jsonify({"success": False, "error": "Failed to update user."}), 500
        return jsonify({
            "success": True,
            "message": f"User '{identifier}' updated successfully.",
            "user": {
                "id": user_id,
                "identifier": identifier,
                "display_name": display_name,
            },
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@settings_bp.route("/api/settings/users/<int:user_id>/delete", methods=["POST"], endpoint="api_delete_user")
@login_required
def api_delete_user(user_id):
    existing = get_authorized_user_by_id(user_id)
    if not existing:
        return jsonify({"success": False, "error": "User not found."}), 404

    identifier = existing["identifier"]
    try:
        deleted = delete_authorized_user(user_id)
        if not deleted:
            return jsonify({"success": False, "error": "Could not delete user."}), 500
        return jsonify({
            "success": True,
            "message": f"User '{identifier}' deleted successfully.",
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500

