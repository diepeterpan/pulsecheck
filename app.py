from __future__ import annotations

import asyncio
import base64
import csv
import functools
import gzip
import hashlib
from html.parser import HTMLParser
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

# Ensure sys.modules["app"] references this module even when executed as __main__
if "app" not in sys.modules:
    sys.modules["app"] = sys.modules[__name__]
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

from core.config import *
from core.database import *

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
GLOBAL_SERVER = None
IS_SCANNING = False
IS_SCANNING_LOCK = threading.Lock()


def run_web_server(host: str = DEFAULT_IP, port: int = DEFAULT_PORT):
    """Run Werkzeug WSGI server, tracking GLOBAL_SERVER and ensuring clean socket reuse."""
    global GLOBAL_SERVER
    from werkzeug.serving import make_server

    server = make_server(host, port, app, threaded=True)
    try:
        server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        os.set_inheritable(server.socket.fileno(), False)
    except Exception:
        pass
    GLOBAL_SERVER = server
    try:
        server.serve_forever()
    finally:
        try:
            server.server_close()
        except Exception:
            pass
        GLOBAL_SERVER = None


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

from services.scanner import (
    create_ssl_context,
    is_ssl_handshake_failure,
    decompress_gzip_payload,
    decompress_socket_response_if_gzip,
    format_response_headers,
    AsyncHttpManager,
    async_fetch_response,
    fetch_response,
    fetch_tcp_response,
    fetch_tcp_ssl_response,
    fetch_udp_response,
    fetch_udp_ssl_response,
    fetch_icmp_ping_response,
    make_basic_auth_headers,
    format_protocol_label,
    get_protocol_icon_svg,
    get_overall_status_icon_svg,
    format_ports_column,
    register_template_filters,
    scan_service,
    probe_single_port_diagnostics,
    parse_diagnostic_ports,
    diagnose_service_ports,
    scan_service_with_retries,
    discover_ports,
)
from services.importer import (
    ImportCancelled,
    EncryptedPasswordError,
    parse_csv_ports,
    apply_csv_protocols,
    export_services_csv,
    import_services_from_csv,
    import_service_names,
    encrypt_csv_password,
    decrypt_csv_password,
    has_encrypted_csv_fields,
)
from services.icons import (
    get_manufacturer_icons_dir,
    get_service_icons_dir,
    is_godaddy_or_parked_icon,
    get_manufacturer_name_aliases,
    slugify_manufacturer,
    get_manufacturer_icon_url,
    extract_service_device_slug,
    extract_service_product_name,
    slugify_service_name,
    detect_image_extension,
    get_service_icon_url,
    get_known_manufacturer_domains,
    get_regional_prefixes,
    resolve_and_cache_manufacturer_icon,
    get_known_service_domains,
    get_html_content_icon_mappings,
    decode_data_uri_image,
    extract_script_icon_data_uris,
    extract_icon_links_from_html,
    fetch_service_html_body,
    fetch_service_content_responses,
    resolve_and_cache_service_icon,
    trigger_service_icon_resolution_async,
    resolve_missing_service_icons,
)
from services.notifications import (
    send_email,
    send_state_change_notification,
)
from services.scheduler import (
    _resolve_ip,
    _resolve_mac,
    _lookup_manufacturer,
    _update_discovery_fields,
    discover_network_info_for_service,
    run_discovery_for_all_services,
    trigger_discovery_async,
    resolve_missing_manufacturers_and_icons,
    get_service_snapshots,
    dump_line_profiler_stats,
    get_line_profiler_stats_text,
    enable_line_profiling,
    check_all_services,
    get_scan_schedule_info,
    run_background_tasks,
)
register_template_filters(app)


# ── Blueprints Registration ───────────────────────────────────────────────────
from routes.home import (
    home_bp,
    compute_system_overall_status,
    index,
    status,
    status_check_state,
    debug_profile,
    serve_manufacturer_icon,
    serve_service_icon,
    preview_email,
)
from routes.services import (
    services_bp,
    sync_service_ports,
    add_service,
    update_service,
    parse_port_values,
    bulk_update_ports,
    delete_service,
    services,
    add_service_route,
    bulk_ports_route,
    bulk_delete_route,
    edit_service,
    test_service_edit_route,
    test_service_generic_route,
    delete_service_route,
    rescan_service_route,
)
from routes.settings import (
    settings_bp,
    is_safe_remote_command,
    parse_remote_service_names,
    execute_remote_ssh,
    execute_remote_telnet,
    execute_remote_source,
    ICON_JOB_STATUS,
    ICON_JOB_LOCK,
    _run_icon_regeneration_worker,
    settings_route,
    api_test_remote_source,
    api_fetch_remote_services,
    api_get_icons_status,
    api_regenerate_icons,
    api_list_cached_icons,
    api_delete_one_icon,
    api_delete_all_icons,
    api_get_icon_mappings,
    api_save_icon_mappings,
    api_reset_icon_mappings,
    api_backup_export,
    api_backup_import,
)
from routes.import_export import (
    import_bp,
    create_import_session,
    update_import_state,
    run_import_worker,
    create_csv_import_session,
    run_csv_import_worker,
    handle_import,
    export_services_route,
    start_import,
    start_csv_import,
    import_status,
    cancel_import,
)

app.register_blueprint(home_bp)
app.register_blueprint(services_bp)
app.register_blueprint(settings_bp)
app.register_blueprint(import_bp)


def _resolve_blueprint_url(error, endpoint, values):
    """Fallback handler so templates and code using unprefixed endpoints resolve properly."""
    for ep in app.view_functions:
        if ep.endswith("." + endpoint):
            return url_for(ep, **values)
    return None


app.url_build_error_handlers.append(_resolve_blueprint_url)





def start_mode(mode: str):
    """Start application in the requested mode ('1': standard, '2': debug, '3': profiler)."""
    os.environ["PULSECHECK_AUTORUN_MODE"] = str(mode)
    if mode == "1":
        print(f"Starting web application on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
        run_web_server(host=DEFAULT_IP, port=DEFAULT_PORT)
    elif mode == "2":
        global EXPLICIT_DEBUG
        EXPLICIT_DEBUG = True
        print(f"Starting web application with explicit debugging on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
        run_web_server(host=DEFAULT_IP, port=DEFAULT_PORT)
    elif mode == "3":
        if enable_line_profiling():
            print(f"Starting web application with Line-Profiler on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            print("Line-by-line profiling active for check_all_services, scan_service, scan_service_with_retries, fetch_response, and /status.")
            print("Timing stats will display after each scan cycle and when shutting down.\n")
            run_web_server(host=DEFAULT_IP, port=DEFAULT_PORT)


def cli_menu():
    while True:
        print("\nPulseCheck menu")
        print("1. Start web app")
        print("2. Start web with Explicit debugging")
        print("3. Start web with Line-Profiler (profiles scan lines & elapsed CPU/time)")
        print("4. Exit")
        choice = input("Select an option: ").strip()

        if choice in ("1", "2", "3"):
            start_mode(choice)
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
        autorun_mode = os.getenv("PULSECHECK_AUTORUN_MODE", "").strip()
        if autorun_mode in ("1", "2", "3"):
            start_mode(autorun_mode)
        elif os.getenv("PULSECHECK_HEADLESS", "").lower() in ("1", "true", "yes") or not sys.stdin.isatty():
            print(f"Starting web application on {get_base_url()} (listening on {DEFAULT_IP}:{DEFAULT_PORT})")
            run_web_server(host=DEFAULT_IP, port=DEFAULT_PORT)
        else:
            cli_menu()
    finally:
        if LINE_PROFILER_ENABLED and GLOBAL_LINE_PROFILER is not None:
            dump_line_profiler_stats(disable=True)
        if GLOBAL_SCHEDULER:
            GLOBAL_SCHEDULER.shutdown(wait=False)
