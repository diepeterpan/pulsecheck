"""Core configuration constants and environment variable settings."""
from __future__ import annotations

import builtins
import http.client
import os
from pathlib import Path
import socket
import aiohttp
from aiohttp.http_exceptions import HttpProcessingError

BASE_DIR = Path(__file__).resolve().parent.parent
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
APP_VERSION = os.getenv("PULSECHECK_VERSION", "1.4.2")
__version__ = APP_VERSION

if "profile" not in builtins.__dict__:
    def profile(func):
        return func
    builtins.__dict__["profile"] = profile
else:
    profile = builtins.__dict__["profile"]

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
