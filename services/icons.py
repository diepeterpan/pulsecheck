"""
Service and manufacturer icon caching, signature matching, and discovery routines.
"""
from __future__ import annotations

import base64
from concurrent.futures import ThreadPoolExecutor
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import sys
import threading
import time
import urllib.parse
from urllib.parse import urljoin

from core.config import (
    DEFAULT_SCANNER_BYPASS_KEY,
    MANUFACTURER_ICONS_DIR as DEFAULT_MANUFACTURER_ICONS_DIR,
    SERVICE_ICONS_DIR as DEFAULT_SERVICE_ICONS_DIR,
)
from core.database import (
    get_db_connection,
    normalize_service,
    parse_port_protocol,
    parse_hex_bytes,
)


def get_manufacturer_icons_dir() -> Path:
    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, "MANUFACTURER_ICONS_DIR"):
        return getattr(app_mod, "MANUFACTURER_ICONS_DIR")
    return DEFAULT_MANUFACTURER_ICONS_DIR


def get_service_icons_dir() -> Path:
    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, "SERVICE_ICONS_DIR"):
        return getattr(app_mod, "SERVICE_ICONS_DIR")
    return DEFAULT_SERVICE_ICONS_DIR


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

_MANUFACTURER_NAME_ALIASES = DEFAULT_MANUFACTURER_NAME_ALIASES

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
    "magic home pro": "magic home.net",
}

DEFAULT_REGIONAL_PREFIXES = [
    "shenzhen", "beijing", "shanghai", "hangzhou", "guangzhou", "dongguan",
    "chengdu", "wuhan", "nanjing", "taipei", "hong kong", "hongkong"
]

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
    [r"(?:<esp-app\b|\besphome\b)", "esphome.io"],
]

# Known hashes of generic GoDaddy parked page favicons across multiple sizes and CDNs
_GODADDY_PARKED_ICON_HASHES = {
    "0f51e723b5ea18cf223bd66aaf0bda85",  # Google Favicon 64px (1045 bytes)
    "6bceda3c3c8d58b353b71a1641a3e73d",  # Google Favicon 32px (510 bytes)
    "8379b3a54a273ff25f7ec28c565341e8",  # Google Favicon 16px (302 bytes)
    "b01122b8efe9b9022ddb161443198081",  # Google Favicon 128px (1965 bytes)
    "d9e87c52cf05be95fb7a09ff01080983",  # GoDaddy CDN img1.wsimg.com direct favicon (2238 bytes)
}


def _get_http_manager():
    """Look up AsyncHttpManager from app module if available, otherwise from services/scanner."""
    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, "AsyncHttpManager"):
        return getattr(app_mod, "AsyncHttpManager")
    try:
        from services.scanner import AsyncHttpManager
        return AsyncHttpManager
    except ImportError:
        return None


def _get_scanner_fn(name: str):
    """Retrieve scanning function from app module or services/scanner."""
    app_mod = sys.modules.get("app")
    if app_mod is not None and hasattr(app_mod, name):
        return getattr(app_mod, name)
    try:
        import services.scanner as scanner_mod
        return getattr(scanner_mod, name, None)
    except ImportError:
        return None


def make_basic_auth_headers(username: str | None, password: str | None) -> dict[str, str]:
    """Generate Basic Authorization header dictionary if username or password provided."""
    u = str(username or "").strip()
    p = str(password or "")
    if not u and not p:
        return {}
    token = base64.b64encode(f"{u}:{p}".encode("latin1")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def is_godaddy_or_parked_icon(data: bytes | None) -> bool:
    """Return True if image data matches known GoDaddy parked domain favicon signatures."""
    if not data or len(data) < 50:
        return True
    h = hashlib.md5(data).hexdigest()
    return h in _GODADDY_PARKED_ICON_HASHES


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


def slugify_manufacturer(name: str) -> str:
    """Normalize a manufacturer name into a safe filesystem slug."""
    s = (name or "").lower().strip()
    aliases = get_manufacturer_name_aliases()
    for alias_key, canon_name in aliases.items():
        if alias_key == s or alias_key in s:
            s = canon_name.lower()
            break
    s = re.sub(r"\b(inc|incorporated|corp|corporation|llc|ltd|limited|co|gmbh|sa|bv|s\.p\.a|s\.a|n\.v)\b\.?", "", s)
    s = re.sub(r"[^\w\s-]", "", s)
    s = re.sub(r"[\s-]+", "_", s).strip("_")
    return s or "unknown"


def get_manufacturer_icon_url(manufacturer: str | None) -> str | None:
    """Return local cached URL for manufacturer icon if it exists on disk."""
    if not manufacturer or manufacturer.strip().upper() in ("", "NONE"):
        return None
    slug = slugify_manufacturer(manufacturer)
    mfg_dir = get_manufacturer_icons_dir()
    for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
        icon_path = mfg_dir / f"{slug}{ext}"
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


def extract_service_device_slug(service_name: str) -> str:
    """
    Extract the device/host specific prefix up to the first dot.
    Keeps port and path if present in that first token (e.g. host:port/path).
    Example: 'fridge-temperature.galleon.co.za' -> 'fridge-temperature'
    Example: 'fridge-temperature' -> 'fridge-temperature'
    """
    if not service_name:
        return ""
    raw = re.sub(r"^https?://", "", service_name.strip(), flags=re.I)
    first_part = raw.split(".")[0].strip()
    s = re.sub(r"[^\w\-:]", "", first_part).strip("_")
    return s.lower() or "unknown"


def extract_service_product_name(service_name: str) -> str:
    """Extract the primary product / application name from a service hostname or label."""
    if not service_name:
        return ""
    raw = re.sub(r"^https?://", "", service_name.strip(), flags=re.I)
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
    """
    Return local cached URL for service / product icon if it exists on disk.
    Priority 1: On-device specific slug up to first dot (e.g. fridge-temperature.<ext>)
    Priority 2: Generic product slug (e.g. fridge.<ext>)
    """
    if not service_name or service_name.strip().upper() in ("", "NONE"):
        return None

    device_slug = extract_service_device_slug(service_name)
    product_slug = slugify_service_name(service_name)

    candidates = [device_slug]
    if product_slug and product_slug != device_slug:
        candidates.append(product_slug)

    svc_dir = get_service_icons_dir()
    for slug in candidates:
        for ext in (".png", ".ico", ".jpg", ".svg", ".webp", ".gif"):
            icon_path = svc_dir / f"{slug}{ext}"
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
    mfg_dir = get_manufacturer_icons_dir()
    if not force_refresh:
        for ext in (".png", ".ico", ".jpg", ".svg", ".webp"):
            cached_file = mfg_dir / f"{slug}{ext}"
            if cached_file.is_file() and cached_file.stat().st_size > 0:
                return f"/static/manufacturer-icons/{slug}{ext}"

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
        tokens = [t for t in slug.split("_") if t and t not in (
            "technology", "electronics", "information", "networks", "network",
            "telecom", "telecommunication", "digital", "system", "systems", "group", "holdings", "holding"
        )]
        if len(tokens) > 1 and tokens[0] in regional_prefixes_set:
            second_token = tokens[1]
            if len(second_token) > 2:
                candidate_domains.append(f"{second_token}.com")
                candidate_domains.append(f"{second_token}tech.com")

        if tokens and len(tokens[0]) > 2:
            candidate_domains.append(f"{tokens[0]}.com")

    candidate_domains = [d for d in candidate_domains if not any(d == f"{reg}.com" for reg in regional_prefixes_set)]

    icon_bytes = None
    http_manager = _get_http_manager()
    if not http_manager:
        return None

    # Step A: Google Favicon service
    for test_dom in candidate_domains:
        try:
            fav_url = f"https://www.google.com/s2/favicons?domain={test_dom}&sz=64"
            data, status, _ = http_manager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=4.0)
            if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                icon_bytes = data
                break
        except Exception:
            pass

    # Step B: Direct website probe
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
                    data, status, headers = http_manager.get_url(candidate_url, headers={"User-Agent": ua}, timeout=4.0)
                    ctype = headers.get("Content-Type", "") or headers.get("content-type", "")
                    if status == 200 and len(data) > 100 and ("image" in ctype or candidate_url.endswith((".png", ".ico", ".jpg", ".svg"))) and not is_godaddy_or_parked_icon(data):
                        icon_bytes = data
                        break
                except Exception:
                    continue
            if icon_bytes:
                break

            try:
                home_url = f"https://www.{test_dom}/"
                data, status, _ = http_manager.get_url(home_url, headers={"User-Agent": ua}, timeout=4.0)
                if status == 200:
                    html = data.decode("utf-8", errors="ignore")
                    found_links = re.findall(r'<link[^>]+rel=[\"\'](?:shortcut )?icon[\"\'][^>]+href=[\"\']([^\"\']+)[\"\']', html, re.I)
                    found_logos = re.findall(r'<img[^>]+src=[\"\']([^\"\']*(?:logo|icon)[^\"\']*)[\"\']', html, re.I)
                    for relative_or_abs in (found_links + found_logos):
                        target = urljoin(home_url, relative_or_abs)
                        try:
                            t_data, t_status, _ = http_manager.get_url(target, headers={"User-Agent": ua}, timeout=4.0)
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

    # Step C: Wikimedia pageimages fallback
    if not icon_bytes:
        try:
            query_title = manufacturer.split(",")[0].strip()
            wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=pageimages&format=json&titles={urllib.parse.quote(query_title)}&pithumbsize=64"
            data, status, _ = http_manager.get_url(wiki_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=4.0)
            if status == 200:
                payload = json.loads(data.decode())
                pages = payload.get("query", {}).get("pages", {})
                thumb_url = None
                for p in pages.values():
                    if "thumbnail" in p and "source" in p["thumbnail"]:
                        thumb_url = p["thumbnail"]["source"]
                        break
                if thumb_url:
                    img_data, img_status, _ = http_manager.get_url(thumb_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=4.0)
                    if img_status == 200 and len(img_data) > 100 and not is_godaddy_or_parked_icon(img_data):
                        icon_bytes = img_data
        except Exception:
            pass

    if icon_bytes and not is_godaddy_or_parked_icon(icon_bytes):
        ext = detect_image_extension(icon_bytes)
        actual_path = mfg_dir / f"{slug}{ext}"
        try:
            with open(actual_path, "wb") as f:
                f.write(icon_bytes)
            return f"/static/manufacturer-icons/{slug}{ext}"
        except Exception as exc:
            print(f"[IconCache] Failed to write {actual_path}: {exc}")

    return None


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


def decode_data_uri_image(uri: str) -> tuple[bytes | None, str | None]:
    """Parse and decode a data URI. Returns (raw_bytes, extension) or (None, None)."""
    if not uri or not isinstance(uri, str):
        return None, None
    s = uri.strip()
    if not s.lower().startswith("data:"):
        return None, None
    header, sep, data_part = s[5:].partition(",")
    if not sep or not data_part or not data_part.strip():
        return None, None

    header_lower = header.lower()
    raw_bytes = None
    if ";base64" in header_lower:
        try:
            raw_bytes = base64.b64decode(data_part)
        except Exception:
            return None, None
    else:
        try:
            raw_bytes = urllib.parse.unquote_to_bytes(data_part)
        except Exception:
            try:
                raw_bytes = urllib.parse.unquote(data_part).encode("utf-8")
            except Exception:
                return None, None

    if not raw_bytes or len(raw_bytes) < 10 or is_godaddy_or_parked_icon(raw_bytes):
        return None, None

    ext = detect_image_extension(raw_bytes, content_type=header)
    return raw_bytes, ext


class _HtmlIconLinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.candidates: list[dict] = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() != "link":
            return
        attr_map = {k.lower(): (v or "") for k, v in attrs}
        rel_val = attr_map.get("rel", "").lower()
        if not rel_val:
            return
        rels = re.split(r"\s+", rel_val.strip())
        is_icon = "icon" in rels or ("shortcut" in rels and "icon" in rels) or "shortcut-icon" in rels
        is_apple = "apple-touch-icon" in rels or "apple-touch-icon-precomposed" in rels
        if not (is_icon or is_apple):
            return

        href = attr_map.get("href", "").strip()
        if not href or href.lower() in ("data:", "data:,"):
            return

        dim = 0
        sizes = attr_map.get("sizes", "").lower()
        if "x" in sizes:
            try:
                parts = sizes.split("x")
                dim = max(int(parts[0]), int(parts[1]))
            except Exception:
                dim = 0
        elif is_apple:
            dim = 180
        elif "shortcut" in rels and "icon" in rels:
            dim = 32
        else:
            dim = 16

        self.candidates.append({
            "href": href,
            "dim": dim,
            "is_apple": is_apple,
            "type": attr_map.get("type", "").lower()
        })


def extract_script_icon_data_uris(text: str) -> list[str]:
    """Extract embedded data URI icons from script content or HTML text."""
    if not text or "data:image/" not in text:
        return []
    matches = re.findall(r"""(["'`])(data:image/[a-zA-Z0-9+.-]+(?:;base64)?[^\r\n]*?)\1""", text)
    uris = []
    seen = set()
    for _, u in matches:
        cleaned = u.strip()
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            uris.append(cleaned)
    return uris


def extract_icon_links_from_html(html: str) -> list[str]:
    """Extract icon link hrefs from HTML, ordered by descending dimension."""
    if not html or "<link" not in html.lower():
        return []
    parser = _HtmlIconLinkParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    sorted_candidates = sorted(
        parser.candidates,
        key=lambda c: (c["dim"], 1 if not c["is_apple"] else 0),
        reverse=True
    )
    seen = set()
    result = []
    for c in sorted_candidates:
        h = c["href"]
        if h not in seen:
            seen.add(h)
            result.append(h)
    return result


def fetch_service_html_body(service_name: str, max_redirects: int = 3, http_username: str = "", http_password: str = "") -> str | None:
    """Retrieve landing page HTML across https:// and http://."""
    clean_host = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
    if not clean_host:
        return None

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    headers = {"User-Agent": ua}
    if DEFAULT_SCANNER_BYPASS_KEY:
        headers["X-Scanner-Bypass-Key"] = DEFAULT_SCANNER_BYPASS_KEY
    basic_hdrs = make_basic_auth_headers(http_username, http_password)
    if basic_hdrs:
        headers.update(basic_hdrs)

    http_manager = _get_http_manager()
    if not http_manager:
        return None

    for proto in ("https", "http"):
        current_url = f"{proto}://{clean_host}/"
        try:
            data, status, headers_out = http_manager.get_url(current_url, headers=headers, timeout=2.5, max_redirects=max_redirects)
            ctype = (headers_out.get("Content-Type") or headers_out.get("content-type") or "").lower()
            if status == 200 and ("text" in ctype or "html" in ctype or b"<html" in data[:4096] or b"<body" in data[:4096]):
                return data[:65536].decode("utf-8", errors="ignore")
        except Exception:
            pass

    return None


def fetch_service_content_responses(service_name: str, port_protocol_data: str | list | None = None, http_username: str = "", http_password: str = "") -> list[str]:
    """Retrieve content bodies and socket/SSL banners from service endpoints.
    Prioritizes 'web' (WEB Get) ports first, followed by custom TCP/UDP socket banners.
    Ignores auto-detect and ICMP ports.
    Returns a list of decoded string responses from active endpoints."""
    clean_host = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
    if not clean_host:
        return []

    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    headers = {"User-Agent": ua}
    if DEFAULT_SCANNER_BYPASS_KEY:
        headers["X-Scanner-Bypass-Key"] = DEFAULT_SCANNER_BYPASS_KEY
    basic_hdrs = make_basic_auth_headers(http_username, http_password)
    if basic_hdrs:
        headers.update(basic_hdrs)

    http_manager = _get_http_manager()
    parsed_ports = parse_port_protocol(port_protocol_data) if port_protocol_data else []

    # Filter out auto-detect and ICMP ports
    valid_ports = []
    for p in parsed_ports:
        port_num = p.get("port")
        proto = (p.get("protocol") or "").strip().lower()
        if not port_num or not isinstance(port_num, int):
            continue
        if not proto or proto in ("auto", "auto-detect", "icmp", "icmp-ping"):
            continue
        valid_ports.append(p)

    # Sort ports: 'web' request_type (WEB Get) first, then others
    web_ports = [p for p in valid_ports if (p.get("request_type") or "web").strip().lower() == "web"]
    non_web_ports = [p for p in valid_ports if (p.get("request_type") or "web").strip().lower() != "web"]
    ordered_ports = web_ports + non_web_ports

    responses = []
    seen_contents = set()

    for p in ordered_ports:
        port_num = p.get("port")
        proto = (p.get("protocol") or "").strip().lower()
        rtype = (p.get("request_type") or "web").strip().lower()
        url_path = (p.get("url_path") or "").strip() or "/"
        custom_req_raw = p.get("request_payload") or ""

        req_bytes = None
        if rtype == "custom" and custom_req_raw:
            try:
                req_bytes = parse_hex_bytes(custom_req_raw)
            except Exception:
                req_bytes = None

        content_str = None

        # 1. Web GET on HTTP / HTTPS / socket web
        if rtype == "web" and proto in ("http", "https", "web", "socket", "tcp", "socket-ssl", "tcp-ssl", ""):
            # Check via HTTP/HTTPS if http_manager is available
            if http_manager:
                schemes = ["https", "http"] if "ssl" in proto or port_num in (443, 8443) else ["http", "https"]
                for scheme in schemes:
                    t_url = f"{scheme}://{clean_host}:{port_num}{url_path if url_path.startswith('/') else '/' + url_path}"
                    try:
                        data, status, hdrs_out = http_manager.get_url(t_url, headers=headers, timeout=2.5)
                        ctype = (hdrs_out.get("Content-Type") or hdrs_out.get("content-type") or "").lower()
                        if status == 200 and ("text" in ctype or "html" in ctype or b"<html" in data[:4096] or b"<body" in data[:4096]):
                            content_str = data[:65536].decode("utf-8", errors="ignore")
                            break
                    except Exception:
                        pass

        # 2. Raw TCP / TCP-SSL socket
        if not content_str:
            if proto in ("tcp", "socket"):
                fetch_tcp_fn = _get_scanner_fn("fetch_tcp_response")
                if fetch_tcp_fn:
                    try:
                        raw = fetch_tcp_fn(clean_host, port_num, url_path=url_path, custom_request_bytes=req_bytes)
                        if raw:
                            content_str = raw[:65536].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
            elif proto in ("tcp-ssl", "socket-ssl"):
                fetch_tcp_ssl_fn = _get_scanner_fn("fetch_tcp_ssl_response")
                if fetch_tcp_ssl_fn:
                    try:
                        raw = fetch_tcp_ssl_fn(clean_host, port_num, url_path=url_path, custom_request_bytes=req_bytes)
                        if raw:
                            content_str = raw[:65536].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
            elif proto == "udp":
                fetch_udp_fn = _get_scanner_fn("fetch_udp_response")
                if fetch_udp_fn:
                    try:
                        raw = fetch_udp_fn(clean_host, port_num, url_path=url_path, custom_request_bytes=req_bytes, timeout=1.5)
                        if raw:
                            content_str = raw[:65536].decode("utf-8", errors="ignore")
                    except Exception:
                        pass
            elif proto == "udp-ssl":
                fetch_udp_ssl_fn = _get_scanner_fn("fetch_udp_ssl_response")
                if fetch_udp_ssl_fn:
                    try:
                        raw = fetch_udp_ssl_fn(clean_host, port_num, url_path=url_path, custom_request_bytes=req_bytes, timeout=1.5)
                        if raw:
                            content_str = raw[:65536].decode("utf-8", errors="ignore")
                    except Exception:
                        pass

        if content_str and content_str not in seen_contents:
            seen_contents.add(content_str)
            responses.append(content_str)

    # If no configured ports produced content, fall back to standard root HTTP/HTTPS landing page
    if not responses:
        root_html = fetch_service_html_body(service_name, http_username=http_username, http_password=http_password)
        if root_html:
            responses.append(root_html)

    return responses


def resolve_and_cache_service_icon(service_name: str, force_refresh: bool = False, http_username: str = "", http_password: str = "") -> str | None:
    """
    Find, download, and cache an icon for the product/service in SERVICE_ICONS_DIR.
    """
    # If app.resolve_and_cache_service_icon has been patched, delegate to it
    app_mod = sys.modules.get("app")
    if app_mod is not None:
        patched_fn = getattr(app_mod, "resolve_and_cache_service_icon", None)
        if patched_fn is not None and getattr(patched_fn, "__module__", "") != __name__ and patched_fn != resolve_and_cache_service_icon:
            return patched_fn(service_name, force_refresh=force_refresh, http_username=http_username, http_password=http_password)

    if not service_name or service_name.strip().upper() in ("", "NONE"):
        return None

    auth_user = http_username
    auth_pass = http_password
    service_port_protocol = None
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT http_username, http_password, port_protocol FROM services WHERE name = ? OR name = ?", (service_name, normalize_service(service_name))).fetchone()
        conn.close()
        if row:
            if not auth_user and not auth_pass:
                auth_user = row["http_username"] or ""
                auth_pass = row["http_password"] or ""
            service_port_protocol = row["port_protocol"]
    except Exception:
        pass
    basic_auth_hdrs = make_basic_auth_headers(auth_user, auth_pass)

    product = extract_service_product_name(service_name)
    if not product or len(product) < 2:
        return None

    device_slug = extract_service_device_slug(service_name)
    product_slug = slugify_service_name(service_name)
    svc_dir = get_service_icons_dir()

    if not force_refresh:
        for check_slug in (device_slug, product_slug):
            if not check_slug:
                continue
            for ext in (".png", ".ico", ".jpg", ".svg", ".webp", ".gif"):
                cached_file = svc_dir / f"{check_slug}{ext}"
                if cached_file.is_file() and cached_file.stat().st_size > 0:
                    try:
                        data = cached_file.read_bytes()
                        if is_godaddy_or_parked_icon(data):
                            cached_file.unlink(missing_ok=True)
                            continue
                    except Exception:
                        pass
                    return f"/static/service-icons/{check_slug}{ext}"

    icon_bytes = None
    is_device_origin = False
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    http_manager = _get_http_manager()
    if not http_manager:
        return None

    # Priority 0: Exact Full Service Name Override from Known Service Domains
    known_service_domains = get_known_service_domains()
    try:
        norm_full_service = normalize_service(service_name)
    except Exception:
        norm_full_service = service_name.strip().lower()

    host_only = norm_full_service.split(":")[0].strip()
    override_key = norm_full_service if norm_full_service in known_service_domains else (host_only if host_only in known_service_domains else None)

    if override_key:
        override_target = known_service_domains[override_key].strip()
        if override_target.lower().startswith(("http://", "https://")):
            try:
                data, status, _ = http_manager.get_url(override_target, headers={"User-Agent": ua}, timeout=4.0)
                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                    icon_bytes = data
                    is_device_origin = True
            except Exception:
                pass
        elif override_target:
            target_dom = re.sub(r"^https?://", "", override_target, flags=re.I).split("/")[0].strip()
            if target_dom:
                try:
                    fav_url = f"https://www.google.com/s2/favicons?domain={target_dom}&sz=64"
                    data, status, _ = http_manager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=2.5)
                    if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                        icon_bytes = data
                        is_device_origin = True
                except Exception:
                    pass

                if not icon_bytes:
                    for probe_url in (f"https://www.{target_dom}/favicon.ico", f"https://{target_dom}/favicon.ico", f"http://{target_dom}/favicon.ico"):
                        try:
                            data, status, headers = http_manager.get_url(probe_url, headers={"User-Agent": ua}, timeout=2.5)
                            ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
                            if status == 200 and len(data) > 100 and ("html" not in ctype) and not is_godaddy_or_parked_icon(data):
                                icon_bytes = data
                                is_device_origin = True
                                break
                        except Exception:
                            continue

    # Priority 1: Explicit Image URL from Known Service Domains (Product Token)
    if not icon_bytes and product in known_service_domains:
        target_val = known_service_domains[product].strip()
        if target_val.lower().startswith(("http://", "https://")):
            try:
                data, status, _ = http_manager.get_url(target_val, headers={"User-Agent": ua}, timeout=4.0)
                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                    icon_bytes = data
                    is_device_origin = False
            except Exception:
                pass

    # Priority 2: Explicit URL from Protocol & Content Signatures & Embedded Icon Links
    content_responses: list[str] = []
    html_page = None
    if not icon_bytes:
        content_responses = fetch_service_content_responses(
            service_name,
            port_protocol_data=service_port_protocol,
            http_username=auth_user,
            http_password=auth_pass,
        )
        if content_responses:
            html_mappings = get_html_content_icon_mappings()
            for resp_text in content_responses:
                if html_page is None and ("<html" in resp_text.lower() or "<body" in resp_text.lower()):
                    html_page = resp_text

                for pattern, target in html_mappings:
                    if target.lower().startswith(("http://", "https://")):
                        if re.search(pattern, resp_text, re.I):
                            try:
                                data, status, _ = http_manager.get_url(target, headers={"User-Agent": ua}, timeout=3.5)
                                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                                    icon_bytes = data
                                    is_device_origin = False
                                    break
                            except Exception:
                                pass
                if icon_bytes:
                    break

            if not icon_bytes:
                clean_host_guess = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
                html_icon_links = extract_icon_links_from_html(html_page)
                for link_href in html_icon_links:
                    if link_href.lower().startswith("data:"):
                        decoded_bytes, _ = decode_data_uri_image(link_href)
                        if decoded_bytes and len(decoded_bytes) > 20 and not is_godaddy_or_parked_icon(decoded_bytes):
                            icon_bytes = decoded_bytes
                            is_device_origin = True
                            break
                    elif clean_host_guess:
                        for proto in ("https", "http"):
                            target_url = urljoin(f"{proto}://{clean_host_guess}/", link_href)
                            direct_hdrs = {"User-Agent": ua}
                            if DEFAULT_SCANNER_BYPASS_KEY:
                                direct_hdrs["X-Scanner-Bypass-Key"] = DEFAULT_SCANNER_BYPASS_KEY
                            if basic_auth_hdrs:
                                direct_hdrs.update(basic_auth_hdrs)
                            try:
                                t_data, t_status, t_hdrs = http_manager.get_url(target_url, headers=direct_hdrs, timeout=2.0)
                                t_ctype = (t_hdrs.get("Content-Type") or t_hdrs.get("content-type") or "").lower()
                                if t_status == 200 and len(t_data) > 50 and ("html" not in t_ctype) and not is_godaddy_or_parked_icon(t_data):
                                    icon_bytes = t_data
                                    is_device_origin = True
                                    break
                            except Exception:
                                pass
                        if icon_bytes:
                            break

            if not icon_bytes and html_page:
                inline_uris = extract_script_icon_data_uris(html_page)
                for u in inline_uris:
                    decoded_bytes, _ = decode_data_uri_image(u)
                    if decoded_bytes and len(decoded_bytes) > 20 and not is_godaddy_or_parked_icon(decoded_bytes):
                        icon_bytes = decoded_bytes
                        is_device_origin = True
                        break

                if not icon_bytes and ("<script" in html_page.lower()):
                    script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", html_page, re.I)
                    clean_host_guess = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
                    for s_src in script_srcs:
                        s_src = s_src.strip()
                        if not s_src:
                            continue
                        if s_src.startswith(("http://", "https://")):
                            s_url = s_src
                        elif clean_host_guess:
                            s_url = urljoin(f"http://{clean_host_guess}/", s_src)
                        else:
                            continue

                        s_hdrs = {"User-Agent": ua}
                        if basic_auth_hdrs and (clean_host_guess in s_url):
                            s_hdrs.update(basic_auth_hdrs)
                        try:
                            s_data, s_status, _ = http_manager.get_url(s_url, headers=s_hdrs, timeout=2.5)
                            if s_status == 200 and len(s_data) > 50:
                                s_text = s_data.decode("utf-8", errors="ignore")
                                for u in extract_script_icon_data_uris(s_text):
                                    decoded_bytes, _ = decode_data_uri_image(u)
                                    if decoded_bytes and len(decoded_bytes) > 20 and not is_godaddy_or_parked_icon(decoded_bytes):
                                        icon_bytes = decoded_bytes
                                        is_device_origin = True
                                        break
                        except Exception:
                            pass
                        if icon_bytes:
                            break

    # Priority 3: Direct Site Probe (https:// then http://)
    if not icon_bytes:
        clean_host = re.sub(r"^https?://", "", service_name.strip(), flags=re.I).split("/")[0].strip()
        if clean_host:
            direct_headers = {"User-Agent": ua}
            if DEFAULT_SCANNER_BYPASS_KEY:
                direct_headers["X-Scanner-Bypass-Key"] = DEFAULT_SCANNER_BYPASS_KEY
            if basic_auth_hdrs:
                direct_headers.update(basic_auth_hdrs)

            for proto in ("https", "http"):
                base_url = f"{proto}://{clean_host}"

                try:
                    fav_url = f"{base_url}/favicon.ico"
                    data, status, headers = http_manager.get_url(fav_url, headers=direct_headers, timeout=1.5)
                    ctype = (headers.get("Content-Type") or headers.get("content-type") or "").lower()
                    if status == 200 and len(data) > 100 and ("html" not in ctype) and not is_godaddy_or_parked_icon(data):
                        icon_bytes = data
                        is_device_origin = True
                        break
                except Exception:
                    pass

                if not icon_bytes:
                    try:
                        home_data, home_status, _ = http_manager.get_url(f"{base_url}/", headers=direct_headers, timeout=1.5)
                        if home_status == 200:
                            html = home_data.decode("utf-8", errors="ignore")
                            found_links = extract_icon_links_from_html(html)
                            for link_href in found_links:
                                if link_href.lower().startswith("data:"):
                                    decoded_bytes, _ = decode_data_uri_image(link_href)
                                    if decoded_bytes and len(decoded_bytes) > 20 and not is_godaddy_or_parked_icon(decoded_bytes):
                                        icon_bytes = decoded_bytes
                                        is_device_origin = True
                                        break
                                else:
                                    target = urljoin(f"{base_url}/", link_href)
                                    target_headers = direct_headers if clean_host in target else {"User-Agent": ua}
                                    try:
                                        t_data, t_status, t_headers = http_manager.get_url(target, headers=target_headers, timeout=1.5)
                                        t_ctype = (t_headers.get("Content-Type") or t_headers.get("content-type") or "").lower()
                                        if t_status == 200 and len(t_data) > 50 and ("html" not in t_ctype) and not is_godaddy_or_parked_icon(t_data):
                                            icon_bytes = t_data
                                            is_device_origin = True
                                            break
                                    except Exception:
                                        continue
                    except Exception:
                        pass

                if icon_bytes:
                    break

    # Priority 4: Domain Lookups & Platform Fallbacks
    if not icon_bytes:
        candidate_domains = []
        if product in known_service_domains:
            target_dom = known_service_domains[product].strip()
            if target_dom and not target_dom.lower().startswith(("http://", "https://")):
                candidate_domains.append(target_dom)

        for tld in (".com", ".io", ".org", ".net", ".app", ".dev", ".media"):
            guess = f"{product}{tld}"
            if guess not in candidate_domains:
                candidate_domains.append(guess)

        for test_dom in candidate_domains:
            try:
                fav_url = f"https://www.google.com/s2/favicons?domain={test_dom}&sz=64"
                data, status, _ = http_manager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=2.0)
                if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                    icon_bytes = data
                    is_device_origin = False
                    break
            except Exception:
                pass

        if not icon_bytes and len(product) > 2:
            try:
                wiki_url = f"https://en.wikipedia.org/w/api.php?action=query&prop=pageimages&format=json&titles={urllib.parse.quote(product.capitalize())}&pithumbsize=64"
                data, status, _ = http_manager.get_url(wiki_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=2.0)
                if status == 200:
                    payload = json.loads(data.decode())
                    pages = payload.get("query", {}).get("pages", {})
                    thumb_url = None
                    for p in pages.values():
                        if "thumbnail" in p and "source" in p["thumbnail"]:
                            thumb_url = p["thumbnail"]["source"]
                            break
                    if thumb_url:
                        img_data, img_status, _ = http_manager.get_url(thumb_url, headers={"User-Agent": "PulseCheck/1.0 (network-monitor)"}, timeout=2.0)
                        if img_status == 200 and len(img_data) > 100 and not is_godaddy_or_parked_icon(img_data):
                            icon_bytes = img_data
                            is_device_origin = False
            except Exception:
                pass

        if not icon_bytes:
            if not content_responses:
                content_responses = fetch_service_content_responses(
                    service_name,
                    port_protocol_data=service_port_protocol,
                    http_username=auth_user,
                    http_password=auth_pass,
                )

            if content_responses:
                html_mappings = get_html_content_icon_mappings()
                for resp_text in content_responses:
                    matched_domain = None
                    for pattern, dom in html_mappings:
                        if not dom.lower().startswith(("http://", "https://")):
                            if re.search(pattern, resp_text, re.I):
                                matched_domain = dom
                                break

                    if matched_domain:
                        try:
                            fav_url = f"https://www.google.com/s2/favicons?domain={matched_domain}&sz=64"
                            data, status, _ = http_manager.get_url(fav_url, headers={"User-Agent": "Mozilla/5.0 (compatible; PulseCheck)"}, timeout=2.0)
                            if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                                icon_bytes = data
                                is_device_origin = False
                                break
                        except Exception:
                            pass

                        if not icon_bytes:
                            for probe_url in (f"https://www.{matched_domain}/favicon.ico", f"https://{matched_domain}/favicon.ico"):
                                try:
                                    data, status, _ = http_manager.get_url(probe_url, headers={"User-Agent": ua}, timeout=2.5)
                                    if status == 200 and len(data) > 100 and not is_godaddy_or_parked_icon(data):
                                        icon_bytes = data
                                        is_device_origin = False
                                        break
                                except Exception:
                                    continue

                    if icon_bytes:
                        break

    if icon_bytes and not is_godaddy_or_parked_icon(icon_bytes):
        save_slug = device_slug if is_device_origin else product_slug
        ext = detect_image_extension(icon_bytes)
        actual_path = svc_dir / f"{save_slug}{ext}"
        try:
            with open(actual_path, "wb") as f:
                f.write(icon_bytes)
            return f"/static/service-icons/{save_slug}{ext}"
        except Exception as exc:
            print(f"[ServiceIconCache] Failed to write {actual_path}: {exc}")

    return None


def trigger_service_icon_resolution_async(service_name: str, http_username: str = "", http_password: str = ""):
    """Fire-and-forget service icon lookup on add or edit."""
    if not service_name:
        return
    t = threading.Thread(
        target=resolve_and_cache_service_icon,
        args=(service_name,),
        kwargs={"http_username": http_username, "http_password": http_password},
        daemon=True,
    )
    t.start()


def resolve_missing_service_icons():
    """Startup-only task: Checks all distinct services and caches missing icons."""
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
