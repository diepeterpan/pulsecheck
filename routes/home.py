from __future__ import annotations

import os
import sys

from flask import (
    Blueprint,
    Response,
    abort,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from core.config import (
    APP_VERSION,
    MANUFACTURER_ICONS_DIR,
    SERVICE_ICONS_DIR,
    get_status_url,
)
from core.database import (
    get_status_rows,
    get_last_scheduled_check,
    get_current_local_time_str,
)
from services.icons import is_godaddy_or_parked_icon
from services.scheduler import (
    get_scan_schedule_info,
    get_line_profiler_stats_text,
)

home_bp = Blueprint("home_bp", __name__)


def _get_app_attr(name: str, default=None):
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


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
        ports_list = first_entry.get("ports") or []
        if not ports_list:
            continue

        valid_ports = [entry for entry in entries if entry.get("status") is not None and (entry.get("port") is not None or any(p.get("port") is None for p in ports_list))]
        if not valid_ports:
            offline_services += 1
            services_with_ports += 1
            continue

        active_ports = [e for e in valid_ports if e.get("status") != "skipped"]
        if not active_ports:
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


@home_bp.route("/", endpoint="index")
def index():
    return redirect(url_for("status"))


@home_bp.route("/status/check-state", endpoint="status_check_state")
def status_check_state():
    last_check = get_last_scheduled_check()
    fn_sched = _get_app_attr("get_scan_schedule_info", get_scan_schedule_info)
    schedule_info = fn_sched()
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


@home_bp.route("/status", endpoint="status")
@profile
def status():
    rows = get_status_rows()
    grouped = {}
    for row in rows:
        grouped.setdefault(row["name"], []).append(row)
    last_check = get_last_scheduled_check()
    fn_sched = _get_app_attr("get_scan_schedule_info", get_scan_schedule_info)
    schedule_info = fn_sched()
    overall_status = compute_system_overall_status(rows)
    return render_template(
        "status.html",
        grouped=grouped,
        last_check=last_check,
        schedule_info=schedule_info,
        overall_status=overall_status,
    )


@home_bp.route("/debug/profile", endpoint="debug_profile")
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


@home_bp.route("/static/manufacturer-icons/<path:filename>", endpoint="serve_manufacturer_icon")
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


@home_bp.route("/static/service-icons/<path:filename>", endpoint="serve_service_icon")
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


@home_bp.route("/preview/email", endpoint="preview_email")
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
            return "#16a34a"
        elif st in ("OFFLINE", "DOWN"):
            return "#dc2626"
        elif st in ("DEGRADED", "PARTIAL"):
            return "#ea580c"
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
