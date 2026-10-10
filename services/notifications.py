"""Notification services including email sending and state change notifications."""
from __future__ import annotations

import io
from email.message import EmailMessage
from pathlib import Path
import smtplib
import ssl
import sys

from core.config import (
    APP_VERSION,
    BASE_DIR,
    get_status_url,
)
from core.database import (
    get_current_local_time_str,
    get_settings,
)


def send_email(
    to_email: str,
    subject: str,
    body: str,
    settings: dict[str, str] | None = None,
    timeout: int = 10,
    html_body: str | None = None,
    logo_path: str | Path | None = None,
    inline_images: list[tuple[str, Path | bytes, str]] | None = None,
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
            try:
                from PIL import Image
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

    if inline_images:
        for cid_key, img_source, mime_type in inline_images:
            try:
                img_data = b""
                if isinstance(img_source, (bytes, bytearray)):
                    img_data = bytes(img_source)
                elif isinstance(img_source, (str, Path)):
                    p = Path(img_source)
                    if p.is_file():
                        img_data = p.read_bytes()
                if img_data:
                    subtype = mime_type.split("/")[-1] if "/" in mime_type else "png"
                    clean_cid = cid_key.strip("<>")
                    msg.get_payload()[-1].add_related(
                        img_data,
                        maintype="image",
                        subtype=subtype,
                        cid=f"<{clean_cid}>",
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
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                if smtp_username:
                    server.login(smtp_username, smtp_password)
                server.send_message(msg)
        return True, f"Test email sent successfully to {to_email}."
    except Exception as exc:
        return False, f"Failed to send email: {exc}"


def send_state_change_notification(changes: list[dict]) -> tuple[bool, str]:
    if not changes:
        return False, "No changes to notify."

    app_mod = sys.modules.get("app")
    settings_fn = getattr(app_mod, "get_settings", get_settings) if app_mod else get_settings
    settings = settings_fn()
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
        web_url = item.get("web_url")
        if web_url:
            lines.append(f"• Service: {target_name} ({web_url}) [{new_st}]")
        else:
            lines.append(f"• Service: {target_name} [{new_st}]")

        meta_parts = []
        if item.get("discovered_ip"):
            meta_parts.append(f"IP: {item['discovered_ip']}")
        if item.get("discovered_mac"):
            meta_parts.append(f"MAC: {item['discovered_mac']}")
        if item.get("discovered_manufacturer") and str(item["discovered_manufacturer"]).strip().upper() not in ("", "NONE"):
            meta_parts.append(f"Mfg: {item['discovered_manufacturer']}")
        if meta_parts:
            lines.append(f"  {' | '.join(meta_parts)}")

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

    # Helper functions to look up icon paths
    from services.icons import (
        get_service_icon_path,
        get_manufacturer_icon_path,
    )
    fn_get_svc_path = getattr(app_mod, "get_service_icon_path", get_service_icon_path) if app_mod else get_service_icon_path
    fn_get_mfg_path = getattr(app_mod, "get_manufacturer_icon_path", get_manufacturer_icon_path) if app_mod else get_manufacturer_icon_path

    inline_attachments: list[tuple[str, Path | bytes, str]] = []
    seen_cids: dict[str, str] = {}

    def get_inline_image_cid(file_path: Path, prefix: str) -> str:
        f_str = str(file_path.resolve())
        if f_str in seen_cids:
            return seen_cids[f_str]
        cid = f"{prefix}_{len(seen_cids)}"
        ext = file_path.suffix.lower().lstrip(".")
        mime_type = "image/png"
        if ext in ("jpg", "jpeg"):
            mime_type = "image/jpeg"
        elif ext == "gif":
            mime_type = "image/gif"
        elif ext == "webp":
            mime_type = "image/webp"
        elif ext == "svg":
            mime_type = "image/svg+xml"
        inline_attachments.append((cid, file_path, mime_type))
        seen_cids[f_str] = cid
        return cid

    cards_html = []
    for item in changes:
        target_name = item.get("service") or item.get("name")
        old_st = (item.get("old_status") or "").upper()
        new_st = (item.get("new_status") or "").upper()
        web_url = item.get("web_url")
        badge_color = get_status_badge_color(new_st)
        old_color = get_status_badge_color(old_st)

        # Service icon
        svc_path = fn_get_svc_path(target_name)
        svc_img_html = ""
        if svc_path and svc_path.is_file():
            svc_cid = get_inline_image_cid(svc_path, "svc_icon")
            svc_img_html = f'<img src="cid:{svc_cid}" alt="" width="22" height="22" style="width: 22px; height: 22px; max-width: 22px; max-height: 22px; object-fit: contain; vertical-align: middle; margin-right: 8px; border-radius: 4px;" />'

        # Service name header with optional web URL
        if web_url:
            svc_title_html = f'<a href="{web_url}" target="_blank" rel="noopener noreferrer" style="font-size: 16px; font-weight: 700; color: #2563eb; text-decoration: none; margin-right: 8px; vertical-align: middle;">{target_name}</a>'
        else:
            svc_title_html = f'<strong style="font-size: 16px; color: #0f172a; margin-right: 8px; vertical-align: middle;">{target_name}</strong>'

        # Hardware / network metadata
        ip_val = item.get("discovered_ip")
        mac_val = item.get("discovered_mac")
        mfg_val = item.get("discovered_manufacturer")
        if mfg_val and str(mfg_val).strip().upper() in ("", "NONE"):
            mfg_val = None

        mfg_img_html = ""
        if mfg_val:
            mfg_path = fn_get_mfg_path(mfg_val)
            if mfg_path and mfg_path.is_file():
                mfg_cid = get_inline_image_cid(mfg_path, "mfg_icon")
                mfg_img_html = f'<img src="cid:{mfg_cid}" alt="" height="14" style="height: 14px; max-height: 14px; max-width: 24px; object-fit: contain; vertical-align: middle; margin-right: 4px;" />'

        meta_chips = []
        if ip_val:
            meta_chips.append(f'<span style="display: inline-block; background: #f1f5f9; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 11.5px; color: #0f172a; margin-right: 6px; margin-bottom: 4px;"><strong>IP:</strong> {ip_val}</span>')
        if mac_val:
            meta_chips.append(f'<span style="display: inline-block; background: #f1f5f9; padding: 2px 7px; border-radius: 4px; font-family: monospace; font-size: 11.5px; color: #334155; margin-right: 6px; margin-bottom: 4px;"><strong>MAC:</strong> {mac_val}</span>')
        if mfg_val:
            meta_chips.append(f'<span style="display: inline-block; background: #f1f5f9; padding: 2px 7px; border-radius: 4px; font-size: 11.5px; color: #334155; margin-right: 6px; margin-bottom: 4px; vertical-align: middle;">{mfg_img_html}<strong>Mfg:</strong> {mfg_val}</span>')

        network_meta_html = ""
        if meta_chips:
            joined_chips = "".join(meta_chips)
            network_meta_html = f'<div style="margin: 6px 0 8px 0; line-height: 1.5;">{joined_chips}</div>'

        ports_html = ""
        if item.get("port_changes"):
            p_items = "".join(f"<li style='margin: 4px 0;'>{format_port_change_html(str(p))}</li>" for p in item["port_changes"])
            ports_html = f"<div style='margin-top: 10px; padding-top: 8px; border-top: 1px dashed #e2e8f0; font-size: 13px; color: #475569;'><strong style='color: #334155;'>Port Details:</strong><ul style='margin: 4px 0 0 18px; padding: 0;'>{p_items}</ul></div>"

        cards_html.append(
            f"""<div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px 16px; margin-bottom: 12px; background: #ffffff;">
  <div style="margin-bottom: 6px;">
    {svc_img_html}{svc_title_html}
    <span style="display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; background-color: {badge_color}; color: #ffffff; vertical-align: middle;">{new_st}</span>
  </div>
  {network_meta_html}
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
        app_mod = sys.modules.get("app")
        sender = getattr(app_mod, "send_email", send_email) if app_mod else send_email
        success, msg = sender(
            recipient,
            subject,
            body,
            settings=settings,
            html_body=html_body,
            inline_images=inline_attachments if inline_attachments else None,
        )
        if not success:
            print(f"[PulseCheck Alert Error] Failed to send state change notification: {msg}")
        return success, msg

    except Exception as exc:
        print(f"[PulseCheck Alert Error] Exception sending state change notification: {exc}")
        return False, str(exc)
