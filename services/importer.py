"""CSV and text service import/export handling."""
from __future__ import annotations

import base64
import csv
import io
import os
import re
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from core.database import (
    get_db_connection,
    normalize_service,
    derive_match,
    normalize_url_path,
    service_exists,
    service_list,
    port_protocol_to_json,
    format_hex_bytes,
)
from core.config import HTTPS_PORTS
from services.scanner import (
    discover_ports as _scanner_discover_ports,
    parse_diagnostic_ports as _scanner_parse_diagnostic_ports,
    diagnose_service_ports as _scanner_diagnose_service_ports,
    scan_service as _scanner_scan_service,
)
from services.scheduler import trigger_discovery_async as _scheduler_trigger_discovery_async
from services.icons import trigger_service_icon_resolution_async as _icons_trigger_service_icon_resolution_async


class ImportCancelled(Exception):
    pass


class EncryptedPasswordError(Exception):
    pass


def encrypt_csv_password(password_plain: str, key_phrase: str) -> str:
    """Encrypt a password string using AES-256-GCM and PBKDF2-HMAC-SHA256."""
    if not password_plain or not key_phrase:
        return password_plain
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(key_phrase.encode("utf-8"))
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ct = aesgcm.encrypt(nonce, password_plain.encode("utf-8"), None)
    payload = salt + nonce + ct
    return "ENC:v1:" + base64.b64encode(payload).decode("ascii")


def decrypt_csv_password(enc_token: str, key_phrase: str) -> str:
    """Decrypt a password token produced by encrypt_csv_password.
    Raises EncryptedPasswordError on missing password or authentication tag failure."""
    if not enc_token or not enc_token.startswith("ENC:v1:"):
        return enc_token
    if not key_phrase:
        raise EncryptedPasswordError("Decryption password required for encrypted password field.")
    try:
        raw = base64.b64decode(enc_token[7:])
        salt = raw[:16]
        nonce = raw[16:28]
        ct = raw[28:]
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = kdf.derive(key_phrase.encode("utf-8"))
        aesgcm = AESGCM(key)
        pt = aesgcm.decrypt(nonce, ct, None)
        return pt.decode("utf-8")
    except Exception as exc:
        raise EncryptedPasswordError(f"Failed to decrypt password: {exc}") from exc


def has_encrypted_csv_fields(csv_content: str) -> bool:
    """Check if CSV content contains any ENC:v1: tokens."""
    return "ENC:v1:" in csv_content


def _get_app_attr(name: str, default=None):
    """Retrieve attribute from app module if imported/patched there, else fall back to default."""
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod is not None and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


def parse_csv_ports(value: str) -> list[dict] | None:
    """Parse a CSV ports field into list[dict] with port+protocol keys."""
    clean = (value or "").strip().strip("[]()")
    if not clean:
        return None
    result = []
    for part in re.split(r"[,;]+", clean):
        cleaned = part.strip().lower()
        if not cleaned:
            continue
        if cleaned in ("icmp", "icmp-ping"):
            result.append({"port": None, "protocol": "icmp-ping"})
            continue
        try:
            p = int(cleaned)
            if 1 <= p <= 65535:
                result.append({"port": p, "protocol": ""})
        except ValueError:
            pass
    return result or None


def apply_csv_protocols(port_list: list[dict], protocols_str: str) -> list[dict]:
    """Zip a port list with a comma-separated protocol string by position."""
    proto_parts = [p.strip().lower() for p in re.split(r"[,;]+", protocols_str or "") if p.strip()]
    result = [dict(p) for p in port_list]
    for i, port_entry in enumerate(result):
        if i < len(proto_parts) and proto_parts[i]:
            result[i]["protocol"] = proto_parts[i]
    return result


def export_services_csv(encryption_password: str = "") -> tuple[str, int]:
    services = service_list()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "Service", "Comment", "Paused", "Proxy", "Protocol", "Ports",
        "Request Type", "URL path", "Match", "Request", "Response",
        "HTTP Username", "HTTP Password"
    ])
    for s in services:
        ports_list: list[dict] = s["ports"]
        tcp_ports = [p for p in ports_list if p.get("port") is not None]
        icmp_present = any(p.get("port") is None for p in ports_list)
        ordered_ports = list(tcp_ports)
        if icmp_present:
            ordered_ports.append({"port": None, "protocol": "icmp-ping", "request_type": "web", "match": "", "url_path": "", "request_payload": "", "response_payload": ""})

        port_nums = [str(p["port"]) if p.get("port") is not None else "icmp" for p in ordered_ports]
        port_protos = [p.get("protocol") or ("icmp-ping" if p.get("port") is None else "") for p in ordered_ports]
        port_rtypes = [(p.get("request_type") or "web") for p in ordered_ports]
        port_matches = [p.get("match") or "" for p in ordered_ports]
        port_url_paths = [p.get("url_path") or "" for p in ordered_ports]
        port_req_payloads = [p.get("request_payload") or "" for p in ordered_ports]
        port_resp_payloads = [p.get("response_payload") or "" for p in ordered_ports]

        distinct_protos = {pr for pr in port_protos if pr}
        if len(distinct_protos) == 1:
            proto_str = list(distinct_protos)[0]
        elif len(distinct_protos) > 1:
            proto_str = ", ".join(port_protos)
        else:
            proto_str = s.get("protocol") or ""

        distinct_rtypes = set(port_rtypes)
        if len(distinct_rtypes) == 1:
            rtype_str = list(distinct_rtypes)[0]
        else:
            rtype_str = ", ".join(port_rtypes)

        tcp_matches = [p.get("match") or "" for p in tcp_ports]
        tcp_url_paths = [p.get("url_path") or "" for p in tcp_ports]
        tcp_req_payloads = [p.get("request_payload") or "" for p in tcp_ports]
        tcp_resp_payloads = [p.get("response_payload") or "" for p in tcp_ports]

        non_empty_matches = [m for m in tcp_matches if m]
        if not non_empty_matches:
            match_str = ""
        elif len(set(tcp_matches)) == 1:
            match_str = tcp_matches[0]
        else:
            match_str = ", ".join(port_matches)

        non_empty_paths = [p for p in tcp_url_paths if p]
        if not non_empty_paths:
            path_str = ""
        elif len(set(tcp_url_paths)) == 1:
            path_str = tcp_url_paths[0]
        else:
            path_str = ", ".join(port_url_paths)

        non_empty_req_payloads = [p for p in tcp_req_payloads if p]
        if not non_empty_req_payloads:
            req_str = ""
        elif len(set(tcp_req_payloads)) == 1:
            req_str = tcp_req_payloads[0]
        else:
            req_str = ", ".join(port_req_payloads)

        non_empty_resp_payloads = [p for p in tcp_resp_payloads if p]
        if not non_empty_resp_payloads:
            resp_str = ""
        elif len(set(tcp_resp_payloads)) == 1:
            resp_str = tcp_resp_payloads[0]
        else:
            resp_str = ", ".join(port_resp_payloads)

        raw_user = s.get("http_username", "") or ""
        raw_pass = s.get("http_password", "") or ""
        if raw_pass and encryption_password:
            pass_exported = encrypt_csv_password(raw_pass, encryption_password)
        else:
            pass_exported = raw_pass

        writer.writerow([
            s["name"],
            s.get("comment", "") or "",
            "1" if s["paused"] else "0",
            "1" if s.get("use_proxy") else "0",
            proto_str,
            ", ".join(port_nums),
            rtype_str,
            path_str,
            match_str,
            req_str,
            resp_str,
            raw_user,
            pass_exported,
        ])
    return output.getvalue(), len(services)


def import_services_from_csv(
    csv_content: str,
    progress_callback=None,
    cancelled_check=None,
    decryption_password: str = "",
) -> dict:
    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "invalid": 0,
        "imported_services": [],
        "skipped_services": [],
        "invalid_rows": [],
    }

    raw_rows = [r for r in csv.reader(io.StringIO(csv_content)) if r and any(cell.strip() for cell in r)]
    if not raw_rows:
        return summary

    col_map = {}
    first_cells = [c.strip().lower() for c in raw_rows[0]]
    if any(h in first_cells for h in ("service", "service name", "name")):
        for idx, col in enumerate(first_cells):
            if col in ("service", "service name", "name"):
                col_map["service"] = idx
            elif col in ("match", "service match"):
                col_map["match"] = idx
            elif col in ("url path", "url_path", "path", "url"):
                col_map["url_path"] = idx
            elif col in ("comment", "comments", "note", "notes"):
                col_map["comment"] = idx
            elif col in ("paused", "is_paused"):
                col_map["paused"] = idx
            elif col in ("proxy", "use_proxy", "use proxy", "is_proxy", "proxy server", "proxy_server"):
                col_map["proxy"] = idx
            elif col in ("protocol", "proto", "service protocol"):
                col_map["protocol"] = idx
            elif col in ("ports", "port", "monitored ports"):
                col_map["ports"] = idx
            elif col in ("port protocols", "port_protocols", "protocols", "port protocol"):
                col_map["port_protocols"] = idx
            elif col in ("request type", "request_type", "type"):
                col_map["request_type"] = idx
            elif col in ("request", "request payload", "request_payload", "req"):
                col_map["request"] = idx
            elif col in ("response", "response payload", "response_payload", "resp"):
                col_map["response"] = idx
            elif col in ("http username", "http_username", "username", "auth username", "user"):
                col_map["http_username"] = idx
            elif col in ("http password", "http_password", "password", "auth password", "pass"):
                col_map["http_password"] = idx
        data_rows = raw_rows[1:]
    else:
        first_len = len(raw_rows[0])
        if first_len >= 13:
            col_map = {"service": 0, "comment": 1, "paused": 2, "proxy": 3, "protocol": 4, "ports": 5, "request_type": 6, "url_path": 7, "match": 8, "request": 9, "response": 10, "http_username": 11, "http_password": 12}
        elif first_len >= 11:
            col_map = {"service": 0, "comment": 1, "paused": 2, "proxy": 3, "protocol": 4, "ports": 5, "request_type": 6, "url_path": 7, "match": 8, "request": 9, "response": 10}
        elif first_len >= 8:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "proxy": 5, "protocol": 6, "ports": 7}
        elif first_len == 7:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "proxy": 5, "ports": 6}
        elif first_len == 6:
            col_map = {"service": 0, "match": 1, "url_path": 2, "comment": 3, "paused": 4, "ports": 5}
        else:
            col_map = {"service": 0, "match": 1, "url_path": 2, "paused": 3, "ports": 4}
        data_rows = raw_rows

    total_records = len(data_rows)

    ImportCancelled_cls = _get_app_attr("ImportCancelled", ImportCancelled)
    for index, row in enumerate(data_rows, start=1):
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled_cls("Import cancelled")

        summary["total"] += 1
        s_idx = col_map.get("service", 0)
        service_val = row[s_idx].strip() if s_idx < len(row) else ""

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total_records,
                "service": service_val or f"Record {index}",
                "status": "processing",
                "message": f"Processing record {index} of {total_records}: {service_val}",
            })

        if not service_val or any(c.isspace() for c in service_val):
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid service '{service_val}'")
            continue

        try:
            normalized = normalize_service(service_val)
        except ValueError:
            summary["invalid"] += 1
            summary["invalid_rows"].append(f"Row {index}: Invalid service '{service_val}'")
            continue

        if service_exists(normalized):
            summary["skipped"] += 1
            summary["skipped_services"].append(normalized)
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

        prx_idx = col_map.get("proxy", -1)
        proxy_raw = row[prx_idx].strip().lower() if prx_idx != -1 and prx_idx < len(row) else "0"
        proxy_val = proxy_raw in ("1", "true", "yes", "t", "y")

        prto_idx = col_map.get("protocol", -1)
        protocol_val = row[prto_idx].strip().lower() if prto_idx != -1 and prto_idx < len(row) else ""

        user_idx = col_map.get("http_username", -1)
        http_username_val = row[user_idx].strip() if user_idx != -1 and user_idx < len(row) else ""

        pass_idx = col_map.get("http_password", -1)
        http_password_raw = row[pass_idx].strip() if pass_idx != -1 and pass_idx < len(row) else ""
        if http_password_raw.startswith("ENC:v1:"):
            http_password_val = decrypt_csv_password(http_password_raw, decryption_password)
        else:
            http_password_val = http_password_raw

        pts_idx = col_map.get("ports", -1)
        ports_raw = row[pts_idx].strip() if pts_idx != -1 and pts_idx < len(row) else ""
        ports_val = parse_csv_ports(ports_raw) or []

        pproto_idx = col_map.get("port_protocols", -1)
        if pproto_idx != -1 and pproto_idx < len(row) and row[pproto_idx].strip():
            ports_val = apply_csv_protocols(ports_val, row[pproto_idx].strip())
        elif protocol_val:
            if "," in protocol_val or ";" in protocol_val:
                ports_val = apply_csv_protocols(ports_val, protocol_val)
            else:
                ports_val = [{"port": p["port"], "protocol": protocol_val if p.get("port") is not None else "icmp-ping"} for p in ports_val]

        matches_raw = row[m_idx].strip() if m_idx != -1 and m_idx < len(row) else ""
        match_parts = [m.strip() for m in re.split(r"[,;]+", matches_raw)] if matches_raw else []

        paths_raw = row[u_idx].strip() if u_idx != -1 and u_idx < len(row) else ""
        path_parts = [p.strip() for p in re.split(r"[,;]+", paths_raw)] if paths_raw else []

        rtype_idx = col_map.get("request_type", -1)
        rtypes_raw = row[rtype_idx].strip() if rtype_idx != -1 and rtype_idx < len(row) else ""
        rtype_parts = [rt.strip().lower() for rt in re.split(r"[,;]+", rtypes_raw)] if rtypes_raw else []

        req_idx = col_map.get("request", -1)
        reqs_raw = row[req_idx].strip() if req_idx != -1 and req_idx < len(row) else ""
        req_parts = [rq.strip() for rq in re.split(r"[,;]+", reqs_raw)] if reqs_raw else []

        resp_idx = col_map.get("response", -1)
        resps_raw = row[resp_idx].strip() if resp_idx != -1 and resp_idx < len(row) else ""
        resp_parts = [rs.strip() for rs in re.split(r"[,;]+", resps_raw)] if resps_raw else []

        for i, p in enumerate(ports_val):
            if len(rtype_parts) == 1:
                rt = rtype_parts[0]
            elif i < len(rtype_parts):
                rt = rtype_parts[i]
            else:
                rt = "web"
            if rt not in ("web", "custom"):
                rt = "web"
            p["request_type"] = rt

            if p.get("port") is None:
                p["match"] = ""
                p["url_path"] = ""
                p["request_payload"] = ""
                p["response_payload"] = ""
            else:
                if rt == "custom":
                    p["match"] = ""
                    p["url_path"] = ""
                    if len(req_parts) == 1:
                        p["request_payload"] = format_hex_bytes(req_parts[0])
                    elif i < len(req_parts):
                        p["request_payload"] = format_hex_bytes(req_parts[i])
                    else:
                        p["request_payload"] = ""

                    if len(resp_parts) == 1:
                        p["response_payload"] = format_hex_bytes(resp_parts[0])
                    elif i < len(resp_parts):
                        p["response_payload"] = format_hex_bytes(resp_parts[i])
                    else:
                        p["response_payload"] = ""
                else:
                    p["request_payload"] = ""
                    p["response_payload"] = ""
                    if len(match_parts) == 1:
                        p["match"] = match_parts[0]
                    elif i < len(match_parts):
                        p["match"] = match_parts[i]
                    else:
                        p["match"] = ""

                    if len(path_parts) == 1:
                        p["url_path"] = path_parts[0]
                    elif i < len(path_parts):
                        p["url_path"] = path_parts[i]
                    else:
                        p["url_path"] = ""

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, comment, paused, use_proxy, request_type, port_protocol, http_username, http_password) VALUES (?, ?, ?, ?, 'web', ?, ?, ?)",
            (normalized, comment_val, int(paused_val), int(proxy_val), port_protocol_to_json(ports_val), http_username_val, http_password_val),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()

        trigger_discovery_async = _get_app_attr("trigger_discovery_async", _scheduler_trigger_discovery_async)
        trigger_service_icon_resolution_async = _get_app_attr("trigger_service_icon_resolution_async", _icons_trigger_service_icon_resolution_async)
        scan_service = _get_app_attr("scan_service", _scanner_scan_service)

        trigger_discovery_async(service_id, normalized)
        trigger_service_icon_resolution_async(normalized)

        if not paused_val and ports_val:
            if progress_callback is not None:
                port_nums_str = ", ".join(str(p["port"]) if p.get("port") is not None else "icmp" for p in ports_val)
                progress_callback({
                    "index": index,
                    "total": total_records,
                    "service": normalized,
                    "status": "scanning",
                    "message": f"Scanning ports for {normalized} ({port_nums_str})",
                })
            scan_service(service_id, normalized, ports_val, "", url_path="", use_proxy=proxy_val)

        summary["imported"] += 1
        summary["imported_services"].append(normalized)

    return summary


def import_service_names(service_names, progress_callback=None, cancelled_check=None):
    ImportCancelled_cls = _get_app_attr("ImportCancelled", ImportCancelled)
    discover_ports = _get_app_attr("discover_ports", _scanner_discover_ports)
    parse_diagnostic_ports = _get_app_attr("parse_diagnostic_ports", _scanner_parse_diagnostic_ports)
    diagnose_service_ports = _get_app_attr("diagnose_service_ports", _scanner_diagnose_service_ports)
    trigger_discovery_async = _get_app_attr("trigger_discovery_async", _scheduler_trigger_discovery_async)
    trigger_service_icon_resolution_async = _get_app_attr("trigger_service_icon_resolution_async", _icons_trigger_service_icon_resolution_async)
    scan_service = _get_app_attr("scan_service", _scanner_scan_service)
    https_ports_val = _get_app_attr("HTTPS_PORTS", HTTPS_PORTS)

    summary = {
        "total": 0,
        "imported": 0,
        "skipped": 0,
        "duplicates": [],
        "invalid": [],
    }

    entries = [str(value).strip() for value in service_names if str(value).strip()]
    total = len(entries)
    for index, value in enumerate(entries, start=1):
        summary["total"] += 1
        if cancelled_check is not None and cancelled_check():
            raise ImportCancelled_cls("Import cancelled")
        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "service": value,
                "port": None,
                "status": "checking",
                "message": f"Checking service {index} of {total}: {value}",
            })
        try:
            normalized = normalize_service(value)
        except ValueError:
            summary["invalid"].append(value)
            summary["skipped"] += 1
            continue

        if service_exists(normalized):
            summary["duplicates"].append(normalized)
            summary["skipped"] += 1
            continue

        if progress_callback is not None:
            progress_callback({
                "index": index,
                "total": total,
                "service": normalized,
                "port": None,
                "status": "scanning",
                "message": f"Scanning ports for {normalized}",
            })

        detected = discover_ports(
            normalized,
            progress_callback=lambda info, s=normalized: progress_callback({
                "index": index,
                "total": total,
                "service": s,
                "port": info["port"],
                "status": "port",
                "message": info["message"],
            }) if progress_callback else None,
            cancelled_check=cancelled_check,
        )

        derived = derive_match(normalized)
        detected_entries = parse_diagnostic_ports(detected)
        for p in detected_entries:
            if p.get("port") is not None:
                p["match"] = derived
                p["url_path"] = ""
            else:
                p["match"] = ""
                p["url_path"] = ""

        if detected_entries:
            if cancelled_check is not None and cancelled_check():
                raise ImportCancelled_cls("Import cancelled")
            if progress_callback is not None:
                progress_callback({
                    "index": index,
                    "total": total,
                    "service": normalized,
                    "port": None,
                    "status": "diagnosing",
                    "message": f"Diagnosing protocols for {normalized}",
                })

            diag_results = diagnose_service_ports(
                normalized,
                detected_entries,
                match=derived,
                url_path="",
            )

            if cancelled_check is not None and cancelled_check():
                raise ImportCancelled_cls("Import cancelled")

            diag_ports = {
                p_res.get("port"): p_res
                for p_res in (diag_results.get("ports") or [])
            }

            for p in detected_entries:
                p_num = p.get("port")
                diag = diag_ports.get(p_num)
                if diag and diag.get("status") == "online":
                    proto = (diag.get("protocol") or "").strip().lower()
                    if proto == "ssl-handshake":
                        proto = "https" if p_num in https_ports_val else "tcp-ssl"
                    if proto:
                        p["protocol"] = proto

        conn = get_db_connection()
        cursor = conn.execute(
            "INSERT INTO services (name, paused, request_type, port_protocol) VALUES (?, 0, 'web', ?)",
            (normalized, port_protocol_to_json(detected_entries)),
        )
        conn.commit()
        service_id = cursor.lastrowid
        conn.close()
        trigger_discovery_async(service_id, normalized)
        trigger_service_icon_resolution_async(normalized)
        scan_service(service_id, normalized, detected_entries, derived, url_path="")
        summary["imported"] += 1

    return summary
