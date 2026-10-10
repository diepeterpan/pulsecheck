from __future__ import annotations

import sys
from flask import (
    Blueprint,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)

from core.database import (
    get_db_connection,
    get_service_by_id,
    normalize_service,
    normalize_url_path,
    derive_match,
    service_exists,
    service_list,
    parse_port_protocol,
    port_protocol_to_json,
)
from services.scanner import (
    scan_service,
    parse_diagnostic_ports,
    diagnose_service_ports,
    discover_ports as _scanner_discover_ports,
)
from services.icons import trigger_service_icon_resolution_async
from routes.auth import login_required

services_bp = Blueprint("services_bp", __name__)


def _get_app_attr(name: str, default=None):
    """Retrieve attribute from app module if patched or imported there."""
    app_mod = sys.modules.get("app") or sys.modules.get("__main__")
    if app_mod and hasattr(app_mod, name):
        return getattr(app_mod, name)
    return default


def discover_ports(service_name: str, progress_callback=None, cancelled_check=None) -> list[dict]:
    fn = _get_app_attr("discover_ports", _scanner_discover_ports)
    if fn:
        return fn(service_name, progress_callback=progress_callback, cancelled_check=cancelled_check)
    return []


def sync_service_ports(service_id: int, service_name: str, detected_ports: list | None = None):
    """Sync port list to DB (list[dict] or list[int]) and trigger a scan."""
    fn_disc = _get_app_attr("discover_ports", discover_ports)
    if detected_ports is not None:
        raw = detected_ports
    else:
        raw = fn_disc(service_name)
    # Normalise to list[dict]
    if raw and isinstance(raw[0], int):
        ports = [{"port": p, "protocol": ""} for p in raw]
    else:
        ports = [dict(p) for p in raw]
    conn = get_db_connection()
    conn.execute(
        "UPDATE services SET port_protocol = ? WHERE id = ?",
        (port_protocol_to_json(ports), service_id),
    )
    conn.commit()
    conn.close()
    service = get_service_by_id(service_id)
    scanner = _get_app_attr("scan_service", scan_service)
    scanner(
        service_id,
        service_name,
        ports,
        service["match"] if service else derive_match(service_name),
        url_path=service["url_path"] if service else "",
    )


def add_service(
    service_name: str | None = None,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool = False,
    comment: str = "",
    use_proxy: bool = False,
    name: str | None = None,
    ports: list | str | None = None,
    icmp_enabled: bool | None = None,
    protocol: str = "",
    port_protocol: list | str | None = None,
    http_username: str = "",
    http_password: str = "",
):
    """Add a new service. `ports` or `port_protocol` may be a JSON string, a list[dict], or a list[int]."""
    target_name = service_name if service_name is not None else name
    if not target_name:
        raise ValueError("Service name cannot be empty.")
    normalized = normalize_service(target_name)
    if service_exists(normalized):
        return None
    service_match = (match if match is not None else derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    target_ports = port_protocol if port_protocol is not None else ports
    detected: list[dict] = []
    if target_ports is not None and target_ports != "" and target_ports != []:
        detected = parse_diagnostic_ports(target_ports)
    elif target_ports is None and not paused:
        fn_disc = _get_app_attr("discover_ports", discover_ports)
        detected = parse_diagnostic_ports(fn_disc(normalized))
    clean_proto = (protocol or "").strip().lower()
    if clean_proto:
        if clean_proto in ("icmp", "icmp-ping"):
            if not detected:
                icmp_enabled = True
            else:
                for p in detected:
                    if p.get("port") is not None and not p.get("protocol"):
                        p["protocol"] = clean_proto
        else:
            for p in detected:
                if p.get("port") is not None and not p.get("protocol"):
                    p["protocol"] = clean_proto
    # Add / remove ICMP entry if requested
    if icmp_enabled is not None:
        detected = [p for p in detected if p.get("port") is not None]  # remove any stale ICMP
        if icmp_enabled:
            detected.append({"port": None, "protocol": "icmp-ping"})
    for p in detected:
        if p.get("port") is not None:
            if not p.get("match") and service_match:
                p["match"] = service_match
            if not p.get("url_path") and normalized_path:
                p["url_path"] = normalized_path
        else:
            p["match"] = ""
            p["url_path"] = ""

    clean_user = (http_username or "").strip()
    clean_pass = str(http_password or "")

    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO services (name, comment, paused, use_proxy, request_type, port_protocol, http_username, http_password) VALUES (?, ?, ?, ?, 'web', ?, ?, ?)",
        (normalized, (comment or "").strip(), int(paused), int(use_proxy), port_protocol_to_json(detected), clean_user, clean_pass),
    )
    conn.commit()
    service_id = cursor.lastrowid
    conn.close()
    if detected and not paused:
        scanner = _get_app_attr("scan_service", scan_service)
        scanner(service_id, normalized, detected, service_match, url_path=normalized_path, use_proxy=use_proxy, http_username=clean_user, http_password=clean_pass)
    return service_id


def update_service(
    service_id: int,
    name: str,
    ports_input,
    match: str | None = None,
    url_path: str | None = None,
    paused: bool | None = None,
    comment: str | None = None,
    use_proxy: bool | None = None,
    icmp_enabled: bool | None = None,
    protocol: str | None = None,
    http_username: str | None = None,
    http_password: str | None = None,
):
    """Update a service."""
    normalized = normalize_service(name)
    service_match = (match if match is not None else derive_match(normalized)).strip().lower()
    normalized_path = normalize_url_path(url_path)
    existing_service = None
    if (
        paused is None
        or comment is None
        or use_proxy is None
        or http_username is None
        or http_password is None
        or http_password == ""
    ):
        existing_service = get_service_by_id(service_id)

    if paused is None:
        paused = existing_service["paused"] if existing_service else False

    if use_proxy is None:
        use_proxy_val = existing_service["use_proxy"] if existing_service and "use_proxy" in existing_service else False
    else:
        use_proxy_val = bool(use_proxy)

    if comment is None:
        comment_val = existing_service["comment"] if existing_service and "comment" in existing_service.keys() else ""
    else:
        comment_val = str(comment).strip()

    if http_username is None:
        user_val = existing_service["http_username"] if existing_service and "http_username" in existing_service.keys() else ""
    else:
        user_val = str(http_username).strip()

    if http_password is None or (http_password == "" and existing_service and existing_service.get("http_password") and user_val):
        pass_val = existing_service["http_password"] if existing_service and "http_password" in existing_service.keys() else ""
    else:
        pass_val = str(http_password)

    # If username is cleared, clear password as well
    if not user_val:
        pass_val = ""

    # Parse incoming ports to list[dict]
    parsed_ports = parse_diagnostic_ports(ports_input) if ports_input else []
    had_icmp_in_input = any(p.get("port") is None for p in parsed_ports)
    incoming_ports = [p for p in parsed_ports if p.get("port") is not None]

    if protocol is not None:
        clean_proto = (protocol or "").strip().lower()
        if clean_proto in ("icmp", "icmp-ping"):
            if not incoming_ports:
                icmp_enabled = True
            else:
                for p in incoming_ports:
                    if p.get("port") is not None and not p.get("protocol"):
                        p["protocol"] = clean_proto
        elif clean_proto:
            for p in incoming_ports:
                if p.get("port") is not None and not p.get("protocol"):
                    p["protocol"] = clean_proto

    # Handle ICMP
    if icmp_enabled is None:
        if had_icmp_in_input:
            icmp_enabled = True
        else:
            if existing_service is None:
                existing_service = get_service_by_id(service_id)
            if existing_service:
                existing_ports = existing_service.get("ports") or []
                icmp_enabled = any(p.get("port") is None for p in existing_ports)
            else:
                icmp_enabled = False

    if icmp_enabled:
        incoming_ports.append({"port": None, "protocol": "icmp-ping"})

    for p in incoming_ports:
        if p.get("port") is not None:
            if not p.get("match") and service_match:
                p["match"] = service_match
            if not p.get("url_path") and normalized_path:
                p["url_path"] = normalized_path
        else:
            p["match"] = ""
            p["url_path"] = ""

    conn = get_db_connection()
    conn.execute(
        "UPDATE services SET name = ?, comment = ?, paused = ?, use_proxy = ?, port_protocol = ?, http_username = ?, http_password = ? WHERE id = ?",
        (
            normalized,
            comment_val,
            int(paused),
            int(use_proxy_val),
            port_protocol_to_json(incoming_ports),
            user_val,
            pass_val,
            service_id,
        ),
    )
    # Clean up obsolete port_checks for removed ports and remove all latest_port_checks records for this service
    conn.execute("DELETE FROM latest_port_checks WHERE service_id = ?", (service_id,))
    configured_ports = {p.get("port") for p in incoming_ports}
    if None not in configured_ports:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NULL", (service_id,))
    numeric_ports = [p["port"] for p in incoming_ports if p.get("port") is not None]
    if numeric_ports:
        placeholders = ", ".join("?" for _ in numeric_ports)
        conn.execute(f"DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL AND port NOT IN ({placeholders})", (service_id, *numeric_ports))
    else:
        conn.execute("DELETE FROM port_checks WHERE service_id = ? AND port IS NOT NULL", (service_id,))
    conn.commit()
    conn.close()
    if incoming_ports and not paused:
        scanner = _get_app_attr("scan_service", scan_service)
        scanner(service_id, normalized, incoming_ports, service_match, url_path=normalized_path, use_proxy=use_proxy_val, http_username=user_val, http_password=pass_val)


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


def bulk_update_ports(service_ids, action: str, ports_input: str):
    """Add or remove ports for the selected services."""
    new_port_nums = parse_port_values(ports_input)
    if not service_ids:
        raise ValueError("Select at least one service.")
    if action not in {"add", "remove"}:
        raise ValueError("Choose whether to add or remove ports.")
    if not new_port_nums:
        raise ValueError("Enter at least one port.")

    conn = get_db_connection()
    placeholders = ", ".join("?" for _ in service_ids)
    rows = conn.execute(
        f"SELECT id, port_protocol FROM services WHERE id IN ({placeholders})",
        tuple(service_ids),
    ).fetchall()
    found_ids = {row["id"] for row in rows}
    if found_ids != set(service_ids):
        conn.close()
        raise ValueError("One or more selected services no longer exists.")

    for row in rows:
        current_ports: list[dict] = parse_port_protocol(row["port_protocol"])
        current_port_nums = {p["port"] for p in current_ports if p.get("port") is not None}
        if action == "add":
            for pnum in new_port_nums:
                if pnum not in current_port_nums:
                    current_ports.append({"port": pnum, "protocol": ""})
                    current_port_nums.add(pnum)
        else:
            current_ports = [p for p in current_ports if p.get("port") not in set(new_port_nums)]
        conn.execute(
            "UPDATE services SET port_protocol = ? WHERE id = ?",
            (port_protocol_to_json(current_ports), row["id"]),
        )
        if action == "remove":
            port_placeholders = ", ".join("?" for _ in new_port_nums)
            conn.execute(
                f"DELETE FROM port_checks WHERE service_id = ? AND port IN ({port_placeholders})",
                (row["id"], *new_port_nums),
            )
            conn.execute(
                f"DELETE FROM latest_port_checks WHERE service_id = ? AND port IN ({port_placeholders})",
                (row["id"], *new_port_nums),
            )
    conn.commit()
    conn.close()


def delete_service(service_id: int):
    conn = get_db_connection()
    conn.execute("DELETE FROM port_checks WHERE service_id = ?", (service_id,))
    conn.execute("DELETE FROM latest_port_checks WHERE service_id = ?", (service_id,))
    conn.execute("DELETE FROM services WHERE id = ?", (service_id,))
    conn.commit()
    conn.close()


@services_bp.route("/services", endpoint="services")
@login_required
def services():
    items = service_list()
    return render_template("services.html", services=items)


@services_bp.route("/services/add", methods=["GET", "POST"], endpoint="add_service_route")
@login_required
def add_service_route():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        comment = request.form.get("comment", "").strip()
        url_path = request.form.get("url_path", "").strip()
        http_username = request.form.get("http_username", "").strip()
        http_password = request.form.get("http_password", "")
        ports_json_input = request.form.get("ports_json", "").strip()
        ports_input = ports_json_input or request.form.get("ports", "").strip()
        icmp_raw = request.form.get("icmp_enabled")
        icmp_enabled = icmp_raw in ("on", "1", "true", "icmp-ping", "icmp")
        paused = request.form.get("paused") == "on" or request.form.get("paused") == "1"
        use_proxy = request.form.get("use_proxy") == "on" or request.form.get("use_proxy") == "1"
        if not name:
            flash("A service name is required.")
            return redirect(url_for("add_service_route"))
        try:
            fn_add = _get_app_attr("add_service", add_service)
            result = fn_add(
                name=name,
                match=match,
                url_path=url_path,
                comment=comment,
                paused=paused,
                use_proxy=use_proxy,
                ports=ports_input if ports_input else [],
                icmp_enabled=icmp_enabled,
                http_username=http_username,
                http_password=http_password,
            )
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("add_service_route"))
        if result is None:
            flash("That service already exists.")
            return redirect(url_for("services"))

        fn_disc_async = _get_app_attr("trigger_discovery_async")
        if fn_disc_async:
            fn_disc_async(result, normalize_service(name))
        trigger_service_icon_resolution_async(name, http_username=http_username, http_password=http_password)
        flash(f"Added service {name}.")
        return redirect(url_for("services"))

    return render_template("add_service.html")


@services_bp.route("/services/bulk-ports", methods=["POST"], endpoint="bulk_ports_route")
@login_required
def bulk_ports_route():
    raw_ids = request.form.getlist("service_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    try:
        service_ids = sorted({int(value) for value in raw_ids})
        fn_bulk = _get_app_attr("bulk_update_ports", bulk_update_ports)
        fn_bulk(
            service_ids,
            request.form.get("port_action", ""),
            request.form.get("ports", ""),
        )
    except (TypeError, ValueError) as exc:
        flash(str(exc))
        return redirect(return_to or url_for("services"))
    flash("Updated ports for the selected services.")
    return redirect(return_to or url_for("services"))


@services_bp.route("/services/bulk-delete", methods=["POST"], endpoint="bulk_delete_route")
@login_required
def bulk_delete_route():
    raw_ids = request.form.getlist("service_ids")
    return_to = request.form.get("return_to", "").strip()
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    try:
        service_ids = sorted({int(value) for value in raw_ids})
    except ValueError:
        flash("Invalid service selection.")
        return redirect(return_to or url_for("services"))
    if not service_ids:
        flash("Select at least one service to delete.")
        return redirect(return_to or url_for("services"))

    deleted = 0
    fn_del = _get_app_attr("delete_service", delete_service)
    for service_id in service_ids:
        if get_service_by_id(service_id) is not None:
            fn_del(service_id)
            deleted += 1
    flash(f"Deleted {deleted} selected service{'s' if deleted != 1 else ''}.")
    return redirect(return_to or url_for("services"))


@services_bp.route("/services/<int:service_id>/edit", methods=["GET", "POST"], endpoint="edit_service")
@login_required
def edit_service(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        flash("Service not found.")
        return redirect(url_for("services"))

    return_to = request.args.get("return_to") or request.form.get("return_to") or ""
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        match = request.form.get("match", "").strip()
        url_path = request.form.get("url_path", "")
        comment = request.form.get("comment", "").strip()
        http_username = request.form.get("http_username", "").strip()
        http_password = request.form.get("http_password", "")
        ports_json_input = request.form.get("ports_json", "").strip()
        ports_input = ports_json_input or request.form.get("ports", "")
        icmp_raw = request.form.get("icmp_enabled")
        icmp_enabled = icmp_raw in ("on", "1", "true", "icmp-ping", "icmp")
        paused = request.form.get("paused") == "on"
        use_proxy = request.form.get("use_proxy") == "on" or request.form.get("use_proxy") == "1"
        old_name = service["name"]
        try:
            fn_update = _get_app_attr("update_service", update_service)
            fn_update(
                service_id,
                name,
                ports_input,
                match,
                url_path,
                paused,
                comment=comment,
                use_proxy=use_proxy,
                icmp_enabled=icmp_enabled,
                http_username=http_username,
                http_password=http_password,
            )
        except ValueError as exc:
            flash(str(exc))
            return redirect(url_for("edit_service", service_id=service_id, return_to=return_to))
        if normalize_service(name) != old_name:
            svc = get_service_by_id(service_id)
            fn_disc_async = _get_app_attr("trigger_discovery_async")
            if fn_disc_async:
                fn_disc_async(service_id, normalize_service(name),
                              prev_mac=svc.get("discovered_mac") if svc else None)
        svc_fresh = get_service_by_id(service_id) or {}
        trigger_service_icon_resolution_async(
            name,
            http_username=svc_fresh.get("http_username", ""),
            http_password=svc_fresh.get("http_password", ""),
        )
        flash(f"Updated service {name}.")
        return redirect(return_to or url_for("services"))

    return render_template("edit_service.html", service=service, return_to=return_to)


@services_bp.route("/services/<int:service_id>/test", methods=["POST"], endpoint="test_service_edit_route")
@login_required
def test_service_edit_route(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        return jsonify({"success": False, "error": "Service not found."}), 404

    data = request.get_json(silent=True) or request.form

    service_name = (data.get("name") or data.get("service_name") or service["name"]).strip()
    match = data.get("match") if "match" in data else service["match"]
    url_path = data.get("url_path") if "url_path" in data else service.get("url_path", "")

    http_username = data.get("http_username") if "http_username" in data else service.get("http_username", "")
    http_username = (http_username or "").strip()
    http_password = data.get("http_password") if "http_password" in data else service.get("http_password", "")
    if (http_password is None or http_password == "") and http_username and service.get("http_password"):
        http_password = service.get("http_password", "")

    raw_proxy = data.get("use_proxy")
    if raw_proxy is not None:
        use_proxy = raw_proxy is True or str(raw_proxy).lower() in ("true", "1", "on")
    else:
        use_proxy = bool(service.get("use_proxy"))

    ports_input = data.get("ports")
    icmp_raw = data.get("icmp_enabled")
    icmp_enabled = icmp_raw is True or str(icmp_raw).lower() in ("true", "1", "on", "icmp-ping", "icmp") if icmp_raw is not None else False

    if ports_input is None:
        ports = list(service["ports"])
    else:
        ports = parse_diagnostic_ports(ports_input)

    if icmp_enabled and not any(p.get("port") is None for p in ports):
        ports.append({"port": None, "protocol": "icmp-ping"})

    if not service_name:
        return jsonify({"success": False, "error": "Service name cannot be empty."}), 400
    if not ports:
        return jsonify({"success": False, "error": "No valid ports specified to test."}), 400

    fn_diagnose = _get_app_attr("diagnose_service_ports", diagnose_service_ports)
    results = fn_diagnose(
        service_name=service_name,
        ports=ports,
        match=match or "",
        url_path=url_path or "",
        use_proxy=use_proxy,
        http_username=http_username,
        http_password=http_password,
    )
    return jsonify(results)


@services_bp.route("/services/test", methods=["POST"], endpoint="test_service_generic_route")
@login_required
def test_service_generic_route():
    data = request.get_json(silent=True) or request.form
    service_name = (data.get("name") or data.get("service_name") or "").strip()
    match = (data.get("match") or "").strip()
    url_path = data.get("url_path") or ""
    http_username = (data.get("http_username") or "").strip()
    http_password = data.get("http_password") or ""
    raw_proxy = data.get("use_proxy")
    use_proxy = raw_proxy is True or str(raw_proxy).lower() in ("true", "1", "on")
    ports_input = data.get("ports") or ""
    ports = parse_diagnostic_ports(ports_input)
    icmp_raw = data.get("icmp_enabled")
    icmp_enabled = icmp_raw is True or str(icmp_raw).lower() in ("true", "1", "on", "icmp-ping", "icmp") if icmp_raw is not None else False
    if icmp_enabled:
        if not any(p.get("port") is None for p in ports):
            ports.append({"port": None, "protocol": "icmp-ping"})

    if not service_name:
        return jsonify({"success": False, "error": "Service name cannot be empty."}), 400
    if not ports:
        return jsonify({"success": False, "error": "No valid ports specified to test."}), 400

    match_to_use = match or derive_match(service_name)
    fn_diagnose = _get_app_attr("diagnose_service_ports", diagnose_service_ports)
    results = fn_diagnose(
        service_name=service_name,
        ports=ports,
        match=match_to_use,
        url_path=url_path,
        use_proxy=use_proxy,
        http_username=http_username,
        http_password=http_password,
    )
    return jsonify(results)


@services_bp.route("/services/<int:service_id>/delete", methods=["POST"], endpoint="delete_service_route")
@login_required
def delete_service_route(service_id):
    service = get_service_by_id(service_id)
    return_to = request.form.get("return_to") or request.args.get("return_to") or ""
    if not (
        return_to.startswith("/services")
        or return_to.startswith("services")
    ):
        return_to = ""
    if service is not None:
        fn_del = _get_app_attr("delete_service", delete_service)
        fn_del(service_id)
        flash(f"Deleted service {service['name']}.")
    return redirect(return_to or url_for("services"))


@services_bp.route("/services/<int:service_id>/rescan", methods=["POST"], endpoint="rescan_service_route")
@login_required
def rescan_service_route(service_id):
    service = get_service_by_id(service_id)
    if service is None:
        flash("Service not found.")
        return redirect(url_for("services"))
    scanner = _get_app_attr("scan_service", scan_service)
    scanner(
        service_id,
        service["name"],
        service["ports"],
        service["match"],
        url_path=service["url_path"],
        use_proxy=service.get("use_proxy", False),
    )
    flash(f"Rescanned {service['name']}.")
    return redirect(url_for("status"))
