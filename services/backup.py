"""Encrypted backup and restore service for PulseCheck settings."""
from __future__ import annotations

import base64
import json
import os
import sys
import threading
import time
from datetime import datetime, timezone

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from core.config import APP_VERSION, DEFAULT_SETTINGS
from core.database import get_db_connection


class BackupError(Exception):
    """Base exception for backup operations."""
    pass


class InvalidPasswordError(BackupError):
    """Raised when password decryption fails."""
    pass


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(password.encode("utf-8"))


def export_settings_encrypted(password: str) -> bytes:
    """Export all system settings to an AES-256-GCM encrypted byte package.
    
    Raises ValueError if password is empty.
    """
    if not password or not str(password).strip():
        raise ValueError("Password is mandatory to export settings.")

    conn = get_db_connection()
    rows = conn.execute("SELECT key, value FROM settings").fetchall()
    user_rows = []
    try:
        user_rows = conn.execute("SELECT identifier, display_name, created_at, updated_at FROM authorized_users ORDER BY id ASC").fetchall()
    except Exception:
        pass
    conn.close()

    settings_dict = {}
    for row in rows:
        settings_dict[row["key"]] = row["value"]

    users_list = []
    for u in user_rows:
        users_list.append({
            "identifier": u["identifier"],
            "display_name": u["display_name"] or "",
            "created_at": u["created_at"],
            "updated_at": u["updated_at"],
        })

    payload = {
        "format": "pulsecheck-settings",
        "version": 2,
        "app_version": APP_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "settings": settings_dict,
        "authorized_users": users_list,
    }
    payload_bytes = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")

    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    ciphertext = aesgcm.encrypt(nonce, payload_bytes, None)

    envelope = {
        "magic": "PULSECHECK_BACKUP",
        "format_version": 1,
        "app_version": APP_VERSION,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }
    return json.dumps(envelope, indent=2).encode("utf-8")


def import_settings_encrypted(file_content: bytes | str, password: str) -> tuple[bool, str, int]:
    """Decrypt and import settings from an encrypted package.
    
    Returns (success: bool, message: str, count: int).
    """
    if not password or not str(password).strip():
        return False, "Decryption password is required.", 0

    if isinstance(file_content, bytes):
        try:
            file_str = file_content.decode("utf-8")
        except UnicodeDecodeError:
            return False, "File format is invalid or corrupted (not UTF-8).", 0
    else:
        file_str = file_content

    try:
        envelope = json.loads(file_str)
    except Exception:
        return False, "Invalid file format: not a valid PulseCheck backup file.", 0

    if not isinstance(envelope, dict) or envelope.get("magic") != "PULSECHECK_BACKUP":
        return False, "Unrecognized backup file. Missing PulseCheck signature.", 0

    try:
        salt = base64.b64decode(envelope["salt"])
        nonce = base64.b64decode(envelope["nonce"])
        ciphertext = base64.b64decode(envelope["ciphertext"])
    except Exception:
        return False, "Backup envelope is corrupted or improperly encoded.", 0

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    try:
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception:
        return False, "Incorrect password or corrupted file data.", 0

    try:
        data = json.loads(decrypted_bytes.decode("utf-8"))
    except Exception:
        return False, "Decrypted data is not valid JSON.", 0

    if not isinstance(data, dict) or "settings" not in data or not isinstance(data["settings"], dict):
        return False, "Decrypted package missing valid settings dictionary.", 0

    settings_to_apply = data["settings"]
    users_to_apply = data.get("authorized_users", [])
    if not settings_to_apply and not users_to_apply:
        return False, "Backup file contains no settings or user entries.", 0

    # Write settings and users into DB within a single transaction
    conn = get_db_connection()
    restored_users_count = 0
    try:
        with conn:
            for k, v in settings_to_apply.items():
                conn.execute(
                    "INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                    (str(k), str(v)),
                )
            if isinstance(users_to_apply, list):
                for u in users_to_apply:
                    if isinstance(u, dict) and u.get("identifier"):
                        ident = str(u["identifier"]).strip()
                        dname = str(u.get("display_name") or "").strip()
                        c_at = u.get("created_at") or datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
                        u_at = u.get("updated_at") or c_at
                        # Upsert user by identifier (case-insensitive check)
                        existing = conn.execute("SELECT id FROM authorized_users WHERE LOWER(identifier) = LOWER(?)", (ident,)).fetchone()
                        if existing:
                            conn.execute(
                                "UPDATE authorized_users SET identifier = ?, display_name = ?, updated_at = ? WHERE id = ?",
                                (ident, dname, u_at, existing["id"]),
                            )
                        else:
                            conn.execute(
                                "INSERT INTO authorized_users (identifier, display_name, created_at, updated_at) VALUES (?, ?, ?, ?)",
                                (ident, dname, c_at, u_at),
                            )
                        restored_users_count += 1
    finally:
        conn.close()

    msg = f"Successfully imported {len(settings_to_apply)} settings"
    if restored_users_count > 0:
        msg += f" and {restored_users_count} authorized users"
    msg += "."
    return True, msg, len(settings_to_apply)


def trigger_server_restart(delay_seconds: float = 1.0) -> None:
    """Schedule a server restart via os.execv in a background daemon thread."""
    def _restart():
        time.sleep(delay_seconds)
        app_mod = sys.modules.get("app") or sys.modules.get("__main__")

        # 1. Gracefully shut down and close the WSGI server socket
        if app_mod and hasattr(app_mod, "GLOBAL_SERVER"):
            server = getattr(app_mod, "GLOBAL_SERVER")
            if server:
                try:
                    server.shutdown()
                except Exception:
                    pass
                try:
                    server.server_close()
                except Exception:
                    pass

        # 2. Shut down background scheduler
        if app_mod and hasattr(app_mod, "GLOBAL_SCHEDULER"):
            try:
                scheduler = getattr(app_mod, "GLOBAL_SCHEDULER")
                if scheduler:
                    scheduler.shutdown(wait=False)
            except Exception:
                pass

        # 3. Clean up any leftover inherited server fd env variable
        os.environ.pop("WERKZEUG_SERVER_FD", None)

        # 4. Re-execute current Python interpreter with same arguments
        try:
            os.execv(sys.executable, [sys.executable] + sys.argv)
        except Exception as exc:
            print(f"[Backup] Failed to restart server via execv: {exc}", file=sys.stderr)
            os._exit(0)

    t = threading.Thread(target=_restart, daemon=True, name="pulsecheck-restart-worker")
    t.start()
