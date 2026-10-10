from __future__ import annotations

import functools
import os
import urllib.parse
from flask import (
    Blueprint,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from authlib.integrations.flask_client import OAuth

from core.config import (
    OIDC_ENABLED,
    OIDC_ISSUER,
    OIDC_CLIENT_ID,
    OIDC_CLIENT_SECRET,
    OIDC_REDIRECT_URI,
    OIDC_SCOPES,
    OIDC_MATCH_CLAIM,
    OIDC_SSL_VERIFY,
)
from core.database import (
    get_settings,
    is_user_authorized,
    get_authorized_user_by_identifier,
)

auth_bp = Blueprint("auth_bp", __name__)
oauth = OAuth()


def is_oidc_active() -> bool:
    """Check if OIDC authentication is enabled via environment variable."""
    env_val = os.getenv("PULSECHECK_OIDC_ENABLED")
    if env_val is not None:
        return env_val.strip().lower() in ("true", "1", "yes")
    return bool(OIDC_ENABLED)


def get_active_match_claim() -> str:
    """Retrieve active match claim (from settings or fallback to env/default 'email')."""
    try:
        settings = get_settings()
        claim = settings.get("oidc_match_claim")
        if claim and claim.strip():
            return claim.strip()
    except Exception:
        pass
    env_claim = os.getenv("PULSECHECK_OIDC_MATCH_CLAIM")
    if env_claim and env_claim.strip():
        return env_claim.strip()
    return OIDC_MATCH_CLAIM or "email"


def get_oidc_ssl_verify() -> bool | str:
    """Resolve SSL certificate verification configuration for OIDC requests.
    Returns:
      - Path to custom CA certificate file (str) if a custom CA path is provided
      - False if explicitly disabled ('false', '0', 'no', 'insecure')
      - True (default) for standard system/certifi CA verification
    """
    raw_val = (os.getenv("PULSECHECK_OIDC_SSL_VERIFY") or OIDC_SSL_VERIFY or "true").strip()
    if raw_val.lower() in ("false", "0", "no", "disable", "disabled", "insecure"):
        return False
    if raw_val.lower() in ("true", "1", "yes", "default"):
        return True
    # If file exists or path specified, return path string
    return raw_val


def _enable_tolerant_ssl_verification() -> None:
    """Relax OpenSSL 3.x X509_V_FLAG_X509_STRICT (0x20) flag to permit internal
    CA-issued certificates that lack Authority Key Identifiers, while keeping
    full cryptographic signature and hostname verification active.
    """
    import ssl
    if getattr(ssl.SSLContext, "_pc_tolerant_patched", False):
        return

    orig_wrap_socket = ssl.SSLContext.wrap_socket

    def tolerant_wrap_socket(self, *args, **kwargs):
        if hasattr(self, "verify_flags"):
            self.verify_flags &= ~0x20
        return orig_wrap_socket(self, *args, **kwargs)

    ssl.SSLContext.wrap_socket = tolerant_wrap_socket
    ssl.SSLContext._pc_tolerant_patched = True


def init_oauth(app):
    """Register OIDC client with Authlib on application start."""
    oauth.init_app(app)
    issuer = (os.getenv("PULSECHECK_OIDC_ISSUER") or OIDC_ISSUER or "").strip()
    client_id = (os.getenv("PULSECHECK_OIDC_CLIENT_ID") or OIDC_CLIENT_ID or "").strip()
    client_secret = (os.getenv("PULSECHECK_OIDC_CLIENT_SECRET") or OIDC_CLIENT_SECRET or "").strip()
    scopes = (os.getenv("PULSECHECK_OIDC_SCOPES") or OIDC_SCOPES or "openid email profile").strip()

    # Normalize issuer for well-known server metadata
    server_metadata_url = None
    if issuer:
        if "/.well-known/" in issuer:
            server_metadata_url = issuer
        else:
            server_metadata_url = issuer.rstrip("/") + "/.well-known/openid-configuration"

    ssl_verify = get_oidc_ssl_verify()
    if ssl_verify is not False:
        _enable_tolerant_ssl_verification()

    client_kwargs = {
        "scope": scopes,
        "code_challenge_method": "S256",
        "verify": ssl_verify,
    }

    if ssl_verify is False:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    oauth.register(
        name="oidc",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=server_metadata_url,
        client_kwargs=client_kwargs,
    )


def login_required(f):
    """Route decorator: redirects unauthenticated users to OIDC login if enabled."""
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_oidc_active():
            return f(*args, **kwargs)

        user = session.get("user")
        if not user or not user.get("identifier"):
            # Store target destination in session
            session["next_url"] = request.url
            return redirect(url_for("auth_bp.login"))

        identifier = user.get("identifier", "")
        # Verify user has not been revoked from database
        if not is_user_authorized(identifier):
            session.pop("user", None)
            flash("Your access authorization has been revoked.", "error")
            session["next_url"] = request.url
            return redirect(url_for("auth_bp.login"))

        return f(*args, **kwargs)
    return decorated_function


@auth_bp.route("/auth/login")
def login():
    if not is_oidc_active():
        return redirect(url_for("home_bp.status"))

    user = session.get("user")
    if user and user.get("identifier") and is_user_authorized(user.get("identifier")):
        next_url = session.pop("next_url", None)
        return redirect(next_url or url_for("services_bp.services"))

    if not session.get("next_url"):
        next_param = request.args.get("next")
        if next_param:
            session["next_url"] = next_param

    redirect_uri = (os.getenv("PULSECHECK_OIDC_REDIRECT_URI") or OIDC_REDIRECT_URI or "").strip()
    if not redirect_uri:
        redirect_uri = url_for("auth_bp.callback", _external=True)

    client = oauth.create_client("oidc")
    if not client:
        flash("OIDC client is not properly configured.", "error")
        return redirect(url_for("home_bp.status"))

    return client.authorize_redirect(redirect_uri)


@auth_bp.route("/auth/callback")
def callback():
    if not is_oidc_active():
        return redirect(url_for("home_bp.status"))

    client = oauth.create_client("oidc")
    if not client:
        flash("OIDC authentication client is not configured.", "error")
        return redirect(url_for("home_bp.status"))

    try:
        token = client.authorize_access_token()
    except Exception as exc:
        flash(f"OIDC authentication failed: {exc}", "error")
        return redirect(url_for("home_bp.status"))

    # Extract claims from userinfo endpoint and/or id_token
    claims = {}

    # 1. Check if Authlib already parsed userinfo or id_token
    if isinstance(token.get("userinfo"), dict):
        claims.update(token["userinfo"])

    # 2. Try fetching from userinfo endpoint explicitly passing the access token
    try:
        ui = client.userinfo(token=token)
        if isinstance(ui, dict):
            claims.update(ui)
    except Exception as ui_exc:
        print(f"[OIDC] Warning: client.userinfo(token=token) call failed: {ui_exc}")

    # 3. If still missing claims or userinfo was incomplete, extract from id_token
    id_token_raw = token.get("id_token")
    if id_token_raw:
        if isinstance(id_token_raw, dict):
            claims = {**id_token_raw, **claims}
        elif isinstance(id_token_raw, str):
            try:
                # First try client.parse_id_token if state nonce is available
                parsed_id = client.parse_id_token(token, nonce=None)
                if isinstance(parsed_id, dict):
                    claims = {**parsed_id, **claims}
            except Exception:
                pass
            # Also decode unverified payload as safe fallback
            try:
                parts = id_token_raw.split(".")
                if len(parts) >= 2:
                    import base64
                    import json
                    payload_b64 = parts[1] + "=" * (-len(parts[1]) % 4)
                    payload_dict = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
                    if isinstance(payload_dict, dict):
                        claims = {**payload_dict, **claims}
            except Exception as jwt_exc:
                print(f"[OIDC] Warning: Failed decoding id_token payload: {jwt_exc}")

    userinfo = claims
    match_claim = get_active_match_claim()
    raw_ident = userinfo.get(match_claim)

    # Fallback checks if specific claim wasn't found directly
    if not raw_ident:
        if match_claim == "email":
            raw_ident = userinfo.get("mail") or userinfo.get("email_address")
        elif match_claim == "preferred_username":
            raw_ident = userinfo.get("username") or userinfo.get("sub")
        elif match_claim == "sub":
            raw_ident = userinfo.get("id")

    ident = str(raw_ident).strip() if raw_ident else ""
    if not ident:
        available_claims = list(userinfo.keys())
        print(f"[OIDC] Error: Claim '{match_claim}' not found in userinfo/id_token. Available claims: {available_claims}")
        flash(
            f"OIDC authentication succeeded, but claim '{match_claim}' was not found in provider response.",
            "error",
        )
        return redirect(url_for("home_bp.status"))

    # Check authorization in database
    if not is_user_authorized(ident):
        flash(
            f"User '{ident}' is authenticated with OIDC but not authorized to access PulseCheck. Contact your administrator.",
            "error",
        )
        return redirect(url_for("home_bp.status"))

    db_user = get_authorized_user_by_identifier(ident)
    display_name = (db_user["display_name"] if db_user and db_user["display_name"] else userinfo.get("name") or ident)

    # Store user in session
    session["user"] = {
        "identifier": ident,
        "name": display_name,
        "claim": match_claim,
    }

    flash(f"Welcome back, {display_name}!", "success")
    next_url = session.pop("next_url", None)
    # Validate next_url to prevent open redirects
    if next_url and (next_url.startswith("/") or next_url.startswith(request.host_url)):
        return redirect(next_url)
    return redirect(url_for("services_bp.services"))


@auth_bp.route("/auth/logout", methods=["GET", "POST"])
def logout():
    session.pop("user", None)
    session.pop("next_url", None)
    flash("You have been signed out.", "info")
    return redirect(url_for("home_bp.status"))
