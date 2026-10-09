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

    oauth.register(
        name="oidc",
        client_id=client_id,
        client_secret=client_secret,
        server_metadata_url=server_metadata_url,
        client_kwargs={
            "scope": scopes,
            "code_challenge_method": "S256",
        },
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

    # Extract claims from userinfo endpoint or id_token
    userinfo = token.get("userinfo")
    if not userinfo:
        try:
            userinfo = client.userinfo()
        except Exception:
            userinfo = {}
    if not userinfo and "id_token" in token:
        userinfo = token.get("id_token", {})

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
