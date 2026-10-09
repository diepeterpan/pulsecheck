from __future__ import annotations

from routes.home import home_bp
from routes.services import services_bp
from routes.settings import settings_bp
from routes.import_export import import_bp
from routes.auth import auth_bp, login_required

__all__ = [
    "home_bp",
    "services_bp",
    "settings_bp",
    "import_bp",
    "auth_bp",
    "login_required",
]
