from __future__ import annotations

from routes.home import home_bp
from routes.services import services_bp
from routes.settings import settings_bp
from routes.import_export import import_bp

__all__ = [
    "home_bp",
    "services_bp",
    "settings_bp",
    "import_bp",
]
