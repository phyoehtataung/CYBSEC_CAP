"""WebSET configuration. Demo scans are restricted to authorised local targets."""

from pathlib import Path

APP_NAME = "WebSET"
APP_VERSION = "0.1.0"
SCHEMA_VERSION = "1.0.0"

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"
DB_PATH = DATA_DIR / "webset.db"
CATALOG_DIR = Path(__file__).resolve().parent / "data" / "catalogs"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"

# Only these hosts/ports may be scanned. External/live targets are rejected.
ALLOWED_HOSTS = {
    "localhost",
    "127.0.0.1",
    "::1",
    "juice-shop",
    "dvwa",
    "host.docker.internal",
}
ALLOWED_PORTS = {80, 3000, 4280, 8080, 8443}

DEMO_TARGETS = [
    {
        "id": "juice-shop",
        "name": "OWASP Juice Shop",
        "url": "http://localhost:3000",
        "stack": ["Node.js", "Express", "Angular", "SQLite"],
        "notes": "Deliberately vulnerable shop. Start with docker compose.",
    },
    {
        "id": "dvwa",
        "name": "DVWA",
        "url": "http://localhost:4280",
        "stack": ["PHP", "MySQL", "Apache"],
        "notes": "Damn Vulnerable Web Application. Start with docker compose.",
    },
]
