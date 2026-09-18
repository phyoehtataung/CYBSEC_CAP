"""WebSET configuration. Scans are restricted to authorised local targets."""

import os
from pathlib import Path

APP_NAME = "WebSET"
APP_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"

ROOT_DIR = Path(__file__).resolve().parents[2]
BACKEND_DIR = Path(__file__).resolve().parents[1]
DATA_DIR = BACKEND_DIR / "data"
DB_PATH = DATA_DIR / "webset.db"
CATALOG_DIR = Path(__file__).resolve().parent / "data" / "catalogs"
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
FRONTEND_DIST = ROOT_DIR / "frontend" / "dist"
LABS_DIR = ROOT_DIR / "labs"

# Local clones of teaching-app source, used by static analysis when present.
LAB_SOURCES = {
    "juice-shop": LABS_DIR / "juice-shop",
    "dvwa": LABS_DIR / "dvwa",
}

# Optional extra SAST (semgrep / bandit). Off unless WEBSET_EXTERNAL_SAST=1
# and the tools are installed on PATH.
ENABLE_EXTERNAL_SAST = os.environ.get("WEBSET_EXTERNAL_SAST", "").lower() in {
    "1",
    "true",
    "yes",
}

STATIC_MAX_FILE_BYTES = 512_000
STATIC_MAX_FILES = 2500
STATIC_MAX_FINDINGS = 80
DYNAMIC_MAX_PAGES = 40
DYNAMIC_MAX_DEPTH = 3
DYNAMIC_TIMEOUT_SECONDS = 4.0
DYNAMIC_MAX_BODY_BYTES = 400_000

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
