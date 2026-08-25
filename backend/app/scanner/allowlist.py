from urllib.parse import urlparse

from ..config import ALLOWED_HOSTS, ALLOWED_PORTS


class TargetNotAllowed(ValueError):
    """Raised when a scan target is not an authorised local lab host."""


def validate_local_target(url: str) -> str:
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"http", "https"}:
        raise TargetNotAllowed("Only http and https URLs are accepted.")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_HOSTS:
        raise TargetNotAllowed(
            "WebSET only scans authorised local labs (localhost / Docker). "
            "External or production URLs are blocked."
        )
    port = parsed.port
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if port not in ALLOWED_PORTS:
        raise TargetNotAllowed(
            f"Port {port} is not on the local lab allow-list "
            f"({sorted(ALLOWED_PORTS)})."
        )
    if parsed.username or parsed.password:
        raise TargetNotAllowed("Credentials in URLs are not accepted.")
    return url.rstrip("/")
