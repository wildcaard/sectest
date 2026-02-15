from urllib.parse import urlparse
import validators as val_lib


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a target URL. Returns (is_valid, message)."""
    if not url:
        return False, "URL cannot be empty"

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    if not val_lib.url(url):
        return False, f"Invalid URL format: {url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        return False, "URL must have a hostname"

    if parsed.hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        return False, "Scanning localhost is not allowed for safety"

    return True, url


def normalize_url(url: str) -> str:
    """Normalize URL by ensuring scheme and removing trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")
