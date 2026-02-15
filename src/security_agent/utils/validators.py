from urllib.parse import urlparse
import validators as val_lib


def validate_url(url: str) -> tuple[bool, str]:
    """Validate a target URL. Returns (is_valid, message)."""
    if not url:
        return False, "URL cannot be empty"

    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urlparse(url)
    if not parsed.hostname:
        return False, "URL must have a hostname"

    # Handle localhost URLs separately since validators library rejects them
    if parsed.hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
        # Basic validation for localhost URLs
        if not parsed.scheme or not parsed.port:
            # Allow default ports (80 for http, 443 for https)
            if parsed.scheme not in ("http", "https"):
                return False, f"Invalid URL scheme: {parsed.scheme}"
        return True, url
    
    # Use validators library for non-localhost URLs
    if not val_lib.url(url):
        return False, f"Invalid URL format: {url}"

    return True, url


def is_localhost_url(url: str) -> bool:
    """Check if URL is a localhost/local address."""
    parsed = urlparse(url)
    return parsed.hostname in ("localhost", "127.0.0.1", "::1", "0.0.0.0")


def normalize_url(url: str) -> str:
    """Normalize URL by ensuring scheme and removing trailing slash."""
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    return url.rstrip("/")
