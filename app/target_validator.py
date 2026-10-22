"""Validation for explicitly local scan targets."""

from ipaddress import ip_address
from urllib.parse import urlsplit, urlunsplit


def validate_target(target: str) -> str:
    """Return an HTTP(S) URL pinned to a literal loopback address."""
    if not isinstance(target, str) or not target.strip():
        raise ValueError("Target must be a non-empty URL.")

    value = target.strip()
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise ValueError("Target URL contains invalid whitespace or control characters.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Target URL is malformed.") from exc

    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS targets are supported.")
    if not parsed.netloc or hostname is None:
        raise ValueError("Target must include a host.")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in target URLs are not allowed.")
    if "%" in hostname or "\\" in parsed.netloc:
        raise ValueError("Scoped or encoded hostnames are not allowed.")

    if hostname.lower() == "localhost":
        normalized_host = "127.0.0.1"
    else:
        try:
            address = ip_address(hostname)
        except ValueError as exc:
            raise ValueError(
                "Only localhost and literal loopback IP addresses are allowed."
            ) from exc
        if not address.is_loopback:
            raise ValueError("Only localhost and literal loopback IP addresses are allowed.")
        normalized_host = str(address)

    if not normalized_host:
        raise ValueError("Only localhost and loopback IP addresses are allowed.")

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Target port must be between 1 and 65535.")

    if ":" in normalized_host:
        normalized_host = f"[{normalized_host}]"
    netloc = f"{normalized_host}:{port}" if port is not None else normalized_host
    return urlunsplit(
        (parsed.scheme.lower(), netloc, parsed.path or "/", parsed.query, "")
    )
