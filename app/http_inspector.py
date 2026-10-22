"""Bounded, read-only HTTP inspection for validated local targets."""

from dataclasses import dataclass
from http.cookies import SimpleCookie
import re
from time import perf_counter

import requests

from app.target_validator import validate_target

DEFAULT_TIMEOUT = (3.05, 5.0)
SAFE_RESPONSE_HEADERS = (
    "server",
    "content-type",
    "location",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "allow",
    "x-powered-by",
)
RETAINED_RESPONSE_HEADERS = (
    "server",
    "content-type",
    "location",
    "content-security-policy",
    "strict-transport-security",
    "x-content-type-options",
    "referrer-policy",
)
_SAFE_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,64}$")
_SENSITIVE_COOKIE_NAME = re.compile(
    r"(session|auth|token|secret|password|passwd|credential|api.?key|^sid$|^jwt$)",
    re.IGNORECASE,
)
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_TECH_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+/-]{0,39}")
_SENSITIVE_TECH_VALUE = re.compile(
    r"(token|secret|password|authorization|cookie|session|api.?key)\s*[:=]",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class CookieObservation:
    display_name: str
    secure: bool
    httponly: bool
    samesite: str | None


def _header_value(headers, name: str) -> str | None:
    for header_name, value in headers.items():
        if header_name.lower() == name.lower():
            return str(value)
    return None


def _cookie_headers(response) -> list[str]:
    raw_headers = getattr(getattr(response, "raw", None), "headers", None)
    getlist = getattr(raw_headers, "getlist", None)
    if callable(getlist):
        values = getlist("Set-Cookie")
        if values:
            return [str(value) for value in values]
    value = _header_value(response.headers, "Set-Cookie")
    return [value] if value else []


def _cookie_observations(response) -> list[CookieObservation]:
    observations = []
    for index, raw_cookie in enumerate(_cookie_headers(response), start=1):
        parsed_cookie = SimpleCookie()
        try:
            parsed_cookie.load(raw_cookie)
        except (TypeError, ValueError):
            parsed_cookie = SimpleCookie()

        if parsed_cookie:
            morsel = next(iter(parsed_cookie.values()))
            name = morsel.key
            attributes = {
                key.lower(): value for key, value in morsel.items()
            }
            secure = bool(attributes.get("secure"))
            httponly = bool(attributes.get("httponly"))
            same_site = attributes.get("samesite", "").strip().lower() or None
        else:
            parts = raw_cookie.split(";")
            name, separator, _value = parts[0].strip().partition("=")
            if not separator:
                name = ""
            attribute_parts = [part.strip().split("=", 1) for part in parts[1:]]
            attributes = {
                part[0].lower(): part[1].strip().strip('"')
                if len(part) == 2
                else ""
                for part in attribute_parts
                if part and part[0]
            }
            secure = "secure" in attributes
            httponly = "httponly" in attributes
            same_site = attributes.get("samesite", "").lower() or None

        safe_name = (
            name
            if _SAFE_COOKIE_NAME.fullmatch(name)
            and not _SENSITIVE_COOKIE_NAME.search(name)
            else f"Cookie {index}"
        )
        if same_site not in {"strict", "lax", "none"}:
            same_site = "invalid" if same_site else None
        observations.append(
            CookieObservation(
                display_name=safe_name,
                secure=secure,
                httponly=httponly,
                samesite=same_site,
            )
        )
    return observations


def _safe_technology_value(value: str | None) -> str:
    if not value:
        return ""
    if _SENSITIVE_TECH_VALUE.search(value):
        return "technology details omitted"
    tokens = _TECH_TOKEN.findall(value)
    safe_tokens = [
        token for token in tokens[:3] if not _SENSITIVE_TECH_VALUE.search(token)
    ]
    return " ".join(safe_tokens)[:100] or "technology details omitted"


def _technology_headers(headers) -> dict[str, str]:
    technology: dict[str, str] = {}
    for name in ("server", "x-powered-by"):
        safe_value = _safe_technology_value(_header_value(headers, name))
        if safe_value:
            technology[name] = safe_value
    return technology


def _allow_methods(value: str | None) -> list[str]:
    if not value:
        return []
    return sorted(
        {
            method.upper()
            for part in value.split(",")
            if (method := part.strip()) and _HTTP_TOKEN.fullmatch(method)
        }
    )


def _open_local_response(url: str, **request_options):
    """Open one direct request, ignoring environment-configured proxies."""
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.get(url, **request_options)
    except requests.RequestException:
        session.close()
        raise
    return session, response


@dataclass(frozen=True)
class HttpInspection:
    url: str
    status_code: int
    elapsed_seconds: float
    headers: dict[str, str]
    redirect_location: str | None
    tls_verified: bool | None = None
    cookies: list[CookieObservation] | None = None
    allow_methods: list[str] | None = None
    cors_wildcard_origin: bool = False
    cors_null_origin: bool = False
    cors_credentials_enabled: bool = False
    technology_headers: dict[str, str] | None = None
    response_header_presence: dict[str, bool] | None = None


def inspect_http(target: str, timeout: tuple[float, float] = DEFAULT_TIMEOUT) -> HttpInspection:
    """Make one GET request without following redirects or downloading its body."""
    safe_target = validate_target(target)
    started_at = perf_counter()
    session, response = _open_local_response(
        safe_target,
        timeout=timeout,
        allow_redirects=False,
        stream=True,
        verify=True,
    )
    try:
        elapsed_seconds = perf_counter() - started_at
        headers: dict[str, str] = {}
        for name in RETAINED_RESPONSE_HEADERS:
            value = _header_value(response.headers, name)
            if value is not None:
                headers[name] = value
        technology_headers = _technology_headers(response.headers)
        headers.update(technology_headers)
        allow_value = _header_value(response.headers, "Allow")
        methods = _allow_methods(allow_value)
        if methods:
            headers["allow"] = ", ".join(methods)
        cors_origin = _header_value(response.headers, "Access-Control-Allow-Origin")
        cors_credentials = _header_value(
            response.headers, "Access-Control-Allow-Credentials"
        )
        return HttpInspection(
            url=safe_target,
            status_code=response.status_code,
            elapsed_seconds=elapsed_seconds,
            headers=headers,
            redirect_location=response.headers.get("Location"),
            tls_verified=(
                True if safe_target.lower().startswith("https://") else None
            ),
            cookies=_cookie_observations(response),
            allow_methods=methods,
            cors_wildcard_origin=(cors_origin or "").strip() == "*",
            cors_null_origin=(cors_origin or "").strip().lower() == "null",
            cors_credentials_enabled=(cors_credentials or "").strip().lower() == "true",
            technology_headers=technology_headers,
            response_header_presence={
                name: _header_value(response.headers, name) is not None
                for name in SAFE_RESPONSE_HEADERS
            },
        )
    finally:
        response.close()
        session.close()
