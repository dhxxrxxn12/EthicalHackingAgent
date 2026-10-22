"""Structured, cautious findings derived from observed response headers."""

from dataclasses import asdict, dataclass
from enum import Enum
import re
from urllib.parse import urlsplit, urlunsplit

from app.header_analyzer import HeaderCheck
from app.http_inspector import CookieObservation, HttpInspection


class Severity(str, Enum):
    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    severity: Severity
    confidence: int
    affected_url: str
    evidence: str
    explanation: str
    remediation: str

    def to_dict(self) -> dict[str, str | int]:
        result = asdict(self)
        result["severity"] = self.severity.value
        return result


def safe_origin(url: str) -> str:
    """Keep scheme/authority only so paths and query-string secrets are not reported."""
    parsed = urlsplit(url)
    hostname = parsed.hostname or ""
    host = f"[{hostname}]" if ":" in hostname else hostname
    try:
        port = parsed.port
    except ValueError:
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme.lower(), netloc, "/", "", ""))


def findings_from_header_checks(
    checks: list[HeaderCheck], *, affected_url: str
) -> list[Finding]:
    findings = []
    for check in checks:
        if check.status != "missing":
            continue
        slug = "".join(
            character if character.isalnum() else "-"
            for character in check.name.upper()
        ).strip("-")
        severity = (
            Severity.MEDIUM
            if check.name in {"Content-Security-Policy", "Strict-Transport-Security"}
            else Severity.LOW
        )
        findings.append(
            Finding(
                finding_id=f"WEB-HEADER-{slug}-MISSING",
                title=f"Potential missing {check.name} header",
                severity=severity,
                confidence=95,
                affected_url=safe_origin(affected_url),
                evidence=f"The response did not include the {check.name} header.",
                explanation=(
                    f"The observed response omitted {check.name}. This can reduce "
                    "browser-side protection, but does not by itself confirm an "
                    "exploitable vulnerability."
                ),
                remediation=check.recommendation,
            )
        )
    return findings


def _cookie_finding(
    cookie_name: str,
    condition: str,
    *,
    affected_url: str,
    explanation: str,
    remediation: str,
    severity: Severity = Severity.LOW,
) -> Finding:
    slug = (
        "UNSPECIFIED"
        if re.fullmatch(r"Cookie \d+", cookie_name)
        else re.sub(r"[^A-Z0-9]+", "-", cookie_name.upper()).strip("-")
    )
    condition_slug = re.sub(r"[^A-Z0-9]+", "-", condition.upper()).strip("-")
    return Finding(
        finding_id=f"WEB-COOKIE-{slug}-{condition_slug}",
        title=f"{cookie_name}: {condition}",
        severity=severity,
        confidence=95,
        affected_url=safe_origin(affected_url),
        evidence=f"{cookie_name} was observed without the {condition} attribute.",
        explanation=explanation,
        remediation=remediation,
    )


def findings_from_cookies(
    cookies: list[CookieObservation], *, affected_url: str, is_https: bool
) -> list[Finding]:
    findings: list[Finding] = []
    for cookie in cookies:
        name = cookie.display_name
        if not cookie.httponly:
            findings.append(
                _cookie_finding(
                    name,
                    "HttpOnly",
                    affected_url=affected_url,
                    explanation=(
                        "Without HttpOnly, client-side scripts may be able to read "
                        "the cookie. The observation alone does not establish a "
                        "script-injection issue or exposure."
                    ),
                    remediation=(
                        "Set HttpOnly for cookies that do not need JavaScript access."
                    ),
                )
            )
        if cookie.samesite is None:
            findings.append(
                _cookie_finding(
                    name,
                    "SameSite",
                    affected_url=affected_url,
                    explanation=(
                        "The cookie did not declare a SameSite policy. Browser defaults "
                        "and application context affect the practical impact."
                    ),
                    remediation="Set an appropriate SameSite=Lax or SameSite=Strict policy.",
                )
            )
        if cookie.samesite == "none" and not cookie.secure:
            findings.append(
                _cookie_finding(
                    name,
                    "SameSite=None requires Secure",
                    affected_url=affected_url,
                    explanation=(
                        "The observed cookie uses SameSite=None without Secure. Modern "
                        "browsers generally reject this combination; this observation "
                        "does not establish an exploitable vulnerability."
                    ),
                    remediation="Add Secure to the cookie and serve it over HTTPS.",
                    severity=Severity.MEDIUM,
                )
            )
        elif is_https and not cookie.secure:
            findings.append(
                _cookie_finding(
                    name,
                    "Secure",
                    affected_url=affected_url,
                    explanation=(
                        "A cookie observed over HTTPS omitted Secure, so it may also "
                        "be sent over an unencrypted HTTP connection. Impact depends "
                        "on the application and deployment."
                    ),
                    remediation="Set Secure and serve the application exclusively over HTTPS.",
                )
            )
    return findings


def findings_from_http_observations(result: HttpInspection) -> list[Finding]:
    findings = findings_from_cookies(
        result.cookies or [],
        affected_url=result.url,
        is_https=result.url.lower().startswith("https://"),
    )
    if result.cors_wildcard_origin and result.cors_credentials_enabled:
        findings.append(
            Finding(
                finding_id="WEB-CORS-WILDCARD-CREDENTIALS",
                title="Potential CORS wildcard and credentials misconfiguration",
                severity=Severity.MEDIUM,
                confidence=95,
                affected_url=safe_origin(result.url),
                evidence=(
                    "The response advertised Access-Control-Allow-Origin: * and "
                    "Access-Control-Allow-Credentials: true."
                ),
                explanation=(
                    "These headers form a suspicious combination. Browsers normally "
                    "reject credentialed CORS responses with a wildcard origin, and "
                    "header observations alone do not prove an exploitable CORS issue."
                ),
                remediation=(
                    "Allow only explicitly trusted origins and enable credentials "
                    "only where required."
                ),
            )
        )
    elif result.cors_null_origin and result.cors_credentials_enabled:
        findings.append(
            Finding(
                finding_id="WEB-CORS-NULL-ORIGIN-CREDENTIALS",
                title="Potential CORS null-origin credentials configuration",
                severity=Severity.MEDIUM,
                confidence=90,
                affected_url=safe_origin(result.url),
                evidence=(
                    "The response advertised Access-Control-Allow-Origin: null and "
                    "Access-Control-Allow-Credentials: true."
                ),
                explanation=(
                    "This is a sensitive CORS configuration. Header observations "
                    "alone do not prove an exploitable CORS issue."
                ),
                remediation=(
                    "Avoid allowing the null origin with credentials unless a "
                    "specific trusted use case requires it."
                ),
            )
        )

    for header_name, value in (result.technology_headers or {}).items():
        if not value:
            continue
        # Common servers use either "name/1.2" or "name 1.2" notation. Keep
        # this observation conservative: it identifies version-shaped text,
        # not whether the software is vulnerable or outdated.
        has_version = bool(re.search(r"(?:/|\b)\d+(?:\.\d+)+(?:[-+._][A-Za-z0-9.-]+)?", value))
        finding_id = (
            "WEB-INFO-SERVER-VERSION-DISCLOSED"
            if header_name == "server" and has_version
            else f"WEB-INFO-{header_name.upper().replace('-', '-')}-DISCLOSED"
        )
        title = (
            "Server version disclosed in response header"
            if header_name == "server" and has_version
            else f"Technology details disclosed in {header_name} header"
        )
        findings.append(
            Finding(
                finding_id=finding_id,
                title=title,
                severity=Severity.INFORMATIONAL,
                confidence=90,
                affected_url=safe_origin(result.url),
                evidence=f"The {header_name} response header disclosed: {value}.",
                explanation=(
                    "Technology metadata can assist fingerprinting, but disclosure "
                    "alone is not a vulnerability or evidence that the software is "
                    "out of date."
                ),
                remediation=(
                    "Consider minimizing version details in response headers as part "
                    "of a broader information-disclosure policy."
                ),
            )
        )
    return deduplicate_findings(findings)


def deduplicate_findings(findings: list[Finding]) -> list[Finding]:
    unique: dict[str, Finding] = {}
    for finding in findings:
        unique.setdefault(finding.finding_id, finding)
    return list(unique.values())
