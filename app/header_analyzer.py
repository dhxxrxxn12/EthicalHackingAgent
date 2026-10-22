"""Presence checks for a small set of common browser security headers."""

from dataclasses import dataclass
from collections.abc import Mapping


@dataclass(frozen=True)
class HeaderCheck:
    name: str
    present: bool
    status: str
    recommendation: str


def analyze_security_headers(
    headers: Mapping[str, str], *, is_https: bool
) -> list[HeaderCheck]:
    """Report whether baseline security headers are present."""
    normalized_headers = {name.lower() for name in headers}
    checks: list[HeaderCheck] = []

    expected = (
        ("Content-Security-Policy", "Define a policy appropriate for the application."),
        ("X-Content-Type-Options", "Set this header to nosniff."),
        ("Referrer-Policy", "Choose a restrictive referrer policy."),
    )
    for name, recommendation in expected:
        present = name.lower() in normalized_headers
        checks.append(
            HeaderCheck(
                name=name,
                present=present,
                status="present" if present else "missing",
                recommendation="" if present else recommendation,
            )
        )

    hsts_present = "strict-transport-security" in normalized_headers
    if is_https:
        checks.append(
            HeaderCheck(
                name="Strict-Transport-Security",
                present=hsts_present,
                status="present" if hsts_present else "missing",
                recommendation=(
                    "" if hsts_present else "Configure HSTS after confirming HTTPS works."
                ),
            )
        )
    else:
        checks.append(
            HeaderCheck(
                name="Strict-Transport-Security",
                present=hsts_present,
                status="not applicable (HTTP)",
                recommendation="Use HTTPS before relying on HSTS.",
            )
        )
    return checks
