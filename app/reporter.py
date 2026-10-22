"""Secret-conscious JSON and self-contained HTML scan reports."""

from collections import Counter
from datetime import datetime, timezone
from html import escape
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from uuid import uuid4

from app.findings import Finding, Severity, safe_origin
from app.http_inspector import HttpInspection, SAFE_RESPONSE_HEADERS

REPORT_VERSION = "1"
_SAFE_FILENAME_PART = re.compile(r"[^A-Za-z0-9._-]+")
_SAFE_ERROR_MESSAGES = {
    "TargetValidationError": "The requested target was rejected by local-only validation.",
    "SSLError": "TLS certificate verification failed; no HTTP result was accepted.",
    "Timeout": "The HTTP request timed out.",
    "ConnectTimeout": "The connection to the local target timed out.",
    "ReadTimeout": "The local target response timed out.",
    "ConnectionError": "Could not connect to the local target.",
    "RequestException": "The HTTP request could not be completed.",
    "ScanError": "The scan could not be completed.",
}


def create_scan_report(
    *,
    target: str | None,
    http_result: HttpInspection | None,
    findings: list[Finding],
    errors: list[dict[str, str]],
    timestamp: datetime | None = None,
) -> dict:
    created_at = timestamp or datetime.now(timezone.utc)
    safe_target = safe_origin(target) if target else None
    http_data = None
    if http_result is not None:
        present_headers = http_result.response_header_presence
        if present_headers is None:
            retained = {header.lower() for header in http_result.headers}
            present_headers = {
                name: name.lower() in retained for name in SAFE_RESPONSE_HEADERS
            }
        http_data = {
            "status_code": http_result.status_code,
            "elapsed_seconds": round(http_result.elapsed_seconds, 6),
            "redirected": http_result.redirect_location is not None,
            "headers_present": present_headers,
            "tls_verified": http_result.tls_verified,
            "allow_methods": http_result.allow_methods or [],
            "cors": {
                "wildcard_origin": http_result.cors_wildcard_origin,
                "null_origin": http_result.cors_null_origin,
                "credentials_enabled": http_result.cors_credentials_enabled,
            },
            "technology": http_result.technology_headers or {},
            "cookies_observed": len(http_result.cookies or []),
        }

    safe_errors = []
    for error in errors:
        error_type = str(error.get("type", "RequestException"))
        safe_type = (
            error_type
            if error_type in _SAFE_ERROR_MESSAGES
            else "RequestException"
        )
        safe_errors.append(
            {
                "type": safe_type,
                "message": _SAFE_ERROR_MESSAGES.get(
                    safe_type, "The scan could not be completed."
                ),
            }
        )
    return {
        "metadata": {
            "scanner": "EthicalHackingAgent",
            "report_version": REPORT_VERSION,
            "scan_id": str(uuid4()),
            "timestamp": created_at.astimezone(timezone.utc).isoformat(),
        },
        "target": safe_target,
        "http": http_data,
        "findings": [finding.to_dict() for finding in findings],
        "errors": safe_errors,
    }


def _safe_filename(target: str | None, timestamp: str) -> str:
    hostname = urlsplit(target).hostname if target else None
    host_part = _SAFE_FILENAME_PART.sub("_", hostname or "scan").strip("._-")
    timestamp_part = _SAFE_FILENAME_PART.sub("_", timestamp).strip("._-")
    return f"scan-{host_part or 'scan'}-{timestamp_part}"


def write_reports(
    report: dict, output_dir: str | Path, *, target: str | None
) -> tuple[Path, Path]:
    """Write paired JSON and HTML reports using generated, sanitized filenames."""
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stem = _safe_filename(target, report["metadata"]["timestamp"])
    json_path = directory / f"{stem}.json"
    html_path = directory / f"{stem}.html"
    json_path.write_text(json.dumps(report, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    html_path.write_text(render_html_report(report), encoding="utf-8")
    return json_path, html_path


def render_html_report(report: dict) -> str:
    findings = report.get("findings", [])
    counts = Counter(item.get("severity", "") for item in findings)
    summary = "".join(
        f'<li><strong>{escape(severity)}</strong>: {counts.get(severity, 0)}</li>'
        for severity in (item.value for item in Severity)
    )

    finding_sections = []
    for finding in findings:
        details = (
            ("ID", finding.get("finding_id", "")),
            ("Severity", finding.get("severity", "")),
            ("Confidence in observation", f'{finding.get("confidence", 0)}%'),
            ("Affected URL", finding.get("affected_url", "")),
            ("Evidence", finding.get("evidence", "")),
            ("Explanation", finding.get("explanation", "")),
            ("Remediation", finding.get("remediation", "")),
        )
        content = "".join(
            f"<dt>{escape(label)}</dt><dd>{escape(str(value))}</dd>"
            for label, value in details
        )
        finding_sections.append(
            f'<article class="finding"><h3>{escape(str(finding.get("title", "")))}</h3>'
            f"<dl>{content}</dl></article>"
        )

    http_result = report.get("http")
    http_html = "<p>No HTTP response was received.</p>"
    if http_result is not None:
        safe_items = (
            ("Status", http_result.get("status_code", "")),
            ("Response time (seconds)", http_result.get("elapsed_seconds", "")),
            ("Redirect observed", http_result.get("redirected", False)),
            ("TLS certificate verified", http_result.get("tls_verified")),
        )
        http_rows = "".join(
            f"<tr><th>{escape(label)}</th><td>{escape(str(value))}</td></tr>"
            for label, value in safe_items
        )
        header_rows = "".join(
            f"<tr><th>{escape(str(name))}</th><td>{'present' if present else 'missing'}</td></tr>"
            for name, present in http_result.get("headers_present", {}).items()
        )
        methods = ", ".join(
            escape(str(method)) for method in http_result.get("allow_methods", [])
        ) or "None observed"
        cors = http_result.get("cors", {})
        cors_rows = "".join(
            f"<tr><th>{escape(label)}</th><td>{escape(str(cors.get(key, False)))}</td></tr>"
            for key, label in (
                ("wildcard_origin", "Wildcard origin advertised"),
                ("null_origin", "Null origin advertised"),
                ("credentials_enabled", "Credentials enabled"),
            )
        )
        technology_rows = "".join(
            f"<tr><th>{escape(str(name))}</th><td>{escape(str(value))}</td></tr>"
            for name, value in http_result.get("technology", {}).items()
        ) or "<tr><td colspan=\"2\">No technology details observed</td></tr>"
        http_html = (
            f"<table><tbody>{http_rows}</tbody></table>"
            f"<h3>Response header presence</h3><table><tbody>{header_rows}</tbody></table>"
            f"<h3>Passive observations</h3><ul>"
            f"<li>Advertised methods (not verified): {methods}</li>"
            f"<li>Set-Cookie headers observed: "
            f"{escape(str(http_result.get('cookies_observed', 0)))}</li></ul>"
            f"<table><tbody>{cors_rows}</tbody></table>"
            f"<h3>Technology headers</h3><table><tbody>{technology_rows}</tbody></table>"
        )

    error_html = "".join(
        f'<li><strong>{escape(str(error.get("type", "Error")))}</strong>: '
        f'{escape(str(error.get("message", "")))}</li>'
        for error in report.get("errors", [])
    ) or "<li>None</li>"
    metadata = report.get("metadata", {})

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>EthicalHackingAgent scan report</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; color: #202938; background: #f4f6f8; }}
body {{ margin: 0; padding: 1rem; }}
main {{ max-width: 960px; margin: auto; background: white; padding: clamp(1rem, 4vw, 2rem); border-radius: .75rem; }}
h1, h2 {{ color: #172554; }}
ul {{ padding-left: 1.25rem; }}
.finding {{ border: 1px solid #d1d5db; border-left: .35rem solid #64748b; border-radius: .35rem; padding: 1rem; margin: 1rem 0; overflow-wrap: anywhere; }}
dl {{ display: grid; grid-template-columns: minmax(8rem, 12rem) 1fr; gap: .5rem 1rem; }}
dt {{ font-weight: 700; }} dd {{ margin: 0; overflow-wrap: anywhere; }}
table {{ border-collapse: collapse; width: 100%; margin: .5rem 0 1rem; }}
th, td {{ text-align: left; border-bottom: 1px solid #e5e7eb; padding: .5rem; overflow-wrap: anywhere; }}
@media (max-width: 560px) {{ dl {{ grid-template-columns: 1fr; gap: .15rem; }} dd {{ margin-bottom: .65rem; }} }}
</style>
</head>
<body><main>
<h1>EthicalHackingAgent scan report</h1>
<p><strong>Target:</strong> {escape(str(report.get("target") or "Unavailable"))}</p>
<p><strong>Scan ID:</strong> {escape(str(metadata.get("scan_id", "")))}</p>
<p><strong>Timestamp (UTC):</strong> {escape(str(metadata.get("timestamp", "")))}</p>
<h2>Severity summary</h2><ul>{summary}</ul>
<h2>HTTP results</h2>{http_html}
<h2>Findings</h2>{''.join(finding_sections) or '<p>No potential findings recorded.</p>'}
<h2>Errors</h2><ul>{error_html}</ul>
<p>Findings are potential observations for manual verification, not confirmation of exploitability.</p>
</main></body></html>
"""
