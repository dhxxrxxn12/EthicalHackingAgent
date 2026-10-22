"""Schema-tolerant comparison and assessment summaries for local scan records."""

from collections import Counter
from html import escape
import json
import re
from typing import Any

from app.findings import safe_origin


CHECKS_PERFORMED = ["security_headers", "cookies", "cors", "allow_methods", "technology"]
LIMITATIONS = [
    "Findings are passive observations, not proof of exploitability.",
    "Only one bounded GET request is made; redirects are not followed.",
    "Response bodies, secrets, cookie values, and authorization headers are not retained.",
    "A missing finding is not treated as resolved after a failed or incomplete scan.",
]
_SECRET_PATTERN = re.compile(
    r"(?i)(\b(?:token|secret|password|passwd|authorization|cookie|session|api[_-]?key)\b\s*[:=]\s*)([^\s;&,]+)"
)


def _redact_text(value: Any) -> str:
    text = str(value)
    return _SECRET_PATTERN.sub(r"\1[REDACTED]", text)[:2000]


def _safe_finding(finding: Any) -> dict[str, Any] | None:
    if not isinstance(finding, dict) or not isinstance(finding.get("finding_id"), str):
        return None
    result: dict[str, Any] = {
        "finding_id": _redact_text(finding["finding_id"]),
        "title": _redact_text(finding.get("title", "")),
        "severity": _redact_text(finding.get("severity", "")),
        "confidence": finding.get("confidence", 0) if isinstance(finding.get("confidence", 0), int) else 0,
        "affected_url": "",
        "evidence": _redact_text(finding.get("evidence", "")),
        "explanation": _redact_text(finding.get("explanation", "")),
        "remediation": _redact_text(finding.get("remediation", "")),
    }
    affected_url = finding.get("affected_url", "")
    if isinstance(affected_url, str):
        try:
            result["affected_url"] = safe_origin(affected_url)
        except (TypeError, ValueError):
            result["affected_url"] = ""
    return result


def safe_findings(scan: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in scan.get("findings", []) or []:
        finding = _safe_finding(raw)
        if finding and finding["finding_id"] not in seen:
            seen.add(finding["finding_id"])
            findings.append(finding)
    return findings


def finding_category(finding_id: str) -> str:
    parts = finding_id.split("-")
    return {
        "COOKIE": "Cookies",
        "CORS": "CORS",
        "HEADER": "Security headers",
        "INFO": "Information disclosure",
    }.get(parts[1] if len(parts) > 1 else "", "Other")


def scan_completed(scan: dict[str, Any]) -> bool:
    if "completed" in scan:
        return scan["completed"] is True
    return not scan.get("errors") and isinstance(scan.get("status_code"), int)


def _relevant_check(finding_id: str) -> str | None:
    prefix = finding_id.split("-")[1] if len(finding_id.split("-")) > 1 else ""
    return {
        "COOKIE": "cookies",
        "CORS": "cors",
        "HEADER": "security_headers",
        "INFO": "technology",
    }.get(prefix)


def compare_scans(earlier: dict[str, Any], later: dict[str, Any]) -> dict[str, Any]:
    if earlier.get("target") != later.get("target"):
        raise ValueError("Scans must have the same normalized target.")
    if not scan_completed(earlier) or not scan_completed(later):
        raise ValueError("Only completed scans can be compared.")
    before = {item["finding_id"]: item for item in safe_findings(earlier)}
    after = {item["finding_id"]: item for item in safe_findings(later)}
    new = [after[key] for key in after.keys() - before.keys()]
    recurring = [after[key] for key in after.keys() & before.keys()]
    resolved: list[dict[str, Any]] = []
    not_assessed: list[dict[str, Any]] = []
    checks = later.get("checks_performed")
    for key in before.keys() - after.keys():
        relevant_check = _relevant_check(key)
        if not isinstance(checks, list) or relevant_check is None or relevant_check not in checks:
            not_assessed.append({**before[key], "reason": "The later scan did not establish that this check ran."})
        else:
            resolved.append(before[key])
    return {
        "earlier_scan_id": earlier.get("scan_id"),
        "later_scan_id": later.get("scan_id"),
        "target": earlier.get("target"),
        "new": new,
        "recurring": recurring,
        "resolved": resolved,
        "not_assessed": not_assessed,
        "limitations": LIMITATIONS,
    }


def assessment_summary(scan: dict[str, Any]) -> dict[str, Any]:
    findings = safe_findings(scan)
    severity_counts = Counter(item.get("severity", "Unknown") for item in findings)
    category_counts = Counter(finding_category(item["finding_id"]) for item in findings)
    return {
        "scan": {
            "scan_id": scan.get("scan_id"),
            "target": scan.get("target"),
            "timestamp": scan.get("timestamp"),
            "status_code": scan.get("status_code"),
            "completed": scan_completed(scan),
        },
        "scope": "One passive, bounded GET request to a validated localhost/loopback target.",
        "checks_performed": scan.get("checks_performed") or [],
        "severity_counts": dict(severity_counts),
        "category_counts": dict(category_counts),
        "findings": findings,
        "errors": [
            {"type": _redact_text(item.get("type", "")), "message": _redact_text(item.get("message", ""))}
            for item in scan.get("errors", []) if isinstance(item, dict)
        ],
        "limitations": LIMITATIONS,
    }


def render_summary_html(summary: dict[str, Any]) -> str:
    def h(value: Any) -> str:
        return escape(str(value if value is not None else ""))

    finding_sections = []
    for finding in summary.get("findings", []):
        rows = "".join(
            f"<dt>{h(label)}</dt><dd>{h(finding.get(key, ''))}</dd>"
            for label, key in (
                ("Severity", "severity"), ("Confidence", "confidence"),
                ("Affected URL", "affected_url"), ("Evidence", "evidence"),
                ("Explanation", "explanation"), ("Remediation", "remediation"),
            )
        )
        finding_sections.append(f"<article><h3>{h(finding.get('title'))}</h3><dl>{rows}</dl></article>")
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>EthicalHackingAgent assessment summary</title>
<style>body{{font-family:system-ui,sans-serif;max-width:960px;margin:auto;padding:1rem}}article{{border:1px solid #ccc;padding:1rem;margin:1rem 0}}dt{{font-weight:bold}}dd{{margin:0 0 .5rem;overflow-wrap:anywhere}}table{{border-collapse:collapse}}td,th{{padding:.4rem;border-bottom:1px solid #ddd;text-align:left}}</style></head>
<body><h1>Assessment summary</h1><p><strong>Target:</strong> {h(summary.get('scan', {}).get('target'))}</p>
<p><strong>Timestamp:</strong> {h(summary.get('scan', {}).get('timestamp'))}</p><p><strong>Scope:</strong> {h(summary.get('scope'))}</p>
<h2>Severity</h2><pre>{h(json.dumps(summary.get('severity_counts', {}), indent=2))}</pre>
<h2>Categories</h2><pre>{h(json.dumps(summary.get('category_counts', {}), indent=2))}</pre>
<h2>Findings</h2>{''.join(finding_sections) or '<p>No potential findings observed.</p>'}
<h2>Limitations</h2><ul>{''.join(f'<li>{h(item)}</li>' for item in summary.get('limitations', []))}</ul>
</body></html>"""
