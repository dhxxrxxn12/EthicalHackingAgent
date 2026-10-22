import json
from datetime import datetime, timezone

from app.findings import Finding, Severity, findings_from_header_checks
from app.header_analyzer import analyze_security_headers
from app.http_inspector import HttpInspection
from app.reporter import create_scan_report, render_html_report, write_reports


def test_findings_have_stable_ids_and_cautious_explanations():
    checks = analyze_security_headers({}, is_https=True)
    first = findings_from_header_checks(checks, affected_url="https://localhost/a?token=secret")
    second = findings_from_header_checks(checks, affected_url="https://localhost/a?token=secret")

    assert [finding.finding_id for finding in first] == [
        finding.finding_id for finding in second
    ]
    assert all(finding.severity in Severity for finding in first)
    assert all(finding.confidence == 95 for finding in first)
    assert all("does not by itself confirm" in finding.explanation for finding in first)
    assert all(finding.affected_url == "https://localhost/" for finding in first)


def test_json_report_redacts_secrets_and_uses_safe_filenames(tmp_path):
    secret = "super-secret-value"
    result = HttpInspection(
        url=f"http://localhost:8000/private?token={secret}",
        status_code=200,
        elapsed_seconds=0.125,
        headers={
            "server": "Example",
            "set-cookie": f"session={secret}",
            "authorization": f"Bearer {secret}",
            "content-security-policy": "default-src 'self'",
        },
        redirect_location=f"/next?token={secret}",
    )
    report = create_scan_report(
        target=result.url,
        http_result=result,
        findings=[],
        errors=[{"type": "Timeout", "message": f"leaked {secret}"}],
        timestamp=datetime(2026, 10, 21, tzinfo=timezone.utc),
    )

    json_path, html_path = write_reports(report, tmp_path, target=result.url)
    serialized = json_path.read_text(encoding="utf-8")

    assert secret not in serialized
    assert "set-cookie" not in serialized.lower()
    assert "authorization" not in serialized.lower()
    assert report["target"] == "http://localhost:8000/"
    assert report["http"]["headers_present"]["content-security-policy"] is True
    assert report["http"]["tls_verified"] is None
    assert json_path.exists() and html_path.exists()
    assert json_path.parent == tmp_path
    assert "/" not in json_path.name
    json.loads(serialized)


def test_html_escapes_untrusted_finding_text_and_has_no_external_assets():
    finding = Finding(
        finding_id="TEST-1",
        title='<script>alert("x")</script>',
        severity=Severity.LOW,
        confidence=50,
        affected_url="http://localhost/?x=<script>",
        evidence='<img src=x onerror="alert(1)">',
        explanation="Observed text & details",
        remediation="Fix <this>",
    )
    report = create_scan_report(
        target="http://localhost/",
        http_result=None,
        findings=[finding],
        errors=[],
    )

    html = render_html_report(report)

    assert "<script>" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;img" in html
    assert "&amp; details" in html
    assert "<link " not in html.lower()
    assert "<script " not in html.lower()


def test_tls_failure_is_not_recorded_as_verified():
    report = create_scan_report(
        target="https://localhost:8443/",
        http_result=None,
        findings=[],
        errors=[
            {
                "type": "SSLError",
                "message": "certificate error; leaked token=private",
            }
        ],
    )

    assert report["http"] is None
    assert report["errors"][0]["message"] == (
        "TLS certificate verification failed; no HTTP result was accepted."
    )
    assert "private" not in json.dumps(report)
