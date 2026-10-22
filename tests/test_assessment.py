import json

from fastapi.testclient import TestClient

from app.assessment import assessment_summary, compare_scans, render_summary_html
from app.dashboard import CHECKS_PERFORMED, HistoryStore, create_app


def finding(finding_id, title=None, severity="Low"):
    return {
        "finding_id": finding_id,
        "title": title or finding_id,
        "severity": severity,
        "confidence": 90,
        "affected_url": "http://127.0.0.1:8765/",
        "evidence": "Observed safely",
        "explanation": "Observation only",
        "remediation": "Review configuration",
    }


def scan(scan_id, timestamp, findings, *, errors=None, checks=None, target="http://127.0.0.1:8765/"):
    severity_counts = {}
    for item in findings:
        severity_counts[item["severity"]] = severity_counts.get(item["severity"], 0) + 1
    return {
        "scan_id": scan_id,
        "timestamp": timestamp,
        "target": target,
        "status_code": 200 if not errors else None,
        "completed": not errors,
        "checks_performed": CHECKS_PERFORMED if checks is None and not errors else (checks or []),
        "finding_count": len(findings),
        "severity_counts": severity_counts,
        "errors": errors or [],
        "findings": findings,
        "json_report": f"scan-127.0.0.1-{scan_id}.json",
        "html_report": f"scan-127.0.0.1-{scan_id}.html",
    }


def test_comparison_categorizes_new_recurring_and_resolved_findings():
    earlier = scan("a" * 32, "2026-10-20T10:00:00+00:00", [finding("WEB-HEADER-A"), finding("WEB-CORS-B")])
    later = scan("b" * 32, "2026-10-21T10:00:00+00:00", [finding("WEB-CORS-B"), finding("WEB-COOKIE-C")])

    result = compare_scans(earlier, later)

    assert [item["finding_id"] for item in result["new"]] == ["WEB-COOKIE-C"]
    assert [item["finding_id"] for item in result["recurring"]] == ["WEB-CORS-B"]
    assert [item["finding_id"] for item in result["resolved"]] == ["WEB-HEADER-A"]
    assert result["not_assessed"] == []


def test_comparison_does_not_claim_resolution_for_incomplete_later_checks():
    earlier = scan("a" * 32, "2026-10-20T10:00:00+00:00", [finding("WEB-COOKIE-A")])
    later = scan("b" * 32, "2026-10-21T10:00:00+00:00", [], checks=["security_headers"])

    result = compare_scans(earlier, later)

    assert result["resolved"] == []
    assert result["not_assessed"][0]["finding_id"] == "WEB-COOKIE-A"
    assert "not establish" in result["not_assessed"][0]["reason"]


def test_comparison_rejects_failed_mismatched_and_duplicate_schema_records():
    earlier = scan("a" * 32, "2026-10-20T10:00:00+00:00", [finding("WEB-HEADER-A"), finding("WEB-HEADER-A")])
    failed = scan("b" * 32, "2026-10-21T10:00:00+00:00", [], errors=[{"type": "Timeout", "message": "safe"}])
    mismatched = scan("c" * 32, "2026-10-21T10:00:00+00:00", [], target="http://127.0.0.1:9000/")

    try:
        compare_scans(earlier, failed)
        assert False, "failed scans must be rejected"
    except ValueError as exc:
        assert "completed" in str(exc)
    try:
        compare_scans(earlier, mismatched)
        assert False, "mismatched targets must be rejected"
    except ValueError as exc:
        assert "target" in str(exc)
    assert len(compare_scans(earlier, scan("d" * 32, "2026-10-22T10:00:00+00:00", [finding("WEB-HEADER-A")]))["recurring"]) == 1


def test_summary_redacts_secrets_and_escapes_html():
    item = finding("WEB-INFO-X", '<script>alert(1)</script>')
    item["evidence"] = "token=super-secret"
    summary = assessment_summary(scan("a" * 32, "2026-10-20T10:00:00+00:00", [item]))
    html = render_summary_html(summary)

    assert "super-secret" not in json.dumps(summary)
    assert "&lt;script&gt;" in html
    assert "<script>alert" not in html


def test_dashboard_history_filter_comparison_and_summary_exports(tmp_path):
    store = HistoryStore(tmp_path)
    earlier = scan("a" * 32, "2026-10-20T10:00:00+00:00", [finding("WEB-HEADER-A")])
    later = scan("b" * 32, "2026-10-21T10:00:00+00:00", [finding("WEB-COOKIE-B", severity="Medium")])
    store.append(earlier)
    store.append(later)
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))

    filtered = client.get("/api/history?date_from=2026-10-21&severity=Medium")
    comparison = client.post("/api/compare", json={"earlier_scan_id": earlier["scan_id"], "later_scan_id": later["scan_id"]})
    summary_json = client.get(f"/reports/{later['scan_id']}/summary.json")
    summary_html = client.get(f"/reports/{later['scan_id']}/summary.html")

    assert filtered.status_code == 200
    assert [item["scan_id"] for item in filtered.json()["scans"]] == [later["scan_id"]]
    assert comparison.status_code == 200
    assert comparison.json()["new"][0]["finding_id"] == "WEB-COOKIE-B"
    assert summary_json.status_code == 200
    assert summary_json.json()["scan"]["scan_id"] == later["scan_id"]
    assert summary_html.status_code == 200
    assert "Assessment summary" in summary_html.text

