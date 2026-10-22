import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

from app.findings import (
    deduplicate_findings,
    findings_from_cookies,
    findings_from_http_observations,
)
from app.http_inspector import CookieObservation, HttpInspection, inspect_http
from app.reporter import create_scan_report, render_html_report


COOKIE_SECRET = "cookie-value-must-never-appear"


class PassiveHeadersHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.24.0"
    sys_version = ""

    def do_GET(self):
        self.send_response(200)
        self.send_header(
            "Set-Cookie", f"sessionid={COOKIE_SECRET}; Path=/; SameSite=None"
        )
        self.send_header("Set-Cookie", f"theme=dark; Path=/; HttpOnly; SameSite=Lax")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Credentials", "true")
        self.send_header("Allow", "GET, HEAD")
        self.send_header("X-Powered-By", "Express")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_passive_observations_redact_cookie_values_and_report_safe_findings():
    server = ThreadingHTTPServer(("127.0.0.1", 0), PassiveHeadersHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = inspect_http(f"http://127.0.0.1:{server.server_port}/")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result.cookies == [
        CookieObservation("Cookie 1", False, False, "none"),
        CookieObservation("theme", False, True, "lax"),
    ]
    assert COOKIE_SECRET not in repr(result)
    assert "set-cookie" not in result.headers
    assert result.allow_methods == ["GET", "HEAD"]
    assert result.cors_wildcard_origin is True
    assert result.cors_credentials_enabled is True
    assert result.technology_headers == {
        "server": "nginx/1.24.0",
        "x-powered-by": "Express",
    }

    findings = findings_from_http_observations(result)
    report = create_scan_report(
        target=result.url,
        http_result=result,
        findings=findings,
        errors=[],
    )
    json_text = json.dumps(report)
    html_text = render_html_report(report)
    combined_findings = " ".join(
        f"{finding.title} {finding.evidence} {finding.explanation}"
        for finding in findings
    )
    assert COOKIE_SECRET not in combined_findings
    assert COOKIE_SECRET not in json_text
    assert COOKIE_SECRET not in html_text
    assert any(
        finding.finding_id == "WEB-COOKIE-UNSPECIFIED-SAMESITE-NONE-REQUIRES-SECURE"
        for finding in findings
    )
    assert any(finding.finding_id == "WEB-CORS-WILDCARD-CREDENTIALS" for finding in findings)
    assert any(
        finding.finding_id == "WEB-INFO-SERVER-VERSION-DISCLOSED"
        for finding in findings
    )
    assert any(
        finding.finding_id == "WEB-INFO-X-POWERED-BY-DISCLOSED"
        for finding in findings
    )
    assert report["http"]["allow_methods"] == ["GET", "HEAD"]
    assert report["http"]["cookies_observed"] == 2
    assert "Advertised methods (not verified)" in html_text


def test_cookie_secure_check_is_context_aware_for_https():
    cookie = CookieObservation("preference", False, True, "lax")

    findings = findings_from_cookies(
        [cookie], affected_url="https://localhost/", is_https=True
    )

    assert len(findings) == 1
    assert findings[0].finding_id == "WEB-COOKIE-PREFERENCE-SECURE"


def test_cookie_secure_is_not_reported_for_http_and_missing_attributes_are_independent():
    findings = findings_from_cookies(
        [CookieObservation("preference", False, False, "lax")],
        affected_url="http://localhost/",
        is_https=False,
    )

    assert {finding.finding_id for finding in findings} == {
        "WEB-COOKIE-PREFERENCE-HTTPONLY",
    }


def test_server_version_detection_accepts_space_separated_versions():
    result = HttpInspection(
        url="http://127.0.0.1/",
        status_code=200,
        elapsed_seconds=0,
        headers={},
        redirect_location=None,
        cookies=[],
        technology_headers={"server": "Apache 2.4.58"},
    )

    findings = findings_from_http_observations(result)

    assert [finding.finding_id for finding in findings] == [
        "WEB-INFO-SERVER-VERSION-DISCLOSED"
    ]


def test_missing_optional_technology_observations_are_safe():
    result = HttpInspection(
        url="http://127.0.0.1/",
        status_code=200,
        elapsed_seconds=0,
        headers={},
        redirect_location=None,
        cookies=[],
    )

    assert findings_from_http_observations(result) == []


def test_duplicate_cookie_and_header_findings_are_deduplicated():
    cookie = CookieObservation("Cookie 1", False, False, None)
    duplicates = findings_from_cookies(
        [cookie, CookieObservation("Cookie 2", False, False, None)],
        affected_url="http://localhost/",
        is_https=False,
    )

    unique = deduplicate_findings(duplicates + duplicates)

    assert {finding.finding_id for finding in unique} == {
        "WEB-COOKIE-UNSPECIFIED-HTTPONLY",
        "WEB-COOKIE-UNSPECIFIED-SAMESITE",
    }
    assert len(unique) == 2


def test_cors_wildcard_without_credentials_is_observation_not_a_finding():
    result = HttpInspection(
        url="http://127.0.0.1/",
        status_code=200,
        elapsed_seconds=0,
        headers={},
        redirect_location=None,
        cors_wildcard_origin=True,
        cors_credentials_enabled=False,
        cookies=[],
        technology_headers={},
    )

    assert not any(
        finding.finding_id.startswith("WEB-CORS-")
        for finding in findings_from_http_observations(result)
    )


def test_null_origin_with_credentials_is_flagged_cautiously():
    result = HttpInspection(
        url="http://127.0.0.1/",
        status_code=200,
        elapsed_seconds=0,
        headers={},
        redirect_location=None,
        cors_null_origin=True,
        cors_credentials_enabled=True,
        cookies=[],
        technology_headers={},
    )

    findings = findings_from_http_observations(result)

    assert len(findings) == 1
    assert findings[0].finding_id == "WEB-CORS-NULL-ORIGIN-CREDENTIALS"
    assert "do not prove an exploitable" in findings[0].explanation
