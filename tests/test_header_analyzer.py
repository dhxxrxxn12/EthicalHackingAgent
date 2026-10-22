from app.header_analyzer import analyze_security_headers


def test_reports_present_and_missing_headers_case_insensitively():
    checks = analyze_security_headers(
        {
            "content-security-policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff",
        },
        is_https=True,
    )

    by_name = {check.name: check for check in checks}
    assert by_name["Content-Security-Policy"].status == "present"
    assert by_name["X-Content-Type-Options"].status == "present"
    assert by_name["Referrer-Policy"].status == "missing"
    assert by_name["Strict-Transport-Security"].status == "missing"


def test_hsts_is_not_applicable_over_http():
    checks = analyze_security_headers({}, is_https=False)
    hsts = next(check for check in checks if check.name == "Strict-Transport-Security")

    assert hsts.status == "not applicable (HTTP)"
