"""Command-line entry point for local web security inspection."""

import argparse
import logging
from urllib.parse import urlsplit, urlunsplit

import requests
from app.header_analyzer import analyze_security_headers
from app.findings import (
    deduplicate_findings,
    findings_from_header_checks,
    findings_from_http_observations,
)
from app.http_inspector import DEFAULT_TIMEOUT, inspect_http
from app.reporter import create_scan_report, write_reports
from app.target_validator import validate_target

DEFAULT_TARGET = "http://127.0.0.1:8000/"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Inspect HTTP metadata and security headers on a local target."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default=DEFAULT_TARGET,
        help=f"localhost or loopback URL (default: {DEFAULT_TARGET})",
    )
    parser.add_argument(
        "--report-dir",
        help="write paired JSON and HTML reports into this directory",
    )
    return parser


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
    args = build_parser().parse_args()
    target = None
    result = None
    findings = []
    errors = []
    try:
        target = validate_target(args.target)
    except ValueError as exc:
        logging.error("Scan could not be completed: %s", exc)
        errors.append({"type": "TargetValidationError", "message": str(exc)})
    if target is not None:
        try:
            result = inspect_http(target, timeout=DEFAULT_TIMEOUT)
        except requests.exceptions.SSLError:
            message = "TLS certificate verification failed; no HTTP result was accepted."
            logging.error("%s", message)
            errors.append({"type": "SSLError", "message": message})
        except requests.Timeout:
            message = "The HTTP request timed out."
            logging.error("%s", message)
            errors.append({"type": "Timeout", "message": message})
        except requests.RequestException as exc:
            message = "The HTTP request failed; see the error type in the report."
            logging.error("HTTP request failed (%s).", type(exc).__name__)
            errors.append({"type": type(exc).__name__, "message": message})

    if result is not None:
        checks = analyze_security_headers(
            result.headers, is_https=result.url.lower().startswith("https://")
        )
        findings = findings_from_header_checks(checks, affected_url=result.url)
        findings.extend(findings_from_http_observations(result))
        findings = deduplicate_findings(findings)

    report = create_scan_report(
        target=target,
        http_result=result,
        findings=findings,
        errors=errors,
    )

    if args.report_dir:
        try:
            json_path, html_path = write_reports(
                report, args.report_dir, target=target
            )
        except OSError:
            logging.error("Could not write reports to the requested directory.")
            return 1
        print(f"JSON report: {json_path}")
        print(f"HTML report: {html_path}")

    if result is None:
        return 1

    parsed_url = urlsplit(result.url)
    safe_display_url = urlunsplit(
        (parsed_url.scheme, parsed_url.netloc, parsed_url.path, "", "")
    )
    print(f"Target: {safe_display_url}")
    print(f"HTTP status: {result.status_code}")
    print(f"Response time: {result.elapsed_seconds:.3f} s")
    redirect = result.redirect_location
    if redirect:
        parsed_redirect = urlsplit(redirect)
        if parsed_redirect.scheme and parsed_redirect.hostname:
            host = parsed_redirect.hostname
            if ":" in host:
                host = f"[{host}]"
            try:
                port = parsed_redirect.port
            except ValueError:
                port = None
            netloc = f"{host}:{port}" if port is not None else host
            redirect = urlunsplit((parsed_redirect.scheme, netloc, "/", "", ""))
        else:
            redirect = "(relative destination; path omitted)"
    print(f"Redirect: {redirect or 'none'}")
    print(f"Server: {result.headers.get('server', 'not provided')}")
    if result.allow_methods:
        print(f"Advertised methods (unverified): {', '.join(result.allow_methods)}")
    if report["http"]["tls_verified"] is True:
        print("TLS: certificate verification succeeded")
    print("Security headers:")
    for check in checks:
        suffix = f" — {check.recommendation}" if check.recommendation else ""
        print(f"  {check.name}: {check.status}{suffix}")
    print("Potential findings:")
    for finding in findings:
        print(f"  [{finding.severity.value}] {finding.title}")
    if not findings:
        print("  none observed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
