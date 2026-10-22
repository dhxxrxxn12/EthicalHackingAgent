# EthicalHackingAgent

A local-first, non-invasive web application inspection tool for learning. It
accepts only `localhost` and loopback IP addresses. It does not follow redirects,
submit forms, download response bodies, or attempt exploits.

## Milestones 1–6

- Validate HTTP(S) targets as localhost or loopback addresses.
- Make one bounded-timeout GET request and report status, elapsed time, redirect,
  and security-header presence.
- Verify HTTPS certificates using Requests' default CA and hostname checks.
  TLS verification remains enabled; a certificate error means no successful
  HTTP/TLS result is reported.
- Pin `localhost` to `127.0.0.1` before connecting, and require literal loopback
  IPs for all other targets. This avoids hostname DNS resolution and common
  alternate numeric-IP ambiguity. The HTTPS certificate must match the pinned
  IP address when `localhost` is used. Requests ignores environment-configured
  proxies, and redirects are reported but never followed.
- Create cautious, structured potential findings with stable IDs, severity,
  confidence in the observation, evidence, explanation, and remediation.
- Passively inspect Set-Cookie attributes, CORS response headers, advertised
  `Allow` methods, and technology/version details in response headers already
  returned by the single GET request.
- Cookie checks report missing `Secure` only for cookies observed over HTTPS,
  report missing `HttpOnly` and `SameSite`, and flag `SameSite=None` without
  `Secure`. Cookie values are never retained; sensitive or unsafe names become
  generic labels. Missing attributes are configuration observations, not proof
  of exploitability.
- CORS checks summarize wildcard/null origins and credentials. The scanner does
  not send `Origin` probes, and an observed header combination alone does not
  prove a CORS vulnerability. `Allow` methods are recorded as advertised,
  unverified observations; no `OPTIONS`, `PUT`, or `DELETE` requests are sent.
- Retain only safe cookie labels and cookie-attribute booleans; raw Set-Cookie
  values are discarded immediately. CORS values are summarized as booleans and
  advertised methods are token-filtered. These checks do not prove exploitability.
- Optionally export paired JSON and self-contained responsive HTML reports.
- Omit query strings, response bodies, raw Set-Cookie values, and authorization
  headers from reports. Technology header values are filtered and summarized;
  other header values are not included in reports.
- Run tests, including an in-process HTTP server bound to loopback.
- Provide an optional FastAPI dashboard at `http://127.0.0.1:8080/` with local
  scan history, severity totals, structured findings, and links to the paired
  JSON/HTML reports. The dashboard uses the existing scanner and enforces the
  same server-side localhost/loopback validation; it does not add probing or
  active-testing capabilities.
- Harden the dashboard with a loopback Host allowlist, security response
  headers, same-origin JavaScript, generic error responses, serialized scan
  execution, bounded request timeouts, and no permissive CORS.
- Store history with record validation and atomic replacement. Missing,
  truncated, malformed, or partially invalid history is ignored safely, while a
  failed write leaves the previous history file intact. Report routes serve
  only recorded, generated JSON/HTML files whose contents pass basic integrity
  checks.
- Filter scan history by ISO date and severity, compare two completed scans of
  the same normalized target, and classify stable-ID findings as new, recurring,
  observed-resolved, or not assessed. A failed or incomplete later scan never
  turns a missing finding into a claimed fix.
- Export per-scan assessment summaries as JSON or self-contained HTML. Summaries
  include scope, timestamp, checks performed, severity/category totals, findings,
  and known limitations; values are redacted and HTML-escaped.

Findings are potential observations for manual verification, not proof of a
vulnerability. Do not scan systems without ownership or explicit authorization.

## Setup on macOS

From the project directory:

```sh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest
```

## Run the CLI

The default target is `http://127.0.0.1:8000/`:

```sh
python -m app.main
```

Or specify a localhost/loopback URL:

```sh
python -m app.main http://localhost:8000/
```

To create both report formats, provide an output directory:

```sh
python -m app.main http://127.0.0.1:8000/ --report-dir reports
```

The CLI prints the generated `.json` and `.html` paths. Filenames use a
sanitized local hostname and UTC timestamp. Reports contain a scan ID, timestamp,
safe target origin, HTTP status/response time/redirect indicator, security-header
presence, TLS verification state, cookie count, safe technology details, CORS
configuration indicators, filtered advertised methods, findings, and sanitized
errors.

The scanner performs a single GET request, does not follow redirects, and closes
the streamed response without reading its body. Redirect responses are never
followed, even when they point to another loopback address; off-target redirect
destinations are not requested. Requests use a 3.05-second
connection timeout and a 5-second read timeout. A 4xx or 5xx response is recorded
as an HTTP result rather than treated as a transport error.

## Demonstrate against a local test server

In a second terminal, from the project directory:

```sh
python3 -m http.server 8000 --bind 127.0.0.1
```

With the virtual environment activated in the scanner terminal:

```sh
python -m app.main http://127.0.0.1:8000/
```

The Python test suite also starts temporary local HTTP servers to check status
and redirect reporting without sending traffic to an external system.

## Run the local dashboard

Install the dependencies in the virtual environment, including FastAPI and
Uvicorn:

```sh
python -m pip install -r requirements.txt
python -m app.dashboard
```

Open `http://127.0.0.1:8080/` in a browser. The service binds to loopback by
default. Scan reports and up to 100 recent scan-history records are stored in
the local `reports/` directory. The dashboard exposes only reports referenced
by its own scan history; arbitrary filesystem paths are not accepted. Targets
are validated on the server and remain limited to localhost/literal loopback
addresses. It accepts Host headers for `127.0.0.1`, `localhost`, and IPv6
loopback only, and returns generic errors without tracebacks or filesystem
paths. Scans are serialized and use the same bounded timeout as the scanner.
Stop the process with Ctrl-C when finished.

The history API is available at `/api/history` with optional `date_from`,
`date_to`, and `severity` query parameters. Comparisons use
`POST /api/compare` with `earlier_scan_id` and `later_scan_id`. Per-scan
assessment exports are available at `/api/scans/{scan_id}/summary`,
`/reports/{scan_id}/summary.json`, and
`/reports/{scan_id}/summary.html`. These routes accept only scan IDs present in
validated local history.

For tests only, `create_app(..., allowed_hosts=["testserver"])` can inject a
specific Host allowlist. The runnable dashboard does not expose a remote-host
or permissive-host option; do not change its loopback bind without reviewing
the local-only safety policy.

## Example output

The precise response time, report filenames, and header results depend on the
local server. A typical CLI run looks like:

```text
JSON report: reports/scan-127.0.0.1-2026-10-21T18_30_00_123456_00_00.json
HTML report: reports/scan-127.0.0.1-2026-10-21T18_30_00_123456_00_00.html
Target: http://127.0.0.1:8000/
HTTP status: 200
Response time: 0.012 s
Redirect: none
Server: SimpleHTTP/0.6 Python/3.11.9
Security headers:
  Content-Security-Policy: missing — Define a policy appropriate for the application.
  X-Content-Type-Options: missing — Set this header to nosniff.
  Referrer-Policy: missing — Choose a restrictive referrer policy.
  Strict-Transport-Security: not applicable (HTTP) — Use HTTPS before relying on HSTS.
```
