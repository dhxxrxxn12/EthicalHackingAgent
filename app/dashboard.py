"""Local-only FastAPI dashboard for the existing passive scanner."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from threading import Lock
from tempfile import NamedTemporaryFile
from typing import Any

import requests
from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from pydantic import BaseModel, ConfigDict

from app.findings import (
    deduplicate_findings,
    findings_from_header_checks,
    findings_from_http_observations,
    safe_origin,
)
from app.assessment import (
    CHECKS_PERFORMED,
    assessment_summary,
    compare_scans,
    render_summary_html,
)
from app.header_analyzer import analyze_security_headers
from app.http_inspector import DEFAULT_TIMEOUT, inspect_http
from app.reporter import create_scan_report, write_reports
from app.target_validator import validate_target


APP_DIR = Path(__file__).resolve().parent
HISTORY_FILENAME = "dashboard-history.json"
SAFE_SCAN_ID = re.compile(r"^[0-9a-fA-F-]{20,64}$")
SAFE_REPORT_FILENAME = re.compile(r"^scan-[A-Za-z0-9._-]+\.(json|html)$")
REPORT_FORMATS = {"json": "json_report", "html": "html_report"}
DEFAULT_ALLOWED_HOSTS = ["127.0.0.1", "localhost", "[::1]"]
SCAN_TIMEOUT = DEFAULT_TIMEOUT


class ScanRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str


class CompareRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    earlier_scan_id: str
    later_scan_id: str


def _safe_error(error_type: str) -> dict[str, str]:
    messages = {
        "TargetValidationError": "The requested target was rejected by local-only validation.",
        "SSLError": "TLS certificate verification failed; no HTTP result was accepted.",
        "Timeout": "The HTTP request timed out.",
        "RequestException": "The HTTP request could not be completed.",
        "ScanError": "The scan could not be completed.",
    }
    safe_type = error_type if error_type in messages else "RequestException"
    return {"type": safe_type, "message": messages[safe_type]}


def _run_existing_scan(target: str | None) -> tuple[str | None, Any, list, list[dict[str, str]]]:
    """Run the same validated, single-request scan used by the CLI."""
    validated_target = None
    result = None
    findings = []
    errors: list[dict[str, str]] = []
    try:
        validated_target = validate_target(target or "")
    except ValueError:
        errors.append(_safe_error("TargetValidationError"))
        return validated_target, result, findings, errors

    try:
        result = inspect_http(validated_target, timeout=SCAN_TIMEOUT)
    except requests.exceptions.SSLError:
        errors.append(_safe_error("SSLError"))
    except requests.Timeout:
        errors.append(_safe_error("Timeout"))
    except requests.RequestException:
        errors.append(_safe_error("RequestException"))
    except Exception:
        errors.append(_safe_error("ScanError"))

    if result is not None:
        checks = analyze_security_headers(
            result.headers, is_https=result.url.lower().startswith("https://")
        )
        try:
            findings = findings_from_header_checks(checks, affected_url=result.url)
            findings.extend(findings_from_http_observations(result))
            findings = deduplicate_findings(findings)
        except Exception:
            findings = []
            errors.append(_safe_error("ScanError"))
    return validated_target, result, findings, errors


def _valid_history_entry(entry: Any) -> bool:
    if not isinstance(entry, dict):
        return False
    scan_id = entry.get("scan_id")
    timestamp = entry.get("timestamp")
    target = entry.get("target")
    if not isinstance(scan_id, str) or not SAFE_SCAN_ID.fullmatch(scan_id):
        return False
    if not isinstance(timestamp, str):
        return False
    try:
        datetime.fromisoformat(timestamp)
    except ValueError:
        return False
    if target is not None:
        if not isinstance(target, str) or target != safe_origin(target):
            return False
    for key in ("json_report", "html_report"):
        filename = entry.get(key)
        if not isinstance(filename, str) or not SAFE_REPORT_FILENAME.fullmatch(filename):
            return False
        if not filename.endswith(f".{key.removesuffix('_report')}"):
            return False
    if not isinstance(entry.get("status_code"), (int, type(None))):
        return False
    if not isinstance(entry.get("finding_count"), int) or entry["finding_count"] < 0:
        return False
    if "completed" in entry and not isinstance(entry["completed"], bool):
        return False
    if "checks_performed" in entry and (
        not isinstance(entry["checks_performed"], list)
        or any(not isinstance(check, str) or check not in CHECKS_PERFORMED for check in entry["checks_performed"])
    ):
        return False
    severity_counts = entry.get("severity_counts")
    if not isinstance(severity_counts, dict) or any(
        not isinstance(key, str) or not isinstance(value, int) or value < 0
        for key, value in severity_counts.items()
    ):
        return False
    if not isinstance(entry.get("errors"), list) or not isinstance(entry.get("findings"), list):
        return False
    return all(
        isinstance(item, dict)
        and isinstance(item.get("type"), str)
        and isinstance(item.get("message"), str)
        for item in entry["errors"]
    ) and all(
        isinstance(item, dict)
        and all(isinstance(item.get(key), str) for key in (
            "finding_id", "title", "severity", "affected_url", "evidence",
            "explanation", "remediation",
        ))
        and isinstance(item.get("confidence"), int)
        for item in entry["findings"]
    )


class HistoryStore:
    def __init__(self, report_dir: Path, history_path: Path | None = None):
        self.report_dir = report_dir
        self.history_path = history_path or report_dir / HISTORY_FILENAME
        self._lock = Lock()
        self.report_dir.mkdir(parents=True, exist_ok=True)

    def read(self) -> list[dict[str, Any]]:
        with self._lock:
            return self.read_unlocked()

    def append(self, entry: dict[str, Any]) -> None:
        with self._lock:
            entries = self.read_unlocked()
            entries.insert(0, entry)
            serialized = json.dumps(entries[:100], indent=2, ensure_ascii=True) + "\n"
            temporary_name = None
            try:
                with NamedTemporaryFile(
                    mode="w", encoding="utf-8", dir=self.history_path.parent,
                    prefix=f".{self.history_path.name}.", suffix=".tmp", delete=False,
                ) as temporary:
                    temporary_name = temporary.name
                    temporary.write(serialized)
                    temporary.flush()
                    os.fsync(temporary.fileno())
                os.replace(temporary_name, self.history_path)
            except OSError:
                if temporary_name:
                    try:
                        os.unlink(temporary_name)
                    except OSError:
                        pass
                raise

    def read_unlocked(self) -> list[dict[str, Any]]:
        try:
            data = json.loads(self.history_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, ValueError):
            return []
        if not isinstance(data, list):
            return []
        return [entry for entry in data[:100] if _valid_history_entry(entry)]

    def find(self, scan_id: str) -> dict[str, Any] | None:
        return next((item for item in self.read() if item.get("scan_id") == scan_id), None)


def _history_entry(report: dict, findings: list, json_path: Path, html_path: Path) -> dict[str, Any]:
    counts = Counter(finding.severity.value for finding in findings)
    http_result = report.get("http") or {}
    return {
        "scan_id": report["metadata"]["scan_id"],
        "timestamp": report["metadata"]["timestamp"],
        "target": report.get("target"),
        "status_code": http_result.get("status_code"),
        "finding_count": len(findings),
        "completed": not report.get("errors") and report.get("http") is not None,
        "checks_performed": CHECKS_PERFORMED if report.get("http") is not None else [],
        "severity_counts": dict(counts),
        "errors": report.get("errors", []),
        "findings": [finding.to_dict() for finding in findings],
        "json_report": json_path.name,
        "html_report": html_path.name,
    }


def _overview(store: HistoryStore) -> dict[str, Any]:
    history = store.read()
    severity_counts: Counter[str] = Counter()
    for entry in history:
        severity_counts.update(entry.get("severity_counts", {}))
    return {
        "scan_count": len(history),
        "severity_counts": dict(severity_counts),
        "recent_scans": history[:20],
    }


def _parse_filter_bound(value: str | None, *, end: bool = False) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="Invalid date filter.") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def render_dashboard_page() -> str:
    return (APP_DIR / "dashboard.html").read_text(encoding="utf-8")


def create_app(
    report_dir: str | Path = "reports",
    *,
    allowed_hosts: list[str] | None = None,
) -> FastAPI:
    store = HistoryStore(Path(report_dir).resolve())
    app = FastAPI(title="EthicalHackingAgent Dashboard", docs_url=None, redoc_url=None)
    app.state.history_store = store
    app.state.scan_lock = Lock()
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=allowed_hosts or DEFAULT_ALLOWED_HOSTS,
    )

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_request: Request, _exc: RequestValidationError):
        return JSONResponse(status_code=422, content={"detail": "Invalid request."})

    @app.exception_handler(Exception)
    async def unexpected_error(_request: Request, _exc: Exception):
        return JSONResponse(
            status_code=500,
            content={"detail": "The dashboard could not complete the request."},
        )

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        )
        return response

    @app.get("/", response_class=HTMLResponse)
    def dashboard() -> str:
        return render_dashboard_page()

    @app.get("/dashboard.js")
    def dashboard_script() -> FileResponse:
        return FileResponse(APP_DIR / "dashboard.js", media_type="text/javascript")

    @app.get("/api/overview")
    def overview() -> dict[str, Any]:
        return _overview(store)

    @app.get("/api/history")
    def history(
        date_from: str | None = None,
        date_to: str | None = None,
        severity: str | None = None,
    ) -> dict[str, Any]:
        start = _parse_filter_bound(date_from)
        end = _parse_filter_bound(date_to, end=True)
        if end and len(date_to or "") == 10:
            end = end.replace(hour=23, minute=59, second=59, microsecond=999999)
        allowed_severity = severity.casefold() if severity else None
        records = []
        for entry in store.read():
            timestamp = datetime.fromisoformat(entry["timestamp"]).astimezone(timezone.utc)
            if start and timestamp < start or end and timestamp > end:
                continue
            if allowed_severity and not any(
                name.casefold() == allowed_severity
                for name in entry.get("severity_counts", {})
            ):
                continue
            records.append(entry)
        return {"scan_count": len(records), "scans": records}

    @app.get("/api/scans/{scan_id}")
    def scan_details(scan_id: str) -> dict[str, Any]:
        if not SAFE_SCAN_ID.fullmatch(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        entry = store.find(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return entry

    @app.post("/api/compare")
    def compare(request: CompareRequest) -> dict[str, Any]:
        if not SAFE_SCAN_ID.fullmatch(request.earlier_scan_id) or not SAFE_SCAN_ID.fullmatch(request.later_scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        earlier = store.find(request.earlier_scan_id)
        later = store.find(request.later_scan_id)
        if earlier is None or later is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        try:
            return compare_scans(earlier, later)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    def get_summary(scan_id: str) -> dict[str, Any]:
        if not SAFE_SCAN_ID.fullmatch(scan_id):
            raise HTTPException(status_code=404, detail="Scan not found")
        entry = store.find(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        return assessment_summary(entry)

    @app.get("/api/scans/{scan_id}/summary")
    def summary_json(scan_id: str) -> dict[str, Any]:
        return get_summary(scan_id)

    @app.get("/reports/{scan_id}/summary.json")
    def summary_json_report(scan_id: str) -> JSONResponse:
        return JSONResponse(get_summary(scan_id))

    @app.get("/reports/{scan_id}/summary.html", response_class=HTMLResponse)
    def summary_html_report(scan_id: str) -> str:
        return render_summary_html(get_summary(scan_id))

    @app.post("/api/scans", status_code=201)
    def create_scan(request: ScanRequest) -> dict[str, Any]:
        if not app.state.scan_lock.acquire(blocking=False):
            raise HTTPException(status_code=429, detail="A scan is already in progress.")
        try:
            target, result, findings, errors = _run_existing_scan(request.target)
            report = create_scan_report(
                target=target,
                http_result=result,
                findings=findings,
                errors=errors,
            )
            json_path, html_path = write_reports(report, store.report_dir, target=target)
            entry = _history_entry(report, findings, json_path, html_path)
            store.append(entry)
            return {**entry, "findings": [finding.to_dict() for finding in findings]}
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=500, detail="The scan could not be completed.")
        finally:
            app.state.scan_lock.release()

    @app.get("/reports/{scan_id}/{report_format}")
    def report(scan_id: str, report_format: str) -> FileResponse:
        if not SAFE_SCAN_ID.fullmatch(scan_id) or report_format not in REPORT_FORMATS:
            raise HTTPException(status_code=404, detail="Report not found")
        entry = store.find(scan_id)
        if entry is None:
            raise HTTPException(status_code=404, detail="Report not found")
        filename = entry[REPORT_FORMATS[report_format]]
        if not isinstance(filename, str) or not SAFE_REPORT_FILENAME.fullmatch(filename):
            raise HTTPException(status_code=404, detail="Report not found")
        if not filename.endswith(f".{report_format}"):
            raise HTTPException(status_code=404, detail="Report not found")
        candidate = (store.report_dir / filename).resolve()
        if candidate.parent != store.report_dir.resolve() or candidate.name != filename:
            raise HTTPException(status_code=404, detail="Report not found")
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="Report not found")
        try:
            content = candidate.read_text(encoding="utf-8")
            if report_format == "json":
                parsed = json.loads(content)
                if not isinstance(parsed, dict) or "metadata" not in parsed:
                    raise ValueError
            elif not content.lstrip().lower().startswith("<!doctype html>"):
                raise ValueError
        except (OSError, UnicodeError, ValueError):
            raise HTTPException(status_code=404, detail="Report not found")
        media_type = "application/json" if report_format == "json" else "text/html"
        return FileResponse(candidate, media_type=media_type, filename=candidate.name)

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8080)
