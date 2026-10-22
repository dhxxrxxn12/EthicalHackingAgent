import json

from fastapi.testclient import TestClient

from app.dashboard import APP_DIR, HistoryStore, create_app, render_dashboard_page
from app.http_inspector import HttpInspection


def fake_inspection(target, timeout):
    return HttpInspection(
        url=target,
        status_code=200,
        elapsed_seconds=0.01,
        headers={"server": "LocalTest/1.0"},
        redirect_location=None,
        cookies=[],
        allow_methods=[],
        technology_headers={"server": "LocalTest/1.0"},
        response_header_presence={"server": True},
    )


def test_dashboard_page_uses_safe_dom_rendering_for_untrusted_values():
    page = render_dashboard_page()

    script = (APP_DIR / "dashboard.js").read_text(encoding="utf-8")
    assert "textContent" in script
    assert "innerHTML" not in script
    assert "<script>alert" not in page


def test_dashboard_rejects_external_target_before_request(monkeypatch, tmp_path):
    called = False

    def unexpected_request(*args, **kwargs):
        nonlocal called
        called = True

    monkeypatch.setattr("app.dashboard.inspect_http", unexpected_request)
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))

    response = client.post("/api/scans", json={"target": "https://example.com/"})

    assert response.status_code == 201
    assert response.json()["errors"][0]["type"] == "TargetValidationError"
    assert called is False
    report_files = list(tmp_path.glob("*.json"))
    assert len(report_files) == 2  # report plus local dashboard history


def test_dashboard_scan_history_and_restricted_report_access(monkeypatch, tmp_path):
    monkeypatch.setattr("app.dashboard.inspect_http", fake_inspection)
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))

    response = client.post(
        "/api/scans", json={"target": "http://localhost:8765/?token=hidden"}
    )

    assert response.status_code == 201
    scan = response.json()
    assert scan["target"] == "http://127.0.0.1:8765/"
    assert "token=hidden" not in json.dumps(scan)
    scan_id = scan["scan_id"]

    overview = client.get("/api/overview")
    assert overview.status_code == 200
    assert overview.json()["scan_count"] == 1
    assert overview.json()["recent_scans"][0]["scan_id"] == scan_id

    json_report = client.get(f"/reports/{scan_id}/json")
    html_report = client.get(f"/reports/{scan_id}/html")
    assert json_report.status_code == 200
    assert html_report.status_code == 200
    assert json_report.json()["target"] == "http://127.0.0.1:8765/"
    assert client.get(f"/reports/{scan_id}/../../dashboard-history.json").status_code in {404, 422}
    assert client.get("/reports/not-a-scan/json").status_code == 404
    assert client.get(f"/reports/{scan_id}/txt").status_code == 404


def test_dashboard_validation_errors_are_safe_and_rendered_as_data(tmp_path):
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))

    response = client.post("/api/scans", json={"target": "http://localhost\"<script>"})

    assert response.status_code == 201
    payload = response.json()
    assert payload["errors"][0]["message"] == (
        "The requested target was rejected by local-only validation."
    )
    assert "script" not in json.dumps(payload).lower()


def test_default_host_allowlist_and_security_headers(tmp_path):
    client = TestClient(create_app(tmp_path))

    blocked = client.get("/", headers={"host": "attacker.example"})
    allowed = client.get("/", headers={"host": "127.0.0.1"})

    assert blocked.status_code == 400
    assert allowed.status_code == 200
    assert allowed.headers["x-content-type-options"] == "nosniff"
    assert allowed.headers["x-frame-options"] == "DENY"
    assert "script-src 'self'" in allowed.headers["content-security-policy"]
    assert "dashboard.js" in allowed.text


def test_unexpected_scan_errors_are_generic(monkeypatch, tmp_path):
    def fail(*args, **kwargs):
        raise RuntimeError("secret path /private/token")

    monkeypatch.setattr("app.dashboard.inspect_http", fail)
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))

    response = client.post("/api/scans", json={"target": "http://127.0.0.1:8000/"})

    assert response.status_code == 201
    body = response.json()
    assert body["errors"][0]["type"] == "ScanError"
    assert "private" not in json.dumps(body)
    assert "traceback" not in json.dumps(body).lower()


def test_repeated_scan_is_rejected_while_one_is_running(tmp_path):
    app = create_app(tmp_path, allowed_hosts=["testserver"])
    client = TestClient(app)
    assert app.state.scan_lock.acquire(blocking=False)
    try:
        response = client.post("/api/scans", json={"target": "http://127.0.0.1:8000/"})
    finally:
        app.state.scan_lock.release()
    assert response.status_code == 429
    assert response.json() == {"detail": "A scan is already in progress."}


def test_malformed_history_is_ignored_and_atomic_write_preserves_old_file(tmp_path, monkeypatch):
    history_path = tmp_path / "dashboard-history.json"
    history_path.write_text("{truncated", encoding="utf-8")
    store = HistoryStore(tmp_path)
    assert store.read() == []

    original = "[{\"keep\": true}]\n"
    history_path.write_text(original, encoding="utf-8")
    monkeypatch.setattr("app.dashboard.os.replace", lambda *args: (_ for _ in ()).throw(OSError("disk full")))
    try:
        store.append({"new": "record"})
    except OSError:
        pass
    assert history_path.read_text(encoding="utf-8") == original


def test_corrupt_report_is_not_served(monkeypatch, tmp_path):
    monkeypatch.setattr("app.dashboard.inspect_http", fake_inspection)
    client = TestClient(create_app(tmp_path, allowed_hosts=["testserver"]))
    scan = client.post("/api/scans", json={"target": "http://127.0.0.1:8765/"}).json()
    report_path = tmp_path / scan["json_report"]
    report_path.write_text("not json", encoding="utf-8")

    response = client.get(f"/reports/{scan['scan_id']}/json")

    assert response.status_code == 404
