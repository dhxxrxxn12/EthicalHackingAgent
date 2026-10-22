from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import pytest
import requests

from app.http_inspector import inspect_http


def install_fake_session(monkeypatch, get_callback):
    sessions = []

    class FakeSession:
        def __init__(self):
            self.trust_env = True
            self.closed = False
            sessions.append(self)

        def get(self, url, **kwargs):
            return get_callback(url, **kwargs)

        def close(self):
            self.closed = True

    monkeypatch.setattr(requests, "Session", FakeSession)
    return sessions


class LocalHandler(BaseHTTPRequestHandler):
    server_version = "LocalTest"
    sys_version = ""

    def do_GET(self):
        if self.path == "/unavailable":
            self.send_response(503)
        else:
            self.send_response(302)
            self.send_header("Location", "/next?token=should-not-be-reported")
        self.send_header("Content-Security-Policy", "default-src 'self'")
        self.send_header("Set-Cookie", "session=should-not-be-reported")
        self.end_headers()

    def log_message(self, format, *args):
        pass


def test_inspects_status_and_redirect_without_following_or_exposing_cookies():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = inspect_http(f"http://127.0.0.1:{server.server_port}/")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result.status_code == 302
    assert result.redirect_location == "/next?token=should-not-be-reported"
    assert "LocalTest" in result.headers["server"]
    assert result.headers["content-security-policy"] == "default-src 'self'"
    assert "set-cookie" not in result.headers
    assert result.elapsed_seconds >= 0


def test_unexpected_http_status_is_reported_without_raising():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        result = inspect_http(f"http://127.0.0.1:{server.server_port}/unavailable")
    finally:
        server.shutdown()
        thread.join()
        server.server_close()

    assert result.status_code == 503


def test_timeout_is_propagated(monkeypatch):
    monkeypatch.setenv("HTTP_PROXY", "http://192.0.2.1:8080")
    monkeypatch.setenv("NO_PROXY", "")

    def raise_timeout(*args, **kwargs):
        raise requests.Timeout("request timed out")

    sessions = install_fake_session(monkeypatch, raise_timeout)
    with pytest.raises(requests.Timeout):
        inspect_http("http://localhost:8000/")
    assert sessions[0].trust_env is False
    assert sessions[0].closed is True


def test_https_request_keeps_certificate_verification_enabled(monkeypatch):
    class FakeResponse:
        status_code = 200
        headers = {}

        def close(self):
            pass

    captured = {}

    def fake_get(url, **kwargs):
        captured.update(kwargs)
        return FakeResponse()

    sessions = install_fake_session(monkeypatch, fake_get)
    result = inspect_http("https://localhost:8443/")

    assert captured["verify"] is True
    assert result.status_code == 200
    assert result.tls_verified is True
    assert sessions[0].trust_env is False


def test_https_certificate_error_is_propagated_without_a_result(monkeypatch):
    def fail_certificate_check(url, **kwargs):
        assert kwargs["verify"] is True
        raise requests.exceptions.SSLError("certificate verification failed")

    install_fake_session(monkeypatch, fail_certificate_check)
    with pytest.raises(requests.exceptions.SSLError):
        inspect_http("https://localhost:8443/")


def test_external_redirect_is_reported_but_never_followed(monkeypatch):
    class FakeResponse:
        status_code = 302
        headers = {"Location": "https://example.invalid/redirect"}
        raw = None

        def close(self):
            pass

    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        return FakeResponse()

    install_fake_session(monkeypatch, fake_get)
    result = inspect_http("http://localhost:8000/")

    assert result.status_code == 302
    assert result.redirect_location == "https://example.invalid/redirect"
    assert len(calls) == 1
    assert calls[0][0] == "http://127.0.0.1:8000/"
    assert calls[0][1]["allow_redirects"] is False
