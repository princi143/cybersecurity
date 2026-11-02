import asyncio

import httpx
import pytest
from fastapi.testclient import TestClient

from app import scanner
from app.main import app
from app.scanner import (ScanError, check_cookies, check_disclosure, check_headers,
                         grade_for, normalise_target, score_checks, Check)


def resp(headers):
    return httpx.Response(200, headers=headers, request=httpx.Request("GET", "https://x.com/"))


# ---------------- input validation / SSRF
@pytest.mark.parametrize("raw,host", [
    ("example.com", "example.com"),
    ("https://Example.COM/path?q=1", "example.com"),
    ("http://shop.example.in", "shop.example.in"),
])
def test_normalise_ok(raw, host):
    assert normalise_target(raw) == host


@pytest.mark.parametrize("raw", ["", "ftp://example.com", "localhost", "http://example.com:8080",
                                 "http://user:pw@example.com", "javascript:alert(1)"])
def test_normalise_rejects(raw):
    with pytest.raises(ScanError):
        normalise_target(raw)


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"])
def test_private_ips_blocked(ip):
    assert scanner._is_public(ip) is False


def test_public_ip_allowed():
    assert scanner._is_public("8.8.8.8") is True


def test_private_host_rejected(monkeypatch):
    async def fake(host, port, type=0):
        return [(None, None, None, None, ("169.254.169.254", 0))]
    loop = asyncio.new_event_loop()
    monkeypatch.setattr(loop, "getaddrinfo", fake)
    with pytest.raises(ScanError):
        loop.run_until_complete(scanner.assert_public_host("metadata.evil.com"))
    loop.close()


# ---------------- header checks
def test_all_headers_present_pass():
    checks = check_headers(resp({
        "strict-transport-security": "max-age=31536000; includeSubDomains",
        "content-security-policy": "default-src 'self'; frame-ancestors 'self'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "permissions-policy": "camera=()",
    }))
    assert all(c.status == "pass" for c in checks)


def test_short_hsts_is_warning():
    checks = {c.id: c for c in check_headers(resp({"strict-transport-security": "max-age=300"}))}
    assert checks["hdr_hsts"].status == "warn"


def test_missing_headers_fail_with_fix():
    checks = check_headers(resp({}))
    assert all(c.status == "fail" and c.fix for c in checks)


def test_disclosure():
    checks = {c.id: c for c in check_disclosure(resp({"server": "Apache/2.4.1", "x-powered-by": "PHP/7.4"}))}
    assert checks["disc_server"].status == "warn"
    assert checks["disc_powered"].status == "warn"


def test_cookies_weak_and_strong():
    weak = check_cookies(resp([("set-cookie", "sid=1; Path=/")]))
    assert weak.status == "warn" and "sid" in weak.detail
    strong = check_cookies(resp([("set-cookie", "sid=1; Secure; HttpOnly; SameSite=Lax")]))
    assert strong.status == "pass"


# ---------------- scoring
def test_scoring_and_grades():
    checks = [Check("a", "x", "a", "pass", "", weight=10), Check("b", "x", "b", "warn", "", weight=10),
              Check("c", "x", "c", "info", "", weight=50)]
    assert score_checks(checks) == 75
    assert [grade_for(s) for s in (95, 80, 65, 45, 10)] == list("ABCDF")


# ---------------- API
client = TestClient(app)


def test_health():
    assert client.get("/api/health").json() == {"status": "ok"}


def test_scan_rejects_bad_input():
    r = client.post("/api/scan", json={"url": "http://localhost"})
    assert r.status_code == 400


def test_contact_validation_and_honeypot(tmp_path, monkeypatch):
    monkeypatch.setattr("app.main.DB_PATH", str(tmp_path / "t.db"))
    ok = client.post("/api/contact", json={"name": "Ravi", "email": "ravi@shop.in", "message": "hi"},
                     headers={"x-forwarded-for": "1.1.1.1"})
    assert ok.status_code == 201
    bad = client.post("/api/contact", json={"name": "Ravi", "email": "nope"},
                      headers={"x-forwarded-for": "2.2.2.2"})
    assert bad.status_code == 422
    bot = client.post("/api/contact", json={"name": "Bot", "email": "x", "company_fax": "123"},
                      headers={"x-forwarded-for": "3.3.3.3"})
    assert bot.status_code == 201


def test_leads_requires_token(monkeypatch, tmp_path):
    monkeypatch.setattr("app.main.DB_PATH", str(tmp_path / "t.db"))
    assert client.get("/api/leads").status_code == 401
    monkeypatch.setenv("ADMIN_TOKEN", "s3cret")
    assert client.get("/api/leads", headers={"Authorization": "Bearer wrong"}).status_code == 401
    assert client.get("/api/leads", headers={"Authorization": "Bearer s3cret"}).status_code == 200
