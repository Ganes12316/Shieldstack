import pytest
from fastapi.testclient import TestClient
from starlette.requests import Request
from app.web.main import app, load_stats, _client_ip

client = TestClient(app)

def test_get_stats_endpoint():
    response = client.get("/stats")
    assert response.status_code == 200
    data = response.json()
    assert "repos_tested" in data
    assert "automated_tests" in data
    assert "languages_supported" in data
    assert "bugs_found" in data
    assert "total_scans" in data
    assert data["stats_backend"] in {"local", "upstash"}

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ShieldStack API running"
    assert "stats" in data


def make_request(headers=None, client_host="203.0.113.10"):
    raw_headers = [(key.lower().encode(), value.encode()) for key, value in (headers or {}).items()]
    return Request({
        "type": "http", "http_version": "1.1", "method": "GET", "scheme": "http",
        "path": "/", "raw_path": b"/", "query_string": b"", "headers": raw_headers,
        "server": ("testserver", 80), "client": (client_host, 12345),
    })


def test_client_ip_uses_last_forwarded_entry_and_ignores_forged_first(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    request = make_request({"X-Forwarded-For": "198.51.100.77, 203.0.113.42"})
    assert _client_ip(request) == "203.0.113.42"


def test_client_ip_falls_back_when_forwarded_chain_has_too_few_entries(monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "2")
    request = make_request({"X-Forwarded-For": "198.51.100.77"}, "203.0.113.10")
    assert _client_ip(request) == "203.0.113.10"


@pytest.mark.parametrize("forwarded", [None, "not-an-ip", "198.51.100.1, invalid"])
def test_client_ip_falls_back_to_direct_address_for_missing_or_invalid_header(forwarded, monkeypatch):
    monkeypatch.setenv("TRUSTED_PROXY_HOPS", "1")
    headers = {} if forwarded is None else {"X-Forwarded-For": forwarded}
    assert _client_ip(make_request(headers, "203.0.113.10")) == "203.0.113.10"


def test_health_is_exempt_from_rate_limits():
    headers = {"X-Forwarded-For": "198.51.100.31"}
    for _ in range(125):
        assert client.get("/health", headers=headers).status_code == 200


def test_scan_is_limited_after_ten_requests_per_minute():
    headers = {"X-Forwarded-For": "198.51.100.32"}
    for _ in range(10):
        assert client.post("/scan", json={}, headers=headers).status_code == 200
    limited = client.post("/scan", json={}, headers=headers)
    assert limited.status_code == 429
    assert limited.json() == {"detail": "Too many requests. Please wait a minute and try again."}
    assert "Retry-After" in limited.headers


def test_two_client_ips_have_separate_scan_counters():
    first = {"X-Forwarded-For": "198.51.100.33"}
    second = {"X-Forwarded-For": "198.51.100.34"}
    for _ in range(10):
        assert client.post("/scan", json={}, headers=first).status_code == 200
    assert client.post("/scan", json={}, headers=second).status_code == 200
    limited = client.post("/scan", json={}, headers=first)
    assert limited.status_code == 429
    assert client.post("/scan", json={}, headers=second).status_code == 200
