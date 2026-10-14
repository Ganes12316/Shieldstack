import pytest
from fastapi.testclient import TestClient
from app.web.main import app, load_stats

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

def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ShieldStack API running"
    assert "stats" in data
