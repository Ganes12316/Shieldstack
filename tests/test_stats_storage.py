import json
import tempfile
from pathlib import Path

import pytest
import requests

from app.web import main


@pytest.fixture
def stats_tmp_path():
    # Keep test files under the writable workspace instead of pytest's default
    # per-user %TEMP% tree, which may be inaccessible in restricted Windows setups.
    with tempfile.TemporaryDirectory(
        prefix="stats-test-", dir=Path(__file__).resolve().parent
    ) as temp_dir:
        yield Path(temp_dir)


class MockRedisResponse:
    def __init__(self, result):
        self.result = result

    def raise_for_status(self):
        return None

    def json(self):
        return {"result": self.result}


def _write_local_stats(path, repos=2, findings=5, scans=3):
    path.write_text(
        json.dumps({
            "repos_tested": repos,
            "bugs_found": findings,
            "total_scans": scans,
        }),
        encoding="utf-8",
    )


def test_upstash_stats_success_uses_atomic_increments(monkeypatch, stats_tmp_path):
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_URL", "https://redis.example")
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_TOKEN", "test-secret-token")
    monkeypatch.setattr(main, "STATS_FILE", stats_tmp_path / "stats.json")
    commands = []
    timeouts = []

    def mock_post(url, json, headers, timeout):
        commands.append(json)
        timeouts.append(timeout)
        if json[0] == "MGET":
            return MockRedisResponse(["4", "9", "4"])
        return MockRedisResponse(1)

    monkeypatch.setattr(main.requests, "post", mock_post)

    result = main.record_scan_stats(2)

    assert result["repos_tested"] == 4
    assert result["bugs_found"] == 9
    assert result["total_scans"] == 4
    assert result["stats_backend"] == "upstash"
    assert commands == [
        ["INCRBY", "repos_tested", 1],
        ["INCRBY", "bugs_found", 2],
        ["INCRBY", "total_scans", 1],
        ["MGET", "repos_tested", "bugs_found", "total_scans"],
    ]
    assert timeouts == [3, 3, 3, 3]
    assert not (stats_tmp_path / "stats.json").exists()


def test_upstash_failure_falls_back_to_local_file(monkeypatch, stats_tmp_path):
    local_file = stats_tmp_path / "stats.json"
    _write_local_stats(local_file)
    monkeypatch.setattr(main, "STATS_FILE", local_file)
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_URL", "https://redis.example")
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_TOKEN", "test-secret-token")

    def mock_post(*args, **kwargs):
        raise requests.ConnectionError("unavailable")

    monkeypatch.setattr(main.requests, "post", mock_post)

    result = main.record_scan_stats(4)

    assert result["repos_tested"] == 3
    assert result["bugs_found"] == 9
    assert result["total_scans"] == 4
    assert result["stats_backend"] == "local"
    assert json.loads(local_file.read_text(encoding="utf-8"))["bugs_found"] == 9
    assert "test-secret-token" not in repr(result)


def test_missing_upstash_env_uses_local_file_without_redis_call(monkeypatch, stats_tmp_path):
    local_file = stats_tmp_path / "stats.json"
    _write_local_stats(local_file, repos=7, findings=11, scans=8)
    monkeypatch.setattr(main, "STATS_FILE", local_file)
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_URL", "")
    monkeypatch.setattr(main, "UPSTASH_REDIS_REST_TOKEN", "")

    def unexpected_post(*args, **kwargs):
        raise AssertionError("Redis should not be called without configuration")

    monkeypatch.setattr(main.requests, "post", unexpected_post)

    result = main.load_stats()

    assert result["repos_tested"] == 7
    assert result["bugs_found"] == 11
    assert result["total_scans"] == 8
    assert result["stats_backend"] == "local"
