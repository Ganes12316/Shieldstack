from fastapi.testclient import TestClient
from pathlib import Path

from app.scanner.file_selection import is_fixture_path
from app.scanner.secrets_detector import get_scanned_file_count, get_skipped_file_count, scan_directory
from app.web import main


def test_default_fixture_paths_are_excluded_but_regular_secret_paths_are_scanned(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "tests").mkdir()
    (tmp_path / "src" / "settings.py").write_text("DEBUG = True\n")
    (tmp_path / "tests" / "settings.py").write_text("DEBUG = True\n")

    findings = scan_directory(tmp_path)
    assert [finding.file_path for finding in findings] == [str(tmp_path / "src" / "settings.py")]
    assert get_scanned_file_count(tmp_path) == 1
    assert get_skipped_file_count(tmp_path) == 1


def test_shieldstackignore_adds_glob_exclusions(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "generated").mkdir()
    (tmp_path / "src" / "generated" / "example.py").write_text("DEBUG = True\n")
    (tmp_path / ".shieldstackignore").write_text("# generated examples\nsrc/generated/*.py\n")

    assert is_fixture_path(tmp_path / "src" / "generated" / "example.py", tmp_path)
    assert get_scanned_file_count(tmp_path) == 0


def test_include_fixtures_scans_excluded_paths_and_patterns(tmp_path):
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "auth_test.py").write_text("DEBUG = True\n")
    (tmp_path / ".shieldstackignore").write_text("tests/*.py\n")

    findings = scan_directory(tmp_path, include_fixtures=True)
    assert len(findings) == 1
    assert get_scanned_file_count(tmp_path, include_fixtures=True) == 1


def test_vulnerable_sample_app_requires_fixture_opt_in():
    sample_root = Path(__file__).resolve().parents[1] / "sample_vulnerable_app"
    assert get_scanned_file_count(sample_root) == 0
    assert get_scanned_file_count(sample_root, include_fixtures=True) > 0
    assert scan_directory(sample_root, include_fixtures=True)


def test_web_response_reports_skipped_count_and_only_fixture_repositories(tmp_path, monkeypatch):
    (tmp_path / "samples").mkdir()
    (tmp_path / "samples" / "demo.py").write_text("DEBUG = True\n")
    monkeypatch.setattr(main, "load_repo", lambda _url: tmp_path)
    monkeypatch.setattr(main, "load_stats", lambda: {**main.DEFAULT_STATS, "stats_backend": "local"})
    client = TestClient(main.app)

    response = client.post("/scan", json={"repo_url": "https://github.com/example/repo"})
    assert response.status_code == 200
    data = response.json()
    assert data["findings"] == []
    assert data["skipped_files"] == 1
    assert "All 1 scannable files were excluded" in data["summary_report"]

