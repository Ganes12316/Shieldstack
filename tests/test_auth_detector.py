import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from app.scanner.auth_detector import scan_file_for_client_only_auth

def _write_temp(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".jsx", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)

def test_detects_client_side_only_delete():
    code = '''
function UserTools({ user }) {
  const handleDelete = (id) => {
    if (user.isAuthorized) {
      fetch(`/api/users/${id}`, { method: "DELETE" });
    }
  };
}
'''
    path = _write_temp(code)
    findings = scan_file_for_client_only_auth(path)
    assert len(findings) == 1
    assert findings[0].category == "client_side_only_authorization"
    assert findings[0].confidence == 0.75  # capped, per design

def test_ignores_get_requests():
    code = '''
function List({ user }) {
  const load = () => {
    if (user.isAuthorized) {
      fetch(`/api/users`, { method: "GET" });
    }
  };
}
'''
    path = _write_temp(code)
    findings = scan_file_for_client_only_auth(path)
    assert len(findings) == 0

def test_ignores_delete_without_auth_wrapper():
    # No client-side-only-auth issue detectable from this file alone —
    # this is a different category (backend_detector's job), not this detector's.
    code = '''
function UserTools() {
  const handleDelete = (id) => {
    fetch(`/api/users/${id}`, { method: "DELETE" });
  };
}
'''
    path = _write_temp(code)
    findings = scan_file_for_client_only_auth(path)
    assert len(findings) == 0

def test_ignores_non_jsx_files():
    path = _write_temp("not real code")
    path = path.rename(path.with_suffix(".txt"))
    findings = scan_file_for_client_only_auth(path)
    assert findings == []
