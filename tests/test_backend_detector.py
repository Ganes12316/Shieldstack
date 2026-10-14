import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from app.scanner.backend_detector import normalize_path, extract_backend_routes, cross_reference

def _write_temp(content: str, suffix: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)

# --- normalize_path ---
def test_normalize_express_param():
    assert normalize_path("/api/users/:id") == "/api/users/<param>"

def test_normalize_fastapi_param():
    assert normalize_path("/api/users/{id}") == "/api/users/<param>"

def test_normalize_js_template_literal_param():
    assert normalize_path("/api/users/${id}") == "/api/users/<param>"

def test_normalize_strips_trailing_slash():
    assert normalize_path("/api/users/") == "/api/users"

# --- extract_backend_routes: unguarded route detected ---
def test_extracts_unguarded_fastapi_route():
    code = '''
@app.delete("/api/users/{id}")
def delete_user(id: int):
    db.delete_user(id)
'''
    path = _write_temp(code, ".py")
    routes = extract_backend_routes(path)
    assert len(routes) == 1
    assert routes[0]["has_auth_guard"] is False

# --- extract_backend_routes: guarded route (underscore-normalized match) ---
def test_extracts_guarded_route_with_underscore_decorator():
    code = '''
@app.delete("/api/users/{id}")
@require_auth
def delete_user(id: int):
    db.delete_user(id)
'''
    path = _write_temp(code, ".py")
    routes = extract_backend_routes(path)
    assert len(routes) == 1
    assert routes[0]["has_auth_guard"] is True

# --- cross_reference: proves unauthenticated route reachable from frontend ---
def test_cross_reference_flags_unguarded_matched_route():
    frontend_calls = [{"method": "DELETE", "path": "/api/users/<param>", "line_no": 4, "file_path": "UserTools.jsx"}]
    backend_routes = [{"method": "DELETE", "path": "/api/users/<param>", "line_no": 1, "has_auth_guard": False, "file_path": "routes.py"}]
    findings = cross_reference(frontend_calls, backend_routes)
    assert len(findings) == 1
    assert findings[0].category == "unauthenticated_backend_route"

def test_cross_reference_ignores_guarded_route():
    frontend_calls = [{"method": "DELETE", "path": "/api/users/<param>", "line_no": 4, "file_path": "UserTools.jsx"}]
    backend_routes = [{"method": "DELETE", "path": "/api/users/<param>", "line_no": 1, "has_auth_guard": True, "file_path": "routes.py"}]
    findings = cross_reference(frontend_calls, backend_routes)
    assert len(findings) == 0

def test_cross_reference_ignores_unmatched_route():
    frontend_calls = [{"method": "DELETE", "path": "/api/orders/<param>", "line_no": 4, "file_path": "UserTools.jsx"}]
    backend_routes = [{"method": "DELETE", "path": "/api/users/<param>", "line_no": 1, "has_auth_guard": False, "file_path": "routes.py"}]
    findings = cross_reference(frontend_calls, backend_routes)
    assert len(findings) == 0
