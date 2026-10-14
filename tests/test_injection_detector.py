import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import tempfile
from app.scanner.injection_detector import detect_sql_injection, detect_xss

def _write_temp(content: str, suffix: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)

# --- SQL injection: direct case ---
def test_detects_direct_sql_injection():
    code = '''
def search(name: str):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    assert len(findings) == 1
    assert findings[0].category == "sql_injection"

# --- SQL injection: FastAPI typed parameter as taint source ---
def test_detects_typed_parameter_taint_source():
    code = '''
def search_users(name: str):
    query = f"SELECT * FROM users LIKE '{name}'"
    cursor = conn.execute(query)
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    assert len(findings) == 1

# --- SQL injection: default-value typed parameter (Query(...)) ---
def test_detects_default_value_typed_parameter():
    code = '''
def search(name: str = Query(...)):
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    cursor.execute(query)
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    assert len(findings) == 1

# --- SQL injection: one-hop through a locally-defined function ---
def test_detects_one_hop_call_taint():
    code = '''
def search_users(name: str):
    return _run_search(name)

def _run_search(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    assert len(findings) == 1

# --- SQL injection: no duplicate findings ---
def test_no_duplicate_findings_for_standalone_function():
    code = '''
def search_users(name: str):
    return _run_search(name)

def _run_search(name):
    query = f"SELECT * FROM users WHERE name = '{name}'"
    db.execute(query)
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    lines = [f.line_number for f in findings]
    assert len(lines) == len(set(lines)), "duplicate findings on the same line"

# --- SQL injection: safe parameterized query is NOT flagged ---
def test_ignores_parameterized_query():
    code = '''
def delete_user(id: int):
    cursor.execute("DELETE FROM users WHERE id = ?", (id,))
'''
    path = _write_temp(code, ".py")
    findings = detect_sql_injection(path)
    assert len(findings) == 0

# --- XSS: direct dangerouslySetInnerHTML with tainted source ---
def test_detects_xss_with_tainted_source():
    code = '''
function Profile({ location }) {
  const bio = location.search;
  return <div dangerouslySetInnerHTML={{ __html: bio }} />;
}
'''
    path = _write_temp(code, ".jsx")
    findings = detect_xss(path)
    assert len(findings) == 1

# --- XSS: KNOWN LIMITATION — reassignment/sanitization after initial taint is not
# tracked (documented in README). This test locks in the CURRENT documented behavior
# so a silent regression is still caught, without falsely claiming the gap is fixed.
def test_reassignment_after_taint_is_not_yet_tracked():
    code = '''
function Notice(props) {
  let brandHtml = props.brandHtml;
  brandHtml = sanitizeHtml(brandHtml);
  return <div dangerouslySetInnerHTML={{ __html: brandHtml }} />;
}
'''
    path = _write_temp(code, ".jsx")
    findings = detect_xss(path)
    # Expected false positive — see README "Known limitations".
    assert len(findings) == 1

# --- Non-matching file types return no findings ---
def test_sql_injection_skips_non_python_files():
    path = _write_temp("SELECT * FROM users", ".txt")
    assert detect_sql_injection(path) == []

def test_xss_skips_non_js_files():
    path = _write_temp("dangerouslySetInnerHTML", ".py")
    assert detect_xss(path) == []

def test_detects_js_express_sql_injection():
    code = '''
router.post('/login', function(req, res) {
    const username = req.body.username;
    const password = req.body.password;
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    db.query(query, (err, results) => {});
});
'''
    path = _write_temp(code, ".js")
    findings = detect_sql_injection(path)
    assert len(findings) >= 1

def test_js_untyped_params_not_auto_tainted():
    # Regression guard: req/res themselves shouldn't be marked tainted just for
    # existing as parameters — only their .body/.query/.params accesses should be
    code = '''
router.get('/health', function(req, res) {
    res.send("ok");
});
'''
    path = _write_temp(code, ".js")
    findings = detect_sql_injection(path)
    assert len(findings) == 0