import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from app.scanner.secrets_detector import scan_file, shannon_entropy, redact
import tempfile

def _write_temp(content: str) -> Path:
    f = tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False, encoding="utf-8")
    f.write(content)
    f.close()
    return Path(f.name)

def test_detects_hardcoded_api_key():
    path = _write_temp('API_KEY = "ZX9pQ2Lm7Vr4Nk8t"\n')
    findings = scan_file(path)
    assert any(f.category == "hardcoded_secret" for f in findings)

def test_ignores_low_entropy_placeholder():
    path = _write_temp('API_KEY = "your_api_key_here"\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_detects_debug_mode():
    path = _write_temp('DEBUG = True\n')
    findings = scan_file(path)
    assert any(f.category == "debug_mode_enabled" for f in findings)

def test_ignores_debug_false():
    path = _write_temp('DEBUG = False\n')
    findings = scan_file(path)
    assert not any(f.category == "debug_mode_enabled" for f in findings)

def test_shannon_entropy_high_for_random_string():
    assert shannon_entropy("4eC39HqLyjWDarjtT1zdp7dc") > 3.5

def test_shannon_entropy_low_for_repeated_chars():
    assert shannon_entropy("aaaaaaaaaa") < 1.0

def test_redact_short_string():
    assert redact("abc") == "***"

def test_redact_long_string_keeps_prefix_suffix():
    result = redact("ZX9pQ2Lm7Vr4Nk8t")
    assert result.startswith("ZX9p")
    assert result.endswith("Nk8t")
    assert "*" in result
# --- Regression tests for false positives found via real-repo testing ---

def test_ignores_commented_out_secret():
    path = _write_temp('// API_KEY = "ZX9pQ2Lm7Vr4Nk8t"\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_ignores_hash_commented_secret():
    path = _write_temp('# password = "reallyLongSecretValue123"\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_ignores_php_variable_interpolation():
    path = _write_temp('$sql = "SELECT * FROM users WHERE password = \'$password\'";\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_ignores_python_fstring_interpolation():
    path = _write_temp('query = f"SELECT * FROM users WHERE password = \'{password}\'"\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_ignores_js_template_literal_interpolation():
    path = _write_temp('const query = `SELECT * FROM users WHERE password = \'${password}\'`;\n')
    findings = scan_file(path)
    assert not any(f.category == "hardcoded_secret" for f in findings)

def test_still_detects_real_literal_password():
    # Regression guard: the variable-reference fix should NOT swallow real hardcoded secrets
    path = _write_temp('password = "actualHardcodedValue987"\n')
    findings = scan_file(path)
    assert any(f.category == "hardcoded_secret" for f in findings)
