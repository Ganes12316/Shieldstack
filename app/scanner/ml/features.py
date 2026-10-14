import re

CATEGORY_ENCODING = {
    "hardcoded_secret": 0, "open_cors": 1, "debug_mode_enabled": 2,
    "client_side_only_authorization": 3, "unauthenticated_backend_route": 4,
    "sql_injection": 5, "xss_unsanitized_render": 6,
}
SEVERITY_ENCODING = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

# Matches placeholder-looking VALUES (e.g. "your_api_key_here") — used against evidence strings only.
PLACEHOLDER_KEYWORDS = re.compile(r"(?i)(example|dummy|placeholder|fake|mock|changeme|xxx)")

# Matches genuine test-directory PATHS (e.g. tests/, __tests__/, spec/) — used against file paths only.
# Deliberately does NOT match "sample" since sample_vulnerable_app etc. are real test fixtures
# containing genuine vulnerabilities, not placeholder/test-only code.
TEST_PATH_PATTERN = re.compile(r"(?i)(^|[\\/])(tests?|__tests__|spec)([\\/]|$)")

FEATURE_ORDER = ["category", "severity", "base_confidence", "evidence_length",
                  "has_placeholder_keyword", "path_looks_like_test"]

def extract_features(finding) -> dict:
    sev = finding.severity.value if hasattr(finding.severity, "value") else finding.severity
    return {
        "category": CATEGORY_ENCODING.get(finding.category, -1),
        "severity": SEVERITY_ENCODING.get(sev, 0),
        "base_confidence": finding.confidence,
        "evidence_length": len(finding.evidence),
        "has_placeholder_keyword": 1 if PLACEHOLDER_KEYWORDS.search(finding.evidence) else 0,
        "path_looks_like_test": 1 if TEST_PATH_PATTERN.search(finding.file_path) else 0,
    }
