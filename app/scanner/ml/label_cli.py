import click
from pathlib import Path
from app.scanner.secrets_detector import scan_directory
from app.scanner.auth_detector import scan_file_for_client_only_auth
from app.scanner.injection_detector import detect_sql_injection, detect_xss
from app.scanner.backend_detector import extract_backend_routes, extract_frontend_calls, cross_reference
from app.scanner.ml.dataset import append_labeled_finding

def show_context(file_path: str, line_number: int, window: int = 3):
    try:
        lines = Path(file_path).read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return
    start = max(0, line_number - 1 - window)
    end = min(len(lines), line_number + window)
    print("  --- context ---")
    for i in range(start, end):
        marker = ">>" if i == line_number - 1 else "  "
        print(f"  {marker} {i+1}: {lines[i]}")
    print("  ---------------")

@click.command()
@click.option("--path", required=True)
def label(path):
    root = Path(path)
    findings = scan_directory(root)
    backend_routes, frontend_calls = [], []
    for p in root.rglob("*"):
        if p.is_file():
            if p.suffix in (".js", ".jsx", ".ts", ".tsx"):
                findings.extend(scan_file_for_client_only_auth(p))
                backend_routes.extend(extract_backend_routes(p))
                frontend_calls.extend(extract_frontend_calls(p))
            if p.suffix == ".py":
                backend_routes.extend(extract_backend_routes(p))
            findings.extend(detect_sql_injection(p))
            findings.extend(detect_xss(p))
    findings.extend(cross_reference(frontend_calls, backend_routes))

    for f in findings:
        print(f"\n[{f.severity.value}] {f.category} — {f.file_path}:{f.line_number}")
        print(f"  Description: {f.description}")
        show_context(f.file_path, f.line_number)
        ans = input("  Real vulnerability, given the actual code above? (y/n/skip): ").strip().lower()
        if ans == "y":
            append_labeled_finding(f, label=1)
        elif ans == "n":
            append_labeled_finding(f, label=0)

if __name__ == "__main__":
    label()