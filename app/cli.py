import click
from pathlib import Path
from app.scanner.repo_loader import load_repo, RepoLoadError
from app.scanner.secrets_detector import scan_directory, get_scanned_file_count
from app.scanner.auth_detector import scan_file_for_client_only_auth
from app.scanner.injection_detector import detect_sql_injection, detect_xss
from app.scanner.report_generator import generate_report
from app.scanner.secrets_detector import scan_directory, get_scanned_file_count
from app.scanner.backend_detector import (
    extract_backend_routes,
    extract_frontend_calls,
    cross_reference,
)
from app.scanner.ml.predict import refine_confidence
from app.scanner.reachability_checker import check_route_reachability
import warnings
warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

SKIP_DIRS = {"node_modules", ".git", "venv", "__pycache__", "dist", "build", "vendor"}

def _should_skip(p: Path) -> bool:
    if any(part in SKIP_DIRS for part in p.parts):
        return True
    if p.name.endswith(".min.js"):
        return True
    return False


@click.command()
@click.option("--repo", help="GitHub repo URL to clone and scan")
@click.option("--path", help="Local directory to scan instead of cloning")
@click.option("--verify-live", help="Base URL of a RUNNING LOCAL instance (localhost only) to check route reachability against, e.g. http://localhost:8000")
def main(repo, path, verify_live):
    target = None

    if repo:
        click.echo(f"Cloning {repo}...")
        try:
            target = load_repo(repo)
        except RepoLoadError as e:
            click.echo(f"\n❌ Couldn't scan this repository.\n\n{e}\n")
            return
    elif path:
        target = Path(path)
        if not target.exists():
            click.echo(
                f"\n❌ Couldn't find the folder '{path}'.\n"
                "  Check the path is correct and that you're running this command "
                "from the right directory.\n"
            )
            return
        if not target.is_dir():
            click.echo(f"\n❌ '{path}' exists but isn't a folder — point --path at a directory.\n")
            return
    else:
        click.echo("Provide --repo <url> or --path <local dir>")
        return

    click.echo(f"Scanning {target}...")

    file_count = get_scanned_file_count(target)
    if file_count == 0:
        click.echo(
            "\n⚠️  No scannable files found.\n"
            "  Secrets/config scanning covers: Python, JS/TS/JSX, HTML, Java, Go, Ruby, PHP, C#, "
            "plus YAML/JSON/XML/properties config files.\n"
            "  Full detection (auth, injection, XSS) is currently Python/JS/TS/JSX only.\n"
        )
        return
    click.echo(f"  Found {file_count} file(s) to analyze.\n")

    try:
        # Phase 1: secrets + config
        findings = scan_directory(target)

        # Phase 2: client-side-only auth (AST)
        for p in target.rglob("*"):
            if p.is_file() and not _should_skip(p) and p.suffix in (".js", ".jsx", ".ts", ".tsx"):
                findings.extend(scan_file_for_client_only_auth(p))

        # Phase 3: backend route extraction + frontend/backend cross-reference
        backend_routes = []
        frontend_calls = []
        for p in target.rglob("*"):
            if p.is_file() and not _should_skip(p):
                if p.suffix == ".py":
                    backend_routes.extend(extract_backend_routes(p))
                if p.suffix in (".js", ".jsx", ".ts", ".tsx"):
                    backend_routes.extend(extract_backend_routes(p))
                    frontend_calls.extend(extract_frontend_calls(p))
        findings.extend(cross_reference(frontend_calls, backend_routes))

        # Phase 4: injection detection (SQLi + XSS)
        for p in target.rglob("*"):
            if p.is_file() and not _should_skip(p):
                findings.extend(detect_sql_injection(p))
                findings.extend(detect_xss(p))

        # Phase 5: ML-refined confidence (no-op until a model is trained)
        findings = [refine_confidence(f) for f in findings]

    except Exception as e:
        click.echo(
            f"\n❌ Something went wrong while scanning.\n"
            f"  {type(e).__name__}: {e}\n"
            "  This is likely a bug in ShieldStack rather than an issue with your code — "
            "worth reporting or checking the file that was being processed when this happened.\n"
        )
        return

    if not findings:
        click.echo("✅ No issues found.")
        return

    click.echo("\n" + "=" * 60)
    click.echo("SHIELDSTACK SUMMARY")
    click.echo("=" * 60)
    click.echo(generate_report(findings))
    click.echo("=" * 60 + "\n")

    for f in sorted(findings, key=lambda x: x.severity.value):
        click.echo(f"\n[{f.severity.value}] {f.category} — {f.file_path}:{f.line_number}")
        click.echo(f"  Evidence: {f.evidence}")
        click.echo(f"  Confidence: {f.confidence:.0%}")
        click.echo(f"  Fix: {f.recommended_fix}")

    # Phase 9: optional live reachability check (localhost only)
    if verify_live:
        click.echo(f"\nVerifying live reachability against {verify_live}...")
        for f in findings:
            if f.category == "unauthenticated_backend_route":
                route_part = f.evidence.split(" — ")[0]
                method, path_part = route_part.split(" ", 1)
                result = check_route_reachability(verify_live, path_part, method)
                if result["checked"]:
                    click.echo(f"  [{f.file_path}:{f.line_number}] {result['verdict']} (HTTP {result['status_code']})")
                else:
                    click.echo(f"  [{f.file_path}:{f.line_number}] Skipped: {result['reason']}")


if __name__ == "__main__":
    main()