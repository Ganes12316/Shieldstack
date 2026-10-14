type Finding = {
  category: string;
  evidence: string;
  file_path: string;
};

export function generateFixSnippet(finding: Finding): { before: string; after: string } | null {
  const ev = finding.evidence.trim();

  switch (finding.category) {
    case "hardcoded_secret": {
      // Extract a plausible variable name if present (e.g. "API_KEY = ...")
      const varMatch = ev.match(/([A-Za-z_][A-Za-z0-9_]*)\s*[:=]/);
      const varName = varMatch ? varMatch[1] : "API_KEY";
      return {
        before: ev,
        after: `${varName} = os.environ.get("${varName}")  # loaded from .env, never committed`,
      };
    }
    case "sql_injection": {
      return {
        before: ev,
        after: ev.includes("query(")
          ? `db.query("SELECT * FROM users WHERE id = ?", [id], callback)  // parameterized`
          : `cursor.execute("SELECT * FROM users WHERE id = %s", (id,))  // parameterized`,
      };
    }
    case "xss_unsanitized_render": {
      return {
        before: ev,
        after: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(bio) }} />  // sanitized`,
      };
    }
    case "client_side_only_authorization":
    case "unauthenticated_backend_route": {
      return {
        before: ev,
        after: `@app.delete("/api/users/{id}", dependencies=[Depends(require_auth)])  // server-side check added`,
      };
    }
    case "debug_mode_enabled": {
      return {
        before: ev,
        after: `DEBUG = os.environ.get("DEBUG", "False") == "True"  // defaults safely off`,
      };
    }
    default:
      return null;
  }
}
