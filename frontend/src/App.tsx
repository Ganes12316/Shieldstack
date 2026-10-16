import { useState, useEffect, useRef } from "react";
import axios from "axios";
import { generateFixSnippet } from "./fixSnippets";
import "./App.css";
import TypewriterReveal from "./TypewriterReveal";
import { useScrollReveal } from "./useScrollReveal";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
const isLocalApi = /localhost|127\.0\.0\.1/.test(new URL(API_URL).hostname);

type Stats = {
  repos_tested: number;
  automated_tests: number;
  languages_supported: number;
  bugs_found: number;
  total_scans: number;
  stats_backend: "local" | "upstash";
};

type Finding = {
  category: string;
  file_path: string;
  line_number: number;
  evidence: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  confidence: number;
  description: string;
  recommended_fix: string;
};

type ScanResponse = {
  findings: Finding[];
  summary_report: string;
  total: number;
  critical_count: number;
  skipped_files: number;
  stats?: Stats;
};

type StatsAvailability = "loading" | "available" | "unavailable";

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: "#F87171",
  HIGH: "#FB923C",
  MEDIUM: "#FACC15",
  LOW: "#818CF8",
};

const CATEGORIES = [
  { icon: "🔑", title: "Hardcoded API Keys & Secrets", desc: "Detects unencrypted API tokens, private keys, and environment variables embedded in source code." },
  { icon: "🛡️", title: "Client-Side Auth Bypasses", desc: "Identifies UI-only authorization traps that expose backend REST endpoints to unauthorized access." },
  { icon: "💉", title: "SQL & Command Injections", desc: "Flags unsanitized dynamic query strings and raw database execution in Python, JS, PHP, and Go." },
  { icon: "⚡", title: "DOM-Based XSS Vulnerabilities", desc: "Highlights unsanitized user inputs directly rendered into DOM templates or reactive state." },
];

const FAQS = [
  {
    q: "What programming languages and frameworks does ShieldStack scan?",
    a: "Deep semantic detectors (authorization traps, SQL dynamic queries, XSS rendering) cover Python, JavaScript, TypeScript, and PHP. Hardcoded secret and credential scanners operate across Python, JS/TS, Vue, HTML, Java, Go, Ruby, PHP, C#, plus YAML, JSON, and ENV configuration files.",
  },
  {
    q: "Is ShieldStack completely free and private to run?",
    a: "Repository scans run on the hosted ShieldStack backend. When Gemini is configured, finding details are sent to Google's Gemini API to write the summary; otherwise ShieldStack uses a local fallback summary.",
  },
  {
    q: "How does ShieldStack differ from conventional AST security tools?",
    a: "ShieldStack is specifically optimized for AI codegen (Cursor, Claude, Copilot, ChatGPT). Instead of generating hundreds of bloated enterprise false-positives, it pinpoints the exact high-risk architectural anti-patterns AI models produce.",
  },
  {
    q: "Does running ShieldStack replace manual code reviews or penetration tests?",
    a: "No static linter replaces human security architecture or dynamic pentesting. ShieldStack serves as your automated first line of defense to catch critical vulnerabilities during development before code reaches staging or production.",
  },
  {
    q: "Can I scan private repositories and local projects?",
    a: "The hosted scanner accepts public GitHub repository URLs. Local folder scanning is disabled on the public server and can be enabled only for trusted local development.",
  },
  {
    q: "How rigorously has ShieldStack been validated?",
    a: "ShieldStack's detection rules are validated against real-world applications and benchmark suites (including OWASP NodeGoat and vulnerable microservices) across Node.js, Python, PHP, and Java.",
  },
];

export default function App() {
  const [path, setPath] = useState("");
  const [includeFixtures, setIncludeFixtures] = useState(false);
  const [loading, setLoading] = useState(false);
  const [serverWaking, setServerWaking] = useState(false);
  const [result, setResult] = useState<ScanResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  const [feedbackOpen, setFeedbackOpen] = useState(false);
  const [feedbackMsg, setFeedbackMsg] = useState("");
  const [feedbackSent, setFeedbackSent] = useState(false);
  const [feedbackSending, setFeedbackSending] = useState(false);
  const [feedbackError, setFeedbackError] = useState<string | null>(null);
  const featuresReveal = useScrollReveal<HTMLElement>();
  const vibeReveal = useScrollReveal<HTMLElement>();
  const speaksReveal = useScrollReveal<HTMLElement>();
  const stepsReveal = useScrollReveal<HTMLElement>();
  const fixDemoReveal = useScrollReveal<HTMLElement>();
  const ctaSectionReveal = useScrollReveal<HTMLElement>();
  const faqReveal = useScrollReveal<HTMLElement>();

  const [openFaq, setOpenFaq] = useState<number | null>(null);

  // Free Scan Popup Banner on Scroll
  const [showScanPopup, setShowScanPopup] = useState(false);
  const [popupDismissed, setPopupDismissed] = useState(() => {
    return sessionStorage.getItem("shieldstack_popup_dismissed") === "true";
  });

  useEffect(() => {
    const handleScroll = () => {
      if (window.scrollY > 450 && !popupDismissed) {
        setShowScanPopup(true);
      }
    };
    window.addEventListener("scroll", handleScroll);
    return () => window.removeEventListener("scroll", handleScroll);
  }, [popupDismissed]);

  const dismissPopup = () => {
    setShowScanPopup(false);
    setPopupDismissed(true);
    sessionStorage.setItem("shieldstack_popup_dismissed", "true");
  };

  const scrollToScanAndFocus = () => {
    const scanEl = document.getElementById("scan");
    if (scanEl) {
      scanEl.scrollIntoView({ behavior: "smooth" });
      const input = scanEl.querySelector("input");
      if (input) input.focus();
    }
    dismissPopup();
  };

  const [stats, setStats] = useState<Stats>({
    repos_tested: 0,
    automated_tests: 51,
    languages_supported: 4,
    bugs_found: 0,
    total_scans: 0,
    stats_backend: "local",
  });
  const [statsAvailability, setStatsAvailability] = useState<StatsAvailability>("loading");
  const statsRequestInFlight = useRef(false);
  const lastBackendResponseAt = useRef(0);

  const updateStats = (incoming: Stats, completedScanFindings?: number) => {
    if (completedScanFindings === undefined) {
      setStats(incoming);
      return;
    }

    setStats((current) => {
      return {
        ...incoming,
        repos_tested: Math.max(incoming.repos_tested, current.repos_tested + 1),
        bugs_found: Math.max(incoming.bugs_found, current.bugs_found + completedScanFindings),
        total_scans: Math.max(
          incoming.total_scans,
          current.total_scans + 1,
        ),
      };
    });
  };

  const fetchStats = async () => {
    if (statsRequestInFlight.current) return;
    statsRequestInFlight.current = true;
    try {
      const res = await axios.get<Stats>(`${API_URL}/stats`);
      lastBackendResponseAt.current = Date.now();
      if (res.data) {
        updateStats(res.data);
        setStatsAvailability("available");
      }
    } catch {
      setStatsAvailability("unavailable");
    } finally {
      statsRequestInFlight.current = false;
    }
  };

  useEffect(() => {
    let statsTimer: number | undefined;
    let lastActivityAt = Date.now();
    const startPolling = () => {
      if (statsTimer === undefined && !document.hidden) {
        statsTimer = window.setInterval(() => {
          if (Date.now() - lastActivityAt > 2 * 60_000) {
            stopPolling();
            return;
          }
          fetchStats();
        }, 30_000);
      }
    };
    const stopPolling = () => {
      if (statsTimer !== undefined) {
        window.clearInterval(statsTimer);
        statsTimer = undefined;
      }
    };
    const handleVisibility = () => {
      if (document.hidden) {
        stopPolling();
      } else {
        lastActivityAt = Date.now();
        fetchStats();
        startPolling();
      }
    };
    const handleActivity = () => {
      lastActivityAt = Date.now();
      startPolling();
    };

    fetchStats();
    startPolling();
    document.addEventListener("visibilitychange", handleVisibility);
    document.addEventListener("pointerdown", handleActivity, { passive: true });
    document.addEventListener("keydown", handleActivity);
    document.addEventListener("touchstart", handleActivity, { passive: true });
    return () => {
      stopPolling();
      document.removeEventListener("visibilitychange", handleVisibility);
      document.removeEventListener("pointerdown", handleActivity);
      document.removeEventListener("keydown", handleActivity);
      document.removeEventListener("touchstart", handleActivity);
    };
  }, []);

  const runScan = async () => {
    if (!path.trim()) return;
    if (!isLocalApi && !path.trim().startsWith("https://github.com/")) {
      setError("Enter a public HTTPS GitHub repository URL.");
      return;
    }
    setLoading(true);
    setServerWaking(false);
    setError(null);
    setResult(null);
    // Scroll to results area immediately so user sees the loading animation
    setTimeout(() => {
      const resultsEl = document.getElementById("results-panel");
      if (resultsEl) resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
    }, 100);
    try {
      const trimmed = path.trim();
      const isUrl = trimmed.startsWith("https://github.com/");
      if (Date.now() - lastBackendResponseAt.current > 60_000) {
        setServerWaking(true);
        try {
          await axios.get(`${API_URL}/health`, { timeout: 90_000 });
          lastBackendResponseAt.current = Date.now();
        } catch {
          // A failed health probe should not prevent the scan attempt.
        }
      }
      setServerWaking(false);
      const scanRequest = () => axios.post<ScanResponse>(`${API_URL}/scan`, {
        ...(isUrl ? { repo_url: trimmed } : { local_path: trimmed }),
        include_fixtures: includeFixtures,
      }, { timeout: 120_000 });
      let res;
      try {
        res = await scanRequest();
      } catch (firstError: any) {
        if (firstError?.response || !axios.isAxiosError(firstError) || firstError.code === "ERR_CANCELED") {
          throw firstError;
        }
        await new Promise((resolve) => setTimeout(resolve, 5000));
        res = await scanRequest();
      }
      lastBackendResponseAt.current = Date.now();
      setResult(res.data);
      if (res.data.stats) {
        updateStats(res.data.stats, res.data.findings.length);
        setStatsAvailability("available");
      } else {
        fetchStats();
      }
      // Scroll to results after data arrives
      setTimeout(() => {
        const resultsEl = document.getElementById("results-panel");
        if (resultsEl) resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
    } catch (e: any) {
      if (e?.response?.status === 429) {
        setError("⏱️ Too many scans — you've hit the rate limit. Please wait a minute and try again.");
      } else {
        const detail = e?.response?.data?.detail;
        setError(detail || "The server may be waking up. Please try again in a moment.");
      }
      setTimeout(() => {
        const resultsEl = document.getElementById("results-panel");
        if (resultsEl) resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });
      }, 150);
    } finally {
      setServerWaking(false);
      setLoading(false);
    }
  };

  const submitFeedback = async () => {
    if (!feedbackMsg.trim() || feedbackSending) return;
    setFeedbackSending(true);
    setFeedbackError(null);
    try {
      await axios.post(`${API_URL}/feedback`, { message: feedbackMsg.trim() });
      setFeedbackSent(true);
      setFeedbackMsg("");
      setTimeout(() => {
        setFeedbackSent(false);
        setFeedbackOpen(false);
      }, 2000);
    } catch {
      setFeedbackError("Couldn't send feedback — is the backend running?");
    } finally {
      setFeedbackSending(false);
    }
  };

  const severityCounts = result?.findings.reduce<Record<string, number>>((counts, finding) => {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    return counts;
  }, {}) ?? {};

  return (
    <div className="app">
      <div className="orb-field">
        <div className="orb orb-1" />
        <div className="orb orb-2" />
      </div>

      <header className="site-header">
        <nav className="navbar">
          <div className="nav-brand-pill">
            <img src="/shieldstack-logo.png" alt="ShieldStack" className="nav-logo" />
            <span className="brand-name">ShieldStack</span>
          </div>

          <div className="nav-links">
            <a href="#features">Features</a>
            <a href="#how-it-works">How it works</a>
            <a href="#scan">Scan</a>
            <a href="#faq">FAQ</a>
            <a href="https://github.com/Ganes12316" target="_blank" rel="noreferrer">GitHub</a>
          </div>

          <a href="#scan" className="nav-cta">Start scanning</a>
        </nav>
      </header>

      <section className="hero">
        <div className="hero-content">
          <div className="hero-badge">
            <img src="/shieldstack-logo.png" alt="Logo" className="badge-mini-logo" />
            <span>🛡️ Open-Source Security Engine · Hosted Repository Scanning</span>
          </div>
          <h1>Autonomous Security Guardrails<br />For AI-Generated Codebases</h1>
          <TypewriterReveal
            as="p"
            className="tagline"
            text="Purpose-built static linting engineered for AI-generated applications. Intercept secret leaks, bypassable authorization logic, and injection flaws with zero setup."
          />

          <div className="live-pill">
            <span className="pulse-dot"></span> Live Security Telemetry
          </div>

          <div className="stats-row">
            <div className="stat-chip">
              <div className="num">{statsAvailability === "available" ? stats.repos_tested : statsAvailability === "loading" ? "Loading" : "Unavailable"}</div>
              <div className="label">Repos Audited</div>
            </div>
            <div className="stat-chip">
              <div className="num">{statsAvailability === "available" ? stats.bugs_found : statsAvailability === "loading" ? "Loading" : "Unavailable"}</div>
              <div className="label">Potential Findings</div>
            </div>
            <div className="stat-chip">
              <div className="num">51</div>
              <div className="label">Tests</div>
            </div>
            <div className="stat-chip">
              <div className="num">{stats.languages_supported}</div>
              <div className="label">Languages</div>
            </div>
            <label className="fixture-option">
              <input
                type="checkbox"
                checked={includeFixtures}
                onChange={(event) => setIncludeFixtures(event.target.checked)}
              />
              Include test and sample code
            </label>
          </div>

          <div className="hero-checklist-row">
            <div className="check-item">4 detection categories</div>
            <div className="check-item"><span className="check-icon">🔒</span> Zero-Trust Static Analysis</div>
            <div className="check-item"><span className="check-icon">⚡</span> Automated Remediation Code</div>
          </div>

          <div className="scan-input-wrapper" id="scan">
            <div className="scan-section-label">
              <span className="scan-section-icon">🔍</span>
              <span>Repository security scan</span>
            </div>
            <label className="scan-field-label" htmlFor="scan-target">GitHub repository URL{isLocalApi ? " or local project folder" : ""}</label>
            <div className="scan-input">
              <input
                id="scan-target"
                className="scan-path-input"
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder={isLocalApi ? "GitHub URL or absolute local folder path" : "https://github.com/owner/repository"}
                autoComplete="off"
                aria-describedby="scan-privacy-note"
                style={{ colorScheme: "dark", backgroundColor: "#111113", color: "#fafafa" }}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
              />
              <button onClick={runScan} disabled={loading}>
                {loading ? "Scanning…" : "Scan repository"}
              </button>
            </div>
            <p className="scan-privacy-note" id="scan-privacy-note">
              Repositories are downloaded temporarily by the hosted backend and deleted after scanning. Finding details are sent to Google Gemini to write the summary when Gemini is configured.
            </p>
          </div>
        </div>
      </section>

      {/* --- Results Panel: immediately below hero --- */}
      {(loading || error || result) && (
        <section
          id="results-panel"
          className="results-section"
          aria-live="polite"
        >
          <div className="results-panel">
            {loading && (
              <div className="scan-animation">
                <div className="scan-line" />
                <p>Scanning for vulnerability patterns...</p>
                {serverWaking && <p>Waking up the server, this can take up to a minute...</p>}
              </div>
            )}

            {error && <div className="error-banner">{error}</div>}

            {result && !loading && (
              <>
                <div className="results-heading">
                  <div>
                    <p className="results-eyebrow">Scan complete</p>
                    <h2>Security findings</h2>
                  </div>
                  <span className="results-total">{result.total} {result.total === 1 ? "finding" : "findings"}</span>
                </div>
                <div className="summary-bar">
                  {(["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const).map((severity) => (
                    <div className={`stat severity-stat ${severity.toLowerCase()}`} key={severity}>
                      <span className="stat-number">{severityCounts[severity] || 0}</span>
                      <span className="stat-label">{severity}</span>
                    </div>
                  ))}
                </div>

                <div className="report-card">
                  <h2>Summary Report</h2>
                  <pre>{result.summary_report}</pre>
                </div>

                {result.skipped_files > 0 && result.total > 0 && (
                  <p className="skipped-files-note" role="status">
                    Skipped {result.skipped_files} test/sample files. Include them with the checkbox above.
                  </p>
                )}

                {result.findings.length === 0 ? (
                  <div className="no-findings" role="status">
                    <span className="no-findings-mark" aria-hidden="true">✓</span>
                    <div>
                      {result.summary_report.startsWith("All ") ? (
                        <>
                          <h3>Only test/sample files found</h3>
                          <p>{result.summary_report}</p>
                        </>
                      ) : (
                        <>
                          <h3>No findings detected</h3>
                          <p>The scanner did not identify issues in the checks it ran. This is not a substitute for a full security review.</p>
                        </>
                      )}
                    </div>
                  </div>
                ) : <div className="findings-list">
                  {result.findings.map((f, i) => (
                    <div
                      key={i}
                      className="finding-card"
                      style={{ borderLeftColor: SEVERITY_COLORS[f.severity] }}
                    >
                      <div className="finding-header">
                        <span className="severity-badge" style={{ backgroundColor: SEVERITY_COLORS[f.severity] }}>
                          {f.severity}
                        </span>
                        <span className="category">{f.category.replace(/_/g, " ")}</span>
                        <span className="confidence">{Math.round(f.confidence * 100)}%</span>
                      </div>
                      <p className="location">{f.file_path}:{f.line_number}</p>
                      <p className="evidence"><code>{f.evidence}</code></p>
                      <p className="description">{f.description}</p>
                      <p className="fix"><strong>Fix:</strong> {f.recommended_fix}</p>
                      {(() => {
                        const snippet = generateFixSnippet(f);
                        if (!snippet) return null;
                        return (
                          <div className="fix-comparison">
                            <div className="fix-col vulnerable">
                              <span className="fix-label">● VULNERABLE</span>
                              <code>{snippet.before}</code>
                            </div>
                            <div className="fix-col fixed">
                              <span className="fix-label">● FIXED PATTERN</span>
                              <code>{snippet.after}</code>
                            </div>
                          </div>
                        );
                      })()}
                    </div>
                  ))}
                </div>}
              </>
            )}
          </div>
        </section>
      )}

      {/* --- Live Telemetry Strip --- */}
      <div className="telemetry-strip">
        <div className="telemetry-inner">
          <div className="telemetry-item">
            <span className="telemetry-icon amber">⚠️</span>
            <span className="telemetry-val">{statsAvailability === "available" ? stats.bugs_found : statsAvailability === "loading" ? "Loading" : "Unavailable"}</span> {statsAvailability !== "available" ? "" : stats.stats_backend === "upstash" ? "total findings" : "potential findings since restart"}
          </div>
          <div className="telemetry-item">
            <span className="telemetry-icon cyan">🛡️</span>
            <span className="telemetry-val">{statsAvailability === "available" ? stats.repos_tested : statsAvailability === "loading" ? "Loading" : "Unavailable"}</span> {statsAvailability !== "available" ? "" : stats.stats_backend === "upstash" ? "total repositories scanned" : "repositories scanned since restart"}
          </div>
          <div className="telemetry-item">
            <span className="telemetry-icon green">⚡</span>
            <span className="telemetry-val">{statsAvailability === "available" ? stats.total_scans : statsAvailability === "loading" ? "Loading" : "Unavailable"}</span> {statsAvailability !== "available" ? "" : stats.stats_backend === "upstash" ? "total scans" : "successful scans since restart"}
          </div>
        </div>
      </div>

      {/* --- Section: Vibe coding is amazing. Until it's not. --- */}
      <section
        ref={vibeReveal.ref}
        className={`vibe-cards-section reveal ${vibeReveal.visible ? "visible" : ""}`}
      >
        <h2 className="vibe-heading">
          AI Codegen is Fast. <span className="dim">Who Audits the Logic?</span>
        </h2>
        <div className="vibe-cards-grid">
          <div className="vibe-card">
            <div className="vibe-icon-box red">⚠️</div>
            <h3>AI Hallucinates Security Flaws</h3>
            <p>LLMs write functional features rapidly, but routinely generate client-side auth traps, hardcoded credentials, and unsafe queries.</p>
          </div>
          <div className="vibe-card">
            <div className="vibe-icon-box red">⚡</div>
            <h3>Commercial Scanners are Bloated</h3>
            <p>Traditional SAST enterprise tools cost thousands per seat and overwhelm developers with hundreds of non-actionable false positives.</p>
          </div>
          <div className="vibe-card">
            <div className="vibe-icon-box red">🔒</div>
            <h3>Hosted Repository Verification</h3>
            <p>Run a static security scan on the hosted backend before pushing to production.</p>
          </div>
        </div>
      </section>

      {/* --- Section: Intelligent Guardrails for AI-Generated Code --- */}
      <section
        ref={speaksReveal.ref}
        className={`speaks-section reveal ${speaksReveal.visible ? "visible" : ""}`}
        id="features"
      >
        <h2 className="speaks-heading">
          Intelligent Guardrails for <span className="highlight-blue">AI-Generated Code</span>
        </h2>
        <p className="speaks-sub">Engineered to eliminate high-risk vulnerabilities introduced by AI code assistants</p>

        <div className="speaks-grid">
          <div className="speaks-card">
            <div className="speaks-icon-box">⚡</div>
            <h3>Instant Static Linting</h3>
            <p>High-performance parsing engine that inspects your repository for critical security vulnerabilities in seconds.</p>
          </div>
          <div className="speaks-card">
            <div className="speaks-icon-box">🧠</div>
            <h3>AI Anti-Pattern Detection</h3>
            <p>Precision rules targeting hardcoded secrets, client-side auth bypasses, and unsanitized query parameters.</p>
          </div>
          <div className="speaks-card">
            <div className="speaks-icon-box">📊</div>
            <h3>Prioritized Threat Diagnostics</h3>
            <p>Clear, evidence-backed security reports featuring exact line numbers, severity tiers, and confidence ratings.</p>
          </div>
          <div className="speaks-card">
            <div className="speaks-icon-box">🛠️</div>
            <h3>Framework Remediation</h3>
            <p>Production-ready replacement code snippets for React, Express, FastAPI, Next.js, and PHP.</p>
          </div>
        </div>
      </section>

      {/* --- Section: From Repository URL to Patched Code --- */}
      <section
        ref={stepsReveal.ref}
        className={`steps-section reveal ${stepsReveal.visible ? "visible" : ""}`}
        id="how-it-works"
      >
        <h2 className="steps-heading">
          From Source Repository to <span className="highlight-blue">Secured Code</span>
        </h2>

        <div className="steps-timeline">
          <div className="timeline-line"></div>
          <div className="step-node">
            <div className="step-circle">🔗</div>
            <span className="step-tag">STEP 1</span>
            <h3>Target Input</h3>
            <p>Enter a public GitHub repository URL for hosted scanning.</p>
          </div>
          <div className="step-node">
            <div className="step-circle">🔍</div>
            <span className="step-tag">STEP 2</span>
            <h3>Deep AST Parsing</h3>
            <p>Static engine executes token analysis and tracks unparameterized data flow</p>
          </div>
          <div className="step-node">
            <div className="step-circle">📄</div>
            <span className="step-tag">STEP 3</span>
            <h3>Threat Diagnostics</h3>
            <p>Examine categorized security findings with line-level code evidence</p>
          </div>
          <div className="step-node">
            <div className="step-circle">🚀</div>
            <span className="step-tag">STEP 4</span>
            <h3>Apply Fix &amp; Ship</h3>
            <p>Copy framework-tailored patches and deploy with full confidence</p>
          </div>
        </div>
      </section>

      {/* --- Section: See the Fix in Action --- */}
      <section
        ref={fixDemoReveal.ref}
        className={`action-fix-section reveal ${fixDemoReveal.visible ? "visible" : ""}`}
      >
        <div className="action-fix-card">
          <h2>See the Fix in Action</h2>
          <p className="action-fix-sub">
            ShieldStack transforms detected vulnerabilities into verified, copy-pasteable production code fixes.
          </p>

          <div className="action-fix-demo-grid">
            <div className="fix-box vulnerable-box">
              <div className="box-header vuln-label">● VULNERABLE</div>
              <pre className="code-content">
                <code>{`// Exposed API key in client
const supabase = createClient(
  process.env.SUPABASE_URL,
  "sb-xxx-secret-key"
);`}</code>
              </pre>
            </div>

            <div className="fix-arrow-connector">
              <span className="arrow-icon">➔</span>
              <span className="connector-brand">ShieldStack</span>
              <span className="arrow-icon">➔</span>
            </div>

            <div className="fix-box fixed-box">
              <div className="box-header fix-label">● FIXED</div>
              <pre className="code-content">
                <code>{`// Use anon key (safe for client)
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_ANON_KEY
);`}</code>
              </pre>
            </div>
          </div>
        </div>
      </section>

      {/* --- What it actually catches section --- */}
      <section
        ref={featuresReveal.ref}
        className={`feature-section reveal ${featuresReveal.visible ? "visible" : ""}`}
      >
        <h2>What it actually catches</h2>
        <p className="sub">Four categories, built and tested against real AI-generated and real-world code.</p>
        <div className="empty-state">
          {CATEGORIES.map((c, i) => (
            <div className="empty-card" key={i}>
              <div className="icon">{c.icon}</div>
              <h3>{c.title}</h3>
              <p>{c.desc}</p>
            </div>
          ))}
        </div>
      </section>



      <section
        ref={faqReveal.ref}
        className={`faq-section reveal ${faqReveal.visible ? "visible" : ""}`}
        id="faq"
      >
        <h2>Frequently Asked <span className="accent">Questions</span></h2>
        <div className="faq-list">
          {FAQS.map((item, i) => (
            <div key={i} className={`faq-item ${openFaq === i ? "open" : ""}`}>
              <button
                className="faq-question"
                onClick={() => setOpenFaq(openFaq === i ? null : i)}
                aria-expanded={openFaq === i}
              >
                {item.q}
                <span className="faq-chevron">⌄</span>
              </button>
              {openFaq === i && <p className="faq-answer">{item.a}</p>}
            </div>
          ))}
        </div>
      </section>

      {/* --- Section: Ready to ship with confidence? --- */}
      <section
        ref={ctaSectionReveal.ref}
        className={`cta-bottom-section reveal ${ctaSectionReveal.visible ? "visible" : ""}`}
      >
        <div className="cta-bottom-card">
          <div className="cta-shield-badge">🛡️</div>
          <h2>
            Fortify Your Codebase in <span className="highlight-blue">Seconds</span>
          </h2>
          <p className="cta-sub">
            Join developers worldwide using ShieldStack to keep their applications secure and production-ready.
          </p>

          <button className="cta-primary-btn" onClick={scrollToScanAndFocus}>
            Launch Deep Scan ➔
          </button>

          <div className="cta-guarantees-row">
            <span>🛡️ Repository source deleted after scan</span>
            <span>🔒 Finding details sent to Gemini when configured</span>
            <span>⚡ Millisecond Rule Execution</span>
            <span>✨ Open-Source &amp; Always Free</span>
          </div>
        </div>
      </section>

      <footer className="footer">
        <div className="footer-left-col">
          <div className="footer-brand-logo">
            <img src="/shieldstack-logo.png" alt="ShieldStack" className="nav-logo" />
            <span className="brand-name">ShieldStack</span>
          </div>
          <p className="footer-tagline">Next-generation static security linting for AI-assisted engineering teams.</p>
          <div className="footer-social-icons">
            <a href="https://github.com/Ganes12316" target="_blank" rel="noreferrer" className="social-btn" aria-label="ShieldStack on GitHub">
              <svg className="social-github-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false">
                <path fill="currentColor" d="M12 .9a11.1 11.1 0 0 0-3.51 21.63c.55.1.76-.24.76-.53v-2.08c-3.1.67-3.76-1.32-3.76-1.32-.5-1.28-1.24-1.62-1.24-1.62-1.01-.69.08-.68.08-.68 1.12.08 1.71 1.15 1.71 1.15.99 1.7 2.6 1.21 3.23.93.1-.72.39-1.21.7-1.49-2.48-.28-5.09-1.24-5.09-5.52 0-1.22.44-2.21 1.15-2.99-.12-.28-.5-1.42.11-2.95 0 0 .94-.3 3.05 1.14a10.6 10.6 0 0 1 5.55 0c2.12-1.44 3.05-1.14 3.05-1.14.61 1.53.23 2.67.11 2.95.72.78 1.15 1.77 1.15 2.99 0 4.29-2.61 5.23-5.1 5.51.4.35.75 1.02.75 2.06V22c0 .29.2.63.77.52A11.1 11.1 0 0 0 12 .9Z" />
              </svg>
              𝕏
            </a>
          </div>
        </div>

        <div className="footer-links">
          <div className="footer-col">
            <h4>Product</h4>
            <a href="#features">Features</a>
            <a href="#how-it-works">How it works</a>
          </div>
        </div>
      </footer>

      {/* --- Scroll-triggered Free Scan Popup --- */}
      {showScanPopup && (
        <div className="scroll-scan-popup">
          <button className="popup-close-btn" onClick={dismissPopup} aria-label="Close popup">
            ✕
          </button>
          <div className="popup-badge">⚡ Hosted Public Repository Scan</div>
          <h3>Scan Your Project Now</h3>
          <p>Scan a public GitHub repository through the hosted service. Source files are temporary; finding details go to Gemini when configured.</p>
          <div className="popup-actions">
            <button className="popup-scan-btn" onClick={scrollToScanAndFocus}>
              Launch Free Scan ➔
            </button>
            <button className="popup-dismiss-btn" onClick={dismissPopup}>
              Maybe later
            </button>
          </div>
        </div>
      )}

      <div className="feedback-widget">
        {!feedbackOpen && (
          <button className="feedback-fab" onClick={() => setFeedbackOpen(true)}>
            💬 Feedback
          </button>
        )}
        {feedbackOpen && (
          <div className="feedback-panel">
            {feedbackSent ? (
              <p className="feedback-thanks">Thanks — got it! 🙌</p>
            ) : (
              <>
                <div className="feedback-header">
                  <span>Send feedback</span>
                  <button
                    className="feedback-close"
                    onClick={() => setFeedbackOpen(false)}
                    aria-label="Close feedback"
                  >
                    ✕
                  </button>
                </div>
                <textarea
                  value={feedbackMsg}
                  onChange={(e) => setFeedbackMsg(e.target.value)}
                  placeholder="Bug, feature idea, anything..."
                  rows={4}
                  maxLength={2000}
                />
                {feedbackError && <p className="feedback-error">{feedbackError}</p>}
                <button
                  className="feedback-submit"
                  onClick={submitFeedback}
                  disabled={feedbackSending || !feedbackMsg.trim()}
                >
                  {feedbackSending ? "Sending..." : "Send"}
                </button>
              </>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
