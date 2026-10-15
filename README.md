# ShieldStack

ShieldStack scans code repositories for common security issues, including exposed secrets, unsafe authentication patterns, and injection risks. The FastAPI API serves the React and Vite interface and can optionally use Gemini to summarize findings.

## Run locally

Requirements: Python 3.13 and Node.js/npm.

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.web.main:app --reload --port 8000
```

In another terminal:

```powershell
cd frontend
npm install
npm run dev
```

The frontend defaults to `http://localhost:8000`. Copy `.env.example` to `.env` and `frontend/.env.example` to `frontend/.env` to customize settings.

## Environment variables

| Variable | Where | Purpose |
| --- | --- | --- |
| `GEMINI_API_KEY` | Backend (optional) | Sends finding details to Google Gemini for the scan summary; a local summary is used when unset or unavailable. |
| `GEMINI_MODEL` | Backend (optional) | Primary Gemini model; defaults to `gemini-3.5-flash-lite`, with `gemini-3.8-flash` as fallback. |
| `FRONTEND_URL` | Backend | Frontend origin allowed by CORS, e.g. `https://shieldstack-one.vercel.app`. |
| `ALLOW_LOCAL_PATH` | Backend | Set to `1` only for trusted local development; leave unset or `0` on public hosting. |
| `UPSTASH_REDIS_REST_URL` | Backend (optional) | Upstash Redis REST endpoint for persistent scan counters, copied from the Upstash database's REST API page. |
| `UPSTASH_REDIS_REST_TOKEN` | Backend (optional) | Upstash Redis REST token. Never exposed to the browser or logs. |
| `STATS_FILE` | Backend (optional) | Local JSON fallback path; used only when its parent folder exists and is writable. Defaults to `data/stats.json`. |
| `VITE_API_URL` | Frontend | Backend base URL; defaults to `http://localhost:8000`; production uses `https://shieldstack.onrender.com`. |
| `PORT` | Render | Supplied by Render and used by Uvicorn's start command. |

## Deployment

### Render backend

Create a Web Service from this repository with:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.web.main:app --host 0.0.0.0 --port $PORT`
- Environment: set `FRONTEND_URL=https://shieldstack-one.vercel.app`. Optionally set `GEMINI_API_KEY` and `GEMINI_MODEL`. Keep `ALLOW_LOCAL_PATH` unset or set it to `0`.
- Health check path: `/health`
- For persistent counters on the free Render tier, create a free Upstash Redis database, copy its REST URL and token, and set them as `UPSTASH_REDIS_REST_URL` and `UPSTASH_REDIS_REST_TOKEN` in Render's environment settings. Redeploy after setting them. When either value is absent or Redis is unavailable, counters use the local `data/stats.json` fallback, which can reset with the hosted instance.

The model at `app/scanner/ml/model.pkl` and training data at `data/labeled_findings.csv` are required repository assets. The free Render server can sleep when idle; its first request after inactivity can take up to about one minute to wake.

### Vercel frontend

The frontend is live at [https://shieldstack-one.vercel.app](https://shieldstack-one.vercel.app), with the backend at [https://shieldstack.onrender.com](https://shieldstack.onrender.com). For redeployments, import the `frontend` directory as the Vercel project root, use `npm run build` and output directory `dist`, and set `VITE_API_URL=https://shieldstack.onrender.com`.

The dashboard refreshes shared scan counters every 30 seconds while the tab is visible and active. It pauses polling while hidden and after two minutes without user activity, so an idle page does not keep the free backend warm. A scan performed in the current browser updates the counters as soon as the backend returns its result. The display says “total” while Upstash is active and “since restart” when using local fallback storage. Repository source archives are downloaded temporarily and deleted after scanning. Finding details are sent to Google Gemini for the summary when Gemini is configured.

## Test and sample code

By default, ShieldStack skips common test and sample locations (`tests/`, `test/`, `__tests__/`, `fixtures/`, `sample_*/`, `samples/`, `examples/`, and `research_apps/`) and test-named files (`*test*.py`, `*.test.js`, `*.spec.js`, and `*.test.tsx`). This keeps intentionally vulnerable examples from dominating normal application results. If files are skipped, the result shows the count. Enable **Include test and sample code** in the web scanner to scan them too.

The CLI also skips these files by default. Use `--include-fixtures` with either `--repo` or `--path` to include them:

```powershell
python -m app.cli --path . --include-fixtures
```

To exclude additional paths, add a `.shieldstackignore` file at the repository root with one glob pattern per line. Blank lines and lines beginning with `#` are ignored. These patterns are additive; the web checkbox or CLI flag opts into scanning those paths as well.
