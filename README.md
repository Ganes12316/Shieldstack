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
| `GEMINI_API_KEY` | Backend (optional) | Gemini summary generation; scans fall back to a local summary when unset. |
| `GEMINI_MODEL` | Backend (optional) | Primary Gemini model; defaults to `gemini-3.5-flash-lite`, with `gemini-3.8-flash` as fallback. |
| `FRONTEND_URL` | Backend | Deployed frontend origin allowed by CORS, e.g. `https://your-app.vercel.app`. |
| `ALLOW_LOCAL_PATH` | Backend | Set to `1` only for trusted local development; leave unset or `0` on public hosting. |
| `VITE_API_URL` | Frontend | Backend base URL; defaults to `http://localhost:8000`. |

## Deployment

### Render backend

Create a Web Service from this repository with:

- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.web.main:app --host 0.0.0.0 --port $PORT`
- Environment: set `FRONTEND_URL` to the exact Vercel origin. Optionally set `GEMINI_API_KEY`. Keep `ALLOW_LOCAL_PATH` unset or set it to `0`.
- Health check path: `/health`

The model at `app/scanner/ml/model.pkl` and training data at `data/labeled_findings.csv` are required repository assets. Render free services can sleep when idle; the first request after inactivity may take up to about 60 seconds while the server wakes.

### Vercel frontend

Import the `frontend` directory as the project root. Use build command `npm run build`, output directory `dist`, and set `VITE_API_URL` to the deployed Render API base URL (for example `https://your-service.onrender.com`). Set Render's `FRONTEND_URL` to the resulting Vercel origin, then redeploy the backend.

## Live demo

Coming soon: [Live demo URL]
