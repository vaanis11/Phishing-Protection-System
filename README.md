# PhishGuard (Phishing Protection System)

This is a small Flask web app that scans a URL and returns a risk score + findings.

## What’s in here

- `app.py` — Flask app + API routes (`/api/scan`, `/api/stats`, `/api/health`)
- `modules/detector.py` — URL analysis engine
- `modules/stats.py` — stores scan stats in `data/stats.json`
- `templates/index.html`, `static/main.css`, `js/*.js` — frontend UI

## How to start (Windows / PowerShell)

### 1) Use Python 3.11 (recommended)
The repo includes `runtime.txt` (`python-3.11.9`) which is a deployment hint. For local dev, install Python 3.11.x.

### 2) Create a virtual environment
From the project folder:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If you get an execution policy error, run:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

### 3) Install dependencies
```powershell
python -m pip install -r .\requirements.txt
```

### 4) Run the app
```powershell
python .\app.py
```

Then open:

- `http://127.0.0.1:5001/`

## API quick test

```powershell
curl http://127.0.0.1:5001/api/health
curl -Method POST http://127.0.0.1:5001/api/scan -ContentType application/json -Body '{\"url\":\"https://example.com\"}'
```

## Common issues

- **`ModuleNotFoundError: No module named 'flask'`**: you didn’t install requirements inside the active venv.
- **Gunicorn on Windows**: `gunicorn` is primarily for Linux/macOS servers; for local dev on Windows, run `python .\app.py`.
- **Repo contains a `phishing/` folder**: that appears to be a checked-in virtualenv; it’s not portable and you can ignore it and use `.venv` instead.

## Deployment notes

- `Procfile` is set for platforms that run `gunicorn` and provide a `$PORT` env var.
- Stats are written to a temp folder by default (so they work on read-only slugs). To control the location, set `PHISHGUARD_STATS_FILE` or `PHISHGUARD_DATA_DIR`.
