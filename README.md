# SafeShield

SafeShield is a local-first cyber-risk analysis application for user-initiated inspection of messages, URLs, images, QR codes, and Android APK files. It combines deterministic rules, optional machine-learning models, URL live inspection, OCR/QR extraction, explainable findings, and a React interface backed by FastAPI.

This is an educational and research prototype. Results are evidence for human review, not a complete malware verdict or a replacement for security, financial, legal, or incident-response decisions.

## Current State

Implemented:

- React web application with demo login, dashboard shell, four scanners, history, and reports views.
- Message analysis using word-boundary indicators, deterministic scoring, and an optional `message_model.joblib` model.
- URL analysis using trusted-domain fast-path, normalization, static rules, optional calibrated ML, and dynamic HTTP/HTML inspection.
- Image analysis using Pillow/OpenCV, optional pyzbar QR decoding, Tesseract OCR, and recursive URL/message analysis of extracted content.
- APK static analysis using Androguard: metadata, SHA-256, permissions, dangerous combinations, DEX/API indicators, manifest issues, network indicators, certificates, and component counts.
- Explainable response fields: risk score and level, category/verdict, confidence, reasons, indicators, recommendation, model status, and supporting telemetry where applicable.
- Scan persistence through MongoDB when configured, with a local JSON fallback at `backend/data/analyses_history.json` capped at 500 records.
- Offline message and URL training/evaluation utilities.
- Chrome Manifest V3 extension prototype with local result templates only.

Known limitations:

- Login uses hard-coded demo credentials and generates a token, but the analysis/history/report API routes do not currently validate that token. Do not deploy this authentication design as production security.
- The dashboard cards and recent-analysis area are static placeholders; use History and Reports for live stored data.
- The frontend API URL is hard-coded to `http://127.0.0.1:8000`; the commented `VITE_API_URL` line is not active.
- URL live inspection makes outbound HTTP requests. It can fail, time out, or fall back to static analysis. It is not a browser sandbox and does not execute JavaScript.
- APK analysis is static only. It does not execute, decompile, or fully determine whether an application is malicious.
- OCR and pyzbar depend on local native tooling. Tesseract is optional at runtime; without it, OCR reports `tesseract_not_installed`. QR decoding can be limited when the pyzbar native library is unavailable.
- No frontend test suite exists. Backend coverage is focused on API smoke tests and selected image/message behavior.
- The extension does not call the backend, inspect WhatsApp, or use the React login session.

For code ownership, data flow, contracts, and AI maintenance guidance, read [ARCHITECTURE.md](ARCHITECTURE.md).

## Repository Layout

```text
SafeShield/
|- backend/                 FastAPI service and Python analyzers
|  |- analyzer/            Message, URL, APK, image, and live inspection code
|  |- data/                Datasets and local analysis history
|  |- ml/                  Message preprocessing and training scripts
|  |- main.py              API app, schemas, routes, uploads, and persistence calls
|  |- risk_engine.py       Message scoring, categories, recommendations, and hashing
|  |- database.py          MongoDB/local JSON persistence
|  `- test_*.py            Backend tests
|- frontend/                React 18 and Vite application
|- extension/               Chrome Manifest V3 popup prototype
|- url_checker/             URL rules, features, models, datasets, and scripts
|- ARCHITECTURE.md          System design and AI change context
`- README.md                Setup and operational guide
```

## Requirements

- Python 3.10 or newer.
- Node.js 16 or newer and npm.
- MongoDB is optional. Without it, the backend writes local JSON history.
- Tesseract OCR is optional for image text extraction. Set `TESSERACT_CMD` when the executable is not discoverable.
- APK support requires the Androguard and Loguru packages used by `backend/analyzer/apk_analyzer.py`.

Install Python dependencies from [backend/requirements.txt](backend/requirements.txt). On a clean environment, verify that the APK and native OCR/QR prerequisites are available before using those scanners.

## Setup and Run

From the repository root on Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
py -m pip install -r backend\requirements.txt
```

Start the backend in one terminal:

```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```

Start the frontend in another terminal:

```powershell
Set-Location frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000). The backend API documentation is at [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs). The frontend requires the backend health check to be reachable and initially shows the login page.

Demo credentials are displayed on the login screen:

| Username | Password | Role returned |
|---|---|---|
| `admin` | `password123` | `admin` |
| `analyst` | `safeshield2026` | `analyst` |
| `demo` | `demo123` | `analyst` |

The frontend stores the returned token, username, and role in browser `localStorage` under `ss_token`, `ss_username`, and `ss_role`. This is prototype behavior, not a production session implementation.

## Configuration and Persistence

Create `backend/.env` only when using MongoDB:

```dotenv
MONGODB_URI=mongodb://localhost:27017
MONGODB_DATABASE=safeshield
```

`backend/database.py` prefers MongoDB when a URI is configured. If MongoDB is absent or a write/query fails, it falls back to `backend/data/analyses_history.json`. Local history is newest-first and limited to 500 records. Message persistence stores only a SHA-256 hash, never message plaintext; history responses also remove any accidental plaintext field.

The backend CORS allowlist includes local port 3000, the configured Render frontend origin in `backend/main.py`, and Chrome extension origins matching `chrome-extension://*`. Keep CORS and the hard-coded frontend URL synchronized when deployment targets change.

## API Quick Reference

| Method | Route | Request | Purpose |
|---|---|---|---|
| GET | `/` | none | Service metadata and documentation links |
| GET | `/health` | none | Health response and version |
| POST | `/login` | `{ "username": "...", "password": "..." }` | Demo credential check and token generation |
| POST | `/analyze/message` | `{ "message": "..." }` | Message risk analysis |
| POST | `/analyze/url` | `{ "url": "..." }` | URL risk analysis and live telemetry |
| POST | `/analyze/image` | multipart field `file` | OCR, QR, URL, and message analysis |
| POST | `/analyze/apk` | multipart field `file` | APK static analysis |
| GET | `/history` | optional `scan_type`, `limit` | Stored analyses, newest first |
| GET | `/reports/stats` | none | Aggregate counts by verdict, risk level, and scan type |

Message input is 1-5000 characters and URL input is 1-2048 characters. Request models reject unknown JSON fields and blank values are rejected after trimming. Analysis IDs use the format `SS-XXXXXXXXXX`.

Message and URL responses expose `risk_score`, `risk_level`, `category`, `confidence`, `reasons`, `detected_indicators`, `recommendation`, `model_prediction`, `model_confidence`, and `rule_confidence`. URL responses additionally expose original/normalized URLs, `verdict`, `domain_valid`, `live_inspection`, and `scoring_breakdown`. Image responses expose OCR/QR status and nested URL/message results. APK responses include `success`, file/package metadata, hash, permissions, static findings, score, risk level, and verdict.

Message risk levels are `LOW`, `MEDIUM`, `HIGH`, and `CRITICAL` at score thresholds 25, 50, and 75. URL and image verdicts are `SAFE`, `SUSPICIOUS`, or `FRAUD`; a verdict can be stricter than the numeric score when rules or live evidence require it. APK verdicts are `low_risk`, `suspicious`, or `dangerous`.

## Tests and Models

Run backend tests from the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend -p "test_*.py"
```

Run URL checks and evaluation:

```powershell
Set-Location url_checker
..\.venv\Scripts\python.exe scripts\test_rule_check.py
..\.venv\Scripts\python.exe scripts\evaluate_url_checker.py
```

Train models:

```powershell
Set-Location backend
..\.venv\Scripts\python.exe ml\train_message_model.py

Set-Location ..\url_checker
..\.venv\Scripts\python.exe train_model.py
```

Runtime model paths are `backend/ml/models/message_model.joblib` and, for URLs, `url_checker/model/url_model_calibrated.pkl` with fallback to `url_model.pkl`. Model loading is lazy and failures degrade to rule-only analysis with `model_prediction: "unavailable"`.

## Browser Extension

Load `extension/` through Chrome `chrome://extensions/` with Developer mode enabled. The extension is a standalone popup prototype. Its local last-result key is `safeShieldLastResult`; backend integration and content-script inspection are not implemented.

## AI Development Rules

- Treat the implementation as the source of truth and update this README and [ARCHITECTURE.md](ARCHITECTURE.md) when routes, model paths, integrations, or status change.
- Preserve response fields and explainability because the React pages and tests consume them.
- Keep message plaintext out of persistence and logs.
- Test rule thresholds, URL normalization, allowlist/live-inspection fallback, upload validation, model-unavailable behavior, and persistence failure paths when changing them.
- Avoid trusting a model score alone. URL live evidence, trusted-domain behavior, deterministic rules, and verdict logic are separate parts of the contract.
- Do not expose API keys, credentials, private datasets, raw provider responses, or generated environments in commits.

## License

SafeShield is currently intended for educational and prototype use in a cybersecurity context.
