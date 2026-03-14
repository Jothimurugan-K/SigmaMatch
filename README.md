# SigmaMatch

A minimal web app to upload a Sigma rule (YAML) and a log file (JSON/NDJSON) and check whether the rule matches any events.

## Quick Start (no venv, no Node.js)

### 1. Install dependencies

```bash
cd backend
pip install fastapi uvicorn pydantic pyyaml python-multipart
```

### 2. Run the server

```bash
cd backend
uvicorn app.main:app --reload --port 8000
```

### 3. Open in browser

Go to **http://localhost:8000**

That's it! The UI is served directly by the Python backend — no Node.js needed.

---

## Run with Docker

```bash
docker-compose up --build
```

Then open **http://localhost:8000**.

---

## Run tests

```bash
cd backend
pip install pytest
pytest -v
```

---

## Project Structure

```
SigmaRuleSite/
  backend/
    app/
      main.py              # FastAPI app entry point
      api/
        routes.py           # POST /api/validate, POST /api/check
      core/
        models.py           # Pydantic data models
        parser.py           # Sigma YAML → internal model
        matcher.py          # Evaluation engine
        validators.py       # Rule validation
      tests/
        test_matcher.py     # 22 unit tests
    static/
      index.html            # Single-page frontend (vanilla JS)
    pyproject.toml
  samples/
    rules/                  # 3 sample Sigma rules
    logs/                   # 3 sample log files
  Dockerfile
  docker-compose.yml
  README.md
```

## API Endpoints

### `POST /api/validate`

Validate a Sigma rule YAML.

```bash
curl -X POST http://localhost:8000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"rule_yaml": "title: Test\ndetection:\n  selection:\n    foo|contains: bar\n  condition: selection"}'
```

### `POST /api/check`

Check a Sigma rule against log events.

```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains:\n      - powershell\n      - -enc\n  condition: selection\nlevel: medium",
    "logs_text": "{\"CommandLine\": \"powershell -enc AAAA\"}"
  }'
```

## Features

- **Modifiers**: `equals`, `contains`, `startswith`, `endswith`, `re` (regex)
- **Conditions**: `selection`, `sel1 and sel2`, `sel1 or sel2`, `not filter`, `1 of selection_*`, `all of selection_*`, parentheses
- **Log formats**: JSON (single object or array), NDJSON (one object per line)
- **File size limit**: 5 MB
- **Privacy**: All processing in memory, no files persisted

## Security Notes

- Input size limited to 5 MB
- YAML parsed with `yaml.safe_load` (no code execution)
- No file persistence — uploads discarded after request
- CORS not enabled by default (same-origin only)
- Rate limiting: add middleware (e.g., `slowapi`) for production

## Future (not MVP)

- EVTX/XML log support
- Advanced modifiers (base64, cidr, numeric comparisons)
- Correlation rules
- Field mapping presets (Sysmon, ECS)
- Multi-backend query preview via sigma-cli
