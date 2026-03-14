# SigmaMatch

**Instant Sigma Rule Testing for Real-World Logs.**

SigmaMatch is a web-based tool that lets security analysts upload **Sigma detection rules** (YAML) and **log events** (JSON, NDJSON, XML, CSV, Key=Value), then instantly check whether the rules match any events. Get detailed results showing which selections triggered, which fields matched, and why.

## Features

- **9 field modifiers** — `equals`, `contains`, `startswith`, `endswith`, `re`, and their negations
- **Full boolean conditions** — `and`, `or`, `not`, parentheses, `1 of selection_*`, `all of them`
- **Multi-format log parsing** — JSON, NDJSON, Windows Event XML, CSV/TSV, Key=Value (auto-detected)
- **Batch mode** — validate and match multiple `---` separated rules in one request
- **Export results** — download matches as JSON or CSV
- **Built-in samples** — 3 pre-loaded rules with matching logs for quick testing
- **Safe by design** — `yaml.safe_load`, `defusedxml`, XSS-safe frontend, rate limiting, match timeout
- **Redis-backed rate limiter** — correct limits across multiple workers/containers (falls back to in-memory for local dev)

## Quick Start

### Local (no Docker)

```bash
cd backend
pip install -e .
uvicorn app.main:app --reload
```

Open **http://localhost:8000**

### Docker

```bash
docker-compose up --build
```

Open **http://localhost:8000** — runs 4 Uvicorn workers + Redis for shared rate limiting.

### Run Tests

```bash
cd backend
pip install -e ".[dev]"
pytest -v
```

22 unit tests covering the matching engine and validator.

## API Endpoints

| Endpoint | Method | Rate Limit | Description |
|----------|--------|------------|-------------|
| `/health` | GET | — | Health check |
| `/api/validate` | POST | 60/min | Validate a single Sigma rule |
| `/api/batch-validate` | POST | 30/min | Validate multiple rules (`---` separated) |
| `/api/check` | POST | 30/min | Match a rule against log events |
| `/api/batch-check` | POST | 10/min | Match multiple rules against log events |

### Example: Check a rule

```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{
    "rule_yaml": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: powershell\n  condition: selection\nlevel: high",
    "logs_text": "{\"CommandLine\": \"powershell -enc ABC\"}"
  }'
```

## Project Structure

```
SigmaMatch/
├── backend/
│   ├── app/
│   │   ├── main.py              # FastAPI app, CORS, rate limiter, health check
│   │   ├── api/routes.py        # API endpoints
│   │   ├── core/
│   │   │   ├── config.py        # Shared config (limiter, timeouts)
│   │   │   ├── models.py        # Pydantic data models
│   │   │   ├── parser.py        # Sigma YAML → SigmaRule parser
│   │   │   ├── matcher.py       # Rule-vs-event matching engine
│   │   │   ├── validators.py    # Rule validation
│   │   │   ├── log_parsers.py   # XML, CSV, Key=Value parsers
│   │   │   └── log_generator.py # Synthetic log generator for bulk tests
│   │   └── tests/
│   │       ├── test_matcher.py  # 22 unit tests
│   │       └── bulk_test.py     # Bulk test runner (SigmaHQ rules)
│   ├── static/index.html        # Single-page frontend (vanilla JS)
│   └── pyproject.toml
├── samples/                     # Sample rules and log files
├── Dockerfile
├── docker-compose.yml
├── render.yaml                  # Render deployment config
└── DOCUMENTATION.md             # Full project documentation
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ALLOWED_ORIGINS` | _(empty)_ | CORS allowed origins (comma-separated) |
| `MATCH_TIMEOUT` | `30` | Max seconds per match operation |
| `REDIS_URL` | _(empty)_ | Redis URI for shared rate limiting (e.g. `redis://localhost:6379/0`) |

## Tech Stack

Python 3.11+ · FastAPI · Uvicorn · Pydantic v2 · PyYAML · defusedxml · slowapi + Redis · Docker

## License

MIT

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
