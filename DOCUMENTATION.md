# SigmaMatch — Project Documentation

## 1. Project Overview

**SigmaMatch** is a web-based MVP tool that allows security analysts to upload a **Sigma detection rule** (YAML) and **log events** (JSON/NDJSON), then instantly check whether the rule matches any of the provided log events. It provides detailed match results including which selections triggered, which fields matched, and why.

**Tagline:** *Instant Sigma Rule Testing for Real-World Logs.*

---

## 2. Architecture

### 2.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Browser (Client)                        │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              Static HTML + Vanilla JS + CSS               │  │
│  │         (Single-page app served by FastAPI)               │  │
│  └──────┬────────┬───────────┬──────────────┬────────────────┘  │
│         │        │           │              │                   │
│    POST /api/ POST /api/ POST /api/   POST /api/               │
│    validate  check     batch-validate batch-check              │
└─────────┼────────┼───────────┼──────────────┼───────────────────┘
          │        │           │              │
          ▼        ▼           ▼              ▼
┌─────────────────────────────────────────────────────────────────┐
│              FastAPI Backend (Python) — Multi-worker            │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌───────────────┐  │
│  │  Routes   │─▶│ Validator│  │  Parser  │─▶│   Matcher     │  │
│  │(routes.py)│  │          │  │          │  │(Condition Eval)│  │
│  └──────────┘  └──────────┘  └──────────┘  └───────────────┘  │
│                                                                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────────────────┐  │
│  │Log Parser│  │Log Gen.  │  │ asyncio.to_thread (non-block)│  │
│  │(XML/CSV/ │  │(Synthetic│  │ CPU-bound work off event loop│  │
│  │ KV/JSON) │  │ events)  │  └──────────────────────────────┘  │
│  └──────────┘  └──────────┘                                    │
│                                                                 │
│  Middleware: CORS │ Rate Limiting (slowapi + Redis)              │
│  Health Check: GET /health                                      │
│  Static Serving:  /static/index.html, /static/favicon.svg      │
│  Workers: Uvicorn × 4 (configurable)                            │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 Technology Stack

| Layer       | Technology                                  |
|-------------|---------------------------------------------|
| Language    | Python 3.11+                                |
| Framework   | FastAPI (ASGI)                              |
| Server      | Uvicorn                                     |
| Data Models | Pydantic v2                                 |
| YAML Parser | PyYAML (`yaml.safe_load`)                   |
| XML Parser  | defusedxml (safe XML parsing)               |
| Rate Limit  | slowapi + limits + Redis                    |
| Frontend    | Single static HTML file (vanilla JS + CSS)  |
| Container   | Docker + docker-compose                     |
| Testing     | pytest                                      |
| Linting     | ruff                                        |

### 2.3 Request Flow

```
User pastes rule + logs → clicks "Check Match"
        │
        ▼
Browser sends POST /api/check { rule_yaml, logs_text }
        │
        ▼
Rate Limiter checks: ≤ 30 req/min per IP?
        │ Yes
        ▼
routes.py: api_check()
        │
        ├─▶ parser.py: parse_rule(yaml_text) → SigmaRule
        │         │
        │         ├── yaml.safe_load → dict
        │         ├── Extract detection block, condition, logsource
        │         └── Build SelectionBlock + FieldCondition models
        │
        ├─▶ routes.py: _parse_logs(logs_text) → list[dict]
        │         │
        │         ├── Try JSON array / single object
        │         └── Fall back to NDJSON (line-by-line)
        │
        └─▶ matcher.py: match_events(rule, events) → MatchResult
                  │
                  ├── For each event:
                  │     ├── _ConditionEvaluator(rule, event)
                  │     ├── Tokenize condition string
                  │     ├── Recursive-descent boolean parse
                  │     │     (AND / OR / NOT / parentheses / N of)
                  │     ├── _selection_matches() → AND of FieldConditions
                  │     └── _field_matches() → apply modifier (equals/contains/startswith/endswith/re)
                  │
                  └── Return MatchResult { matched, match_count, total_events, matches[], explanation }
        │
        ▼
Browser renders: ✅ Matched / ❌ Not Matched + details table
```

---

## 3. Folder Structure

```
SigmaRuleSite/
├── backend/
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py                  # FastAPI app entry point, CORS, rate limiter, health check
│   │   ├── api/
│   │   │   ├── __init__.py
│   │   │   └── routes.py            # API endpoints (validate, check, batch-validate, batch-check)
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── models.py            # Pydantic data models
│   │   │   ├── parser.py            # Sigma YAML → SigmaRule parser (single + multi-doc)
│   │   │   ├── matcher.py           # Rule-vs-event matching engine
│   │   │   ├── validators.py        # Rule YAML validator (single + batch)
│   │   │   ├── log_parsers.py       # XML, CSV/TSV, Key=Value log parsers
│   │   │   └── log_generator.py     # Synthetic log event generator for bulk testing
│   │   └── tests/
│   │       ├── __init__.py
│   │       ├── test_matcher.py      # 22 unit tests
│   │       └── bulk_test.py         # Bulk test runner against SigmaHQ rules
│   ├── static/
│   │   ├── index.html               # Full frontend (HTML + CSS + JS)
│   │   └── favicon.svg              # Σ logo icon
│   └── pyproject.toml               # Python project config & dependencies
├── samples/
│   ├── rules/
│   │   ├── windows_powershell_contains.yml
│   │   ├── okta_user_locked_out.yml
│   │   └── linux_ssh_failed_login.yml
│   └── logs/
│       ├── sysmon_event1.json
│       ├── okta_events.json
│       ├── linux_auth.ndjson
│       ├── linux_auth.csv
│       └── windows_security.xml
├── Dockerfile                        # Multi-worker Uvicorn container
├── docker-compose.yml                # Docker orchestration with health checks
├── README.md
└── DOCUMENTATION.md                  # ← This file
```

---

## 4. Module Details

### 4.1 `models.py` — Data Models

Defines all Pydantic models used across the application.

**Sigma Rule Models (input):**

| Model            | Purpose                                            |
|------------------|----------------------------------------------------|
| `SigmaModifier`  | Enum: `equals`, `contains`, `startswith`, `endswith`, `re`, `not_contains`, `not_startswith`, `not_endswith`, `not_re` |
| `FieldCondition` | Single field check — field name, modifiers, values (OR'd) |
| `SelectionBlock` | Named selection — list of FieldConditions (AND'd)  |
| `LogSource`      | product / category / service from `logsource:`     |
| `SigmaRule`      | Full parsed rule: title, id, level, selections, condition |

**Match Result Models (output):**

| Model           | Purpose                                              |
|-----------------|------------------------------------------------------|
| `FieldMatch`    | Details of one matched field (field, modifier, expected, actual) |
| `EventMatch`    | One matched log event (index, selections, fields, explanation)  |
| `MatchResult`   | Overall result: matched (bool), match_count, total_events, matches[], warnings[] |
| `RuleMatchResult`| Result for one rule in a batch (rule_title, rule_id, result, error)   |
| `BatchMatchResult`| Batch result: total_rules, rules_matched, total_events, results[]   |

**Validation Models:**

| Model                 | Purpose                                         |
|-----------------------|-------------------------------------------------|
| `Issue`               | Single validation issue (severity + message)    |
| `ValidationResult`    | valid (bool), issues[], title, logsource        |
| `BatchValidationResult` | Batch result: total_rules, valid_count, results[] |

---

### 4.2 `parser.py` — Sigma YAML Parser

Parses raw YAML text into a `SigmaRule` model.

**Key functions:**

| Function            | Description                                              |
|---------------------|----------------------------------------------------------|
| `parse_rule(yaml_text)` | Main entry — returns `SigmaRule`, raises `ValueError` on invalid input |
| `_parse_field_key(key)` | Splits `"CommandLine\|contains\|nocase"` → (field, modifiers, case_flag) |
| `_coerce_to_str_list(value)` | Normalizes scalar/list values to `list[str]`       |
| `_parse_selection(name, data)` | Builds a `SelectionBlock` from a detection dict  |

**Parsing logic:**
1. `yaml.safe_load` the text (safe — no arbitrary code execution)
2. Extract `detection` section → must have `condition` key
3. Iterate detection keys (skip `condition`, `timeframe`) → build `SelectionBlock` objects
4. Handle both dict-style and list-of-dicts-style selections
5. Parse `logsource` fields and metadata (title, id, level, etc.)

---

### 4.3 `matcher.py` — Matching Engine

The core detection engine. Evaluates a parsed `SigmaRule` against log events.

**Architecture — Three-layer evaluation:**

```
match_events()                    ← Public API: iterates events
    └── _ConditionEvaluator       ← Evaluates condition expression per event
            ├── _bool_eval()      ← Recursive-descent boolean parser
            │     ├── OR expressions
            │     ├── AND expressions
            │     ├── NOT expressions
            │     ├── Parenthesised grouping
            │     └── "N of pattern" / "all of pattern"
            ├── _selection_matches()  ← AND of FieldConditions
            └── _field_matches()      ← Single field check with modifiers
```

**Supported condition syntax:**

| Syntax                          | Example                           |
|---------------------------------|-----------------------------------|
| Plain selection name            | `selection`                       |
| AND                             | `selection and filter`            |
| OR                              | `selection1 or selection2`        |
| NOT                             | `selection and not filter`        |
| Parentheses                     | `(sel1 or sel2) and not filter`   |
| 1 of selection_*                | `1 of selection_*`                |
| all of selection_*              | `all of selection_*`              |
| 1 of them                       | `1 of them`                       |

**Supported field modifiers:**

| Modifier     | Behavior                              |
|--------------|---------------------------------------|
| `equals`     | Exact string match (default)          |
| `contains`   | Substring match                       |
| `startswith` | Prefix match                          |
| `endswith`   | Suffix match                          |
| `re`         | Regex match via `re.search()`         |
| `not_contains`   | Negated substring match (no value found) |
| `not_startswith` | Negated prefix match                 |
| `not_endswith`   | Negated suffix match                 |
| `not_re`         | Negated regex match                  |

All string comparisons are **case-insensitive by default** (Sigma convention).

---

### 4.4 `validators.py` — Rule Validator

Validates a Sigma rule YAML and returns structured issues.

**Checks performed:**

| Check                  | Severity  | Message                                      |
|------------------------|-----------|----------------------------------------------|
| Empty input            | error     | "Rule YAML is empty."                        |
| Invalid YAML           | error     | Parse error details                          |
| Missing `detection`    | error     | (raised by parser)                           |
| Missing `condition`    | error     | (raised by parser)                           |
| No selections found    | error     | "No selections found in detection block."    |
| Missing `title`        | warning   | "Rule is missing a 'title'."                 |
| Missing `id`           | warning   | "Rule is missing an 'id' (UUID)."            |
| Missing `level`        | info      | "Rule is missing 'level'."                   |
| Empty `logsource`      | warning   | "Rule 'logsource' has no product/category/service." |
| Uses `timeframe`       | info      | "Rule uses 'timeframe' — temporal aggregation is not yet supported." |

---

### 4.5 `log_parsers.py` — Log Format Parsers

Parses non-JSON log formats into `list[dict]` for the matcher.

**Supported formats:**

| Format | Detection | Parser | Notes |
|--------|-----------|--------|-------|
| Windows Event XML | Starts with `<Event` or `<?xml` | `parse_xml_events()` | Flattens `<System>` + `<EventData>` + `<UserData>` into flat dict. Uses defusedxml for XXE protection. |
| CSV / TSV | Header row with 2+ commas or tabs, 2+ lines | `parse_csv_events()` | Auto-detects delimiter. Header row becomes dict keys. |
| Key=Value | Lines containing `key=value` patterns | `parse_kv_events()` | Supports `key=value`, `key="quoted value"`, `key='quoted value'`. One event per line. |

**Key functions:**

| Function | Description |
|----------|-------------|
| `detect_and_parse(text)` | Auto-detects format and returns `list[dict]` or `None` |
| `parse_xml_events(text)` | Parses Windows Event XML (single or multiple `<Event>` elements) |
| `parse_csv_events(text)` | Parses CSV/TSV with header row |
| `parse_kv_events(text)` | Parses key=value log lines |

---

### 4.6 `routes.py` — API Endpoints

| Endpoint              | Method | Rate Limit   | Request Body                         | Response              |
|-----------------------|--------|--------------|--------------------------------------|-----------------------|
| `/health`             | GET    | —            | —                                    | `{ "status": "ok" }` |
| `/api/validate`       | POST   | 60/min per IP| `{ "rule_yaml": "<yaml>" }`          | `ValidationResult`    |
| `/api/batch-validate` | POST   | 30/min per IP| `{ "rule_yaml": "<yaml>" }`          | `BatchValidationResult` |
| `/api/check`          | POST   | 30/min per IP| `{ "rule_yaml": "<yaml>", "logs_text": "<json>" }` | `MatchResult` |
| `/api/batch-check`    | POST   | 10/min per IP| `{ "rule_yaml": "<yaml>", "logs_text": "<json>" }` | `BatchMatchResult` |

**Request body size limit:** 5 MB per field.

**Non-blocking execution:** All CPU-bound matching operations run via `asyncio.to_thread()` so they don't block the async event loop, allowing the server to handle other requests concurrently.

**Log parsing** (`_parse_logs`):
1. Try `json.loads` → if array, return list of dicts; if single dict, wrap in list
2. Fall back to NDJSON (one JSON object per line, invalid lines skipped)
3. Fall back to Windows Event XML (detected via `<Event` prefix, parsed with defusedxml)
4. Fall back to CSV/TSV (auto-detects delimiter from header row)
5. Fall back to Key=Value pairs (one event per line, supports quoted values)

---

### 4.7 `main.py` — Application Entry Point

Configures and assembles the FastAPI application:

1. **Rate Limiter** — `slowapi.Limiter` keyed by client IP address, backed by Redis when `REDIS_URL` is set (falls back to in-memory for local dev)
2. **429 Exception Handler** — Returns friendly JSON on rate limit exceeded
3. **CORS Middleware** — Configurable via `ALLOWED_ORIGINS` env var (default: same-origin only)
4. **API Router** — Mounts `/api/validate`, `/api/batch-validate`, `/api/check`, `/api/batch-check`
5. **Health Check** — `GET /health` returns `{"status": "ok"}` for load balancers and monitoring
6. **Static Files** — Serves `static/` directory at `/static/`
7. **Root Route** — `GET /` serves `index.html`

---

### 4.8 `index.html` — Frontend UI

A **single static HTML file** containing all CSS and JavaScript inline. No build tools required.

**Features:**

| Feature                | Description                                           |
|------------------------|-------------------------------------------------------|
| Dark theme UI          | Professional dark color scheme with indigo accents    |
| Two-pane layout        | Left: rule editor, Right: logs + results              |
| 3 sample rules         | Dropdown to load pre-built rules with matching logs   |
| "Try with Test Data"   | One-click button to load a sample rule + matching logs |
| Rule upload            | File input (.yml/.yaml, max 5 MB) — supports multiple files  |
| Rule editor            | Textarea with monospace font for YAML editing         |
| Log upload             | File input (.json/.ndjson/.xml/.csv/.tsv/.log/.txt, max 5 MB) or paste textarea |
| Multi-format support   | JSON, NDJSON, XML, CSV/TSV, Key=Value log formats     |
| Validate Rule button   | Calls `/api/validate` or `/api/batch-validate` for multi-rule |
| Check Match button     | Calls `/api/check` or `/api/batch-check` for multi-rule, shows results |
| Batch mode             | Auto-detects `---` separated multi-rule YAML and uses batch endpoints |
| Clear buttons          | Clear Rule, Clear Logs, Reset All                     |
| Results display        | Match banner (green/gray) + details table             |
| Batch results          | Per-rule collapsible sections with color-coded headers (green/red/gray) |
| Export results (JSON)  | Download match results as a structured JSON file      |
| Export results (CSV)   | Download match results as CSV with headers            |
| Docker setup modal     | In-app self-hosting instructions with copy buttons    |
| Privacy / OPSEC banner | Warning about not using production logs on hosted version |
| Σ favicon + logo       | Indigo branded sigma symbol                           |
| Responsive             | Grid collapses to single column on narrow screens     |
| XSS protection         | All dynamic text escaped via DOM `textContent` method |

---

### 4.9 `test_matcher.py` — Unit Tests

**22 tests** across 9 test classes:

| Test Class            | Tests | What It Covers                                 |
|-----------------------|-------|-------------------------------------------------|
| `TestPositiveMatch`   | 2     | contains match, case insensitivity              |
| `TestNegativeMatch`   | 2     | Missing field, wrong value                      |
| `TestOneOfSelection`  | 3     | `1 of selection_*` — first, second, neither     |
| `TestAndNotCondition` | 2     | `selection and not filter` — pass and filtered   |
| `TestStartsWith`      | 2     | `startswith` — match and no-match               |
| `TestRegex`           | 2     | `re` modifier — match and no-match              |
| `TestAllOfSelection`  | 2     | `all of selection_*` — full and partial          |
| `TestMultipleEvents`  | 1     | Mixed events, correct count and indices          |
| `TestValidator`       | 4     | Valid rule, empty, invalid YAML, missing detection|
| `TestEqualsModifier`  | 2     | Exact match and exact no-match                  |

---

## 5. Sample Data

### 5.1 Sample Rules

| File                              | Detection                            | Modifier     |
|-----------------------------------|--------------------------------------|--------------|
| `windows_powershell_contains.yml` | PowerShell with encoded command      | `contains`   |
| `okta_user_locked_out.yml`        | Okta user account lockout            | `equals`     |
| `linux_ssh_failed_login.yml`      | SSH failed password attempts         | `startswith` |

### 5.2 Sample Logs

| File                  | Format        | Events | Description                         |
|-----------------------|---------------|--------|-------------------------------------|
| `sysmon_event1.json`  | Single JSON   | 1      | Windows Sysmon process creation     |
| `okta_events.json`    | JSON array    | 2      | Okta system log (lock + session)    |
| `linux_auth.ndjson`   | NDJSON        | 4      | Linux SSH auth log lines            |
| `windows_security.xml`| Event XML     | 1      | Windows logon failure (Event 4625)  |
| `linux_auth.csv`      | CSV           | 4      | Linux auth events with timestamps   |
| `auditd.log`          | Key=Value     | 3      | Linux auditd authentication events  |

---

## 6. Security Features

| Feature                  | Implementation                                              |
|--------------------------|--------------------------------------------------------------|
| CORS                     | `CORSMiddleware` — restrict origins via `ALLOWED_ORIGINS` env var |
| Rate Limiting            | `slowapi` + Redis — 60/min for validate, 30/min for batch-validate, 30/min for check, 10/min for batch-check per IP; shared across all workers/containers via Redis |
| Input Size Cap           | 5 MB max per request field (`max_length` on Pydantic fields) |
| Safe YAML Parse          | `yaml.safe_load` — prevents arbitrary code execution        |
| Safe XML Parse           | `defusedxml` — prevents XXE and entity expansion attacks    |
| XSS Prevention           | Frontend escapes all dynamic content via DOM `textContent`   |
| Match Timeout            | Configurable timeout (default 30s) for match operations via `MATCH_TIMEOUT` env var |
| Non-blocking Matcher     | CPU-bound matching offloaded via `asyncio.to_thread()` to prevent event loop blocking |
| Multi-worker Deployment  | Uvicorn runs 4 workers by default for parallel request handling |
| Health Check             | `GET /health` endpoint for load balancer liveness probes    |
| Docker Health Monitoring | Container healthcheck pings `/health` every 30s with auto-restart on failure |

---

## 7. How to Execute

### 7.1 Prerequisites

- **Python 3.11 or higher** installed
- **pip** available on PATH

### 7.2 Local Setup (without Docker)

```powershell
# 1. Navigate to the backend directory
cd SigmaRuleSite\backend

# 2. Install dependencies
pip install -e .

# 3. Start the server
uvicorn app.main:app --reload
```

The app will be available at **http://localhost:8000**

### 7.3 Docker Setup

```powershell
# From the project root (SigmaRuleSite/)
docker-compose up --build
```

The app will be available at **http://localhost:8000**

The Docker setup includes a **Redis** container for shared rate limiting and the app container running **4 Uvicorn workers**. Health checks ping `/health` every 30 seconds with automatic restart on failure. Redis health is checked via `redis-cli ping` every 10 seconds.

### 7.4 Running Tests

```powershell
# From the backend/ directory
pip install -e ".[dev]"
pytest
```

This runs all 22 unit tests for the matching engine and validator.

### 7.5 Environment Variables

| Variable          | Default   | Description                                             |
|-------------------|-----------|---------------------------------------------------------|
| `ALLOWED_ORIGINS` | _(empty)_ | Comma-separated origins for CORS (empty = same-origin)  |
| `MATCH_TIMEOUT`   | `30`      | Max seconds for match operations (0 = no timeout)       |
| `REDIS_URL`       | _(empty)_ | Redis connection URI for shared rate limiting (e.g. `redis://localhost:6379/0`). Falls back to in-memory if unset. |

Example:
```powershell
$env:ALLOWED_ORIGINS = "https://yourdomain.com,https://www.yourdomain.com"
uvicorn app.main:app --reload
```

### 7.6 API Usage (curl)

**Validate a rule:**
```bash
curl -X POST http://localhost:8000/api/validate \
  -H "Content-Type: application/json" \
  -d '{"rule_yaml": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: powershell\n  condition: selection\nlevel: high"}'
```

**Check rule against logs:**
```bash
curl -X POST http://localhost:8000/api/check \
  -H "Content-Type: application/json" \
  -d '{"rule_yaml": "title: Test\nlogsource:\n  product: windows\ndetection:\n  selection:\n    CommandLine|contains: powershell\n  condition: selection\nlevel: high", "logs_text": "{\"CommandLine\": \"powershell -enc ABC\"}"}'
```

---

## 8. Dependencies

### Runtime Dependencies

| Package            | Version   | Purpose                          |
|--------------------|-----------|----------------------------------|
| `fastapi`          | >=0.115   | Web framework                    |
| `uvicorn[standard]`| >=0.30    | ASGI server                      |
| `pydantic`         | >=2       | Data validation/serialization    |
| `pyyaml`           | >=6       | YAML parsing                     |
| `python-multipart` | >=0.0.9   | File upload support              |
| `slowapi`          | >=0.1.9   | Rate limiting middleware         |
| `redis`            | >=5       | Redis client for shared rate limiting |
| `defusedxml`       | >=0.7     | Safe XML parsing (XXE protection)|

### Dev Dependencies

| Package  | Version | Purpose           |
|----------|---------|-------------------|
| `pytest` | >=8     | Unit test runner  |
| `httpx`  | >=0.27  | HTTP test client  |
| `ruff`   | >=0.5   | Linter/formatter  |

---

## 9. Bulk Testing Against SigmaHQ Rules

You can test this tool against **all 3,000+ Sigma rules** from the official SigmaHQ repository — even without real logs.

### How It Works

The bulk test script uses a **synthetic log generator** that:
1. Reads each rule's detection fields and modifiers
2. Auto-generates a fake log event that *should* match (positive test)
3. Auto-generates a fake log event that *should not* match (negative test)
4. Runs both through the matcher and checks correctness

### Steps to Run

```powershell
# 1. Clone the SigmaHQ rules repo (shallow clone for speed)
cd SigmaRuleSite
git clone --depth 1 https://github.com/SigmaHQ/sigma.git

# 2. Run the bulk test from the backend directory
cd backend
python -m app.tests.bulk_test ../sigma/rules
```

### What It Tests

| Check      | What It Verifies                                          |
|------------|-----------------------------------------------------------|
| PARSE      | Can every rule YAML be parsed without errors?             |
| POSITIVE   | Does a matching synthetic event correctly trigger a match?|
| NEGATIVE   | Does a non-matching event correctly return no match?      |

### Output

- **Live progress** printed to terminal (failures shown in detail, successes summarized)
- **Summary** with parse success rate, positive/negative match rates
- **Report file** `bulk_test_report.txt` with all failures listed for debugging

### Test a Specific Subfolder

```powershell
# Only Windows process creation rules
python -m app.tests.bulk_test ../sigma/rules/windows/process_creation

# Only Linux rules
python -m app.tests.bulk_test ../sigma/rules/linux

# Only cloud rules
python -m app.tests.bulk_test ../sigma/rules/cloud
```

### Interpreting Results

- **Parse failures** — The rule uses YAML syntax or Sigma features not yet supported by this MVP (e.g. correlation rules, pipes). These are logged for you to investigate.
- **Positive match failures** — The synthetic log generator couldn't produce a value that satisfies a complex condition (e.g. nested regex). The rule itself may still work with real logs.
- **Negative match failures** — Rare. Indicates a potential false-positive bug in the matcher.

---

## 10. Feature Status

### 10.1 Implemented Features

| Feature | Status | Details |
|---------|--------|---------|
| Single rule validation | ✅ Done | `POST /api/validate` — checks structure, metadata, detection block |
| Batch rule validation | ✅ Done | `POST /api/batch-validate` — validates `---` separated multi-rule YAML |
| Single rule matching | ✅ Done | `POST /api/check` — match one rule against log events |
| Batch rule matching | ✅ Done | `POST /api/batch-check` — match multiple rules against log events |
| 9 field modifiers | ✅ Done | `equals`, `contains`, `startswith`, `endswith`, `re`, `not_contains`, `not_startswith`, `not_endswith`, `not_re` |
| Boolean condition syntax | ✅ Done | `and`, `or`, `not`, parentheses, `1 of selection_*`, `all of them` |
| JSON / NDJSON log parsing | ✅ Done | Auto-detects arrays, single objects, line-by-line JSON |
| Windows Event XML parsing | ✅ Done | Flattens `<System>` + `<EventData>` + `<UserData>` via defusedxml |
| CSV / TSV log parsing | ✅ Done | Auto-detects delimiter from header row |
| Key=Value log parsing | ✅ Done | Supports `key=value`, `key="quoted value"` per line |
| Format auto-detection | ✅ Done | Automatically tries JSON → NDJSON → XML → CSV/TSV → KV |
| Export results (JSON) | ✅ Done | Download match results as structured JSON file |
| Export results (CSV) | ✅ Done | Download match results as CSV with headers |
| Multi-file rule upload | ✅ Done | Upload multiple .yml/.yaml files, auto-concatenated |
| Sample data dropdown | ✅ Done | 3 pre-built rules with matching logs |
| "Try with Test Data" button | ✅ Done | One-click sample data loading |
| Docker setup modal | ✅ Done | In-app self-hosting instructions with copy buttons |
| Privacy / OPSEC banner | ✅ Done | Warning about not using production logs on hosted version |
| Collapsible batch results | ✅ Done | Per-rule sections with color-coded headers |
| Rate limiting | ✅ Done | Per-IP, per-endpoint throttling via slowapi |
| CORS protection | ✅ Done | Configurable allowed origins |
| Safe XML parsing | ✅ Done | defusedxml prevents XXE attacks |
| Match timeout | ✅ Done | Configurable via `MATCH_TIMEOUT` env var (default 30s) |
| Non-blocking matcher | ✅ Done | CPU-bound work offloaded via `asyncio.to_thread()` |
| Multi-worker Uvicorn | ✅ Done | 4 workers by default in Docker for concurrent request handling |
| Health check endpoint | ✅ Done | `GET /health` for load balancers and monitoring |
| Docker healthcheck | ✅ Done | Auto-restart on failure (30s interval, 3 retries) |
| Synthetic log generator | ✅ Done | Auto-generates positive/negative test events from rules |
| Bulk test runner | ✅ Done | Test against 3,000+ SigmaHQ rules with automated pass/fail |
| Responsive UI | ✅ Done | Dark theme, mobile-friendly, two-pane layout |
| XSS protection | ✅ Done | All dynamic content escaped via DOM `textContent` |
| Redis-backed rate limiter | ✅ Done | Shared rate limiting across all workers/containers via Redis; falls back to in-memory for local dev |

### 10.2 Yet to Implement

- Loading spinner animation during API calls — deferred; luxury feature
- Syntax highlighting for YAML and JSON editors — deferred; may slow down at 10K+ lines
- Footer with version info and links — deferred; luxury feature
- Persistent storage / match history — deferred; luxury feature
- User authentication and session management — deferred; luxury feature
- Log source filtering (match `logsource` fields against log metadata) — deferred; requires building a log-source taxonomy/fingerprinting layer with no universal standard across SIEMs
- Sigma rule `timeframe` condition support — partial: rules with `timeframe` are detected and a warning is shown; full temporal aggregation deferred
- Field name mapping / field aliases — deferred; requires maintaining a large vendor-specific mapping table (Sigma generic fields → Sysmon/ECS/Splunk CIM/etc.)
- CI/CD pipeline (GitHub Actions)
- Production deployment guide (Nginx reverse proxy, HTTPS, systemd)
