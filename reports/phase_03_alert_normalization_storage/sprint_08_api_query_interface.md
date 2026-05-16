# Sprint 8 Report: API Layer and Runtime Query Interface

## Sprint Goal

Expose normalized runtime data through FastAPI without exposing hidden ground truth.

## Why This Sprint Matters

Later modules need a clean runtime API for alerts, evidence, rules, MITRE references, and metrics. This API gives those modules a stable query interface while keeping evaluation-only labels and casebook data disabled by default.

## Deliverables

- `src/safeagentsoc/api/main.py`
- `src/safeagentsoc/api/dependencies.py`
- `src/safeagentsoc/api/utils.py`
- `src/safeagentsoc/api/routes_alerts.py`
- `src/safeagentsoc/api/routes_evidence.py`
- `src/safeagentsoc/api/routes_metrics.py`
- `src/safeagentsoc/api/routes_eval.py`
- `docs/phase_03_alert_normalization_storage/api_reference.md`
- `tests/test_api_static.py`

## Runtime Endpoints

- `GET /health`
- `GET /alerts`
- `GET /alerts/{alert_uid}`
- `GET /evidence/{evidence_id}`
- `GET /rules/{rule_id}`
- `GET /mitre/{technique_id}`
- `GET /metrics/normalization`
- `GET /metrics/runtime-summary`

## Runtime Filters

`GET /alerts` supports:

- agent name
- platform
- rule ID
- rule level
- decoder name
- event category
- event action
- event outcome
- normalized severity
- MITRE technique ID
- timestamp range
- source
- normalization status

## Evaluation Endpoints

Evaluation endpoints are implemented under `/eval`, but disabled by default.

They require:

- `SAFEAGENTSOC_ENABLE_EVAL_API=true`
- optional `SAFEAGENTSOC_EVAL_API_TOKEN`
- `X-Eval-Token` header when a token is configured

## Runtime/Evaluation Boundary

Runtime routes use the runtime repository and runtime views. Evaluation routes are separate, opt-in, and documented as unavailable to runtime or AI modules.

## Install and Run

```powershell
py -m pip install "fastapi[standard]" "uvicorn[standard]" "psycopg[binary]"
$env:SAFEAGENTSOC_DATABASE_URL = "postgresql://safeagentsoc:safeagentsoc@localhost:5432/safeagentsoc"
$env:PYTHONPATH = "src"
py -m uvicorn safeagentsoc.api.main:app --reload --host 127.0.0.1 --port 8000
```

## Sprint 8 Done Criteria

- [x] API source files exist
- [x] Health endpoint exists
- [x] Alerts endpoint exists
- [x] Single alert lookup exists
- [x] Evidence lookup exists
- [x] Rule lookup exists
- [x] MITRE lookup exists
- [x] Normalization metrics endpoint exists
- [x] Runtime summary endpoint exists
- [x] Evaluation routes are separate and disabled by default
- [x] API reference exists
- [ ] API started locally against PostgreSQL

## Notes

The Codex shell does not have FastAPI, Uvicorn, or psycopg installed. The API should be started from your PostgreSQL-ready PowerShell after installing dependencies.
