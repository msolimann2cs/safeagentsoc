# SafeAgentSOC Runtime API Reference

## Purpose

Sprint 8 exposes normalized runtime data through FastAPI without exposing hidden ground truth by default.

## Install Requirements

From the repo root:

```powershell
py -m pip install "fastapi[standard]" "uvicorn[standard]" "psycopg[binary]"
```

## Connection String

```powershell
$env:SAFEAGENTSOC_DATABASE_URL = "postgresql://safeagentsoc:safeagentsoc@localhost:5432/safeagentsoc"
```

## Start API

```powershell
$env:PYTHONPATH = "src"
py -m uvicorn safeagentsoc.api.main:app --reload --host 127.0.0.1 --port 8000
```

Open:

```text
http://127.0.0.1:8000/docs
```

## Runtime Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Service health |
| GET | `/alerts` | List runtime alerts |
| GET | `/alerts/{alert_uid}` | Fetch one runtime alert |
| GET | `/evidence/{evidence_id}` | Fetch evidence reference |
| GET | `/rules/{rule_id}` | Fetch runtime rule summary |
| GET | `/mitre/{technique_id}` | Fetch runtime MITRE technique reference |
| GET | `/metrics/normalization` | Fetch normalization metrics |
| GET | `/metrics/runtime-summary` | Fetch runtime database summary |

## Alert Filters

`GET /alerts` supports:

- `agent_name`
- `platform`
- `rule_id`
- `rule_level`
- `decoder_name`
- `event_category`
- `event_action`
- `event_outcome`
- `normalized_severity`
- `mitre_technique_id`
- `timestamp_from`
- `timestamp_to`
- `source`
- `normalization_status`
- `limit`
- `offset`

Example:

```powershell
Invoke-RestMethod "http://127.0.0.1:8000/alerts?platform=linux&normalized_severity=high&limit=10"
```

## Evaluation Endpoints

Evaluation endpoints are disabled by default:

| Method | Path | Purpose |
|---|---|---|
| GET | `/eval/labels/{alert_uid}` | Evaluation-only labels |
| GET | `/eval/casebook` | Evaluation-only casebook metadata |
| GET | `/eval/fatigue-baseline` | Evaluation-only fatigue baseline |
| GET | `/eval/linkage-metrics` | Evaluation linkage metrics |

To enable evaluator endpoints:

```powershell
$env:SAFEAGENTSOC_ENABLE_EVAL_API = "true"
$env:SAFEAGENTSOC_EVAL_API_TOKEN = "local-eval-token"
```

Then send:

```text
X-Eval-Token: local-eval-token
```

Evaluation endpoints are not for runtime or AI modules.

## Runtime Safety Rule

Runtime endpoints query only `safeagentsoc_runtime` views and tables. They do not expose labels, casebook answers, expected conclusions, gold links, true-positive fields, or false-positive fields.
