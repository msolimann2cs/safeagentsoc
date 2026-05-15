import csv
import json
from pathlib import Path
from datetime import datetime

alerts_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/full/raw_alerts_full.jsonl")
run_log_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/scenario_run_log_frozen.csv")
out_dir = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/per_run")
out_dir.mkdir(parents=True, exist_ok=True)


def parse_ts(value):
    if not value:
        return None
    value = value.strip().replace("Z", "+00:00")
    if len(value) >= 5 and (value[-5] in ["+", "-"]) and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]
    try:
        return datetime.fromisoformat(value)
    except Exception:
        return None


runs = []
with run_log_file.open("r", encoding="utf-8", errors="ignore") as f:
    reader = csv.DictReader(f)
    for row in reader:
        start = parse_ts(row.get("start_ts", ""))
        end = parse_ts(row.get("end_ts", ""))
        if not start or not end:
            continue
        runs.append({
            "run_id": row.get("run_id", ""),
            "scenario_id": row.get("scenario_id", ""),
            "campaign_id": row.get("campaign_id", ""),
            "host": row.get("host", ""),
            "execution_mode": row.get("execution_mode", ""),
            "tool": row.get("tool", ""),
            "start": start,
            "end": end,
        })

alerts = []
with alerts_file.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        ts = parse_ts(alert.get("timestamp", ""))
        if ts:
            alerts.append((ts, alert))

summary = []

for run in runs:
    rows = []
    for ts, alert in alerts:
        agent_name = alert.get("agent", {}).get("name", "")
        if run["start"] <= ts <= run["end"]:
            if not run["host"] or run["host"] == agent_name:
                alert["_safesoc_correlation"] = {
                    "run_id": run["run_id"],
                    "scenario_id": run["scenario_id"],
                    "campaign_id": run["campaign_id"],
                    "execution_mode": run["execution_mode"],
                    "tool": run["tool"],
                    "start_ts": run["start"].isoformat(),
                    "end_ts": run["end"].isoformat(),
                }
                rows.append(alert)

    out = out_dir / f"{run['run_id']}_alerts.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")

    summary.append((run["run_id"], len(rows), str(out)))

summary_file = out_dir / "per_run_export_summary.csv"
with summary_file.open("w", encoding="utf-8") as f:
    f.write("run_id,alert_count,file\n")
    for run_id, count, file in summary:
        f.write(f"{run_id},{count},{file}\n")

print(summary_file)
for item in summary:
    print(item)
