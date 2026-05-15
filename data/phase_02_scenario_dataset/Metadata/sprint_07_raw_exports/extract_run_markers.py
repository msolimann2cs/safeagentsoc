import json
import re
from pathlib import Path

input_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/full/raw_alerts_full.jsonl")
output_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/run_markers_found.csv")

run_id_re = re.compile(r"RUN_ID=([A-Za-z0-9_.-]+)")

rows = []

with input_file.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        full_log = alert.get("full_log", "")
        match = run_id_re.search(full_log)
        if match:
            rows.append({
                "timestamp": alert.get("timestamp", ""),
                "agent_name": alert.get("agent", {}).get("name", ""),
                "run_id": match.group(1),
                "rule_id": alert.get("rule", {}).get("id", ""),
                "rule_level": alert.get("rule", {}).get("level", ""),
                "rule_description": alert.get("rule", {}).get("description", ""),
                "full_log": full_log.replace("\n", " ")[:500],
            })

with output_file.open("w", encoding="utf-8") as f:
    f.write("timestamp,agent_name,run_id,rule_id,rule_level,rule_description,full_log\n")
    for r in rows:
        values = [
            r["timestamp"],
            r["agent_name"],
            r["run_id"],
            str(r["rule_id"]),
            str(r["rule_level"]),
            r["rule_description"].replace(",", " "),
            r["full_log"].replace(",", " "),
        ]
        f.write(",".join(values) + "\n")

print(f"Found {len(rows)} run-marker alerts")
print(output_file)

