import json
from pathlib import Path

input_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/full/raw_alerts_full.jsonl")
out_dir = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/per_agent")
out_dir.mkdir(parents=True, exist_ok=True)

agents = {
    "safesoc-win-01": [],
    "safesoc-lnx-01": [],
    "safesoc-wazuh-01": [],
}

unknown = []

with input_file.open("r", encoding="utf-8", errors="ignore") as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        agent_name = alert.get("agent", {}).get("name", "unknown")

        if agent_name in agents:
            agents[agent_name].append(alert)
        else:
            unknown.append(alert)

for agent, rows in agents.items():
    out = out_dir / f"{agent}_alerts.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    print(agent, len(rows), out)

with (out_dir / "unknown_alerts.jsonl").open("w", encoding="utf-8") as f:
    for row in unknown:
        f.write(json.dumps(row) + "\n")

print("unknown", len(unknown))

