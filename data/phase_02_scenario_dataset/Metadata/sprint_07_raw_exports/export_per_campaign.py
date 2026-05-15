import json
from pathlib import Path
from collections import defaultdict

per_run_dir = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/per_run")
out_dir = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/per_campaign")
out_dir.mkdir(parents=True, exist_ok=True)

campaigns = defaultdict(list)

for file in per_run_dir.glob("*_alerts.jsonl"):
    with file.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            try:
                alert = json.loads(line)
            except json.JSONDecodeError:
                continue
            corr = alert.get("_safesoc_correlation", {})
            campaign_id = corr.get("campaign_id", "")
            if campaign_id:
                campaigns[campaign_id].append(alert)

summary = []

for campaign_id, rows in campaigns.items():
    out = out_dir / f"{campaign_id}_alerts.jsonl"
    with out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")
    summary.append((campaign_id, len(rows), str(out)))

summary_file = out_dir / "per_campaign_export_summary.csv"
with summary_file.open("w", encoding="utf-8") as f:
    f.write("campaign_id,alert_count,file\n")
    for campaign_id, count, file in summary:
        f.write(f"{campaign_id},{count},{file}\n")

print(summary_file)
for item in summary:
    print(item)
