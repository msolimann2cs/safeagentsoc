import json
from pathlib import Path

input_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/full/raw_alerts_full.jsonl")
out_file = Path("06_data/phase_02_scenario_dataset/sprint_07_raw_exports/sanitized_sample/sanitized_sample_alerts.jsonl")

out_file.parent.mkdir(parents=True, exist_ok=True)


def mask_ip(ip):
    if not isinstance(ip, str):
        return ip
    parts = ip.split(".")
    if len(parts) == 4:
        return f"{parts[0]}.{parts[1]}.x.x"
    return ip


def sanitize(alert):
    alert = dict(alert)

    if "agent" in alert and isinstance(alert["agent"], dict):
        if "ip" in alert["agent"]:
            alert["agent"]["ip"] = mask_ip(alert["agent"]["ip"])

    if "data" in alert and isinstance(alert["data"], dict):
        for key in ["srcip", "dstip"]:
            if key in alert["data"]:
                alert["data"][key] = mask_ip(alert["data"][key])

    if "full_log" in alert:
        alert["full_log"] = alert["full_log"][:500]

    return alert


count = 0
with input_file.open("r", encoding="utf-8", errors="ignore") as f, out_file.open("w", encoding="utf-8") as out:
    for line in f:
        if count >= 100:
            break
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.write(json.dumps(sanitize(alert)) + "\n")
        count += 1

print(f"Wrote {count} sanitized sample alerts to {out_file}")
