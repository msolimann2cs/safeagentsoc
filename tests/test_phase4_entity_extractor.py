from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.entity_extractor import extract_observed_entities


def test_extract_observed_entities_uses_runtime_fields_only():
    alerts = [
        {
            "alert_uid": "alert_1",
            "timestamps": {"event_time_utc": "2026-05-15T00:00:00+00:00"},
            "host": {
                "hostname": "safesoc-win-01",
                "agent_name": "safesoc-win-01",
                "agent_ip": "10.10.10.21",
                "platform": "windows",
            },
            "entities": {
                "user": {"username": "Administrator", "domain": "LAB"},
                "process": {"name": "powershell.exe", "command_line": "powershell.exe -NoProfile", "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"},
                "network": {"src_ip": "10.10.10.21", "dst_ip": None},
            },
            "rule": {"rule_id": "92004", "rule_level": 4, "rule_description": "PowerShell activity"},
            "mitre": {"technique_ids": ["T1059.001"], "tactics": ["Execution"]},
            "event": {"category": "process_execution", "action": "powershell_execution"},
            "severity": {"normalized": "medium"},
        }
    ]

    extracted = extract_observed_entities(alerts)

    assert extracted["hosts"][0]["observed_host"] == "safesoc-win-01"
    assert extracted["hosts"][0]["alert_count"] == 1
    assert extracted["users"][0]["observed_username"] == "Administrator"
    assert extracted["processes"][0]["process_name"] == "powershell.exe"
    assert extracted["rules"][0]["rule_id"] == "92004"

