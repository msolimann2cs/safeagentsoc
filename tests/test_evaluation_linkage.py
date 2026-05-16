from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.evaluation.linkage import build_label_crosswalk, build_normalized_index


def test_label_crosswalk_links_phase2_alert_id_to_phase3_alert_uid():
    normalized_alert = {
        "alert_uid": "alert_123",
        "source": {"source_event_id": "source-1", "source_location": "/var/log/auth.log"},
        "timestamps": {
            "source_time_raw": "2026-05-14T23:41:36.705-0400",
            "event_time_utc": "2026-05-15T03:41:36.705000+00:00",
        },
        "host": {"agent_name": "safesoc-lnx-01"},
        "rule": {"rule_id": "5402", "rule_description": "Successful sudo to ROOT executed."},
        "event": {"category": "privilege_activity", "action": "sudo_success", "outcome": "success"},
        "severity": {"normalized": "low"},
        "mitre": {"technique_ids": ["T1548.003"]},
        "normalization": {"status": "success"},
        "evidence": {
            "evidence_id": "evidence_123",
            "raw_file_name": "raw_alerts_full.jsonl",
            "raw_line_number": 5603,
            "raw_alert_sha256": "a" * 64,
        },
    }
    labels = [
        {
            "label_id": "LBL-000001",
            "alert_uid": "ALERT-939476A8BF516E30",
            "agent_name": "safesoc-lnx-01",
            "timestamp": "2026-05-14T23:41:36.705-0400",
            "rule_id": "5402",
            "rule_description": "Successful sudo to ROOT executed.",
            "run_id": "C-LNX-01-CAL-R001",
            "label": "attack_like",
            "event_role": "trigger",
        }
    ]

    crosswalk, candidates = build_label_crosswalk(labels, build_normalized_index([normalized_alert]), {"C-LNX-01-CAL-R001": "CASE-001"})

    assert crosswalk[0]["phase2_alert_uid"] == "ALERT-939476A8BF516E30"
    assert crosswalk[0]["primary_phase3_alert_uid"] == "alert_123"
    assert crosswalk[0]["case_id"] == "CASE-001"
    assert candidates[0]["evidence_id"] == "evidence_123"
