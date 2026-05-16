from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.adapters.wazuh.jsonl_parser import ParsedWazuhAlert
from safeagentsoc.normalization.event_taxonomy import infer_event_category, infer_event_outcome
from safeagentsoc.normalization.normalizer import normalize_alert
from safeagentsoc.normalization.severity import normalize_severity


def sample_lineage() -> dict[str, str]:
    return {
        "alert_uid": "alert_123",
        "evidence_id": "evidence_123",
        "raw_alert_sha256": "a" * 64,
        "raw_file_sha256": "b" * 64,
        "raw_file_name": "raw_alerts_full.jsonl",
        "raw_line_number": "1",
        "source_system": "wazuh",
        "source_adapter": "wazuh_jsonl_v1",
        "ingestion_batch_id": "phase3_v1",
        "ingested_at_utc": "2026-05-16T00:00:00+00:00",
    }


def sample_alert() -> ParsedWazuhAlert:
    raw = {
        "timestamp": "2026-05-15T00:00:00Z",
        "id": "abc",
        "agent": {"id": "001", "name": "win01", "ip": "10.0.0.5"},
        "rule": {
            "id": "92004",
            "level": 4,
            "description": "Powershell process spawned Windows command shell instance",
            "groups": ["windows", "powershell"],
            "firedtimes": 1,
            "mitre": {"id": ["T1059.001"], "tactic": ["Execution"], "technique": ["PowerShell"]},
        },
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "data": {
            "win": {
                "eventdata": {
                    "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "commandLine": "powershell.exe -NoProfile",
                    "user": "LAB\\mohamed",
                }
            }
        },
    }
    return ParsedWazuhAlert(raw=raw, raw_line="{}", line_number=1)


def test_severity_mapping():
    assert normalize_severity(3)[0] == "low"
    assert normalize_severity(7)[0] == "medium"
    assert normalize_severity(11)[0] == "high"
    assert normalize_severity(12)[0] == "critical"


def test_event_taxonomy_mapping():
    assert infer_event_category("Successful sudo to ROOT executed.", "sudo", []) == "privilege_activity"
    assert infer_event_category("Powershell process spawned Windows command shell instance", "windows_eventchannel", []) == "process_execution"
    assert infer_event_outcome("Apparmor DENIED", 3) == "blocked"


def test_normalized_alert_has_runtime_shape_and_no_labels():
    normalized, warnings, errors = normalize_alert(sample_alert(), sample_lineage(), "2026-05-16T00:00:00+00:00")

    assert errors == []
    assert normalized is not None
    assert normalized["alert_uid"] == "alert_123"
    assert normalized["schema_version"] == "1.0.0"
    assert normalized["source"]["source_system"] == "wazuh"
    assert normalized["event"]["category"] == "process_execution"
    assert normalized["severity"]["normalized"] == "medium"
    assert normalized["mitre"]["technique_ids"] == ["T1059.001"]
    assert normalized["evidence"]["raw_line_number"] == 1

    raw_text = str(normalized).lower()
    assert "ground_truth" not in raw_text
    assert "casebook" not in raw_text
    assert "expected_conclusion" not in raw_text
