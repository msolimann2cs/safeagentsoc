import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.adapters.wazuh.jsonl_parser import flatten_json, parse_wazuh_jsonl
from safeagentsoc.ingestion.field_profiler import WazuhFieldProfiler


def test_parse_wazuh_jsonl_counts_invalid_lines(tmp_path):
    input_path = tmp_path / "alerts.jsonl"
    input_path.write_text(
        "\n".join(
            [
                json.dumps({"timestamp": "2026-05-15T00:00:00Z", "rule": {"id": "1001"}}),
                "{invalid json",
                "",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    result = parse_wazuh_jsonl(input_path)

    assert result.parsed_count == 1
    assert result.invalid_count == 1
    assert result.blank_lines == 1


def test_flatten_json_handles_nested_objects_and_lists():
    flattened = flatten_json({"rule": {"mitre": {"id": ["T1057"]}}, "agent": {"name": "host1"}})

    assert flattened["rule.mitre.id"] == ["T1057"]
    assert flattened["rule.mitre.id[]"] == "T1057"
    assert flattened["agent.name"] == "host1"


def test_profiler_counts_core_distributions():
    input_path = REPO_ROOT / "tests" / "_tmp_profile_alerts.jsonl"
    input_path.write_text(
        json.dumps(
            {
                "timestamp": "2026-05-15T00:00:00Z",
                "agent": {"id": "001", "name": "win01", "ip": "10.0.0.5"},
                "rule": {"id": "1001", "level": 7, "description": "test", "mitre": {"id": ["T1057"], "tactic": ["Discovery"]}},
                "decoder": {"name": "windows_eventchannel"},
                "location": "EventChannel",
            }
        ),
        encoding="utf-8",
    )

    try:
        result = parse_wazuh_jsonl(input_path)
        profile = WazuhFieldProfiler().profile(result.alerts)
    finally:
        input_path.unlink(missing_ok=True)

    assert profile["total_alerts"] == 1
    assert profile["agents"]["win01|001|10.0.0.5"] == 1
    assert profile["decoders"]["windows_eventchannel"] == 1
    assert profile["mitre_ids"]["T1057"] == 1
