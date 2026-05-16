from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.adapters.wazuh.jsonl_parser import flatten_json, parse_wazuh_jsonl


def test_jsonl_parser_counts_valid_invalid_and_blank_lines(tmp_path: Path):
    sample = tmp_path / "sample.jsonl"
    sample.write_text('{"timestamp":"2026-05-16T00:00:00Z","rule":{"id":"1"}}\n\nnot-json\n[]\n', encoding="utf-8")

    result = parse_wazuh_jsonl(sample)

    assert result.total_lines == 4
    assert result.blank_lines == 1
    assert result.parsed_count == 1
    assert result.invalid_count == 2
    assert result.alerts[0].line_number == 1


def test_flatten_json_preserves_nested_wazuh_fields():
    raw = {
        "agent": {"name": "win01"},
        "rule": {"mitre": {"id": ["T1059.001"]}},
    }

    flattened = flatten_json(raw)

    assert flattened["agent.name"] == "win01"
    assert flattened["rule.mitre.id"] == ["T1059.001"]
    assert flattened["rule.mitre.id[]"] == "T1059.001"
