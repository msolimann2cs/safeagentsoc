from pathlib import Path
import json
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.evidence.lineage import build_raw_alert_lineage
from safeagentsoc.evidence.uid import build_alert_uid, natural_alert_fingerprint, sha256_text


def sample_alert() -> dict:
    return {
        "timestamp": "2026-05-15T00:00:00Z",
        "agent": {"name": "win01"},
        "rule": {"id": "1001"},
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "full_log": "sample raw evidence text",
    }


def test_alert_uid_is_deterministic():
    alert = sample_alert()

    first = build_alert_uid(alert, raw_line_number=1)
    second = build_alert_uid(alert, raw_line_number=999)

    assert first == second
    assert first.startswith("alert_")


def test_alert_uid_line_disambiguator_changes_duplicate_uid():
    alert = sample_alert()

    first = build_alert_uid(alert, raw_line_number=1, use_line_disambiguator=True)
    second = build_alert_uid(alert, raw_line_number=2, use_line_disambiguator=True)

    assert first != second


def test_natural_fingerprint_ignores_raw_line_number():
    alert = sample_alert()

    assert natural_alert_fingerprint(alert) == natural_alert_fingerprint(dict(alert))


def test_sha256_text_is_stable():
    assert sha256_text("abc") == sha256_text("abc")


def test_lineage_disambiguates_duplicate_natural_fingerprints(tmp_path):
    input_path = tmp_path / "raw_alerts_full.jsonl"
    alert = sample_alert()
    input_path.write_text(
        "\n".join([json.dumps(alert), json.dumps(alert)]) + "\n",
        encoding="utf-8",
    )

    lineages, summary = build_raw_alert_lineage(input_path, ingestion_batch_id="test_batch", ingested_at_utc="2026-05-15T00:00:00+00:00")

    assert len(lineages) == 2
    assert lineages[0].alert_uid != lineages[1].alert_uid
    assert lineages[0].uid_disambiguation == "raw_line_number"
    assert summary["unique_alert_uids"] == 2
    assert summary["alerts_disambiguated_by_line"] == 2
