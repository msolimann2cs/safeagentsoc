from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.evidence.uid import build_alert_uid, build_evidence_id, natural_alert_fingerprint, sha256_text


def sample_raw_alert() -> dict:
    return {
        "timestamp": "2026-05-16T00:00:00Z",
        "agent": {"name": "win01"},
        "rule": {"id": "92004"},
        "decoder": {"name": "windows_eventchannel"},
        "location": "EventChannel",
        "full_log": "process started",
    }


def test_alert_uid_is_deterministic_for_same_evidence_fields():
    raw = sample_raw_alert()

    first = build_alert_uid(raw, raw_line_number=7)
    second = build_alert_uid(dict(raw), raw_line_number=7)

    assert first == second
    assert first.startswith("alert_")


def test_alert_uid_line_disambiguator_changes_duplicate_uid():
    raw = sample_raw_alert()

    first = build_alert_uid(raw, raw_line_number=7, use_line_disambiguator=True)
    second = build_alert_uid(raw, raw_line_number=8, use_line_disambiguator=True)

    assert first != second
    assert natural_alert_fingerprint(raw) == natural_alert_fingerprint(dict(raw))


def test_evidence_id_binds_alert_hash_and_batch():
    evidence_id = build_evidence_id("alert_123", sha256_text("raw"), "phase3_v1")

    assert evidence_id.startswith("evidence_")
    assert evidence_id == build_evidence_id("alert_123", sha256_text("raw"), "phase3_v1")
