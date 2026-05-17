from __future__ import annotations

from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.cases.case_builder import build_case_outputs


def main() -> int:
    output_root = WORKSPACE_ROOT / "06_data" / "phase_05_case_builder_alert_compression"
    enriched_alerts = WORKSPACE_ROOT / "03_data" / "context" / "exports" / "context_enriched_alerts_with_risk.jsonl"
    build_case_outputs(enriched_alerts, output_root)
    print(f"[OK] Case review pack refreshed at {output_root / 'review_packs' / 'case_review_pack.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

