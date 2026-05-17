from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.reason.evidence_verifier import verify_evidence
from safeagentsoc.reason.recommended_checks import validate_recommended_checks
from safeagentsoc.reason.schema_validator import validate_hypothesis_response
from safeagentsoc.reason.unsupported_claim_detector import detect_unsupported_claims


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Validate Phase 7 raw hypothesis outputs.")
    parser.add_argument(
        "--context-pack",
        type=Path,
        default=WORKSPACE_ROOT / "06_data" / "Phase6" / "timelines" / "exports" / "case_llm_context_pack.jsonl",
    )
    parser.add_argument("--raw", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason" / "outputs" / "llm_hypotheses_raw.jsonl")
    parser.add_argument("--output-dir", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason" / "qa")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    contexts = {row["case_id"]: row for row in read_jsonl(args.context_pack)}
    raw_outputs = read_jsonl(args.raw)
    rows: list[dict[str, object]] = []
    for raw in raw_outputs:
        case_id = raw.get("case_id")
        context = contexts.get(str(case_id), {})
        schema = validate_hypothesis_response(raw, context)
        evidence = verify_evidence(raw, context) if schema["schema_valid"] else {"evidence_validation_status": "skipped", "evidence_support_rate": 0}
        unsupported = detect_unsupported_claims(raw, context) if schema["schema_valid"] else {"unsupported_claim_count": 1}
        checks_ok = False
        if schema["schema_valid"]:
            check_rows = []
            for hypothesis in raw.get("hypotheses") or []:
                check_rows.extend(validate_recommended_checks([str(item) for item in hypothesis.get("recommended_checks") or []])["rows"])
            checks_ok = bool(check_rows) and all(row["allowed"] for row in check_rows)
        rows.append(
            {
                "case_id": case_id,
                "schema_validation_status": schema["schema_validation_status"],
                "schema_errors": schema["schema_errors"],
                "evidence_validation_status": evidence["evidence_validation_status"],
                "evidence_support_rate": evidence["evidence_support_rate"],
                "unsupported_claim_count": unsupported["unsupported_claim_count"],
                "recommended_checks_valid": checks_ok,
            }
        )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_csv(args.output_dir / "hypothesis_revalidation_report.csv", rows)
    print(f"[OK] Revalidated {len(rows)} hypothesis outputs")
    print(f"[OK] Wrote report to {args.output_dir / 'hypothesis_revalidation_report.csv'}")
    return 0


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_csv(path: Path, rows: list[dict[str, object]]) -> None:
    fieldnames: list[str] = []
    for row in rows:
        for key in row:
            if key not in fieldnames:
                fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: json.dumps(value, sort_keys=True) if isinstance(value, (list, dict)) else value for key, value in row.items()})


if __name__ == "__main__":
    raise SystemExit(main())
