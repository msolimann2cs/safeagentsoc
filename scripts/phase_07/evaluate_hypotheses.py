from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


WORKSPACE_ROOT = Path(__file__).resolve().parents[4]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Evaluate Phase 7 hypothesis grounding offline.")
    parser.add_argument("--reason-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason")
    parser.add_argument("--output-dir", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason" / "evaluation")
    parser.add_argument(
        "--ground-truth",
        type=Path,
        default=WORKSPACE_ROOT / "05_code" / "safeagentsoc" / "data" / "phase_02_scenario_dataset" / "Metadata" / "sprint_08_ground_truth" / "ground_truth_labels.csv",
    )
    parser.add_argument(
        "--casebook",
        type=Path,
        default=WORKSPACE_ROOT / "05_code" / "safeagentsoc" / "data" / "phase_02_scenario_dataset" / "Metadata" / "sprint_09_casebook" / "casebook.csv",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    validated = read_jsonl(args.reason_root / "validated" / "validated_hypotheses.jsonl")
    validation_rows = read_csv(args.reason_root / "qa" / "hypothesis_validation_report.csv")
    evidence_rows = read_csv(args.reason_root / "qa" / "evidence_support_report.csv")
    unsupported_rows = read_csv(args.reason_root / "qa" / "unsupported_claim_report.csv")
    check_rows = read_csv(args.reason_root / "qa" / "recommended_checks_report.csv")
    ledger_rows = read_jsonl(args.reason_root / "ledger" / "ai_decision_ledger.jsonl")
    metrics = {
        "evaluated_case_count": len(validated),
        "schema_compliance_rate": rate(validation_rows, "schema_valid", "True"),
        "evidence_support_rate": mean_float(evidence_rows, "evidence_support_rate"),
        "unsupported_claim_rate": rate_inverse(unsupported_rows, "claim_status", "supported"),
        "missing_evidence_identification_rate": rate_hypotheses_with(validated, "missing_evidence"),
        "recommended_check_relevance": rate(check_rows, "allowed", "True"),
        "decision_traceability_score": round(len(ledger_rows) / max(len(validation_rows), 1), 4),
        "ground_truth_rows_available_offline": count_csv_rows(args.ground_truth),
        "casebook_rows_available_offline": count_csv_rows(args.casebook),
        "runtime_leakage_boundary": "evaluation_only_no_runtime_writes",
    }
    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_metric_csv(args.output_dir / "phase_07_evaluation_metrics.csv", metrics)
    write_report(args.output_dir / "llm_grounding_report.md", metrics)
    write_report(args.output_dir / "agent_firewall_evaluation.md", metrics)
    print(f"[OK] Evaluated Phase 7 hypotheses for {len(validated)} validated cases")
    print(f"[OK] Evidence support rate: {metrics['evidence_support_rate']}")
    print(f"[OK] Wrote evaluation to {args.output_dir}")
    return 0


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def read_csv(path: Path) -> list[dict]:
    if not path.exists():
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def count_csv_rows(path: Path) -> int:
    return len(read_csv(path))


def rate(rows: list[dict], key: str, expected: str) -> float:
    return round(sum(1 for row in rows if str(row.get(key)) == expected) / max(len(rows), 1), 4)


def rate_inverse(rows: list[dict], key: str, expected_safe: str) -> float:
    return round(sum(1 for row in rows if str(row.get(key)) != expected_safe) / max(len(rows), 1), 4)


def mean_float(rows: list[dict], key: str) -> float:
    values = [float(row.get(key) or 0) for row in rows]
    return round(sum(values) / max(len(values), 1), 4)


def rate_hypotheses_with(records: list[dict], key: str) -> float:
    hypotheses = [hypothesis for record in records for hypothesis in record.get("hypotheses", [])]
    return round(sum(1 for hypothesis in hypotheses if hypothesis.get(key)) / max(len(hypotheses), 1), 4)


def write_metric_csv(path: Path, metrics: dict[str, object]) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=["metric", "value"])
        writer.writeheader()
        for key, value in metrics.items():
            writer.writerow({"metric": key, "value": value})


def write_report(path: Path, metrics: dict[str, object]) -> None:
    path.write_text(
        "\n".join(
            [
                f"# {path.stem.replace('_', ' ').title()}",
                "",
                "This report may summarize offline evaluation availability, but it does not write answer-key labels into runtime outputs.",
                "",
                *[f"- {key}: {value}" for key, value in metrics.items()],
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )


if __name__ == "__main__":
    raise SystemExit(main())
