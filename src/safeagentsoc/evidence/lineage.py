from __future__ import annotations

import argparse
from collections import Counter
import csv
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any

from safeagentsoc.adapters.wazuh.jsonl_parser import parse_wazuh_jsonl
from safeagentsoc.evidence.uid import (
    UID_STRATEGY_VERSION,
    build_alert_uid,
    build_evidence_id,
    natural_alert_fingerprint,
    sha256_file,
    sha256_text,
)


LINEAGE_FIELDS = [
    "alert_uid",
    "evidence_id",
    "raw_alert_sha256",
    "raw_file_sha256",
    "raw_file_name",
    "raw_line_number",
    "source_system",
    "source_adapter",
    "ingestion_batch_id",
    "ingested_at_utc",
    "normalizer_version",
    "uid_strategy_version",
    "natural_alert_fingerprint",
    "natural_fingerprint_count",
    "uid_disambiguation",
]


EVIDENCE_REFERENCE_FIELDS = [
    "evidence_id",
    "alert_uid",
    "raw_alert_sha256",
    "raw_file_sha256",
    "raw_file_name",
    "raw_line_number",
    "ingestion_batch_id",
    "source_system",
    "source_adapter",
    "evidence_confidence",
]


@dataclass(frozen=True)
class RawAlertLineage:
    alert_uid: str
    evidence_id: str
    raw_alert_sha256: str
    raw_file_sha256: str
    raw_file_name: str
    raw_line_number: int
    source_system: str
    source_adapter: str
    ingestion_batch_id: str
    ingested_at_utc: str
    normalizer_version: str
    uid_strategy_version: str
    natural_alert_fingerprint: str
    natural_fingerprint_count: int
    uid_disambiguation: str


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_raw_alert_lineage(
    input_path: Path,
    ingestion_batch_id: str,
    source_system: str = "wazuh",
    source_adapter: str = "wazuh_jsonl_v1",
    normalizer_version: str = "not_normalized_yet",
    ingested_at_utc: str | None = None,
) -> tuple[list[RawAlertLineage], dict[str, Any]]:
    parse_result = parse_wazuh_jsonl(input_path)
    raw_file_sha256 = sha256_file(input_path)
    natural_fingerprints = [
        natural_alert_fingerprint(alert.raw)
        for alert in parse_result.alerts
    ]
    natural_counts = Counter(natural_fingerprints)
    seen_alert_uids: set[str] = set()
    lineages: list[RawAlertLineage] = []
    ingested_at = ingested_at_utc or utc_now_iso()

    for alert, natural_fingerprint in zip(parse_result.alerts, natural_fingerprints):
        duplicate_count = natural_counts[natural_fingerprint]
        use_line_disambiguator = duplicate_count > 1
        alert_uid = build_alert_uid(
            alert.raw,
            raw_line_number=alert.line_number,
            use_line_disambiguator=use_line_disambiguator,
        )
        raw_alert_sha256 = sha256_text(alert.raw_line)
        evidence_id = build_evidence_id(alert_uid, raw_alert_sha256, ingestion_batch_id)

        if alert_uid in seen_alert_uids:
            raise ValueError(f"Duplicate alert_uid generated: {alert_uid}")
        seen_alert_uids.add(alert_uid)

        lineages.append(
            RawAlertLineage(
                alert_uid=alert_uid,
                evidence_id=evidence_id,
                raw_alert_sha256=raw_alert_sha256,
                raw_file_sha256=raw_file_sha256,
                raw_file_name=input_path.name,
                raw_line_number=alert.line_number,
                source_system=source_system,
                source_adapter=source_adapter,
                ingestion_batch_id=ingestion_batch_id,
                ingested_at_utc=ingested_at,
                normalizer_version=normalizer_version,
                uid_strategy_version=UID_STRATEGY_VERSION,
                natural_alert_fingerprint=natural_fingerprint,
                natural_fingerprint_count=duplicate_count,
                uid_disambiguation="raw_line_number" if use_line_disambiguator else "none",
            )
        )

    summary = {
        "input_file": str(input_path),
        "raw_file_name": input_path.name,
        "raw_file_sha256": raw_file_sha256,
        "total_lines": parse_result.total_lines,
        "parsed_alerts": parse_result.parsed_count,
        "invalid_json_lines": parse_result.invalid_count,
        "blank_lines": parse_result.blank_lines,
        "unique_alert_uids": len(seen_alert_uids),
        "natural_duplicate_groups": sum(1 for count in natural_counts.values() if count > 1),
        "alerts_disambiguated_by_line": sum(1 for lineage in lineages if lineage.uid_disambiguation == "raw_line_number"),
        "ingestion_batch_id": ingestion_batch_id,
        "source_system": source_system,
        "source_adapter": source_adapter,
        "normalizer_version": normalizer_version,
        "uid_strategy_version": UID_STRATEGY_VERSION,
        "ingested_at_utc": ingested_at,
    }

    return lineages, summary


def write_lineage_csv(path: Path, lineages: list[RawAlertLineage]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=LINEAGE_FIELDS)
        writer.writeheader()
        writer.writerows(asdict(lineage) for lineage in lineages)


def write_evidence_reference_csv(path: Path, lineages: list[RawAlertLineage]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=EVIDENCE_REFERENCE_FIELDS)
        writer.writeheader()
        for lineage in lineages:
            writer.writerow(
                {
                    "evidence_id": lineage.evidence_id,
                    "alert_uid": lineage.alert_uid,
                    "raw_alert_sha256": lineage.raw_alert_sha256,
                    "raw_file_sha256": lineage.raw_file_sha256,
                    "raw_file_name": lineage.raw_file_name,
                    "raw_line_number": lineage.raw_line_number,
                    "ingestion_batch_id": lineage.ingestion_batch_id,
                    "source_system": lineage.source_system,
                    "source_adapter": lineage.source_adapter,
                    "evidence_confidence": "high",
                }
            )


def write_batch_manifest(path: Path, summary: dict[str, Any]) -> None:
    source_path = str(summary["input_file"]).replace("'", "''")
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "phase: phase_03_alert_normalization_storage",
        f"batch_id: {summary['ingestion_batch_id']}",
        "status: lineage_generated",
        f"created_at_utc: {summary['ingested_at_utc']}",
        f"source_system: {summary['source_system']}",
        f"source_adapter: {summary['source_adapter']}",
        f"normalizer_version: {summary['normalizer_version']}",
        f"uid_strategy_version: {summary['uid_strategy_version']}",
        "input:",
        f"  file_name: {summary['raw_file_name']}",
        f"  source_path: '{source_path}'",
        f"  raw_file_sha256: {summary['raw_file_sha256']}",
        "counts:",
        f"  total_lines: {summary['total_lines']}",
        f"  parsed_alerts: {summary['parsed_alerts']}",
        f"  invalid_json_lines: {summary['invalid_json_lines']}",
        f"  blank_lines: {summary['blank_lines']}",
        f"  unique_alert_uids: {summary['unique_alert_uids']}",
        f"  natural_duplicate_groups: {summary['natural_duplicate_groups']}",
        f"  alerts_disambiguated_by_line: {summary['alerts_disambiguated_by_line']}",
        "outputs:",
        "  raw_alert_lineage: 06_data/phase_03_alert_normalization_storage/lineage/raw_alert_lineage.csv",
        "  evidence_reference: 06_data/phase_03_alert_normalization_storage/lineage/evidence_reference.csv",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Generate SafeAgentSOC raw alert lineage and evidence references.")
    parser.add_argument("--input", required=True, type=Path, help="Path to raw Wazuh JSONL file.")
    parser.add_argument("--lineage-output", required=True, type=Path, help="Path for raw_alert_lineage.csv.")
    parser.add_argument("--evidence-output", required=True, type=Path, help="Path for evidence_reference.csv.")
    parser.add_argument("--manifest-output", required=True, type=Path, help="Path for normalization_batch_manifest.yaml.")
    parser.add_argument("--batch-id", default="phase3_v1")
    parser.add_argument("--source-system", default="wazuh")
    parser.add_argument("--source-adapter", default="wazuh_jsonl_v1")
    parser.add_argument("--normalizer-version", default="not_normalized_yet")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)

    if not args.input.exists():
        print(f"[FAIL] Input file not found: {args.input}", file=sys.stderr)
        return 1

    lineages, summary = build_raw_alert_lineage(
        input_path=args.input,
        ingestion_batch_id=args.batch_id,
        source_system=args.source_system,
        source_adapter=args.source_adapter,
        normalizer_version=args.normalizer_version,
    )
    write_lineage_csv(args.lineage_output, lineages)
    write_evidence_reference_csv(args.evidence_output, lineages)
    write_batch_manifest(args.manifest_output, summary)

    print(f"[OK] Parsed alerts: {summary['parsed_alerts']}")
    print(f"[OK] Unique alert UIDs: {summary['unique_alert_uids']}")
    print(f"[OK] Natural duplicate groups: {summary['natural_duplicate_groups']}")
    print(f"[OK] Alerts disambiguated by raw line number: {summary['alerts_disambiguated_by_line']}")
    print(f"[OK] Raw alert lineage: {args.lineage_output}")
    print(f"[OK] Evidence references: {args.evidence_output}")
    print(f"[OK] Batch manifest: {args.manifest_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
