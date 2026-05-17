from __future__ import annotations

import csv
from dataclasses import asdict
from datetime import UTC, datetime
import json
from pathlib import Path
from statistics import mean
from typing import Any

from safeagentsoc.timeline.attack_catalog import tactic_sort_key
from safeagentsoc.timeline.attack_story import build_attack_story, write_story_markdown
from safeagentsoc.timeline.claim_classifier import classify_technique_claim
from safeagentsoc.timeline.heatmap import build_heatmap_outputs
from safeagentsoc.timeline.kill_chain import build_kill_chain_progression
from safeagentsoc.timeline.missing_evidence import build_missing_evidence
from safeagentsoc.timeline.mitre_mapper import build_case_mitre_mappings
from safeagentsoc.timeline.schemas import TimelineBuildResult
from safeagentsoc.timeline.technique_confidence import score_technique_confidence


FORBIDDEN_RUNTIME_FIELDS = {
    "ground_truth",
    "expected_conclusion",
    "casebook_answer",
    "true_positive",
    "false_positive",
    "event_role",
    "scenario_label",
    "gold_label",
    "answer_key",
}


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def write_json(path: Path, row: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(row, sort_keys=True, indent=2, ensure_ascii=False), encoding="utf-8", newline="\n")


def write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if fieldnames is None:
        fieldnames = []
        for row in rows:
            for key in row:
                if key not in fieldnames:
                    fieldnames.append(key)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: csv_value(row.get(key)) for key in fieldnames})


def csv_value(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def build_timeline_outputs(generated_cases_path: Path, enriched_alerts_path: Path, output_root: Path) -> TimelineBuildResult:
    started = datetime.now(UTC)
    cases = read_jsonl(generated_cases_path)
    enriched_alerts = read_jsonl(enriched_alerts_path)
    alerts_by_uid = {str(alert["alert_uid"]): alert for alert in enriched_alerts}
    exports_dir = output_root / "exports"
    stories_dir = output_root / "stories"
    heatmaps_dir = output_root / "heatmaps"
    qa_dir = output_root / "qa"

    timelines: list[dict[str, Any]] = []
    all_steps: list[dict[str, Any]] = []
    all_claims: list[dict[str, Any]] = []
    all_missing: list[dict[str, Any]] = []
    all_stories: list[dict[str, Any]] = []
    all_kill_chain: list[dict[str, Any]] = []
    llm_context_pack: list[dict[str, Any]] = []
    unsupported_report: list[dict[str, Any]] = []

    for case in cases:
        mappings = build_case_mitre_mappings(case, alerts_by_uid)
        claims = build_technique_claims(mappings)
        steps = build_timeline_steps(case, claims, alerts_by_uid)
        missing = build_missing_evidence(case, claims)
        kill_chain = build_kill_chain_progression(case, claims)
        story = build_attack_story(case, steps, claims, missing, kill_chain)
        story_path = write_story_markdown(stories_dir, story)
        story["markdown_path"] = story_path
        timeline = {
            "case_id": case["case_id"],
            "case_title": case["case_title"],
            "case_priority_label": case["case_priority_label"],
            "primary_asset_id": case.get("primary_asset_id"),
            "primary_identity_id": case.get("primary_identity_id"),
            "business_unit": case.get("business_unit"),
            "business_service": case.get("business_service"),
            "timeline_step_count": len(steps),
            "technique_claim_count": len(claims),
            "missing_evidence_count": len(missing),
            "kill_chain_progression": kill_chain["progression_depth"],
            "timeline_steps": steps,
        }
        timelines.append(timeline)
        all_steps.extend(steps)
        all_claims.extend(claims)
        all_missing.extend(missing)
        all_stories.append(strip_markdown(story))
        all_kill_chain.append(kill_chain)
        llm_context_pack.append(build_llm_context(case, steps, claims, missing, story))
        unsupported_report.extend(
            {"case_id": case["case_id"], "warning": warning, "case_title": case["case_title"]}
            for warning in story.get("overclaiming_warnings", [])
        )

    matrix, by_case, tactic_summary, navigator_layer = build_heatmap_outputs(all_claims)
    metrics = build_quality_metrics(cases, timelines, all_steps, all_claims, all_missing, all_stories, all_kill_chain, unsupported_report, started)
    result = TimelineBuildResult(
        timelines=timelines,
        timeline_steps=all_steps,
        technique_claims=safe_claim_rows(all_claims),
        missing_evidence=all_missing,
        attack_stories=all_stories,
        kill_chain_progression=all_kill_chain,
        mitre_coverage_matrix=matrix,
        mitre_heatmap_by_case=by_case,
        mitre_tactic_summary=tactic_summary,
        navigator_layer=navigator_layer,
        llm_context_pack=llm_context_pack,
        unsupported_claim_report=unsupported_report,
        quality_metrics=metrics,
    )
    write_outputs(result, exports_dir, stories_dir, heatmaps_dir, qa_dir)
    return result


def build_technique_claims(mappings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    claims: list[dict[str, Any]] = []
    for mapping in mappings:
        confidence = score_technique_confidence(mapping)
        classification = classify_technique_claim(mapping, confidence)
        claim = {
            key: value
            for key, value in mapping.items()
            if key != "source_records"
        }
        claim.update(confidence)
        claim.update(classification)
        claims.append(claim)
    return claims


def build_timeline_steps(case: dict[str, Any], claims: list[dict[str, Any]], alerts_by_uid: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    sorted_claims = sorted(claims, key=lambda claim: (claim.get("first_seen") or "", tactic_sort_key(claim.get("tactic")), claim.get("technique_id") or ""))
    for claim in sorted_claims:
        steps.append(
            {
                "case_id": case["case_id"],
                "step_id": f"step_{len(steps) + 1:04d}",
                "event_time_utc": claim.get("first_seen") or case.get("case_start_time_utc"),
                "step_order": len(steps) + 1,
                "step_type": "technique_step",
                "tactic": claim.get("tactic"),
                "technique_id": claim.get("technique_id"),
                "technique_name": claim.get("technique_name"),
                "claim_type": claim.get("claim_type"),
                "confidence_score": claim.get("confidence_score"),
                "confidence_label": claim.get("confidence_label"),
                "alert_uids": claim.get("alert_uids") or [],
                "evidence_ids": claim.get("evidence_ids") or [],
                "rule_ids": rule_ids_for_alerts(claim.get("alert_uids") or [], alerts_by_uid),
                "behavior_family": first_value(claim.get("behavior_families")),
                "source_roles": claim.get("source_roles") or [],
                "duplicate_count": claim.get("duplicate_count") or 0,
                "collapsed_evidence_ids": collapsed_evidence_ids(claim),
                "first_seen": claim.get("first_seen"),
                "last_seen": claim.get("last_seen"),
                "evidence_summary": evidence_summary_for_claim(claim),
                "limitations": claim.get("limitations") or [],
            }
        )
    if not steps or is_backlog_case(case):
        steps.append(build_case_summary_step(case, len(steps) + 1))
    sorted_steps = sorted(steps, key=lambda step: (str(step.get("event_time_utc") or ""), int(step["step_order"])))
    for index, step in enumerate(sorted_steps, start=1):
        step["step_order"] = index
        step["step_id"] = f"step_{index:04d}"
    return sorted_steps


def build_case_summary_step(case: dict[str, Any], step_number: int) -> dict[str, Any]:
    step_type = "backlog_step" if is_backlog_case(case) else "behavior_step"
    visible_evidence = [
        link.get("evidence_id")
        for link in case.get("case_alerts", [])
        if str(link.get("visibility_level") or "").startswith("visible")
    ]
    collapsed = [
        link.get("evidence_id")
        for link in case.get("case_alerts", [])
        if str(link.get("visibility_level") or "").startswith("collapsed")
    ]
    return {
        "case_id": case["case_id"],
        "step_id": f"step_{step_number:04d}",
        "event_time_utc": case.get("case_start_time_utc"),
        "step_order": step_number,
        "step_type": step_type,
        "tactic": None,
        "technique_id": None,
        "technique_name": None,
        "claim_type": "observed",
        "confidence_score": round(float(case.get("case_confidence") or 0), 4),
        "confidence_label": "medium" if float(case.get("case_confidence") or 0) >= 0.55 else "low",
        "alert_uids": [link.get("alert_uid") for link in case.get("case_alerts", []) if str(link.get("visibility_level") or "").startswith("visible")],
        "evidence_ids": [item for item in visible_evidence if item],
        "rule_ids": case.get("rule_ids") or [],
        "behavior_family": case.get("primary_behavior_family"),
        "source_roles": ["trigger", "supporting"],
        "duplicate_count": case.get("duplicate_alert_count") or 0,
        "collapsed_evidence_ids": [item for item in collapsed if item],
        "first_seen": case.get("case_start_time_utc"),
        "last_seen": case.get("case_end_time_utc"),
        "evidence_summary": f"{case.get('case_title')} summarized with {case.get('visible_alert_count')} visible alerts and {case.get('suppressed_alert_count')} collapsed alerts.",
        "limitations": ["This step summarizes repeated or non-ATT&CK case activity rather than asserting a technique."],
    }


def write_outputs(result: TimelineBuildResult, exports_dir: Path, stories_dir: Path, heatmaps_dir: Path, qa_dir: Path) -> None:
    write_jsonl(exports_dir / "case_timelines.jsonl", result.timelines)
    write_csv(exports_dir / "case_timeline_steps.csv", result.timeline_steps)
    write_csv(exports_dir / "case_technique_claims.csv", result.technique_claims)
    write_jsonl(exports_dir / "case_missing_evidence.jsonl", result.missing_evidence)
    write_jsonl(exports_dir / "case_attack_stories.jsonl", result.attack_stories)
    write_csv(exports_dir / "kill_chain_progression_matrix.csv", result.kill_chain_progression)
    write_jsonl(exports_dir / "case_llm_context_pack.jsonl", result.llm_context_pack)
    write_csv(heatmaps_dir / "mitre_coverage_matrix.csv", result.mitre_coverage_matrix)
    write_csv(heatmaps_dir / "mitre_heatmap_by_case.csv", result.mitre_heatmap_by_case)
    write_csv(heatmaps_dir / "mitre_tactic_summary.csv", result.mitre_tactic_summary)
    write_json(heatmaps_dir / "attack_navigator_layer.json", result.navigator_layer)
    write_csv(qa_dir / "timeline_quality_metrics.csv", [{"metric": key, "value": value} for key, value in result.quality_metrics.items()])
    write_csv(qa_dir / "unsupported_claim_report.csv", result.unsupported_claim_report, ["case_id", "case_title", "warning"])
    write_csv(qa_dir / "missing_evidence_summary.csv", summarize_missing(result.missing_evidence))
    write_phase6_reports(stories_dir.parent, result)


def build_quality_metrics(
    cases: list[dict[str, Any]],
    timelines: list[dict[str, Any]],
    steps: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    missing: list[dict[str, Any]],
    stories: list[dict[str, Any]],
    kill_chain_rows: list[dict[str, Any]],
    unsupported: list[dict[str, Any]],
    started: datetime,
) -> dict[str, Any]:
    return {
        "timeline_builder_run_id": f"timeline_builder_run_{started.strftime('%Y%m%dT%H%M%SZ')}",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "total_cases_processed": len(cases),
        "cases_with_timeline": len(timelines),
        "cases_with_attack_story": len(stories),
        "cases_with_missing_evidence": len({row["case_id"] for row in missing}),
        "cases_with_kill_chain": len(kill_chain_rows),
        "total_timeline_steps": len(steps),
        "average_steps_per_case": round(len(steps) / len(cases), 4) if cases else 0,
        "observed_claim_count": sum(1 for claim in claims if claim.get("claim_type") == "observed"),
        "inferred_claim_count": sum(1 for claim in claims if claim.get("claim_type") == "inferred"),
        "unknown_claim_count": sum(1 for claim in claims if claim.get("claim_type") == "unknown"),
        "not_observed_claim_count": sum(1 for item in missing if item.get("status") == "not_observed"),
        "avg_technique_confidence": round(mean([float(claim.get("confidence_score") or 0) for claim in claims] or [0]), 4),
        "cases_with_no_mitre": sum(1 for timeline in timelines if timeline["technique_claim_count"] == 0),
        "cases_with_backlog_label": sum(1 for row in kill_chain_rows if row.get("progression_depth") == "telemetry_backlog"),
        "stories_with_evidence_ids": sum(1 for story in stories if story.get("evidence_ids")),
        "stories_with_missing_evidence": sum(1 for story in stories if story.get("missing_evidence")),
        "unsupported_claim_count_runtime": len(unsupported),
        "runtime_seconds": round((datetime.now(UTC) - started).total_seconds(), 4),
        "runtime_safety": "runtime_only_no_evaluation_artifacts",
    }


def build_llm_context(
    case: dict[str, Any],
    steps: list[dict[str, Any]],
    claims: list[dict[str, Any]],
    missing: list[dict[str, Any]],
    story: dict[str, Any],
) -> dict[str, Any]:
    return {
        "case_id": case["case_id"],
        "case_title": case["case_title"],
        "analyst_priority": case.get("case_priority_label"),
        "observed_timeline": [step for step in steps if step.get("claim_type") == "observed"],
        "observed_technique_chain": [
            {"tactic": claim["tactic"], "technique_id": claim["technique_id"], "confidence": claim["confidence_score"]}
            for claim in claims
            if claim.get("claim_type") == "observed"
        ],
        "inferred_relationships": [
            {"tactic": claim["tactic"], "technique_id": claim["technique_id"], "reason": claim.get("inference_reason")}
            for claim in claims
            if claim.get("claim_type") == "inferred"
        ],
        "missing_evidence": [entry for entry in missing if entry["status"] in {"not_observed", "unknown"}],
        "evidence_ids": story.get("evidence_ids") or [],
        "safe_conclusion": story["safe_conclusion"],
        "recommended_investigation_checks": story["recommended_investigation_checks"],
        "llm_forbidden_claims": story["llm_forbidden_claims"],
    }


def safe_claim_rows(claims: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{key: value for key, value in claim.items() if key != "source_records"} for claim in claims]


def strip_markdown(story: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in story.items() if key != "markdown"}


def is_backlog_case(case: dict[str, Any]) -> bool:
    title = str(case.get("case_title") or "").lower()
    family = str(case.get("primary_behavior_family") or "")
    return "vulnerability backlog" in title or family in {"wazuh_security_infrastructure", "sca_compliance_backlog", "linux_package_management"} and int(case.get("suppressed_alert_count") or 0) > int(case.get("visible_alert_count") or 0)


def first_value(values: list[Any] | None) -> Any:
    return values[0] if values else None


def rule_ids_for_alerts(alert_uids: list[str], alerts_by_uid: dict[str, dict[str, Any]]) -> list[str]:
    return sorted(
        {
            str(((alerts_by_uid.get(uid) or {}).get("original_alert_summary") or {}).get("rule_id"))
            for uid in alert_uids
            if ((alerts_by_uid.get(uid) or {}).get("original_alert_summary") or {}).get("rule_id")
        }
    )


def collapsed_evidence_ids(claim: dict[str, Any]) -> list[str]:
    collapsed: list[str] = []
    for record in claim.get("source_records") or []:
        link = record.get("link") or {}
        if str(link.get("visibility_level") or "").startswith("collapsed") and link.get("evidence_id"):
            collapsed.append(str(link["evidence_id"]))
    return collapsed


def evidence_summary_for_claim(claim: dict[str, Any]) -> str:
    verb = "observed" if claim.get("claim_type") == "observed" else "mapped"
    return f"{claim.get('technique_name')} ({claim.get('technique_id')}) {verb} for tactic {claim.get('tactic')} using {len(claim.get('evidence_ids') or [])} evidence record(s)."


def summarize_missing(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    counts: dict[tuple[str, str], int] = {}
    for row in rows:
        key = (row["missing_evidence_type"], row["status"])
        counts[key] = counts.get(key, 0) + 1
    return [
        {"missing_evidence_type": key[0], "status": key[1], "case_count": count}
        for key, count in sorted(counts.items())
    ]


def write_phase6_reports(output_root: Path, result: TimelineBuildResult) -> None:
    qa = output_root / "qa" / "phase_06_qa_report.md"
    metrics = result.quality_metrics
    qa.write_text(
        "\n".join(
            [
                "# Phase 6 QA Report",
                "",
                f"- cases processed: {metrics['total_cases_processed']}",
                f"- cases with timelines: {metrics['cases_with_timeline']}",
                f"- cases with deterministic stories: {metrics['cases_with_attack_story']}",
                f"- total timeline steps: {metrics['total_timeline_steps']}",
                f"- observed claims: {metrics['observed_claim_count']}",
                f"- inferred claims: {metrics['inferred_claim_count']}",
                f"- runtime unsupported claim warnings: {metrics['unsupported_claim_count_runtime']}",
                f"- backlog-labeled cases: {metrics['cases_with_backlog_label']}",
                "",
                "Runtime generation is deterministic and uses no evaluation labels or LLM calls.",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )
