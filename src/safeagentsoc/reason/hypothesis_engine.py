from __future__ import annotations

import csv
from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from statistics import mean
from time import perf_counter
from typing import Any

from safeagentsoc.agent_firewall.decision_ledger import ledger_entry
from safeagentsoc.agent_firewall.permission_enforcer import enforce_permission, permission_matrix_rows
from safeagentsoc.agent_firewall.prompt_injection_tester import run_prompt_injection_tests
from safeagentsoc.reason.evidence_verifier import sanitize_case_citations, verify_evidence
from safeagentsoc.reason.llm_adapter import LLMProvider, provider_from_env
from safeagentsoc.reason.llm_context_builder import build_prompt_pack
from safeagentsoc.reason.recommended_checks import CHECK_CATALOG, normalize_recommended_checks, validate_recommended_checks
from safeagentsoc.reason.schema_validator import confidence_label, validate_hypothesis_response
from safeagentsoc.reason.unsupported_claim_detector import FORBIDDEN_CLAIM_PATTERNS, detect_unsupported_claims
from safeagentsoc.timeline.attack_catalog import technique_info


FORBIDDEN_RUNTIME_TERMS = {
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


@dataclass(frozen=True)
class HypothesisEngineResult:
    prompt_pack: list[dict[str, Any]]
    raw_outputs: list[dict[str, Any]]
    validated_outputs: list[dict[str, Any]]
    invalid_outputs: list[dict[str, Any]]
    validation_rows: list[dict[str, Any]]
    evidence_rows: list[dict[str, Any]]
    unsupported_rows: list[dict[str, Any]]
    recommended_check_rows: list[dict[str, Any]]
    citation_repair_rows: list[dict[str, Any]]
    normalization_rows: list[dict[str, Any]]
    case_runtime_rows: list[dict[str, Any]]
    ledger_rows: list[dict[str, Any]]
    agent_firewall_rows: list[dict[str, Any]]
    prompt_injection_results: dict[str, Any]
    metrics: dict[str, Any]


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def write_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows),
        encoding="utf-8",
        newline="\n",
    )


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
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, ensure_ascii=False)
    return value


def build_hypothesis_outputs(
    *,
    context_pack_path: Path,
    output_root: Path,
    provider_name: str | None = None,
    max_cases: int | None = None,
    start_index: int = 0,
    case_ids: list[str] | None = None,
    provider: LLMProvider | None = None,
    verbose: bool = False,
) -> HypothesisEngineResult:
    started = datetime.now(UTC)
    all_contexts = read_jsonl(context_pack_path)
    if start_index < 0:
        start_index = 0
    if case_ids:
        requested = {case_id.strip() for case_id in case_ids if case_id and case_id.strip()}
        contexts = [row for row in all_contexts if row.get("case_id") in requested]
    else:
        selected_contexts = all_contexts[start_index:]
        contexts = selected_contexts[:max_cases] if max_cases is not None else selected_contexts
    prompt_pack = build_prompt_pack(contexts, max_cases=None)
    provider_instance = provider or provider_from_env(provider_name)
    provider_diagnostics = provider_instance.provider_diagnostics()
    contexts_by_case = {context["case_id"]: context for context in contexts}
    interrupted = False
    if verbose:
        print(f"[INFO] Loaded {len(all_contexts)} Phase 6 context rows")
        if case_ids:
            print(f"[INFO] Running explicit case IDs: {case_ids}")
        else:
            print(f"[INFO] Starting at case index {start_index}")
        print(f"[INFO] Building hypotheses for {len(prompt_pack)} case(s)")
        print(f"[INFO] Provider diagnostics: {json.dumps(provider_diagnostics, sort_keys=True)}")

    raw_outputs: list[dict[str, Any]] = []
    validated_outputs: list[dict[str, Any]] = []
    invalid_outputs: list[dict[str, Any]] = []
    validation_rows: list[dict[str, Any]] = []
    evidence_rows: list[dict[str, Any]] = []
    unsupported_rows: list[dict[str, Any]] = []
    recommended_check_rows: list[dict[str, Any]] = []
    citation_repair_rows: list[dict[str, Any]] = []
    normalization_rows: list[dict[str, Any]] = []
    case_runtime_rows: list[dict[str, Any]] = []
    ledger_rows: list[dict[str, Any]] = []

    for index, prompt in enumerate(prompt_pack, start=1):
        case_id = prompt["case_id"]
        context = contexts_by_case[case_id]
        if verbose:
            print(f"[CASE {index}/{len(prompt_pack)}] Requesting hypotheses for {case_id}", flush=True)
        case_started = perf_counter()
        permission = enforce_permission("hypothesis_generator", "read", "case_llm_context_pack")
        if not permission["allowed"]:
            raise RuntimeError(permission["reason"])
        try:
            raw = provider_instance.generate_hypotheses(prompt)
        except KeyboardInterrupt:
            interrupted = True
            if verbose:
                elapsed = round(perf_counter() - case_started, 2)
                print(f"[CASE {index}/{len(prompt_pack)}] Interrupted by user after {elapsed}s", flush=True)
            break
        except Exception as exc:  # provider errors are runtime records, not silent failures
            if verbose:
                elapsed = round(perf_counter() - case_started, 2)
                print(f"[CASE {index}/{len(prompt_pack)}] Provider error for {case_id} after {elapsed}s: {exc}", flush=True)
            raw = {
                "case_id": case_id,
                "provider": provider_name or "unknown",
                "generated_at_utc": datetime.now(UTC).isoformat(),
                "hypotheses": [],
                "provider_error": str(exc),
            }
        raw_outputs.append(raw)
        candidate, normalizations = normalize_hypothesis_output(
            raw,
            context,
            provider_metadata=provider_diagnostics,
        )
        normalization_rows.extend(
            [{"case_id": case_id, "normalization_type": item} for item in normalizations]
        )
        if verbose and normalizations:
            print(f"[CASE {index}/{len(prompt_pack)}] Applied normalizations for {case_id}: {normalizations}", flush=True)
        validation = validate_hypothesis_response(candidate, context)
        if validation["schema_valid"]:
            candidate, repairs = sanitize_case_citations(candidate, context)
            citation_repair_rows.extend(repairs)
            if verbose and repairs:
                print(f"[CASE {index}/{len(prompt_pack)}] Repaired {len(repairs)} citation issue(s) for {case_id}", flush=True)
            validation = validate_hypothesis_response(candidate, context)
        evidence = verify_evidence(candidate, context) if validation["schema_valid"] else failed_evidence_result(candidate)
        unsupported = detect_unsupported_claims(candidate, context) if validation["schema_valid"] else failed_unsupported_result(candidate)
        checks = validate_checks_for_response(candidate) if validation["schema_valid"] else failed_check_result(candidate)
        passed = (
            validation["schema_valid"]
            and evidence["evidence_validation_status"] == "passed"
            and unsupported["unsupported_claim_count"] == 0
            and checks["recommended_checks_valid"]
        )
        validation_rows.append(
            {
                "case_id": case_id,
                "schema_validation_status": validation["schema_validation_status"],
                "schema_valid": validation["schema_valid"],
                "schema_errors": validation["schema_errors"],
                "citation_repairs": [row for row in citation_repair_rows if row.get("case_id") == case_id],
                "normalizations": [row["normalization_type"] for row in normalization_rows if row.get("case_id") == case_id],
                "provider_error": raw.get("provider_error"),
            }
        )
        evidence_rows.extend(flatten_evidence_rows(evidence))
        unsupported_rows.extend(unsupported["rows"])
        recommended_check_rows.extend(checks["rows"])
        validated_record = {
            "case_id": case_id,
            "provider": candidate.get("provider"),
            "model": candidate.get("model"),
            "normalized_by": candidate.get("normalized_by"),
            "generated_at_utc": candidate.get("generated_at_utc"),
            "validation_status": "passed" if passed else "failed",
            "hypotheses": candidate.get("hypotheses") if passed else [],
            "validation": validation,
            "evidence_verification": evidence,
            "unsupported_claims": unsupported,
            "recommended_checks_validation": checks,
            "citation_repairs": [row for row in citation_repair_rows if row.get("case_id") == case_id],
            "normalizations": [row["normalization_type"] for row in normalization_rows if row.get("case_id") == case_id],
        }
        if passed:
            validated_outputs.append(validated_record)
            if verbose:
                elapsed = round(perf_counter() - case_started, 2)
                print(f"[CASE {index}/{len(prompt_pack)}] Passed validation for {case_id} in {elapsed}s", flush=True)
        else:
            invalid_outputs.append({"case_id": case_id, "raw_output": raw, "validated_record": validated_record})
            if verbose:
                elapsed = round(perf_counter() - case_started, 2)
                print(f"[CASE {index}/{len(prompt_pack)}] Failed validation for {case_id} in {elapsed}s", flush=True)
                print(
                    f"[CASE {index}/{len(prompt_pack)}] Failure details: "
                    f"schema={validation['schema_validation_status']}, "
                    f"evidence={evidence['evidence_validation_status']}, "
                    f"unsupported={unsupported['unsupported_claim_count']}, "
                    f"checks={checks['recommended_checks_valid']}",
                    flush=True,
                )
        elapsed = round(perf_counter() - case_started, 4)
        case_runtime_rows.append(
            {
                "case_id": case_id,
                "elapsed_seconds": elapsed,
                "validation_status": "passed" if passed else "failed",
                "schema_validation_status": validation["schema_validation_status"],
                "evidence_validation_status": evidence["evidence_validation_status"],
                "unsupported_claim_count": int(unsupported["unsupported_claim_count"]),
                "recommended_checks_valid": bool(checks["recommended_checks_valid"]),
                "provider_error": bool(raw.get("provider_error")),
            }
        )
        ledger_rows.append(
            ledger_entry(
                case_id=case_id,
                agent_id="hypothesis_generator",
                input_record=prompt,
                raw_output=raw,
                validated_output=validated_record,
                schema_validation_status=validation["schema_validation_status"],
                evidence_validation_status=evidence["evidence_validation_status"],
                unsupported_claim_count=int(unsupported["unsupported_claim_count"]),
            )
        )

    prompt_injection_results = run_prompt_injection_tests()
    agent_firewall_rows = build_agent_firewall_rows(prompt_injection_results)
    metrics = build_metrics(
        prompt_pack=prompt_pack,
        raw_outputs=raw_outputs,
        validated_outputs=validated_outputs,
        validation_rows=validation_rows,
        evidence_rows=evidence_rows,
        unsupported_rows=unsupported_rows,
        recommended_check_rows=recommended_check_rows,
        citation_repair_rows=citation_repair_rows,
        normalization_rows=normalization_rows,
        case_runtime_rows=case_runtime_rows,
        ledger_rows=ledger_rows,
        prompt_injection_results=prompt_injection_results,
        started=started,
        interrupted=interrupted,
        total_cases_target=len(prompt_pack),
        start_index=start_index,
    )
    result = HypothesisEngineResult(
        prompt_pack=prompt_pack,
        raw_outputs=raw_outputs,
        validated_outputs=validated_outputs,
        invalid_outputs=invalid_outputs,
        validation_rows=validation_rows,
        evidence_rows=evidence_rows,
        unsupported_rows=unsupported_rows,
        recommended_check_rows=recommended_check_rows,
        citation_repair_rows=citation_repair_rows,
        normalization_rows=normalization_rows,
        case_runtime_rows=case_runtime_rows,
        ledger_rows=ledger_rows,
        agent_firewall_rows=agent_firewall_rows,
        prompt_injection_results=prompt_injection_results,
        metrics=metrics,
    )
    write_outputs(output_root, result)
    return result


def validate_checks_for_response(response: dict[str, Any]) -> dict[str, Any]:
    rows: list[dict[str, Any]] = []
    for hypothesis in response.get("hypotheses") or []:
        validation = validate_recommended_checks([str(item) for item in hypothesis.get("recommended_checks") or []])
        for row in validation["rows"]:
            rows.append(
                {
                    "case_id": response.get("case_id"),
                    "hypothesis_id": hypothesis.get("hypothesis_id"),
                    **row,
                }
            )
    return {
        "recommended_checks_valid": bool(rows) and all(row["allowed"] for row in rows),
        "rows": rows,
    }


def failed_evidence_result(raw: dict[str, Any]) -> dict[str, Any]:
    return {
        "evidence_validation_status": "failed",
        "evidence_support_rate": 0.0,
        "rows": [
            {
                "case_id": raw.get("case_id"),
                "hypothesis_id": "",
                "invalid_evidence_ids": [],
                "invalid_alert_uids": [],
                "unsupported_techniques": [],
                "evidence_supported": False,
            }
        ],
    }


def failed_unsupported_result(raw: dict[str, Any]) -> dict[str, Any]:
    return {"unsupported_claim_count": 1, "unsupported_claim_rate": 1.0, "rows": [{"case_id": raw.get("case_id"), "hypothesis_id": "", "claim_status": "schema_failed"}]}


def failed_check_result(raw: dict[str, Any]) -> dict[str, Any]:
    return {"recommended_checks_valid": False, "rows": [{"case_id": raw.get("case_id"), "hypothesis_id": "", "allowed": False, "recommended_check": ""}]}


def flatten_evidence_rows(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        {
            **row,
            "invalid_evidence_ids": row.get("invalid_evidence_ids") or [],
            "invalid_alert_uids": row.get("invalid_alert_uids") or [],
            "unsupported_techniques": row.get("unsupported_techniques") or [],
            "evidence_support_rate": evidence.get("evidence_support_rate"),
        }
        for row in evidence.get("rows") or []
    ]


ATTACK_ID_RE = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)


def normalize_hypothesis_output(
    raw: dict[str, Any],
    case_context: dict[str, Any],
    *,
    provider_metadata: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], list[str]]:
    if not isinstance(raw, dict):
        return raw, []
    hypotheses = raw.get("hypotheses")
    if not isinstance(hypotheses, list):
        return raw, []
    fallback_evidence_ids = case_evidence_defaults(case_context)
    fallback_alert_uids = case_alert_defaults(case_context)
    fallback_missing = case_missing_defaults(case_context)
    allowed_techniques = case_allowed_techniques(case_context)
    normalized = {**raw, "hypotheses": []}
    if provider_metadata:
        if provider_metadata.get("provider"):
            normalized["provider"] = str(provider_metadata["provider"])
        if provider_metadata.get("model"):
            normalized["model"] = str(provider_metadata["model"])
    normalized["normalized_by"] = "SafeAgentSOC"
    if not normalized.get("generated_at_utc"):
        normalized["generated_at_utc"] = datetime.now(UTC).isoformat()
    flags: set[str] = set()
    for hypothesis in hypotheses:
        if not isinstance(hypothesis, dict):
            normalized["hypotheses"].append(hypothesis)
            continue
        item = {**hypothesis}
        item, text_sanitized = sanitize_hypothesis_text_fields(item)
        if text_sanitized:
            flags.add("sanitize_text_fields")
        score = item.get("confidence_score")
        if isinstance(score, (int, float)):
            expected_label = confidence_label(float(score))
            if item.get("confidence_label") != expected_label:
                item["confidence_label"] = expected_label
                flags.add("confidence_label_from_score")
        for field in ("supporting_evidence_ids", "supporting_alert_uids", "mitre_techniques"):
            values = item.get(field)
            if isinstance(values, list):
                deduped = []
                seen = set()
                for value in values:
                    key = str(value)
                    if key in seen:
                        continue
                    deduped.append(value)
                    seen.add(key)
                if len(deduped) != len(values):
                    flags.add(f"dedupe_{field}")
                item[field] = deduped
        evidence_ids = list(item.get("supporting_evidence_ids") or [])
        if not evidence_ids and fallback_evidence_ids:
            item["supporting_evidence_ids"] = fallback_evidence_ids[:3]
            flags.add("backfill_supporting_evidence_ids_from_case")
        alert_uids = list(item.get("supporting_alert_uids") or [])
        if not alert_uids and fallback_alert_uids:
            item["supporting_alert_uids"] = fallback_alert_uids[:3]
            flags.add("backfill_supporting_alert_uids_from_case")
        if not item.get("missing_evidence") and fallback_missing:
            item["missing_evidence"] = fallback_missing
            flags.add("backfill_missing_evidence_from_case")
        canonical_techniques = canonicalize_techniques(item.get("mitre_techniques") or [])
        canonical_techniques = [tech for tech in canonical_techniques if tech in allowed_techniques]
        if item.get("mitre_techniques") != canonical_techniques:
            flags.add("canonicalize_mitre_techniques")
        item["mitre_techniques"] = canonical_techniques
        mappings = item.get("mitre_tactic_mappings")
        if isinstance(mappings, list):
            cleaned_mappings: list[dict[str, Any]] = []
            seen_mappings: set[tuple[str, str]] = set()
            for mapping in mappings:
                if not isinstance(mapping, dict):
                    continue
                canonical_id = canonicalize_technique_id(mapping.get("technique_id"))
                if not canonical_id or canonical_id not in allowed_techniques:
                    continue
                mapping_info = technique_info(canonical_id)
                tactic = str(mapping.get("tactic") or "unknown")
                if tactic == "unknown":
                    fallback_tactic = next((row for row in mapping_info.tactics if row != "unknown"), "unknown")
                    tactic = fallback_tactic
                key = (canonical_id, tactic)
                if key in seen_mappings:
                    continue
                cleaned_mappings.append(
                    {
                        "technique_id": canonical_id,
                        "tactic": tactic,
                        "technique_name": mapping.get("technique_name")
                        if mapping.get("technique_name") and str(mapping.get("technique_name")) != f"ATT&CK technique {canonical_id}"
                        else mapping_info.name,
                    }
                )
                seen_mappings.add(key)
            if cleaned_mappings != mappings:
                flags.add("canonicalize_mitre_tactic_mappings")
            item["mitre_tactic_mappings"] = cleaned_mappings
        if not item.get("mitre_techniques") and item.get("mitre_tactic_mappings"):
            from_mappings = canonicalize_techniques(
                [mapping.get("technique_id") for mapping in item.get("mitre_tactic_mappings") if isinstance(mapping, dict)]
            )
            from_mappings = [tech for tech in from_mappings if tech in allowed_techniques]
            if from_mappings:
                item["mitre_techniques"] = from_mappings
                flags.add("backfill_mitre_techniques_from_mappings")
        if not item.get("mitre_tactic_mappings") and canonical_techniques:
            item["mitre_tactic_mappings"] = default_tactic_mappings(canonical_techniques)
            flags.add("backfill_mitre_tactic_mappings")
        check_values = item.get("recommended_checks")
        if not isinstance(check_values, list):
            check_values = []
        normalized_checks, checks_changed = normalize_recommended_checks(check_values)
        if checks_changed:
            flags.add("normalize_recommended_checks_to_catalog")
        if len(normalized_checks) < 3:
            normalized_checks = list(dict.fromkeys(normalized_checks + CHECK_CATALOG[:3]))[:5]
            flags.add("default_recommended_checks_added")
        item["recommended_checks"] = normalized_checks[:5]
        if len(check_values) > 5:
            flags.add("cap_recommended_checks")
        item, softened = soften_unsupported_language(item)
        if softened:
            flags.add("soften_unsupported_claim_language")
        normalized["hypotheses"].append(item)
    return normalized, sorted(flags)


def case_evidence_defaults(case_context: dict[str, Any]) -> list[str]:
    values = list(case_context.get("evidence_ids") or [])
    if values:
        return values
    for step in case_context.get("observed_timeline", []):
        values.extend(step.get("evidence_ids") or [])
    return list(dict.fromkeys(values))


def case_alert_defaults(case_context: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for step in case_context.get("observed_timeline", []):
        values.extend(step.get("alert_uids") or [])
    return list(dict.fromkeys(values))


def case_missing_defaults(case_context: dict[str, Any]) -> list[dict[str, Any]]:
    entries = case_context.get("missing_evidence") or []
    if entries:
        return entries[:2]
    return [
        {
            "missing_evidence_type": "visibility_gap",
            "status": "unknown",
            "reason": "No explicit missing evidence record was provided in case context.",
        }
    ]


def case_allowed_techniques(case_context: dict[str, Any]) -> set[str]:
    values: set[str] = set()
    for row in case_context.get("observed_technique_chain", []):
        canonical = canonicalize_technique_id(row.get("technique_id"))
        if canonical:
            values.add(canonical)
    for row in case_context.get("inferred_relationships", []):
        canonical = canonicalize_technique_id(row.get("technique_id"))
        if canonical:
            values.add(canonical)
    for row in case_context.get("mitre_tactic_mappings", []):
        canonical = canonicalize_technique_id(row.get("technique_id"))
        if canonical:
            values.add(canonical)
    return values


def canonicalize_techniques(values: list[Any]) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        canonical = canonicalize_technique_id(value)
        if not canonical or canonical in seen:
            continue
        result.append(canonical)
        seen.add(canonical)
    return result


def canonicalize_technique_id(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    match = ATTACK_ID_RE.search(text)
    if not match:
        return None
    return match.group(0).upper()


TEXT_ARTIFACT_TOKENS = {
    "missing_evidence_identities",
    "recommended_checks_brief",
    "missing_evidence",
    "missing_evidence_type",
    "missing_evidence_type_for_case",
    "status",
    "limitations",
}


def sanitize_hypothesis_text_fields(hypothesis: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    result = {**hypothesis}
    changed = False
    for field in ("title", "description"):
        value = result.get(field)
        if isinstance(value, str):
            sanitized = sanitize_text_value(value)
            if sanitized != value:
                changed = True
            result[field] = sanitized
    for field in ("observed_facts", "inferred_facts", "limitations"):
        values = result.get(field)
        if not isinstance(values, list):
            continue
        cleaned: list[str] = []
        for value in values:
            if not isinstance(value, str):
                changed = True
                continue
            sanitized = sanitize_text_value(value)
            lowered = sanitized.lower()
            if not sanitized:
                changed = True
                continue
            if lowered in TEXT_ARTIFACT_TOKENS or lowered.startswith("missing_evidence_type_for_case"):
                changed = True
                continue
            cleaned.append(sanitized)
        deduped = list(dict.fromkeys(cleaned))
        if deduped != values:
            changed = True
        result[field] = deduped
    missing_values = result.get("missing_evidence")
    if isinstance(missing_values, list):
        cleaned_missing: list[dict[str, Any]] = []
        for row in missing_values:
            if not isinstance(row, dict):
                changed = True
                continue
            item = {**row}
            miss_type = str(item.get("missing_evidence_type") or "").strip().lower()
            if miss_type in {"lateral_materal", "lateral_mmovement"}:
                item["missing_evidence_type"] = "lateral_movement"
                changed = True
            reason = item.get("reason")
            if isinstance(reason, str):
                sanitized_reason = sanitize_text_value(reason)
                if sanitized_reason != reason:
                    changed = True
                item["reason"] = sanitized_reason
            cleaned_missing.append(item)
        result["missing_evidence"] = cleaned_missing
    return result, changed


def sanitize_text_value(value: str) -> str:
    text = value.replace("\u0000", " ").replace("\r", " ").replace("\n", " ").strip()
    text = re.sub(r"\s+", " ", text)
    text = text.replace("']," , "").replace('"],', "")
    text = text.replace("The supplied evidence may indicate The evidence supports", "The supplied evidence indicates")
    text = text.replace("non-normally", "abnormally")
    text = text.replace("missing lateral/m2 external signals", "missing lateral movement and external C2 signals")
    text = re.sub(
        r"(ATT&CK\s+(T\d{4}(?:\.\d{3})?)\s+observed\s+for\s+)unknown tactic",
        lambda match: f"{match.group(1)}{primary_tactic_for(match.group(2))}",
        text,
        flags=re.IGNORECASE,
    )
    text = text.replace("for unknown tactic", "for mapped ATT&CK tactics")
    text = text.strip(" '\"[];,")
    if text.lower() in TEXT_ARTIFACT_TOKENS:
        return ""
    return text


def primary_tactic_for(technique_id: str) -> str:
    info = technique_info(technique_id.upper())
    return next((tactic for tactic in info.tactics if tactic != "unknown"), "mapped ATT&CK tactics")


def default_tactic_mappings(techniques: list[str]) -> list[dict[str, str]]:
    mappings: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for technique_id in techniques:
        info = technique_info(technique_id)
        for tactic in info.tactics:
            key = (technique_id, tactic)
            if key in seen:
                continue
            mappings.append(
                {
                    "technique_id": technique_id,
                    "tactic": tactic,
                    "technique_name": info.name,
                }
            )
            seen.add(key)
    return mappings


def soften_unsupported_language(hypothesis: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    replacements = {
        "confirmed compromise": "possible compromise not yet confirmed",
        "credential dumping occurred": "credential dumping is not confirmed",
        "lateral movement occurred": "lateral movement is not confirmed",
        "data exfiltration occurred": "data exfiltration is not confirmed",
        "domain controller compromise": "possible domain controller risk not confirmed",
        "malware downloaded": "malware download is not confirmed",
        "impact confirmed": "impact is not confirmed",
        "command and control established": "command and control is not confirmed",
    }
    result = {**hypothesis}
    changed = False
    for field in ("title", "description"):
        value = result.get(field)
        if isinstance(value, str):
            updated = value
            for pattern in FORBIDDEN_CLAIM_PATTERNS:
                updated = updated.replace(pattern, replacements.get(pattern, pattern))
                updated = updated.replace(pattern.title(), replacements.get(pattern, pattern).capitalize())
            if updated != value:
                result[field] = updated
                changed = True
    for list_field in ("inferred_facts", "observed_facts", "limitations"):
        values = result.get(list_field)
        if isinstance(values, list):
            updated_values: list[Any] = []
            local_changed = False
            for item in values:
                if not isinstance(item, str):
                    updated_values.append(item)
                    continue
                updated_item = item
                for pattern in FORBIDDEN_CLAIM_PATTERNS:
                    updated_item = updated_item.replace(pattern, replacements.get(pattern, pattern))
                    updated_item = updated_item.replace(pattern.title(), replacements.get(pattern, pattern).capitalize())
                if updated_item != item:
                    local_changed = True
                updated_values.append(updated_item)
            if local_changed:
                result[list_field] = updated_values
                changed = True
    return result, changed


def build_agent_firewall_rows(prompt_injection_results: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [
        {
            "check_type": "permission_matrix",
            "agent_id": row["agent_id"],
            "operation": row["operation"],
            "resource": row["resource"],
            "blocked": not row["allowed"],
            "reason": row["reason"],
        }
        for row in prompt_injection_results["permission_results"]
    ]
    rows.extend(
        {
            "check_type": "prompt_injection",
            "agent_id": "prompt_injection_tester",
            "operation": "inspect",
            "resource": item["test_id"],
            "blocked": item["blocked"],
            "reason": item["reason"],
        }
        for item in prompt_injection_results["prompt_injection_results"]
    )
    rows.extend(
        {
            "check_type": "permission_definition",
            "agent_id": row["agent_id"],
            "operation": "define",
            "resource": "agent_permissions",
            "blocked": False,
            "reason": json.dumps(row, sort_keys=True),
        }
        for row in permission_matrix_rows()
    )
    return rows


def build_metrics(
    *,
    prompt_pack: list[dict[str, Any]],
    raw_outputs: list[dict[str, Any]],
    validated_outputs: list[dict[str, Any]],
    validation_rows: list[dict[str, Any]],
    evidence_rows: list[dict[str, Any]],
    unsupported_rows: list[dict[str, Any]],
    recommended_check_rows: list[dict[str, Any]],
    citation_repair_rows: list[dict[str, Any]],
    normalization_rows: list[dict[str, Any]],
    case_runtime_rows: list[dict[str, Any]],
    ledger_rows: list[dict[str, Any]],
    prompt_injection_results: dict[str, Any],
    started: datetime,
    interrupted: bool,
    total_cases_target: int,
    start_index: int,
) -> dict[str, Any]:
    validated_case_ids = {row.get("case_id") for row in validated_outputs}
    failed_case_ids = [row.get("case_id") for row in raw_outputs if row.get("case_id") not in validated_case_ids]
    schema_rate = sum(1 for row in validation_rows if row["schema_valid"]) / max(len(validation_rows), 1)
    evidence_rate = mean([float(row.get("evidence_support_rate") or 0) for row in evidence_rows] or [0.0])
    unsupported_count = sum(1 for row in unsupported_rows if row.get("claim_status") not in {"supported", None})
    check_rate = sum(1 for row in recommended_check_rows if row.get("allowed")) / max(len(recommended_check_rows), 1)
    provider_error_count = sum(1 for row in raw_outputs if row.get("provider_error"))
    runtime_values = [float(row.get("elapsed_seconds") or 0.0) for row in case_runtime_rows]
    return {
        "hypothesis_run_id": f"hypothesis_run_{started.strftime('%Y%m%dT%H%M%SZ')}",
        "generated_at_utc": datetime.now(UTC).isoformat(),
        "total_cases": len(prompt_pack),
        "total_cases_target": total_cases_target,
        "start_index": start_index,
        "processed_cases": len(raw_outputs),
        "interrupted": interrupted,
        "raw_output_count": len(raw_outputs),
        "provider_error_count": provider_error_count,
        "citation_repair_count": len(citation_repair_rows),
        "normalization_count": len(normalization_rows),
        "validated_case_count": len(validated_outputs),
        "failed_case_count": len(failed_case_ids),
        "failed_case_ids": failed_case_ids,
        "schema_compliance_rate": round(schema_rate, 4),
        "evidence_support_rate": round(evidence_rate, 4),
        "unsupported_claim_count": unsupported_count,
        "unsupported_claim_rate": round(unsupported_count / max(len(unsupported_rows), 1), 4),
        "recommended_check_relevance": round(check_rate, 4),
        "average_case_runtime_seconds": round(mean(runtime_values), 4) if runtime_values else 0.0,
        "max_case_runtime_seconds": round(max(runtime_values), 4) if runtime_values else 0.0,
        "min_case_runtime_seconds": round(min(runtime_values), 4) if runtime_values else 0.0,
        "prompt_injection_rejection_rate": prompt_injection_results["prompt_injection_rejection_rate"],
        "unauthorized_tool_call_block_rate": prompt_injection_results["unauthorized_tool_call_block_rate"],
        "agent_decision_traceability_score": round(len(ledger_rows) / max(len(raw_outputs), 1), 4),
        "runtime_seconds": round((datetime.now(UTC) - started).total_seconds(), 4),
        "runtime_safety": "runtime_only_no_evaluation_artifacts",
    }


def write_outputs(output_root: Path, result: HypothesisEngineResult) -> None:
    prompts_dir = output_root / "prompts"
    outputs_dir = output_root / "outputs"
    validated_dir = output_root / "validated"
    qa_dir = output_root / "qa"
    ledger_dir = output_root / "ledger"
    write_jsonl(prompts_dir / "case_llm_prompt_pack.jsonl", result.prompt_pack)
    write_jsonl(outputs_dir / "llm_hypotheses_raw.jsonl", result.raw_outputs)
    write_jsonl(outputs_dir / "invalid_hypothesis_outputs.jsonl", result.invalid_outputs)
    write_jsonl(validated_dir / "validated_hypotheses.jsonl", result.validated_outputs)
    write_csv(qa_dir / "hypothesis_validation_report.csv", result.validation_rows)
    write_csv(qa_dir / "evidence_support_report.csv", result.evidence_rows)
    write_csv(qa_dir / "unsupported_claim_report.csv", result.unsupported_rows)
    write_csv(qa_dir / "recommended_checks_report.csv", result.recommended_check_rows)
    write_csv(qa_dir / "citation_repair_report.csv", result.citation_repair_rows)
    write_csv(qa_dir / "normalization_report.csv", result.normalization_rows)
    write_csv(qa_dir / "case_runtime_report.csv", result.case_runtime_rows)
    write_csv(qa_dir / "agent_firewall_results.csv", result.agent_firewall_rows)
    write_csv(qa_dir / "llm_grounding_metrics.csv", [{"metric": key, "value": value} for key, value in result.metrics.items()])
    write_jsonl(ledger_dir / "ai_decision_ledger.jsonl", result.ledger_rows)
    write_csv(ledger_dir / "ai_decision_ledger.csv", result.ledger_rows)
    write_agent_security_report(qa_dir / "agent_security_report.md", result)
    write_catalog(output_root / "investigation_check_catalog.yaml")
    write_agent_permissions(output_root / "agent_permissions.yaml")


def write_agent_security_report(path: Path, result: HypothesisEngineResult) -> None:
    metrics = result.metrics
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n".join(
            [
                "# Phase 7 Agent Security Report",
                "",
                f"- prompt injection rejection rate: {metrics['prompt_injection_rejection_rate']}",
                f"- unauthorized tool-call block rate: {metrics['unauthorized_tool_call_block_rate']}",
                f"- schema compliance rate: {metrics['schema_compliance_rate']}",
                f"- unsupported claim rate: {metrics['unsupported_claim_rate']}",
                f"- decision traceability score: {metrics['agent_decision_traceability_score']}",
                "",
            ]
        ),
        encoding="utf-8",
        newline="\n",
    )


def write_catalog(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "allowed_investigation_checks:\n" + "".join(f"  - {item}\n" for item in CHECK_CATALOG),
        encoding="utf-8",
        newline="\n",
    )


def write_agent_permissions(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ["agents:"]
    for row in permission_matrix_rows():
        lines.append(f"  {row['agent_id']}:")
        lines.append("    can_read:")
        lines.extend(f"      - {item}" for item in row["can_read"])
        lines.append("    can_write:")
        lines.extend(f"      - {item}" for item in row["can_write"])
        lines.append("    cannot_read:")
        lines.extend(f"      - {item}" for item in row["cannot_read"])
        lines.append("    cannot_write:")
        lines.extend(f"      - {item}" for item in row["cannot_write"])
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
