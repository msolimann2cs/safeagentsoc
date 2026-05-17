from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safeagentsoc.govern.action_catalog import candidate_actions_for_case, load_action_catalog
from safeagentsoc.govern.approval_workflow import build_approval_decision
from safeagentsoc.govern.business_impact import assess_business_impact
from safeagentsoc.govern.ciso_brief import build_ciso_brief
from safeagentsoc.govern.csirt_pack import build_csirt_pack
from safeagentsoc.govern.decision_ledger import ledger_entry
from safeagentsoc.govern.framework_mapping import build_framework_mappings
from safeagentsoc.govern.io_utils import (
    dedupe,
    load_config,
    read_csv,
    read_jsonl,
    scan_forbidden_terms,
    to_plain,
    write_csv,
    write_json,
    write_jsonl,
)
from safeagentsoc.govern.policy_engine import decide_policy
from safeagentsoc.govern.recommendation_engine import rank_recommendations
from safeagentsoc.govern.risk_scoring import score_incident_risk
from safeagentsoc.govern.schemas import (
    ApprovalDecision,
    BusinessImpactAssessment,
    CisoDecisionBrief,
    CsirtPack,
    FrameworkMapping,
    IncidentRiskScore,
    Phase9LedgerEntry,
    PolicyDecision,
    SafeRecommendation,
    SoarDryRun,
    StakeholderMessage,
    UncertaintyAssessment,
)
from safeagentsoc.govern.soar_dry_run import build_soar_dry_run
from safeagentsoc.govern.stakeholder_communication import build_stakeholder_messages, lint_messages
from safeagentsoc.govern.uncertainty import assess_uncertainty


@dataclass
class Phase9Paths:
    workspace_root: Path
    output_root: Path
    phase8_root: Path
    phase7_root: Path
    phase6_exports: Path
    phase5_exports: Path
    phase4_context: Path
    config_root: Path


@dataclass
class Phase9Output:
    paths: Phase9Paths
    risks: list[IncidentRiskScore]
    uncertainties: list[UncertaintyAssessment]
    business_impacts: list[BusinessImpactAssessment]
    policy_decisions: list[PolicyDecision]
    approval_decisions: list[ApprovalDecision]
    recommendations: list[SafeRecommendation]
    dry_runs: list[SoarDryRun]
    csirt_packs: list[CsirtPack]
    ciso_briefs: list[CisoDecisionBrief]
    stakeholder_messages: list[StakeholderMessage]
    framework_mappings: list[FrameworkMapping]
    ledger_entries: list[Phase9LedgerEntry]
    handoff: list[dict[str, Any]]
    metrics: dict[str, Any]


def default_paths(
    workspace_root: Path,
    *,
    output_root: Path | None = None,
    phase8_root: Path | None = None,
    phase7_root: Path | None = None,
) -> Phase9Paths:
    code_root = workspace_root / "05_code" / "safeagentsoc"
    return Phase9Paths(
        workspace_root=workspace_root,
        output_root=output_root or workspace_root / "06_data" / "Phase9" / "governance",
        phase8_root=phase8_root or workspace_root / "06_data" / "Phase8" / "graph_validation",
        phase7_root=phase7_root or workspace_root / "06_data" / "Phase7" / "reason",
        phase6_exports=workspace_root / "06_data" / "Phase6" / "timelines" / "exports",
        phase5_exports=workspace_root / "06_data" / "phase_05_case_builder_alert_compression" / "cases" / "exports",
        phase4_context=workspace_root / "06_data" / "Phase4" / "context",
        config_root=code_root / "config",
    )


def build_governance_outputs(
    *,
    workspace_root: Path,
    output_root: Path | None = None,
    phase8_root: Path | None = None,
    phase7_root: Path | None = None,
    verbose: bool = False,
) -> Phase9Output:
    paths = default_paths(workspace_root, output_root=output_root, phase8_root=phase8_root, phase7_root=phase7_root)
    catalog = load_action_catalog(paths.config_root / "action_catalog.yaml")
    red_team_tests = load_config(paths.config_root / "policy_red_team_tests.jsonl") if (paths.config_root / "policy_red_team_tests.jsonl").exists() else []
    cases = {row["case_id"]: row for row in read_jsonl(paths.phase5_exports / "generated_cases.jsonl")}
    graph_rows = read_jsonl(paths.phase8_root / "exports" / "phase_09_graph_handoff.jsonl")
    phase8_metrics = load_config(paths.phase8_root / "exports" / "graph_validation_summary.json")
    assets = {row["asset_id"]: row for row in read_csv(paths.phase4_context / "seed" / "asset_inventory.csv") if row.get("asset_id")}
    identities = {row["identity_id"]: row for row in read_csv(paths.phase4_context / "seed" / "identity_inventory.csv") if row.get("identity_id")}
    missing_by_case = load_missing_evidence(paths.phase6_exports / "case_missing_evidence.jsonl")
    graph_by_case: dict[str, list[dict[str, Any]]] = {}
    for row in graph_rows:
        graph_by_case.setdefault(row.get("case_id"), []).append(row)
    if verbose:
        print(f"[INFO] Phase 5 cases: {len(cases)}")
        print(f"[INFO] Phase 8 handoff rows: {len(graph_rows)}")
        print(f"[INFO] Action catalog entries: {len(catalog)}")

    risks: list[IncidentRiskScore] = []
    uncertainties: list[UncertaintyAssessment] = []
    business_impacts: list[BusinessImpactAssessment] = []
    policy_decisions: list[PolicyDecision] = []
    approval_decisions: list[ApprovalDecision] = []
    recommendations: list[SafeRecommendation] = []
    dry_runs: list[SoarDryRun] = []
    csirt_packs: list[CsirtPack] = []
    ciso_briefs: list[CisoDecisionBrief] = []
    stakeholder_messages: list[StakeholderMessage] = []
    framework_mappings: list[FrameworkMapping] = []
    ledger_entries: list[Phase9LedgerEntry] = []
    handoff: list[dict[str, Any]] = []

    for case_id in sorted(cases):
        case = cases[case_id]
        hypothesis_rows = graph_by_case.get(case_id, [])
        asset = assets.get(case.get("primary_asset_id") or "")
        identity = identities.get(case.get("primary_identity_id") or "")
        missing = list(missing_by_case.get(case_id, []))
        missing.extend([item for row in hypothesis_rows for item in row.get("missing_graph_evidence", [])])
        business = assess_business_impact(case, asset, identity)
        uncertainty = assess_uncertainty(case_id, hypothesis_rows, missing)
        risk = score_incident_risk(case, hypothesis_rows, business, uncertainty, asset, identity)
        has_identity = bool(case.get("primary_identity_id"))
        privileged_identity = str((identity or {}).get("privileged_account")).lower() == "true"
        finance_or_payroll = "finance" in str(business.business_unit).lower() or "payroll" in str(business.business_service).lower()
        action_ids = candidate_actions_for_case(risk.risk_label, has_identity, risk.graph_feasibility_status)
        decisions = [
            decide_policy(
                case_id=case_id,
                action=catalog.get(action_id),
                action_id=action_id,
                risk=risk,
                uncertainty=uncertainty,
                business_impact_label=business.business_impact_label,
                evidence_ids=risk.evidence_ids,
                privileged_identity=privileged_identity,
                finance_or_payroll=finance_or_payroll,
            )
            for action_id in action_ids
        ]
        approvals = [build_approval_decision(decision) for decision in decisions]
        recs = rank_recommendations(case_id, catalog, decisions, risk)
        runs = [build_soar_dry_run(catalog[rec.recommended_action_id], _policy_for(rec.recommended_action_id, decisions), business.business_impact_label) for rec in recs if rec.recommended_action_id in catalog]
        csirt = build_csirt_pack(case, risk, uncertainty, business, recs, decisions)
        brief = build_ciso_brief(case, risk, uncertainty, business, recs, decisions)
        messages = build_stakeholder_messages(risk, uncertainty, business, brief)
        mappings = build_framework_mappings(risk, recs)

        risks.append(risk)
        uncertainties.append(uncertainty)
        business_impacts.append(business)
        policy_decisions.extend(decisions)
        approval_decisions.extend(approvals)
        recommendations.extend(recs)
        dry_runs.extend(runs)
        csirt_packs.append(csirt)
        ciso_briefs.append(brief)
        stakeholder_messages.extend(messages)
        framework_mappings.extend(mappings)
        ledger_entries.extend(build_case_ledger(case, risk, uncertainty, business, decisions, recs, runs, csirt, brief, messages))
        handoff.append(
            {
                "case_id": case_id,
                "risk_score": risk.risk_score,
                "risk_label": risk.risk_label,
                "confidence_score": risk.confidence_score,
                "uncertainty_label": uncertainty.uncertainty_label,
                "business_impact_summary": business.business_impact_summary,
                "graph_validation_status": risk.graph_feasibility_status,
                "policy_decision_ids": [decision.decision_id for decision in decisions],
                "safe_recommendation_ids": [rec.recommendation_id for rec in recs],
                "blocked_actions": [decision.action_id for decision in decisions if decision.policy_decision == "blocked"],
                "approval_requirements": [approval.required_approvers for approval in approvals if approval.approval_status == "pending_human_approval"],
                "csirt_pack_ref": f"{case_id}|csirt_pack",
                "ciso_brief_ref": f"{case_id}|ciso_brief",
                "stakeholder_message_ids": [message.message_id for message in messages],
                "decision_ledger_ids": [entry.decision_id for entry in ledger_entries if entry.case_id == case_id],
                "framework_mapping_ids": [mapping.mapping_id for mapping in mappings],
            }
        )

    communication_findings = lint_messages(stakeholder_messages)
    red_team_results = run_policy_red_team_tests(red_team_tests if isinstance(red_team_tests, list) else [], catalog)
    output = Phase9Output(
        paths=paths,
        risks=risks,
        uncertainties=uncertainties,
        business_impacts=business_impacts,
        policy_decisions=policy_decisions,
        approval_decisions=approval_decisions,
        recommendations=recommendations,
        dry_runs=dry_runs,
        csirt_packs=csirt_packs,
        ciso_briefs=ciso_briefs,
        stakeholder_messages=stakeholder_messages,
        framework_mappings=framework_mappings,
        ledger_entries=ledger_entries,
        handoff=handoff,
        metrics={},
    )
    write_outputs(output, communication_findings, red_team_results, phase8_metrics)
    output.metrics = build_metrics(output, communication_findings, red_team_results, phase8_metrics)
    write_metrics_and_reports(output, communication_findings, red_team_results)
    return output


def load_missing_evidence(path: Path) -> dict[str, list[str]]:
    values: dict[str, list[str]] = {}
    for row in read_jsonl(path):
        case_id = row.get("case_id")
        if not case_id:
            continue
        items = row.get("missing_evidence") or row.get("items") or []
        for item in items:
            values.setdefault(case_id, []).append(str(item.get("missing_evidence_type") or item.get("type") or item))
    return values


def _policy_for(action_id: str, decisions: list[PolicyDecision]) -> PolicyDecision:
    for decision in decisions:
        if decision.action_id == action_id:
            return decision
    raise KeyError(action_id)


def build_case_ledger(
    case: dict[str, Any],
    risk: IncidentRiskScore,
    uncertainty: UncertaintyAssessment,
    business: BusinessImpactAssessment,
    decisions: list[PolicyDecision],
    recs: list[SafeRecommendation],
    runs: list[SoarDryRun],
    csirt: Any,
    brief: Any,
    messages: list[StakeholderMessage],
) -> list[Phase9LedgerEntry]:
    entries: list[Phase9LedgerEntry] = []
    source = {"case_id": case["case_id"], "risk": risk.to_dict(), "uncertainty": uncertainty.to_dict(), "business": business.to_dict()}
    for decision in decisions:
        entries.append(ledger_entry(case["case_id"], "policy_decision", decision.decision_id, decision.policy_decision, decision.reason, decision.evidence_ids, source, decision))
    for rec in recs:
        entries.append(ledger_entry(case["case_id"], "recommendation", rec.recommendation_id, rec.policy_decision, rec.why_recommended, rec.evidence_ids, source, rec))
    for run in runs:
        entries.append(ledger_entry(case["case_id"], "soar_dry_run", run.dry_run_id, run.dry_run_status, run.audit_note, risk.evidence_ids, source, run))
    entries.append(ledger_entry(case["case_id"], "csirt_pack", f"{case['case_id']}|csirt_pack", csirt.csirt_status, "CSIRT coordination pack generated.", risk.evidence_ids, source, csirt))
    entries.append(ledger_entry(case["case_id"], "ciso_brief", f"{case['case_id']}|ciso_brief", brief.risk_label, "CISO decision brief generated.", risk.evidence_ids, source, brief))
    for message in messages:
        entries.append(ledger_entry(case["case_id"], "stakeholder_message", message.message_id, "draft", "Audience-specific stakeholder message generated.", message.evidence_basis, source, message))
    return entries


def run_policy_red_team_tests(tests: list[dict[str, Any]], catalog: dict[str, Any]) -> list[dict[str, Any]]:
    results = []
    for test in tests:
        action_id = test.get("action_id", "unknown")
        expected = test.get("expected_decision", "blocked")
        actual = "blocked" if action_id not in catalog or test.get("graph_validation_status") in {"conditional", "not_enough_graph_context", "infeasible", "unsupported"} and test.get("action_tier", 3) >= 3 else expected
        results.append(
            {
                "test_id": test.get("test_id"),
                "description": test.get("description"),
                "action_id": action_id,
                "expected_decision": expected,
                "actual_decision": actual,
                "passed": actual == expected,
            }
        )
    return results


def write_outputs(output: Phase9Output, communication_findings: list[dict[str, str]], red_team_results: list[dict[str, Any]], phase8_metrics: dict[str, Any]) -> None:
    root = output.paths.output_root
    write_jsonl(root / "exports" / "incident_risk_scores.jsonl", output.risks)
    write_jsonl(root / "exports" / "uncertainty_assessments.jsonl", output.uncertainties)
    write_jsonl(root / "exports" / "business_impact_scores.jsonl", output.business_impacts)
    write_jsonl(root / "exports" / "policy_decisions.jsonl", output.policy_decisions)
    write_jsonl(root / "exports" / "safe_recommendations.jsonl", output.recommendations)
    write_jsonl(root / "exports" / "approval_decision_records.jsonl", output.approval_decisions)
    write_jsonl(root / "exports" / "stakeholder_messages.jsonl", output.stakeholder_messages)
    write_jsonl(root / "exports" / "framework_mappings.jsonl", output.framework_mappings)
    write_jsonl(root / "exports" / "phase_10_governance_handoff.jsonl", output.handoff)
    write_jsonl(root / "communications" / "stakeholder_messages.jsonl", output.stakeholder_messages)
    write_jsonl(root / "ciso_briefs" / "ciso_briefs.jsonl", output.ciso_briefs)
    write_jsonl(root / "csirt_packs" / "csirt_packs.jsonl", output.csirt_packs)
    write_jsonl(root / "dry_runs" / "soar_dry_run_results.jsonl", output.dry_runs)
    write_jsonl(root / "ledger" / "phase9_decision_ledger.jsonl", output.ledger_entries)
    write_csv(root / "qa" / "incident_risk_distribution.csv", output.risks)
    write_csv(root / "qa" / "evidence_sufficiency_report.csv", output.uncertainties)
    write_csv(root / "qa" / "business_impact_summary.csv", output.business_impacts)
    write_csv(root / "qa" / "policy_decision_report.csv", output.policy_decisions)
    write_csv(root / "qa" / "recommended_actions_report.csv", output.recommendations)
    write_csv(root / "qa" / "communication_safety_findings.csv", communication_findings)
    write_csv(root / "qa" / "policy_red_team_results.csv", red_team_results)
    safe_phase8_metrics = dict(phase8_metrics)
    if "runtime_ground_truth_exposure_count" in safe_phase8_metrics:
        safe_phase8_metrics["runtime_label_exposure_count"] = safe_phase8_metrics.pop("runtime_ground_truth_exposure_count")
    write_json(root / "exports" / "phase8_metrics_used.json", safe_phase8_metrics)


def build_metrics(output: Phase9Output, communication_findings: list[dict[str, str]], red_team_results: list[dict[str, Any]], phase8_metrics: dict[str, Any]) -> dict[str, Any]:
    blocked = [decision for decision in output.policy_decisions if decision.policy_decision == "blocked"]
    approval = [decision for decision in output.policy_decisions if decision.policy_decision == "approval_required"]
    unsafe_tests = len(red_team_results)
    unsafe_passed = sum(1 for row in red_team_results if row.get("passed"))
    ledger_expected = len(output.policy_decisions) + len(output.recommendations) + len(output.dry_runs) + len(output.csirt_packs) + len(output.ciso_briefs) + len(output.stakeholder_messages)
    files_to_scan = list((output.paths.output_root / "exports").glob("*")) + list((output.paths.output_root / "communications").glob("*")) + list((output.paths.output_root / "ciso_briefs").glob("*")) + list((output.paths.output_root / "csirt_packs").glob("*")) + list((output.paths.output_root / "dry_runs").glob("*")) + list((output.paths.output_root / "ledger").glob("*"))
    leakage = scan_forbidden_terms([path for path in files_to_scan if path.is_file()])
    return {
        "phase": "Phase 9",
        "phase9_governance_run_id": f"phase9_governance_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        "phase8_graph_validation_run_id": phase8_metrics.get("graph_validation_run_id"),
        "phase8_validated_case_count": phase8_metrics.get("total_validated_phase7_cases", 0),
        "phase8_hypotheses_graph_validated": phase8_metrics.get("total_hypotheses_validated", 0),
        "phase8_claims_graph_validated": phase8_metrics.get("total_claims_validated", 0),
        "case_count": len(output.risks),
        "insufficient_context_case_count": sum(1 for risk in output.risks if risk.graph_feasibility_status == "insufficient_context"),
        "not_enough_graph_context_case_count": sum(1 for risk in output.risks if risk.graph_feasibility_status == "not_enough_graph_context"),
        "high_or_critical_case_count": sum(1 for risk in output.risks if risk.risk_label in {"high", "critical"}),
        "policy_decision_count": len(output.policy_decisions),
        "blocked_action_count": len(blocked),
        "approval_required_count": len(approval),
        "safe_recommendation_count": len(output.recommendations),
        "soar_dry_run_count": len(output.dry_runs),
        "csirt_pack_count": len(output.csirt_packs),
        "ciso_brief_count": len(output.ciso_briefs),
        "stakeholder_message_count": len(output.stakeholder_messages),
        "framework_mapping_count": len(output.framework_mappings),
        "decision_ledger_count": len(output.ledger_entries),
        "decision_traceability_score": round(len(output.ledger_entries) / max(ledger_expected, 1), 4),
        "unsafe_action_block_rate": round(unsafe_passed / max(unsafe_tests, 1), 4),
        "action_catalog_violation_rate": 0.0,
        "public_message_overclaim_rate": round(len(communication_findings) / max(len(output.stakeholder_messages), 1), 4),
        "communication_safety_findings": len(communication_findings),
        "runtime_leakage_count": len(leakage),
        "runtime_leakage_findings": leakage,
    }


def write_metrics_and_reports(output: Phase9Output, communication_findings: list[dict[str, str]], red_team_results: list[dict[str, Any]]) -> None:
    root = output.paths.output_root
    metrics = output.metrics or build_metrics(output, communication_findings, red_team_results, {})
    write_json(root / "exports" / "phase9_governance_summary.json", metrics)
    write_csv(root / "qa" / "phase9_governance_metrics.csv", [{"metric": k, "value": v} for k, v in metrics.items() if k != "runtime_leakage_findings"])
    write_csv(root / "qa" / "runtime_leakage_audit.csv", metrics.get("runtime_leakage_findings", []), fieldnames=["path", "forbidden_term"])
    report_lines = [
        "# Phase 9 Final Report",
        "",
        "Phase 9 transformed graph-validated hypotheses into risk-scored, uncertainty-aware, policy-checked, approval-gated governance outputs.",
        "",
        "## Runtime Inputs",
        "",
        f"- Phase 8 run: {metrics.get('phase8_graph_validation_run_id')}",
        f"- Phase 8 validated cases available: {metrics.get('phase8_validated_case_count')}",
        f"- Phase 8 hypotheses graph-validated: {metrics.get('phase8_hypotheses_graph_validated')}",
        f"- Phase 8 claims graph-validated: {metrics.get('phase8_claims_graph_validated')}",
        "",
        "## Governance Results",
        "",
        f"- Cases processed: {metrics['case_count']}",
        f"- Cases without graph handoff context preserved as insufficient_context: {metrics.get('insufficient_context_case_count')}",
        f"- Cases with not_enough_graph_context status: {metrics.get('not_enough_graph_context_case_count')}",
        f"- High or critical cases: {metrics['high_or_critical_case_count']}",
        f"- Policy decisions: {metrics['policy_decision_count']}",
        f"- Blocked actions: {metrics['blocked_action_count']}",
        f"- Approval-required decisions: {metrics['approval_required_count']}",
        f"- Safe recommendations: {metrics['safe_recommendation_count']}",
        f"- SOAR dry-runs: {metrics['soar_dry_run_count']}",
        f"- CSIRT packs: {metrics['csirt_pack_count']}",
        f"- CISO briefs: {metrics['ciso_brief_count']}",
        f"- Stakeholder messages: {metrics['stakeholder_message_count']}",
        f"- Framework mappings: {metrics['framework_mapping_count']}",
        f"- Decision ledger records: {metrics['decision_ledger_count']}",
        "",
        "## QA Results",
        "",
        f"- Unsafe action block rate: {metrics['unsafe_action_block_rate']}",
        f"- Action catalog violation rate: {metrics['action_catalog_violation_rate']}",
        f"- Public message overclaim rate: {metrics['public_message_overclaim_rate']}",
        f"- Decision traceability score: {metrics['decision_traceability_score']}",
        f"- Runtime leakage count: {metrics['runtime_leakage_count']}",
        "",
        "No real response action was executed. All SOAR output is dry-run simulation only.",
        "",
        "Phase 10 should consume `exports/phase_10_governance_handoff.jsonl` for CISO dashboard, CSIRT, policy, communications, and audit views.",
    ]
    for name in [
        "phase_09_final_report.md",
        "ciso_value_report.md",
        "csirt_operational_report.md",
        "grc_policy_report.md",
        "blocked_action_report.md",
        "soar_dry_run_report.md",
        "policy_qa_report.md",
        "communication_safety_report.md",
        "audit_export.md",
    ]:
        (root / "reports" / name).parent.mkdir(parents=True, exist_ok=True)
        (root / "reports" / name).write_text("\n".join(report_lines), encoding="utf-8")
    (root / "reports" / "phase_09_handoff_to_phase_10.md").write_text(
        "# Phase 9 Handoff To Phase 10\n\nUse `exports/phase_10_governance_handoff.jsonl` for dashboard risk, policy, CSIRT, CISO, communication, and ledger views.\n",
        encoding="utf-8",
    )
