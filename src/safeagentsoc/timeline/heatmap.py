from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean
from typing import Any

from safeagentsoc.timeline.attack_catalog import tactic_slug


def build_heatmap_outputs(technique_claims: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
    by_technique: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    by_case: dict[str, list[dict[str, Any]]] = defaultdict(list)
    tactic_counter: Counter[str] = Counter()
    for claim in technique_claims:
        if not claim.get("technique_id"):
            continue
        by_technique[(claim["tactic"], claim["technique_id"])].append(claim)
        by_case[claim["case_id"]].append(claim)
        tactic_counter[claim["tactic"]] += 1

    matrix: list[dict[str, Any]] = []
    for (tactic, technique_id), claims in sorted(by_technique.items()):
        matrix.append(
            {
                "tactic": tactic,
                "technique_id": technique_id,
                "technique_name": claims[0].get("technique_name"),
                "case_count": len({claim["case_id"] for claim in claims}),
                "alert_count": sum(int(claim.get("alert_count") or 0) for claim in claims),
                "trigger_count": sum(int(claim.get("trigger_count") or 0) for claim in claims),
                "supporting_count": sum(int(claim.get("supporting_count") or 0) for claim in claims),
                "avg_confidence": round(mean(float(claim.get("confidence_score") or 0) for claim in claims), 4),
                "observed_count": sum(1 for claim in claims if claim.get("claim_type") == "observed"),
                "inferred_count": sum(1 for claim in claims if claim.get("claim_type") == "inferred"),
            }
        )

    by_case_rows = [
        {
            "case_id": case_id,
            "technique_count": len({claim["technique_id"] for claim in claims}),
            "observed_count": sum(1 for claim in claims if claim.get("claim_type") == "observed"),
            "inferred_count": sum(1 for claim in claims if claim.get("claim_type") == "inferred"),
            "avg_confidence": round(mean(float(claim.get("confidence_score") or 0) for claim in claims), 4),
            "technique_ids": sorted({claim["technique_id"] for claim in claims}),
        }
        for case_id, claims in sorted(by_case.items())
    ]
    tactic_rows = [{"tactic": tactic, "claim_count": count} for tactic, count in sorted(tactic_counter.items())]
    return matrix, by_case_rows, tactic_rows, navigator_layer(matrix)


def navigator_layer(matrix: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "name": "SafeAgentSOC Phase 6 ATT&CK Coverage",
        "versions": {"attack": "19", "navigator": "5.2.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Evidence-weighted ATT&CK coverage generated from SafeAgentSOC Phase 6 deterministic case timelines.",
        "filters": {"platforms": ["Windows", "Linux", "Network"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "showName": True,
            "showID": True,
            "showAggregateScores": True,
            "countUnscored": False,
            "aggregateFunction": "average",
            "expandedSubtechniques": "annotated",
        },
        "hideDisabled": False,
        "techniques": [
            {
                "techniqueID": row["technique_id"],
                "tactic": tactic_slug(row["tactic"]),
                "score": round(float(row["avg_confidence"]) * 100, 2),
                "comment": (
                    f"{row['case_count']} cases; observed={row['observed_count']}; "
                    f"inferred={row['inferred_count']}; duplicate volume not used as confidence multiplier."
                ),
                "metadata": [
                    {"name": "case_count", "value": str(row["case_count"])},
                    {"name": "alert_count", "value": str(row["alert_count"])},
                    {"name": "observed_count", "value": str(row["observed_count"])},
                    {"name": "inferred_count", "value": str(row["inferred_count"])},
                ],
                "showSubtechniques": "." in str(row["technique_id"]),
            }
            for row in matrix
        ],
        "gradient": {"colors": ["#d9e2ec", "#f7c948", "#2f855a"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Weak or sparse evidence", "color": "#d9e2ec"},
            {"label": "Medium confidence", "color": "#f7c948"},
            {"label": "High confidence observed evidence", "color": "#2f855a"},
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#f3f4f6",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
        "selectVisibleTechniques": False,
        "metadata": [
            {"name": "source", "value": "SafeAgentSOC Phase 6 runtime outputs"},
            {"name": "runtime_safety", "value": "runtime_only_no_evaluation_artifacts"},
        ],
    }

