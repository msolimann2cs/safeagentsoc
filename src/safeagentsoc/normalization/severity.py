from __future__ import annotations


def normalize_severity(rule_level: int | None) -> tuple[str, float | None]:
    if rule_level is None:
        return "unknown", None

    if rule_level <= 3:
        return "low", 20.0
    if rule_level <= 7:
        return "medium", 50.0
    if rule_level <= 11:
        return "high", 75.0
    return "critical", 95.0
