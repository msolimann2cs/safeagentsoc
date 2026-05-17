from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.mapping_rules import load_mapping_rules, select_mapping_rule, validate_mapping_rules


MAPPING_RULES = WORKSPACE_ROOT / "06_data" / "Phase4" / "context" / "mappings" / "context_mapping_rules.csv"
SEED_DIR = WORKSPACE_ROOT / "06_data" / "Phase4" / "context" / "seed"


def test_phase4_mapping_rules_validate():
    errors, summary = validate_mapping_rules(MAPPING_RULES, SEED_DIR)

    assert errors == []
    assert summary["mapping_rule_count"] == 39
    assert summary["exact_identity_rules"] >= 10
    assert summary["behavioral_rules"] >= 20
    assert summary["agent_fallback_rules"] == 3
    assert summary["unknown_fallback_rules"] == 1


def test_windows_powershell_alert_maps_to_it_admin_workstation():
    rules = load_mapping_rules(MAPPING_RULES)
    alert = {
        "host": {"agent_name": "safesoc-win-01", "platform": "windows"},
        "rule": {"description": "PowerShell was used to delete files or directories"},
        "entities": {"user": {"username": "safesoc-win-01-user"}},
        "mitre": {"technique_ids": ["T1059"]},
    }

    selected = select_mapping_rule(alert, rules)

    assert selected is not None
    assert selected.mapping_id == "MAP-031"
    assert selected.asset_id == "AST-002"
    assert selected.identity_id == "ID-003"


def test_linux_root_sudo_alert_maps_to_identity_service():
    rules = load_mapping_rules(MAPPING_RULES)
    alert = {
        "host": {"agent_name": "safesoc-lnx-01", "platform": "linux"},
        "rule": {"id": "5402", "description": "sudo command executed"},
        "entities": {"user": {"username": "root"}},
    }

    selected = select_mapping_rule(alert, rules)

    assert selected is not None
    assert selected.mapping_id == "MAP-010"
    assert selected.asset_id == "AST-008"
    assert selected.identity_id == "ID-001"


def test_unknown_alert_uses_explicit_unknown_fallback():
    rules = load_mapping_rules(MAPPING_RULES)
    alert = {
        "host": {"agent_name": "not-in-dataset", "platform": "unknown"},
        "rule": {"description": "unmapped event"},
        "entities": {},
    }

    selected = select_mapping_rule(alert, rules)

    assert selected is not None
    assert selected.mapping_id == "MAP-999"
    assert selected.asset_id == "__UNKNOWN__"
    assert selected.fallback_behavior == "return_unknown_context"
