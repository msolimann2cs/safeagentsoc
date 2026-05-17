from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.context_loader import load_csv
from safeagentsoc.context.context_validator import validate_seed_package


SEED_DIR = WORKSPACE_ROOT / "06_data" / "Phase4" / "context" / "seed"
OBSERVED_HOSTS = WORKSPACE_ROOT / "06_data" / "Phase4" / "context" / "exports" / "observed_hosts.csv"


def test_phase4_context_seed_package_validates():
    assert validate_seed_package(SEED_DIR, OBSERVED_HOSTS) == []


def test_phase4_context_seed_covers_all_observed_hosts():
    observed_agents = {row["agent_name"] for row in load_csv(OBSERVED_HOSTS)}
    assets = load_csv(SEED_DIR / "asset_inventory.csv")
    mapped_agents = {row["observed_agent_name"] for row in assets}

    assert observed_agents <= mapped_agents


def test_phase4_seed_models_wazuh_as_critical_security_infrastructure():
    assets = load_csv(SEED_DIR / "asset_inventory.csv")
    wazuh_assets = [row for row in assets if row["observed_agent_name"] == "safesoc-wazuh-01"]

    assert len(wazuh_assets) >= 3
    assert any(row["asset_criticality"] == "critical" for row in wazuh_assets)
    assert any(row["crown_jewel"] == "true" for row in wazuh_assets)
    assert {row["business_unit"] for row in wazuh_assets} == {"Security"}

