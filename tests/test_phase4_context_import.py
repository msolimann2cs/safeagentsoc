from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[1]
WORKSPACE_ROOT = REPO_ROOT.parents[1]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.repositories import (
    ContextImportPaths,
    collect_import_metadata,
    validate_context_import_inputs,
)


SEED_DIR = WORKSPACE_ROOT / "03_data" / "context" / "seed"
MAPPING_RULES = WORKSPACE_ROOT / "03_data" / "context" / "mappings" / "context_mapping_rules.csv"
MIGRATION = REPO_ROOT / "db" / "migrations" / "0002_phase4_context_tables.sql"


def test_phase4_context_import_inputs_validate():
    paths = ContextImportPaths(seed_dir=SEED_DIR, mapping_rules=MAPPING_RULES)

    assert validate_context_import_inputs(paths) == []


def test_phase4_context_import_metadata_records_counts_and_hashes():
    paths = ContextImportPaths(seed_dir=SEED_DIR, mapping_rules=MAPPING_RULES)
    row_counts, file_hashes = collect_import_metadata(paths)

    assert row_counts["asset_inventory"] == 14
    assert row_counts["identity_inventory"] == 15
    assert row_counts["context_mapping_rules"] == 39
    assert set(row_counts) == set(file_hashes)
    assert all(len(value) == 64 for value in file_hashes.values())


def test_phase4_context_migration_is_runtime_only():
    sql = MIGRATION.read_text(encoding="utf-8").lower()

    assert "safeagentsoc_runtime.context_assets" in sql
    assert "safeagentsoc_runtime.context_mapping_rules" in sql
    assert "safeagentsoc_eval" not in sql
    assert "ground_truth" not in sql
    assert "casebook" not in sql
