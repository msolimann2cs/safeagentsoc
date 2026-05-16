from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.context.context_validator import (
    validate_mapping_rule_package,
    validate_schema_package,
    validate_seed_package,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Phase 4 context schema package.")
    parser.add_argument("--schema-dir", type=Path)
    parser.add_argument("--seed-dir", type=Path)
    parser.add_argument("--observed-hosts", type=Path)
    parser.add_argument("--mapping-rules", type=Path)
    args = parser.parse_args(argv)
    errors: list[str] = []
    if args.schema_dir:
        errors.extend(validate_schema_package(args.schema_dir))
    if args.seed_dir:
        errors.extend(validate_seed_package(args.seed_dir, args.observed_hosts))
    if args.mapping_rules:
        if not args.seed_dir:
            print("[FAIL] Provide --seed-dir when validating --mapping-rules.", file=sys.stderr)
            return 1
        errors.extend(validate_mapping_rule_package(args.mapping_rules, args.seed_dir))
    if not args.schema_dir and not args.seed_dir and not args.mapping_rules:
        print("[FAIL] Provide --schema-dir, --seed-dir, or --mapping-rules.", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"[FAIL] {error}", file=sys.stderr)
        return 1
    print("[OK] Phase 4 context files are present, readable, and valid for the requested checks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
