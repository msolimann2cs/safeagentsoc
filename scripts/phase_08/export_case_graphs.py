from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.graph.validation_engine import build_graph_validation_outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Export lightweight per-case graph views for Phase 8.")
    parser.add_argument("--phase7-root", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase8" / "graph_validation")
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--include-context-nodes", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result = build_graph_validation_outputs(
        workspace_root=WORKSPACE_ROOT,
        phase7_root=args.phase7_root,
        output_root=args.output_root,
        export_case_graphs=True,
        include_context_nodes=args.include_context_nodes,
        max_case_graph_exports=args.max_cases,
        verbose=args.verbose,
    )
    print(f"[OK] Case graph exports: {len(result.case_graph_exports)}")
    print(f"[OK] Wrote visualizations to {result.paths.output_root / 'visualizations' / 'case_graphs'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
