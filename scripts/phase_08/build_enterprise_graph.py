from __future__ import annotations

import argparse
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.graph.graph_export import write_enterprise_graph
from safeagentsoc.graph.validation_engine import default_paths
from safeagentsoc.graph.graph_builder import build_enterprise_graph


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build and export the Phase 8 runtime enterprise graph.")
    parser.add_argument("--phase7-root", type=Path, default=None)
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase8" / "graph_validation")
    parser.add_argument("--verbose", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    paths = default_paths(WORKSPACE_ROOT, phase7_root=args.phase7_root, output_root=args.output_root)
    result = build_enterprise_graph(
        graph_nodes_path=paths.phase4_context / "graph_seed" / "graph_nodes.csv",
        graph_edges_path=paths.phase4_context / "graph_seed" / "graph_edges.csv",
        enriched_alerts_path=paths.phase4_context / "exports" / "context_enriched_alerts_with_risk.jsonl",
        asset_inventory_path=paths.phase4_context / "seed" / "asset_inventory.csv",
        identity_inventory_path=paths.phase4_context / "seed" / "identity_inventory.csv",
        network_zones_path=paths.phase4_context / "seed" / "network_zones.csv",
        generated_cases_path=paths.phase5_exports / "generated_cases.jsonl",
        case_timelines_path=paths.phase6_exports / "case_timelines.jsonl",
        validated_hypotheses_path=paths.validated_hypotheses_path,
    )
    write_enterprise_graph(result.graph, paths.output_root)
    print(f"[OK] Graph nodes: {len(result.graph.nodes)}")
    print(f"[OK] Graph edges: {len(result.graph.edges)}")
    print(f"[OK] NetworkX available: {result.graph.networkx_available}")
    print(f"[OK] Wrote graph exports to {paths.output_root / 'exports'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
