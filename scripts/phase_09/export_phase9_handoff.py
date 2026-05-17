from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Export Phase 9 handoff pack for the Phase 10 dashboard.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] Phase 10 handoff rows: {len(result.handoff)}")
    print(f"[OK] Wrote handoff to {result.paths.output_root / 'exports' / 'phase_10_governance_handoff.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
