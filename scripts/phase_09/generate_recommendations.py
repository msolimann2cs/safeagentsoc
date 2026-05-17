from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Generate Phase 9 safe recommendations and safer alternatives.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] Safe recommendations: {len(result.recommendations)}")
    print(f"[OK] Wrote recommendations to {result.paths.output_root / 'exports' / 'safe_recommendations.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
