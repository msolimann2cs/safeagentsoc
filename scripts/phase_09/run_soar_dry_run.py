from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Run Phase 9 SOAR dry-run simulation only.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] SOAR dry-runs: {len(result.dry_runs)}")
    print("[OK] Real response actions executed: 0")
    print(f"[OK] Wrote dry-runs to {result.paths.output_root / 'dry_runs' / 'soar_dry_run_results.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
