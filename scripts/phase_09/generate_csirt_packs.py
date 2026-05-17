from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Generate Phase 9 CSIRT coordination packs.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] CSIRT packs: {len(result.csirt_packs)}")
    print(f"[OK] Wrote CSIRT packs to {result.paths.output_root / 'csirt_packs' / 'csirt_packs.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
