from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Generate Phase 9 CISO decision briefs and board narratives.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] CISO briefs: {len(result.ciso_briefs)}")
    print(f"[OK] Wrote CISO briefs to {result.paths.output_root / 'ciso_briefs' / 'ciso_briefs.jsonl'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
