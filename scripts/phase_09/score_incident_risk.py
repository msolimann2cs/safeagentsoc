from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Score Phase 9 incident risk, uncertainty, and business impact.").parse_args(argv)
    result = run_phase9(args)
    print(f"[OK] Risk scores: {len(result.risks)}")
    print(f"[OK] Uncertainty assessments: {len(result.uncertainties)}")
    print(f"[OK] Business impact assessments: {len(result.business_impacts)}")
    print(f"[OK] Wrote risk outputs to {result.paths.output_root / 'exports'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
