from __future__ import annotations

from _common import build_common_parser, print_summary, run_phase9


def main(argv: list[str] | None = None) -> int:
    parser = build_common_parser("Build full Phase 9 governance, risk, policy, CSIRT, CISO, and handoff outputs.")
    args = parser.parse_args(argv)
    result = run_phase9(args)
    print_summary(result)
    if args.strict_success and result.metrics["runtime_leakage_count"]:
        return 2
    if args.strict_success and result.metrics["unsafe_action_block_rate"] < 1.0:
        return 3
    if args.strict_success and result.metrics["public_message_overclaim_rate"] > 0:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
