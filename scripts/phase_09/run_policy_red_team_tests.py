from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Run Phase 9 unsafe-action and communication safety tests.").parse_args(argv)
    result = run_phase9(args)
    metrics = result.metrics
    print(f"[OK] Unsafe action block rate: {metrics['unsafe_action_block_rate']}")
    print(f"[OK] Action catalog violation rate: {metrics['action_catalog_violation_rate']}")
    print(f"[OK] Public message overclaim rate: {metrics['public_message_overclaim_rate']}")
    print(f"[OK] Runtime leakage count: {metrics['runtime_leakage_count']}")
    print(f"[OK] Wrote QA outputs to {result.paths.output_root / 'qa'}")
    if args.strict_success and metrics["unsafe_action_block_rate"] < 1.0:
        return 3
    if args.strict_success and metrics["public_message_overclaim_rate"] > 0:
        return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
