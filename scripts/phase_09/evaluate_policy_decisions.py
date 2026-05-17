from __future__ import annotations

from _common import build_common_parser, run_phase9


def main(argv: list[str] | None = None) -> int:
    args = build_common_parser("Evaluate Phase 9 action policy decisions.").parse_args(argv)
    result = run_phase9(args)
    blocked = sum(1 for decision in result.policy_decisions if decision.policy_decision == "blocked")
    approval = sum(1 for decision in result.policy_decisions if decision.policy_decision == "approval_required")
    print(f"[OK] Policy decisions: {len(result.policy_decisions)}")
    print(f"[OK] Blocked actions: {blocked}")
    print(f"[OK] Approval-required actions: {approval}")
    print(f"[OK] Wrote policy outputs to {result.paths.output_root / 'exports'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
