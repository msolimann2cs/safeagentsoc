from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys


REPO_ROOT = Path(__file__).resolve().parents[2]
SRC_DIR = REPO_ROOT / "src"
WORKSPACE_ROOT = REPO_ROOT.parents[1]

if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from safeagentsoc.reason.hypothesis_engine import build_hypothesis_outputs
from safeagentsoc.reason.llm_adapter import provider_from_env
from safeagentsoc.reason.repositories import persist_hypothesis_result
from safeagentsoc.storage.db import DatabaseConfig, connect, execute_sql_file


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Build Phase 7 evidence-grounded hypotheses.")
    parser.add_argument(
        "--context-pack",
        type=Path,
        default=WORKSPACE_ROOT / "06_data" / "Phase6" / "timelines" / "exports" / "case_llm_context_pack.jsonl",
    )
    parser.add_argument("--output-root", type=Path, default=WORKSPACE_ROOT / "06_data" / "Phase7" / "reason")
    parser.add_argument("--provider", choices=["mock", "openai"], default="openai")
    parser.add_argument("--model", default="gpt-5-nano")
    parser.add_argument("--timeout-seconds", type=int, default=180)
    parser.add_argument("--reasoning-effort", default="minimal", choices=["minimal", "low", "medium", "high"])
    parser.add_argument("--verbosity", default="low", choices=["low", "medium", "high"])
    parser.add_argument("--max-output-tokens", type=int, default=4096)
    parser.add_argument("--max-retries", type=int, default=2)
    parser.add_argument("--retry-backoff-seconds", type=float, default=1.5)
    parser.add_argument(
        "--api-key-file",
        type=Path,
        default=WORKSPACE_ROOT / "01_admin" / "secrets" / "openai api secret key.txt",
    )
    parser.add_argument("--max-cases", type=int, default=None)
    parser.add_argument("--start-index", type=int, default=0)
    parser.add_argument("--case-ids", default=None, help="Comma-separated case IDs to run (overrides start-index/max-cases).")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--preflight", action="store_true", help="Send one tiny provider request and exit.")
    parser.add_argument("--database-url", default=None)
    parser.add_argument("--schema-file", type=Path, default=REPO_ROOT / "db" / "migrations" / "0005_phase7_reasoning_tables.sql")
    parser.add_argument("--apply-schema", action="store_true")
    parser.add_argument("--persist", action="store_true")
    parser.add_argument("--no-replace", action="store_true")
    parser.add_argument("--strict-success", action="store_true", help="Return non-zero exit code when any case fails validation.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.context_pack = resolve_context_pack(args.context_pack)
    configure_provider_environment(args)
    if args.verbose:
        selected_case_ids = parse_case_ids(args.case_ids)
        print(f"[INFO] Provider: {args.provider}")
        print(f"[INFO] Model: {os.environ.get('SAFEAGENTSOC_LLM_MODEL', '')}")
        print(f"[INFO] Timeout seconds: {os.environ.get('SAFEAGENTSOC_LLM_TIMEOUT_SECONDS', '')}")
        print(f"[INFO] Reasoning effort: {os.environ.get('SAFEAGENTSOC_LLM_REASONING_EFFORT', '')}")
        print(f"[INFO] Verbosity: {os.environ.get('SAFEAGENTSOC_LLM_VERBOSITY', '')}")
        print(f"[INFO] Max output tokens: {os.environ.get('SAFEAGENTSOC_LLM_MAX_OUTPUT_TOKENS', '')}")
        print(f"[INFO] Max retries: {os.environ.get('SAFEAGENTSOC_LLM_MAX_RETRIES', '')}")
        print(f"[INFO] Retry backoff seconds: {os.environ.get('SAFEAGENTSOC_LLM_RETRY_BACKOFF_SECONDS', '')}")
        print(f"[INFO] Context pack: {args.context_pack}")
        print(f"[INFO] Output root: {args.output_root}")
        if selected_case_ids:
            print(f"[INFO] Case IDs override: {selected_case_ids}")
        print(f"[INFO] API key file exists: {args.api_key_file.exists()}")
    if args.preflight:
        return run_preflight(args)
    result = build_hypothesis_outputs(
        context_pack_path=args.context_pack,
        output_root=args.output_root,
        provider_name=args.provider,
        max_cases=args.max_cases,
        start_index=args.start_index,
        case_ids=parse_case_ids(args.case_ids),
        verbose=args.verbose,
    )
    if result.metrics.get("interrupted"):
        print("[WARN] Run interrupted before all target cases were processed. Partial outputs were written.")
        return 130
    if args.persist:
        connection = connect(DatabaseConfig(args.database_url) if args.database_url else None)
        with connection:
            if args.apply_schema:
                execute_sql_file(connection, args.schema_file)
            persist_hypothesis_result(
                connection,
                result,
                run_id=str(result.metrics["hypothesis_run_id"]),
                replace=not args.no_replace,
            )
    print(f"[OK] Cases processed: {result.metrics['total_cases']}")
    print(f"[OK] Validated cases: {result.metrics['validated_case_count']}")
    print(f"[OK] Schema compliance rate: {result.metrics['schema_compliance_rate']}")
    print(f"[OK] Evidence support rate: {result.metrics['evidence_support_rate']}")
    print(f"[OK] Unsupported claim rate: {result.metrics['unsupported_claim_rate']}")
    print(f"[OK] Prompt injection rejection rate: {result.metrics['prompt_injection_rejection_rate']}")
    print(f"[OK] Wrote Phase 7 outputs to {args.output_root}")
    failed_count = int(result.metrics.get("failed_case_count", 0))
    if failed_count > 0:
        print(f"[WARN] Failed cases: {failed_count}")
        print(f"[WARN] Failed case IDs: {result.metrics.get('failed_case_ids', [])}")
        print(f"[WARN] OpenAI provider errors: {result.metrics['provider_error_count']}")
        if args.strict_success:
            return 2
    return 0


def resolve_context_pack(path: Path) -> Path:
    if path.exists():
        return path
    fallback = WORKSPACE_ROOT / "06_data" / "Phase6" / "timelines" / "exports" / "case_llm_context_pack.jsonl"
    if fallback.exists():
        return fallback
    legacy_phase = WORKSPACE_ROOT / "03_data" / "Phase6" / "timelines" / "exports" / "case_llm_context_pack.jsonl"
    if legacy_phase.exists():
        return legacy_phase
    legacy = WORKSPACE_ROOT / "03_data" / "timelines" / "exports" / "case_llm_context_pack.jsonl"
    if legacy.exists():
        return legacy
    return path


def configure_provider_environment(args: argparse.Namespace) -> None:
    if args.provider != "openai":
        return
    os.environ.setdefault("SAFEAGENTSOC_LLM_MODEL", args.model)
    os.environ.setdefault("SAFEAGENTSOC_LLM_TIMEOUT_SECONDS", str(args.timeout_seconds))
    os.environ.setdefault("SAFEAGENTSOC_LLM_REASONING_EFFORT", args.reasoning_effort)
    os.environ.setdefault("SAFEAGENTSOC_LLM_VERBOSITY", args.verbosity)
    os.environ.setdefault("SAFEAGENTSOC_LLM_MAX_OUTPUT_TOKENS", str(args.max_output_tokens))
    os.environ.setdefault("SAFEAGENTSOC_LLM_MAX_RETRIES", str(args.max_retries))
    os.environ.setdefault("SAFEAGENTSOC_LLM_RETRY_BACKOFF_SECONDS", str(args.retry_backoff_seconds))
    if not os.environ.get("OPENAI_API_KEY") and args.api_key_file.exists():
        os.environ["OPENAI_API_KEY"] = args.api_key_file.read_text(encoding="utf-8").strip()


def parse_case_ids(raw_value: str | None) -> list[str] | None:
    if not raw_value:
        return None
    values = [item.strip() for item in str(raw_value).split(",") if item.strip()]
    return values or None


def run_preflight(args: argparse.Namespace) -> int:
    provider = provider_from_env(args.provider)
    print(f"[INFO] Provider diagnostics: {provider.provider_diagnostics()}")
    preflight = getattr(provider, "preflight", None)
    if preflight is None:
        print("[OK] Provider does not require network preflight.")
        return 0
    try:
        result = preflight()
    except Exception as exc:
        print(f"[FAIL] Provider preflight failed: {exc}")
        return 2
    print(f"[OK] Provider preflight succeeded: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
