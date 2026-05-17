CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.hypothesis_runs (
    hypothesis_run_id TEXT PRIMARY KEY,
    generated_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    case_count INTEGER NOT NULL,
    validated_case_count INTEGER NOT NULL,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_hypotheses_raw (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    provider TEXT NOT NULL,
    raw_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_hypotheses_validated (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    validation_status TEXT NOT NULL CHECK (validation_status IN ('passed', 'failed')),
    validated_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.hypothesis_validation_results (
    validation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    validation_type TEXT NOT NULL,
    status TEXT NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.evidence_support_results (
    validation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    hypothesis_id TEXT NOT NULL,
    evidence_supported BOOLEAN NOT NULL,
    support_rate NUMERIC(6,4) NOT NULL DEFAULT 0,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.agent_firewall_results (
    result_id TEXT PRIMARY KEY,
    check_type TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    blocked BOOLEAN NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.ai_decision_ledger (
    decision_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    agent_id TEXT NOT NULL,
    ledger_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    hypothesis_run_id TEXT REFERENCES safeagentsoc_runtime.hypothesis_runs(hypothesis_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_hypotheses_raw_provider ON safeagentsoc_runtime.case_hypotheses_raw(provider);
CREATE INDEX IF NOT EXISTS idx_hypothesis_validation_case ON safeagentsoc_runtime.hypothesis_validation_results(case_id);
CREATE INDEX IF NOT EXISTS idx_evidence_support_case ON safeagentsoc_runtime.evidence_support_results(case_id);
CREATE INDEX IF NOT EXISTS idx_agent_firewall_type ON safeagentsoc_runtime.agent_firewall_results(check_type, blocked);
CREATE INDEX IF NOT EXISTS idx_ai_decision_ledger_case ON safeagentsoc_runtime.ai_decision_ledger(case_id);
