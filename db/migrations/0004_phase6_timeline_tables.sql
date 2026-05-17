CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.timeline_builder_runs (
    timeline_builder_run_id TEXT PRIMARY KEY,
    generated_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    case_count INTEGER NOT NULL,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_timelines (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    timeline_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_timeline_steps (
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    step_id TEXT NOT NULL,
    step_order INTEGER NOT NULL,
    step_type TEXT NOT NULL,
    claim_type TEXT NOT NULL CHECK (claim_type IN ('observed', 'inferred', 'not_observed', 'unknown')),
    confidence_score NUMERIC(6,4),
    step_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, step_id)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_technique_claims (
    claim_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    technique_id TEXT,
    tactic TEXT,
    claim_type TEXT NOT NULL CHECK (claim_type IN ('observed', 'inferred', 'not_observed', 'unknown')),
    confidence_score NUMERIC(6,4),
    claim_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_missing_evidence (
    missing_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    missing_evidence_type TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('observed', 'not_observed', 'unknown')),
    missing_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_attack_stories (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    story_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_kill_chain_progression (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    progression_depth TEXT NOT NULL,
    progression_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.timeline_quality_metrics (
    metric TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    timeline_builder_run_id TEXT REFERENCES safeagentsoc_runtime.timeline_builder_runs(timeline_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_case_timeline_steps_case ON safeagentsoc_runtime.case_timeline_steps(case_id, step_order);
CREATE INDEX IF NOT EXISTS idx_case_technique_claims_case ON safeagentsoc_runtime.case_technique_claims(case_id);
CREATE INDEX IF NOT EXISTS idx_case_technique_claims_technique ON safeagentsoc_runtime.case_technique_claims(technique_id, tactic);
CREATE INDEX IF NOT EXISTS idx_case_missing_evidence_case ON safeagentsoc_runtime.case_missing_evidence(case_id);
CREATE INDEX IF NOT EXISTS idx_case_kill_chain_depth ON safeagentsoc_runtime.case_kill_chain_progression(progression_depth);

