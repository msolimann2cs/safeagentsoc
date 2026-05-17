CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_builder_runs (
    case_builder_run_id TEXT PRIMARY KEY,
    generated_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    input_alert_count INTEGER NOT NULL,
    generated_case_count INTEGER NOT NULL,
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.generated_cases (
    case_id TEXT PRIMARY KEY,
    case_priority_label TEXT NOT NULL CHECK (case_priority_label IN ('P1 critical', 'P2 high', 'P3 medium', 'P4 low')),
    case_priority_score NUMERIC(6,2) NOT NULL,
    case_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    case_builder_run_id TEXT REFERENCES safeagentsoc_runtime.case_builder_runs(case_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.alert_case_links (
    case_id TEXT NOT NULL REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    alert_uid TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    runtime_alert_role TEXT NOT NULL CHECK (runtime_alert_role IN ('trigger', 'supporting', 'duplicate', 'noise', 'context', 'unrelated')),
    visibility_level TEXT NOT NULL CHECK (visibility_level IN ('visible_primary', 'visible_supporting', 'collapsed_duplicate', 'collapsed_noise', 'excluded')),
    link_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    case_builder_run_id TEXT REFERENCES safeagentsoc_runtime.case_builder_runs(case_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, alert_uid)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_alert_roles (
    case_id TEXT NOT NULL,
    alert_uid TEXT NOT NULL,
    runtime_alert_role TEXT NOT NULL,
    role_confidence NUMERIC(5,4),
    role_reason TEXT,
    role_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    case_builder_run_id TEXT REFERENCES safeagentsoc_runtime.case_builder_runs(case_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (case_id, alert_uid)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_evidence_summary (
    case_id TEXT PRIMARY KEY REFERENCES safeagentsoc_runtime.generated_cases(case_id),
    evidence_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
    case_builder_run_id TEXT REFERENCES safeagentsoc_runtime.case_builder_runs(case_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_builder_metrics (
    metric TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    case_builder_run_id TEXT REFERENCES safeagentsoc_runtime.case_builder_runs(case_builder_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_generated_cases_priority ON safeagentsoc_runtime.generated_cases(case_priority_label, case_priority_score DESC);
CREATE INDEX IF NOT EXISTS idx_alert_case_links_case ON safeagentsoc_runtime.alert_case_links(case_id);
CREATE INDEX IF NOT EXISTS idx_alert_case_links_alert ON safeagentsoc_runtime.alert_case_links(alert_uid);
CREATE INDEX IF NOT EXISTS idx_alert_case_links_role ON safeagentsoc_runtime.alert_case_links(runtime_alert_role);
CREATE INDEX IF NOT EXISTS idx_alert_case_links_visibility ON safeagentsoc_runtime.alert_case_links(visibility_level);

