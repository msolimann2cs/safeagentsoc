CREATE SCHEMA IF NOT EXISTS safeagentsoc_eval;

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.ground_truth_labels (
    label_id BIGSERIAL PRIMARY KEY,
    alert_uid TEXT NOT NULL,
    label TEXT NOT NULL,
    event_role TEXT NOT NULL,
    confidence TEXT NOT NULL,
    scenario_id TEXT,
    campaign_id TEXT,
    run_id TEXT,
    case_id TEXT,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (label IN (
        'benign',
        'noise',
        'ambiguous_noise',
        'attack_like',
        'attack_like_failed',
        'simulated_only',
        'unrelated_background'
    )),
    CHECK (event_role IN ('trigger', 'supporting', 'duplicate', 'noise', 'unrelated')),
    CHECK (confidence IN ('high', 'medium', 'low'))
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.casebook_cases (
    case_id TEXT PRIMARY KEY,
    scenario_id TEXT,
    campaign_id TEXT,
    run_id TEXT,
    execution_mode TEXT,
    expected_conclusion TEXT,
    case_summary TEXT,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    casebook_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.alert_case_links_gold (
    link_id BIGSERIAL PRIMARY KEY,
    alert_uid TEXT NOT NULL,
    case_id TEXT NOT NULL REFERENCES safeagentsoc_eval.casebook_cases(case_id),
    event_role TEXT NOT NULL,
    confidence TEXT,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (alert_uid, case_id, event_role)
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.scenario_run_log (
    run_id TEXT PRIMARY KEY,
    scenario_id TEXT,
    campaign_id TEXT,
    execution_mode TEXT,
    host_name TEXT,
    platform TEXT,
    start_time_utc TIMESTAMPTZ,
    end_time_utc TIMESTAMPTZ,
    operator_notes TEXT,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.detection_gap_register (
    gap_id TEXT PRIMARY KEY,
    scenario_id TEXT,
    campaign_id TEXT,
    run_id TEXT,
    technique_id TEXT,
    gap_type TEXT,
    gap_description TEXT NOT NULL,
    expected_detection TEXT,
    observed_detection TEXT,
    severity TEXT,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.alert_fatigue_baseline (
    baseline_id BIGSERIAL PRIMARY KEY,
    alert_uid TEXT,
    rule_id TEXT,
    rule_description TEXT,
    agent_name TEXT,
    event_time_utc TIMESTAMPTZ,
    baseline_bucket TEXT,
    baseline_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    evaluation_source TEXT NOT NULL,
    loaded_batch_id TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_eval.evaluation_scores (
    score_id BIGSERIAL PRIMARY KEY,
    evaluation_run_id TEXT NOT NULL,
    metric_name TEXT NOT NULL,
    metric_value NUMERIC,
    metric_unit TEXT,
    scope TEXT,
    notes TEXT,
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (evaluation_run_id, metric_name, scope)
);
