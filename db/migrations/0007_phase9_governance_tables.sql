CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.phase9_governance_runs (
    phase9_governance_run_id TEXT PRIMARY KEY,
    generated_at_utc TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.incident_risk_scores (
    risk_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.uncertainty_assessments (
    uncertainty_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.business_impact_assessments (
    business_impact_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.action_catalog (
    action_id TEXT PRIMARY KEY,
    action_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.policy_decisions (
    decision_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.safe_recommendations (
    recommendation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.soar_dry_runs (
    dry_run_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.approval_workflows (
    approval_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.stakeholder_messages (
    message_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.ciso_decision_briefs (
    brief_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.csirt_coordination_packs (
    pack_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.framework_mappings (
    mapping_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.phase9_decision_ledger (
    decision_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    result_record JSONB NOT NULL,
    phase9_governance_run_id TEXT REFERENCES safeagentsoc_runtime.phase9_governance_runs(phase9_governance_run_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_phase9_risk_case ON safeagentsoc_runtime.incident_risk_scores(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_uncertainty_case ON safeagentsoc_runtime.uncertainty_assessments(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_business_case ON safeagentsoc_runtime.business_impact_assessments(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_policy_case ON safeagentsoc_runtime.policy_decisions(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_recommendations_case ON safeagentsoc_runtime.safe_recommendations(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_dry_runs_case ON safeagentsoc_runtime.soar_dry_runs(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_approvals_case ON safeagentsoc_runtime.approval_workflows(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_messages_case ON safeagentsoc_runtime.stakeholder_messages(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_ciso_case ON safeagentsoc_runtime.ciso_decision_briefs(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_csirt_case ON safeagentsoc_runtime.csirt_coordination_packs(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_framework_case ON safeagentsoc_runtime.framework_mappings(case_id);
CREATE INDEX IF NOT EXISTS idx_phase9_ledger_case ON safeagentsoc_runtime.phase9_decision_ledger(case_id);
