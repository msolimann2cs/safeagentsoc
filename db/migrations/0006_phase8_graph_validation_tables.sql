CREATE SCHEMA IF NOT EXISTS safeagentsoc_runtime;

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.graph_validation_runs (
    graph_validation_run_id TEXT PRIMARY KEY,
    generated_at_utc TIMESTAMPTZ NOT NULL DEFAULT now(),
    metrics JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.enterprise_graph_nodes (
    node_id TEXT PRIMARY KEY,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.enterprise_graph_edges (
    edge_id TEXT PRIMARY KEY,
    source_node_id TEXT NOT NULL,
    target_node_id TEXT NOT NULL,
    relationship TEXT NOT NULL,
    weight NUMERIC(8,4) NOT NULL DEFAULT 1.0,
    properties JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.hypothesis_graph_claims (
    claim_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    claim_type TEXT NOT NULL,
    claim_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.claim_entity_resolution (
    resolution_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.claim_path_validation (
    path_validation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.graph_validation_results (
    validation_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.missing_graph_evidence (
    missing_graph_evidence_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL,
    hypothesis_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    result_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS safeagentsoc_runtime.case_graph_exports (
    case_id TEXT PRIMARY KEY,
    export_record JSONB NOT NULL DEFAULT '{}'::jsonb,
    graph_validation_run_id TEXT REFERENCES safeagentsoc_runtime.graph_validation_runs(graph_validation_run_id),
    created_at_utc TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_enterprise_graph_nodes_type ON safeagentsoc_runtime.enterprise_graph_nodes(node_type);
CREATE INDEX IF NOT EXISTS idx_enterprise_graph_edges_relationship ON safeagentsoc_runtime.enterprise_graph_edges(relationship);
CREATE INDEX IF NOT EXISTS idx_hypothesis_graph_claims_case ON safeagentsoc_runtime.hypothesis_graph_claims(case_id, hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_claim_entity_resolution_case ON safeagentsoc_runtime.claim_entity_resolution(case_id, hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_claim_path_validation_case ON safeagentsoc_runtime.claim_path_validation(case_id, hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_graph_validation_results_case ON safeagentsoc_runtime.graph_validation_results(case_id, hypothesis_id);
CREATE INDEX IF NOT EXISTS idx_missing_graph_evidence_case ON safeagentsoc_runtime.missing_graph_evidence(case_id, hypothesis_id);
