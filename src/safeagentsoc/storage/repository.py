from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


class QueryConnection(Protocol):
    def execute(self, query: str, params: object | None = None) -> Any:
        ...


RUNTIME_SCHEMA = "safeagentsoc_runtime"
EVAL_SCHEMA = "safeagentsoc_eval"


def ensure_runtime_query(query: str) -> None:
    lowered = query.lower()
    forbidden_fragments = [
        f"{EVAL_SCHEMA}.",
        "ground_truth",
        "casebook",
        "expected_conclusion",
        "gold_",
    ]
    for fragment in forbidden_fragments:
        if fragment in lowered:
            raise ValueError(f"Runtime repository query references evaluation-only data: {fragment}")


@dataclass
class RuntimeAlertRepository:
    connection: QueryConnection

    def execute_runtime_query(self, query: str, params: object | None = None) -> Any:
        ensure_runtime_query(query)
        return self.connection.execute(query, params)

    def list_alerts(
        self,
        *,
        limit: int = 100,
        offset: int = 0,
        agent_name: str | None = None,
        platform: str | None = None,
        rule_id: str | None = None,
        rule_level: int | None = None,
        decoder_name: str | None = None,
        event_category: str | None = None,
        event_action: str | None = None,
        event_outcome: str | None = None,
        severity: str | None = None,
        mitre_technique_id: str | None = None,
        timestamp_from: str | None = None,
        timestamp_to: str | None = None,
        source: str | None = None,
        normalization_status: str | None = None,
    ) -> Any:
        clauses: list[str] = []
        params: dict[str, object] = {"limit": limit, "offset": offset}

        if agent_name:
            clauses.append("agent_name = %(agent_name)s")
            params["agent_name"] = agent_name
        if platform:
            clauses.append("platform = %(platform)s")
            params["platform"] = platform
        if rule_id:
            clauses.append("rule_id = %(rule_id)s")
            params["rule_id"] = rule_id
        if rule_level is not None:
            clauses.append("rule_level = %(rule_level)s")
            params["rule_level"] = rule_level
        if decoder_name:
            clauses.append("decoder_name = %(decoder_name)s")
            params["decoder_name"] = decoder_name
        if event_category:
            clauses.append("event_category = %(event_category)s")
            params["event_category"] = event_category
        if event_action:
            clauses.append("event_action = %(event_action)s")
            params["event_action"] = event_action
        if event_outcome:
            clauses.append("event_outcome = %(event_outcome)s")
            params["event_outcome"] = event_outcome
        if severity:
            clauses.append("severity_normalized = %(severity)s")
            params["severity"] = severity
        if mitre_technique_id:
            clauses.append("%(mitre_technique_id)s = ANY(mitre_technique_ids)")
            params["mitre_technique_id"] = mitre_technique_id
        if timestamp_from:
            clauses.append("event_time_utc >= %(timestamp_from)s")
            params["timestamp_from"] = timestamp_from
        if timestamp_to:
            clauses.append("event_time_utc <= %(timestamp_to)s")
            params["timestamp_to"] = timestamp_to
        if source:
            clauses.append("source_system = %(source)s")
            params["source"] = source
        if normalization_status:
            clauses.append("normalization_status = %(normalization_status)s")
            params["normalization_status"] = normalization_status

        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.v_alerts_runtime
            {where_sql}
            ORDER BY event_time_utc DESC
            LIMIT %(limit)s
            OFFSET %(offset)s
        """
        return self.execute_runtime_query(query, params)

    def get_alert(self, alert_uid: str) -> Any:
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.v_alerts_runtime
            WHERE alert_uid = %(alert_uid)s
        """
        return self.execute_runtime_query(query, {"alert_uid": alert_uid})

    def get_evidence(self, evidence_id: str) -> Any:
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.v_evidence_runtime
            WHERE evidence_id = %(evidence_id)s
        """
        return self.execute_runtime_query(query, {"evidence_id": evidence_id})

    def normalization_metrics(self) -> Any:
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.v_normalization_metrics
            ORDER BY ingestion_batch_id
        """
        return self.execute_runtime_query(query)

    def runtime_summary(self) -> Any:
        query = f"""
            SELECT
                COUNT(*) AS alert_count,
                COUNT(DISTINCT agent_name) AS agent_count,
                COUNT(DISTINCT rule_id) AS rule_count,
                COUNT(*) FILTER (WHERE severity_normalized = 'critical') AS critical_count,
                COUNT(*) FILTER (WHERE severity_normalized = 'high') AS high_count,
                COUNT(*) FILTER (WHERE normalization_status = 'failed') AS failed_normalization_count,
                MIN(event_time_utc) AS earliest_event_time_utc,
                MAX(event_time_utc) AS latest_event_time_utc
            FROM {RUNTIME_SCHEMA}.v_alerts_runtime
        """
        return self.execute_runtime_query(query)

    def get_rule(self, rule_id: str) -> Any:
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.v_rule_summary
            WHERE rule_id = %(rule_id)s
        """
        return self.execute_runtime_query(query, {"rule_id": rule_id})

    def get_mitre(self, technique_id: str) -> Any:
        query = f"""
            SELECT *
            FROM {RUNTIME_SCHEMA}.mitre_techniques
            WHERE technique_id = %(technique_id)s
        """
        return self.execute_runtime_query(query, {"technique_id": technique_id})


@dataclass
class EvaluationRepository:
    connection: QueryConnection

    def label_linkage_metrics(self) -> Any:
        query = f"""
            SELECT *
            FROM {EVAL_SCHEMA}.v_label_linkage_metrics
            ORDER BY loaded_batch_id
        """
        return self.connection.execute(query)

    def casebook_linkage_metrics(self) -> Any:
        query = f"""
            SELECT *
            FROM {EVAL_SCHEMA}.v_casebook_linkage_metrics
            ORDER BY loaded_batch_id
        """
        return self.connection.execute(query)
