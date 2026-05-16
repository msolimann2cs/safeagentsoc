# Alert UID Strategy

## Purpose

SafeAgentSOC uses deterministic alert identifiers so every downstream object can trace back to raw evidence.

## Strategy Version

`alert_uid_v1`

## UID Inputs

The natural alert fingerprint is generated from runtime-safe raw Wazuh fields:

- `timestamp`
- `agent.name`
- `rule.id`
- `decoder.name`
- `location`
- SHA256 of `full_log`, when present

The fingerprint does not use ground-truth labels, casebook answers, expected conclusions, or evaluation-only data.

## UID Format

Alert UIDs use this public format:

```text
alert_<32 hex characters>
```

The UID is generated from a SHA256 hash over a canonical JSON payload containing the strategy version and UID inputs.

## Duplicate Behavior

If multiple raw alerts produce the same natural fingerprint, SafeAgentSOC disambiguates those alerts by adding `raw_line_number` to the final UID payload.

This preserves two important properties:

- identical raw events can still be represented as separate evidence-bearing alerts
- duplicate behavior is explicit and measurable

The lineage CSV records:

- `natural_alert_fingerprint`
- `natural_fingerprint_count`
- `uid_disambiguation`

## Stability Boundary

The UID is stable for the same raw export and line ordering. If a source system later provides a durable event ID, a future strategy version can prefer that value while preserving `alert_uid_v1` for historical reproducibility.

## Runtime/Evaluation Boundary

UID generation is runtime-safe. It does not use:

- labels
- event roles
- casebook answers
- expected conclusions
- gold case links
- true-positive or false-positive indicators
