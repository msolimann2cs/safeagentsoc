# Schema Decision Record: Sprint 1

## Decision

SafeAgentSOC will use an internal canonical alert schema instead of building directly on Wazuh raw alerts.

## Reason

Phase 3 must support future SIEM adapters, including Splunk, Sentinel, Elastic, Defender, CrowdStrike, and Google SecOps.

If SafeAgentSOC depends directly on Wazuh field names, the project becomes a Wazuh plugin.

## Dataset-Specific Requirements

The schema must support:

- 6,893 raw Wazuh alerts
- 800 gold-label rows in evaluation only
- 50 investigation cases in evaluation only
- manual execution mode
- Atomic Red Team execution mode
- Caldera execution mode
- simulated-only gaps
- benign and noisy activity
- unlabeled background telemetry
- missing or partially recovered Caldera metadata

## Ground-Truth Leakage Decision

Ground-truth labels are excluded from runtime normalized alerts.

Evaluation labels are represented by a separate evaluation-only schema.

## Evidence Decision

Every normalized alert must link back to:

- raw file name
- raw file line number
- raw alert SHA256
- raw file SHA256
- ingestion batch ID
- evidence ID

## Status

Accepted for Phase 3 Sprint 1.
