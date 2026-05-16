# Normalized Alert Schema

SafeAgentSOC uses `normalized_alert` as the canonical runtime alert object.

This schema is intentionally:
- SIEM-agnostic
- evidence-linked
- runtime-safe
- evaluation-separated

The schema must support:
- 6,893 raw Wazuh alerts
- 800 evaluation-only gold labels
- 50 investigation cases
- manual, Atomic Red Team, Caldera, benign, noise, and simulated-only execution modes
- missing or partial Caldera metadata

Ground-truth labels and casebook answers are excluded from runtime objects.
