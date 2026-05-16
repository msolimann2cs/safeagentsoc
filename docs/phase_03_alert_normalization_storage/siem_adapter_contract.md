# SIEM Adapter Contract

SafeAgentSOC adapters translate source-specific alert formats into the canonical internal contract.

Required adapter outputs:
- normalized alert
- raw alert reference
- evidence reference
- warnings
- errors

Adapters must not expose evaluation-only labels or expected conclusions.

Wazuh is the first adapter, but not the only supported source.
