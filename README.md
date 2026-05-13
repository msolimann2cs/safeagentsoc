# SafeAgentSOC

SafeAgentSOC is a GRC-aware, tool-constrained AI SOC co-analyst prototype for reducing SOC alert fatigue through SIEM telemetry, alert normalization, incident case-building, context enrichment, LLM-assisted hypothesis generation, graph validation, risk scoring, GRC policy guardrails, constrained action recommendations, and human-in-the-loop approval.

## Current Status

Phase 1 completed: Lab Foundation.

## Phase 1 Summary

The SafeAgentSOC lab foundation was completed by deploying a Wazuh-based SIEM/XDR environment, onboarding Windows and Linux endpoints, configuring endpoint telemetry, and proving that login, process, Sysmon, SSH, and sudo events are ingested into Wazuh.

## Phase 1 Components

| Component | Status |
|---|---|
| Wazuh server | Complete |
| Windows endpoint | Complete |
| Linux endpoint | Complete |
| Sysmon telemetry | Complete |
| Wazuh agent onboarding | Complete |
| Log ingestion proof | Complete |
| Network diagram | Complete |
| VM inventory | Complete |
| Troubleshooting log | Complete |
| Lab foundation report | Complete |

## Lab Topology

| Host | Role | IP |
|---|---|---:|
| safesoc-wazuh-01 | Wazuh server, indexer, dashboard | 10.10.10.10 |
| safesoc-win-01 | Windows endpoint, Wazuh agent, Sysmon | 10.10.10.21 |
| safesoc-lnx-01 | Linux endpoint, Wazuh agent, SSH/auth/sudo logs | 10.10.10.31 |

Network details:

```text
VMware VMnet10
Subnet: 10.10.10.0/24
Host VMnet10 adapter: 10.10.10.1
VMware NAT gateway: 10.10.10.2
```

## Safety Scope

This project is conducted only inside a controlled lab environment. It does not target third-party systems, does not deploy destructive response actions by default, and does not use the LLM as the final decision-maker.

## Next Phase

Phase 2 will focus on telemetry scenarios and dataset creation.

