# Phase 2 Plan: Scenario Design, Emulation, and Dataset Creation

## Objective

Create a controlled, labeled, MITRE-mapped Wazuh alert dataset across benign baseline, manual adversary emulation, Atomic Red Team validation, MITRE Caldera campaigns, and simulated-only high-risk gaps.

## Private Mapping

| Private plan | Public GitHub name |
|---|---|
| Month 3 | Phase 2 |
| Scenario and dataset creation | Scenario Design, Emulation, and Dataset Creation |
| month_03 | phase_02_scenario_dataset |
| month-03-dataset | feature/scenario-dataset |
| Month 3 report | Dataset Creation Report |

## Primary Deliverables

- Scenario catalog
- Campaign catalog
- Raw Wazuh alert dataset
- Ground-truth labels
- MITRE mapping table
- Simulated-only gap register
- Dataset documentation
- Dataset QA report
- Dataset Creation Report

## Target Dataset Size

| Target | Meaning |
|---|---|
| 300 alerts | Minimum acceptable dataset size |
| 600 alerts | Strong practical target |
| 1,000 alerts | Upper target if labeling remains clean |

## Safety Boundary

All tests must run only inside the SafeAgentSOC lab. No third-party systems, no malware, no credential dumping, no ransomware simulation, no destructive persistence, and no real data exfiltration.

## Carried-Forward Lab

| Host | Role | IP |
|---|---|---:|
| safesoc-wazuh-01 | Wazuh manager, indexer, dashboard | 10.10.10.10 |
| safesoc-win-01 | Windows endpoint with Wazuh agent and Sysmon | 10.10.10.21 |
| safesoc-lnx-01 | Linux endpoint with Wazuh agent | 10.10.10.31 |
| VMnet10 | VMware NAT lab network | 10.10.10.0/24 |
| NAT gateway | VMware NAT gateway | 10.10.10.2 |

## Sprint Plan

| Sprint | Public name | Main output |
|---|---|---|
| Sprint 0 | Workspace, dataset governance, and safety setup | Clean folders, dataset rules, evidence plan, Git branch |
| Sprint 1 | Scenario taxonomy and detection design | Execution layers, labels, quality gate, detection matrix |
| Sprint 2 | Scenario catalog and MITRE mapping | S01 to S12, campaign definitions, gap register, mapping table |
| Sprint 3 | Emulation infrastructure setup | Caldera VM, Atomic Red Team prep, tooling validation |
| Sprint 4 | Benign baseline and noise generation | Baseline/admin/noisy telemetry |
| Sprint 5 | Manual adversary emulation | Explainable ATT&CK-aligned events |
| Sprint 6 | Atomic Red Team validation | Technique-level validation runs |
| Sprint 7 | MITRE Caldera campaign emulation | Multi-step campaign telemetry |
| Sprint 8 | Dataset assembly and export | Raw alerts, manifests, run logs |
| Sprint 9 | Ground-truth labeling and QA | labels.csv, QA report, coverage matrix |
| Sprint 10 | Phase 2 report and handoff | Dataset Creation Report and Phase 3 readiness |

## Sprint 0 Completion Criteria

- Phase 2 Git branch exists.
- Public docs folder exists.
- Public report folder exists.
- Local data folders exist outside GitHub.
- Local evidence folders exist outside GitHub.
- Safety checklist exists.
- Scenario run log template exists.
- Dataset schemas exist.
- Label template exists.
- Evidence log exists.
- Sprint 0 screenshots captured.
- No scenarios executed yet.

## Sprint 0 Completion Note

Sprint 0 prepares the repository, local folders, schemas, run logs, labels, and safety rules before anything is executed.

No scenarios, Atomic tests, or Caldera operations are allowed during Sprint 0.

## Sprint 1 Completion Note

Sprint 1 defines the execution layers, label values, event roles, simulation types, confidence values, quality gate, and detection matrix that will govern Phase 2.

No scenarios, Atomic tests, or Caldera operations are allowed during Sprint 1.

## Sprint 2 Completion Note

Sprint 2 finalizes the scenario catalog, campaign catalog, simulated-only gaps, MITRE mapping, and coverage matrix before infrastructure setup.

No scenarios, Atomic tests, or Caldera operations are allowed during Sprint 2.


## Sprint 1 Completion Note

Sprint 1 defines the scenario taxonomy, dataset balance targets, expected detection signals, evidence requirements, safety ratings, and quality gate that must be satisfied before scenario execution.

Sprint 1 confirms that Phase 2 will not generate random alerts. Each scenario must be traceable, reproducible, safe, labeled, and useful for later alert normalization, clustering, MITRE mapping, LLM hypothesis evaluation, graph validation, and policy-safe response evaluation.
