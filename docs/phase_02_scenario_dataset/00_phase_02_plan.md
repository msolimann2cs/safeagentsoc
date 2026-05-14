# Phase 2 Plan: Scenario Design and Dataset Creation

## Objective

Create a controlled, labeled, MITRE-mapped Wazuh alert dataset across realistic attack-like, benign, noisy, and false-positive scenarios.

## Private Mapping

| Private plan | Public GitHub name |
|---|---|
| Month 3 | Phase 2 |
| Scenario and dataset creation | Scenario Design and Dataset Creation |
| month_03 | phase_02_scenario_dataset |
| month-03-dataset | feature/scenario-dataset |
| Month 3 report | Dataset Creation Report |

## Primary Deliverables

- Scenario catalog
- Raw Wazuh alert dataset
- Ground-truth labels
- MITRE mapping table
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
| Sprint 1 | Scenario taxonomy and detection design | Scenario design rules, alert goals, coverage targets |
| Sprint 2 | Scenario catalog and MITRE mapping | 8 to 12 scenario definitions and mapping table |
| Sprint 3 | Benign baseline and noise generation | Benign/admin/noisy alert baseline |
| Sprint 4 | Windows attack-like scenario execution | Windows Sysmon/Security alerts exported and labeled |
| Sprint 5 | Linux attack-like scenario execution | Linux SSH/sudo/auth alerts exported and labeled |
| Sprint 6 | Alert export pipeline and raw dataset assembly | Raw Wazuh alerts, manifest, run logs |
| Sprint 7 | Ground-truth labeling and dataset QA | labels.csv, QA report, MITRE coverage matrix |
| Sprint 8 | Phase 2 report and handoff | Dataset Creation Report and Phase 3 readiness |

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

