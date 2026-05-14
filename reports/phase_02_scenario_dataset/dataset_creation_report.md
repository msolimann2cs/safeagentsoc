# Dataset Creation Report

## 1. Objective

The objective of Phase 2 is to create a controlled, labeled, MITRE-mapped Wazuh alert dataset across realistic attack-like, benign, noisy, and false-positive scenarios.

## 2. Lab Foundation

Phase 2 builds on the completed Phase 1 lab foundation.

| Host | Role | IP |
|---|---|---:|
| safesoc-wazuh-01 | Wazuh manager, indexer, dashboard | 10.10.10.10 |
| safesoc-win-01 | Windows endpoint with Wazuh agent and Sysmon | 10.10.10.21 |
| safesoc-lnx-01 | Linux endpoint with Wazuh agent | 10.10.10.31 |

## 3. Dataset Governance

Raw alerts will be stored locally outside GitHub. Only sanitized samples, schemas, and documentation will be committed.

## 4. Scenario Design

TBD

## 5. MITRE Mapping

TBD

## 6. Dataset Collection Method

TBD

## 7. Ground-Truth Labeling

TBD

## 8. Dataset QA

TBD

## 9. Safety and Scope Controls

TBD

## 10. Results

TBD

## 11. Limitations

TBD

## 12. Handoff to Phase 3

Phase 3 will consume the raw Wazuh alerts, ground-truth labels, MITRE mapping, and scenario metadata to build the alert normalization layer.


## Sprint 1: Scenario Taxonomy and Detection Design

Sprint 1 defined the rules for creating a research-quality alert dataset. The purpose was to prevent Phase 2 from becoming an unstructured collection of random Wazuh alerts.

The dataset was divided into five major categories:

| Category | Purpose |
|---|---|
| Attack-like Windows | Exercise Windows Sysmon, PowerShell, process, and Security telemetry |
| Attack-like Linux | Exercise Linux SSH, sudo, auth, discovery, and cron-like telemetry |
| Benign admin activity | Provide known-benign data for false-positive and triage evaluation |
| Noisy repeated low-value alerts | Support alert fatigue and duplicate suppression testing |
| Mixed/ambiguous scenarios | Support conditional reasoning and realistic uncertainty |

Sprint 1 also created a detection design matrix that defines the expected local signals, Wazuh signals, DQL query ideas, event roles, safety ratings, and expected labels for scenarios S01 to S12.

The key quality gate is that no scenario may be executed until it has an objective, affected host, commands, expected Wazuh signal, MITRE mapping or N/A justification, safety rating, cleanup plan, and evidence filenames.

This sprint prepares the project for Sprint 2, where the full scenario catalog and MITRE mapping table will be completed.
