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

