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

## Sprint 2: Scenario Catalog and MITRE Mapping

Sprint 2 finalized the Phase 2 scenario catalog and MITRE mapping design. The catalog contains 12 controlled scenarios across Windows, Linux, benign administrative activity, noisy repeated activity, and ambiguous authentication behavior.

The catalog was designed to support research-grade evaluation rather than simple alert generation. Each scenario includes an objective, affected host, analyst hypothesis, wrong inference warning, MITRE mapping or N/A justification, expected local signal, expected Wazuh query, cleanup plan, safety rating, and expected ground-truth label.

### Scenario Coverage

| Category | Scenarios |
|---|---|
| Windows attack-like | S01, S02, S03, S04 |
| Linux attack-like | S07, S08, S09, S10 |
| Benign | S05, S11 |
| Noise | S06 |
| Ambiguous/noise | S12 |

### MITRE Coverage

The attack-like scenarios cover the following ATT&CK techniques:

| Technique ID | Technique Name | Scenario |
|---|---|---|
| T1059.001 | PowerShell | S01 |
| T1082 | System Information Discovery | S02, S09 |
| T1033 | System Owner/User Discovery | S02, S09 |
| T1016 | System Network Configuration Discovery | S02, S09 |
| T1053.005 | Scheduled Task | S03 |
| T1560.001 | Archive via Utility | S04 |
| T1110.001 | Password Guessing | S07 |
| T1548.003 | Sudo and Sudo Caching | S08 |
| T1053.003 | Cron | S10 |

### Research-Quality Controls

Benign and noisy scenarios were not force-mapped to ATT&CK. This preserves label quality and prevents artificial technique inflation. Attack-like scenarios are mapped only when the observable behavior clearly resembles a technique. All planned execution remains inside the SafeAgentSOC lab, and high-risk actions such as malware execution, credential dumping, destructive persistence, third-party scanning, and real exfiltration are excluded.

Sprint 2 produced the human-readable scenario catalog, MITRE mapping table, machine-readable scenario catalog, MITRE mapping CSV, and coverage matrix. No scenarios were executed during this sprint.

## Sprint 2: Scenario Catalog, Campaign Design, and MITRE Mapping

Sprint 2 finalized the Phase 2 scenario catalog, campaign design, simulated-only gap register, and MITRE mapping. The catalog now supports manual adversary emulation, Atomic Red Team validation, and MITRE Caldera campaign emulation while explicitly reserving unsafe techniques as simulated-only documentation.

### Scenario Coverage

| Category | Scenarios |
|---|---|
| Windows attack-like | S01, S02, S03, S04 |
| Linux attack-like | S07, S08, S09, S10 |
| Benign | S05, S11 |
| Noise | S06 |
| Ambiguous/noise | S12 |

### Campaign Coverage

| Campaign | Target | Purpose |
|---|---|---|
| C-WIN-01 | safesoc-win-01 | Windows foothold-to-staging emulation |
| C-LNX-01 | safesoc-lnx-01 | Linux access-to-persistence emulation |

### Simulated-Only Gaps

Unsafe techniques such as credential dumping, ransomware-like encryption, /etc/shadow dumping, and real exfiltration are documented only as simulated-only gaps. They are included in methodology and limitations, but they are not executed.

### Research-Quality Controls

Benign and noisy scenarios were not force-mapped to ATT&CK. Attack-like scenarios are mapped conservatively and kept explainable. Campaigns are designed for later manual, Atomic Red Team, and Caldera-based validation in future sprints. No scenarios, Atomic tests, or Caldera operations were executed during Sprint 2.
