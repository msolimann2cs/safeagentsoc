# SafeAgentSOC Phase 2 Dataset Creation Report

## 1. Executive Summary

Phase 2 created a research-grade SOC alert dataset for SafeAgentSOC using controlled adversary emulation, benign baselines, noisy false-positive-like activity, Atomic Red Team validation, MITRE Caldera campaign emulation, and simulated-only high-risk gap documentation.

The final dataset contains 6,893 raw Wazuh alerts, an 800-row QA-validated gold-label subset, and a 50-case investigation casebook with alert-fatigue baseline metrics.

## 2. Research Purpose

The purpose of this phase was to create a controlled dataset that can later evaluate whether SafeAgentSOC can reduce duplicate and noisy alerts, preserve meaningful trigger evidence, summarize alert groups into investigation cases, distinguish benign/noisy/attack-like/failed/simulated-only/unrelated telemetry, and support analyst-facing triage conclusions.

## 3. Lab Environment

| Host | Role | IP |
|---|---|---|
| safesoc-wazuh-01 | Wazuh manager/indexer/dashboard | 10.10.10.10 |
| safesoc-win-01 | Windows endpoint | 10.10.10.21 |
| safesoc-lnx-01 | Linux endpoint | 10.10.10.31 |
| safesoc-caldera-01 | Caldera adversary-emulation server | 10.10.10.41 |
| safesoc-sim-01 | Operator/staging node if used | 10.10.10.42 |

## 4. Methodology

| Layer | Name | Execution Mode | Purpose |
|---|---|---|---|
| L0 | Benign baseline | manual | Normal user/admin behavior |
| L1 | Noise and false-positive-like activity | manual | Alert fatigue and duplicate suppression evaluation |
| L2 | Manual adversary emulation | manual | Explainable command-level ground truth |
| L3 | Atomic Red Team validation | atomic_red_team | Standardized ATT&CK technique validation |
| L4 | MITRE Caldera campaign emulation | caldera | Multi-step adversary campaigns |
| L5 | Simulated-only high-risk gaps | simulated_only | Dangerous behaviors documented safely |

## 5. Scenario Catalog Summary

| Scenario | Platform | Type | Purpose | MITRE |
|---|---|---|---|---|
| S01 | Windows | attack_like | PowerShell execution | T1059.001 |
| S02 | Windows | attack_like | Discovery sequence | T1082, T1033, T1016 |
| S03 | Windows | attack_like | Scheduled task marker | T1053.005 |
| S04 | Windows | attack_like | Archive/staging behavior | T1560.001 |
| S05 | Windows | benign | Normal admin maintenance | N/A |
| S06 | Windows | noise | Repeated benign process noise | N/A |
| S07 | Linux | attack_like | SSH failed login pattern | T1110.001 |
| S08 | Linux | attack_like | Sudo authentication pattern | T1548.003 |
| S09 | Linux | attack_like | Linux discovery sequence | T1082, T1033, T1016 |
| S10 | Linux | attack_like | Cron marker | T1053.003 |
| S11 | Linux | benign | Normal admin maintenance | N/A |
| S12 | Cross-endpoint | ambiguous_noise | Typo/noisy authentication | N/A |

## 6. Campaign Summary

`C-WIN-01` represented Windows foothold-to-staging behavior: PowerShell execution, Windows discovery, scheduled task marker activity, and archive/staging behavior.

`C-LNX-01` represented Linux access-to-persistence behavior: SSH/access probing, sudo/PAM activity, Linux discovery, and cron/persistence-like activity.

## 7. Tooling Summary

| Tool | Purpose |
|---|---|
| Wazuh | SIEM, alert collection, rule detection |
| Sysmon | Windows telemetry enrichment |
| Atomic Red Team | ATT&CK technique validation |
| MITRE Caldera | Campaign-level adversary emulation |
| PowerShell/Bash | Manual emulation and markers |
| Node scripts | Dataset processing, QA, and casebook generation |

## 8. Raw Alert Export Method

The final raw alert dataset was reconstructed from active and rotated Wazuh JSON alert files under `/var/ossec/logs/alerts/`, including active `alerts.json` and compressed historical `ossec-alerts-*.json.gz` files.

| Metric | Value |
|---|---:|
| Raw alerts | 6,893 |
| Raw export size | 12 MB |
| Raw export format | JSONL |
| SHA256 | 44EF71B93BBC663FB35DB71F4FF129833BC83D244B8A133E83753FEE7FE0C0BF |

## 9. Correlation Method

Alerts were correlated using RUN_ID marker alerts, scenario run windows, agent/host matching, Wazuh timestamps, scenario IDs, campaign IDs, Atomic test metadata, and Caldera campaign metadata where available.

## 10. Ground-Truth Labeling

Sprint 8 produced an 800-row gold-label dataset.

| Metric | Value |
|---|---:|
| Total labeled rows | 800 |
| Unique alert UIDs | 631 |
| Attack-like labels | 491 |
| Unrelated background labels | 247 |
| Benign labels | 48 |
| Ambiguous noise labels | 14 |

Labels include `benign`, `noise`, `ambiguous_noise`, `attack_like`, `attack_like_failed`, `simulated_only`, and `unrelated_background`. Event roles include `trigger`, `supporting`, `duplicate`, `noise`, and `unrelated`.

## 11. Dataset QA

QA checks included schema validation, label completeness, MITRE coverage, endpoint coverage, execution-mode distribution, confidence distribution, duplicate UID checking, and background sample separation. Schema validation passed for 800 labeled rows.

## 12. Investigation Casebook

Sprint 9 converted alert-level labels into a case-level SOC benchmark.

| Metric | Value |
|---|---:|
| Investigation cases | 50 |
| Run cases | 22 |
| Campaign cases | 2 |
| Scenario cases | 10 |
| Background/noise cases | 5 |
| Technique cases | 11 |
| Total case alert references | 1,549 |
| Meaningful alert references | 838 |
| Suppression candidate references | 713 |
| Average duplicate ratio | 0.2601 |
| Average compression potential | 0.4377 |

## 13. Alert-Fatigue Baseline

```text
duplicate_ratio = duplicate_alert_count / raw_alert_count
compression_potential = suppression_candidate_count / raw_alert_count
meaningful_alert_count = trigger_alert_count + supporting_alert_count
```

Suppression candidates are capped at `raw_alert_count` to avoid double-counting alerts that are both duplicate and noise.

## 14. Key Findings

1. The Linux Caldera campaign was the strongest alert-fatigue workload, with 164 campaign alert references and 0.6037 compression potential.
2. S12 authentication-noise cases reached 1.0000 compression potential.
3. Several background/noise rule-family cases reached 1.0000 compression potential.
4. C-WIN-01-CAL-R001 was the cleanest small campaign run with 2 alert references and no duplicate/compression candidates.
5. The remaining raw alert pool was retained as unlabeled telemetry instead of being weakly labeled.

## 15. Raw Background Pool

The full raw export contained 6,893 raw alerts. The gold-label subset contained 800 rows and 631 unique alert UIDs. Sprint 9 identified 719 raw alert occurrences overlapping the gold-label UID set and retained an estimated 6,174 raw alert occurrences as an unlabeled background telemetry pool.

The unlabeled remainder was retained for background-noise profiling, future labeling, and casebook expansion. It was excluded from gold-label metrics to avoid weak or unverified labels.

## 16. Limitations and Threats to Validity

1. The dataset was generated in a controlled lab and does not represent all enterprise SOC variability.
2. Campaign-level windows can overlap with run-level windows.
3. Casebook totals are benchmark references, not deduplicated raw alert totals.
4. Some Caldera metadata was not recoverable after execution and is marked as `not_recovered`.
5. Some weak-detection cases contain attack-like execution but are dominated by unrelated/background telemetry.
6. Raw alert volume exceeded the original target due to repeated Linux and audit/process telemetry.
7. High-risk behaviors were simulated-only when destructive or credential-exposing.

## 17. Phase 3 Handoff

Phase 3 should use the casebook to test whether SafeAgentSOC can group alerts into cases, suppress duplicate and noisy alerts, preserve trigger evidence, generate analyst-facing case summaries, match expected analyst conclusions, and report alert reduction without hiding important evidence.

## 18. Conclusion

Phase 2 successfully produced a research-grade adversary-emulation dataset for SafeAgentSOC. The final package includes raw Wazuh telemetry, a QA-validated gold-label subset, MITRE mappings, case-level investigation records, alert-fatigue baseline metrics, and Phase 3 normalization requirements.
