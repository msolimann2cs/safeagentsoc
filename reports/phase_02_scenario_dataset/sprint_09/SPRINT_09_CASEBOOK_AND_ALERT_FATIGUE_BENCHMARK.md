# Sprint 9: Investigation Casebook and Alert-Fatigue Benchmark

## Goal

Convert Sprint 8 alert-level labels into case-level investigation records and baseline alert-fatigue metrics for future SafeAgentSOC evaluation.

## Inputs

| Input | Path |
|---|---|
| Ground-truth labels | `06_data/phase_02_scenario_dataset/sprint_09_casebook/ground_truth_labels.csv` |
| Raw Wazuh alerts | `06_data/phase_02_scenario_dataset/sprint_09_casebook/raw_alerts_full.jsonl` |
| Sprint 8 QA report | `06_data/phase_02_scenario_dataset/sprint_09_casebook/sprint_08_dataset_qa_report.md` |

## Outputs

| Output | Path |
|---|---|
| Investigation casebook | `06_data/phase_02_scenario_dataset/sprint_09_casebook/casebook.csv` |
| Detailed JSONL casebook | `06_data/phase_02_scenario_dataset/sprint_09_casebook/casebook_detailed.jsonl` |
| Alert-fatigue baseline | `06_data/phase_02_scenario_dataset/sprint_09_casebook/alert_fatigue_baseline.csv` |
| Case-level summary dataset | `06_data/phase_02_scenario_dataset/sprint_09_casebook/case_level_summary_dataset.csv` |
| Casebook QA summary | `06_data/phase_02_scenario_dataset/sprint_09_casebook/casebook_qa_summary.md` |
| Raw background pool profile | `06_data/phase_02_scenario_dataset/sprint_09_casebook/raw_pool_rule_profile.csv` |
| Raw background pool summary | `06_data/phase_02_scenario_dataset/sprint_09_casebook/raw_background_pool_summary.md` |
| Phase 3 normalization requirements | `06_data/phase_02_scenario_dataset/sprint_09_casebook/phase_03_normalization_requirements.md` |
| Key findings | `06_data/phase_02_scenario_dataset/sprint_09_casebook/sprint_09_key_findings.md` |

## Method

Sprint 9 created investigation cases from the Sprint 8 ground-truth labels using five case views:

1. Run-level cases.
2. Campaign-level cases.
3. Scenario-level cases.
4. Technique-focused subcases.
5. Background/noise cases.

Each case includes raw alert count, unique Wazuh rule count, trigger/supporting/duplicate/noise counts, duplicate ratio, compression potential, MITRE techniques, execution mode, tool, a case summary, and an expected analyst conclusion.

## Casebook Summary

| Metric | Value |
|---|---:|
| Investigation cases generated | 50 |
| Total case alert references | 1,549 |
| Meaningful alert references | 838 |
| Suppression candidate references | 713 |
| Average duplicate ratio | 0.2601 |
| Average compression potential | 0.4377 |

## Case Type Distribution

| Case Type | Count |
|---|---:|
| run_case | 22 |
| campaign_case | 2 |
| scenario_case | 10 |
| background_noise_case | 5 |
| technique_case | 11 |

## Alert-Fatigue Metrics

Alert fatigue was measured using:

```text
duplicate_ratio = duplicate_alert_count / raw_alert_count
compression_potential = suppression_candidate_count / raw_alert_count
meaningful_alert_count = trigger_alert_count + supporting_alert_count
```

Suppression candidates include duplicate alerts, noise alerts, and unrelated background alerts. Each alert reference contributes at most once to compression potential. Suppression candidates are capped at `raw_alert_count` to avoid double-counting alerts that are both duplicate and noise.

## Raw Background Pool

The full Wazuh export contained 6,893 raw alerts. Sprint 8 produced an 800-row gold-label subset with 631 unique alert UIDs. Sprint 9 identified 719 raw alert occurrences overlapping the gold-label UID set and retained an estimated 6,174 raw alert occurrences as an unlabeled background telemetry pool.

The unlabeled remainder was not discarded. It was retained as raw telemetry for background-noise analysis, future labeling, and casebook expansion. It is excluded from gold-label metrics to avoid weak or unverified labels.

## Key Findings

| Finding | Result |
|---|---|
| Highest campaign workload | C-LNX-01 with 164 campaign alert references and 0.6037 compression potential |
| Highest noise workload | S12 authentication-noise cases and background/noise rule families reached 1.0000 compression potential |
| Cleanest small run | C-WIN-01-CAL-R001 had 2 alert references with 0.0000 duplicate/compression ratios |
| Raw background pool | 6,174 estimated unlabeled raw alert occurrences retained for future analysis |

## Limitations

- Campaign cases may overlap with run-level cases.
- Casebook totals are benchmark references, not deduplicated raw alert totals.
- Background/noise cases are used for alert-fatigue benchmarking.
- Some attack-like runs were retained as `weak_detection_case` or `attack_like_failed` notes when the observed telemetry was too weak or off-target for a confident attack-like conclusion.
- Technique cases can overlap because one event sequence may map to multiple ATT&CK techniques.
- UID overlap is based on stable alert UID hashing and may count repeated raw alert occurrences with the same UID.
- Sprint 10 will package these artifacts into the final Phase 2 dataset report.

## Completion Status

Sprint 9 is complete when the casebook contains 45 to 55 investigation cases, alert-fatigue metrics are generated, the raw background pool is profiled, and Phase 3 normalization requirements are documented.
