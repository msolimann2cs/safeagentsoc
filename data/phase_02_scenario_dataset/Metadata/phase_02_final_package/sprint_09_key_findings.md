# Sprint 9 Key Findings

## Most Alert-Fatigue-Heavy Cases

| Rank | Case ID | Reason |
|---|---|---|
| 1 | CASE-034 | S12 scenario-level ambiguous authentication noise reached 1.0000 compression potential across 14 alert references. |
| 2 | CASE-022 | S12-MAN-R002 run-level ambiguous authentication noise reached 1.0000 compression potential with a 0.5714 duplicate ratio. |
| 3 | CASE-036 | Background/noise case for a single repeated rule family reached 1.0000 compression potential across 17 unrelated-background alert references. |
| 4 | CASE-035 | Background/noise case for a single repeated rule family reached 1.0000 compression potential across 17 unrelated-background alert references. |
| 5 | CASE-037 | Background/noise case reached 1.0000 compression potential across 10 unrelated-background alert references. |

## Cleanest Cases

| Rank | Case ID | Reason |
|---|---|---|
| 1 | CASE-004 | C-WIN-01-CAL-R001 had 2 alert references, 2 unique rules, and 0.0000 duplicate/compression ratios. |
| 2 | CASE-012 | S07-MAN-R002 had 9 alert references across 3 rules with no duplicate or compression candidates. |
| 3 | CASE-014 | S08-MAN-R002 had 10 alert references across 5 rules with no duplicate or compression candidates. |
| 4 | CASE-049 | S07 technique-focused case had 12 alert references across 2 rules with no duplicate or compression candidates. |
| 5 | CASE-015 | S09-MAN-R001 had 13 alert references across 7 rules with no duplicate or compression candidates. |

## Campaign Findings

| Campaign Case | Alert References | Duplicate Ratio | Compression Potential | Interpretation |
|---|---:|---:|---:|---|
| CASE-023 C-LNX-01 | 164 | 0.6037 | 0.6037 | Linux campaign telemetry is alert-fatigue-heavy and should be a strong Phase 3 compression test. |
| CASE-024 C-WIN-01 | 12 | 0.3333 | 0.3333 | Windows campaign telemetry is smaller but still contains repeated alert references. |

## Raw Background Pool Finding

The full Wazuh export contains 6,893 raw alerts. Sprint 8 produced an 800-row QA-validated gold-label subset with 631 unique alert UIDs. Sprint 9 identified 719 raw alert occurrences overlapping the gold-label UID set and retained an estimated 6,174 raw alert occurrences as an unlabeled background telemetry pool.

## Interpretation

The Sprint 9 benchmark shows which cases create the highest analyst workload and which cases are cleaner. This provides a baseline for evaluating whether SafeAgentSOC can compress duplicate and noisy alerts while preserving trigger evidence.
