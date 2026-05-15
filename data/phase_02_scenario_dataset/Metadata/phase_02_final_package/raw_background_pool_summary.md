# Raw Background Pool Summary

## Summary

| Metric | Value |
|---|---:|
| Full raw alerts | 6893 |
| Gold-label rows | 800 |
| Unique gold-label alert UIDs | 631 |
| Labeled unique UID overlap in raw export | 719 |
| Estimated unlabeled raw pool | 6174 |
| Unique agent/rule families | 4034 |

## Top Agents

| Agent | Count |
|---|---:|
| safesoc-lnx-01 | 5338 |
| safesoc-win-01 | 1042 |
| safesoc-wazuh-01 | 513 |

## Top Rule IDs

| Rule ID | Count |
|---|---:|
| 23502 | 1400 |
| 2904 | 688 |
| 23504 | 667 |
| 19007 | 586 |
| 550 | 481 |
| 2902 | 438 |
| 23505 | 431 |
| 19008 | 339 |
| 23508 | 282 |
| 5501 | 150 |
| 5502 | 140 |
| 5402 | 122 |
| 19009 | 115 |
| 92604 | 103 |
| 92032 | 101 |
| 92004 | 97 |
| 554 | 52 |
| 92021 | 43 |
| 92066 | 40 |
| 92031 | 37 |

## Interpretation

The remaining raw alert pool is retained as unlabeled background telemetry. It is not discarded. It supports alert-fatigue analysis, background-noise profiling, and future labeling expansion. Sprint 9 uses this pool to document non-gold telemetry instead of pretending all raw alerts have verified ground-truth labels.
