# Sprint 8 Dataset QA Report

## Summary

| Metric | Value |
|---|---:|
| Total labeled rows | 800 |
| Unique alert UIDs | 631 |
| Duplicate alert UID groups | 121 |
| Low-confidence rows | 0 |

## Label Distribution

| Value | Count |
|---|---:|
| attack_like | 491 |
| unrelated_background | 247 |
| benign | 48 |
| ambiguous_noise | 14 |

## Event Role Distribution

| Value | Count |
|---|---:|
| supporting | 289 |
| unrelated | 247 |
| duplicate | 214 |
| trigger | 45 |
| noise | 5 |

## Scenario Distribution

| Value | Count |
|---|---:|
| EMPTY | 381 |
| S10 | 132 |
| S07 | 60 |
| S09 | 50 |
| S11 | 48 |
| S02 | 39 |
| S08 | 28 |
| S01 | 24 |
| S04 | 16 |
| S12 | 14 |
| S03 | 8 |

## Campaign Distribution

| Value | Count |
|---|---:|
| EMPTY | 624 |
| C-LNX-01 | 164 |
| C-WIN-01 | 12 |

## Endpoint Distribution

| Value | Count |
|---|---:|
| safesoc-lnx-01 | 559 |
| safesoc-win-01 | 182 |
| safesoc-wazuh-01 | 59 |

## Execution Mode Distribution

| Value | Count |
|---|---:|
| manual | 339 |
| background_sample | 205 |
| caldera | 176 |
| atomic_red_team | 80 |

## Confidence Distribution

| Value | Count |
|---|---:|
| medium | 755 |
| high | 45 |

## MITRE Technique Distribution

| Value | Count |
|---|---:|
| N/A | 228 |
| T1057 | 149 |
| T1548.003 | 80 |
| T1053.003 | 79 |
| T1078 | 70 |
| T1082/T1033/T1016 | 34 |
| T1059.001 | 23 |
| T1110.001 | 22 |
| T1070.004 | 19 |
| T1110.001/T1021.004 | 17 |
| T1059.003 | 14 |
| T1087/T1059.003 | 12 |
| T1087 | 11 |
| T1110.001/T1548.003/T1082/T1033/T1016/T1053.003 | 10 |
| T1110 | 7 |
| T1059.001/T1082/T1033/T1016/T1053.005/T1560.001 | 5 |
| T1087/T1059.001 | 3 |
| T1135 | 3 |
| T1546.011 | 3 |
| T1053.005 | 2 |
| T1078/T1110 | 2 |
| T1484 | 2 |
| T1531 | 2 |
| T1027/T1112 | 1 |
| T1562.001 | 1 |
| T1565.001 | 1 |

## Cleanup Review Notes

- Caldera operation names, adversary profiles, and operation-level ability ID sets were recovered from Caldera report JSON evidence.
- Low-confidence rows were spot-checked as unrelated/background rows and upgraded to medium confidence with explicit notes.
- Trigger roles were tightened to primary evidence. Repeated telemetry, especially repeated process-discovery events, was moved to supporting or duplicate.
- Duplicate alert UIDs represent repeated correlation references across overlapping run/campaign windows, not necessarily duplicate raw alerts.

## Limitations

- Caldera ability IDs are operation-level ability sets from report JSON, not per-alert ability attribution.
- Campaign-level windows may overlap with scenario-level windows.
- Some labels are derived from timestamp correlation and require conservative confidence scoring.
- Sprint 9 will group these labels into investigation cases and alert-fatigue metrics.
