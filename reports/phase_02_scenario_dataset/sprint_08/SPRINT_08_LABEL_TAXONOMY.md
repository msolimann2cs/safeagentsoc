# Sprint 8 Label Taxonomy

## Label Values

| Label | Meaning |
|---|---|
| benign | Expected legitimate activity |
| noise | Repeated low-value or false-positive-like activity |
| ambiguous_noise | Noisy activity that could look suspicious but has benign ground truth |
| attack_like | Controlled adversary-emulation behavior |
| attack_like_failed | Attack-like behavior attempted but blocked or failed |
| simulated_only | High-risk behavior represented safely without destructive execution |
| unrelated_background | Background telemetry not directly caused by the scenario |

## Event Role Values

| Event Role | Meaning |
|---|---|
| trigger | Primary alert that proves the scenario or technique occurred |
| supporting | Relevant context alert around the scenario |
| duplicate | Repeated alert with same meaning as another alert in same run |
| noise | Low-value alert expected in noisy/benign activity |
| unrelated | Alert occurred in the time window but is not part of the scenario |

## Confidence Values

| Confidence | Meaning |
|---|---|
| high | Alert directly tied to run marker, command, Atomic test, Caldera ability, or scenario evidence |
| medium | Alert is probably related based on host/time/rule but not directly marked |
| low | Alert is weakly related or likely background |

## Ground-Truth Rules

1. RUN_ID marker alerts are trigger events.
2. Atomic test execution alerts are trigger events when matching the technique.
3. Caldera ability execution alerts are trigger events when matching the campaign stage.
4. Discovery, auth, cron, PowerShell, archive, scheduled task, and systemd evidence inside the correct run window are supporting or trigger events.
5. Repeated identical alerts in the same run are duplicate events.
6. Benign maintenance scenarios are labeled benign unless clearly unrelated.
7. Noise scenarios are labeled noise or ambiguous_noise.
8. Alerts inside campaign windows but unrelated to the campaign are labeled unrelated.
9. Simulated-only high-risk gaps are labeled simulated_only.
10. Sprint 8 does not change raw data. It only creates labels and QA metrics.
