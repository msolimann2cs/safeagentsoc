# Sprint 9 Casebook QA Summary

## Summary

| Metric | Value |
|---|---:|
| Investigation cases generated | 50 |
| Total case alert references | 1549 |
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

## QA Status

PASS: Case count is within the 45 to 55 target.

## Notes

- Case-level totals are benchmark references and may include overlapping campaign/run views.
- Compression potential is estimated as suppression_candidate_count / raw_alert_count.
- Suppression candidates include duplicate and noise/unrelated alerts.
- Sprint 10 should report these metrics as baseline alert-fatigue measurements.
