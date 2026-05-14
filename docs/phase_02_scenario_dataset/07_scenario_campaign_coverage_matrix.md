# Scenario and Campaign Coverage Matrix

## Scenario Coverage

| Category | Items | Count |
|---|---|---:|
| Windows attack-like | S01, S02, S03, S04 | 4 |
| Linux attack-like | S07, S08, S09, S10 | 4 |
| Benign | S05, S11 | 2 |
| Noise/ambiguous | S06, S12 | 2 |
| Campaigns | C-WIN-01, C-LNX-01 | 2 |
| Simulated-only gaps | GAP-WIN-001, GAP-WIN-002, GAP-LNX-001, GAP-X-001 | 4 |

## Execution Mode Coverage

| Execution Mode | Used For |
|---|---|
| manual | Baseline, noise, calibration |
| atomic_red_team | Single-technique validation |
| caldera | Campaign-level emulation |
| simulated_only | High-risk gaps |

## Research Readiness

- [x] Both Windows and Linux covered
- [x] Benign/noise included
- [x] Attack-like techniques included
- [x] Atomic validation planned
- [x] Caldera campaigns planned
- [x] High-risk gaps documented but not executed

