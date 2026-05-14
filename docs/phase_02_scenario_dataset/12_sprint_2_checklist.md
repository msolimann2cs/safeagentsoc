# Sprint 2 Checklist: Scenario Catalog and MITRE Mapping

## Scenario Catalog

- [x] S01 Windows PowerShell execution defined
- [x] S02 Windows discovery sequence defined
- [x] S03 Windows scheduled task marker defined
- [x] S04 Windows archive/staging behavior defined
- [x] S05 Windows normal admin maintenance defined
- [x] S06 Windows repeated benign noise defined
- [x] S07 Linux SSH failed login pattern defined
- [x] S08 Linux sudo authentication pattern defined
- [x] S09 Linux discovery sequence defined
- [x] S10 Linux cron marker defined
- [x] S11 Linux normal admin maintenance defined
- [x] S12 repeated typo/noisy authentication defined

## MITRE Mapping

- [x] Attack-like Windows scenarios mapped
- [x] Attack-like Linux scenarios mapped
- [x] Benign scenarios marked N/A
- [x] Noise scenarios marked N/A
- [x] Ambiguous scenario marked N/A or justified
- [x] Mapping confidence included
- [x] Observable signal included
- [x] No benign scenario force-mapped to ATT&CK

## Machine-Readable Files

- [x] `scenario_catalog.yaml` created
- [x] `mitre_mapping.csv` created
- [x] local `scenario_catalog.yaml` copied to manifests folder
- [x] local `mitre_mapping.csv` copied to manifests folder

## Research Quality

- [x] Every scenario has objective
- [x] Every scenario has analyst hypothesis
- [x] Every scenario has wrong inference warning
- [x] Every scenario has expected local signal
- [x] Every scenario has expected Wazuh query
- [x] Every scenario has cleanup plan
- [x] Every scenario has safety rating
- [x] Every scenario has expected label
- [x] Coverage matrix completed

## Safety

- [x] No scenarios executed during Sprint 2
- [x] No raw alerts exported during Sprint 2
- [x] No real malware included
- [x] No credential dumping included
- [x] No destructive persistence included
- [x] No third-party targets included

## Evidence

- [ ] Scenario catalog screenshot captured
- [ ] MITRE mapping table screenshot captured
- [ ] Scenario coverage matrix screenshot captured
- [ ] Git status screenshot captured

