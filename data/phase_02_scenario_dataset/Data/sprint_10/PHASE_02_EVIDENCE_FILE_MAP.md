# Phase 2 Evidence File Map

## Purpose

This file maps the Phase 2 evidence locations after the Sprint 10 organization pass.

## Evidence Roots

| Location | Purpose | Git Status |
|---|---|---|
| `C:\D-Drive\Seneca\Co op\SafeAgentSOC\07_evidence\phase_02_scenario_dataset` | Original external evidence workspace | Outside repo |
| `C:\D-Drive\Seneca\Co op\SafeAgentSOC\05_code\safeagentsoc\07_evidence\phase_02_scenario_dataset` | Repo-local sprint-organized evidence workspace | Ignored by Git |
| `C:\D-Drive\Seneca\Co op\SafeAgentSOC\05_code\safeagentsoc\06_data\phase_02_scenario_dataset\phase_02_final_package` | Final local package with inventories and summary artifacts | Ignored by Git |

## Inventory Files

| Inventory | Path |
|---|---|
| Evidence inventory CSV | `07_evidence/phase_02_scenario_dataset/phase_02_evidence_inventory.csv` |
| Evidence inventory Markdown | `07_evidence/phase_02_scenario_dataset/phase_02_evidence_inventory.md` |
| Final package evidence inventory CSV | `06_data/phase_02_scenario_dataset/phase_02_final_package/phase_02_evidence_inventory.csv` |
| Final package evidence inventory Markdown | `06_data/phase_02_scenario_dataset/phase_02_final_package/phase_02_evidence_inventory.md` |

## Mirrored Evidence Summary

| Metric | Value |
|---|---:|
| Organized evidence files | 221 |
| Source files copied from external evidence | 211 |
| Inventory includes SHA256 hashes | Yes |
| `screenshots` bucket contains evidence files | No |

## Notes

The repo-local evidence mirror is intentionally ignored by Git because it may include screenshots, CSV exports, local paths, and private lab evidence. Public reports reference the evidence structure and summary metrics, while raw evidence remains local.

The previous `screenshots/Phase2` bucket has been emptied and the files have been placed under sprint-specific evidence folders. Sprint 9 and Sprint 10 also include generated QA, inventory, and validation evidence files.
