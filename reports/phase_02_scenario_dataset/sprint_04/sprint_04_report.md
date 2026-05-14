# Sprint 4 Report: Benign Baseline and Noise Generation

## Objective

Sprint 4 generated benign baseline and noise telemetry before adversary emulation. The goal was to produce realistic SOC background activity for later alert-fatigue, duplicate-suppression, and case-building evaluation.

## Executed Scenarios

| Scenario | Description | Runs | Host |
|---|---|---:|---|
| S05 | Windows admin maintenance | 3 | safesoc-win-01 |
| S06 | Windows repeated benign process/noise | 3 | safesoc-win-01 |
| S11 | Linux admin maintenance | 3 | safesoc-lnx-01 |
| S12 | Authentication typo/noise | 3 | Windows/Linux |

## Execution Mode

All Sprint 4 activity used manual execution. No Atomic Red Team tests and no Caldera campaigns were executed.

## Detection Notes

Some benign administrative commands did not generate alert-level Wazuh events because Wazuh does not alert on every normal operating system query by default. Local transcripts and screenshots were kept as operator ground truth. Wazuh validation focused on rule-matched telemetry observed during each timestamp window.

## Windows Baseline Notes

Windows activity generated Wazuh detections related to PowerShell-spawned command shell activity, command prompt execution, net.exe execution, discovery activity, service activity, and registry/FIM-related background changes.

## Linux Baseline Notes

Linux activity focused on sudo-authenticated administrative behavior and auth.log-backed telemetry. This generated realistic benign authentication and administrative baseline data.

## Authentication Noise Notes

Authentication typo/noise was generated in a controlled manner using small numbers of failed authentication attempts followed by successful authentication. This avoids brute-force behavior while still producing false-positive-like SOC telemetry.

## Safety Notes

No malware was executed.
No destructive activity was executed.
No credential dumping was executed.
No Atomic Red Team tests were executed.
No Caldera operations were executed.
No account lockout behavior was intentionally triggered.

## Evidence Summary

| Evidence ID | Description |
|---|---|
| EVD-S04-100 | Windows full Sprint 4 summary |
| EVD-S04-102 | Linux full Sprint 4 summary |
| EVD-S04-104 | Authentication-noise summary |
| EVD-S04-106 | Windows noise summary |

## Completion Status

Sprint 4 is complete when all 12 planned runs have local proof, Wazuh proof or justified limited Wazuh visibility, timestamps, exported CSVs where available, and scenario run log entries.

