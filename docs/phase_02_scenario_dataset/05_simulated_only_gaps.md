# Simulated-Only High-Risk Gaps

## Purpose

Some techniques are relevant to real intrusions but are not executed because they are unsafe, destructive, unethical, or unnecessary for this dataset.

## Gap Table

| Gap ID | Technique/Concept | Reason Not Executed | Dataset Handling |
|---|---|---|---|
| GAP-WIN-001 | T1003 OS Credential Dumping | Credential dumping is unsafe and unnecessary | simulated_only |
| GAP-WIN-002 | Ransomware-like encryption | Destructive behavior | simulated_only |
| GAP-LNX-001 | /etc/shadow dumping | Credential material access | simulated_only |
| GAP-X-001 | Real exfiltration | No real data exfiltration | simulated_only |

## Rule

These gaps may appear in methodology and limitations, but they do not generate executable telemetry.

