# Phase 1 VM Inventory

## VM Inventory

| VM Name | Role | OS | IP Address | CPU | RAM | Disk | Status |
|---|---|---|---:|---:|---:|---:|---|
| safesoc-wazuh-01 | Wazuh SIEM/XDR server | Ubuntu | 10.10.10.10 | 4 vCPU | 8 GB | 100 GB | Complete |
| safesoc-win-01 | Windows endpoint | Windows 10/11 | 10.10.10.21 | 2 vCPU | 4 GB | 60 GB | Complete |
| safesoc-lnx-01 | Linux endpoint | Ubuntu | 10.10.10.31 | 2 vCPU | 2 GB | 30 GB | Complete |
| safesoc-sim-01 | Simulation VM | TBD | 10.10.10.41 | 2 vCPU | 4 GB | 40 GB | Deferred |

## Network Notes

The original planned gateway was `10.10.10.1`, but during implementation it was confirmed that `10.10.10.1` is the Windows host-side VMware VMnet10 adapter. The working VMware NAT gateway is `10.10.10.2`.

## Final Network Layout

| Address | Meaning |
|---|---|
| 10.10.10.1 | Host VMnet10 adapter |
| 10.10.10.2 | VMware NAT gateway |
| 10.10.10.10 | Wazuh server |
| 10.10.10.21 | Windows endpoint |
| 10.10.10.31 | Linux endpoint |

## Snapshot Plan

| VM Name | Snapshot Name | Status |
|---|---|---|
| safesoc-wazuh-01 | clean-ubuntu-before-wazuh | Complete |
| safesoc-wazuh-01 | wazuh-installed-working | Complete |
| safesoc-win-01 | clean-windows-before-agent | Complete |
| safesoc-win-01 | win-agent-sysmon-working | Complete |
| safesoc-lnx-01 | clean-ubuntu-before-agent | Complete |
| safesoc-lnx-01 | linux-agent-working | Complete |

