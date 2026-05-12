# Phase 1 Network Diagram

## Objective

Document the SafeAgentSOC lab network used for Wazuh and endpoint telemetry collection.

## Logical Topology

```text
Host PC
  |
Virtualization Network
  |
10.10.10.0/24
  |
  |-- safesoc-wazuh-01    10.10.10.10    Wazuh Server
  |-- safesoc-win-01      10.10.10.21    Windows Endpoint
  |-- safesoc-lnx-01      10.10.10.31    Linux Endpoint
  |-- safesoc-sim-01      10.10.10.41    Optional Simulation VMIP Address Plan
HostIPPurpose
safesoc-wazuh-0110.10.10.10Wazuh server, dashboard, manager
safesoc-win-0110.10.10.21Windows telemetry source
safesoc-lnx-0110.10.10.31Linux telemetry source
safesoc-sim-0110.10.10.41Optional attack simulation later
Network Mode Decision

Chosen mode: TBD

Options:

NAT Network
Host-only + NAT
Bridged
Proxmox virtual bridge
Diagram File

Visual diagram location:

diagrams/network/phase_01_lab_network.drawio

Exported image location:

diagrams/network/phase_01_lab_network.png
Notes
The lab must remain isolated from third-party systems.
Only safe lab telemetry should be generated.
This phase focuses on ingestion proof, not adversary emulation.
