# Phase 1 Network Diagram

## Objective

Document the SafeAgentSOC lab network used for Wazuh and endpoint telemetry collection.

## Virtualization Platform

Chosen platform: TBD

## Network Mode Decision

Chosen mode: NAT Network

Network name: SafeAgentSOC-LabNet  
Virtual network identifier: TBD  
Subnet: 10.10.10.0/24  
Gateway: 10.10.10.1  

Reason:
NAT Network allows the lab VMs to communicate with each other while still allowing internet access for package updates and tool installation. It also avoids exposing lab services directly to the physical network like bridged mode would.

## Logical Topology

```text
Host PC
  |
Virtualization Platform
  |
SafeAgentSOC-LabNet
10.10.10.0/24
  |
  |-- safesoc-wazuh-01    10.10.10.10    Wazuh Server / Manager / Dashboard
  |
  |-- safesoc-win-01      10.10.10.21    Windows Endpoint / Sysmon / Wazuh Agent
  |
  |-- safesoc-lnx-01      10.10.10.31    Linux Endpoint / Auth Logs / Wazuh Agent
  |
  |-- safesoc-sim-01      10.10.10.41    Optional Simulation VM Later
IP Address Plan
HostIPPurpose
safesoc-wazuh-0110.10.10.10Wazuh server, dashboard, manager
safesoc-win-0110.10.10.21Windows telemetry source
safesoc-lnx-0110.10.10.31Linux telemetry source
safesoc-sim-0110.10.10.41Optional attack simulation later
Main Communication Paths
SourceDestinationPurpose
Host PCsafesoc-wazuh-01Access Wazuh dashboard
safesoc-win-01safesoc-wazuh-01Send Windows logs and Sysmon events
safesoc-lnx-01safesoc-wazuh-01Send Linux auth, SSH, and sudo logs
VMsInternetUpdates, packages, and downloads
Expected Traffic Flow
safesoc-win-01  --->  safesoc-wazuh-01
safesoc-lnx-01  --->  safesoc-wazuh-01
Host PC         --->  safesoc-wazuh-01 Wazuh Dashboard
Isolation Notes
The lab is isolated from third-party systems.
The lab is used only for controlled defensive telemetry generation.
No unauthorized scanning or testing is performed outside the lab.
This phase focuses on ingestion proof, not adversary emulation.
Diagram File

Visual diagram location:

diagrams/network/phase_01_lab_network.drawio

Exported image location:

diagrams/network/phase_01_lab_network.png

