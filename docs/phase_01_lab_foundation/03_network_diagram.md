# Phase 1 Network Diagram

## Final Network Design

The SafeAgentSOC lab uses VMware Workstation Pro with VMnet10 as an isolated NAT network.

| Item | Value |
|---|---|
| Virtualization platform | VMware Workstation Pro |
| VMware network | VMnet10 |
| Network type | NAT |
| Subnet | 10.10.10.0/24 |
| Host-side VMnet10 adapter | 10.10.10.1 |
| VMware NAT gateway | 10.10.10.2 |

## Final Topology

```text
Host PC
  |
  | Host VMnet10 adapter: 10.10.10.1
  |
VMware VMnet10 NAT Network
Subnet: 10.10.10.0/24
NAT Gateway: 10.10.10.2
  |
  |-- safesoc-wazuh-01    10.10.10.10    Wazuh Server / Manager / Dashboard
  |
  |-- safesoc-win-01      10.10.10.21    Windows Endpoint / Sysmon / Wazuh Agent
  |
  |-- safesoc-lnx-01      10.10.10.31    Linux Endpoint / SSH / Auth / Sudo Logs
```

## Diagram Files

Editable diagram:

```text
diagrams/network/phase_01_lab_network.drawio
```

Exported diagram:

```text
diagrams/network/phase_01_lab_network.png
```

## Implementation Note

During implementation, the lab gateway was corrected from `10.10.10.1` to `10.10.10.2`. The address `10.10.10.1` belongs to the Windows host-side VMware VMnet10 adapter, while `10.10.10.2` acts as the NAT gateway for lab VMs.

