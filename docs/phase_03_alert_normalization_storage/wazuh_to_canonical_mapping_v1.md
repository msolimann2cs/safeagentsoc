# Wazuh to SafeAgentSOC Canonical Mapping v1

## Purpose

This document defines the initial mapping from Wazuh JSON alert fields to the SafeAgentSOC normalized alert schema.

## Core Mapping

| Wazuh Field | SafeAgentSOC Field |
|---|---|
| `timestamp` | `timestamps.event_time_utc` |
| `agent.id` | `host.agent_id` |
| `agent.name` | `host.agent_name` |
| `agent.ip` | `host.agent_ip` |
| `manager.name` | source metadata, optional |
| `rule.id` | `rule.rule_id` |
| `rule.level` | `rule.rule_level` and `severity.original_level` |
| `rule.description` | `rule.rule_description` and `event.description` |
| `rule.groups` | `rule.rule_groups` |
| `rule.firedtimes` | `rule.rule_firedtimes` |
| `decoder.name` | `decoder.decoder_name` |
| `location` | `source.source_location` |
| `rule.mitre.id` | `mitre.technique_ids` |
| `rule.mitre.tactic` | `mitre.tactics` |
| raw line number | `evidence.raw_line_number` |
| raw alert SHA256 | `evidence.raw_alert_sha256` |
| raw file SHA256 | `evidence.raw_file_sha256` |

## Windows Entity Candidates

| Wazuh Field Candidate | SafeAgentSOC Field |
|---|---|
| `data.win.eventdata.TargetUserName` | `entities.user.username` |
| `data.win.eventdata.SubjectUserName` | `entities.user.username` |
| `data.win.eventdata.Image` | `entities.process.path` |
| `data.win.eventdata.CommandLine` | `entities.process.command_line` |
| `data.win.eventdata.ParentImage` | `entities.process.parent_path` |
| `data.win.eventdata.ProcessId` | `entities.process.pid` |
| `data.win.eventdata.IpAddress` | `entities.network.src_ip` |

## Linux Entity Candidates

| Wazuh Field Candidate | SafeAgentSOC Field |
|---|---|
| `data.srcuser` | `entities.user.username` |
| `data.dstuser` | `entities.user.username` |
| `data.srcip` | `entities.network.src_ip` |
| `data.srcport` | `entities.network.src_port` |
| `data.command` | `entities.process.command_line` |
| `full_log` | fallback evidence text, private only |

## Severity Mapping

| Wazuh Rule Level | SafeAgentSOC Severity |
|---:|---|
| 0-3 | low |
| 4-7 | medium |
| 8-11 | high |
| 12+ | critical |

## Important Rule

This mapping must not use ground-truth labels.

Normalization maps raw alert fields into runtime-safe objects only.
