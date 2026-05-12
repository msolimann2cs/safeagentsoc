# SafeAgentSOC

SafeAgentSOC is a GRC-aware, tool-constrained AI SOC co-analyst prototype for reducing SOC alert fatigue through SIEM telemetry, alert normalization, incident case-building, context enrichment, LLM-assisted hypothesis generation, graph validation, risk scoring, GRC policy guardrails, constrained action recommendations, and human-in-the-loop approval.

## Current Status

Phase 1: Lab Foundation.

## Current Sprint

Sprint 0: Workspace and documentation setup.

## Phase 1 Goal

Deploy a controlled Wazuh-based SOC lab with Windows and Linux endpoints and prove log ingestion.

## Phase 1 Deliverables

- Working Wazuh lab
- Windows endpoint
- Linux endpoint
- Sysmon telemetry
- Wazuh agent onboarding proof
- Log ingestion proof
- Network diagram
- VM inventory
- Deployment documentation
- Evidence screenshots
- Lab foundation report

## Repository Structure

```text
docs/               Project documentation
docs/phase_01_lab_foundation
diagrams/           Architecture and network diagrams
infrastructure/     Setup scripts and infrastructure notes
data/               Small sample data and schemas only
reports/            Phase reports and final writeups 
Safety Scope

This project is conducted only inside a controlled lab environment. It does not target third-party systems, does not deploy destructive response actions by default, and does not use the LLM as the final decision-maker.
