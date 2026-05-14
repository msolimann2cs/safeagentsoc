# Sprint 1: Scenario Taxonomy and Detection Design

## Purpose

Sprint 1 defines what counts as a valid Phase 2 scenario, what dataset balance is required, what evidence each scenario must produce, and what quality gates must be met before any scenario is executed.

This sprint does not execute scenarios. It prepares the design rules that prevent the dataset from becoming unstructured, biased, unsafe, or hard to label later.

## Sprint 1 Output

| Output | Purpose |
|---|---|
| Dataset taxonomy | Defines attack-like, benign, noise, ambiguous, and false-positive-like scenario categories |
| Dataset balance plan | Prevents the dataset from containing only attack-like alerts |
| Detection design matrix | Defines expected Wazuh signals before scenarios are executed |
| Scenario quality gate | Blocks unsafe or underdefined scenarios |
| Evidence requirements | Ensures every scenario can be traced to screenshots, timestamps, commands, and labels |
| Alert volume plan | Defines the expected alert count contribution per scenario group |

## Dataset Category Taxonomy

| Category | Definition | Example | Label Value |
|---|---|---|---|
| Attack-like Windows | Safe Windows behavior that resembles attacker tradecraft but uses benign commands | PowerShell execution, discovery commands, scheduled task marker | attack_like |
| Attack-like Linux | Safe Linux behavior that resembles attacker tradecraft but uses benign commands | SSH failed login, sudo authentication, discovery commands, cron marker | attack_like |
| Benign admin activity | Legitimate administrative or maintenance activity | Get-Service, apt update, systemctl status | benign |
| Noisy repeated low-value activity | Repetitive events useful for testing duplicate suppression and alert fatigue | repeated notepad, calc, whoami, sudo typo loops | noise |
| False-positive candidate | Known-benign behavior that may look suspicious to a detection system | admin PowerShell or maintenance-like discovery | false_positive_candidate |
| Ambiguous mixed activity | Events that have partial suspiciousness but insufficient malicious context | failed login followed by success, repeated typo, admin-like behavior | ambiguous |

## Dataset Balance Targets

| Dataset Category | Target Share | Reason |
|---|---:|---|
| Attack-like Windows | 25 to 30% | Exercises Sysmon, PowerShell, process, Windows Security telemetry |
| Attack-like Linux | 20 to 25% | Exercises SSH, sudo, auth, discovery, and cron-like telemetry |
| Benign admin activity | 20 to 25% | Needed to evaluate false-positive handling and benign classification |
| Noisy/repeated low-value alerts | 15 to 20% | Needed for alert fatigue, duplicate suppression, and case-building evaluation |
| Mixed/ambiguous scenarios | 5 to 10% | Needed for realistic uncertainty and conditional labeling |

## Practical Dataset Target

| Target | Meaning |
|---|---|
| 300 alerts | Minimum acceptable dataset size |
| 600 alerts | Strong practical target |
| 1,000 alerts | Upper target only if labeling remains clean |

The preferred target is approximately 600 alerts. A smaller, well-labeled dataset is better than a larger, messy dataset.

## Scenario ID Rules

| Rule | Requirement |
|---|---|
| Scenario IDs | Use S01 to S12 |
| Run IDs | Use SXX-RYYY format, e.g., S01-R001 |
| Alert traceability | Every alert must map to `scenario_id` and `run_id` where possible |
| Execution separation | Run one scenario at a time |
| Time windows | Every scenario run must have `start_ts` and `end_ts` |
| Cleanup | Every scenario that creates artifacts must have cleanup commands |
| Evidence | Every scenario must have screenshot proof |

## Scenario Type Rules

### attack_like

Use for safe lab behavior that intentionally resembles adversary behavior.

Requirements:
- Must have MITRE ATT&CK mapping.
- Must have a clear hypothesis.
- Must have cleanup steps if anything is created.
- Must not use real malware, credential dumping, destructive persistence, or third-party targeting.

### benign

Use for clearly normal administrative activity.

Requirements:
- MITRE mapping should usually be N/A.
- Do not force adversarial mapping.
- Must state why it is benign.

### noise

Use for repeated, low-value events designed to test alert fatigue and duplicate suppression.

Requirements:
- Must be safe and repetitive.
- Must define expected repetition count.
- Must be labeled as noise, not attack_like.

### false_positive_candidate

Use for known-benign activity that could look suspicious.

Requirements:
- Must state why it could trigger detection.
- Must state why ground truth is benign.
- MITRE mapping can be N/A or related technique only if justified.

### ambiguous

Use for mixed signals where analyst interpretation should be conditional.

Requirements:
- Must state what evidence would make it malicious.
- Must state what evidence would make it benign.
- Must use medium or low label confidence if uncertainty remains.

## Scenario Hypothesis Rules

Each scenario must answer:

| Question | Required Answer |
|---|---|
| What should the analyst infer? | Expected interpretation of the scenario |
| What would be a wrong inference? | What the alert should not be overclaimed as |
| What evidence supports the inference? | Expected Wazuh fields, logs, commands, or rule descriptions |
| What evidence is missing? | What cannot be concluded from the scenario |
| What should the label be? | attack_like, benign, noise, false_positive_candidate, or ambiguous |

## Detection Design Matrix

| Scenario | Platform | Category | Main Expected Signal | Local Proof | Wazuh Query Idea | Expected Role |
|---|---|---|---|---|---|---|
| S01 | Windows | attack_like | PowerShell process/Sysmon event | PowerShell command output and Sysmon local event | `agent.name: "safesoc-win-01" and powershell` | trigger |
| S02 | Windows | attack_like | Discovery command process events | command output | `agent.name: "safesoc-win-01" and (whoami or systeminfo)` | trigger/supporting |
| S03 | Windows | attack_like | Scheduled task creation/deletion | `schtasks` output | `agent.name: "safesoc-win-01" and schtasks` | trigger |
| S04 | Windows | attack_like | File staging/archive activity | `Compress-Archive` output | `agent.name: "safesoc-win-01" and archive` | trigger/supporting |
| S05 | Windows | benign | Normal admin process events | command output | `agent.name: "safesoc-win-01" and Get-Service` | benign/supporting |
| S06 | Windows | noise | Repeated benign process events | loop command output | `agent.name: "safesoc-win-01" and notepad` | noise/duplicate |
| S07 | Linux | attack_like | Failed SSH authentication | `journalctl` or `auth.log` | `agent.name: "safesoc-lnx-01" and ssh` | trigger |
| S08 | Linux | attack_like | sudo authentication event | `journalctl` or `auth.log` | `agent.name: "safesoc-lnx-01" and sudo` | trigger |
| S09 | Linux | attack_like | Discovery commands | terminal output | `agent.name: "safesoc-lnx-01" and (whoami or uname)` | trigger/supporting |
| S10 | Linux | attack_like | Cron marker creation/execution | `crontab` output and marker file | `agent.name: "safesoc-lnx-01" and cron` | trigger |
| S11 | Linux | benign | Normal admin maintenance | `apt` / `systemctl` / `journalctl` output | `agent.name: "safesoc-lnx-01" and systemctl` | benign/supporting |
| S12 | Cross-endpoint | ambiguous/noise | Repeated auth typo then success | local login/auth logs | `agent.name: "<agent>" and failed` | noise/ambiguous |

## Evidence Requirements Per Scenario

Every scenario run must produce:

| Evidence Type | Filename Pattern | Purpose |
|---|---|---|
| Pre-run state | `YYYY-MM-DD_SXX_RYYY_pre-run_state.png` | Shows correct VM, time, and scenario setup |
| Commands executed | `YYYY-MM-DD_SXX_RYYY_commands_executed.png` | Proves the scenario was actually run |
| Local log proof | `YYYY-MM-DD_SXX_RYYY_local_log_proof.png` | Proves endpoint generated local evidence |
| Wazuh results | `YYYY-MM-DD_SXX_RYYY_wazuh_results.png` | Proves Wazuh ingested matching events |
| Wazuh event details | `YYYY-MM-DD_SXX_RYYY_wazuh_event_details.png` | Shows timestamp, agent, rule ID, and event fields |
| Cleanup proof | `YYYY-MM-DD_SXX_RYYY_cleanup_proof.png` | Proves test artifacts were removed if applicable |

## Scenario Quality Gate

No scenario can be executed until all of these are defined:

- [ ] Scenario ID
- [ ] Scenario name
- [ ] Scenario category
- [ ] Platform
- [ ] Affected host
- [ ] Objective
- [ ] Analyst hypothesis
- [ ] Wrong inference warning
- [ ] MITRE mapping or N/A justification
- [ ] Expected local signal
- [ ] Expected Wazuh signal
- [ ] Wazuh query idea
- [ ] Commands
- [ ] Cleanup commands
- [ ] Safety rating
- [ ] Expected label
- [ ] Evidence filenames
- [ ] Run log row prepared

## Safety Ratings

| Rating | Meaning | Allowed? |
|---|---|---|
| Low | Benign commands, read-only discovery, safe file creation in test folder | Yes |
| Medium | Creates scheduled task, cron job, temporary marker, or repeated auth failures | Yes with cleanup |
| High | Credential dumping, malware behavior, destructive persistence, external targeting | No, simulate or skip |

## Phase 2 Execution Rule

If a scenario cannot be documented, safely cleaned up, mapped to evidence, and labeled before execution, it must not be run.

## Sprint 1 Done When

- Dataset taxonomy is written.
- Dataset balance targets are written.
- Scenario type rules are written.
- Detection design matrix is written.
- Scenario quality gate is written.
- Evidence requirements are written.
- Safety ratings are written.
- Sprint 2 can now create the full scenario catalog.

