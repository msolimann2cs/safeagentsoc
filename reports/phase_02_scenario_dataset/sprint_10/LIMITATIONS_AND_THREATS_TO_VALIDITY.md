# Phase 2 Limitations and Threats to Validity

## 1. Lab Environment Limitation

The dataset was generated in a controlled VMware lab. It does not fully represent the diversity, noise, identity systems, business applications, and endpoint diversity of a production enterprise SOC.

## 2. Alert Volume Limitation

The original raw alert target was 900 to 2,500 alerts. The final export contains 6,893 alerts because Wazuh generated repeated Linux, audit, process, and authentication telemetry. This was retained rather than discarded to preserve realistic alert-fatigue behavior.

## 3. Gold-Label Scope

Only 800 alerts were included in the QA-validated gold-label subset. The remaining raw alerts were retained as an unlabeled background pool to avoid weak or unverifiable labels.

## 4. Overlap Limitation

Campaign, scenario, technique, and run-level cases may overlap. Casebook totals are benchmark references, not deduplicated global alert totals.

## 5. Timestamp Correlation Limitation

Some labels were derived from timestamp windows and host matching. These labels were conservatively confidence-scored and included in QA reports.

## 6. Caldera Metadata Limitation

Some Caldera UI metadata was not recoverable after execution. These fields are marked as `not_recovered` where needed.

## 7. Detection Coverage Limitation

Some attack-like scenarios produced weak or unrelated-dominated alert evidence. These were retained as weak-detection cases rather than hidden, because they are useful for evaluating SafeAgentSOC uncertainty handling.

## 8. High-Risk Behavior Limitation

Credential dumping, credential-material access, destructive log clearing, ransomware-like encryption, and real exfiltration were not executed destructively. They were represented as simulated-only gaps when needed.

## 9. Generalization Limitation

The dataset is intended as a controlled benchmark for SafeAgentSOC development. It should not be presented as a universal SOC dataset.
