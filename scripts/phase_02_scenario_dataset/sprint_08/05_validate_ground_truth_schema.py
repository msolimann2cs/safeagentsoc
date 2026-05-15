"""Sprint 8 compatibility wrapper for schema validation."""

import subprocess

subprocess.run(
    ["node", "scripts/phase_02_scenario_dataset/sprint_08/run_sprint8_ground_truth.js"],
    check=True,
)
