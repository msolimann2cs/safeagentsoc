"""Sprint 8 compatibility wrapper for combining draft and background labels."""

import subprocess

subprocess.run(
    ["node", "scripts/phase_02_scenario_dataset/sprint_08/run_sprint8_ground_truth.js"],
    check=True,
)
