"""Sprint 8 compatibility wrapper.

The local host used for this sprint does not have Python installed, so the
implemented Sprint 8 pipeline is in run_sprint8_ground_truth.js. Running this
file on a Python-enabled system executes the same pipeline through Node.
"""

import subprocess

subprocess.run(
    ["node", "scripts/phase_02_scenario_dataset/sprint_08/run_sprint8_ground_truth.js"],
    check=True,
)
