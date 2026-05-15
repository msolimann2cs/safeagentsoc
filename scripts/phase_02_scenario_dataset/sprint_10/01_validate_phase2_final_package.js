const fs = require("fs");

const requiredFiles = [
  "reports/phase_02_scenario_dataset/sprint_10/PHASE_02_DATASET_CREATION_REPORT.md",
  "reports/phase_02_scenario_dataset/sprint_10/ATOMIC_RED_TEAM_DOCUMENTATION.md",
  "reports/phase_02_scenario_dataset/sprint_10/CALDERA_OPERATION_DOCUMENTATION.md",
  "reports/phase_02_scenario_dataset/sprint_10/LIMITATIONS_AND_THREATS_TO_VALIDITY.md",
  "reports/phase_02_scenario_dataset/sprint_10/PHASE_03_HANDOFF.md",
  "docs/phase_02_scenario_dataset/final/PHASE_02_DATASET_MANIFEST_FINAL.md",
  "docs/phase_02_scenario_dataset/final/PHASE_02_PUBLIC_SUMMARY.md",
  "06_data/phase_02_scenario_dataset/phase_02_final_package/phase_02_artifact_inventory.csv",
  "06_data/phase_02_scenario_dataset/phase_02_final_package/casebook.csv",
  "06_data/phase_02_scenario_dataset/phase_02_final_package/alert_fatigue_baseline.csv",
  "06_data/phase_02_scenario_dataset/phase_02_final_package/dataset_qa_report.md",
  "06_data/phase_02_scenario_dataset/phase_02_final_package/phase_03_normalization_requirements.md",
];

let failed = false;

console.log("Validating Phase 2 final package...\n");

for (const file of requiredFiles) {
  if (!fs.existsSync(file)) {
    console.log(`MISSING: ${file}`);
    failed = true;
  } else {
    const size = fs.statSync(file).size;
    console.log(`OK: ${file} (${size} bytes)`);
  }
}

if (failed) {
  console.log("\nPHASE 2 FINAL PACKAGE VALIDATION FAILED");
  process.exit(1);
}

console.log("\nPHASE 2 FINAL PACKAGE VALIDATION PASSED");
