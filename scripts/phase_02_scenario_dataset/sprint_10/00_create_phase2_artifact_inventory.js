const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const files = [
  "06_data/phase_02_scenario_dataset/sprint_07_raw_exports/full/raw_alerts_full.jsonl",
  "06_data/phase_02_scenario_dataset/sprint_07_raw_exports/dataset_manifest.yaml",
  "06_data/phase_02_scenario_dataset/sprint_08_ground_truth/ground_truth_labels.csv",
  "06_data/phase_02_scenario_dataset/sprint_08_ground_truth/dataset_qa_report.md",
  "06_data/phase_02_scenario_dataset/sprint_09_casebook/casebook.csv",
  "06_data/phase_02_scenario_dataset/sprint_09_casebook/alert_fatigue_baseline.csv",
  "06_data/phase_02_scenario_dataset/sprint_09_casebook/raw_background_pool_summary.md",
  "06_data/phase_02_scenario_dataset/sprint_09_casebook/phase_03_normalization_requirements.md",
];

const outDir = "06_data/phase_02_scenario_dataset/phase_02_final_package";
fs.mkdirSync(outDir, { recursive: true });

function sha256(file) {
  const hash = crypto.createHash("sha256");
  hash.update(fs.readFileSync(file));
  return hash.digest("hex").toUpperCase();
}

function esc(value) {
  const text = String(value ?? "");
  if (text.includes(",") || text.includes('"') || text.includes("\n")) {
    return `"${text.replace(/"/g, '""')}"`;
  }
  return text;
}

const rows = files.map((file) => {
  if (!fs.existsSync(file)) {
    return { file, exists: "no", size_bytes: "", sha256: "", purpose: "missing" };
  }

  const stat = fs.statSync(file);
  return {
    file,
    exists: "yes",
    size_bytes: stat.size,
    sha256: sha256(file),
    purpose: path.basename(file),
  };
});

const csv = [
  "file,exists,size_bytes,sha256,purpose",
  ...rows.map((r) => [r.file, r.exists, r.size_bytes, r.sha256, r.purpose].map(esc).join(",")),
].join("\n");

fs.writeFileSync(path.join(outDir, "phase_02_artifact_inventory.csv"), csv);

const md = `# Phase 2 Artifact Inventory

| File | Exists | Size Bytes | SHA256 |
|---|---|---:|---|
${rows.map((r) => `| \`${r.file}\` | ${r.exists} | ${r.size_bytes} | \`${r.sha256}\` |`).join("\n")}

## Notes

Raw telemetry and full labels are private local artifacts. Public GitHub should only contain reports, schemas, sanitized samples, and summary metrics.
`;

fs.writeFileSync(path.join(outDir, "phase_02_artifact_inventory.md"), md);

console.log("Wrote artifact inventory.");
console.log(path.join(outDir, "phase_02_artifact_inventory.csv"));
console.log(path.join(outDir, "phase_02_artifact_inventory.md"));

for (const row of rows) {
  console.log(`${row.exists.toUpperCase()} ${row.file} ${row.size_bytes}`);
}
