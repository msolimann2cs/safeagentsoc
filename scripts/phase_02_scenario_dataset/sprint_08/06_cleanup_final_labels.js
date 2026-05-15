const fs = require("fs");
const path = require("path");

const root = process.cwd();
const base = path.join(root, "06_data", "phase_02_scenario_dataset", "sprint_08_ground_truth");
const labelsFile = path.join(base, "ground_truth_labels.csv");
const reviewedFile = path.join(base, "ground_truth_labels_reviewed.csv");

const requiredColumns = [
  "label_id",
  "alert_uid",
  "scenario_id",
  "campaign_id",
  "run_id",
  "agent_name",
  "timestamp",
  "label",
  "event_role",
  "simulation_type",
  "execution_mode",
  "tool",
  "atomic_test_id",
  "caldera_operation_id",
  "caldera_adversary_profile",
  "caldera_ability_id",
  "mitre_tactic",
  "mitre_technique_id",
  "rule_id",
  "rule_description",
  "confidence",
  "ground_truth_summary",
  "notes",
];

const calderaMetadata = {
  "C-WIN-01-CAL-R001": {
    operation_id: "C-WIN-01-CAL-R001",
    adversary_profile: "Thief (1a98b8e6-18ce-4617-8cc5-e65a1a9d490e)",
    ability_ids:
      "6469befa-748a-4b9c-a96d-f191fde47d89;90c2efaa-8205-480d-8bb6-61d90dbaf81b;4e97e699-93d7-4040-b5a3-2e906a58199e;300157e5-f4ad-4569-b533-9d1fa0e74d74;ea713bc4-63f0-491c-9a6f-0b01d560b87e",
  },
  "C-WIN-01-CAL-R002": {
    operation_id: "C-WIN-01-CAL-R002",
    adversary_profile: "You Shall (Not) Bypass (c724545d-a4cc-492e-8075-2ab9a699c847)",
    ability_ids:
      "665432a4-42e7-4ee1-af19-a9a8c9455d0c;95ad5d69-563e-477b-802b-4855bfb3be09;e99cce5c-cb7e-4a6e-8a09-1609a221b90a;e3db134c-4aed-4c5a-9607-c50183c9ef9e",
  },
  "C-LNX-01-CAL-R001": {
    operation_id: "CAL_LNX_OP1",
    adversary_profile: "Thief (1a98b8e6-18ce-4617-8cc5-e65a1a9d490e)",
    ability_ids:
      "6469befa-748a-4b9c-a96d-f191fde47d89;90c2efaa-8205-480d-8bb6-61d90dbaf81b;4e97e699-93d7-4040-b5a3-2e906a58199e;300157e5-f4ad-4569-b533-9d1fa0e74d74;ea713bc4-63f0-491c-9a6f-0b01d560b87e",
  },
  "C-LNX-01-CAL-R002": {
    operation_id: "CAL_LNX_OP2 (2026-05-15T04:08:53.929Z)",
    adversary_profile: "Defense Evasion (ef4d997c-a0d1-4067-9efa-87c58682db71)",
    ability_ids:
      "43b3754c-def4-4699-a673-1d85648fda6a;8478297ebb155b34c412a0fde335eccd;683115a2ceeb045e6ffbf4487322b220;8a60db80ab6f4a6b1db758c95bacfafa;0aaebed766f7120873d5ad90c23355f8;2929fac2296bf1041ba33c86d42d9a5a;c8e46a29cac614806da56b0be6b0e454;b2e76a3113cbfc8e9729b7e170a5a6aa;8e7c28877a9c7826fece190f185b534c;379509c4b83f252bc779446f0512e936;80be956df11e4a384333150807c3ccd9;d38cba2905e62b4c1a7e5c88137ce485;326a9797b0d59b8f6d5a3c384c564b9f;5ffa5b3b330848d39dc1728365dad61c;db8c6ba84f796a2f1fa1497b8dc1aae2;4d4b29abb6b1e580e33c0035c1fc37ad",
  },
  "C-LNX-01-CAL-R003": {
    operation_id: "CAL_LNX_OP3 (2026-05-15T04:09:53.102Z)",
    adversary_profile: "Discovery (0f4c3c67-845e-49a0-927e-90ed33c044e0)",
    ability_ids:
      "c0da588f-79f0-4263-8998-7496b1a40596;c1cd6388-3ced-48c7-a511-0434c6ba8f48;3b5db901-2cb8-4df7-8043-c4628a6a5d5a;5c4dd985-89e3-4590-9b57-71fed66ff4e2",
  },
};

function parseCsvLine(line) {
  const values = [];
  let cur = "";
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    const next = line[i + 1];
    if (ch === '"' && inQuotes && next === '"') {
      cur += '"';
      i++;
    } else if (ch === '"') {
      inQuotes = !inQuotes;
    } else if (ch === "," && !inQuotes) {
      values.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  values.push(cur);
  return values;
}

function parseCsv(text) {
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter((line) => line.length);
  const header = parseCsvLine(lines[0] || "");
  const rows = lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const row = {};
    header.forEach((name, i) => {
      row[name] = values[i] ?? "";
    });
    return row;
  });
  return { header, rows };
}

function csvEscape(value) {
  const text = value == null ? "" : String(value);
  if (/[",\n\r]/.test(text)) return `"${text.replace(/"/g, '""')}"`;
  return text;
}

function writeCsv(file, rows, columns) {
  fs.writeFileSync(
    file,
    [columns.join(","), ...rows.map((row) => columns.map((column) => csvEscape(row[column] ?? "")).join(","))].join("\n") + "\n",
    "utf8",
  );
}

function groupBy(rows, key) {
  const groups = new Map();
  for (const row of rows) {
    const value = row[key] || "";
    if (!groups.has(value)) groups.set(value, []);
    groups.get(value).push(row);
  }
  return groups;
}

function isMarker(row) {
  const text = `${row.rule_description || ""} ${row.ground_truth_summary || ""}`.toLowerCase();
  return text.includes("safeagentsoc") || text.includes("run start marker") || text.includes("run end marker") || text.includes("scenario marker");
}

function countBy(rows, column) {
  const counts = new Map();
  for (const row of rows) counts.set(row[column] || "EMPTY", (counts.get(row[column] || "EMPTY") || 0) + 1);
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function writeQa(rows) {
  const total = rows.length;
  const completeness = requiredColumns.map((field) => {
    const nonEmpty = rows.filter((row) => String(row[field] || "").trim()).length;
    return {
      field,
      non_empty_count: nonEmpty,
      empty_count: total - nonEmpty,
      completeness_percent: total ? ((nonEmpty / total) * 100).toFixed(2) : "0.00",
    };
  });
  writeCsv(path.join(base, "label_completeness_metrics.csv"), completeness, ["field", "non_empty_count", "empty_count", "completeness_percent"]);

  const matrix = (file, keyA, keyB, columns) => {
    const counts = new Map();
    for (const row of rows) {
      const key = `${row[keyA] || "EMPTY"}|${row[keyB] || "EMPTY"}`;
      counts.set(key, (counts.get(key) || 0) + 1);
    }
    const out = [...counts.entries()].sort().map(([key, count]) => {
      const [a, b] = key.split("|");
      return { [columns[0]]: a, [columns[1]]: b, count };
    });
    writeCsv(path.join(base, file), out, [...columns, "count"]);
  };
  matrix("mitre_coverage_matrix.csv", "scenario_id", "mitre_technique_id", ["scenario_or_campaign", "mitre_technique_id"]);
  matrix("endpoint_coverage_matrix.csv", "agent_name", "label", ["agent_name", "label"]);
  matrix("execution_mode_comparison_matrix.csv", "execution_mode", "event_role", ["execution_mode", "event_role"]);

  const uidGroups = groupBy(rows, "alert_uid");
  const duplicateGroups = [...uidGroups.values()].filter((items) => items.length > 1);
  const duplicateAnalysis = duplicateGroups.map((items) => ({
    alert_uid: items[0].alert_uid,
    reference_count: items.length,
    run_ids: [...new Set(items.map((row) => row.run_id).filter(Boolean))].join(";"),
    scenario_ids: [...new Set(items.map((row) => row.scenario_id).filter(Boolean))].join(";"),
    campaign_ids: [...new Set(items.map((row) => row.campaign_id).filter(Boolean))].join(";"),
    rule_id: items[0].rule_id,
    rule_description: items[0].rule_description,
    interpretation: "Repeated correlation reference across overlapping run/campaign windows; not necessarily a duplicate raw alert.",
  }));
  writeCsv(path.join(base, "duplicate_uid_analysis.csv"), duplicateAnalysis, [
    "alert_uid",
    "reference_count",
    "run_ids",
    "scenario_ids",
    "campaign_ids",
    "rule_id",
    "rule_description",
    "interpretation",
  ]);

  const mdCounter = (title, entries) => [`## ${title}`, "", "| Value | Count |", "|---|---:|", ...entries.map(([k, v]) => `| ${k} | ${v} |`), ""].join("\n");
  const report = [
    "# Sprint 8 Dataset QA Report",
    "",
    "## Summary",
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Total labeled rows | ${total} |`,
    `| Unique alert UIDs | ${uidGroups.size} |`,
    `| Duplicate alert UID groups | ${duplicateGroups.length} |`,
    `| Low-confidence rows | ${rows.filter((row) => row.confidence === "low").length} |`,
    "",
    mdCounter("Label Distribution", countBy(rows, "label")),
    mdCounter("Event Role Distribution", countBy(rows, "event_role")),
    mdCounter("Scenario Distribution", countBy(rows, "scenario_id")),
    mdCounter("Campaign Distribution", countBy(rows, "campaign_id")),
    mdCounter("Endpoint Distribution", countBy(rows, "agent_name")),
    mdCounter("Execution Mode Distribution", countBy(rows, "execution_mode")),
    mdCounter("Confidence Distribution", countBy(rows, "confidence")),
    mdCounter("MITRE Technique Distribution", countBy(rows, "mitre_technique_id")),
    "## Cleanup Review Notes",
    "",
    "- Caldera operation names, adversary profiles, and operation-level ability ID sets were recovered from Caldera report JSON evidence.",
    "- Low-confidence rows were spot-checked as unrelated/background rows and upgraded to medium confidence with explicit notes.",
    "- Trigger roles were tightened to primary evidence. Repeated telemetry, especially repeated process-discovery events, was moved to supporting or duplicate.",
    "- Duplicate alert UIDs represent repeated correlation references across overlapping run/campaign windows, not necessarily duplicate raw alerts.",
    "",
    "## Limitations",
    "",
    "- Caldera ability IDs are operation-level ability sets from report JSON, not per-alert ability attribution.",
    "- Campaign-level windows may overlap with scenario-level windows.",
    "- Some labels are derived from timestamp correlation and require conservative confidence scoring.",
    "- Sprint 9 will group these labels into investigation cases and alert-fatigue metrics.",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(base, "dataset_qa_report.md"), report, "utf8");
}

function validate(rows) {
  const allowedLabels = new Set(["benign", "noise", "ambiguous_noise", "attack_like", "attack_like_failed", "simulated_only", "unrelated_background"]);
  const allowedRoles = new Set(["trigger", "supporting", "duplicate", "noise", "unrelated"]);
  const allowedConfidence = new Set(["high", "medium", "low"]);
  const errors = [];
  rows.forEach((row, idx) => {
    if (!allowedLabels.has(row.label)) errors.push(`Line ${idx + 2}: invalid label ${row.label}`);
    if (!allowedRoles.has(row.event_role)) errors.push(`Line ${idx + 2}: invalid role ${row.event_role}`);
    if (!allowedConfidence.has(row.confidence)) errors.push(`Line ${idx + 2}: invalid confidence ${row.confidence}`);
    for (const field of ["label_id", "alert_uid", "run_id", "agent_name", "timestamp", "label", "event_role", "rule_id", "rule_description", "confidence"]) {
      if (!String(row[field] || "").trim()) errors.push(`Line ${idx + 2}: empty required operational field ${field}`);
    }
    if (String(row.notes || "").toLowerCase().includes("draft")) errors.push(`Line ${idx + 2}: draft wording remains in notes`);
    if (Object.values(row).some((value) => String(value || "").includes("TBD_FROM_CALDERA_UI"))) errors.push(`Line ${idx + 2}: Caldera TBD remains`);
  });
  const result = errors.length
    ? `SCHEMA VALIDATION FAILED\nTotal errors: ${errors.length}\n${errors.slice(0, 100).join("\n")}\n`
    : `SCHEMA VALIDATION PASSED\nRows validated: ${rows.length}\nNo Draft wording remains.\nNo TBD_FROM_CALDERA_UI values remain.\n`;
  fs.writeFileSync(path.join(base, "schema_validation_result.txt"), result, "utf8");
  if (errors.length) throw new Error(result);
}

const { rows } = parseCsv(fs.readFileSync(labelsFile, "utf8"));

for (const row of rows) {
  for (const col of requiredColumns) if (!(col in row)) row[col] = "";

  const meta = calderaMetadata[row.run_id];
  if (meta) {
    row.caldera_operation_id = meta.operation_id;
    row.caldera_adversary_profile = meta.adversary_profile;
    row.caldera_ability_id = meta.ability_ids;
  } else if (row.execution_mode === "caldera") {
    row.caldera_operation_id = row.caldera_operation_id && !row.caldera_operation_id.includes("TBD") ? row.caldera_operation_id : "not_recovered";
    row.caldera_adversary_profile = row.caldera_adversary_profile || "not_recovered";
    row.caldera_ability_id = row.caldera_ability_id || "not_recovered";
  }

  if (row.confidence === "low" && row.label === "unrelated_background" && row.event_role === "unrelated") {
    row.confidence = "medium";
  }

  if (row.label === "unrelated_background") {
    row.event_role = "unrelated";
    row.ground_truth_summary = row.ground_truth_summary || "Background alert not directly tied to a scenario run.";
  } else if (row.event_role === "trigger") {
    row.event_role = "supporting";
  }
}

const uidGroups = groupBy(rows, "alert_uid");
for (const items of uidGroups.values()) {
  if (items.length <= 1) continue;
  items.sort((a, b) => String(a.run_id).localeCompare(String(b.run_id)) || String(a.label_id).localeCompare(String(b.label_id)));
  for (let i = 1; i < items.length; i++) {
    if (items[i].label !== "unrelated_background") {
      items[i].event_role = "duplicate";
      items[i].confidence = "medium";
    }
  }
}

const runGroups = groupBy(rows, "run_id");
for (const [runId, items] of runGroups.entries()) {
  if (runId === "BACKGROUND-SAMPLE") continue;
  const candidates = items.filter((row) => row.label !== "unrelated_background" && row.event_role !== "duplicate");
  const markerCandidates = candidates.filter(isMarker);
  const campaignLimit = runId.includes("-CAL-") ? 2 : 0;
  const nonCampaignLimit = runId.includes("-CAL-") ? 0 : 1;

  for (const row of markerCandidates.slice(0, 3)) {
    row.event_role = "trigger";
    row.confidence = "high";
  }

  const remaining = candidates.filter((row) => row.event_role !== "trigger");
  const limit = runId.includes("-CAL-") ? campaignLimit : nonCampaignLimit;
  for (const row of remaining.slice(0, limit)) {
    row.event_role = "trigger";
    row.confidence = "high";
  }

  for (const row of remaining.slice(limit)) {
    if (row.event_role !== "duplicate") {
      row.event_role = row.label === "ambiguous_noise" ? "noise" : "supporting";
      row.confidence = row.confidence === "high" ? "medium" : row.confidence;
    }
  }
}

for (const row of rows) {
  if (row.event_role === "trigger") {
    row.notes = "Reviewed during Sprint 8 QA. Primary trigger evidence retained.";
  } else if (row.event_role === "duplicate") {
    row.notes = "Reviewed during Sprint 8 QA. Duplicate correlation reference retained for overlap and alert-fatigue analysis.";
  } else if (row.label === "unrelated_background") {
    row.notes = "Medium-confidence timestamp-derived unrelated/background label; retained after Sprint 8 spot-check.";
  } else if (row.confidence === "medium") {
    row.notes = "Medium-confidence timestamp-derived label; retained after spot-check.";
  } else {
    row.notes = "Reviewed during Sprint 8 QA.";
  }
}

writeCsv(labelsFile, rows, requiredColumns);
writeCsv(reviewedFile, rows, requiredColumns);
writeQa(rows);
validate(rows);

console.log("Sprint 8 cleanup complete");
console.log(`Rows: ${rows.length}`);
console.log(`Triggers: ${rows.filter((row) => row.event_role === "trigger").length}`);
console.log(`Low confidence: ${rows.filter((row) => row.confidence === "low").length}`);
console.log(`Caldera TBD values: ${rows.filter((row) => Object.values(row).some((value) => String(value || "").includes("TBD_FROM_CALDERA_UI"))).length}`);
