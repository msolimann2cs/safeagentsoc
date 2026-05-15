const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const root = process.cwd();
const base = path.join(root, "06_data", "phase_02_scenario_dataset", "sprint_08_ground_truth");
const perRunDir = path.join(base, "per_run");
const rawFile = path.join(base, "raw_alerts_full.jsonl");
const runLogFrozen = path.join(base, "scenario_run_log_frozen.csv");
const runLogNormalized = path.join(base, "scenario_run_log_normalized.csv");

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
  "caldera_ability_id",
  "mitre_tactic",
  "mitre_technique_id",
  "rule_id",
  "rule_description",
  "confidence",
  "ground_truth_summary",
  "notes",
];

const scenarioLabels = {
  S01: ["attack_like", "Execution", "T1059.001"],
  S02: ["attack_like", "Discovery", "T1082/T1033/T1016"],
  S03: ["attack_like", "Persistence", "T1053.005"],
  S04: ["attack_like", "Collection", "T1560.001"],
  S05: ["benign", "N/A", "N/A"],
  S06: ["noise", "N/A", "N/A"],
  S07: ["attack_like", "Credential Access", "T1110.001"],
  S08: ["attack_like", "Privilege Escalation/Defense Evasion", "T1548.003"],
  S09: ["attack_like", "Discovery", "T1082/T1033/T1016"],
  S10: ["attack_like", "Persistence", "T1053.003"],
  S11: ["benign", "N/A", "N/A"],
  S12: ["ambiguous_noise", "N/A", "N/A"],
};

const campaignLabels = {
  "C-WIN-01": ["attack_like", "Campaign", "T1059.001/T1082/T1033/T1016/T1053.005/T1560.001"],
  "C-LNX-01": ["attack_like", "Campaign", "T1110.001/T1548.003/T1082/T1033/T1016/T1053.003"],
};

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

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
  if (lines.length === 0) return { header: [], rows: [] };
  const header = parseCsvLine(lines[0]);
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
  const lines = [columns.join(",")];
  for (const row of rows) {
    lines.push(columns.map((column) => csvEscape(row[column] ?? "")).join(","));
  }
  fs.writeFileSync(file, lines.join("\n") + "\n", "utf8");
}

function compactJson(value) {
  return JSON.stringify(value, Object.keys(value).sort());
}

function parseTimestamp(value) {
  if (!value) return null;
  let text = String(value).trim().replace(/^"|"$/g, "");
  if (!text) return null;
  if (/^\d+(\.\d+)?$/.test(text)) {
    const serial = Number(text);
    const baseDate = Date.UTC(1899, 11, 30);
    return new Date(baseDate + serial * 24 * 60 * 60 * 1000);
  }
  text = text.replace("Z", "+00:00").replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function toUtcIso(value) {
  const parsed = parseTimestamp(value);
  return parsed ? parsed.toISOString() : (value || "");
}

function alertUid(alert) {
  const parts = {
    index: alert._index || "",
    id: alert._id || alert.id || "",
    timestamp: alert.timestamp || "",
    agent: alert.agent?.name || "",
    rule_id: alert.rule?.id || "",
    full_log: String(alert.full_log || "").slice(0, 1000),
    decoder: alert.decoder?.name || "",
    location: alert.location || "",
  };
  const digest = crypto.createHash("sha256").update(compactJson(parts), "utf8").digest("hex").slice(0, 16).toUpperCase();
  return `ALERT-${digest}`;
}

function duplicateKey(alert, runId) {
  let normalized = String(alert.full_log || "");
  normalized = normalized.replace(/\d{4}-\d{2}-\d{2}T[^\s]+/g, "<TIME>");
  normalized = normalized.replace(/\b\d+\b/g, "<NUM>");
  const key = {
    run_id: runId,
    agent: alert.agent?.name || "",
    rule_id: alert.rule?.id || "",
    rule_description: alert.rule?.description || "",
    log: normalized.slice(0, 500),
  };
  return crypto.createHash("sha256").update(compactJson(key), "utf8").digest("hex").slice(0, 16);
}

function extractMitre(alert, fallbackTactic, fallbackTechnique) {
  const mitre = alert.rule?.mitre || {};
  let ids = mitre.id || "";
  let tactics = mitre.tactic || "";
  if (Array.isArray(ids)) ids = ids.join("/");
  if (Array.isArray(tactics)) tactics = tactics.join("/");
  return [tactics || fallbackTactic, ids || fallbackTechnique];
}

function inferEventRole(alert, runId, scenarioId, campaignId) {
  const text = `${alert.full_log || ""} ${alert.rule?.description || ""}`.toLowerCase();
  if (runId && text.includes(runId.toLowerCase())) return ["trigger", "high"];
  if (text.includes("safesoc") || text.includes("atomic") || text.includes("caldera")) return ["trigger", "high"];

  const triggerTerms = [
    "powershell",
    "sysmon",
    "scheduled task",
    "cron",
    "systemd",
    "ssh",
    "failed password",
    "invalid user",
    "sudo",
    "pam",
    "tar",
    "zip",
    "archive",
    "audit",
    "execve",
  ];
  if (triggerTerms.some((term) => text.includes(term))) return ["supporting", "medium"];
  if (scenarioId === "S11") return ["supporting", "medium"];
  if (scenarioId === "S12") return ["noise", "medium"];
  if (campaignId) return ["supporting", "medium"];
  return ["unrelated", "low"];
}

function readJsonl(file) {
  return fs
    .readFileSync(file, "utf8")
    .split(/\r?\n/)
    .filter(Boolean)
    .map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function normalizeRunLog() {
  const { header, rows } = parseCsv(fs.readFileSync(runLogFrozen, "utf8"));
  const columns = [...header];
  if (!columns.includes("start_ts_iso")) columns.push("start_ts_iso");
  if (!columns.includes("end_ts_iso")) columns.push("end_ts_iso");
  for (const row of rows) {
    row.start_ts_iso = toUtcIso(row.start_ts);
    row.end_ts_iso = toUtcIso(row.end_ts);
  }
  writeCsv(runLogNormalized, rows, columns);
  console.log(`Wrote normalized run log: ${runLogNormalized}`);
  console.log(`Rows: ${rows.length}`);
  return rows;
}

function buildDraftLabels(runRows) {
  const runMap = Object.fromEntries(runRows.map((row) => [row.run_id, row]));
  const seenDup = new Set();
  const rows = [];
  const uidRows = [];
  let labelCounter = 1;

  const files = fs
    .readdirSync(perRunDir)
    .filter((name) => name.endsWith("_alerts.jsonl"))
    .sort();

  for (const name of files) {
    const file = path.join(perRunDir, name);
    const runId = name.replace("_alerts.jsonl", "");
    const runMeta = runMap[runId] || {};
    const alerts = readJsonl(file);

    for (const alert of alerts) {
      const uid = alertUid(alert);
      const corr = alert._safesoc_correlation || {};
      const scenarioId = corr.scenario_id || runMeta.scenario_id || "";
      const campaignId = corr.campaign_id || runMeta.campaign_id || "";
      const [baseLabel, fallbackTactic, fallbackTechnique] = campaignId
        ? campaignLabels[campaignId] || ["attack_like", "Campaign", "N/A"]
        : scenarioLabels[scenarioId] || ["unrelated_background", "N/A", "N/A"];

      let [role, confidence] = inferEventRole(alert, runId, scenarioId, campaignId);
      const dkey = duplicateKey(alert, runId);
      if (seenDup.has(dkey) && role !== "trigger") {
        role = "duplicate";
        confidence = "medium";
      } else {
        seenDup.add(dkey);
      }

      const [mitreTactic, mitreTechnique] = extractMitre(alert, fallbackTactic, fallbackTechnique);
      const rule = alert.rule || {};
      const label = role === "unrelated" ? "unrelated_background" : baseLabel;
      const summary =
        role === "trigger"
          ? `Primary trigger evidence for ${runId}`
          : role === "supporting"
            ? `Supporting telemetry for ${runId}`
            : role === "duplicate"
              ? `Duplicate repeated telemetry for ${runId}`
              : role === "noise"
                ? `Noisy/false-positive-like telemetry for ${runId}`
                : `Background alert inside ${runId} time window`;

      rows.push({
        label_id: `LBL-${String(labelCounter).padStart(6, "0")}`,
        alert_uid: uid,
        scenario_id: scenarioId,
        campaign_id: campaignId,
        run_id: runId,
        agent_name: alert.agent?.name || "",
        timestamp: alert.timestamp || "",
        label,
        event_role: role,
        simulation_type: runMeta.simulation_type || corr.simulation_type || "",
        execution_mode: runMeta.execution_mode || corr.execution_mode || "",
        tool: runMeta.tool || corr.tool || "",
        atomic_test_id: runMeta.atomic_test_id || "",
        caldera_operation_id: runMeta.caldera_operation_id || "",
        caldera_ability_id: runMeta.caldera_ability_id || "",
        mitre_tactic: mitreTactic,
        mitre_technique_id: mitreTechnique,
        rule_id: rule.id || "",
        rule_description: rule.description || "",
        confidence,
        ground_truth_summary: summary,
        notes: `Draft label from Sprint 8 automated correlation. Source file=${name}; manual review recommended.`,
      });

      uidRows.push({
        alert_uid: uid,
        timestamp: alert.timestamp || "",
        agent_name: alert.agent?.name || "",
        rule_id: rule.id || "",
        rule_description: rule.description || "",
        source_run: runId,
      });
      labelCounter++;
    }
  }

  writeCsv(path.join(base, "ground_truth_labels_draft.csv"), rows, requiredColumns);
  writeCsv(path.join(base, "alert_uid_map.csv"), uidRows, ["alert_uid", "timestamp", "agent_name", "rule_id", "rule_description", "source_run"]);
  console.log(`Wrote draft labels: ${rows.length}`);
  return rows;
}

function sampleBackground(draftRows, target = 205) {
  const existing = new Set(draftRows.map((row) => row.alert_uid));
  const rawAlerts = readJsonl(rawFile);
  const rows = [];
  const ruleAgentCounts = new Map();

  for (const alert of rawAlerts) {
    if (rows.length >= target) break;
    const uid = alertUid(alert);
    if (existing.has(uid)) continue;
    const text = `${alert.full_log || ""} ${alert.rule?.description || ""}`.toLowerCase();
    if (text.includes("run_id=") || text.includes("safesoc_") || text.includes("atomic") || text.includes("caldera")) continue;
    const agent = alert.agent?.name || "";
    const rule = alert.rule || {};
    const key = `${agent}|${rule.id || ""}`;
    const count = ruleAgentCounts.get(key) || 0;
    if (count >= 5) continue;
    ruleAgentCounts.set(key, count + 1);

    rows.push({
      label_id: `LBL-BG-${String(rows.length + 1).padStart(4, "0")}`,
      alert_uid: uid,
      scenario_id: "",
      campaign_id: "",
      run_id: "BACKGROUND-SAMPLE",
      agent_name: agent,
      timestamp: alert.timestamp || "",
      label: "unrelated_background",
      event_role: "unrelated",
      simulation_type: "background",
      execution_mode: "background_sample",
      tool: "wazuh",
      atomic_test_id: "",
      caldera_operation_id: "",
      caldera_ability_id: "",
      mitre_tactic: "N/A",
      mitre_technique_id: "N/A",
      rule_id: rule.id || "",
      rule_description: rule.description || "",
      confidence: "medium",
      ground_truth_summary: "Stratified background alert sampled from raw Wazuh export and not correlated to a scenario run.",
      notes: "Automated background sample for Sprint 8; manual review recommended.",
    });
  }

  writeCsv(path.join(base, "background_unrelated_sample.csv"), rows, requiredColumns);
  console.log(`Wrote background sample: ${rows.length}`);
  return rows;
}

function combineForReview(draftRows, backgroundRows) {
  const rows = [...draftRows, ...backgroundRows].map((row, index) => ({
    ...row,
    label_id: `LBL-${String(index + 1).padStart(6, "0")}`,
  }));
  writeCsv(path.join(base, "ground_truth_labels_reviewed.csv"), rows, requiredColumns);
  writeCsv(path.join(base, "ground_truth_labels.csv"), rows, requiredColumns);
  console.log(`Wrote final labels: ${rows.length}`);
  return rows;
}

function countBy(rows, column) {
  const counts = new Map();
  for (const row of rows) {
    const key = row[column] || "EMPTY";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
}

function writeMatrix(file, rows, columns) {
  writeCsv(file, rows, columns);
}

function mdCounter(title, entries) {
  return [`## ${title}`, "", "| Value | Count |", "|---|---:|", ...entries.map(([k, v]) => `| ${k} | ${v} |`), ""].join("\n");
}

function generateQa(rows) {
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

  const mitreRows = [];
  const mitreMap = new Map();
  for (const row of rows) {
    const key = `${row.scenario_id || row.campaign_id || "background"}|${row.mitre_technique_id || "EMPTY"}`;
    mitreMap.set(key, (mitreMap.get(key) || 0) + 1);
  }
  for (const [key, count] of [...mitreMap.entries()].sort()) {
    const [scenario_or_campaign, mitre_technique_id] = key.split("|");
    mitreRows.push({ scenario_or_campaign, mitre_technique_id, count });
  }
  writeMatrix(path.join(base, "mitre_coverage_matrix.csv"), mitreRows, ["scenario_or_campaign", "mitre_technique_id", "count"]);

  const endpointRows = [];
  const endpointMap = new Map();
  for (const row of rows) {
    const key = `${row.agent_name || "EMPTY"}|${row.label || "EMPTY"}`;
    endpointMap.set(key, (endpointMap.get(key) || 0) + 1);
  }
  for (const [key, count] of [...endpointMap.entries()].sort()) {
    const [agent_name, label] = key.split("|");
    endpointRows.push({ agent_name, label, count });
  }
  writeMatrix(path.join(base, "endpoint_coverage_matrix.csv"), endpointRows, ["agent_name", "label", "count"]);

  const execRows = [];
  const execMap = new Map();
  for (const row of rows) {
    const key = `${row.execution_mode || "EMPTY"}|${row.event_role || "EMPTY"}`;
    execMap.set(key, (execMap.get(key) || 0) + 1);
  }
  for (const [key, count] of [...execMap.entries()].sort()) {
    const [execution_mode, event_role] = key.split("|");
    execRows.push({ execution_mode, event_role, count });
  }
  writeMatrix(path.join(base, "execution_mode_comparison_matrix.csv"), execRows, ["execution_mode", "event_role", "count"]);

  const uidCounts = new Map();
  for (const row of rows) uidCounts.set(row.alert_uid, (uidCounts.get(row.alert_uid) || 0) + 1);
  const duplicateUids = [...uidCounts.values()].filter((count) => count > 1).length;

  const report = [
    "# Sprint 8 Dataset QA Report",
    "",
    "## Summary",
    "",
    "| Metric | Value |",
    "|---|---:|",
    `| Total labeled rows | ${total} |`,
    `| Unique alert UIDs | ${uidCounts.size} |`,
    `| Duplicate alert UIDs | ${duplicateUids} |`,
    "",
    mdCounter("Label Distribution", countBy(rows, "label")),
    mdCounter("Event Role Distribution", countBy(rows, "event_role")),
    mdCounter("Scenario Distribution", countBy(rows, "scenario_id")),
    mdCounter("Campaign Distribution", countBy(rows, "campaign_id")),
    mdCounter("Endpoint Distribution", countBy(rows, "agent_name")),
    mdCounter("Execution Mode Distribution", countBy(rows, "execution_mode")),
    mdCounter("Confidence Distribution", countBy(rows, "confidence")),
    mdCounter("MITRE Technique Distribution", countBy(rows, "mitre_technique_id")),
    "## QA Checks",
    "",
    "- Required schema fields were checked for completeness.",
    "- MITRE mappings were summarized by scenario and campaign.",
    "- Endpoint balance was summarized by agent.",
    "- Execution modes were summarized by event role.",
    "- Duplicate alert UIDs were counted.",
    "- Manual review is recommended for medium-confidence and unrelated_background rows.",
    "",
    "## Limitations",
    "",
    "- Campaign-level windows may overlap with scenario-level windows.",
    "- Some labels are derived from timestamp correlation and require conservative confidence scoring.",
    "- Background samples are used to support unrelated/noise classification.",
    "- Sprint 9 will group these labels into investigation cases and alert-fatigue metrics.",
    "",
  ].join("\n");
  fs.writeFileSync(path.join(base, "dataset_qa_report.md"), report, "utf8");
  console.log("Wrote QA report and matrices");
}

function validateSchema(rows) {
  const allowedLabels = new Set(["benign", "noise", "ambiguous_noise", "attack_like", "attack_like_failed", "simulated_only", "unrelated_background"]);
  const allowedRoles = new Set(["trigger", "supporting", "duplicate", "noise", "unrelated"]);
  const allowedConfidence = new Set(["high", "medium", "low"]);
  const errors = [];

  rows.forEach((row, index) => {
    if (!allowedLabels.has(row.label)) errors.push(`Line ${index + 2}: invalid label ${row.label}`);
    if (!allowedRoles.has(row.event_role)) errors.push(`Line ${index + 2}: invalid event_role ${row.event_role}`);
    if (!allowedConfidence.has(row.confidence)) errors.push(`Line ${index + 2}: invalid confidence ${row.confidence}`);
    for (const field of ["label_id", "alert_uid", "run_id", "agent_name", "timestamp", "label", "event_role", "rule_id", "rule_description", "confidence"]) {
      if (!String(row[field] || "").trim()) errors.push(`Line ${index + 2}: empty required operational field ${field}`);
    }
  });

  const resultFile = path.join(base, "schema_validation_result.txt");
  if (errors.length) {
    fs.writeFileSync(resultFile, `SCHEMA VALIDATION FAILED\nTotal errors: ${errors.length}\n${errors.slice(0, 200).join("\n")}\n`, "utf8");
    throw new Error(`Schema validation failed with ${errors.length} errors. See ${resultFile}`);
  }
  fs.writeFileSync(resultFile, `SCHEMA VALIDATION PASSED\nRows validated: ${rows.length}\n`, "utf8");
  console.log("SCHEMA VALIDATION PASSED");
  console.log(`Rows validated: ${rows.length}`);
}

function main() {
  ensureDir(base);
  const runRows = normalizeRunLog();
  const draftRows = buildDraftLabels(runRows);
  const backgroundRows = sampleBackground(draftRows, 205);
  const finalRows = combineForReview(draftRows, backgroundRows);
  generateQa(finalRows);
  validateSchema(finalRows);
}

main();
