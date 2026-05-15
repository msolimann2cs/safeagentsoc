const fs = require("fs");
const path = require("path");

const BASE = "06_data/phase_02_scenario_dataset/sprint_09_casebook";
const LABELS = path.join(BASE, "ground_truth_labels.csv");

const CASEBOOK = path.join(BASE, "casebook.csv");
const CASEBOOK_JSONL = path.join(BASE, "casebook_detailed.jsonl");
const FATIGUE = path.join(BASE, "alert_fatigue_baseline.csv");
const CASE_QA = path.join(BASE, "casebook_qa_summary.md");
const CASE_LEVEL = path.join(BASE, "case_level_summary_dataset.csv");

function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    const next = text[i + 1];

    if (c === '"' && inQuotes && next === '"') {
      field += '"';
      i++;
    } else if (c === '"') {
      inQuotes = !inQuotes;
    } else if (c === "," && !inQuotes) {
      row.push(field);
      field = "";
    } else if ((c === "\n" || c === "\r") && !inQuotes) {
      if (c === "\r" && next === "\n") i++;
      row.push(field);
      field = "";
      if (row.some((v) => v !== "")) rows.push(row);
      row = [];
    } else {
      field += c;
    }
  }

  if (field.length || row.length) {
    row.push(field);
    rows.push(row);
  }

  const headers = rows.shift();
  return rows.map((r) => {
    const obj = {};
    headers.forEach((h, i) => {
      obj[h] = r[i] || "";
    });
    return obj;
  });
}

function toCsv(rows, headers) {
  function esc(v) {
    v = v === undefined || v === null ? "" : String(v);
    if (v.includes('"') || v.includes(",") || v.includes("\n") || v.includes("\r")) {
      return `"${v.replace(/"/g, '""')}"`;
    }
    return v;
  }

  return [
    headers.join(","),
    ...rows.map((row) => headers.map((h) => esc(row[h])).join(",")),
  ].join("\n");
}

function unique(values) {
  return [...new Set(values.filter((v) => v && v !== "EMPTY"))];
}

function counter(rows, field) {
  const c = {};
  for (const r of rows) {
    const v = r[field] || "EMPTY";
    c[v] = (c[v] || 0) + 1;
  }
  return c;
}

function minTimestamp(rows) {
  return rows.map((r) => r.timestamp).filter(Boolean).sort()[0] || "";
}

function maxTimestamp(rows) {
  const vals = rows.map((r) => r.timestamp).filter(Boolean).sort();
  return vals[vals.length - 1] || "";
}

function topValue(rows, field) {
  const c = counter(rows, field);
  return Object.entries(c).sort((a, b) => b[1] - a[1])[0]?.[0] || "";
}

function summarizeCase(caseType, key, rows) {
  const rawCount = rows.length;
  const rules = unique(rows.map((r) => r.rule_id));
  const mitres = unique(rows.map((r) => r.mitre_technique_id).filter((v) => v !== "N/A"));
  const agents = unique(rows.map((r) => r.agent_name));
  const modes = unique(rows.map((r) => r.execution_mode));
  const tools = unique(rows.map((r) => r.tool));
  const labels = counter(rows, "label");
  const roles = counter(rows, "event_role");

  const trigger = roles.trigger || 0;
  const supporting = roles.supporting || 0;
  const duplicate = roles.duplicate || 0;
  const noiseRows = rows.filter(
    (r) =>
      r.event_role === "noise" ||
      r.event_role === "unrelated" ||
      r.label === "unrelated_background" ||
      r.label === "noise" ||
      r.label === "ambiguous_noise",
  );
  const suppressionRows = rows.filter(
    (r) =>
      r.event_role === "duplicate" ||
      r.event_role === "noise" ||
      r.event_role === "unrelated" ||
      r.label === "unrelated_background" ||
      r.label === "noise" ||
      r.label === "ambiguous_noise",
  );
  const noise = noiseRows.length;

  const meaningful = trigger + supporting;
  const suppressionCandidates = suppressionRows.length;
  const duplicateRatio = rawCount ? duplicate / rawCount : 0;
  const compressionPotential = rawCount ? suppressionCandidates / rawCount : 0;

  const scenarioIds = unique(rows.map((r) => r.scenario_id));
  const campaignIds = unique(rows.map((r) => r.campaign_id));
  const runIds = unique(rows.map((r) => r.run_id));

  const dominantLabel = topValue(rows, "label");
  const dominantRole = topValue(rows, "event_role");

  let summary = "";
  let conclusion = "";

  if (caseType === "run_case") {
    summary = `Run-level investigation case for ${key}, containing ${rawCount} correlated labeled alerts across ${rules.length} Wazuh rule IDs.`;
  } else if (caseType === "campaign_case") {
    summary = `Campaign-level investigation case for ${key}, aggregating related campaign telemetry across ${runIds.length} run references.`;
  } else if (caseType === "scenario_case") {
    summary = `Scenario-level case for ${key}, aggregating all labeled telemetry for this scenario.`;
  } else if (caseType === "technique_case") {
    summary = `Technique-focused case for ${key}, grouping alerts by run and MITRE technique.`;
  } else {
    summary = `Background/noise case for ${key}, used to benchmark unrelated or low-value telemetry.`;
  }

  if (dominantLabel === "attack_like") {
    conclusion = "Analyst should conclude controlled attack-like activity occurred. Prioritize trigger alerts, then use supporting alerts for context. Duplicate and unrelated alerts are candidates for compression.";
  } else if (dominantLabel === "benign") {
    conclusion = "Analyst should conclude expected benign administrative activity occurred. Alerts can be used to test false-positive suppression and benign context recognition.";
  } else if (dominantLabel === "ambiguous_noise" || dominantLabel === "noise") {
    conclusion = "Analyst should treat this as noisy or false-positive-like activity unless additional evidence changes the context.";
  } else if (dominantLabel === "unrelated_background") {
    conclusion = "Analyst should classify this case as background telemetry not directly tied to the emulated scenario.";
  } else {
    conclusion = "Analyst should review trigger and supporting alerts before escalation.";
  }

  return {
    case_type: caseType,
    source_key: key,
    run_id: runIds.join(";"),
    campaign_id: campaignIds.join(";"),
    scenario_id: scenarioIds.join(";"),
    agent_name: agents.join(";"),
    start_ts: minTimestamp(rows),
    end_ts: maxTimestamp(rows),
    raw_alert_count: rawCount,
    unique_rule_count: rules.length,
    trigger_alert_count: trigger,
    supporting_alert_count: supporting,
    duplicate_alert_count: duplicate,
    noise_alert_count: noise,
    duplicate_ratio: duplicateRatio.toFixed(4),
    meaningful_alert_count: meaningful,
    suppression_candidate_count: suppressionCandidates,
    compression_potential: compressionPotential.toFixed(4),
    mitre_techniques: mitres.join(";") || "N/A",
    execution_mode: modes.join(";"),
    tool: tools.join(";"),
    dominant_label: dominantLabel,
    dominant_event_role: dominantRole,
    case_summary: summary,
    analyst_expected_conclusion: conclusion,
    rule_ids: rules.join(";"),
  };
}

function groupBy(rows, keyFn) {
  const g = new Map();
  for (const row of rows) {
    const key = keyFn(row);
    if (!key) continue;
    if (!g.has(key)) g.set(key, []);
    g.get(key).push(row);
  }
  return g;
}

const labels = parseCsv(fs.readFileSync(LABELS, "utf8"));

let cases = [];

const byRun = groupBy(labels, (r) => (r.run_id && r.run_id !== "BACKGROUND-SAMPLE" ? r.run_id : ""));
for (const [runId, rows] of byRun.entries()) {
  cases.push(summarizeCase("run_case", runId, rows));
}

const byCampaign = groupBy(labels, (r) => r.campaign_id);
for (const [campaignId, rows] of byCampaign.entries()) {
  cases.push(summarizeCase("campaign_case", campaignId, rows));
}

const byScenario = groupBy(labels, (r) => r.scenario_id);
for (const [scenarioId, rows] of byScenario.entries()) {
  cases.push(summarizeCase("scenario_case", scenarioId, rows));
}

const bgRows = labels.filter((r) => r.run_id === "BACKGROUND-SAMPLE" || r.label === "unrelated_background");
const byBackgroundRule = groupBy(bgRows, (r) => `${r.agent_name || "unknown"}__${r.rule_id || "no_rule"}`);
const bgCases = [...byBackgroundRule.entries()]
  .map(([key, rows]) => summarizeCase("background_noise_case", key, rows))
  .sort((a, b) => b.raw_alert_count - a.raw_alert_count);

for (const c of bgCases.slice(0, 5)) {
  cases.push(c);
}

const attackRows = labels.filter(
  (r) =>
    r.label === "attack_like" &&
    r.mitre_technique_id &&
    r.mitre_technique_id !== "N/A" &&
    r.run_id &&
    r.run_id !== "BACKGROUND-SAMPLE",
);

const byRunTechnique = groupBy(attackRows, (r) => `${r.run_id}__${r.mitre_technique_id}`);
const techniqueCases = [...byRunTechnique.entries()]
  .map(([key, rows]) => summarizeCase("technique_case", key, rows))
  .filter((c) => c.raw_alert_count >= 3)
  .sort((a, b) => b.raw_alert_count - a.raw_alert_count);

for (const c of techniqueCases) {
  if (cases.length >= 50) break;
  cases.push(c);
}

for (const c of bgCases) {
  if (cases.length >= 50) break;
  const exists = cases.some((x) => x.case_type === c.case_type && x.source_key === c.source_key);
  if (exists) continue;
  cases.push(c);
}

if (cases.length < 45) {
  const moreTechniqueCases = [...byRunTechnique.entries()]
    .map(([key, rows]) => summarizeCase("technique_case", key, rows))
    .filter((c) => c.raw_alert_count >= 1)
    .sort((a, b) => b.raw_alert_count - a.raw_alert_count);

  for (const c of moreTechniqueCases) {
    if (cases.length >= 50) break;
    const exists = cases.some((x) => x.case_type === c.case_type && x.source_key === c.source_key);
    if (!exists) cases.push(c);
  }
}

cases = cases.slice(0, 55).map((c, idx) => ({
  case_id: `CASE-${String(idx + 1).padStart(3, "0")}`,
  ...c,
}));

const caseHeaders = [
  "case_id",
  "run_id",
  "campaign_id",
  "case_type",
  "agent_name",
  "start_ts",
  "end_ts",
  "raw_alert_count",
  "unique_rule_count",
  "trigger_alert_count",
  "supporting_alert_count",
  "duplicate_alert_count",
  "noise_alert_count",
  "duplicate_ratio",
  "mitre_techniques",
  "execution_mode",
  "tool",
  "case_summary",
  "analyst_expected_conclusion",
  "meaningful_alert_count",
  "suppression_candidate_count",
  "compression_potential",
  "dominant_label",
  "dominant_event_role",
  "scenario_id",
  "rule_ids",
];

fs.writeFileSync(CASEBOOK, toCsv(cases, caseHeaders));
fs.writeFileSync(CASE_LEVEL, toCsv(cases, caseHeaders));
fs.writeFileSync(CASEBOOK_JSONL, cases.map((c) => JSON.stringify(c)).join("\n"));

const fatigueHeaders = [
  "case_id",
  "case_type",
  "run_id",
  "campaign_id",
  "raw_alert_count",
  "meaningful_alert_count",
  "suppression_candidate_count",
  "duplicate_alert_count",
  "noise_alert_count",
  "duplicate_ratio",
  "compression_potential",
  "unique_rule_count",
  "dominant_label",
  "analyst_expected_conclusion",
];

fs.writeFileSync(FATIGUE, toCsv(cases, fatigueHeaders));

const totalRaw = cases.reduce((s, c) => s + Number(c.raw_alert_count), 0);
const totalMeaningful = cases.reduce((s, c) => s + Number(c.meaningful_alert_count), 0);
const totalSuppression = cases.reduce((s, c) => s + Number(c.suppression_candidate_count), 0);
const avgDupRatio = cases.length ? cases.reduce((s, c) => s + Number(c.duplicate_ratio), 0) / cases.length : 0;
const avgCompression = cases.length ? cases.reduce((s, c) => s + Number(c.compression_potential), 0) / cases.length : 0;

const caseTypeCounts = {};
for (const c of cases) {
  caseTypeCounts[c.case_type] = (caseTypeCounts[c.case_type] || 0) + 1;
}

const caseTypeRows = Object.entries(caseTypeCounts)
  .map(([k, v]) => `| ${k} | ${v} |`)
  .join("\n");

const qa = `# Sprint 9 Casebook QA Summary

## Summary

| Metric | Value |
|---|---:|
| Investigation cases generated | ${cases.length} |
| Total case alert references | ${totalRaw} |
| Meaningful alert references | ${totalMeaningful} |
| Suppression candidate references | ${totalSuppression} |
| Average duplicate ratio | ${avgDupRatio.toFixed(4)} |
| Average compression potential | ${avgCompression.toFixed(4)} |

## Case Type Distribution

| Case Type | Count |
|---|---:|
${caseTypeRows}

## QA Status

${cases.length >= 45 && cases.length <= 55 ? "PASS: Case count is within the 45 to 55 target." : "WARN: Case count is outside the 45 to 55 target."}

## Notes

- Case-level totals are benchmark references and may include overlapping campaign/run views.
- Compression potential is estimated as suppression_candidate_count / raw_alert_count.
- Suppression candidates include duplicate and noise/unrelated alerts.
- Sprint 10 should report these metrics as baseline alert-fatigue measurements.
`;

fs.writeFileSync(CASE_QA, qa);

console.log(`Wrote ${CASEBOOK}`);
console.log(`Wrote ${FATIGUE}`);
console.log(`Wrote ${CASE_LEVEL}`);
console.log(`Wrote ${CASE_QA}`);
console.log(`Cases generated: ${cases.length}`);
console.log(cases.length >= 45 && cases.length <= 55 ? "CASE COUNT PASS" : "CASE COUNT WARNING");
