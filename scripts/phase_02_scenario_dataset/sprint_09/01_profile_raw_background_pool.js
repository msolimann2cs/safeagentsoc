const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const BASE = "06_data/phase_02_scenario_dataset/sprint_09_casebook";
const RAW = path.join(BASE, "raw_alerts_full.jsonl");
const LABELS = path.join(BASE, "ground_truth_labels.csv");

const RAW_PROFILE = path.join(BASE, "raw_pool_rule_profile.csv");
const RAW_SUMMARY = path.join(BASE, "raw_background_pool_summary.md");

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
  return [headers.join(","), ...rows.map((r) => headers.map((h) => esc(r[h])).join(","))].join("\n");
}

function stableStringify(value) {
  return JSON.stringify(value, Object.keys(value).sort());
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

  const hash = crypto
    .createHash("sha256")
    .update(stableStringify(parts))
    .digest("hex")
    .slice(0, 16)
    .toUpperCase();

  return `ALERT-${hash}`;
}

const labelRows = parseCsv(fs.readFileSync(LABELS, "utf8"));
const labeledUids = new Set(labelRows.map((r) => r.alert_uid).filter(Boolean));

let rawCount = 0;
let labeledOverlap = 0;
let unlabeledCount = 0;

const profile = new Map();
const agentCounts = {};
const ruleCounts = {};

const lines = fs.readFileSync(RAW, "utf8").split(/\r?\n/).filter(Boolean);

for (const line of lines) {
  let alert;
  try {
    alert = JSON.parse(line);
  } catch {
    continue;
  }

  rawCount++;
  const uid = alertUid(alert);
  const isLabeled = labeledUids.has(uid);

  if (isLabeled) {
    labeledOverlap++;
  } else {
    unlabeledCount++;
  }

  const agent = alert.agent?.name || "unknown";
  const ruleId = String(alert.rule?.id || "no_rule");
  const ruleDesc = alert.rule?.description || "";
  const level = alert.rule?.level || "";
  const key = `${agent}__${ruleId}__${ruleDesc}`;

  if (!profile.has(key)) {
    profile.set(key, {
      agent_name: agent,
      rule_id: ruleId,
      rule_description: ruleDesc,
      rule_level: level,
      raw_count: 0,
      unlabeled_count: 0,
      labeled_overlap_count: 0,
    });
  }

  const p = profile.get(key);
  p.raw_count++;
  if (isLabeled) p.labeled_overlap_count++;
  else p.unlabeled_count++;

  agentCounts[agent] = (agentCounts[agent] || 0) + 1;
  ruleCounts[ruleId] = (ruleCounts[ruleId] || 0) + 1;
}

const rows = [...profile.values()].sort((a, b) => b.raw_count - a.raw_count);
fs.writeFileSync(
  RAW_PROFILE,
  toCsv(rows, [
    "agent_name",
    "rule_id",
    "rule_description",
    "rule_level",
    "raw_count",
    "unlabeled_count",
    "labeled_overlap_count",
  ]),
);

function mdCounter(obj) {
  return Object.entries(obj)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 20)
    .map(([k, v]) => `| ${k} | ${v} |`)
    .join("\n");
}

const summary = `# Raw Background Pool Summary

## Summary

| Metric | Value |
|---|---:|
| Full raw alerts | ${rawCount} |
| Gold-label rows | ${labelRows.length} |
| Unique gold-label alert UIDs | ${labeledUids.size} |
| Labeled unique UID overlap in raw export | ${labeledOverlap} |
| Estimated unlabeled raw pool | ${unlabeledCount} |
| Unique agent/rule families | ${rows.length} |

## Top Agents

| Agent | Count |
|---|---:|
${mdCounter(agentCounts)}

## Top Rule IDs

| Rule ID | Count |
|---|---:|
${mdCounter(ruleCounts)}

## Interpretation

The remaining raw alert pool is retained as unlabeled background telemetry. It is not discarded. It supports alert-fatigue analysis, background-noise profiling, and future labeling expansion. Sprint 9 uses this pool to document non-gold telemetry instead of pretending all raw alerts have verified ground-truth labels.
`;

fs.writeFileSync(RAW_SUMMARY, summary);

console.log(`Raw alerts: ${rawCount}`);
console.log(`Gold-label rows: ${labelRows.length}`);
console.log(`Unique gold-label alert UIDs: ${labeledUids.size}`);
console.log(`Labeled UID overlap: ${labeledOverlap}`);
console.log(`Estimated unlabeled raw pool: ${unlabeledCount}`);
console.log(`Wrote ${RAW_PROFILE}`);
console.log(`Wrote ${RAW_SUMMARY}`);
