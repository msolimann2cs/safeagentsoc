const fs = require("fs");
const path = require("path");

const root = process.cwd();
const exportRoot = path.join(root, "06_data", "phase_02_scenario_dataset", "sprint_07_raw_exports");
const evidenceRoot = path.resolve(root, "..", "..", "07_evidence", "phase_02_scenario_dataset", "screenshots", "Phase2");
const rawAlertsFile = path.join(exportRoot, "full", "raw_alerts_full.jsonl");

const requiredColumns = [
  "run_id",
  "scenario_id",
  "campaign_id",
  "scenario_name",
  "scenario_type",
  "simulation_type",
  "execution_mode",
  "tool",
  "atomic_test_id",
  "caldera_operation_id",
  "caldera_adversary_profile",
  "caldera_ability_id",
  "host",
  "operator",
  "start_ts",
  "end_ts",
  "commands_file",
  "evidence_ids",
  "wazuh_query",
  "expected_signal",
  "cleanup_status",
  "notes",
];

const scenarioNames = {
  S01: "PowerShell execution",
  S02: "Windows discovery sequence",
  S03: "Scheduled task marker",
  S04: "Archive staging behavior",
  S05: "Windows admin maintenance",
  S06: "Windows repeated benign process noise",
  S07: "Linux SSH failed login pattern",
  S08: "Linux sudo authentication pattern",
  S09: "Linux discovery sequence",
  S10: "Linux cron marker",
  S11: "Linux admin maintenance",
  S12: "Authentication typo noise",
};

const scenarioTypes = {
  S01: "attack_like",
  S02: "attack_like",
  S03: "attack_like",
  S04: "attack_like",
  S05: "benign",
  S06: "noise",
  S07: "attack_like",
  S08: "attack_like",
  S09: "attack_like",
  S10: "attack_like",
  S11: "benign",
  S12: "ambiguous_noise",
};

const expectedSignals = {
  S01: "PowerShell/Sysmon telemetry",
  S02: "Windows discovery telemetry",
  S03: "Scheduled task telemetry",
  S04: "Archive/file staging telemetry",
  S05: "Windows benign admin telemetry",
  S06: "Repeated benign Windows process noise",
  S07: "Linux SSH/auth telemetry",
  S08: "Linux sudo/PAM telemetry",
  S09: "Linux discovery telemetry",
  S10: "Linux cron telemetry",
  S11: "Linux benign admin telemetry",
  S12: "Authentication typo/noise telemetry",
};

const atomicIds = {
  S01: "T1059.001",
  S02: "T1082/T1033/T1016",
  S03: "T1053.005",
  S04: "T1560.001",
  S07: "T1110.001",
  S08: "T1548.003",
  S09: "T1082/T1033/T1016",
  S10: "T1053.003",
};

function ensureDir(dir) {
  fs.mkdirSync(dir, { recursive: true });
}

function walkFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  const out = [];
  for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, item.name);
    if (item.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
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
  const lines = text.replace(/\r\n/g, "\n").replace(/\r/g, "\n").split("\n").filter(Boolean);
  if (lines.length === 0) return { header: [], rows: [] };
  const header = parseCsvLine(lines[0]);
  const rows = lines.slice(1).map((line) => {
    const values = parseCsvLine(line);
    const row = {};
    for (let i = 0; i < header.length; i++) row[header[i]] = values[i] ?? "";
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

function normalizeRawTimestamp(value) {
  if (!value) return "";
  return String(value).trim().replace(/([+-]\d{2})(\d{2})$/, "$1:$2");
}

function parseTimestamp(value) {
  if (!value) return null;
  let text = String(value).trim().replace(/^"|"$/g, "");
  if (!text) return null;
  if (text.includes("@")) {
    text = text.replace("@", "").replace(/\s+/g, " ").trim();
    const parsed = new Date(`${text} GMT-0400`);
    return Number.isNaN(parsed.getTime()) ? null : parsed;
  }
  text = normalizeRawTimestamp(text);
  const parsed = new Date(text);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
}

function formatOffsetIso(date) {
  const pad = (n, width = 2) => String(n).padStart(width, "0");
  const shifted = new Date(date.getTime() - 4 * 60 * 60 * 1000);
  return `${shifted.getUTCFullYear()}-${pad(shifted.getUTCMonth() + 1)}-${pad(shifted.getUTCDate())}T${pad(shifted.getUTCHours())}:${pad(shifted.getUTCMinutes())}:${pad(shifted.getUTCSeconds())}.${pad(shifted.getUTCMilliseconds(), 3)}-04:00`;
}

function deriveRunId(file) {
  const normalized = file.replace(/\\/g, "/");
  const standard = normalized.match(/(?:^|\/)((?:S\d{2})[-_](?:MAN|ART)[-_]R\d{3})(?:\/|_|-|$)/i);
  if (standard) return standard[1].toUpperCase().replace(/_/g, "-");
  const campaign = normalized.match(/(?:^|\/)(C-(?:WIN|LNX)-\d{2}-CAL-R\d{3})(?:\/|_|-|$)/i);
  if (campaign) return campaign[1].toUpperCase();
  const lnxOp = normalized.match(/CAL_LNX_OP(\d+)/i);
  if (lnxOp) return `C-LNX-01-CAL-R${String(Number(lnxOp[1])).padStart(3, "0")}`;
  const winOp = normalized.match(/CAL_WIN_OP(\d+)/i);
  if (winOp) return `C-WIN-01-CAL-R${String(Number(winOp[1])).padStart(3, "0")}`;
  return "";
}

function inferHost(runId, observedHost) {
  if (observedHost) return observedHost;
  if (runId.startsWith("C-WIN") || /^S0[1-6]-/.test(runId)) return "safesoc-win-01";
  if (runId.startsWith("C-LNX") || /^S(0[7-9]|10|11)-/.test(runId)) return "safesoc-lnx-01";
  if (runId.startsWith("S12")) return "";
  return "";
}

function runInfo(runId, host) {
  const scenario = (runId.match(/^S\d{2}/) || [""])[0];
  const campaign = (runId.match(/^C-(?:WIN|LNX)-\d{2}/) || [""])[0];
  const isAtomic = runId.includes("-ART-");
  const isCaldera = runId.includes("-CAL-");
  const isManual = runId.includes("-MAN-");
  const executionMode = isAtomic ? "atomic_red_team" : isCaldera ? "caldera" : isManual ? "manual" : "";
  const tool = isAtomic ? "Atomic Red Team" : isCaldera ? "MITRE Caldera" : scenario.startsWith("S") ? "manual" : "";
  let simulationType = "";
  if (isCaldera) simulationType = "caldera_campaign";
  else if (isAtomic) simulationType = "atomic_validation";
  else if (["S05", "S11"].includes(scenario)) simulationType = "benign_baseline";
  else if (["S06", "S12"].includes(scenario)) simulationType = "benign_noise";
  else if (isManual) simulationType = "manual_adversary_emulation";
  const scenarioName = campaign
    ? campaign === "C-WIN-01"
      ? "Windows foothold-to-staging campaign"
      : "Linux access-to-persistence campaign"
    : scenarioNames[scenario] || "";
  const scenarioType = campaign ? "campaign" : scenarioTypes[scenario] || "";
  const commandsFile = scenario ? `${scenario}_commands.txt` : "";
  const query = host ? `agent.name:"${host}"` : "";
  return {
    scenario,
    campaign,
    scenarioName,
    scenarioType,
    simulationType,
    executionMode,
    tool,
    atomicTestId: isAtomic ? atomicIds[scenario] || "" : "",
    commandsFile,
    wazuhQuery: query,
    expectedSignal: campaign
      ? campaign === "C-WIN-01"
        ? "Windows Caldera campaign telemetry"
        : "Linux Caldera campaign telemetry"
      : expectedSignals[scenario] || "",
  };
}

function buildEvidenceInventory() {
  const files = walkFiles(evidenceRoot);
  const rows = files.map((file) => {
    const stat = fs.statSync(file);
    return {
      relative_path: path.relative(root, file),
      extension: path.extname(file).toLowerCase() || "(none)",
      bytes: stat.size,
      modified: stat.mtime.toISOString(),
    };
  });
  writeCsv(path.join(exportRoot, "evidence_inventory.csv"), rows, ["relative_path", "extension", "bytes", "modified"]);
  return rows;
}

function buildFrozenRunLog() {
  const csvFiles = walkFiles(evidenceRoot).filter((file) => path.extname(file).toLowerCase() === ".csv");
  const runs = new Map();

  for (const file of csvFiles) {
    const runId = deriveRunId(file);
    if (!runId) continue;
    const text = fs.readFileSync(file, "utf8");
    const { header, rows } = parseCsv(text);
    if (header.length === 0) continue;

    let timestampColumn = "";
    if (header.includes("timestamp")) timestampColumn = "timestamp";
    else if (header.includes("Time Ran")) timestampColumn = "Time Ran";
    if (!timestampColumn) continue;

    let min = null;
    let max = null;
    let host = "";
    let eventRows = 0;
    for (const row of rows) {
      const ts = parseTimestamp(row[timestampColumn]);
      if (!ts) continue;
      min = min && min < ts ? min : ts;
      max = max && max > ts ? max : ts;
      host = host || row["agent.name"] || row.Host || "";
      eventRows++;
    }
    if (!min || !max) continue;

    const evidenceId = path.basename(file, ".csv");
    if (!runs.has(runId)) {
      runs.set(runId, {
        runId,
        start: min,
        end: max,
        host,
        evidenceIds: new Set(),
        sourceFiles: new Set(),
        eventRows: 0,
      });
    }
    const existing = runs.get(runId);
    existing.start = existing.start < min ? existing.start : min;
    existing.end = existing.end > max ? existing.end : max;
    existing.host = existing.host || host;
    existing.evidenceIds.add(evidenceId);
    existing.sourceFiles.add(path.relative(root, file));
    existing.eventRows += eventRows;
  }

  const rows = [...runs.values()]
    .sort((a, b) => a.start - b.start || a.runId.localeCompare(b.runId))
    .map((run) => {
      const start = new Date(run.start.getTime() - 2 * 60 * 1000);
      const end = new Date(run.end.getTime() + 2 * 60 * 1000);
      const host = inferHost(run.runId, run.host);
      const info = runInfo(run.runId, host);
      return {
        run_id: run.runId,
        scenario_id: info.scenario,
        campaign_id: info.campaign,
        scenario_name: info.scenarioName,
        scenario_type: info.scenarioType,
        simulation_type: info.simulationType,
        execution_mode: info.executionMode,
        tool: info.tool,
        atomic_test_id: info.atomicTestId,
        caldera_operation_id: info.campaign ? "TBD_FROM_CALDERA_UI" : "",
        caldera_adversary_profile: info.campaign ? "TBD_FROM_CALDERA_UI" : "",
        caldera_ability_id: "",
        host,
        operator: "msolimann",
        start_ts: formatOffsetIso(start),
        end_ts: formatOffsetIso(end),
        commands_file: info.commandsFile,
        evidence_ids: [...run.evidenceIds].sort().join(";"),
        wazuh_query: info.wazuhQuery,
        expected_signal: info.expectedSignal,
        cleanup_status: "not_required_or_documented",
        notes: `Derived during Sprint 7 from ${run.eventRows} evidence CSV event rows with a 2-minute correlation buffer.`,
      };
    });

  writeCsv(path.join(exportRoot, "scenario_run_log_frozen.csv"), rows, requiredColumns);
  return rows;
}

function readRawAlerts() {
  const lines = fs.readFileSync(rawAlertsFile, "utf8").split(/\r?\n/).filter(Boolean);
  return lines
    .map((line) => {
      try {
        return { line, alert: JSON.parse(line), ts: parseTimestamp(JSON.parse(line).timestamp) };
      } catch {
        return null;
      }
    })
    .filter(Boolean);
}

function splitByAgent(rawAlerts) {
  const outDir = path.join(exportRoot, "per_agent");
  ensureDir(outDir);
  const known = new Set(["safesoc-win-01", "safesoc-lnx-01", "safesoc-wazuh-01"]);
  const buckets = new Map([
    ["safesoc-win-01", []],
    ["safesoc-lnx-01", []],
    ["safesoc-wazuh-01", []],
    ["unknown", []],
  ]);

  for (const item of rawAlerts) {
    const agent = item.alert.agent?.name || "unknown";
    const key = known.has(agent) ? agent : "unknown";
    buckets.get(key).push(item.line);
  }

  const rows = [];
  for (const [agent, lines] of buckets) {
    const file = path.join(outDir, `${agent}_alerts.jsonl`);
    fs.writeFileSync(file, lines.join("\n") + (lines.length ? "\n" : ""), "utf8");
    rows.push({ agent, alert_count: lines.length, file: path.relative(root, file) });
    console.log(agent, lines.length, path.relative(root, file));
  }
  writeCsv(path.join(outDir, "per_agent_export_summary.csv"), rows, ["agent", "alert_count", "file"]);
  return rows;
}

function extractRunMarkers(rawAlerts) {
  const rows = [];
  const re = /RUN_ID=([A-Za-z0-9_.-]+)/;
  for (const item of rawAlerts) {
    const fullLog = item.alert.full_log || "";
    const match = fullLog.match(re);
    if (match) {
      rows.push({
        timestamp: item.alert.timestamp || "",
        agent_name: item.alert.agent?.name || "",
        run_id: match[1],
        rule_id: item.alert.rule?.id || "",
        rule_level: item.alert.rule?.level || "",
        rule_description: item.alert.rule?.description || "",
        full_log: fullLog.replace(/\s+/g, " ").slice(0, 500),
      });
    }
  }
  writeCsv(path.join(exportRoot, "run_markers_found.csv"), rows, [
    "timestamp",
    "agent_name",
    "run_id",
    "rule_id",
    "rule_level",
    "rule_description",
    "full_log",
  ]);
  console.log(`Found ${rows.length} run-marker alerts`);
  return rows;
}

function exportPerRun(rawAlerts, runRows) {
  const outDir = path.join(exportRoot, "per_run");
  ensureDir(outDir);
  const summary = [];
  for (const run of runRows) {
    const start = parseTimestamp(run.start_ts);
    const end = parseTimestamp(run.end_ts);
    if (!start || !end) continue;
    const rows = [];
    for (const item of rawAlerts) {
      const agent = item.alert.agent?.name || "";
      if (item.ts && item.ts >= start && item.ts <= end && (!run.host || run.host === agent)) {
        const alert = { ...item.alert };
        alert._safesoc_correlation = {
          run_id: run.run_id,
          scenario_id: run.scenario_id,
          campaign_id: run.campaign_id,
          simulation_type: run.simulation_type,
          execution_mode: run.execution_mode,
          tool: run.tool,
          host: run.host,
          start_ts: run.start_ts,
          end_ts: run.end_ts,
        };
        rows.push(JSON.stringify(alert));
      }
    }
    const file = path.join(outDir, `${run.run_id}_alerts.jsonl`);
    fs.writeFileSync(file, rows.join("\n") + (rows.length ? "\n" : ""), "utf8");
    summary.push({ run_id: run.run_id, alert_count: rows.length, file: path.relative(root, file) });
  }
  writeCsv(path.join(outDir, "per_run_export_summary.csv"), summary, ["run_id", "alert_count", "file"]);
  for (const row of summary) console.log(row.run_id, row.alert_count, row.file);
  return summary;
}

function exportPerCampaign() {
  const perRunDir = path.join(exportRoot, "per_run");
  const outDir = path.join(exportRoot, "per_campaign");
  ensureDir(outDir);
  const groups = new Map();
  for (const file of walkFiles(perRunDir).filter((f) => f.endsWith("_alerts.jsonl"))) {
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean);
    for (const line of lines) {
      try {
        const alert = JSON.parse(line);
        const campaign = alert._safesoc_correlation?.campaign_id || "";
        if (!campaign) continue;
        if (!groups.has(campaign)) groups.set(campaign, []);
        groups.get(campaign).push(JSON.stringify(alert));
      } catch {
        // Skip malformed JSONL rows.
      }
    }
  }
  const summary = [];
  for (const [campaign, lines] of groups) {
    const file = path.join(outDir, `${campaign}_alerts.jsonl`);
    fs.writeFileSync(file, lines.join("\n") + (lines.length ? "\n" : ""), "utf8");
    summary.push({ campaign_id: campaign, alert_count: lines.length, file: path.relative(root, file) });
  }
  writeCsv(path.join(outDir, "per_campaign_export_summary.csv"), summary, ["campaign_id", "alert_count", "file"]);
  for (const row of summary) console.log(row.campaign_id, row.alert_count, row.file);
  return summary;
}

function exportPerScenario() {
  const perRunDir = path.join(exportRoot, "per_run");
  const outDir = path.join(exportRoot, "per_scenario");
  ensureDir(outDir);
  const groups = new Map();
  for (const file of walkFiles(perRunDir).filter((f) => f.endsWith("_alerts.jsonl"))) {
    const lines = fs.readFileSync(file, "utf8").split(/\r?\n/).filter(Boolean);
    for (const line of lines) {
      try {
        const alert = JSON.parse(line);
        const scenario = alert._safesoc_correlation?.scenario_id || "";
        if (!scenario) continue;
        if (!groups.has(scenario)) groups.set(scenario, []);
        groups.get(scenario).push(JSON.stringify(alert));
      } catch {
        // Skip malformed JSONL rows.
      }
    }
  }
  const summary = [];
  for (const [scenario, lines] of [...groups.entries()].sort()) {
    const file = path.join(outDir, `${scenario}_alerts.jsonl`);
    fs.writeFileSync(file, lines.join("\n") + (lines.length ? "\n" : ""), "utf8");
    summary.push({ scenario_id: scenario, alert_count: lines.length, file: path.relative(root, file) });
  }
  writeCsv(path.join(outDir, "per_scenario_export_summary.csv"), summary, ["scenario_id", "alert_count", "file"]);
  for (const row of summary) console.log(row.scenario_id, row.alert_count, row.file);
  return summary;
}

function maskIp(value) {
  if (typeof value !== "string") return value;
  return value.replace(/\b(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}\b/g, "$1.$2.x.x");
}

function sanitizeValue(key, value) {
  if (typeof value === "string") {
    const masked = /ip$/i.test(key) || key === "full_log" ? maskIp(value) : value;
    return key === "full_log" ? masked.slice(0, 500) : masked;
  }
  if (Array.isArray(value)) return value.map((item) => sanitizeValue(key, item));
  if (value && typeof value === "object") {
    const out = {};
    for (const [childKey, childValue] of Object.entries(value)) {
      out[childKey] = sanitizeValue(childKey, childValue);
    }
    return out;
  }
  return value;
}

function createSanitizedSample(rawAlerts) {
  const outDir = path.join(exportRoot, "sanitized_sample");
  ensureDir(outDir);
  const file = path.join(outDir, "sanitized_sample_alerts.jsonl");
  const rows = rawAlerts.slice(0, 100).map((item) => JSON.stringify(sanitizeValue("", item.alert)));
  fs.writeFileSync(file, rows.join("\n") + (rows.length ? "\n" : ""), "utf8");
  console.log(`Wrote ${rows.length} sanitized sample alerts to ${path.relative(root, file)}`);
  return rows.length;
}

function createCountsSummary(fullCount, evidenceInventory, perAgent, markers, runRows, perRun, perScenario, perCampaign, sanitizedCount) {
  const lines = [];
  lines.push(`Full raw alerts: ${fullCount}`);
  lines.push("");
  lines.push("Evidence inventory:");
  const extCounts = {};
  for (const row of evidenceInventory) extCounts[row.extension] = (extCounts[row.extension] || 0) + 1;
  for (const [ext, count] of Object.entries(extCounts).sort()) lines.push(`${ext}: ${count}`);
  lines.push("");
  lines.push("Per-agent:");
  for (const row of perAgent) lines.push(`${row.agent}: ${row.alert_count}`);
  lines.push("");
  lines.push(`Run marker alerts: ${markers.length}`);
  lines.push(`Frozen run log rows: ${runRows.length}`);
  lines.push("");
  lines.push("Per-run correlated alerts:");
  for (const row of perRun) lines.push(`${row.run_id}: ${row.alert_count}`);
  lines.push("");
  lines.push("Per-scenario correlated alerts:");
  for (const row of perScenario) lines.push(`${row.scenario_id}: ${row.alert_count}`);
  lines.push("");
  lines.push("Per-campaign correlated alerts:");
  for (const row of perCampaign) lines.push(`${row.campaign_id}: ${row.alert_count}`);
  lines.push("");
  lines.push(`Sanitized sample alerts: ${sanitizedCount}`);
  fs.writeFileSync(path.join(exportRoot, "sprint_07_counts_summary.txt"), lines.join("\n") + "\n", "utf8");
}

function createManifest(fullCount, evidenceInventory, perAgent, markers, runRows, perRun, perScenario, perCampaign, sanitizedCount) {
  const perAgentYaml = perAgent.map((row) => `    ${row.agent}: ${row.alert_count}`).join("\n");
  const perRunTotal = perRun.reduce((sum, row) => sum + Number(row.alert_count || 0), 0);
  const perScenarioYaml = perScenario.length
    ? perScenario.map((row) => `    ${row.scenario_id}: ${row.alert_count}`).join("\n")
    : "    none: 0";
  const perCampaignYaml = perCampaign.length
    ? perCampaign.map((row) => `    ${row.campaign_id}: ${row.alert_count}`).join("\n")
    : "    none: 0";
  const manifest = `dataset_name: SafeAgentSOC Phase 2 Raw Alert Dataset
dataset_version: phase_02_sprint_07_v1
created_utc: "${new Date().toISOString()}"
source_siem: Wazuh
lab_network: VMnet10 10.10.10.0/24

hosts:
  - hostname: safesoc-wazuh-01
    role: Wazuh manager/indexer/dashboard
    ip: 10.10.10.10
  - hostname: safesoc-win-01
    role: Windows endpoint
    ip: 10.10.10.21
  - hostname: safesoc-lnx-01
    role: Linux endpoint
    ip: 10.10.10.31
  - hostname: safesoc-caldera-01
    role: Caldera server
    ip: 10.10.10.41
  - hostname: safesoc-sim-01
    role: simulation/operator node
    ip: 10.10.10.42

exports:
  full_raw_alerts: full/raw_alerts_full.jsonl
  per_agent_dir: per_agent/
  per_scenario_dir: per_scenario/
  per_run_dir: per_run/
  per_campaign_dir: per_campaign/
  sanitized_sample_dir: sanitized_sample/
  scenario_run_log_frozen: scenario_run_log_frozen.csv
  evidence_inventory: evidence_inventory.csv

counts:
  full_raw_alerts: ${fullCount}
  evidence_files_inventoried: ${evidenceInventory.length}
  run_marker_alerts: ${markers.length}
  frozen_run_rows: ${runRows.length}
  per_run_correlated_alerts_total: ${perRunTotal}
  sanitized_sample_alerts: ${sanitizedCount}
  per_agent:
${perAgentYaml}
  per_scenario:
${perScenarioYaml}
  per_campaign:
${perCampaignYaml}

execution_modes:
  - manual
  - atomic_red_team
  - caldera
  - simulated_only
  - benign
  - noise

notes:
  - Raw data is stored locally only.
  - Sanitized samples only may be committed to GitHub.
  - Alerts were correlated using evidence-derived timestamp windows, agent.name matching, and campaign metadata from run IDs.
  - RUN_ID markers were searched in full_log and included where present.
  - Sprint 8 will create ground-truth labels and QA metrics.
limitations:
  - Current raw Wazuh export contains ${fullCount} alerts; final sufficiency will be reviewed during Sprint 8 QA.
  - Some run windows are derived from Wazuh CSV export timestamps rather than manually recorded start and end timestamps.
  - Background Wazuh telemetry may appear in broad timestamp windows and must be reviewed during Sprint 8 labeling.
`;
  fs.writeFileSync(path.join(exportRoot, "dataset_manifest.yaml"), manifest, "utf8");
}

function main() {
  ensureDir(exportRoot);
  for (const dir of ["per_agent", "per_run", "per_scenario", "per_campaign", "sanitized_sample"]) ensureDir(path.join(exportRoot, dir));

  const evidenceInventory = buildEvidenceInventory();
  const runRows = buildFrozenRunLog();
  const rawAlerts = readRawAlerts();
  const perAgent = splitByAgent(rawAlerts);
  const markers = extractRunMarkers(rawAlerts);
  const perRun = exportPerRun(rawAlerts, runRows);
  const perScenario = exportPerScenario();
  const perCampaign = exportPerCampaign();
  const sanitizedCount = createSanitizedSample(rawAlerts);
  createCountsSummary(rawAlerts.length, evidenceInventory, perAgent, markers, runRows, perRun, perScenario, perCampaign, sanitizedCount);
  createManifest(rawAlerts.length, evidenceInventory, perAgent, markers, runRows, perRun, perScenario, perCampaign, sanitizedCount);

  console.log("Sprint 7 processing complete");
  console.log(path.relative(root, path.join(exportRoot, "dataset_manifest.yaml")));
}

main();
