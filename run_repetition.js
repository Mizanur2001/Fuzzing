/**
 * run_repetition.js — Statistical repetition harness (v2, hardened)
 * -----------------------------------------------------------------------------
 * Runs ONE campaign per iteration via `node index.js` (the run-once CLI entry
 * point), N times, against the SAME live target configured in config/config.js.
 *
 * IMPORTANT: this calls index.js, NOT server.js. server.js starts a web server
 * that never exits, which would hang the harness. index.js runs one campaign
 * and exits, which is what we need.
 *
 * Hardening vs the first version:
 *   - Deletes the previous vulnerability-report.json BEFORE each run, so a
 *     failed run can NEVER be scored from a stale report left on disk.
 *   - Treats "no fresh report produced" as a genuine failure, not a silent pass.
 *   - Flags implausibly fast runs (a real campaign issuing thousands of HTTP
 *     requests cannot finish in a fraction of a second).
 *
 * USAGE:
 *     node run_repetition.js            # 10 runs, no pause
 *     node run_repetition.js 10 30      # 10 runs, 30s pause between runs
 */

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");

const N = parseInt(process.argv[2] || "10", 10);
const PAUSE_SEC = parseInt(process.argv[3] || "0", 10);
const OUTPUT_DIR = path.join(__dirname, "output");
const REPORT = path.join(OUTPUT_DIR, "vulnerability-report.json");
const ENTRY = "index.js";                 // run-once entry point (NOT server.js)
const MIN_PLAUSIBLE_SEC = 3;              // warn if a run is faster than this

const METRIC_KEYS = [
  "totalRequests", "totalFindings", "uniqueFindings",
  "sev_CRITICAL", "sev_HIGH", "sev_MEDIUM", "sev_LOW", "wallClockSec",
];

function extractMetrics(report, wallClockSec) {
  const sev = report.bySeverity || {};
  return {
    totalRequests: report.totalRequests ?? 0,
    totalFindings: report.totalFindings ?? 0,
    uniqueFindings: report.uniqueFindings ?? 0,
    sev_CRITICAL: sev.CRITICAL ?? 0,
    sev_HIGH: sev.HIGH ?? 0,
    sev_MEDIUM: sev.MEDIUM ?? 0,
    sev_LOW: sev.LOW ?? 0,
    wallClockSec: Number(wallClockSec.toFixed(2)),
  };
}
function mean(xs) { return xs.reduce((a, b) => a + b, 0) / xs.length; }
function stdev(xs) {
  if (xs.length < 2) return 0;
  const m = mean(xs);
  const v = xs.reduce((a, b) => a + (b - m) ** 2, 0) / (xs.length - 1);
  return Math.sqrt(v);
}
function sleep(sec) { return new Promise(r => setTimeout(r, sec * 1000)); }

(async function main() {
  console.log(`\n=== Statistical repetition: ${N} runs via ${ENTRY} ===\n`);
  const runs = [];
  let fastWarnings = 0;

  for (let i = 1; i <= N; i++) {
    process.stdout.write(`Run ${i}/${N} ... `);

    if (fs.existsSync(REPORT)) fs.unlinkSync(REPORT);

    const t0 = Date.now();
    let toolFailed = false;
    try {
      execSync(`node ${ENTRY}`, { cwd: __dirname, stdio: "ignore" });
    } catch (e) {
      toolFailed = true;
    }
    const wallClockSec = (Date.now() - t0) / 1000;

    if (!fs.existsSync(REPORT)) {
      console.log(`FAILED — no report produced (tool ${toolFailed ? "errored" : "exited"}); NOT counted`);
      continue;
    }

    const report = JSON.parse(fs.readFileSync(REPORT, "utf8"));
    const m = extractMetrics(report, wallClockSec);
    runs.push(m);

    let flag = "";
    if (wallClockSec < MIN_PLAUSIBLE_SEC) { flag = "  [!] suspiciously fast - verify the target was actually reached"; fastWarnings++; }
    console.log(`done in ${m.wallClockSec}s  (unique=${m.uniqueFindings}, raw=${m.totalFindings})${flag}`);

    if (PAUSE_SEC > 0 && i < N) { await sleep(PAUSE_SEC); }
  }

  if (runs.length === 0) {
    console.error("\nNo successful runs. Is the target reachable at the configured baseURL? Is index.js the correct entry point?");
    process.exit(1);
  }
  if (runs.length < N) {
    console.warn(`\n[!] Only ${runs.length}/${N} runs succeeded. Report the succeeded count honestly, or fix the target and re-run.`);
  }
  if (fastWarnings > 0) {
    console.warn(`[!] ${fastWarnings} run(s) finished under ${MIN_PLAUSIBLE_SEC}s. A real campaign of thousands of requests should take minutes. Investigate before using these numbers.`);
  }

  console.log("\n--- Per-run metrics ---");
  console.log(["run", ...METRIC_KEYS].join("\t"));
  runs.forEach((r, i) => console.log([i + 1, ...METRIC_KEYS.map(k => r[k])].join("\t")));

  console.log(`\n--- Summary across ${runs.length} runs (mean +/- SD) ---`);
  const summary = {};
  for (const k of METRIC_KEYS) {
    const xs = runs.map(r => r[k]);
    const m = mean(xs), sd = stdev(xs);
    summary[k] = { mean: +m.toFixed(2), sd: +sd.toFixed(2), min: Math.min(...xs), max: Math.max(...xs), cv_pct: m !== 0 ? +((sd / m) * 100).toFixed(2) : 0 };
    console.log(`${k.padEnd(16)} mean=${m.toFixed(2).padStart(10)}  SD=${sd.toFixed(2).padStart(8)}  min=${Math.min(...xs)}  max=${Math.max(...xs)}  CV=${summary[k].cv_pct}%`);
  }

  fs.writeFileSync(path.join(__dirname, "repetition_runs.json"), JSON.stringify({ n: runs.length, requested: N, runs, summary }, null, 2));
  const csv = ["metric,mean,sd,min,max,cv_percent"];
  for (const k of METRIC_KEYS) { const s = summary[k]; csv.push(`${k},${s.mean},${s.sd},${s.min},${s.max},${s.cv_pct}`); }
  fs.writeFileSync(path.join(__dirname, "repetition_summary.csv"), csv.join("\n"));

  console.log("\nWrote repetition_runs.json and repetition_summary.csv\n");
})();
