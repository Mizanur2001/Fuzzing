const express = require("express");
const cors = require("cors");
const path = require("path");
const fs = require("fs");

const app = express();
const PORT = process.env.PORT || 4000;

app.use(cors());
app.use(express.json());

// Serve React frontend (production build)
app.use(express.static(path.join(__dirname, "frontend", "dist")));

// ── Paths ──────────────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, "config", "config.js");
const OUTPUT_DIR = path.join(__dirname, "output");
const PAYLOADS_PATH = path.join(OUTPUT_DIR, "payloads.json");
const RESULTS_PATH = path.join(OUTPUT_DIR, "results.json");
const REPORT_PATH = path.join(OUTPUT_DIR, "vulnerability-report.json");

// ── State ──────────────────────────────────────────────────
let fuzzState = { running: false };
let sseClients = [];

// ── SSE helpers ────────────────────────────────────────────
function broadcast(event, data) {
    const msg = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    sseClients.forEach(c => c.res.write(msg));
}

// Heartbeat to keep SSE connections alive
setInterval(() => {
    sseClients.forEach(c => c.res.write(":heartbeat\n\n"));
}, 15000);

// ── API: Config ────────────────────────────────────────────
app.get("/api/config", (req, res) => {
    delete require.cache[require.resolve("./config/config")];
    const config = require("./config/config");
    res.json({
        baseURL: config.baseURL || "",
        OpenApiUrl: config.OpenApiUrl || "",
        authToken: config.authToken || "",
        timeout: config.timeout || 5000,
        maxIterations: config.maxIterations || 5000,
    });
});

app.post("/api/config", (req, res) => {
    const { baseURL, OpenApiUrl, authToken, timeout, maxIterations } = req.body;

    if (!baseURL || !OpenApiUrl) {
        return res.status(400).json({ error: "baseURL and OpenApiUrl are required" });
    }

    const content = `module.exports = {\n` +
        `    baseURL: ${JSON.stringify(String(baseURL))},\n` +
        `    OpenApiUrl: ${JSON.stringify(String(OpenApiUrl))},\n` +
        `    authToken: ${JSON.stringify(String(authToken || ""))},\n` +
        `    maxIterations: ${parseInt(maxIterations) || 5000},\n` +
        `    timeout: ${parseInt(timeout) || 5000}\n` +
        `};\n`;

    fs.writeFileSync(CONFIG_PATH, content);
    delete require.cache[require.resolve("./config/config")];
    res.json({ status: "saved" });
});

// ── API: SSE endpoint ──────────────────────────────────────
app.get("/api/fuzz/events", (req, res) => {
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-cache");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();

    const client = { id: Date.now(), res };
    sseClients.push(client);

    req.on("close", () => {
        sseClients = sseClients.filter(c => c.id !== client.id);
    });
});

// ── API: Start fuzzing ─────────────────────────────────────
app.post("/api/fuzz/start", (req, res) => {
    if (fuzzState.running) {
        return res.status(409).json({ error: "Fuzzing already in progress" });
    }

    fuzzState.running = true;
    res.json({ status: "started" });

    runFuzzPipeline().catch(err => {
        broadcast("fuzz-error", { message: err.message });
        fuzzState.running = false;
    });
});

// ── API: Get status ────────────────────────────────────────
app.get("/api/fuzz/status", (req, res) => {
    res.json({ running: fuzzState.running });
});

// ── API: Get report ────────────────────────────────────────
app.get("/api/report", (req, res) => {
    if (fs.existsSync(REPORT_PATH)) {
        res.json(JSON.parse(fs.readFileSync(REPORT_PATH, "utf-8")));
    } else {
        res.status(404).json({ error: "No report available" });
    }
});

// ── Fuzz pipeline ──────────────────────────────────────────
async function runFuzzPipeline() {
    // Clear all project module caches for fresh config
    const projectRoot = __dirname;
    for (const key of Object.keys(require.cache)) {
        if (key.startsWith(projectRoot) && !key.includes("node_modules")) {
            delete require.cache[key];
        }
    }

    const config = require("./config/config");
    const extractOpenAPI = require("./extractor/extractOpenAPI");
    const runFuzzer = require("./fuzzer/fuzzRunner");
    const { generateReport } = require("./analyzer/reportGenerator");

    if (!fs.existsSync(OUTPUT_DIR)) fs.mkdirSync(OUTPUT_DIR);

    // Phase 1: Extract OpenAPI
    broadcast("status", { phase: "extracting" });

    try {
        await extractOpenAPI(config.OpenApiUrl);
    } catch (err) {
        broadcast("fuzz-error", { message: `OpenAPI extraction failed: ${err.message}` });
        fuzzState.running = false;
        return;
    }

    const payloads = JSON.parse(fs.readFileSync(PAYLOADS_PATH, "utf-8"));
    const keys = Object.keys(payloads);

    // Send endpoint list to clients
    const endpointList = keys.map(k => {
        const i = k.indexOf(" ");
        return { method: k.slice(0, i), path: k.slice(i + 1) };
    });
    broadcast("endpoints", { list: endpointList });

    // Phase 2: Fuzz
    broadcast("status", { phase: "fuzzing", totalEndpoints: keys.length });

    if (fs.existsSync(RESULTS_PATH)) fs.writeFileSync(RESULTS_PATH, "{}");

    const allFindings = {};

    for (let i = 0; i < keys.length; i++) {
        const key = keys[i];
        const si = key.indexOf(" ");
        const method = key.slice(0, si);
        const endpoint = key.slice(si + 1);

        broadcast("endpoint-start", { index: i, method, endpoint });

        try {
            const findings = await runFuzzer(method, endpoint, payloads[key], (progress) => {
                broadcast("progress", {
                    endpointIndex: i,
                    totalEndpoints: keys.length,
                    endpoint: `${method} ${endpoint}`,
                    ...progress,
                });
            });

            const fc = findings.reduce((s, r) => s + (r.findings?.length || 0), 0);
            broadcast("endpoint-done", { index: i, endpoint: `${method} ${endpoint}`, findingsCount: fc });
            allFindings[`${method} ${endpoint}`] = findings;
        } catch (err) {
            broadcast("endpoint-done", { index: i, endpoint: `${method} ${endpoint}`, findingsCount: 0, error: err.message });
            allFindings[`${method} ${endpoint}`] = [];
        }
    }

    // Phase 3: Report
    broadcast("status", { phase: "reporting" });
    generateReport(allFindings);

    fuzzState.running = false;
    broadcast("complete", {});
}

// ── SPA fallback ───────────────────────────────────────────
app.get("*", (req, res) => {
    const indexPath = path.join(__dirname, "frontend", "dist", "index.html");
    if (fs.existsSync(indexPath)) {
        res.sendFile(indexPath);
    } else {
        res.status(404).send("Frontend not built. Run: cd frontend && npm run build");
    }
});

app.listen(PORT, () => {
    console.log(`\n🔒 Fuzzing Framework Server v4.0.0`);
    console.log(`   Dashboard : http://localhost:${PORT}`);
    console.log(`   API       : http://localhost:${PORT}/api\n`);
});
