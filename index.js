const fs = require("fs");
const path = require("path");

const extractOpenAPI = require("./extractor/extractOpenAPI");
const runFuzzer = require("./fuzzer/fuzzRunner");
const { generateReport } = require("./analyzer/reportGenerator");
const config = require("./config/config");

const OPENAPI_URL = config.OpenApiUrl;

const OUTPUT_DIR = path.join(__dirname, "output");
const PAYLOADS_PATH = path.join(OUTPUT_DIR, "payloads.json");

async function main() {
    console.log("🚀 Starting Fuzzing Framework v4.0.0");
    console.log(`   Target      : ${config.baseURL}`);
    console.log(`   Timeout     : ${config.timeout}ms`);
    console.log(`   Auth token  : ${config.authToken ? "✔ configured" : "✘ missing"}`);

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }

    // Always re-extract to pick up new endpoint info format
    console.log("\n📥 Extracting OpenAPI specification...");
    await extractOpenAPI(OPENAPI_URL);

    const payloads = JSON.parse(fs.readFileSync(PAYLOADS_PATH, "utf-8"));

    // Clear previous results file for a fresh run
    const resultsPath = path.join(OUTPUT_DIR, "results.json");
    if (fs.existsSync(resultsPath)) {
        fs.writeFileSync(resultsPath, "{}");
    }

    const allFindings = {};
    const keys = Object.keys(payloads);

    console.log(`\n📋 Found ${keys.length} endpoints to fuzz\n`);

    for (const key of keys) {
        const spaceIdx = key.indexOf(" ");
        const method = key.slice(0, spaceIdx);
        const endpoint = key.slice(spaceIdx + 1);

        const info = payloads[key];
        const bodyFields = info.body ? Object.keys(info.body).length : 0;
        const pathP = (info.pathParams || []).length;
        const queryP = (info.queryParams || []).length;

        console.log(`🔥 Fuzzing: ${method} ${endpoint}`);
        console.log(`   Body fields: ${bodyFields}, Path params: ${pathP}, Query params: ${queryP}`);

        const findings = await runFuzzer(method, endpoint, info);
        allFindings[`${method} ${endpoint}`] = findings;
    }

    // Generate vulnerability report
    generateReport(allFindings);

    console.log("\n✅ Fuzzing complete");
}

main().catch(err => console.error("❌ Fatal error:", err));