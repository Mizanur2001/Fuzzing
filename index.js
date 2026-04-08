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
    console.log("🚀 Starting Fuzzing Framework v3.0.0");
    console.log(`   Target: ${config.baseURL}`);

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }

    if (!fs.existsSync(PAYLOADS_PATH)) {
        console.log("📥 payloads.json not found, extracting OpenAPI...");
        await extractOpenAPI(OPENAPI_URL);
    }

    const payloads = JSON.parse(fs.readFileSync(PAYLOADS_PATH, "utf-8"));
    const allFindings = {};

    for (const key of Object.keys(payloads)) {
        const [method, endpoint] = key.split(" ");

        console.log(`\n🔥 Fuzzing: ${method} ${endpoint}`);

        const findings = await runFuzzer(method, endpoint, payloads[key]);
        allFindings[`${method} ${endpoint}`] = findings;
    }

    // Generate vulnerability report
    generateReport(allFindings);

    console.log("\n✅ Fuzzing complete");
}

main().catch(err => console.error("❌ Fatal error:", err));