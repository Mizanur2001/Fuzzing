const fs = require("fs");
const path = require("path");

const extractOpenAPI = require("./extractor/extractOpenAPI");
const runFuzzer = require("./fuzzer/fuzzRunner");
const config = require("./config/config");

const OPENAPI_URL = config.OpenApiUrl;

const OUTPUT_DIR = path.join(__dirname, "output");
const PAYLOADS_PATH = path.join(OUTPUT_DIR, "payloads.json");

async function main() {
    console.log("🚀 Starting Fuzzing Framework");

    if (!fs.existsSync(OUTPUT_DIR)) {
        fs.mkdirSync(OUTPUT_DIR);
    }

    if (!fs.existsSync(PAYLOADS_PATH)) {
        console.log("📥 payloads.json not found, extracting OpenAPI...");
        await extractOpenAPI(OPENAPI_URL);
    }

    const payloads = JSON.parse(fs.readFileSync(PAYLOADS_PATH, "utf-8"));

    // 🔥 FUZZ ALL POST ENDPOINTS
    for (const key of Object.keys(payloads)) {
        const [method, endpoint] = key.split(" ");

        if (method !== "POST") continue;

        console.log(`\n🔥 Fuzzing endpoint: ${endpoint}`);
        console.log(`📦 Schema:`, payloads[key]);

        await runFuzzer(endpoint, payloads[key]);
    }

    console.log("\n✅ All endpoints fuzzed");
}

main().catch(err => console.error("❌ Fatal error:", err));