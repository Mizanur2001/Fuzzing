const axios = require("axios");
const generateFuzzPayloads = require("./fuzzGenerator");
const config = require("../config/config");
const fs = require("fs");
const path = require("path");

const RESULTS_FILE = path.join(__dirname, "..", "output", "results.json");

function loadExistingResults() {
    if (!fs.existsSync(RESULTS_FILE)) {
        return {};
    }
    return JSON.parse(fs.readFileSync(RESULTS_FILE, "utf-8"));
}

function saveResults(data) {
    fs.writeFileSync(RESULTS_FILE, JSON.stringify(data, null, 2));
}

async function runFuzzer(endpoint, schema) {
    const payloads = generateFuzzPayloads(schema);
    const allResults = loadExistingResults();

    if (!allResults[endpoint]) {
        allResults[endpoint] = [];
    }

    for (let i = 0; i < payloads.length; i++) {
        try {
            const res = await axios.post(
                config.baseURL + endpoint,
                payloads[i],
                {
                    headers: {
                        "Content-Type": "application/json",
                        Authorization: config.authToken
                    },
                    timeout: config.timeout
                }
            );

            allResults[endpoint].push({
                payload: payloads[i],
                status: res.status,
                response: res.data
            });

        } catch (err) {
            allResults[endpoint].push({
                payload: payloads[i],
                status: err.response?.status || "ERROR",
                error: err.response?.data || err.message
            });
        }
    }

    saveResults(allResults);
    console.log(`📁 Results saved for ${endpoint}`);
}

module.exports = runFuzzer;