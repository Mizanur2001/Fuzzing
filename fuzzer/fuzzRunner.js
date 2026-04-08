const axios = require("axios");
const generateFuzzPayloads = require("./fuzzGenerator");
const config = require("../config/config");
const { analyzeResult } = require("../analyzer/vulnerabilityAnalyzer");
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

/**
 * Run fuzzer on a single endpoint.
 *
 * @param {string} method   - HTTP method (GET, POST, PUT, DELETE)
 * @param {string} endpoint - URL path
 * @param {Object} schema   - field → type mapping
 * @returns {Array} results with findings for the report generator
 */
async function runFuzzer(method, endpoint, schema) {
    const fuzzCases = generateFuzzPayloads(schema);
    const allResults = loadExistingResults();
    const key = `${method} ${endpoint}`;
    const endpointFindings = [];

    if (!allResults[key]) {
        allResults[key] = [];
    }

    const total = fuzzCases.length;
    let completed = 0;
    let findingsCount = 0;

    for (const fuzzCase of fuzzCases) {
        completed++;
        const { payload, meta } = fuzzCase;

        const startTime = Date.now();
        let status, responseData, errorData;

        try {
            const axiosConfig = {
                method: method.toLowerCase(),
                url: config.baseURL + endpoint,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: config.authToken,
                },
                timeout: config.timeout,
            };

            // GET/DELETE send params as query; POST/PUT/PATCH send as body
            if (["GET", "DELETE"].includes(method.toUpperCase())) {
                axiosConfig.params = payload;
            } else {
                axiosConfig.data = payload;
            }

            const res = await axios(axiosConfig);
            status = res.status;
            responseData = res.data;
        } catch (err) {
            status = err.response?.status || "ERROR";
            errorData = err.response?.data || err.message;
        }

        const responseTime = Date.now() - startTime;

        // Build the result object with metadata for the analyzer
        const result = {
            payload,
            status,
            response: responseData,
            error: errorData,
            meta,
            responseTime,
        };

        // Run vulnerability analysis
        const findings = analyzeResult(result);
        result.findings = findings;

        if (findings.length > 0) {
            findingsCount += findings.length;
        }

        // Save to results file (without meta to keep it compact)
        allResults[key].push({
            payload,
            status,
            ...(responseData ? { response: responseData } : {}),
            ...(errorData ? { error: errorData } : {}),
            ...(findings.length > 0 ? { findings: findings.map(f => ({ type: f.type, severity: f.severity })) } : {}),
        });

        endpointFindings.push(result);

        // Progress indicator every 50 requests
        if (completed % 50 === 0 || completed === total) {
            process.stdout.write(
                `\r  [${completed}/${total}] ${findingsCount} findings so far`
            );
        }
    }

    console.log(); // newline after progress
    saveResults(allResults);
    console.log(`  📁 Results saved for ${key} (${findingsCount} findings)`);

    return endpointFindings;
}

module.exports = runFuzzer;