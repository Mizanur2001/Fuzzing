const axios = require("axios");
const generateFuzzPayloads = require("./fuzzGenerator");
const config = require("../config/config");
const { analyzeResult } = require("../analyzer/vulnerabilityAnalyzer");
const fs = require("fs");
const path = require("path");

const RESULTS_FILE = path.join(__dirname, "..", "output", "results.json");

function loadExistingResults() {
    if (!fs.existsSync(RESULTS_FILE)) return {};
    return JSON.parse(fs.readFileSync(RESULTS_FILE, "utf-8"));
}

function saveResults(data) {
    fs.writeFileSync(RESULTS_FILE, JSON.stringify(data, null, 2));
}

/**
 * Measure a baseline response time by sending a valid request.
 * Used to detect blind injection (timing-based anomalies).
 */
async function measureBaseline(method, url, options = {}) {
    const times = [];
    const shouldSkip = () => options.shouldSkip?.() || options.signal?.aborted;

    for (let i = 0; i < 3; i++) {
        if (shouldSkip()) return null;

        const start = Date.now();
        try {
            await axios({
                method: method.toLowerCase(),
                url,
                headers: {
                    "Content-Type": "application/json",
                    Authorization: config.authToken,
                },
                timeout: config.timeout,
                signal: options.signal,
                validateStatus: () => true,
            });
        } catch (err) {
            if (shouldSkip() || err.code === "ERR_CANCELED") return null;
        }
        times.push(Date.now() - start);
    }
    return Math.max(...times) * 1.0; // baseline = worst of 3
}

/**
 * Build the actual URL by substituting path parameters with fuzz values.
 * e.g. /api/v1/server/:id  +  payload "admin"  →  /api/v1/server/admin
 */
function buildUrl(baseEndpoint, meta, payload) {
    if (meta.location === "path") {
        return baseEndpoint.replace(
            new RegExp(`\\{${meta.targetField}\\}|:${meta.targetField}`, "g"),
            encodeURIComponent(String(payload))
        );
    }
    return baseEndpoint;
}

/**
 * Run fuzzer on a single endpoint.
 *
 * @param {string} method       - HTTP method (GET, POST, PUT, DELETE, PATCH)
 * @param {string} endpoint     - URL path (may contain :param or {param})
 * @param {Object} endpointInfo - { body, pathParams, queryParams } from extractor
 * @returns {Array} results with findings for the report generator
 */
async function runFuzzer(method, endpoint, endpointInfo, onProgress, options = {}) {
    const fuzzCases = generateFuzzPayloads(endpointInfo, method);
    const allResults = loadExistingResults();
    const key = `${method} ${endpoint}`;
    const endpointFindings = [];
    const shouldSkip = () => options.shouldSkip?.() || options.signal?.aborted;
    let skipped = false;

    if (!allResults[key]) allResults[key] = [];

    // ── Measure baseline response time for blind-injection detection ──
    const baseUrl = config.baseURL + endpoint.replace(/\{[^}]+\}|:[a-zA-Z_]+/g, "test");
    const baselineTime = await measureBaseline(method, baseUrl, options);

    if (baselineTime === null || shouldSkip()) {
        skipped = true;
    }

    // ── Rate-limit detection: count total requests and whether
    //    the endpoint ever throttled. Consecutive-counter approaches
    //    are confounded by 5xx responses that reset the counter
    //    without indicating that the endpoint is actually rate-limited.
    let totalRequests = 0;
    let throttled = false;
    const RATE_LIMIT_THRESHOLD = 50; // if 50+ requests issued without 429, flag it

    const total = fuzzCases.length;
    let completed = 0;
    let findingsCount = 0;

    for (const fuzzCase of fuzzCases) {
        if (skipped || shouldSkip()) {
            skipped = true;
            break;
        }

        completed++;
        const { payload, meta } = fuzzCase;

        const actualPath = buildUrl(endpoint, meta, payload);
        const startTime = Date.now();
        let status, responseData, errorData, responseHeaders;

        try {
            const axiosConfig = {
                method: method.toLowerCase(),
                url: config.baseURL + actualPath,
                headers: {
                    "Content-Type": "application/json",
                },
                timeout: config.timeout,
                signal: options.signal,
                validateStatus: () => true, // don't throw on any status
            };

            // ── Auth header handling ──
            if (meta.authOverride !== undefined) {
                // Auth fuzz: use the override (null = no header at all)
                if (meta.authOverride !== null) {
                    axiosConfig.headers.Authorization = meta.authOverride;
                }
            } else {
                axiosConfig.headers.Authorization = config.authToken;
            }

            // ── Payload placement ──
            if (meta.location === "path") {
                // Already in URL, no body/query needed
            } else if (meta.location === "query" || ["GET", "DELETE"].includes(method.toUpperCase())) {
                if (typeof payload === "object") {
                    axiosConfig.params = payload;
                }
            } else {
                axiosConfig.data = payload;
            }

            const res = await axios(axiosConfig);
            status = res.status;
            responseData = res.data;
            responseHeaders = res.headers;
        } catch (err) {
            if (shouldSkip() || err.code === "ERR_CANCELED") {
                skipped = true;
                break;
            }

            status = err.response?.status || "ERROR";
            errorData = err.response?.data || err.message;
            responseHeaders = err.response?.headers || {};
        }

        const responseTime = Date.now() - startTime;

        // ── Rate-limit tracking ──
        totalRequests++;
        if (status === 429) throttled = true;
        if (responseHeaders && (responseHeaders["retry-after"] || responseHeaders["Retry-After"])) {
            throttled = true;
        }

        // Build the result object with metadata for the analyzer
        const result = {
            payload,
            status,
            response: responseData,
            error: errorData,
            meta,
            endpoint: actualPath,
            responseTime,
            baselineTime,
            responseHeaders,
        };

        // Run vulnerability analysis
        const findings = analyzeResult(result);
        result.findings = findings;

        if (findings.length > 0) {
            findingsCount += findings.length;
        }

        // Save to results file
        allResults[key].push({
            payload: typeof payload === "object" ? payload : { _value: payload },
            status,
            ...(responseData ? { response: responseData } : {}),
            ...(errorData ? { error: errorData } : {}),
            ...(findings.length > 0
                ? { findings: findings.map(f => ({ type: f.type, severity: f.severity })) }
                : {}),
        });

        endpointFindings.push(result);

        // Progress indicator
        if (onProgress) {
            if (completed % 10 === 0 || completed === total) {
                onProgress({ completed, total, findingsCount });
            }
        } else if (completed % 50 === 0 || completed === total) {
            process.stdout.write(
                `\r  [${completed}/${total}] ${findingsCount} findings so far`
            );
        }
    }

    // ── Rate-limit check at end of endpoint ──
    if (!skipped && totalRequests >= RATE_LIMIT_THRESHOLD && !throttled) {
        const rateLimitFinding = {
            payload: { _note: `${totalRequests} requests without rate limiting` },
            status: "N/A",
            response: null,
            error: null,
            meta: {
                strategy: "rate-limit-check",
                targetField: "*",
                categories: ["missing_rate_limit"],
                location: "endpoint",
            },
            responseTime: 0,
            findings: [{
                type: "missing_rate_limit",
                severity: "MEDIUM",
                detail: `${totalRequests} requests completed without HTTP 429 or Retry-After throttling`,
                evidence: `Endpoint ${key} accepted ${totalRequests} requests with no throttling signal`,
            }],
        };
        endpointFindings.push(rateLimitFinding);
        findingsCount++;
    }

    if (skipped) {
        endpointFindings.skipped = true;
    }
    endpointFindings.completed = completed;
    endpointFindings.total = total;

    console.log(); // newline after progress
    saveResults(allResults);
    console.log(
        `  📁 Results saved for ${key} (${findingsCount} findings${skipped ? ", skipped" : ""})`
    );

    return endpointFindings;
}

module.exports = runFuzzer;
