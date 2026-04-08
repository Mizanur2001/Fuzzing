/**
 * Vulnerability Report Generator v2
 *
 * Generates a structured JSON report with finding deduplication.
 * Groups identical root-cause findings per endpoint so the same
 * ValidationError-on-port isn't counted 400 times.
 */

const fs = require("fs");
const path = require("path");

const OUTPUT_DIR = path.join(__dirname, "..", "output");

const TYPE_LABELS = {
    server_error: "Server Error (5xx)",
    nosql_injection: "NoSQL Injection",
    sql_injection: "SQL Injection",
    improper_input_validation: "Improper Input Validation",
    idor: "Insecure Direct Object Reference (IDOR)",
    xss_reflected: "Reflected XSS",
    command_injection: "Command Injection",
    path_traversal: "Path Traversal",
    ssrf: "Server-Side Request Forgery (SSRF)",
    template_injection: "Template Injection (SSTI)",
    information_disclosure: "Information Disclosure",
    denial_of_service: "Denial of Service (DoS)",
    missing_rate_limit: "Missing Rate Limit",
    broken_authentication: "Broken Authentication (BOLA)",
    blind_injection: "Blind Injection (Timing-based)",
    redos: "Regular Expression DoS (ReDoS)",
    log_injection: "Log Injection / Log Forging",
    http_param_pollution: "HTTP Parameter Pollution",
    json_injection: "JSON Injection / Deserialization",
    csv_injection: "CSV / Formula Injection",
    email_injection: "Email Header Injection",
    cors_misconfig: "CORS Misconfiguration",
    business_logic: "Business Logic Flaw",
    graphql_injection: "GraphQL Injection",
    jwt_attacks: "JWT Token Attack",
    open_redirect: "Open Redirect",
    mass_assignment: "Mass Assignment",
    prototype_pollution: "Prototype Pollution",
    xxe: "XML External Entity (XXE)",
    ldap_injection: "LDAP Injection",
    header_injection: "HTTP Header Injection / CRLF",
};

/**
 * Build and save a vulnerability report.
 *
 * @param {Object} allFindings - { endpoint: [ { payload, status, findings, ... } ] }
 */
function generateReport(allFindings) {
    const summary = {
        generatedAt: new Date().toISOString(),
        frameworkVersion: "4.0.0",
        totalEndpoints: 0,
        totalRequests: 0,
        totalFindings: 0,
        uniqueFindings: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        byType: {},
        endpoints: {},
    };

    for (const [endpoint, results] of Object.entries(allFindings)) {
        summary.totalEndpoints++;

        // ── Deduplication: group by type+detail to count unique root causes ──
        const dedupMap = new Map(); // key = "type|detail" → { finding, count, samplePayloads[] }
        let requestCount = 0;

        for (const result of results) {
            requestCount++;
            summary.totalRequests++;
            const findings = result.findings || [];

            for (const f of findings) {
                summary.totalFindings++;
                summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
                summary.byType[f.type] = (summary.byType[f.type] || 0) + 1;

                const dedupKey = `${f.type}|${f.detail}`;
                if (!dedupMap.has(dedupKey)) {
                    dedupMap.set(dedupKey, {
                        type: f.type,
                        severity: f.severity,
                        detail: f.detail,
                        evidence: f.evidence,
                        count: 0,
                        samplePayloads: [],
                    });
                }

                const entry = dedupMap.get(dedupKey);
                entry.count++;
                if (entry.samplePayloads.length < 3) {
                    entry.samplePayloads.push({
                        payload: summarizePayload(result.payload),
                        status: result.status,
                    });
                }
            }
        }

        if (dedupMap.size > 0) {
            // Sort: CRITICAL first, then HIGH, then by count desc
            const severityOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
            const uniqueFindings = [...dedupMap.values()].sort((a, b) =>
                (severityOrder[a.severity] || 9) - (severityOrder[b.severity] || 9)
                || b.count - a.count
            );

            summary.uniqueFindings += uniqueFindings.length;
            summary.endpoints[endpoint] = {
                totalRequests: requestCount,
                uniqueFindings: uniqueFindings.length,
                rawFindings: [...dedupMap.values()].reduce((s, e) => s + e.count, 0),
                findings: uniqueFindings,
            };
        }
    }

    // Save JSON report
    const reportPath = path.join(OUTPUT_DIR, "vulnerability-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(summary, null, 2));
    console.log(`\n📄 Vulnerability report saved: output/vulnerability-report.json`);

    printSummary(summary);
    return summary;
}

function summarizePayload(payload) {
    if (!payload) return null;
    const str = typeof payload === "string" ? payload : JSON.stringify(payload);
    return str.length > 200 ? str.slice(0, 200) + "..." : str;
}

function printSummary(summary) {
    console.log("\n" + "═".repeat(60));
    console.log("  VULNERABILITY SCAN REPORT — v4.0.0");
    console.log("═".repeat(60));
    console.log(`  Date             : ${summary.generatedAt}`);
    console.log(`  Endpoints tested : ${summary.totalEndpoints}`);
    console.log(`  Total requests   : ${summary.totalRequests}`);
    console.log(`  Raw findings     : ${summary.totalFindings}`);
    console.log(`  Unique findings  : ${summary.uniqueFindings}`);
    console.log("─".repeat(60));
    console.log("  SEVERITY BREAKDOWN:");

    for (const sev of ["CRITICAL", "HIGH", "MEDIUM", "LOW"]) {
        if (summary.bySeverity[sev] > 0) {
            const icon = sev === "CRITICAL" ? "🔴" : sev === "HIGH" ? "🟠" : sev === "MEDIUM" ? "🟡" : "⚪";
            console.log(`    ${icon} ${sev.padEnd(10)}: ${summary.bySeverity[sev]}`);
        }
    }

    if (summary.totalFindings === 0) {
        console.log("    No vulnerabilities detected.");
    }

    console.log("─".repeat(60));

    if (Object.keys(summary.byType).length > 0) {
        console.log("  VULNERABILITY TYPES:");
        // Sort by count descending
        const sorted = Object.entries(summary.byType).sort((a, b) => b[1] - a[1]);
        for (const [type, count] of sorted) {
            const label = TYPE_LABELS[type] || type;
            console.log(`    ${label}: ${count}`);
        }
        console.log("─".repeat(60));
    }

    // Show unique findings per endpoint (top 8)
    for (const [endpoint, data] of Object.entries(summary.endpoints)) {
        const critical = data.findings.filter(f => f.severity === "CRITICAL");
        const high = data.findings.filter(f => f.severity === "HIGH");
        if (critical.length > 0 || high.length > 0) {
            console.log(`\n  📌 ${endpoint} (${data.uniqueFindings} unique findings)`);
            for (const f of [...critical, ...high].slice(0, 8)) {
                console.log(`    [${f.severity}] ${TYPE_LABELS[f.type] || f.type} (×${f.count})`);
                console.log(`           ${f.detail}`);
            }
        }
    }

    console.log("\n" + "═".repeat(60));
}

module.exports = { generateReport };
