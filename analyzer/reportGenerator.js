/**
 * Vulnerability Report Generator
 *
 * Generates a structured JSON report and a human-readable summary
 * from the vulnerability findings produced by the analyzer.
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
    template_injection: "Template Injection",
    information_disclosure: "Information Disclosure",
    denial_of_service: "Denial of Service",
    missing_rate_limit: "Missing Rate Limit",
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
        totalEndpoints: 0,
        totalRequests: 0,
        totalFindings: 0,
        bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 },
        byType: {},
        endpoints: {},
    };

    for (const [endpoint, results] of Object.entries(allFindings)) {
        summary.totalEndpoints++;
        const endpointSummary = {
            totalRequests: results.length,
            findings: [],
        };

        for (const result of results) {
            summary.totalRequests++;
            const findings = result.findings || [];

            for (const f of findings) {
                summary.totalFindings++;
                summary.bySeverity[f.severity] = (summary.bySeverity[f.severity] || 0) + 1;
                summary.byType[f.type] = (summary.byType[f.type] || 0) + 1;

                endpointSummary.findings.push({
                    type: f.type,
                    severity: f.severity,
                    detail: f.detail,
                    evidence: f.evidence,
                    payload: summarizePayload(result.payload),
                    status: result.status,
                });
            }
        }

        // only include endpoints that have findings
        if (endpointSummary.findings.length > 0) {
            summary.endpoints[endpoint] = endpointSummary;
        }
    }

    // Save JSON report
    const reportPath = path.join(OUTPUT_DIR, "vulnerability-report.json");
    fs.writeFileSync(reportPath, JSON.stringify(summary, null, 2));
    console.log(`\n📄 Vulnerability report saved: output/vulnerability-report.json`);

    // Print console summary
    printSummary(summary);

    return summary;
}

function summarizePayload(payload) {
    if (!payload) return null;
    const str = JSON.stringify(payload);
    return str.length > 200 ? str.slice(0, 200) + "..." : str;
}

function printSummary(summary) {
    console.log("\n" + "═".repeat(60));
    console.log("  VULNERABILITY SCAN REPORT");
    console.log("═".repeat(60));
    console.log(`  Date       : ${summary.generatedAt}`);
    console.log(`  Endpoints  : ${summary.totalEndpoints}`);
    console.log(`  Requests   : ${summary.totalRequests}`);
    console.log(`  Findings   : ${summary.totalFindings}`);
    console.log("─".repeat(60));
    console.log("  SEVERITY BREAKDOWN:");

    if (summary.bySeverity.CRITICAL > 0)
        console.log(`    CRITICAL : ${summary.bySeverity.CRITICAL}`);
    if (summary.bySeverity.HIGH > 0)
        console.log(`    HIGH     : ${summary.bySeverity.HIGH}`);
    if (summary.bySeverity.MEDIUM > 0)
        console.log(`    MEDIUM   : ${summary.bySeverity.MEDIUM}`);
    if (summary.bySeverity.LOW > 0)
        console.log(`    LOW      : ${summary.bySeverity.LOW}`);

    if (summary.totalFindings === 0) {
        console.log("    No vulnerabilities detected.");
    }

    console.log("─".repeat(60));

    if (Object.keys(summary.byType).length > 0) {
        console.log("  VULNERABILITY TYPES:");
        for (const [type, count] of Object.entries(summary.byType)) {
            const label = TYPE_LABELS[type] || type;
            console.log(`    ${label}: ${count}`);
        }
        console.log("─".repeat(60));
    }

    // Show top findings per endpoint
    for (const [endpoint, data] of Object.entries(summary.endpoints)) {
        const critical = data.findings.filter(f => f.severity === "CRITICAL");
        const high = data.findings.filter(f => f.severity === "HIGH");
        if (critical.length > 0 || high.length > 0) {
            console.log(`\n  ${endpoint}`);
            for (const f of [...critical, ...high].slice(0, 5)) {
                console.log(`    [${f.severity}] ${f.type}: ${f.detail}`);
            }
        }
    }

    console.log("\n" + "═".repeat(60));
}

module.exports = { generateReport };
