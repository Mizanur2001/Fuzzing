import { useState } from "react";

const TYPE_LABELS = {
    server_error: "Server Error (5xx)",
    nosql_injection: "NoSQL Injection",
    sql_injection: "SQL Injection",
    improper_input_validation: "Improper Input Validation",
    idor: "Insecure Direct Object Reference",
    xss_reflected: "Reflected XSS",
    command_injection: "Command Injection",
    path_traversal: "Path Traversal",
    ssrf: "Server-Side Request Forgery",
    template_injection: "Template Injection (SSTI)",
    information_disclosure: "Information Disclosure",
    denial_of_service: "Denial of Service",
    missing_rate_limit: "Missing Rate Limit",
    broken_authentication: "Broken Authentication",
    blind_injection: "Blind Injection",
    redos: "ReDoS",
    log_injection: "Log Injection",
    http_param_pollution: "HTTP Parameter Pollution",
    json_injection: "JSON Injection",
    csv_injection: "CSV / Formula Injection",
    email_injection: "Email Header Injection",
    cors_misconfig: "CORS Misconfiguration",
    business_logic: "Business Logic Flaw",
    graphql_injection: "GraphQL Injection",
    jwt_attacks: "JWT Token Attack",
    open_redirect: "Open Redirect",
    mass_assignment: "Mass Assignment",
    prototype_pollution: "Prototype Pollution",
    xxe: "XML External Entity",
    ldap_injection: "LDAP Injection",
    header_injection: "Header Injection / CRLF",
};

const SEVERITY_COLORS = {
    CRITICAL: "#ff3366",
    HIGH: "#f0883e",
    MEDIUM: "#d29922",
    LOW: "#8b949e",
};

export default function Report({ report, onNewScan }) {
    const [expanded, setExpanded] = useState({});

    const toggle = (ep) =>
        setExpanded((prev) => ({ ...prev, [ep]: !prev[ep] }));

    const downloadReport = () => {
        const blob = new Blob([JSON.stringify(report, null, 2)], {
            type: "application/json",
        });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "vulnerability-report.json";
        a.click();
        URL.revokeObjectURL(url);
    };

    const totalSeverity = Object.values(report.bySeverity).reduce(
        (a, b) => a + b,
        0
    );

    return (
        <div className="report">
            <div className="panel-header">
                <h2>Vulnerability Scan Report</h2>
                <p className="subtitle">
                    Generated{" "}
                    {new Date(report.generatedAt).toLocaleString()} &middot;
                    Framework v{report.frameworkVersion}
                </p>
            </div>

            {/* Summary Cards */}
            <div className="summary-grid">
                <div className="summary-card">
                    <div className="card-value">{report.totalEndpoints}</div>
                    <div className="card-label">Endpoints</div>
                </div>
                <div className="summary-card">
                    <div className="card-value">
                        {report.totalRequests.toLocaleString()}
                    </div>
                    <div className="card-label">Requests</div>
                </div>
                <div className="summary-card accent">
                    <div className="card-value">{report.uniqueFindings}</div>
                    <div className="card-label">Unique Findings</div>
                </div>
                <div className="summary-card">
                    <div className="card-value">
                        {report.totalFindings.toLocaleString()}
                    </div>
                    <div className="card-label">Raw Findings</div>
                </div>
            </div>

            {/* Severity + Types */}
            <div className="report-grid">
                <div className="panel">
                    <h3>Severity Breakdown</h3>
                    {["CRITICAL", "HIGH", "MEDIUM", "LOW"].map((sev) => {
                        const count = report.bySeverity[sev] || 0;
                        if (count === 0) return null;
                        const pct =
                            totalSeverity > 0
                                ? (count / totalSeverity) * 100
                                : 0;
                        return (
                            <div key={sev} className="severity-row">
                                <span
                                    className="severity-label"
                                    style={{ color: SEVERITY_COLORS[sev] }}
                                >
                                    {sev}
                                </span>
                                <div className="severity-bar-bg">
                                    <div
                                        className="severity-bar-fill"
                                        style={{
                                            width: `${pct}%`,
                                            backgroundColor:
                                                SEVERITY_COLORS[sev],
                                        }}
                                    />
                                </div>
                                <span className="severity-count">
                                    {count.toLocaleString()}
                                </span>
                            </div>
                        );
                    })}
                </div>

                <div className="panel">
                    <h3>Vulnerability Types</h3>
                    {Object.entries(report.byType)
                        .sort((a, b) => b[1] - a[1])
                        .map(([type, count]) => (
                            <div key={type} className="type-row">
                                <span className="type-label">
                                    {TYPE_LABELS[type] || type}
                                </span>
                                <span className="type-count">
                                    {count.toLocaleString()}
                                </span>
                            </div>
                        ))}
                </div>
            </div>

            {/* Findings by Endpoint */}
            <div className="panel">
                <h3>Findings by Endpoint</h3>
                {Object.entries(report.endpoints)
                    .sort((a, b) => b[1].rawFindings - a[1].rawFindings)
                    .map(([ep, data]) => (
                        <div key={ep} className="ep-card">
                            <div
                                className="ep-header"
                                onClick={() => toggle(ep)}
                            >
                                <span className="ep-toggle">
                                    {expanded[ep] ? "▾" : "▸"}
                                </span>
                                <span className="ep-name">{ep}</span>
                                <span className="ep-badge">
                                    {data.uniqueFindings} unique
                                </span>
                                <span className="ep-raw">
                                    {data.rawFindings.toLocaleString()} raw
                                </span>
                            </div>

                            {expanded[ep] && (
                                <div className="ep-findings">
                                    {data.findings.map((f, i) => (
                                        <div
                                            key={i}
                                            className={`finding severity-${f.severity.toLowerCase()}`}
                                        >
                                            <div className="finding-header">
                                                <span
                                                    className="finding-badge"
                                                    style={{
                                                        backgroundColor:
                                                            SEVERITY_COLORS[
                                                                f.severity
                                                            ],
                                                    }}
                                                >
                                                    {f.severity}
                                                </span>
                                                <span className="finding-type">
                                                    {TYPE_LABELS[f.type] ||
                                                        f.type}
                                                </span>
                                                <span className="finding-count">
                                                    &times;{f.count}
                                                </span>
                                            </div>
                                            <div className="finding-detail">
                                                {f.detail}
                                            </div>
                                            {f.evidence && (
                                                <div className="finding-evidence">
                                                    <code>{f.evidence}</code>
                                                </div>
                                            )}
                                            {f.samplePayloads?.length > 0 && (
                                                <div className="finding-samples">
                                                    <span className="sample-label">
                                                        Sample payloads:
                                                    </span>
                                                    {f.samplePayloads.map(
                                                        (sp, j) => (
                                                            <code
                                                                key={j}
                                                                className="sample-payload"
                                                            >
                                                                [{sp.status}]{" "}
                                                                {sp.payload}
                                                            </code>
                                                        )
                                                    )}
                                                </div>
                                            )}
                                        </div>
                                    ))}
                                </div>
                            )}
                        </div>
                    ))}
            </div>

            {/* Actions */}
            <div className="report-actions">
                <button className="btn btn-primary" onClick={onNewScan}>
                    🔄 New Scan
                </button>
                <button className="btn btn-secondary" onClick={downloadReport}>
                    📥 Download JSON
                </button>
            </div>
        </div>
    );
}
