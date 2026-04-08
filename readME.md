# Fuzzing Framework (v3.0.0)

An OpenAPI-driven web application fuzzing framework that automatically discovers API endpoints, generates context-aware fuzz payloads, and detects security vulnerabilities.

**Jadavpur University — Final Year Project**
*Mizanur Rahaman (002410502033)*

## Features

- Parses OpenAPI specifications to discover endpoints and request schemas
- **170+ fuzz payloads** across 13 vulnerability categories (SQLi, XSS, NoSQLi, command injection, SSRF, path traversal, SSTI, etc.)
- **Context-aware payload selection** — infers relevant attack payloads from field names (e.g., `email` triggers SQLi/XSS payloads, `url` triggers SSRF)
- **Automatic vulnerability detection** — pattern-based response analysis for SQLi, XSS reflection, command injection, info disclosure, and more
- **Structured vulnerability report** with severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Fuzzes **all HTTP methods** (GET, POST, PUT, DELETE) not just POST
- Response time tracking for DoS detection

## Requirements

- Node.js 18+ (recommended)
- Network access to the target API and its OpenAPI URL

## Install

```bash
npm install
```

## Configure

Edit `config/config.js`:

- `baseURL`: base server URL (example: `http://192.168.0.123:5000`)
- `OpenApiUrl`: OpenAPI spec URL (example: `http://192.168.0.123:5000/openapi.yaml`)
- `authToken`: value used for the `Authorization` header on every request (Bearer token)
- `timeout`: Axios timeout per request (ms)

## Run

```bash
node index.js
```

## Architecture

```
index.js                          # Orchestrator
├── extractor/extractOpenAPI.js   # OpenAPI spec parser
├── fuzzer/
│   ├── payloadDictionary.js      # 170+ categorized vulnerability payloads
│   ├── fuzzGenerator.js          # Context-aware payload selection engine
│   └── fuzzRunner.js             # HTTP execution + analyzer integration
├── analyzer/
│   ├── vulnerabilityAnalyzer.js  # Response-based vuln detection (pattern matching)
│   └── reportGenerator.js        # Structured report output
├── config/config.js              # Target + auth configuration
└── output/
    ├── endpoints.json            # Discovered API endpoints
    ├── payloads.json             # Extracted request schemas
    ├── results.json              # Raw fuzz results
    └── vulnerability-report.json # Vulnerability findings report
```

## How It Works

1. **Extract** — Parses the OpenAPI spec to discover endpoints and their request body schemas.
2. **Generate** — For each field, selects fuzz payloads based on:
   - Field name semantics (e.g., `password` → auth bypass + SQLi payloads)
   - Field type (string vs number payloads)
   - Single-field mutation (one field at a time) + multi-field mutation + edge cases
3. **Execute** — Sends crafted HTTP requests and records status, response, and timing.
4. **Analyze** — Checks each response for vulnerability indicators:
   - SQL error patterns in responses (SQLi)
   - Reflected XSS payloads in response bodies
   - Command output patterns (command injection)
   - Stack traces and sensitive data leaks (info disclosure)
   - High response times (DoS potential)
5. **Report** — Generates `vulnerability-report.json` with findings sorted by severity.

## Vulnerability Categories Tested

| Category | Payloads | Severity |
|---|---|---|
| SQL Injection | `' OR '1'='1`, UNION SELECT, SLEEP(), etc. | CRITICAL |
| NoSQL Injection | `{$gt: ""}`, `{$ne: null}`, prototype pollution | CRITICAL |
| XSS | `<script>`, `<img onerror>`, `<svg onload>`, template injection | HIGH |
| Command Injection | `; ls -la`, `| cat /etc/passwd`, `` `id` `` | CRITICAL |
| Path Traversal | `../../etc/passwd`, encoded variants | HIGH |
| SSRF | `http://169.254.169.254`, localhost variants | HIGH |
| Template Injection | `{{7*7}}`, `${7*7}` | HIGH |
| Prototype Pollution | `__proto__`, constructor overwrite | MEDIUM |
| Buffer Overflow | Long strings (256–65536 chars), format strings | MEDIUM |
| Type Confusion | `null`, `NaN`, `Infinity`, arrays, booleans | LOW |

## Output Files

- `output/endpoints.json` — discovered routes/methods from OpenAPI
- `output/payloads.json` — map of `"METHOD /path"` → extracted request schema
- `output/results.json` — raw fuzz results per endpoint
- `output/vulnerability-report.json` — vulnerability findings with severity, type, evidence, and payload

## References

1. Dharmaadi, I. P. A., Athanasopoulos, E., & Turkmen, F. (2025). Fuzzing frameworks for server-side web applications: a survey. *International Journal of Information Security*, 24, 73.
2. Zhang, A., Zhang, Y., Xu, Y., Wang, C., & Li, S. (2024). Machine Learning-Based Fuzz Testing Techniques: A Survey. *IEEE Access*, 12, 14437–14454.
3. Ferech, M. & Tvrdik, P. (2023). Efficient fuzz testing of web services. *IEEE QRS*, 291–300.
4. Hammersland, R. & Snekkenes, E. (2008). Fuzz testing of web applications. *ARES*, 356–363.

## Troubleshooting

- Seeing `timeout of XXXXms exceeded`: increase `timeout` in `config/config.js` or check server connectivity/performance.
- OpenAPI extraction fails: verify `OpenApiUrl` is reachable and returns a valid OpenAPI document.