# Fuzzing Framework (v4.0.0)

An OpenAPI-driven web application fuzzing framework that automatically discovers API endpoints, generates context-aware fuzz payloads, and detects security vulnerabilities with finding deduplication and false-positive elimination.

**Jadavpur University — Final Year Project**
*Mizanur Rahaman (002410502033)*

## Features

- Parses OpenAPI specifications to discover **all** endpoints (GET, POST, PUT, DELETE, PATCH)
- **909 fuzz payloads** across **28 vulnerability categories** (SQLi, NoSQLi, XSS, CMDi, SSRF, Path Traversal, SSTI, XXE, LDAP, JWT Attacks, Prototype Pollution, ReDoS, IDOR, CORS, CSV Injection, and more)
- **Context-aware payload selection** — infers relevant attack payloads from field names (e.g., `email` triggers SQLi/XSS/LDAP payloads, `url` triggers SSRF/open redirect)
- **6-phase payload generation**:
  1. Single-field body mutation
  2. Multi-field body mutation (all categories)
  3. Path parameter fuzzing
  4. Query parameter fuzzing (with probe params for GET endpoints)
  5. Authentication variation (8 auth bypass cases: no-token, empty-bearer, invalid-token, null-bearer, alg-none JWT, expired-jwt, sql-in-token, no-header)
  6. Edge cases (empty, all-null, all-empty-string)
- **9-strategy vulnerability detection**:
  - Payload-echo-aware pattern matching (strips injected values from responses)
  - Blind injection via timing anomaly (baseline comparison)
  - Broken authentication / BOLA (skips login/health endpoints to avoid FP)
  - IDOR via MongoDB ObjectId CastError analysis
  - Reflected XSS detection
  - Template injection confirmation ({{7*7}} → 49)
  - Information disclosure (stack traces, env vars)
  - Rate-limit detection (flags if 50+ rapid requests accepted without HTTP 429)
  - DoS indicator (response time > 10s)
- **Finding deduplication** — groups identical root causes, shows count + sample payloads
- **Structured vulnerability report** with severity classification (CRITICAL/HIGH/MEDIUM/LOW)
- Response time tracking with timing-based blind injection detection

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
- `maxIterations`: maximum payloads per endpoint (default: 5000)

## Run

```bash
npm run fuzz         # Full run (extract + fuzz + report)
npm run extract      # Extract endpoints only
node index.js        # Same as npm run fuzz
```

## Architecture

```
index.js                          # Orchestrator — extracts, fuzzes all endpoints, generates report
├── extractor/extractOpenAPI.js   # OpenAPI spec parser (body, path params, query params)
├── fuzzer/
│   ├── payloadDictionary.js      # 909 categorized payloads, 28 OWASP categories
│   ├── fuzzGenerator.js          # 6-phase context-aware payload engine
│   └── fuzzRunner.js             # HTTP execution, baseline timing, auth variation, rate-limit check
├── analyzer/
│   ├── vulnerabilityAnalyzer.js  # 9-strategy detection engine with payload-echo stripping
│   └── reportGenerator.js        # Deduplicated report with severity breakdown
├── config/config.js              # Target + auth configuration
└── output/
    ├── endpoints.json            # Discovered API endpoints
    ├── payloads.json             # Extracted request schemas (body + path + query params)
    ├── results.json              # Raw fuzz results per endpoint
    └── vulnerability-report.json # Deduplicated vulnerability report
```

## How It Works

1. **Extract** — Parses the OpenAPI spec to discover all endpoints and their request schemas (body fields, path parameters, query parameters).
2. **Generate** — For each endpoint, produces fuzz payloads across 6 phases:
   - **Phase 1**: Single-field body mutation (one field fuzzed at a time)
   - **Phase 2**: Multi-field body mutation (all categories applied)
   - **Phase 3**: Path parameter fuzzing (`/api/:id` → `/api/<payload>`)
   - **Phase 4**: Query parameter fuzzing (defined params + probe params for GET endpoints with no params)
   - **Phase 5**: Authentication variation (8 auth bypass cases)
   - **Phase 6**: Edge cases (empty body, all-null, all-empty-string)
3. **Execute** — Sends crafted HTTP requests with:
   - Baseline response time measurement (3 valid requests, takes worst)
   - Auth header override per auth-fuzz strategy
   - Payload routing: body → POST data, path → URL substitution, query → URL params
   - Rate-limit tracking (consecutive 2xx without 429)
4. **Analyze** — 9-strategy detection engine checks each response:
   - **Pattern matching** on cleaned text (payload echo stripped) for SQL/NoSQL/XSS/CMDi/SSRF/SSTI errors
   - **IDOR detection** via MongoDB ObjectId CastError
   - **Reflected XSS** — checks if known XSS payloads appear in response body
   - **Blind injection** — flags responses > 3× baseline (min 4s)
   - **Broken auth** — flags 200 responses to auth-fuzz requests (skips login/register/health endpoints)
   - **Info disclosure** — stack traces, env vars, debug output
   - **Rate limit** — flags endpoints accepting 50+ requests without throttling
   - **DoS** — flags response times > 10s
5. **Report** — Generates deduplicated vulnerability report sorted by severity. Each unique finding shows occurrence count and up to 3 sample payloads.

## Payload Categories (28)

| # | Category | Payloads | Severity |
|---|---|---|---|
| 1 | SQL Injection | 70 | CRITICAL |
| 2 | NoSQL Injection | 40 | CRITICAL |
| 3 | XSS (Cross-Site Scripting) | 80 | HIGH |
| 4 | Command Injection | 50 | CRITICAL |
| 5 | Path Traversal / LFI / RFI | 45 | HIGH |
| 6 | SSRF | 45 | HIGH |
| 7 | Template Injection (SSTI) | 35 | HIGH |
| 8 | XXE | 25 | HIGH |
| 9 | LDAP Injection | 15 | MEDIUM |
| 10 | Header Injection / CRLF | 20 | MEDIUM |
| 11 | Prototype Pollution | 20 | HIGH |
| 12 | Type Confusion / Mass Assignment | 41 | LOW |
| 13 | Buffer Overflow / Format String | 20 | MEDIUM |
| 14 | Special Characters / Encoding | 52 | LOW |
| 15 | Auth Bypass | 30 | HIGH |
| 16 | Open Redirect | 37 | MEDIUM |
| 17 | IDOR | 40 | HIGH |
| 18 | Mass Assignment | 45 | HIGH |
| 19 | ReDoS | 25 | MEDIUM |
| 20 | Log Injection | 20 | MEDIUM |
| 21 | HTTP Parameter Pollution | 20 | MEDIUM |
| 22 | JSON Injection / Deserialization | 25 | HIGH |
| 23 | CSV / Formula Injection | 15 | MEDIUM |
| 24 | Email Header Injection | 15 | MEDIUM |
| 25 | CORS Misconfiguration | 15 | MEDIUM |
| 26 | Business Logic / Boundary | 25 | MEDIUM |
| 27 | GraphQL Injection | 20 | HIGH |
| 28 | JWT Attacks | 20 | HIGH |

**Total: 909 payloads**

## Detection Capabilities

| Vulnerability Type | Detection Method |
|---|---|
| SQL/NoSQL Injection | Error pattern matching on cleaned response |
| Blind SQL/NoSQL/CMD Injection | Timing-based (3× baseline, min 4s) |
| XSS (Reflected) | Payload reflection check in response |
| Command Injection | OS output patterns (uid=, root:, etc.) |
| SSRF | Cloud metadata patterns (169.254.x, ami-id) |
| Template Injection | Expression evaluation ({{7*7}} → 49) |
| IDOR | MongoDB ObjectId CastError analysis |
| Broken Authentication | Auth-fuzz with invalid/expired/none tokens |
| Information Disclosure | Stack traces, env vars, debug info |
| Missing Rate Limit | 50+ requests without HTTP 429 |
| DoS Potential | Response time > 10 seconds |
| Server Errors | HTTP 5xx detection |

## Output Files

- `output/endpoints.json` — discovered routes/methods from OpenAPI
- `output/payloads.json` — map of `"METHOD /path"` → extracted request schema (body, path params, query params)
- `output/results.json` — raw fuzz results per endpoint
- `output/vulnerability-report.json` — deduplicated vulnerability report with severity, type, evidence, count, and sample payloads

## Sample Report Output

```
════════════════════════════════════════════════════════════
  VULNERABILITY SCAN REPORT — v4.0.0
════════════════════════════════════════════════════════════
  Endpoints tested : 8
  Total requests   : 2519
  Raw findings     : 4238
  Unique findings  : 47
────────────────────────────────────────────────────────────
  SEVERITY BREAKDOWN:
    🟠 HIGH      : 543
    🟡 MEDIUM    : 2466
    ⚪ LOW       : 1229
────────────────────────────────────────────────────────────
  VULNERABILITY TYPES:
    Improper Input Validation: 1232
    Server Error (5xx): 1229
    Information Disclosure: 1229
    IDOR: 509
    Broken Authentication: 30
    Missing Rate Limit: 5
    Reflected XSS: 2
    SSRF: 2
════════════════════════════════════════════════════════════
```

## References

1. Dharmaadi, I. P. A., Athanasopoulos, E., & Turkmen, F. (2025). Fuzzing frameworks for server-side web applications: a survey. *International Journal of Information Security*, 24, 73.
2. Zhang, A., Zhang, Y., Xu, Y., Wang, C., & Li, S. (2024). Machine Learning-Based Fuzz Testing Techniques: A Survey. *IEEE Access*, 12, 14437–14454.
3. Ferech, M. & Tvrdik, P. (2023). Efficient fuzz testing of web services. *IEEE QRS*, 291–300.
4. Hammersland, R. & Snekkenes, E. (2008). Fuzz testing of web applications. *ARES*, 356–363.
5. OWASP API Security Top 10 (2023) — API1:2023 BOLA, API2:2023 Broken Auth.
6. OWASP Web Security Testing Guide v4.2 (WSTG).

## Changelog

### v4.0.0
- Fuzz **all** endpoints (GET, POST, PUT, DELETE, PATCH) — not just POST with body
- 6-phase payload generation (body, path params, query params, probe params, auth variation, edge cases)
- **909 payloads** across **28 categories** (was 170+ across 13)
- Authentication variation testing (8 auth bypass strategies)
- Timing-based blind injection detection (baseline comparison)
- Rate-limit detection (consecutive 50+ requests without 429)
- Finding deduplication (same root cause counted once per endpoint)
- False-positive elimination (login/register/health endpoints excluded from auth findings)
- Endpoint path passed to analyzer for context-aware detection

### v3.0.0
- Smart payload selection using field name heuristics
- Payload-echo stripping to eliminate false positives
- IDOR detection, reflected XSS, template injection confirmation
- 170+ payloads across 13 categories

## Troubleshooting

- Seeing `timeout of XXXXms exceeded`: increase `timeout` in `config/config.js` or check server connectivity.
- OpenAPI extraction fails: verify `OpenApiUrl` is reachable and returns a valid OpenAPI document.
- Auth findings on public endpoints: the framework auto-skips login/register/health endpoints. For other intentionally-public endpoints, check the `isHealthEndpoint` regex in `vulnerabilityAnalyzer.js`.