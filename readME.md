# Fuzzing Framework (v2.0.0)

A small Node.js fuzzing framework that:

1. downloads/parses an OpenAPI spec,
2. extracts JSON request-body schemas,
3. generates fuzz payloads,
4. fuzzes all **POST** endpoints and saves responses/errors.

## Requirements

- Node.js 18+ (recommended)
- Network access to the target API and the OpenAPI URL

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
- `maxIterations`: present in config but not currently used by the code

Security note: avoid committing real tokens. Prefer injecting the token at runtime (environment variable, local config not committed, etc.).

## Run

```bash
node index.js
```

## What It Does

- Creates the `output/` directory if missing.
- If `output/payloads.json` is missing, it dereferences the OpenAPI spec and writes:
	- `output/endpoints.json`
	- `output/payloads.json`
- Loads `output/payloads.json`.
- Fuzzes **only POST endpoints** found there.
- Saves results to `output/results.json`.

## Output Files

- `output/endpoints.json`: list of discovered routes/methods from OpenAPI
- `output/payloads.json`: map of `"METHOD /path"` → extracted request-body schema (field → type)
- `output/results.json`: map of `"/path"` → array of fuzz attempts

Each fuzz attempt contains:

- `payload`: the JSON payload sent
- `status`: HTTP status code, or `"ERROR"`
- `response`: response body on success
- `error`: error response or message on failure (e.g., timeouts)

## Fuzz Payload Strategy

Implemented in `fuzzer/fuzzGenerator.js`:

- For each field in the schema, generates cases that mutate only that field.
- String-like fields use values such as empty string, quotes, SQL-ish string, script tag, path traversal, very long string, unicode.
- Number/integer fields use values such as `0`, `-1`, `999999999`, `NaN`, `Infinity`.
- All other fields default to `"test"` in each payload.

## Troubleshooting

- Seeing `timeout of XXXXms exceeded`: increase `timeout` in `config/config.js` or check server connectivity/performance.
- OpenAPI extraction fails: verify `OpenApiUrl` is reachable and returns a valid OpenAPI document.