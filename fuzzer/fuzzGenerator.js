const { getPayloadsForField, inferCategoriesFromFieldName, PAYLOAD_CATEGORIES } = require("./payloadDictionary");

/**
 * Generate fuzz payloads using the smart payload dictionary.
 *
 * Strategy (inspired by Ferech & Tvrdik 2023, Dharmaadi et al. 2025):
 *   Phase 1 — Single-field body mutation
 *   Phase 2 — Multi-field body mutation
 *   Phase 3 — Path parameter fuzzing
 *   Phase 4 — Query parameter fuzzing
 *   Phase 5 — Authentication variation (BOLA / broken auth)
 *   Phase 6 — Edge cases (empty, null, overflow)
 *
 * @param {Object} endpointInfo - { body, pathParams, queryParams } from extractor
 * @param {string} method       - HTTP method
 * @returns {Array} array of { payload, meta } objects
 */
function generateFuzzPayloads(endpointInfo, method) {
    const cases = [];

    // Normalize: support both old format ({field:type}) and new format ({body, pathParams, queryParams})
    let body = null;
    let pathParams = [];
    let queryParams = [];

    if (endpointInfo && endpointInfo.body !== undefined) {
        body = endpointInfo.body;
        pathParams = endpointInfo.pathParams || [];
        queryParams = endpointInfo.queryParams || [];
    } else if (endpointInfo && typeof endpointInfo === "object") {
        // Old format: treat as body schema
        body = endpointInfo;
    }

    const bodyFields = body ? Object.keys(body) : [];

    // ═══════════════════════════════════════════════════════════
    //  Phase 1: Single-field body mutation
    // ═══════════════════════════════════════════════════════════
    if (body && bodyFields.length > 0) {
        for (const targetField of bodyFields) {
            const payloads = getPayloadsForField(targetField, body[targetField]);
            const categories = inferCategoriesFromFieldName(targetField);

            for (const value of payloads) {
                const payload = {};
                for (const k of bodyFields) payload[k] = "test";
                payload[targetField] = value;

                cases.push({
                    payload,
                    meta: {
                        strategy: "single-field",
                        targetField,
                        categories,
                        location: "body",
                    },
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 2: Multi-field body mutation
    // ═══════════════════════════════════════════════════════════
    if (body && bodyFields.length > 1) {
        const sharedCategories = [
            "sql_injection", "xss", "nosql_injection", "command_injection",
        ];

        for (const category of sharedCategories) {
            const catPayloads = PAYLOAD_CATEGORIES[category] || [];
            if (catPayloads.length === 0) continue;

            const payload = {};
            for (const field of bodyFields) {
                // Pick first string payload from the category
                const pick = catPayloads.find(p => typeof p === "string");
                payload[field] = pick || "test";
            }

            cases.push({
                payload,
                meta: {
                    strategy: "multi-field",
                    targetField: "*",
                    categories: [category],
                    location: "body",
                },
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 3: Path parameter fuzzing
    // ═══════════════════════════════════════════════════════════
    for (const param of pathParams) {
        const payloads = getPayloadsForField(param.name, param.type);
        const categories = inferCategoriesFromFieldName(param.name);

        for (const value of payloads) {
            cases.push({
                payload: value,
                meta: {
                    strategy: "path-param",
                    targetField: param.name,
                    categories,
                    location: "path",
                },
            });
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 4: Query parameter fuzzing (for GET/DELETE endpoints)
    // ═══════════════════════════════════════════════════════════
    for (const param of queryParams) {
        const payloads = getPayloadsForField(param.name, param.type);
        const categories = inferCategoriesFromFieldName(param.name);

        for (const value of payloads) {
            cases.push({
                payload: { [param.name]: value },
                meta: {
                    strategy: "query-param",
                    targetField: param.name,
                    categories,
                    location: "query",
                },
            });
        }
    }

    // For GET endpoints with no defined params, send common fuzzing query strings
    if (["GET", "DELETE"].includes(method) && queryParams.length === 0 && bodyFields.length === 0) {
        const probingParams = ["id", "search", "q", "filter", "page", "limit", "sort", "order"];
        for (const pName of probingParams) {
            const payloads = getPayloadsForField(pName, "string").slice(0, 15); // top 15 per param
            const categories = inferCategoriesFromFieldName(pName);

            for (const value of payloads) {
                cases.push({
                    payload: { [pName]: value },
                    meta: {
                        strategy: "probe-param",
                        targetField: pName,
                        categories,
                        location: "query",
                    },
                });
            }
        }
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 5: Authentication variation (BOLA / broken auth)
    // ═══════════════════════════════════════════════════════════
    const authFuzzCases = [
        { label: "no-token",      token: "" },
        { label: "empty-bearer",  token: "Bearer " },
        { label: "invalid-token", token: "Bearer invalidtoken123" },
        { label: "null-bearer",   token: "Bearer null" },
        { label: "alg-none",      token: "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwicm9sZSI6ImFkbWluIn0." },
        { label: "expired-jwt",   token: "Bearer eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjB9.invalid" },
        { label: "sql-in-token",  token: "Bearer ' OR '1'='1" },
        { label: "no-header",     token: null },
    ];

    // Send a valid body (or empty) for each auth variation
    const validBody = {};
    if (body) {
        for (const k of bodyFields) validBody[k] = "test";
    }

    for (const authCase of authFuzzCases) {
        cases.push({
            payload: bodyFields.length > 0 ? { ...validBody } : {},
            meta: {
                strategy: "auth-fuzz",
                targetField: "Authorization",
                categories: ["auth_bypass", "jwt_attacks"],
                location: "header",
                authOverride: authCase.token,
                authLabel: authCase.label,
            },
        });
    }

    // ═══════════════════════════════════════════════════════════
    //  Phase 6: Edge cases
    // ═══════════════════════════════════════════════════════════
    cases.push({
        payload: {},
        meta: { strategy: "edge-case", targetField: "*", categories: ["special_chars"], location: "body" },
    });

    if (bodyFields.length > 0) {
        const nullPayload = {};
        for (const k of bodyFields) nullPayload[k] = null;
        cases.push({
            payload: nullPayload,
            meta: { strategy: "edge-case", targetField: "*", categories: ["type_confusion"], location: "body" },
        });

        const emptyPayload = {};
        for (const k of bodyFields) emptyPayload[k] = "";
        cases.push({
            payload: emptyPayload,
            meta: { strategy: "edge-case", targetField: "*", categories: ["special_chars"], location: "body" },
        });
    }

    return cases;
}

module.exports = generateFuzzPayloads;