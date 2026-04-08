const { getPayloadsForField, inferCategoriesFromFieldName } = require("./payloadDictionary");

/**
 * Generate fuzz payloads using the smart payload dictionary.
 *
 * Strategy (inspired by Ferech & Tvrdik 2023, Dharmaadi et al. 2025):
 *   1. For each field, select payloads based on field name semantics and type.
 *   2. Single-field mutation: mutate one field at a time, keep others valid.
 *   3. Multi-field mutation: mutate all fields simultaneously for edge cases.
 *   4. Tag each payload with the vulnerability category being tested.
 *
 * @param {Object} schema - field name → type mapping from OpenAPI
 * @returns {Array} array of { payload, meta } objects
 */
function generateFuzzPayloads(schema) {
    const cases = [];
    const fields = Object.keys(schema);

    // ── Phase 1: Single-field mutation ──────────────────────
    // Mutate one field at a time, keep others as valid defaults
    for (const targetField of fields) {
        const payloads = getPayloadsForField(targetField, schema[targetField]);
        const categories = inferCategoriesFromFieldName(targetField);

        for (const value of payloads) {
            const payload = {};
            for (const k of fields) payload[k] = "test";
            payload[targetField] = value;

            cases.push({
                payload,
                meta: {
                    strategy: "single-field",
                    targetField,
                    categories,
                }
            });
        }
    }

    // ── Phase 2: Multi-field mutation ───────────────────────
    // Mutate ALL fields simultaneously with payloads from the same category
    const sharedCategories = ["sql_injection", "xss", "nosql_injection", "command_injection"];

    for (const category of sharedCategories) {
        const payload = {};
        let hasPayload = false;

        for (const field of fields) {
            const fieldPayloads = getPayloadsForField(field, schema[field]);
            // pick a payload from this category if available
            const match = fieldPayloads.find(p =>
                typeof p === "string" && getPayloadsForField(field, schema[field]).includes(p)
            );
            if (match) {
                payload[field] = match;
                hasPayload = true;
            } else {
                payload[field] = "test";
            }
        }

        if (hasPayload) {
            cases.push({
                payload,
                meta: {
                    strategy: "multi-field",
                    targetField: "*",
                    categories: [category],
                }
            });
        }
    }

    // ── Phase 3: Edge-case payloads ─────────────────────────
    // Empty object, huge values, missing fields
    cases.push({
        payload: {},
        meta: { strategy: "edge-case", targetField: "*", categories: ["special_chars"] }
    });

    // All fields null
    const nullPayload = {};
    for (const k of fields) nullPayload[k] = null;
    cases.push({
        payload: nullPayload,
        meta: { strategy: "edge-case", targetField: "*", categories: ["type_confusion"] }
    });

    // All fields empty string
    const emptyPayload = {};
    for (const k of fields) emptyPayload[k] = "";
    cases.push({
        payload: emptyPayload,
        meta: { strategy: "edge-case", targetField: "*", categories: ["special_chars"] }
    });

    return cases;
}

module.exports = generateFuzzPayloads;