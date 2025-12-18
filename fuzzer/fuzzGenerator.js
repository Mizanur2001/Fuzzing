const FUZZ_STRINGS = [
    "", " ", "null", "'", "\"",
    "' OR '1'='1",
    "<script>alert(1)</script>",
    "../../etc/passwd",
    "A".repeat(5000),
    "😀🔥💥"
];

const FUZZ_NUMBERS = [
    0, -1, 999999999, NaN, Infinity
];

function fuzzValue(type) {
    return type === "number" || type === "integer"
        ? FUZZ_NUMBERS
        : FUZZ_STRINGS;
}

function generateFuzzPayloads(schema) {
    const cases = [];

    for (const field of Object.keys(schema)) {
        fuzzValue(schema[field]).forEach(value => {
            const payload = {};
            for (const k in schema) payload[k] = "test";
            payload[field] = value;
            cases.push(payload);
        });
    }

    return cases;
}

module.exports = generateFuzzPayloads;