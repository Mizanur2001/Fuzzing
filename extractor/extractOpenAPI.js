const SwaggerParser = require("swagger-parser");
const fs = require("fs");
const path = require("path");

async function extractOpenAPI(openapiUrl) {
    const api = await SwaggerParser.dereference(openapiUrl);

    const endpoints = [];
    const payloads = {};

    for (const [route, methods] of Object.entries(api.paths)) {
        for (const [method, operation] of Object.entries(methods)) {
            if (["parameters", "$ref"].includes(method)) continue;

            const key = `${method.toUpperCase()} ${route}`;

            endpoints.push({
                method: method.toUpperCase(),
                path: route,
                summary: operation.summary || "",
            });

            const endpointInfo = { body: null, pathParams: [], queryParams: [] };

            // ── Extract request body schema (POST/PUT/PATCH) ──
            if (operation.requestBody?.content?.["application/json"]) {
                endpointInfo.body = resolveSchema(
                    operation.requestBody.content["application/json"].schema,
                    api
                );
            }

            // ── Extract path and query parameters ──
            const params = [
                ...(methods.parameters || []),
                ...(operation.parameters || []),
            ];

            for (const param of params) {
                const p = param.$ref
                    ? resolveRef(param.$ref, api)
                    : param;

                const paramInfo = {
                    name: p.name,
                    type: p.schema?.type || "string",
                    required: p.required || false,
                };

                if (p.in === "path") {
                    endpointInfo.pathParams.push(paramInfo);
                } else if (p.in === "query") {
                    endpointInfo.queryParams.push(paramInfo);
                }
            }

            // Store info for every endpoint, not just those with bodies
            payloads[key] = endpointInfo;
        }
    }

    const outputDir = path.join(__dirname, "..", "output");
    if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir);

    fs.writeFileSync(
        path.join(outputDir, "endpoints.json"),
        JSON.stringify(endpoints, null, 2)
    );
    fs.writeFileSync(
        path.join(outputDir, "payloads.json"),
        JSON.stringify(payloads, null, 2)
    );

    console.log(`✅ OpenAPI extraction completed — ${endpoints.length} endpoints found`);
}

function resolveSchema(schema, api) {
    if (schema.$ref) {
        const ref = schema.$ref.replace("#/components/schemas/", "");
        return resolveSchema(api.components.schemas[ref], api);
    }

    const obj = {};
    for (const [k, v] of Object.entries(schema.properties || {})) {
        obj[k] = v.type || "string";
    }
    return obj;
}

function resolveRef(ref, api) {
    const parts = ref.replace("#/", "").split("/");
    let node = api;
    for (const p of parts) node = node[p];
    return node;
}

module.exports = extractOpenAPI;