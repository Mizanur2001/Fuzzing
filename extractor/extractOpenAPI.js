const SwaggerParser = require("swagger-parser");
const fs = require("fs");
const path = require("path");

async function extractOpenAPI(openapiUrl) {
    const api = await SwaggerParser.dereference(openapiUrl);

    const endpoints = [];
    const payloads = {};

    for (const [route, methods] of Object.entries(api.paths)) {
        for (const [method, operation] of Object.entries(methods)) {
            const key = `${method.toUpperCase()} ${route}`;

            endpoints.push({
                method: method.toUpperCase(),
                path: route,
                summary: operation.summary || ""
            });

            if (operation.requestBody?.content?.["application/json"]) {
                payloads[key] = resolveSchema(
                    operation.requestBody.content["application/json"].schema,
                    api
                );
            }
        }
    }

    fs.writeFileSync("output/endpoints.json", JSON.stringify(endpoints, null, 2));
    fs.writeFileSync("output/payloads.json", JSON.stringify(payloads, null, 2));

    console.log("✅ OpenAPI extraction completed");
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

module.exports = extractOpenAPI;