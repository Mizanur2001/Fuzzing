import { useState } from "react";

export default function ConfigPanel({ config, setConfig, onStart, report, onViewReport }) {
    const [starting, setStarting] = useState(false);

    const handleChange = (field, value) => {
        setConfig((prev) => ({ ...prev, [field]: value }));
    };

    const handleStart = async () => {
        setStarting(true);
        await onStart();
        setStarting(false);
    };

    return (
        <div className="config-panel">
            <div className="panel-header">
                <h2>Target Configuration</h2>
                <p className="subtitle">
                    Configure the target API server and authentication settings
                </p>
            </div>

            <div className="form-group">
                <label>Base URL</label>
                <input
                    type="url"
                    value={config.baseURL}
                    onChange={(e) => handleChange("baseURL", e.target.value)}
                    placeholder="http://192.168.68.124:5000"
                />
            </div>

            <div className="form-group">
                <label>OpenAPI Spec URL</label>
                <input
                    type="url"
                    value={config.OpenApiUrl}
                    onChange={(e) => handleChange("OpenApiUrl", e.target.value)}
                    placeholder="http://192.168.68.124:5000/openapi.yaml"
                />
            </div>

            <div className="form-group">
                <label>Auth Token (Bearer)</label>
                <textarea
                    value={config.authToken}
                    onChange={(e) => handleChange("authToken", e.target.value)}
                    placeholder="Bearer eyJhbGciOiJIUzI1NiIs..."
                    rows={3}
                />
            </div>

            <div className="form-row">
                <div className="form-group">
                    <label>Timeout (ms)</label>
                    <input
                        type="number"
                        value={config.timeout}
                        onChange={(e) =>
                            handleChange("timeout", parseInt(e.target.value) || 5000)
                        }
                    />
                </div>
                <div className="form-group">
                    <label>Max Iterations</label>
                    <input
                        type="number"
                        value={config.maxIterations}
                        onChange={(e) =>
                            handleChange("maxIterations", parseInt(e.target.value) || 5000)
                        }
                    />
                </div>
            </div>

            <div className="form-actions">
                <button
                    className="btn btn-primary btn-lg"
                    onClick={handleStart}
                    disabled={starting || !config.baseURL || !config.OpenApiUrl}
                >
                    {starting ? "Starting..." : "\uD83D\uDD25 Start Fuzzing"}
                </button>

                {report && (
                    <button className="btn btn-secondary" onClick={onViewReport}>
                        📊 View Last Report
                    </button>
                )}
            </div>
        </div>
    );
}
