export default function FuzzProgress({ endpoints, endpointStatus, progress }) {
    const currentPhase = progress?.phase || "extracting";

    return (
        <div className="progress-section">
            <div className="panel-header">
                <h2>
                    {currentPhase === "extracting" &&
                        "📥 Extracting OpenAPI Specification..."}
                    {currentPhase === "fuzzing" && "🔥 Fuzzing in Progress"}
                    {currentPhase === "reporting" && "📄 Generating Report..."}
                </h2>
            </div>

            {currentPhase === "fuzzing" && progress?.total > 0 && (
                <div className="current-progress">
                    <div className="progress-info">
                        <span className="endpoint-name">
                            Endpoint {(progress.endpointIndex || 0) + 1}/
                            {progress.totalEndpoints || "?"}: {progress.endpoint}
                        </span>
                        <span className="progress-stats">
                            {progress.completed}/{progress.total} requests &middot;{" "}
                            {progress.findingsCount} findings
                        </span>
                    </div>
                    <div className="progress-bar-container">
                        <div
                            className="progress-bar-fill"
                            style={{
                                width: `${Math.round((progress.completed / progress.total) * 100)}%`,
                            }}
                        />
                    </div>
                    <div className="progress-pct">
                        {Math.round((progress.completed / progress.total) * 100)}%
                    </div>
                </div>
            )}

            {(currentPhase === "extracting" || currentPhase === "reporting") && (
                <div className="spinner-container">
                    <div className="spinner" />
                </div>
            )}

            {endpoints.length > 0 && (
                <div className="endpoint-list">
                    <h3>Endpoints</h3>
                    {endpoints.map((ep, i) => {
                        const st = endpointStatus[i];
                        const isDone = st?.status === "done";
                        const isRunning = st?.status === "running";

                        return (
                            <div
                                key={i}
                                className={`endpoint-item ${isDone ? "done" : isRunning ? "running" : "pending"}`}
                            >
                                <span className="endpoint-icon">
                                    {isDone ? "✅" : isRunning ? "🔄" : "⏳"}
                                </span>
                                <span
                                    className={`method method-${ep.method.toLowerCase()}`}
                                >
                                    {ep.method}
                                </span>
                                <span className="ep-path">{ep.path}</span>
                                {isDone && (
                                    <span className="findings-badge">
                                        {st.findingsCount} findings
                                    </span>
                                )}
                                {isRunning && st.total > 0 && (
                                    <span className="findings-badge running">
                                        {st.completed}/{st.total}
                                    </span>
                                )}
                            </div>
                        );
                    })}
                </div>
            )}
        </div>
    );
}
