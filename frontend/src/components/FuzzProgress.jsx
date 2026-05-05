import { useEffect, useState } from "react";

const formatDuration = (ms) => {
    if (!Number.isFinite(ms) || ms < 0) return "estimating";
    if (ms < 1000) return "under 1s";

    const totalSeconds = Math.ceil(ms / 1000);
    const hours = Math.floor(totalSeconds / 3600);
    const minutes = Math.floor((totalSeconds % 3600) / 60);
    const seconds = totalSeconds % 60;

    if (hours > 0) return `${hours}h ${minutes}m`;
    if (minutes > 0) return `${minutes}m ${seconds}s`;
    return `${seconds}s`;
};

const formatClock = (time) => {
    if (!time) return "estimating";
    return new Date(time).toLocaleTimeString([], {
        hour: "numeric",
        minute: "2-digit",
    });
};

export default function FuzzProgress({
    endpoints,
    endpointStatus,
    progress,
    onSkipEndpoint,
    skipPending,
}) {
    const currentPhase = progress?.phase || "extracting";
    const [now, setNow] = useState(Date.now());

    useEffect(() => {
        if (currentPhase !== "fuzzing") return undefined;

        const timer = window.setInterval(() => setNow(Date.now()), 1000);
        return () => window.clearInterval(timer);
    }, [currentPhase]);

    const remainingMs =
        progress?.finishAt && progress.finishAt > now
            ? progress.finishAt - now
            : progress?.remainingMs;
    const scanRemainingMs =
        progress?.scanFinishAt && progress.scanFinishAt > now
            ? progress.scanFinishAt - now
            : progress?.scanRemainingMs;
    const elapsedMs = progress?.startedAt ? now - progress.startedAt : progress?.elapsedMs;

    return (
        <div className="progress-section">
            <div className="panel-header">
                <div>
                    <p className="eyebrow">Live Scan</p>
                    <h2>
                        {currentPhase === "extracting" &&
                            "Extracting OpenAPI Specification"}
                        {currentPhase === "fuzzing" && "Fuzzing in Progress"}
                        {currentPhase === "reporting" && "Generating Report"}
                    </h2>
                </div>
            </div>

            {currentPhase === "fuzzing" && progress?.total > 0 && (
                <div className="current-progress">
                    <div className="progress-info">
                        <div>
                            <span className="endpoint-name">
                                Endpoint {(progress.endpointIndex || 0) + 1}/
                                {progress.totalEndpoints || "?"}: {progress.endpoint}
                            </span>
                            <span className="progress-stats">
                                {progress.completed}/{progress.total} requests &middot;{" "}
                                {progress.findingsCount} findings
                            </span>
                        </div>
                        <button
                            type="button"
                            className="btn btn-warning btn-sm"
                            onClick={onSkipEndpoint}
                            disabled={skipPending}
                        >
                            {skipPending ? "Skipping..." : "Skip Endpoint"}
                        </button>
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
                    <div className="eta-grid">
                        <div className="eta-card">
                            <span>Route ETA</span>
                            <strong>{formatDuration(remainingMs)}</strong>
                        </div>
                        <div className="eta-card">
                            <span>Expected Finish</span>
                            <strong>{formatClock(progress.finishAt)}</strong>
                        </div>
                        <div className="eta-card">
                            <span>Scan ETA</span>
                            <strong>{formatDuration(scanRemainingMs)}</strong>
                        </div>
                        <div className="eta-card">
                            <span>Elapsed</span>
                            <strong>{formatDuration(elapsedMs)}</strong>
                        </div>
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
                        const isSkipping = st?.status === "skipping";
                        const isSkipped = st?.status === "skipped";

                        return (
                            <div
                                key={i}
                                className={`endpoint-item ${
                                    isDone
                                        ? "done"
                                        : isRunning
                                          ? "running"
                                          : isSkipping
                                            ? "skipping"
                                            : isSkipped
                                              ? "skipped"
                                              : "pending"
                                }`}
                            >
                                <span className="endpoint-icon" aria-hidden="true" />
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
                                {isSkipped && (
                                    <span className="findings-badge skipped">
                                        skipped
                                    </span>
                                )}
                                {isSkipping && (
                                    <span className="findings-badge warning">
                                        skipping...
                                    </span>
                                )}
                                {isRunning && st.total > 0 && (
                                    <span className="findings-badge running">
                                        ETA{" "}
                                        {formatDuration(
                                            st.finishAt && st.finishAt > now
                                                ? st.finishAt - now
                                                : st.remainingMs
                                        )}
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
