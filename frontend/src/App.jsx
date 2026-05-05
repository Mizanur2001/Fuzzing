import { useState, useEffect, useRef } from "react";
import ConfigPanel from "./components/ConfigPanel";
import FuzzProgress from "./components/FuzzProgress";
import Report from "./components/Report";

const DEFAULT_CONFIG = {
    baseURL: "",
    OpenApiUrl: "",
    authToken: "",
    timeout: 5000,
    maxIterations: 5000,
};

export default function App() {
    const [phase, setPhase] = useState("config"); // config | running | complete | error
    const [config, setConfig] = useState(null);
    const [endpoints, setEndpoints] = useState([]);
    const [progress, setProgress] = useState(null);
    const [endpointStatus, setEndpointStatus] = useState({});
    const [report, setReport] = useState(null);
    const [error, setError] = useState(null);
    const [skipPending, setSkipPending] = useState(false);
    const esRef = useRef(null);
    const endpointTimingRef = useRef({});
    const routeDurationsRef = useRef([]);

    const withEta = (data, startedAt) => {
        const completed = Number(data.completed) || 0;
        const total = Number(data.total) || 0;
        const elapsedMs = Math.max(Date.now() - startedAt, 0);

        if (completed <= 0 || total <= 0) {
            return { ...data, startedAt, elapsedMs };
        }

        const remaining = Math.max(total - completed, 0);
        const remainingMs = Math.round((elapsedMs / completed) * remaining);
        const estimatedRouteTotalMs = Math.round((elapsedMs / completed) * total);
        const completedRouteDurations = routeDurationsRef.current;
        const averageRouteMs =
            completedRouteDurations.length > 0
                ? completedRouteDurations.reduce((sum, value) => sum + value, 0) /
                  completedRouteDurations.length
                : estimatedRouteTotalMs;
        const remainingRoutes = Math.max(
            (Number(data.totalEndpoints) || 0) - (Number(data.endpointIndex) || 0) - 1,
            0
        );
        const scanRemainingMs = Math.round(remainingMs + averageRouteMs * remainingRoutes);

        return {
            ...data,
            startedAt,
            elapsedMs,
            remainingMs,
            finishAt: Date.now() + remainingMs,
            scanRemainingMs,
            scanFinishAt: Date.now() + scanRemainingMs,
        };
    };

    // ── SSE connection ─────────────────────────────────────
    const connectSSE = () => {
        if (esRef.current) esRef.current.close();

        const es = new EventSource("/api/fuzz/events");
        esRef.current = es;

        es.addEventListener("status", (e) => {
            const data = JSON.parse(e.data);
            setProgress((prev) => ({ ...prev, phase: data.phase }));
        });

        es.addEventListener("endpoints", (e) => {
            setEndpoints(JSON.parse(e.data).list);
        });

        es.addEventListener("endpoint-start", (e) => {
            const data = JSON.parse(e.data);
            const startedAt = Date.now();
            endpointTimingRef.current[data.index] = { startedAt };
            setSkipPending(false);
            setEndpointStatus((prev) => ({
                ...prev,
                [data.index]: {
                    ...data,
                    status: "running",
                    findingsCount: 0,
                    startedAt,
                },
            }));
        });

        es.addEventListener("progress", (e) => {
            const data = JSON.parse(e.data);
            const startedAt =
                endpointTimingRef.current[data.endpointIndex]?.startedAt || Date.now();
            const progressWithEta = withEta(data, startedAt);

            setProgress((prev) => ({ ...prev, phase: "fuzzing", ...progressWithEta }));
            setEndpointStatus((prev) => ({
                ...prev,
                [data.endpointIndex]: {
                    ...prev[data.endpointIndex],
                    completed: progressWithEta.completed,
                    total: progressWithEta.total,
                    findingsCount: progressWithEta.findingsCount,
                    startedAt,
                    elapsedMs: progressWithEta.elapsedMs,
                    remainingMs: progressWithEta.remainingMs,
                    finishAt: progressWithEta.finishAt,
                    status:
                        prev[data.endpointIndex]?.status === "skipping"
                            ? "skipping"
                            : "running",
                },
            }));
        });

        es.addEventListener("endpoint-skip-requested", (e) => {
            const data = JSON.parse(e.data);
            setSkipPending(true);
            setEndpointStatus((prev) => ({
                ...prev,
                [data.index]: {
                    ...prev[data.index],
                    status: "skipping",
                },
            }));
        });

        es.addEventListener("endpoint-done", (e) => {
            const data = JSON.parse(e.data);
            const startedAt = endpointTimingRef.current[data.index]?.startedAt;
            if (startedAt && !data.skipped) {
                routeDurationsRef.current.push(Date.now() - startedAt);
            }

            setSkipPending(false);
            setEndpointStatus((prev) => ({
                ...prev,
                [data.index]: {
                    ...prev[data.index],
                    status: data.skipped ? "skipped" : "done",
                    findingsCount: data.findingsCount,
                    completed: data.completed ?? prev[data.index]?.completed,
                    total: data.total ?? prev[data.index]?.total,
                    skipped: data.skipped === true,
                    remainingMs: 0,
                },
            }));
            delete endpointTimingRef.current[data.index];
        });

        es.addEventListener("complete", async () => {
            es.close();
            try {
                const res = await fetch("/api/report");
                if (res.ok) setReport(await res.json());
            } catch {}
            setSkipPending(false);
            setPhase("complete");
        });

        es.addEventListener("fuzz-error", (e) => {
            const data = JSON.parse(e.data);
            setError(data.message);
            setSkipPending(false);
            es.close();
            setPhase("error");
        });

        es.onerror = () => {
            if (es.readyState === EventSource.CLOSED) {
                setError("Connection to server lost");
                setPhase("error");
            }
        };
    };

    // ── Init: fetch config, status, previous report ────────
    useEffect(() => {
        Promise.all([
            fetch("/api/config").then((r) => r.json()).catch(() => DEFAULT_CONFIG),
            fetch("/api/fuzz/status").then((r) => r.json()).catch(() => ({ running: false })),
            fetch("/api/report").then((r) => (r.ok ? r.json() : null)).catch(() => null),
        ]).then(([cfg, status, rpt]) => {
            setConfig(cfg);
            if (rpt) setReport(rpt);
            if (status.running) {
                setPhase("running");
                connectSSE();
            }
        });

        return () => {
            if (esRef.current) esRef.current.close();
        };
    }, []);

    // ── Start fuzzing ──────────────────────────────────────
    const startFuzzing = async () => {
        setError(null);

        // Save config first
        const saveRes = await fetch("/api/config", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(config),
        });

        if (!saveRes.ok) {
            const data = await saveRes.json().catch(() => ({}));
            setError(data.error || "Failed to save configuration");
            return;
        }

        // Start fuzzing
        const startRes = await fetch("/api/fuzz/start", { method: "POST" });

        if (!startRes.ok) {
            const data = await startRes.json().catch(() => ({}));
            setError(data.error || "Failed to start fuzzing");
            return;
        }

        // Reset & connect
        setPhase("running");
        setEndpoints([]);
        setEndpointStatus({});
        endpointTimingRef.current = {};
        routeDurationsRef.current = [];
        setProgress({ phase: "extracting" });
        setReport(null);
        setSkipPending(false);
        connectSSE();
    };

    const skipCurrentEndpoint = async () => {
        if (skipPending || progress?.phase !== "fuzzing") return;

        setSkipPending(true);
        try {
            const res = await fetch("/api/fuzz/skip-current", { method: "POST" });
            if (!res.ok) {
                const data = await res.json().catch(() => ({}));
                setError(data.error || "Failed to skip endpoint");
                setSkipPending(false);
            }
        } catch {
            setError("Failed to skip endpoint");
            setSkipPending(false);
        }
    };

    const newScan = () => {
        setPhase("config");
        setProgress(null);
        setEndpoints([]);
        setEndpointStatus({});
        endpointTimingRef.current = {};
        routeDurationsRef.current = [];
        setError(null);
        setSkipPending(false);
    };

    if (!config) {
        return (
            <div className="app loading">
                <div className="loading-card">
                    <div className="spinner" />
                    <span>Loading workspace</span>
                </div>
            </div>
        );
    }

    return (
        <div className="app">
            <nav className="navbar">
                <div className="navbar-brand">
                    <span className="logo" aria-hidden="true">
                        FF
                    </span>
                    <span className="brand-copy">
                        <span>Fuzzing Framework</span>
                        <small>API security test runner</small>
                    </span>
                    <span className="version">v4.0.0</span>
                </div>
                <div className={`phase-pill phase-${phase}`}>
                    <span className="phase-dot" />
                    {phase === "config" && "Ready"}
                    {phase === "running" && "Running"}
                    {phase === "complete" && "Report Ready"}
                    {phase === "error" && "Needs Attention"}
                </div>
            </nav>

            <main className="main-content">
                {error && (
                    <div className="error-banner">
                        <span>{error}</span>
                        <button onClick={() => setError(null)}>&times;</button>
                    </div>
                )}

                {phase === "config" && (
                    <ConfigPanel
                        config={config}
                        setConfig={setConfig}
                        onStart={startFuzzing}
                        report={report}
                        onViewReport={() => setPhase("complete")}
                    />
                )}

                {phase === "running" && (
                    <FuzzProgress
                        endpoints={endpoints}
                        endpointStatus={endpointStatus}
                        progress={progress}
                        onSkipEndpoint={skipCurrentEndpoint}
                        skipPending={skipPending}
                    />
                )}

                {phase === "complete" && report && (
                    <Report report={report} onNewScan={newScan} />
                )}

                {phase === "error" && (
                    <div className="error-panel">
                        <h2>Fuzzing Failed</h2>
                        <p>{error || "An unknown error occurred"}</p>
                        <button className="btn btn-primary" onClick={newScan}>
                            Try Again
                        </button>
                    </div>
                )}
            </main>
        </div>
    );
}
