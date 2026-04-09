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
    const esRef = useRef(null);

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
            setEndpointStatus((prev) => ({
                ...prev,
                [data.index]: { ...data, status: "running", findingsCount: 0 },
            }));
        });

        es.addEventListener("progress", (e) => {
            const data = JSON.parse(e.data);
            setProgress((prev) => ({ ...prev, phase: "fuzzing", ...data }));
            setEndpointStatus((prev) => ({
                ...prev,
                [data.endpointIndex]: {
                    ...prev[data.endpointIndex],
                    completed: data.completed,
                    total: data.total,
                    findingsCount: data.findingsCount,
                    status: "running",
                },
            }));
        });

        es.addEventListener("endpoint-done", (e) => {
            const data = JSON.parse(e.data);
            setEndpointStatus((prev) => ({
                ...prev,
                [data.index]: {
                    ...prev[data.index],
                    status: "done",
                    findingsCount: data.findingsCount,
                },
            }));
        });

        es.addEventListener("complete", async () => {
            es.close();
            try {
                const res = await fetch("/api/report");
                if (res.ok) setReport(await res.json());
            } catch {}
            setPhase("complete");
        });

        es.addEventListener("fuzz-error", (e) => {
            const data = JSON.parse(e.data);
            setError(data.message);
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
        setProgress({ phase: "extracting" });
        setReport(null);
        connectSSE();
    };

    const newScan = () => {
        setPhase("config");
        setProgress(null);
        setEndpoints([]);
        setEndpointStatus({});
        setError(null);
    };

    if (!config) {
        return <div className="app loading">Loading...</div>;
    }

    return (
        <div className="app">
            <nav className="navbar">
                <div className="navbar-brand">
                    <span className="logo">🔒</span>
                    <span>Fuzzing Framework</span>
                    <span className="version">v4.0.0</span>
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
