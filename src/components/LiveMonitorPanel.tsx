import {
  Activity,
  AlertTriangle,
  Pause,
  Play,
  RotateCcw,
  StepForward,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { pingEndpoint } from "../lib/api";
import type { MonitorProbeResult, RecordTypeName } from "../types/dns";

interface LiveMonitorPanelProps {
  initialTarget: string;
}

const MAX_SAMPLES = 60;
const RECORD_OPTIONS: RecordTypeName[] = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
];

export function LiveMonitorPanel({ initialTarget }: LiveMonitorPanelProps) {
  const [target, setTarget] = useState(initialTarget || "cloudflare.com");
  const [mode, setMode] = useState<"https" | "tcp" | "dns">("https");
  const [port, setPort] = useState("443");
  const [resolver, setResolver] = useState("cloudflare");
  const [recordType, setRecordType] = useState<RecordTypeName>("A");
  const [intervalMs, setIntervalMs] = useState(2000);
  const [running, setRunning] = useState(false);
  const [probing, setProbing] = useState(false);
  const [samples, setSamples] = useState<MonitorProbeResult[]>([]);

  const inFlightRef = useRef(false);

  useEffect(() => {
    if (initialTarget && samples.length === 0 && !running) {
      setTarget(initialTarget);
    }
  }, [initialTarget, running, samples.length]);

  const runProbeOnce = useCallback(async () => {
    const cleanTarget = target.trim();
    if (!cleanTarget || inFlightRef.current) return;
    inFlightRef.current = true;
    setProbing(true);
    try {
      const result = await pingEndpoint({
        target: cleanTarget,
        mode,
        port: mode === "tcp" ? Number.parseInt(port, 10) || 443 : null,
        resolver: mode === "dns" ? resolver : null,
        record_type: mode === "dns" ? recordType : null,
      });
      setSamples((prev) => [...prev, result].slice(-MAX_SAMPLES));
    } catch (err) {
      const fallback: MonitorProbeResult = {
        timestamp: new Date().toISOString(),
        mode,
        target: cleanTarget,
        status: "down",
        total_ms: 0,
        dns_ms: null,
        tcp_ms: null,
        tls_ms: null,
        ttfb_ms: null,
        http_status: null,
        resolved_values: [],
        summary: String(err),
        error: String(err),
      };
      setSamples((prev) => [...prev, fallback].slice(-MAX_SAMPLES));
    } finally {
      inFlightRef.current = false;
      setProbing(false);
    }
  }, [target, mode, port, resolver, recordType]);

  useEffect(() => {
    if (!running) return;
    void runProbeOnce();
    const id = window.setInterval(() => {
      void runProbeOnce();
    }, intervalMs);
    return () => window.clearInterval(id);
  }, [running, intervalMs, runProbeOnce]);

  const stats = useMemo(() => {
    if (samples.length === 0) {
      return {
        latest: null as MonitorProbeResult | null,
        avgMs: 0,
        p95Ms: 0,
        minMs: 0,
        maxMs: 0,
        uptimePct: 0,
        dnsChangeDetected: false,
      };
    }
    const latencies = samples.map((s) => s.total_ms).sort((a, b) => a - b);
    const sum = latencies.reduce((a, b) => a + b, 0);
    const p95Idx = Math.min(
      latencies.length - 1,
      Math.floor(latencies.length * 0.95),
    );
    const healthyCount = samples.filter((s) => s.status !== "down").length;

    const valueSignatures = new Set(
      samples
        .filter((s) => s.resolved_values.length > 0)
        .map((s) => s.resolved_values.join("|")),
    );

    return {
      latest: samples[samples.length - 1],
      avgMs: Math.round(sum / samples.length),
      p95Ms: latencies[p95Idx],
      minMs: latencies[0],
      maxMs: latencies[latencies.length - 1],
      uptimePct: Math.round((healthyCount / samples.length) * 100),
      dnsChangeDetected: valueSignatures.size > 1,
    };
  }, [samples]);

  const chartMaxMs = Math.max(
    100,
    ...samples.map((s) => s.total_ms),
  );

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
              <Activity className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              Live Ping &amp; Endpoint Monitor
            </h2>
            <p className="text-[11px] text-ink-muted">
              Watch live HTTPS timing waterfalls, TCP reachability, or DNS
              propagation rollouts continuously.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              disabled={probing}
              onClick={() => void runProbeOnce()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink disabled:opacity-50"
            >
              <StepForward className="h-3.5 w-3.5" />
              Probe Once
            </button>
            <button
              type="button"
              onClick={() => setSamples([])}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs text-ink-muted hover:text-ink"
            >
              <RotateCcw className="h-3.5 w-3.5" />
              Reset
            </button>
            <button
              type="button"
              onClick={() => setRunning((r) => !r)}
              className={`inline-flex items-center gap-1.5 rounded-lg px-3.5 py-1.5 text-xs font-semibold transition ${
                running
                  ? "bg-amber-600 text-white hover:bg-amber-500"
                  : "bg-sky-600 text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
              }`}
            >
              {running ? (
                <>
                  <Pause className="h-3.5 w-3.5" />
                  Pause Monitor
                </>
              ) : (
                <>
                  <Play className="h-3.5 w-3.5" />
                  Start Monitor
                </>
              )}
            </button>
          </div>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-12">
          <div className="sm:col-span-5">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Target Domain, IP, or URL
            </label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
              placeholder="cloudflare.com"
            />
          </div>

          <div className="sm:col-span-2">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Probe Mode
            </label>
            <select
              value={mode}
              onChange={(e) =>
                setMode(e.target.value as "https" | "tcp" | "dns")
              }
              className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
            >
              <option value="https">HTTPS Request</option>
              <option value="tcp">TCP Port</option>
              <option value="dns">DNS Query</option>
            </select>
          </div>

          {mode === "tcp" && (
            <div className="sm:col-span-2">
              <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                Port
              </label>
              <input
                type="number"
                min={1}
                max={65535}
                value={port}
                onChange={(e) => setPort(e.target.value)}
                className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
              />
            </div>
          )}

          {mode === "dns" && (
            <>
              <div className="sm:col-span-2">
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Resolver
                </label>
                <select
                  value={resolver}
                  onChange={(e) => setResolver(e.target.value)}
                  className="w-full rounded-lg border border-line bg-canvas px-2 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
                >
                  <option value="cloudflare">Cloudflare</option>
                  <option value="google">Google</option>
                  <option value="quad9">Quad9</option>
                  <option value="system">System</option>
                </select>
              </div>
              <div className="sm:col-span-1">
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Type
                </label>
                <select
                  value={recordType}
                  onChange={(e) =>
                    setRecordType(e.target.value as RecordTypeName)
                  }
                  className="w-full rounded-lg border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
                >
                  {RECORD_OPTIONS.map((t) => (
                    <option key={t} value={t}>
                      {t}
                    </option>
                  ))}
                </select>
              </div>
            </>
          )}

          <div className="sm:col-span-2">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Interval
            </label>
            <select
              value={intervalMs}
              onChange={(e) => setIntervalMs(Number(e.target.value))}
              className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
            >
              <option value={1000}>Every 1s</option>
              <option value={2000}>Every 2s</option>
              <option value={5000}>Every 5s</option>
              <option value={10000}>Every 10s</option>
              <option value={30000}>Every 30s</option>
            </select>
          </div>
        </div>
      </div>

      {/* Stat Summary */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Latest</div>
          <div className="mt-0.5 font-mono text-lg font-semibold text-ink">
            {stats.latest ? `${stats.latest.total_ms}ms` : "—"}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Average</div>
          <div className="mt-0.5 font-mono text-lg font-semibold text-ink">
            {samples.length > 0 ? `${stats.avgMs}ms` : "—"}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">P95 Latency</div>
          <div className="mt-0.5 font-mono text-lg font-semibold text-ink">
            {samples.length > 0 ? `${stats.p95Ms}ms` : "—"}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Min / Max</div>
          <div className="mt-0.5 font-mono text-sm font-semibold text-ink">
            {samples.length > 0 ? `${stats.minMs} / ${stats.maxMs}ms` : "—"}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Uptime ({samples.length})</div>
          <div className="mt-0.5 font-mono text-lg font-semibold text-emerald-600 dark:text-emerald-400">
            {samples.length > 0 ? `${stats.uptimePct}%` : "—"}
          </div>
        </div>
      </div>

      {stats.dnsChangeDetected && (
        <div className="flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>
            Answer change detected during this monitor session (useful when
            watching DNS propagation or load-balancer rotation).
          </span>
        </div>
      )}

      {/* Latency SVG Chart */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="mb-2 flex items-center justify-between text-xs">
          <span className="font-semibold text-ink">
            Latency Timeline (last {MAX_SAMPLES} probes)
          </span>
          <span className="font-mono text-[11px] text-ink-muted">
            Peak {chartMaxMs}ms
          </span>
        </div>
        {samples.length === 0 ? (
          <div className="py-10 text-center text-xs text-ink-muted">
            Press <strong>Start Monitor</strong> or <strong>Probe Once</strong>{" "}
            to begin recording latency samples.
          </div>
        ) : (
          <svg
            viewBox="0 0 600 120"
            className="h-32 w-full overflow-visible"
            role="img"
            aria-label="Live endpoint latency bar chart"
          >
            <line
              x1="0"
              y1="30"
              x2="600"
              y2="30"
              className="stroke-line"
              strokeDasharray="3 3"
            />
            <line
              x1="0"
              y1="65"
              x2="600"
              y2="65"
              className="stroke-line"
              strokeDasharray="3 3"
            />
            <line x1="0" y1="100" x2="600" y2="100" className="stroke-line" />

            {samples.map((s, idx) => {
              const slotW = 600 / MAX_SAMPLES;
              const x = idx * slotW + 1.5;
              const barH = Math.max(
                4,
                Math.min(96, Math.round((s.total_ms / chartMaxMs) * 96)),
              );
              const y = 100 - barH;
              const fillClass =
                s.status === "up"
                  ? "fill-emerald-500"
                  : s.status === "degraded"
                    ? "fill-amber-500"
                    : "fill-rose-500";
              return (
                <rect
                  key={`${s.timestamp}-${idx}`}
                  x={x}
                  y={y}
                  width={Math.max(3, slotW - 3)}
                  height={barH}
                  rx={2}
                  className={fillClass}
                >
                  <title>
                    {`${new Date(s.timestamp).toLocaleTimeString()} — ${s.status.toUpperCase()} (${s.total_ms}ms): ${s.summary}`}
                  </title>
                </rect>
              );
            })}
          </svg>
        )}
      </div>

      {/* Recent Probe Log */}
      {samples.length > 0 && (
        <div className="max-h-72 overflow-y-auto rounded-xl border border-line bg-surface">
          <table className="w-full text-left text-xs">
            <thead className="sticky top-0 border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
              <tr>
                <th className="px-4 py-2">Time</th>
                <th className="px-3 py-2">Status</th>
                <th className="px-3 py-2">Total</th>
                <th className="px-3 py-2">Breakdown</th>
                <th className="px-3 py-2">Summary / Answers</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line font-mono text-[11px]">
              {[...samples].reverse().map((s, i) => (
                <tr key={`${s.timestamp}-${i}`} className="hover:bg-surface-alt/50">
                  <td className="px-4 py-2 text-ink-muted">
                    {new Date(s.timestamp).toLocaleTimeString()}
                  </td>
                  <td className="px-3 py-2">
                    <span
                      className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                        s.status === "up"
                          ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : s.status === "degraded"
                            ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                            : "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                      }`}
                    >
                      {s.status}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-semibold text-ink">
                    {s.total_ms}ms
                  </td>
                  <td className="px-3 py-2 text-ink-muted">
                    {[
                      s.dns_ms != null ? `DNS ${s.dns_ms}ms` : null,
                      s.tcp_ms != null ? `TCP ${s.tcp_ms}ms` : null,
                      s.tls_ms != null ? `TLS ${s.tls_ms}ms` : null,
                      s.ttfb_ms != null ? `TTFB ${s.ttfb_ms}ms` : null,
                    ]
                      .filter(Boolean)
                      .join(" • ") || "—"}
                  </td>
                  <td className="px-3 py-2 text-ink-secondary">{s.summary}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
