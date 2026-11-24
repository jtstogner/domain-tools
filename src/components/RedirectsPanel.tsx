import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock,
  GitBranch,
  Play,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useState } from "react";
import { traceRedirects } from "../lib/api";
import type { RedirectReport } from "../types/dns";

interface RedirectsPanelProps {
  redirects: RedirectReport;
  defaultDomain: string;
}

function statusBadgeTone(code: number): string {
  if (code >= 200 && code < 300) {
    return "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  }
  if (code >= 300 && code < 400) {
    return "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300";
  }
  if (code >= 400 && code < 500) {
    return "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300";
  }
  return "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300";
}

export function RedirectsPanel({ redirects, defaultDomain }: RedirectsPanelProps) {
  const [report, setReport] = useState<RedirectReport>(redirects);
  const [customUrl, setCustomUrl] = useState(`https://${defaultDomain}`);
  const [tracing, setTracing] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  useEffect(() => {
    setReport(redirects);
    setCustomUrl(`https://${defaultDomain}`);
    setTraceError(null);
  }, [redirects, defaultDomain]);

  const handleTrace = async () => {
    const val = customUrl.trim();
    if (!val) return;
    setTracing(true);
    setTraceError(null);
    try {
      const next = await traceRedirects(val);
      setReport(next);
    } catch (err) {
      setTraceError(String(err));
    } finally {
      setTracing(false);
    }
  };

  const wf = report.waterfall;
  const wfTotal = wf ? Math.max(1, wf.dns_ms + wf.tcp_ms + (wf.tls_ms ?? 0) + wf.ttfb_ms) : 1;

  return (
    <div className="space-y-4">
      {/* Custom URL Trace Input */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex flex-wrap items-center gap-2.5">
          <input
            type="text"
            value={customUrl}
            onChange={(e) => setCustomUrl(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") void handleTrace();
            }}
            placeholder="https://example.com/pricing or domain.com"
            className="min-w-[240px] flex-1 rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
          />
          <button
            type="button"
            disabled={tracing}
            onClick={() => void handleTrace()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            <Play className="h-3.5 w-3.5" />
            {tracing ? "Tracing..." : "Trace URL"}
          </button>
          <button
            type="button"
            onClick={() => setReport(redirects)}
            className="rounded-lg border border-line bg-surface-alt px-3 py-1.5 text-xs text-ink-secondary hover:text-ink"
          >
            Reset to Domain Check
          </button>
        </div>
        {traceError && (
          <div className="mt-2 text-xs text-rose-600 dark:text-rose-400">
            {traceError}
          </div>
        )}
      </div>

      {/* Audit Highlights */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <ShieldCheck className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            HTTP → HTTPS
          </div>
          <div className="mt-1 flex items-center gap-1.5 text-xs font-semibold text-ink">
            {report.http_to_https ? (
              <>
                <CheckCircle2 className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                Enforced
              </>
            ) : (
              <>
                <XCircle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                Not Enforced / N/A
              </>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <GitBranch className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
            Canonical URL
          </div>
          <div className="mt-1 truncate font-mono text-xs font-semibold text-ink" title={report.canonical_url ?? ""}>
            {report.canonical_url ?? "Unresolved"}
          </div>
          <div className="mt-0.5 text-[10px] text-ink-muted">
            {report.canonical_consistent ? "Consistent target" : "Multiple destinations"}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Clock className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            HSTS Policy
          </div>
          <div className="mt-1 text-xs font-semibold text-ink">
            {report.hsts_present
              ? `Enabled${report.hsts_max_age != null ? ` (${Math.round(report.hsts_max_age / 86400)}d)` : ""}`
              : "Missing"}
          </div>
          {report.hsts_present && (
            <div className="mt-0.5 text-[10px] text-ink-muted">
              {report.hsts_include_subdomains ? "includeSubDomains " : ""}
              {report.hsts_preload ? "• preload" : ""}
            </div>
          )}
        </div>
      </div>

      {report.issues.length > 0 && (
        <div className="rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-900 dark:text-amber-200">
          <div className="flex items-center gap-2 font-semibold">
            <AlertTriangle className="h-4 w-4 shrink-0" />
            Redirect &amp; Transport Recommendations
          </div>
          <ul className="mt-1.5 list-disc space-y-0.5 pl-5 text-[11px]">
            {report.issues.map((issue) => (
              <li key={issue}>{issue}</li>
            ))}
          </ul>
        </div>
      )}

      {/* Timing Waterfall */}
      {wf && (
        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
            <div>
              <div className="text-xs font-semibold text-ink">
                Connection Timing Waterfall
              </div>
              <div className="font-mono text-[11px] text-ink-muted">
                {wf.target_url}
              </div>
            </div>
            <div className="flex items-center gap-2 font-mono text-xs">
              {wf.http_status && (
                <span className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${statusBadgeTone(wf.http_status)}`}>
                  HTTP {wf.http_status}
                </span>
              )}
              <span className="rounded bg-surface-alt px-2 py-0.5 font-semibold text-ink">
                Total {wf.total_ms}ms
              </span>
            </div>
          </div>

          {wf.error ? (
            <div className="mt-3 text-xs text-rose-600 dark:text-rose-400">
              {wf.error}
            </div>
          ) : (
            <div className="mt-3 space-y-2.5 text-xs">
              {[
                { label: "DNS Lookup", ms: wf.dns_ms, color: "bg-sky-500" },
                { label: "TCP Connect", ms: wf.tcp_ms, color: "bg-indigo-500" },
                ...(wf.tls_ms != null
                  ? [{ label: "TLS Handshake", ms: wf.tls_ms, color: "bg-violet-500" }]
                  : []),
                { label: "TTFB (Server)", ms: wf.ttfb_ms, color: "bg-emerald-500" },
              ].map((phase) => {
                const widthPct = Math.max(3, Math.round((phase.ms / wfTotal) * 100));
                return (
                  <div key={phase.label} className="grid grid-cols-12 items-center gap-3">
                    <div className="col-span-4 text-[11px] font-medium text-ink-secondary sm:col-span-3">
                      {phase.label}
                    </div>
                    <div className="col-span-6 h-2.5 overflow-hidden rounded-full bg-surface-alt sm:col-span-7">
                      <div
                        className={`h-full rounded-full ${phase.color}`}
                        style={{ width: `${widthPct}%` }}
                      />
                    </div>
                    <div className="col-span-2 text-right font-mono text-[11px] text-ink">
                      {phase.ms}ms
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      )}

      {/* Redirect Chains */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
        {report.chains.map((chain) => (
          <div
            key={`${chain.label}-${chain.start_url}`}
            className="rounded-xl border border-line bg-surface p-4"
          >
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
              <div>
                <div className="text-xs font-semibold text-ink">{chain.label}</div>
                <div className="font-mono text-[11px] text-ink-muted">
                  {chain.start_url}
                </div>
              </div>
              <div className="flex items-center gap-2 font-mono text-[11px]">
                <span className="rounded bg-surface-alt px-2 py-0.5 text-ink-secondary">
                  {chain.hop_count} redirect{chain.hop_count === 1 ? "" : "s"}
                </span>
                <span className="text-ink-muted">{chain.total_ms}ms</span>
              </div>
            </div>

            {chain.error && (
              <div className="mt-2.5 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2 text-[11px] text-rose-700 dark:text-rose-300">
                {chain.error}
              </div>
            )}

            <div className="mt-3 space-y-2">
              {chain.hops.map((hop) => (
                <div
                  key={`${hop.hop_index}-${hop.url}`}
                  className="rounded-lg border border-line bg-surface-alt p-2.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[10px] text-ink-muted">
                        #{hop.hop_index}
                      </span>
                      <span
                        className={`rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${statusBadgeTone(
                          hop.status_code,
                        )}`}
                      >
                        {hop.status_code} {hop.status_text}
                      </span>
                      {hop.server && (
                        <span className="text-[10px] text-ink-muted">
                          {hop.server}
                        </span>
                      )}
                    </div>
                    <span className="font-mono text-[10px] text-ink-muted">
                      {hop.latency_ms}ms
                    </span>
                  </div>
                  <div className="mt-1 break-all font-mono text-[11px] text-ink">
                    {hop.url}
                  </div>
                  {hop.resolved_next_url && (
                    <div className="mt-1 flex items-center gap-1 break-all font-mono text-[11px] text-sky-600 dark:text-sky-400">
                      <ArrowRight className="h-3 w-3 shrink-0" />
                      {hop.resolved_next_url}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
