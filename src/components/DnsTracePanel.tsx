import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Play,
  Route,
  Server,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { runDnsTrace } from "../lib/api";
import type { DnsTraceReport } from "../types/dns";

interface DnsTracePanelProps {
  defaultDomain: string;
}

const TRACE_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"];

export function DnsTracePanel({ defaultDomain }: DnsTracePanelProps) {
  const [domain, setDomain] = useState(defaultDomain);
  const [recordType, setRecordType] = useState("A");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<DnsTraceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setDomain(defaultDomain);
    setReport(null);
    setError(null);
  }, [defaultDomain]);

  const handleRun = async () => {
    const target = domain.trim();
    if (!target) return;
    setLoading(true);
    setError(null);
    try {
      const res = await runDnsTrace(target, recordType);
      setReport(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const uniqueSerials = useMemo(() => {
    if (!report) return new Set<number>();
    return new Set(
      report.authoritative_checks
        .map((c) => c.soa_serial)
        .filter((s): s is number => s !== null),
    );
  }, [report]);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[200px] flex-1">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Domain to Trace (Root &rarr; TLD &rarr; Authoritative)
            </label>
            <input
              type="text"
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              placeholder={defaultDomain}
              className="w-full rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
            />
          </div>
          <div className="w-28">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Record Type
            </label>
            <select
              value={recordType}
              onChange={(e) => setRecordType(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
            >
              {TRACE_RECORD_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          </div>
          <button
            type="button"
            disabled={loading || !domain.trim()}
            onClick={() => void handleRun()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {loading ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {loading ? "Tracing..." : "Run DNS Trace"}
          </button>
        </div>
        <p className="mt-2 text-[11px] text-ink-muted">
          Performs an iterative <code className="font-mono">dig +trace</code>{" "}
          delegation walk directly from Root hints over UDP/TCP port 53, then
          audits every authoritative nameserver for lame delegations and SOA
          serial drift.
        </p>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-4">
          {report.issues.length > 0 && (
            <div className="space-y-1.5 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-900 dark:text-amber-200">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                Delegation Issues Detected
              </div>
              <ul className="list-disc space-y-1 pl-5 text-[11px]">
                {report.issues.map((iss, idx) => (
                  <li key={idx}>{iss}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Delegation Hops Timeline */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5">
              <div className="flex items-center gap-2 text-xs font-semibold text-ink">
                <Route className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                Delegation Chain ({report.domain} {report.record_type})
              </div>
              <span className="font-mono text-[11px] text-ink-muted">
                {report.hops.length} hop(s) · {report.total_ms}ms total
              </span>
            </div>

            <div className="divide-y divide-line">
              {report.hops.map((hop) => {
                const levelTone =
                  hop.level === "Root"
                    ? "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300"
                    : hop.level === "TLD"
                      ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                      : "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";

                return (
                  <div key={hop.step} className="space-y-2 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="flex h-5 w-5 items-center justify-center rounded-full bg-surface-alt font-mono text-[11px] font-bold text-ink">
                          {hop.step}
                        </span>
                        <span
                          className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold ${levelTone}`}
                        >
                          {hop.level} ({hop.zone})
                        </span>
                        <span className="font-mono text-xs font-semibold text-ink">
                          {hop.server_name}
                        </span>
                        <span className="font-mono text-[11px] text-ink-muted">
                          ({hop.server_ip})
                        </span>
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5 font-mono text-[11px]">
                        <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-ink-secondary">
                          {hop.rcode}
                        </span>
                        {hop.authoritative && (
                          <span className="rounded border border-emerald-500/30 bg-emerald-500/10 px-1.5 py-0.5 text-emerald-700 dark:text-emerald-300">
                            AA
                          </span>
                        )}
                        {hop.has_ds && (
                          <span className="inline-flex items-center gap-1 rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-sky-700 dark:text-sky-300">
                            <ShieldCheck className="h-3 w-3" />
                            DS
                          </span>
                        )}
                        {hop.has_rrsig && (
                          <span className="rounded border border-violet-500/30 bg-violet-500/10 px-1.5 py-0.5 text-violet-700 dark:text-violet-300">
                            RRSIG
                          </span>
                        )}
                        <span className="text-ink-muted">{hop.latency_ms}ms</span>
                      </div>
                    </div>

                    {hop.note && (
                      <div className="text-[11px] text-ink-muted">{hop.note}</div>
                    )}

                    {hop.referrals.length > 0 && (
                      <div className="rounded-lg border border-line bg-canvas p-2.5">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                          Referred Nameservers ({hop.referrals.length})
                        </div>
                        <div className="mt-1 flex flex-wrap gap-1.5">
                          {hop.referrals.map((ns) => (
                            <span
                              key={ns}
                              className="rounded border border-line bg-surface px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                            >
                              {ns}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {hop.answers.length > 0 && (
                      <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-2.5">
                        <div className="text-[10px] font-semibold uppercase tracking-wider text-emerald-700 dark:text-emerald-300">
                          Answers ({hop.answers.length})
                        </div>
                        <div className="mt-1 space-y-0.5 font-mono text-[11px] text-ink">
                          {hop.answers.map((ans, idx) => (
                            <div key={idx}>{ans}</div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* Authoritative NS Consistency Audit */}
          {report.authoritative_checks.length > 0 && (
            <div className="overflow-hidden rounded-xl border border-line bg-surface">
              <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5">
                <div className="flex items-center gap-2 text-xs font-semibold text-ink">
                  <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  Authoritative Nameserver Consistency Check
                </div>
                {uniqueSerials.size > 1 && (
                  <span className="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
                    SOA Serial Drift Detected
                  </span>
                )}
              </div>

              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas/70 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2.5">Nameserver</th>
                      <th className="px-4 py-2.5">IP</th>
                      <th className="px-4 py-2.5">Status</th>
                      <th className="px-4 py-2.5">SOA Serial</th>
                      <th className="px-4 py-2.5">Child NS Count</th>
                      <th className="px-4 py-2.5 text-right">Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {report.authoritative_checks.map((ns) => (
                      <tr key={ns.nameserver} className="hover:bg-surface-alt/70">
                        <td className="px-4 py-2.5 font-mono font-medium text-ink">
                          {ns.nameserver}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-ink-secondary">
                          {ns.ip ?? "—"}
                        </td>
                        <td className="px-4 py-2.5">
                          {ns.reachable && ns.authoritative ? (
                            <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                              <CheckCircle2 className="h-3 w-3" />
                              Authoritative
                            </span>
                          ) : ns.reachable ? (
                            <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
                              <AlertTriangle className="h-3 w-3" />
                              Lame (No AA)
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-300">
                              <XCircle className="h-3 w-3" />
                              Unreachable
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-ink-secondary">
                          {ns.soa_serial ?? "—"}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-ink-secondary">
                          {ns.ns_records.length}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono text-ink-muted">
                          {ns.latency_ms}ms
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
