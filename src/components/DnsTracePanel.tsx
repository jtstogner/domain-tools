import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  GitBranch,
  Play,
  RefreshCw,
  Server,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useState } from "react";
import { copyToClipboard, runDnsTrace } from "../lib/api";
import type { DnsTraceReport } from "../types/dns";

interface DnsTracePanelProps {
  domain: string;
  onNotify: (msg: string) => void;
}

const TRACE_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CAA"] as const;

export function DnsTracePanel({ domain, onNotify }: DnsTracePanelProps) {
  const [recordType, setRecordType] = useState<string>("A");
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<DnsTraceReport | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    setError(null);
  }, [domain]);

  const handleRunTrace = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await runDnsTrace(domain, recordType);
      setReport(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2.5">
          <GitBranch className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <div>
            <h3 className="text-sm font-semibold text-ink">
              Iterative DNS Delegation Trace (dig +trace)
            </h3>
            <p className="text-xs text-ink-muted">
              Walks Root → TLD → Authoritative nameservers directly to detect lame delegations, glue issues, and SOA serial drift.
            </p>
          </div>
        </div>

        <div className="flex items-center gap-2">
          <select
            value={recordType}
            onChange={(e) => setRecordType(e.target.value)}
            className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          >
            {TRACE_RECORD_TYPES.map((rt) => (
              <option key={rt} value={rt}>
                {rt}
              </option>
            ))}
          </select>
          <button
            type="button"
            disabled={loading}
            onClick={() => void handleRunTrace()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {loading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {loading ? "Tracing..." : "Run Trace"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {!report && !loading && !error && (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center text-xs text-ink-muted">
          Select a record type and click <span className="font-semibold text-ink">Run Trace</span> to trace iterative delegation for <span className="font-mono text-ink">{domain}</span>.
        </div>
      )}

      {report && (
        <div className="space-y-4">
          {report.issues.length > 0 && (
            <div className="space-y-1 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-xs text-amber-900 dark:text-amber-200">
              <div className="flex items-center gap-2 font-semibold">
                <AlertTriangle className="h-4 w-4 text-amber-600 dark:text-amber-400" />
                Delegation Issues Detected ({report.issues.length})
              </div>
              <ul className="space-y-0.5 pl-6 list-disc">
                {report.issues.map((iss, i) => (
                  <li key={i}>{iss}</li>
                ))}
              </ul>
            </div>
          )}

          {report.error && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-800 dark:text-rose-200">
              {report.error}
            </div>
          )}

          {/* Step-by-step Delegation Hops */}
          <div className="space-y-3">
            <div className="flex items-center justify-between text-xs font-semibold uppercase tracking-wider text-ink-muted">
              <span>Delegation Chain ({report.hops.length} hops)</span>
              <span className="font-mono">{report.total_ms}ms total</span>
            </div>

            {report.hops.map((hop) => (
              <div
                key={hop.step}
                className="rounded-xl border border-line bg-surface p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded-md bg-sky-500/15 px-2 py-0.5 font-mono text-xs font-bold text-sky-700 dark:text-sky-300">
                      Step {hop.step}
                    </span>
                    <span className="rounded border border-line bg-surface-alt px-2 py-0.5 text-[11px] font-semibold text-ink-secondary">
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
                    <span
                      className={`rounded-full border px-2 py-0.5 font-semibold ${
                        hop.rcode === "NOERROR"
                          ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                      }`}
                    >
                      {hop.rcode}
                    </span>
                    {hop.authoritative && (
                      <span className="rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 font-semibold text-emerald-700 dark:text-emerald-300">
                        AA
                      </span>
                    )}
                    {hop.has_ds && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-violet-500/40 bg-violet-500/15 px-2 py-0.5 text-violet-700 dark:text-violet-300">
                        <ShieldCheck className="h-3 w-3" />
                        DS
                      </span>
                    )}
                    {hop.has_rrsig && (
                      <span className="rounded-full border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-sky-700 dark:text-sky-300">
                        RRSIG
                      </span>
                    )}
                    <span className="text-ink-muted">{hop.latency_ms}ms</span>
                  </div>
                </div>

                {hop.note && (
                  <div className="mt-2 text-xs text-ink-secondary">{hop.note}</div>
                )}

                {hop.answers.length > 0 && (
                  <div className="mt-2.5 rounded-lg border border-emerald-500/30 bg-emerald-500/[0.06] p-2.5">
                    <div className="mb-1 flex items-center justify-between text-[11px] font-semibold text-emerald-800 dark:text-emerald-300">
                      <span>Answers ({hop.answers.length})</span>
                      <button
                        type="button"
                        onClick={() => {
                          void copyToClipboard(hop.answers.join("\n"));
                          onNotify("Copied trace answers");
                        }}
                        className="inline-flex items-center gap-1 text-[11px] hover:underline"
                      >
                        <Copy className="h-3 w-3" />
                        Copy
                      </button>
                    </div>
                    <div className="space-y-0.5 font-mono text-[11px] text-ink">
                      {hop.answers.map((ans, idx) => (
                        <div key={idx} className="break-all">
                          {ans}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {hop.referrals.length > 0 && (
                  <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                    <span className="text-ink-muted">NS Referrals:</span>
                    {hop.referrals.map((ns) => (
                      <span
                        key={ns}
                        className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-ink-secondary"
                      >
                        {ns}
                      </span>
                    ))}
                  </div>
                )}

                {hop.glue_ips.length > 0 && (
                  <div className="mt-1.5 flex flex-wrap items-center gap-1.5 text-[11px]">
                    <span className="text-ink-muted">Glue:</span>
                    {hop.glue_ips.map((g) => (
                      <span
                        key={g}
                        className="rounded border border-line bg-surface-alt px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
                      >
                        {g}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>

          {/* Authoritative Nameserver Consistency Table */}
          {report.authoritative_checks.length > 0 && (
            <div className="overflow-hidden rounded-xl border border-line bg-surface">
              <div className="flex items-center gap-2 border-b border-line bg-surface-alt px-4 py-2.5 text-xs font-semibold text-ink">
                <Server className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                Authoritative Nameserver Consistency Audit
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2.5">Nameserver</th>
                      <th className="px-4 py-2.5">IP</th>
                      <th className="px-4 py-2.5">Reachable</th>
                      <th className="px-4 py-2.5">AA Flag</th>
                      <th className="px-4 py-2.5">SOA Serial</th>
                      <th className="px-4 py-2.5 text-right">Latency</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {report.authoritative_checks.map((chk) => (
                      <tr key={chk.nameserver} className="hover:bg-surface-alt/70">
                        <td className="px-4 py-2.5 font-mono font-medium text-ink">
                          {chk.nameserver}
                          {chk.error && (
                            <div className="font-sans text-[11px] text-rose-700 dark:text-rose-300">
                              {chk.error}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-ink-secondary">
                          {chk.ip ?? "—"}
                        </td>
                        <td className="px-4 py-2.5">
                          {chk.reachable ? (
                            <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-300">
                              <CheckCircle2 className="h-3.5 w-3.5" />
                              Yes
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-rose-700 dark:text-rose-300">
                              <XCircle className="h-3.5 w-3.5" />
                              No
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5">
                          {chk.authoritative ? (
                            <span className="text-emerald-700 dark:text-emerald-300 font-medium">
                              Authoritative
                            </span>
                          ) : (
                            <span className="text-rose-700 dark:text-rose-300 font-medium">
                              Not AA
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2.5 font-mono text-ink">
                          {chk.soa_serial ?? "—"}
                        </td>
                        <td className="px-4 py-2.5 text-right font-mono text-ink-muted">
                          {chk.latency_ms}ms
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
