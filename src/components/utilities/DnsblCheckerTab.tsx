import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  ExternalLink,
  Globe2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { checkDnsbl, copyToClipboard } from "../../lib/api";
import type { BlacklistEntry, StandaloneDnsblReport } from "../../types/dns";

export interface DnsblCheckerTabProps {
  defaultDomain?: string;
  initialTarget?: string;
  autoRunNonce?: number;
  onInspectDomain?: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type StatusFilter = "all" | "listed" | "blocked" | "clean" | "error";

export function DnsblCheckerTab({
  defaultDomain,
  initialTarget,
  autoRunNonce,
  onInspectDomain,
  onNotify,
}: DnsblCheckerTabProps) {
  const [target, setTarget] = useState(initialTarget || defaultDomain || "");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<StandaloneDnsblReport | null>(null);
  const [filter, setFilter] = useState<StatusFilter>("all");

  const runCheck = async (targetOverride?: string) => {
    const clean = (targetOverride ?? target).trim();
    if (!clean) {
      setError("Enter an IPv4 address or domain name to check across DNSBLs.");
      return;
    }
    setTarget(clean);
    setLoading(true);
    setError(null);
    setFilter("all");
    try {
      const res = await checkDnsbl(clean);
      setReport(res);
      if (res.error) setError(res.error);
    } catch (err) {
      setError(String(err));
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialTarget && initialTarget.trim()) {
      setTarget(initialTarget.trim());
      if (autoRunNonce && autoRunNonce > 0) {
        void runCheck(initialTarget.trim());
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialTarget, autoRunNonce]);

  const filteredEntries = useMemo(() => {
    if (!report) return [];
    if (filter === "all") return report.entries;
    if (filter === "blocked") {
      return report.entries.filter((e) => e.status === "blocked" || e.status === "policy");
    }
    return report.entries.filter((e) => e.status === filter);
  }, [report, filter]);

  const renderStatusPill = (entry: BlacklistEntry) => {
    switch (entry.status) {
      case "listed":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
            <XCircle className="h-3 w-3" />
            Listed
          </span>
        );
      case "blocked":
      case "policy":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
            <AlertTriangle className="h-3 w-3" />
            {entry.status === "policy" ? "Policy" : "Blocked"}
          </span>
        );
      case "error":
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-muted">
            Error
          </span>
        );
      default:
        return (
          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
            <CheckCircle2 className="h-3 w-3" />
            Clean
          </span>
        );
    }
  };

  const copySummary = async () => {
    if (!report) return;
    const listed = report.entries
      .filter((e) => e.status === "listed")
      .map((e) => `- ${e.list_name} (${e.zone}) [${e.target}]: ${e.return_codes.join(", ")}`)
      .join("\n");
    const text = `DNSBL Check for ${report.target} (${report.target_kind})\nChecked: ${report.checked_count} · Listed: ${report.listed_count} · Blocked: ${report.blocked_count}\n${listed || "All checked DNSBLs returned clean."}`;
    await copyToClipboard(text);
    onNotify("Copied DNSBL summary");
  };

  return (
    <div className="space-y-4">
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void runCheck();
        }}
        className="rounded-xl border border-line bg-surface p-4 space-y-3"
      >
        <div className="flex items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-ink">
              DNSBL IP &amp; Domain Reputation Checker
            </h3>
            <p className="text-[11px] text-ink-muted">
              Query Spamhaus, Barracuda, SpamCop, SORBS, URIBL, SURBL, and more for any IPv4 address or domain.
            </p>
          </div>
          {defaultDomain && target.trim() !== defaultDomain && (
            <button
              type="button"
              onClick={() => void runCheck(defaultDomain)}
              className="rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              Check {defaultDomain}
            </button>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            placeholder="e.g. 192.0.2.44 or example.com"
            className="min-w-[220px] flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {loading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Search className="h-3.5 w-3.5" />
            )}
            {loading ? "Checking DNSBLs..." : "Check Reputation"}
          </button>
        </div>
      </form>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-3.5 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-4">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Target ({report.target_kind.toUpperCase()})</div>
              <div className="mt-1 truncate font-mono text-sm font-semibold text-ink" title={report.target}>
                {report.target}
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-ink-muted">
                {report.latency_ms}ms total
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Status</div>
              <div className="mt-1 flex items-center gap-1.5 text-sm font-semibold">
                {report.listed_count > 0 ? (
                  <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
                    <ShieldAlert className="h-4 w-4" />
                    Listed ({report.listed_count})
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="h-4 w-4" />
                    Clean
                  </span>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Zones Checked</div>
              <div className="mt-1 font-mono text-lg font-semibold text-ink">
                {report.checked_count}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Blocked / Policy</div>
              <div className="mt-1 font-mono text-lg font-semibold text-amber-600 dark:text-amber-400">
                {report.blocked_count}
              </div>
            </div>
          </div>

          {report.resolved_ips.length > 0 && (
            <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-4 py-2.5 text-xs">
              <div className="flex flex-wrap items-center gap-1.5">
                <span className="text-ink-muted">Resolved A Records Checked:</span>
                {report.resolved_ips.map((ip) => (
                  <span
                    key={ip}
                    className="rounded border border-line bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                  >
                    {ip}
                  </span>
                ))}
              </div>
              {report.target_kind === "domain" && onInspectDomain && (
                <button
                  type="button"
                  onClick={() => onInspectDomain(report.target)}
                  className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                >
                  <Globe2 className="h-3.5 w-3.5" />
                  Inspect Domain
                </button>
              )}
            </div>
          )}

          {/* Filter & Table */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-1.5 text-xs">
                {(
                  [
                    ["all", `All (${report.entries.length})`],
                    ["listed", `Listed (${report.listed_count})`],
                    ["blocked", `Blocked (${report.blocked_count})`],
                    [
                      "clean",
                      `Clean (${report.entries.filter((e) => e.status === "clean").length})`,
                    ],
                  ] as const
                ).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setFilter(id)}
                    className={`rounded-md px-2.5 py-1 text-[11px] font-medium transition ${
                      filter === id
                        ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              <button
                type="button"
                onClick={() => void copySummary()}
                className="inline-flex items-center gap-1 text-xs text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
              >
                <Copy className="h-3.5 w-3.5" />
                Copy Summary
              </button>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full border-collapse text-left text-xs">
                <thead>
                  <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                    <th className="px-4 py-2">Blacklist</th>
                    <th className="px-4 py-2">Target</th>
                    <th className="px-4 py-2">Status</th>
                    <th className="px-4 py-2">Return Code / Detail</th>
                    <th className="px-4 py-2 text-right">Latency</th>
                    <th className="px-4 py-2 text-right">Action</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-line">
                  {filteredEntries.map((entry, idx) => (
                    <tr
                      key={`${entry.zone}-${entry.target}-${idx}`}
                      className="hover:bg-surface-alt/60"
                    >
                      <td className="px-4 py-2.5">
                        <div className="font-semibold text-ink">{entry.list_name}</div>
                        <div className="font-mono text-[10px] text-ink-muted">{entry.zone}</div>
                      </td>
                      <td className="px-4 py-2.5">
                        <div className="font-mono text-ink-secondary">{entry.target}</div>
                        <div className="text-[10px] text-ink-muted">{entry.target_role}</div>
                      </td>
                      <td className="px-4 py-2.5">{renderStatusPill(entry)}</td>
                      <td className="px-4 py-2.5">
                        {entry.return_codes.length > 0 && (
                          <div className="font-mono text-[11px] text-ink">
                            {entry.return_codes.join(", ")}
                          </div>
                        )}
                        <div className="text-[11px] text-ink-muted">
                          {entry.detail ?? (entry.status === "clean" ? "Not listed" : "—")}
                        </div>
                      </td>
                      <td className="px-4 py-2.5 text-right font-mono text-[11px] text-ink-muted">
                        {entry.latency_ms}ms
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        {entry.delist_url ? (
                          <a
                            href={entry.delist_url}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-1 text-[11px] font-medium text-sky-700 hover:border-sky-500/40 dark:text-sky-300"
                          >
                            Delist / Info
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <span className="text-[11px] text-ink-muted">—</span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {filteredEntries.length === 0 && (
                    <tr>
                      <td colSpan={6} className="px-4 py-6 text-center text-xs text-ink-muted">
                        No DNSBL entries match the selected filter.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
