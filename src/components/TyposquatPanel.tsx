import {
  AlertTriangle,
  ArrowUpRight,
  Copy,
  Play,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard, scanTyposquats } from "../lib/api";
import type { TyposquatReport } from "../types/dns";

interface TyposquatPanelProps {
  domain: string;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

export function TyposquatPanel({
  domain,
  onInspectDomain,
  onNotify,
}: TyposquatPanelProps) {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<TyposquatReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filterMode, setFilterMode] = useState<"registered" | "high" | "web" | "all">("registered");
  const [search, setSearch] = useState("");

  useEffect(() => {
    setReport(null);
    setError(null);
  }, [domain]);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await scanTyposquats(domain);
      setReport(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const filtered = useMemo(() => {
    if (!report) return [];
    const needle = search.trim().toLowerCase();
    return report.candidates.filter((c) => {
      if (filterMode === "registered" && !c.registered) return false;
      if (filterMode === "high" && c.risk_level !== "high") return false;
      if (filterMode === "web" && c.a_records.length === 0 && c.aaaa_records.length === 0) {
        return false;
      }
      if (needle) {
        const hit =
          c.domain.toLowerCase().includes(needle) ||
          c.fuzzer.toLowerCase().includes(needle);
        if (!hit) return false;
      }
      return true;
    });
  }, [report, filterMode, search]);

  const handleCopyRegistered = async () => {
    if (!report) return;
    const reg = report.candidates.filter((c) => c.registered).map((c) => c.domain);
    if (reg.length === 0) return;
    await copyToClipboard(reg.join("\n"));
    onNotify(`Copied ${reg.length} registered lookalike(s)`);
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2.5">
          <ShieldAlert className="h-4 w-4 text-amber-600 dark:text-amber-400" />
          <div>
            <h3 className="text-sm font-semibold text-ink">
              Typosquatting &amp; Brand Lookalike Scanner
            </h3>
            <p className="text-xs text-ink-muted">
              Generates homoglyph, transposition, omission, TLD-swap, and phishing-lure variants and probes DNS for active web/MX impersonation risk.
            </p>
          </div>
        </div>
        <button
          type="button"
          disabled={loading}
          onClick={() => void handleScan()}
          className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
        >
          {loading ? (
            <RefreshCw className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Play className="h-3.5 w-3.5" />
          )}
          {loading ? "Scanning Variants..." : report ? "Re-scan Lookalikes" : "Scan Lookalikes"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {!report && !loading && !error && (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center text-xs text-ink-muted">
          Click <span className="font-semibold text-ink">Scan Lookalikes</span> to check up to 96 typosquatting &amp; phishing lookalike domains for <span className="font-mono text-ink">{domain}</span>.
        </div>
      )}

      {report && (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Variants Checked</div>
              <div className="mt-1 font-mono text-xl font-bold text-ink">
                {report.total_checked}
              </div>
              <div className="text-[11px] text-ink-muted">
                of {report.total_generated} generated ({report.latency_ms}ms)
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Registered</div>
              <div className="mt-1 font-mono text-xl font-bold text-amber-700 dark:text-amber-300">
                {report.registered_count}
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">High Risk (Active MX)</div>
              <div
                className={`mt-1 font-mono text-xl font-bold ${
                  report.high_risk_count > 0
                    ? "text-rose-700 dark:text-rose-300"
                    : "text-emerald-700 dark:text-emerald-300"
                }`}
              >
                {report.high_risk_count}
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Active Web (A/AAAA)</div>
              <div className="mt-1 font-mono text-xl font-bold text-sky-700 dark:text-sky-300">
                {report.active_web_count}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface p-3">
            <div className="flex flex-wrap gap-1.5">
              {(
                [
                  ["registered", `Registered (${report.registered_count})`],
                  ["high", `High Risk MX (${report.high_risk_count})`],
                  ["web", `Active Web (${report.active_web_count})`],
                  ["all", `All Checked (${report.total_checked})`],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setFilterMode(id)}
                  className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
                    filterMode === id
                      ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                      : "border-line bg-canvas text-ink-muted hover:text-ink"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              <div className="relative w-56">
                <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter domains..."
                  className="w-full rounded-lg border border-line-strong bg-canvas py-1.5 pl-8 pr-3 text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
                />
              </div>
              <button
                type="button"
                disabled={report.registered_count === 0}
                onClick={() => void handleCopyRegistered()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink disabled:opacity-40"
              >
                <Copy className="h-3.5 w-3.5" />
                Copy Registered
              </button>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            {filtered.length === 0 ? (
              <div className="px-6 py-10 text-center text-xs text-ink-muted">
                <ShieldCheck className="mx-auto mb-2 h-6 w-6 text-emerald-500/70" />
                No lookalike domains matched this filter.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-surface-alt text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2.5">Candidate Domain</th>
                      <th className="px-4 py-2.5">Technique</th>
                      <th className="px-4 py-2.5">Risk</th>
                      <th className="px-4 py-2.5">DNS Footprint</th>
                      <th className="px-4 py-2.5 text-right">Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {filtered.map((c) => {
                      const badge =
                        c.risk_level === "high" ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[10px] font-bold uppercase text-rose-700 dark:text-rose-300">
                            <AlertTriangle className="h-3 w-3" />
                            High
                          </span>
                        ) : c.risk_level === "medium" ? (
                          <span className="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[10px] font-bold uppercase text-amber-700 dark:text-amber-300">
                            Medium
                          </span>
                        ) : c.risk_level === "low" ? (
                          <span className="rounded-full border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-[10px] font-bold uppercase text-sky-700 dark:text-sky-300">
                            Low
                          </span>
                        ) : (
                          <span className="rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[10px] text-ink-muted">
                            Available
                          </span>
                        );

                      return (
                        <tr
                          key={c.domain}
                          className={
                            c.risk_level === "high"
                              ? "bg-rose-500/[0.06]"
                              : "hover:bg-surface-alt/70"
                          }
                        >
                          <td className="px-4 py-2.5 align-top">
                            <div className="font-mono font-semibold text-ink">
                              {c.domain}
                            </div>
                            <div className="text-[11px] text-ink-muted">
                              {c.risk_reason}
                            </div>
                          </td>
                          <td className="whitespace-nowrap px-4 py-2.5 align-top">
                            <span className="rounded border border-line bg-canvas px-2 py-0.5 text-[11px] text-ink-secondary">
                              {c.fuzzer}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-4 py-2.5 align-top">
                            {badge}
                          </td>
                          <td className="px-4 py-2.5 align-top font-mono text-[11px]">
                            {c.a_records.length > 0 && (
                              <div className="text-ink">A: {c.a_records.join(", ")}</div>
                            )}
                            {c.mx_records.length > 0 && (
                              <div className="text-rose-700 dark:text-rose-300">
                                MX: {c.mx_records.join(", ")}
                              </div>
                            )}
                            {c.ns_records.length > 0 && (
                              <div className="text-ink-muted">
                                NS: {c.ns_records.slice(0, 2).join(", ")}
                              </div>
                            )}
                            {!c.registered && <span className="text-ink-muted">—</span>}
                          </td>
                          <td className="whitespace-nowrap px-4 py-2.5 text-right align-top">
                            {c.registered && (
                              <button
                                type="button"
                                onClick={() => onInspectDomain(c.domain)}
                                className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2 py-1 text-[11px] text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
                              >
                                Inspect
                                <ArrowUpRight className="h-3 w-3" />
                              </button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
