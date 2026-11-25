import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  Copy,
  Download,
  Loader2,
  Mail,
  Search,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard, saveExport, scanTyposquats } from "../lib/api";
import type { TyposquatReport } from "../types/dns";

interface TyposquatPanelProps {
  defaultDomain: string;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type RiskFilter = "all" | "registered" | "high" | "web";

export function TyposquatPanel({
  defaultDomain,
  onInspectDomain,
  onNotify,
}: TyposquatPanelProps) {
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<TyposquatReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState<RiskFilter>("registered");
  const [fuzzerFilter, setFuzzerFilter] = useState<string>("all");
  const [searchText, setSearchText] = useState("");
  const [copiedDomain, setCopiedDomain] = useState<string | null>(null);

  useEffect(() => {
    setReport(null);
    setError(null);
    setFuzzerFilter("all");
    setSearchText("");
  }, [defaultDomain]);

  const handleScan = async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await scanTyposquats(defaultDomain);
      setReport(res);
    } catch (err) {
      setError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const fuzzers = useMemo(() => {
    if (!report) return [];
    return Array.from(new Set(report.candidates.map((c) => c.fuzzer))).sort();
  }, [report]);

  const filtered = useMemo(() => {
    if (!report) return [];
    const needle = searchText.trim().toLowerCase();
    return report.candidates.filter((c) => {
      if (filter === "registered" && !c.registered) return false;
      if (filter === "high" && c.risk_level !== "high") return false;
      if (
        filter === "web" &&
        c.a_records.length === 0 &&
        c.aaaa_records.length === 0
      ) {
        return false;
      }
      if (fuzzerFilter !== "all" && c.fuzzer !== fuzzerFilter) return false;
      if (needle && !c.domain.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [report, filter, fuzzerFilter, searchText]);

  const handleExportCsv = async () => {
    if (!report) return;
    const lines = [
      "domain,fuzzer,registered,risk_level,a_records,mx_records,ns_records,risk_reason",
      ...filtered.map((c) =>
        [
          c.domain,
          c.fuzzer,
          c.registered,
          c.risk_level,
          `"${c.a_records.join(";")}"`,
          `"${c.mx_records.join(";")}"`,
          `"${c.ns_records.join(";")}"`,
          `"${c.risk_reason.replace(/"/g, '""')}"`,
        ].join(","),
      ),
    ];
    try {
      const saved = await saveExport(
        `${report.source_domain}-lookalikes.csv`,
        "csv",
        lines.join("\n") + "\n",
      );
      if (saved) onNotify(`Saved ${report.source_domain}-lookalikes.csv`);
    } catch (err) {
      onNotify(`Export failed: ${String(err)}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div>
          <div className="flex items-center gap-2">
            <ShieldAlert className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <h3 className="text-xs font-semibold text-ink">
              Typosquatting &amp; Brand Lookalike Scanner
            </h3>
          </div>
          <p className="mt-1 text-[11px] text-ink-muted">
            Generates up to 96 homoglyph, transposition, omission, TLD-swap, and
            phishing-lure variants of{" "}
            <span className="font-mono text-ink-secondary">{defaultDomain}</span>{" "}
            and checks live DNS A, AAAA, MX, and NS records.
          </p>
        </div>

        <button
          type="button"
          disabled={loading}
          onClick={() => void handleScan()}
          className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
        >
          {loading ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
          ) : (
            <Search className="h-3.5 w-3.5" />
          )}
          {loading ? "Scanning Lookalikes..." : "Scan Lookalikes"}
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Variants Checked</div>
              <div className="mt-1 font-mono text-xl font-bold text-ink">
                {report.total_checked}
                <span className="ml-1 text-xs font-normal text-ink-muted">
                  / {report.total_generated}
                </span>
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Registered</div>
              <div className="mt-1 font-mono text-xl font-bold text-amber-700 dark:text-amber-300">
                {report.registered_count}
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">
                High Risk (Active MX)
              </div>
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

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-4 py-2.5">
            <div className="flex flex-wrap items-center gap-1.5">
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
                  onClick={() => setFilter(id)}
                  className={`rounded-lg px-2.5 py-1 text-[11px] font-medium transition ${
                    filter === id
                      ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                      : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <select
                value={fuzzerFilter}
                onChange={(e) => setFuzzerFilter(e.target.value)}
                className="rounded-lg border border-line bg-canvas px-2 py-1 text-[11px] text-ink outline-none focus:border-sky-500"
              >
                <option value="all">All fuzzers</option>
                {fuzzers.map((f) => (
                  <option key={f} value={f}>
                    {f}
                  </option>
                ))}
              </select>
              <input
                type="text"
                value={searchText}
                onChange={(e) => setSearchText(e.target.value)}
                placeholder="Filter domain..."
                className="w-40 rounded-lg border border-line bg-canvas px-2.5 py-1 font-mono text-[11px] text-ink outline-none focus:border-sky-500"
              />
              <button
                type="button"
                onClick={() => void handleExportCsv()}
                className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
              >
                <Download className="h-3 w-3" />
                CSV
              </button>
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            {filtered.length === 0 ? (
              <div className="px-4 py-8 text-center text-xs text-ink-muted">
                No lookalike domains match the current filter.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas/70 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2.5">Variant Domain</th>
                      <th className="px-4 py-2.5">Technique</th>
                      <th className="px-4 py-2.5">Risk</th>
                      <th className="px-4 py-2.5">Web / Mail Records</th>
                      <th className="px-4 py-2.5 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {filtered.map((item) => {
                      const riskBadge =
                        item.risk_level === "high" ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
                            <Mail className="h-3 w-3" />
                            High (Active MX)
                          </span>
                        ) : item.risk_level === "medium" ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
                            <AlertTriangle className="h-3 w-3" />
                            Medium (Web IP)
                          </span>
                        ) : item.risk_level === "low" ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-sky-500/40 bg-sky-500/15 px-2 py-0.5 text-[11px] font-medium text-sky-700 dark:text-sky-300">
                            Low (NS Only)
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-muted">
                            <ShieldCheck className="h-3 w-3" />
                            Unregistered
                          </span>
                        );

                      return (
                        <tr
                          key={item.domain}
                          className={
                            item.risk_level === "high"
                              ? "bg-rose-500/[0.04]"
                              : "hover:bg-surface-alt/70"
                          }
                        >
                          <td className="px-4 py-2.5 align-top font-mono font-medium text-ink">
                            {item.domain}
                          </td>
                          <td className="px-4 py-2.5 align-top text-ink-secondary">
                            <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[11px]">
                              {item.fuzzer}
                            </span>
                          </td>
                          <td className="whitespace-nowrap px-4 py-2.5 align-top">
                            {riskBadge}
                          </td>
                          <td className="px-4 py-2.5 align-top text-[11px] text-ink-secondary">
                            {item.mx_records.length > 0 && (
                              <div className="font-mono text-rose-700 dark:text-rose-300">
                                MX: {item.mx_records.slice(0, 2).join(", ")}
                              </div>
                            )}
                            {(item.a_records.length > 0 ||
                              item.aaaa_records.length > 0) && (
                              <div className="font-mono text-ink-secondary">
                                IP:{" "}
                                {[...item.a_records, ...item.aaaa_records]
                                  .slice(0, 3)
                                  .join(", ")}
                              </div>
                            )}
                            {item.ns_records.length > 0 && (
                              <div className="font-mono text-ink-muted">
                                NS: {item.ns_records.slice(0, 2).join(", ")}
                              </div>
                            )}
                            {!item.registered && (
                              <span className="text-ink-muted">NXDOMAIN</span>
                            )}
                          </td>
                          <td className="whitespace-nowrap px-4 py-2.5 text-right align-top">
                            <div className="inline-flex items-center gap-1">
                              <button
                                type="button"
                                onClick={async () => {
                                  await copyToClipboard(item.domain);
                                  setCopiedDomain(item.domain);
                                  onNotify(`Copied ${item.domain}`);
                                  setTimeout(
                                    () =>
                                      setCopiedDomain((p) =>
                                        p === item.domain ? null : p,
                                      ),
                                    1400,
                                  );
                                }}
                                title="Copy domain"
                                className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
                              >
                                {copiedDomain === item.domain ? (
                                  <Check className="h-3.5 w-3.5 text-emerald-500" />
                                ) : (
                                  <Copy className="h-3.5 w-3.5" />
                                )}
                              </button>
                              {item.registered && (
                                <button
                                  type="button"
                                  onClick={() => onInspectDomain(item.domain)}
                                  className="inline-flex items-center gap-1 rounded border border-line bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                                >
                                  Inspect
                                  <ArrowUpRight className="h-3 w-3" />
                                </button>
                              )}
                            </div>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
