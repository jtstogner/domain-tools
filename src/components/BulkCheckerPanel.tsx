import {
  ArrowUpRight,
  Bookmark,
  Download,
  ExternalLink,
  ListChecks,
  Loader2,
  Play,
  Search,
  Trash2,
  Upload,
} from "lucide-react";
import { type ChangeEvent, useEffect, useMemo, useRef, useState } from "react";
import { runBulkCheck, saveExport } from "../lib/api";
import type { BulkDomainResult, BulkProgressEvent } from "../types/dns";

interface BulkCheckerPanelProps {
  watchedDomains?: Set<string>;
  onSaveBulkToWatchlist?: (items: BulkDomainResult[]) => void;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type FilterMode = "all" | "issues" | "expiring";

function parseDomainInput(text: string): string[] {
  const raw = text
    .split(/[\n,;\s]+/)
    .map((s) => s.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, ""))
    .filter((s) => s.length > 0 && s.includes("."));
  return Array.from(new Set(raw.map((s) => s.toLowerCase()))).slice(0, 100);
}

function statusBadge(status: BulkDomainResult["status"]): string {
  switch (status) {
    case "healthy":
      return "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
    case "caution":
      return "bg-amber-500/15 text-amber-700 dark:text-amber-300";
    default:
      return "bg-rose-500/15 text-rose-700 dark:text-rose-300";
  }
}

function tinyPill(status: string): string {
  if (status === "pass") return "text-emerald-600 dark:text-emerald-400";
  if (status === "warn") return "text-amber-600 dark:text-amber-400";
  return "text-rose-600 dark:text-rose-400";
}

function csvCell(v: string | number | boolean | null | undefined): string {
  const s = v == null ? "" : String(v);
  if (/[",\n\r]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

export function BulkCheckerPanel({
  watchedDomains,
  onSaveBulkToWatchlist,
  onInspectDomain,
  onNotify,
}: BulkCheckerPanelProps) {
  const [inputText, setInputText] = useState(
    "cloudflare.com\ngithub.com\nstripe.com",
  );
  const [running, setRunning] = useState(false);
  const [progress, setProgress] = useState<{ completed: number; total: number }>({
    completed: 0,
    total: 0,
  });
  const [results, setResults] = useState<BulkDomainResult[]>([]);
  const [filterMode, setFilterMode] = useState<FilterMode>("all");
  const [search, setSearch] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
      return;
    }
    let active = true;
    let unlisten: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen<BulkProgressEvent>("bulk-progress", ({ payload }) => {
          setProgress({ completed: payload.completed, total: payload.total });
          setResults((prev) => {
            if (prev.some((r) => r.domain === payload.result.domain)) {
              return prev.map((r) =>
                r.domain === payload.result.domain ? payload.result : r,
              );
            }
            return [...prev, payload.result];
          });
        }),
      )
      .then((fn) => {
        if (!active) fn();
        else unlisten = fn;
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const parsedDomains = useMemo(() => parseDomainInput(inputText), [inputText]);

  const handleRun = async () => {
    if (parsedDomains.length === 0) {
      onNotify("Enter at least one valid domain name");
      return;
    }
    setRunning(true);
    setResults([]);
    setProgress({ completed: 0, total: parsedDomains.length });
    try {
      const finalResults = await runBulkCheck(parsedDomains);
      setResults(finalResults);
    } catch (err) {
      onNotify(`Bulk check failed: ${String(err)}`);
    } finally {
      setRunning(false);
    }
  };

  const handleFileUpload = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = () => {
      if (typeof reader.result === "string") {
        setInputText(reader.result);
      }
    };
    reader.readAsText(file);
    e.target.value = "";
  };

  const filteredResults = useMemo(() => {
    const q = search.trim().toLowerCase();
    return results.filter((r) => {
      if (q && !r.domain.toLowerCase().includes(q)) return false;
      if (filterMode === "issues") return r.status !== "healthy";
      if (filterMode === "expiring") {
        return (
          (r.ssl_days_remaining != null && r.ssl_days_remaining <= 30) ||
          (r.domain_days_remaining != null && r.domain_days_remaining <= 30)
        );
      }
      return true;
    });
  }, [results, search, filterMode]);

  const exportCsv = async () => {
    const headers = [
      "domain",
      "status",
      "a_records",
      "mx_count",
      "ns_count",
      "http_status",
      "http_latency_ms",
      "ssl_valid",
      "ssl_days_remaining",
      "ssl_issuer",
      "spf_status",
      "dmarc_status",
      "dnssec_status",
      "registrar",
      "domain_expiry_date",
      "domain_days_remaining",
    ];
    const rows = filteredResults.map((r) =>
      [
        csvCell(r.domain),
        csvCell(r.status),
        csvCell(r.a_records.join("; ")),
        csvCell(r.mx_count),
        csvCell(r.ns_count),
        csvCell(r.http_status),
        csvCell(r.http_latency_ms),
        csvCell(r.ssl_valid),
        csvCell(r.ssl_days_remaining),
        csvCell(r.ssl_issuer),
        csvCell(r.spf_status),
        csvCell(r.dmarc_status),
        csvCell(r.dnssec_status),
        csvCell(r.registrar),
        csvCell(r.domain_expiry_date),
        csvCell(r.domain_days_remaining),
      ].join(","),
    );
    const saved = await saveExport(
      `bulk-domain-check-${Date.now()}.csv`,
      "csv",
      [headers.join(","), ...rows].join("\n") + "\n",
    );
    if (saved) onNotify("Exported bulk report CSV");
  };

  const exportJson = async () => {
    const saved = await saveExport(
      `bulk-domain-check-${Date.now()}.json`,
      "json",
      JSON.stringify(filteredResults, null, 2),
    );
    if (saved) onNotify("Exported bulk report JSON");
  };

  const pct =
    progress.total > 0
      ? Math.round((progress.completed / progress.total) * 100)
      : 0;

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h2 className="flex items-center gap-2 text-sm font-semibold text-ink">
              <ListChecks className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              Bulk Domain Checker
            </h2>
            <p className="text-[11px] text-ink-muted">
              Paste up to 100 domains (newline, comma, or CSV) to audit DNS, HTTP,
              SSL expiry, domain expiry, SPF, DMARC, and DNSSEC concurrently.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".txt,.csv"
              onChange={handleFileUpload}
              className="hidden"
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
            >
              <Upload className="h-3.5 w-3.5" />
              Import .txt/.csv
            </button>
            <button
              type="button"
              onClick={() => setInputText("")}
              className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs text-ink-muted hover:text-ink"
            >
              <Trash2 className="h-3.5 w-3.5" />
              Clear
            </button>
          </div>
        </div>

        <textarea
          rows={4}
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder={"example.com\ncloudflare.com\nmyclientdomain.org"}
          className="w-full rounded-lg border border-line bg-canvas p-3 font-mono text-xs text-ink outline-none focus:border-sky-500"
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="text-xs text-ink-muted">
            <span className="font-mono font-semibold text-ink">
              {parsedDomains.length}
            </span>{" "}
            unique domain{parsedDomains.length === 1 ? "" : "s"} queued (max 100)
          </div>

          <button
            type="button"
            disabled={running || parsedDomains.length === 0}
            onClick={() => void handleRun()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-4 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {running ? (
              <>
                <Loader2 className="h-3.5 w-3.5 animate-spin" />
                Checking {progress.completed}/{progress.total}...
              </>
            ) : (
              <>
                <Play className="h-3.5 w-3.5" />
                Run Bulk Check
              </>
            )}
          </button>
        </div>

        {running && (
          <div className="space-y-1">
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-alt">
              <div
                className="h-full rounded-full bg-sky-500 transition-all duration-200"
                style={{ width: `${Math.max(4, pct)}%` }}
              />
            </div>
          </div>
        )}
      </div>

      {results.length > 0 && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="relative">
                <Search className="pointer-events-none absolute top-2 left-2.5 h-3.5 w-3.5 text-ink-muted" />
                <input
                  type="text"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  placeholder="Filter domains..."
                  className="rounded-lg border border-line bg-surface py-1.5 pr-3 pl-8 text-xs text-ink outline-none focus:border-sky-500"
                />
              </div>

              {(
                [
                  ["all", `All (${results.length})`],
                  [
                    "issues",
                    `Attention (${results.filter((r) => r.status !== "healthy").length})`,
                  ],
                  [
                    "expiring",
                    `Expiring ≤30d (${
                      results.filter(
                        (r) =>
                          (r.ssl_days_remaining != null &&
                            r.ssl_days_remaining <= 30) ||
                          (r.domain_days_remaining != null &&
                            r.domain_days_remaining <= 30),
                      ).length
                    })`,
                  ],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setFilterMode(id)}
                  className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                    filterMode === id
                      ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                      : "border-line bg-surface text-ink-muted hover:text-ink"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              {onSaveBulkToWatchlist && (
                <button
                  type="button"
                  onClick={() => onSaveBulkToWatchlist(filteredResults)}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-sky-500/40 bg-sky-500/10 px-2.5 py-1.5 text-xs font-medium text-sky-700 hover:bg-sky-500/20 dark:text-sky-300"
                >
                  <Bookmark className="h-3.5 w-3.5" />
                  Watch All ({filteredResults.length})
                </button>
              )}
              <button
                type="button"
                onClick={() => void exportCsv()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
              >
                <Download className="h-3.5 w-3.5" />
                CSV
              </button>
              <button
                type="button"
                onClick={() => void exportJson()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
              >
                <Download className="h-3.5 w-3.5" />
                JSON
              </button>
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-line bg-surface">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                <tr>
                  <th className="px-4 py-2.5">Domain</th>
                  <th className="px-3 py-2.5">Status</th>
                  <th className="px-3 py-2.5">HTTP</th>
                  <th className="px-3 py-2.5">SSL Expiry</th>
                  <th className="px-3 py-2.5">Domain Expiry</th>
                  <th className="px-3 py-2.5">SPF / DMARC / DNSSEC</th>
                  <th className="px-3 py-2.5">A / MX / NS</th>
                  <th className="px-3 py-2.5 text-right">Deep Audit</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filteredResults.map((row) => (
                  <tr key={row.domain} className="hover:bg-surface-alt/50">
                    <td className="px-4 py-2.5 font-mono font-semibold text-ink">
                      {row.domain}
                    </td>
                    <td className="px-3 py-2.5">
                      <span
                        className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${statusBadge(row.status)}`}
                      >
                        {row.status}
                      </span>
                    </td>
                    <td className="px-3 py-2.5 font-mono">
                      {row.http_status ? (
                        <span className="text-ink">
                          {row.http_status}
                          {row.http_latency_ms != null && (
                            <span className="ml-1 text-[10px] text-ink-muted">
                              ({row.http_latency_ms}ms)
                            </span>
                          )}
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono">
                      {row.ssl_days_remaining != null ? (
                        <span
                          className={
                            row.ssl_valid === false || row.ssl_days_remaining <= 0
                              ? "font-semibold text-rose-600 dark:text-rose-400"
                              : row.ssl_days_remaining <= 30
                                ? "font-semibold text-amber-600 dark:text-amber-400"
                                : "text-emerald-600 dark:text-emerald-400"
                          }
                        >
                          {row.ssl_days_remaining}d
                          {row.ssl_valid === false ? " (!)" : ""}
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono">
                      {row.domain_days_remaining != null ? (
                        <span
                          title={row.domain_expiry_date ?? undefined}
                          className={
                            row.domain_days_remaining <= 30
                              ? "font-semibold text-amber-600 dark:text-amber-400"
                              : "text-ink-secondary"
                          }
                        >
                          {row.domain_days_remaining}d
                        </span>
                      ) : (
                        <span className="text-ink-muted">—</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px]">
                      <span className={tinyPill(row.spf_status)}>SPF</span>
                      {" / "}
                      <span className={tinyPill(row.dmarc_status)}>DMARC</span>
                      {" / "}
                      <span className={tinyPill(row.dnssec_status)}>DNSSEC</span>
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-ink-secondary">
                      {row.a_records.length}A / {row.mx_count}MX / {row.ns_count}NS
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <div className="inline-flex items-center gap-1.5">
                        {onSaveBulkToWatchlist && (
                          <button
                            type="button"
                            onClick={() => onSaveBulkToWatchlist([row])}
                            title={
                              watchedDomains?.has(row.domain.toLowerCase())
                                ? "Already in Watchlist (click to update baseline)"
                                : "Save to Watchlist"
                            }
                            className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-[11px] font-medium transition ${
                              watchedDomains?.has(row.domain.toLowerCase())
                                ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                                : "border-line bg-surface-alt text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                            }`}
                          >
                            <Bookmark
                              className={`h-3 w-3 ${
                                watchedDomains?.has(row.domain.toLowerCase())
                                  ? "fill-current"
                                  : ""
                              }`}
                            />
                            {watchedDomains?.has(row.domain.toLowerCase())
                              ? "Watched"
                              : "Watch"}
                          </button>
                        )}
                        <button
                          type="button"
                          onClick={() => onInspectDomain(row.domain)}
                          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                        >
                          Inspect
                          {row.final_url ? (
                            <ArrowUpRight className="h-3 w-3" />
                          ) : (
                            <ExternalLink className="h-3 w-3" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
