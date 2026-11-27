import {
  CheckCircle2,
  Copy,
  Globe2,
  HelpCircle,
  RefreshCw,
  Search,
  Sparkles,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { checkTldAvailability, copyToClipboard } from "../../lib/api";
import type { TldAvailabilityItem, TldAvailabilityReport } from "../../types/dns";

export interface TldCheckerTabProps {
  defaultDomain?: string;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

const DEFAULT_TLDS = [
  "com",
  "net",
  "org",
  "io",
  "dev",
  "ai",
  "app",
  "co",
  "xyz",
  "me",
  "gg",
  "cloud",
];

const TLD_PRESETS: Array<{ label: string; tlds: string[] }> = [
  { label: "Popular (12)", tlds: DEFAULT_TLDS },
  {
    label: "Tech & SaaS",
    tlds: ["dev", "app", "ai", "io", "sh", "tech", "cloud", "tools", "software", "systems", "digital", "run"],
  },
  {
    label: "Short & Country",
    tlds: ["co", "me", "gg", "tv", "cc", "to", "uk", "de", "ca", "nl", "eu", "ch"],
  },
];

const ALL_QUICK_TLDS = [
  "com",
  "net",
  "org",
  "io",
  "dev",
  "ai",
  "app",
  "co",
  "xyz",
  "me",
  "gg",
  "cloud",
  "sh",
  "tech",
  "tools",
  "so",
  "tv",
  "cc",
  "uk",
  "de",
  "eu",
  "ca",
  "us",
  "info",
];

type FilterStatus = "all" | "available" | "registered" | "unknown";

function extractBaseName(domainOrLabel: string): string {
  const clean = domainOrLabel
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split(/[/?#]/)[0] ?? "";
  return clean.split(".")[0] ?? "";
}

export function TldCheckerTab({
  defaultDomain,
  onInspectDomain,
  onNotify,
}: TldCheckerTabProps) {
  const [baseName, setBaseName] = useState(extractBaseName(defaultDomain || "") || "myproject");
  const [selectedTlds, setSelectedTlds] = useState<string[]>(DEFAULT_TLDS);
  const [customTlds, setCustomTlds] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<TldAvailabilityReport | null>(null);
  const [filter, setFilter] = useState<FilterStatus>("all");

  const effectiveTlds = useMemo(() => {
    const extra = customTlds
      .split(/[\s,]+/)
      .map((t) => t.trim().toLowerCase().replace(/^\./, ""))
      .filter(Boolean);
    return Array.from(new Set([...selectedTlds, ...extra])).slice(0, 24);
  }, [selectedTlds, customTlds]);

  const toggleTld = (tld: string) => {
    setSelectedTlds((prev) =>
      prev.includes(tld) ? prev.filter((x) => x !== tld) : [...prev, tld].slice(0, 24),
    );
  };

  const runCheck = async () => {
    const clean = baseName.trim();
    if (!clean) {
      setError("Enter a domain label or name (e.g. acme or acme.com).");
      return;
    }
    setLoading(true);
    setError(null);
    setFilter("all");
    try {
      const res = await checkTldAvailability(
        clean,
        effectiveTlds.length > 0 ? effectiveTlds : undefined,
      );
      setReport(res);
    } catch (err) {
      setError(String(err));
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const filteredItems = useMemo(() => {
    if (!report) return [];
    if (filter === "all") return report.items;
    return report.items.filter((i) => i.status === filter);
  }, [report, filter]);

  const copyAvailable = async () => {
    if (!report) return;
    const avail = report.items.filter((i) => i.status === "available").map((i) => i.domain);
    if (avail.length === 0) {
      onNotify("No available domains to copy");
      return;
    }
    await copyToClipboard(avail.join("\n"));
    onNotify(`Copied ${avail.length} available domain(s)`);
  };

  const renderCardBadge = (item: TldAvailabilityItem) => {
    if (item.status === "available") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="h-3 w-3" />
          Available
        </span>
      );
    }
    if (item.status === "registered") {
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-secondary">
          <XCircle className="h-3 w-3 text-ink-muted" />
          Registered
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
        <HelpCircle className="h-3 w-3" />
        Unknown
      </span>
    );
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
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div>
            <h3 className="text-sm font-semibold text-ink">
              Multi-TLD Domain Availability Checker
            </h3>
            <p className="text-[11px] text-ink-muted">
              Concurrently checks DNS + RDAP/WHOIS across up to 24 TLDs to find available domains.
            </p>
          </div>
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            {TLD_PRESETS.map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => setSelectedTlds(preset.tlds)}
                className="rounded-md border border-line bg-surface-alt px-2 py-1 font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
              >
                {preset.label}
              </button>
            ))}
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={baseName}
            onChange={(e) => setBaseName(e.target.value)}
            placeholder="Base name (e.g. acme)"
            className="min-w-[200px] flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          />
          <input
            type="text"
            value={customTlds}
            onChange={(e) => setCustomTlds(e.target.value)}
            placeholder="Extra TLDs (e.g. rs, fm, studio)"
            className="w-56 rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
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
            {loading ? "Checking TLDs..." : `Check (${effectiveTlds.length} TLDs)`}
          </button>
        </div>

        {/* TLD Toggle Chips */}
        <div className="flex flex-wrap gap-1.5 pt-1">
          {ALL_QUICK_TLDS.map((tld) => {
            const active = selectedTlds.includes(tld);
            return (
              <button
                key={tld}
                type="button"
                onClick={() => toggleTld(tld)}
                className={`rounded-md border px-2 py-0.5 font-mono text-[11px] transition ${
                  active
                    ? "border-sky-500/40 bg-sky-500/15 font-semibold text-sky-700 dark:text-sky-300"
                    : "border-line bg-canvas text-ink-muted hover:text-ink"
                }`}
              >
                .{tld}
              </button>
            );
          })}
        </div>
      </form>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-3.5 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-4">
          {/* Summary Bar */}
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-3.5">
            <div className="flex flex-wrap items-center gap-3 text-xs">
              <span className="inline-flex items-center gap-1.5 font-semibold text-ink">
                <Sparkles className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                {report.base_name}.*
              </span>
              <span className="text-ink-muted">Checked: {report.checked_count}</span>
              <span className="font-semibold text-emerald-600 dark:text-emerald-400">
                Available: {report.available_count}
              </span>
              <span className="text-ink-secondary">
                Registered: {report.registered_count}
              </span>
              <span className="font-mono text-[11px] text-ink-muted">
                {report.latency_ms}ms
              </span>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex rounded-lg border border-line bg-surface-alt p-0.5 text-[11px]">
                {(
                  [
                    ["all", "All"],
                    ["available", "Available"],
                    ["registered", "Registered"],
                    ["unknown", "Unknown"],
                  ] as const
                ).map(([id, label]) => (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setFilter(id)}
                    className={`rounded-md px-2 py-0.5 font-medium transition ${
                      filter === id
                        ? "bg-surface text-ink shadow-sm"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>

              {report.available_count > 0 && (
                <button
                  type="button"
                  onClick={() => void copyAvailable()}
                  className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                >
                  <Copy className="h-3 w-3" />
                  Copy Available
                </button>
              )}
            </div>
          </div>

          {/* Availability Grid */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {filteredItems.map((item) => (
              <div
                key={item.domain}
                className={`flex flex-col justify-between rounded-xl border p-3.5 transition ${
                  item.status === "available"
                    ? "border-emerald-500/35 bg-emerald-500/[0.04]"
                    : "border-line bg-surface"
                }`}
              >
                <div>
                  <div className="flex items-start justify-between gap-2">
                    <span className="break-all font-mono text-sm font-semibold text-ink">
                      {item.domain}
                    </span>
                    {renderCardBadge(item)}
                  </div>

                  <div className="mt-2 space-y-1 text-[11px] text-ink-muted">
                    {item.registrar && (
                      <div className="truncate" title={item.registrar}>
                        Registrar: <span className="text-ink-secondary">{item.registrar}</span>
                      </div>
                    )}
                    {item.expiry_date && (
                      <div>
                        Expires: <span className="font-mono text-ink-secondary">{item.expiry_date}</span>
                      </div>
                    )}
                    {item.detail && <div className="text-ink-muted">{item.detail}</div>}
                    <div className="flex items-center gap-2 font-mono text-[10px]">
                      <span>DNS: {item.has_dns ? "Present" : "None"}</span>
                      <span>·</span>
                      <span>{item.latency_ms}ms</span>
                    </div>
                  </div>
                </div>

                <div className="mt-3 flex items-center justify-between gap-2 border-t border-line pt-2.5">
                  <button
                    type="button"
                    onClick={() => {
                      void copyToClipboard(item.domain);
                      onNotify(`Copied ${item.domain}`);
                    }}
                    className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-ink"
                  >
                    <Copy className="h-3 w-3" />
                    Copy
                  </button>
                  <button
                    type="button"
                    onClick={() => onInspectDomain(item.domain)}
                    className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-sky-700 transition hover:border-sky-500/40 dark:text-sky-300"
                  >
                    <Globe2 className="h-3 w-3" />
                    Inspect
                  </button>
                </div>
              </div>
            ))}
          </div>

          {filteredItems.length === 0 && (
            <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
              No domains match this availability filter.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
