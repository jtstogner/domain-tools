import {
  ChevronLeft,
  ChevronRight,
  Database,
  History,
  RefreshCw,
  Trash2,
  Zap,
} from "lucide-react";
import type { HistoryEntry } from "../types/dns";

function dotColor(status: string): string {
  switch (status) {
    case "pass":
      return "bg-emerald-500 dark:bg-emerald-400";
    case "warn":
      return "bg-amber-500 dark:bg-amber-400";
    case "fail":
      return "bg-rose-500 dark:bg-rose-400";
    default:
      return "bg-slate-400 dark:bg-slate-600";
  }
}

interface HistorySidebarProps {
  history: HistoryEntry[];
  collapsed: boolean;
  onToggleCollapse: () => void;
  onSelectDomain: (domain: string, options?: { forceRefresh?: boolean }) => void;
  onClearHistory: () => void;
  cachedDomains?: Record<string, { cachedAt: number; fresh: boolean }>;
  cacheCount?: number;
  onClearCache?: () => void;
  activeDomain?: string;
}

export function HistorySidebar({
  history,
  collapsed,
  onToggleCollapse,
  onSelectDomain,
  onClearHistory,
  cachedDomains,
  cacheCount = 0,
  onClearCache,
  activeDomain,
}: HistorySidebarProps) {
  if (collapsed) {
    return (
      <aside className="flex w-12 shrink-0 flex-col items-center border-r border-line bg-chrome py-3">
        <button
          type="button"
          onClick={onToggleCollapse}
          title="Expand history"
          className="rounded-lg border border-line bg-surface p-2 text-ink-muted hover:text-ink"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
        <History className="mt-4 h-4 w-4 text-ink-muted" />
      </aside>
    );
  }

  return (
    <aside className="flex w-64 shrink-0 flex-col border-r border-line bg-chrome">
      <div className="flex items-center justify-between border-b border-line px-3.5 py-3">
        <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-ink-secondary">
          <History className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
          Recent Lookups
        </div>
        <div className="flex items-center gap-1">
          {history.length > 0 && (
            <button
              type="button"
              onClick={onClearHistory}
              title="Clear history"
              className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-rose-600 dark:hover:text-rose-300"
            >
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          )}
          <button
            type="button"
            onClick={onToggleCollapse}
            title="Collapse sidebar"
            className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-2">
        {history.length === 0 ? (
          <div className="px-2 py-6 text-center text-xs text-ink-muted">
            Domains you query will appear here.
          </div>
        ) : (
          <div className="space-y-1">
            {history.map((item) => {
              const isActive = item.domain === activeDomain;
              const cacheInfo = cachedDomains?.[item.domain.toLowerCase()];
              const timeLabel = new Date(item.queried_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              });

              return (
                <div
                  key={`${item.domain}-${item.queried_at}`}
                  className={`group flex items-stretch rounded-lg border transition ${
                    isActive
                      ? "border-sky-500/40 bg-sky-500/10"
                      : "border-transparent hover:border-line hover:bg-surface-alt"
                  }`}
                >
                  <button
                    type="button"
                    onClick={() => onSelectDomain(item.domain)}
                    className="min-w-0 flex-1 px-2.5 py-2 text-left"
                  >
                    <div className="flex items-center justify-between gap-1.5">
                      <span className="flex min-w-0 items-center gap-1.5">
                        {cacheInfo && (
                          <span
                            title={
                              cacheInfo.fresh
                                ? "Cached full report (instant load)"
                                : "Cached report (stale — will refresh)"
                            }
                            className={`inline-flex shrink-0 items-center ${
                              cacheInfo.fresh
                                ? "text-emerald-600 dark:text-emerald-400"
                                : "text-amber-500/80 dark:text-amber-400/80"
                            }`}
                          >
                            <Zap className="h-3 w-3" />
                          </span>
                        )}
                        <span className="truncate font-mono text-xs font-medium text-ink">
                          {item.domain}
                        </span>
                      </span>
                      <span className="shrink-0 text-[10px] text-ink-muted">
                        {timeLabel}
                      </span>
                    </div>
                    <div className="mt-1.5 flex items-center justify-between text-[10px] text-ink-muted">
                      <span>{item.totalRecords} records</span>
                      <div
                        className="flex items-center gap-1"
                        title={`SPF: ${item.spfStatus} | DMARC: ${item.dmarcStatus} | DKIM: ${item.dkimStatus} | DNSSEC: ${item.dnssecStatus}`}
                      >
                        <span className={`h-1.5 w-1.5 rounded-full ${dotColor(item.spfStatus)}`} />
                        <span className={`h-1.5 w-1.5 rounded-full ${dotColor(item.dmarcStatus)}`} />
                        <span className={`h-1.5 w-1.5 rounded-full ${dotColor(item.dkimStatus)}`} />
                        <span className={`h-1.5 w-1.5 rounded-full ${dotColor(item.dnssecStatus)}`} />
                      </div>
                    </div>
                  </button>

                  <button
                    type="button"
                    onClick={() => onSelectDomain(item.domain, { forceRefresh: true })}
                    title={`Force fresh lookup for ${item.domain}`}
                    className="flex shrink-0 items-center justify-center rounded-r-lg px-1.5 text-ink-muted opacity-0 transition hover:bg-surface hover:text-sky-600 group-hover:opacity-100 focus:opacity-100 dark:hover:text-sky-300"
                  >
                    <RefreshCw className="h-3 w-3" />
                  </button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      {onClearCache && (
        <div className="flex items-center justify-between border-t border-line px-3 py-2 text-[11px] text-ink-muted">
          <span className="inline-flex items-center gap-1.5">
            <Database className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
            <span>
              {cacheCount} cached {cacheCount === 1 ? "domain" : "domains"}
            </span>
          </span>
          {cacheCount > 0 && (
            <button
              type="button"
              onClick={onClearCache}
              title="Clear all cached domain reports"
              className="rounded px-1.5 py-0.5 text-[10px] font-medium text-ink-secondary transition hover:bg-surface-alt hover:text-rose-600 dark:hover:text-rose-300"
            >
              Clear
            </button>
          )}
        </div>
      )}
    </aside>
  );
}
