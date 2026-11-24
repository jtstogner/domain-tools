import { History, Trash2, ChevronLeft, ChevronRight } from "lucide-react";
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
  onSelectDomain: (domain: string) => void;
  onClearHistory: () => void;
  activeDomain?: string;
}

export function HistorySidebar({
  history,
  collapsed,
  onToggleCollapse,
  onSelectDomain,
  onClearHistory,
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
              const timeLabel = new Date(item.queried_at).toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit",
              });

              return (
                <button
                  key={`${item.domain}-${item.queried_at}`}
                  type="button"
                  onClick={() => onSelectDomain(item.domain)}
                  className={`w-full rounded-lg border px-2.5 py-2 text-left transition ${
                    isActive
                      ? "border-sky-500/40 bg-sky-500/10"
                      : "border-transparent hover:border-line hover:bg-surface-alt"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="truncate font-mono text-xs font-medium text-ink">
                      {item.domain}
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
              );
            })}
          </div>
        )}
      </div>
    </aside>
  );
}
