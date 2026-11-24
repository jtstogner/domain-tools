import { CheckCircle2, Clock, Loader2 } from "lucide-react";
import { useEffect, useState } from "react";

export type ProgressStageState = {
  id: string;
  label: string;
  status: "pending" | "running" | "done";
  elapsedMs?: number | null;
};

export const INITIAL_PROGRESS_STAGES: ProgressStageState[] = [
  { id: "dns", label: "DNS Records", status: "pending" },
  { id: "security", label: "Email & DNSSEC", status: "pending" },
  { id: "tls", label: "SSL / TLS", status: "pending" },
  { id: "redirects", label: "Redirects & TTFB", status: "pending" },
  { id: "whois", label: "WHOIS & RDAP", status: "pending" },
  { id: "website", label: "Website Stack", status: "pending" },
  { id: "subdomains", label: "Subdomains", status: "pending" },
  { id: "health", label: "Domain Health", status: "pending" },
  { id: "network", label: "IP / ASN / PTR", status: "pending" },
  { id: "ports", label: "Port Scan", status: "pending" },
];

interface QueryProgressBannerProps {
  domain: string;
  stages: ProgressStageState[];
  startedAt: number | null;
}

export function QueryProgressBanner({
  domain,
  stages,
  startedAt,
}: QueryProgressBannerProps) {
  const [elapsedSec, setElapsedSec] = useState(0);

  useEffect(() => {
    if (!startedAt) {
      setElapsedSec(0);
      return;
    }
    const update = () => {
      setElapsedSec(Math.max(0, (Date.now() - startedAt) / 1000));
    };
    update();
    const timer = window.setInterval(update, 100);
    return () => window.clearInterval(timer);
  }, [startedAt]);

  const completedCount = stages.filter((s) => s.status === "done").length;
  const runningCount = stages.filter((s) => s.status === "running").length;
  const totalCount = stages.length;
  const pct =
    totalCount > 0
      ? Math.min(
          100,
          Math.max(
            6,
            Math.round(
              ((completedCount + runningCount * 0.35) / totalCount) * 100,
            ),
          ),
        )
      : 6;

  return (
    <div
      role="status"
      aria-live="polite"
      className="rounded-xl border border-sky-500/30 bg-surface p-4 shadow-sm"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2.5">
          <Loader2 className="h-4 w-4 animate-spin text-sky-600 dark:text-sky-400" />
          <div className="text-xs font-semibold text-ink">
            Analyzing{" "}
            <span className="font-mono text-sky-600 dark:text-sky-400">
              {domain || "domain"}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-3 text-[11px] font-mono text-ink-muted">
          <span>
            {completedCount}/{totalCount} checks complete
          </span>
          <span className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-0.5 text-ink">
            <Clock className="h-3 w-3 text-sky-600 dark:text-sky-400" />
            {elapsedSec.toFixed(1)}s
          </span>
        </div>
      </div>

      <div className="mt-3 h-1.5 w-full overflow-hidden rounded-full bg-surface-alt">
        <div
          className="h-full rounded-full bg-sky-500 transition-all duration-300 ease-out"
          style={{ width: `${pct}%` }}
        />
      </div>

      <div className="mt-3 flex flex-wrap gap-1.5">
        {stages.map((stage) => {
          const isDone = stage.status === "done";
          const isRunning = stage.status === "running";
          return (
            <div
              key={stage.id}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition-colors ${
                isDone
                  ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : isRunning
                    ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                    : "border-line bg-surface-alt text-ink-muted"
              }`}
            >
              {isDone ? (
                <CheckCircle2 className="h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-400" />
              ) : isRunning ? (
                <Loader2 className="h-3 w-3 shrink-0 animate-spin text-sky-600 dark:text-sky-400" />
              ) : (
                <span className="h-2 w-2 shrink-0 rounded-full bg-ink-muted/40" />
              )}
              <span>{stage.label}</span>
              {isDone && stage.elapsedMs != null && (
                <span className="font-mono text-[10px] opacity-80">
                  {stage.elapsedMs >= 1000
                    ? `${(stage.elapsedMs / 1000).toFixed(1)}s`
                    : `${stage.elapsedMs}ms`}
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
