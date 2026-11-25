import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  HeartPulse,
  Info,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Wrench,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { copyToClipboard, saveExport } from "../lib/api";
import { formatAsAuditHtml, formatAsAuditMarkdown } from "../lib/export";
import type {
  BlacklistEntry,
  DnsQueryReport,
  DomainHealthReport,
  HealthCheckItem,
} from "../types/dns";

function BlacklistBadge({ status }: { status: BlacklistEntry["status"] }) {
  switch (status) {
    case "clean":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="h-3 w-3" />
          Clean
        </span>
      );
    case "listed":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-300">
          <ShieldX className="h-3 w-3" />
          Listed
        </span>
      );
    case "policy":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-3 w-3" />
          Policy
        </span>
      );
    case "blocked":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-secondary">
          <Info className="h-3 w-3" />
          Blocked
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-muted">
          <XCircle className="h-3 w-3" />
          Error
        </span>
      );
  }
}

function SeverityBadge({ severity }: { severity: HealthCheckItem["severity"] }) {
  const tone =
    severity === "critical"
      ? "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
      : severity === "high"
        ? "border-orange-500/40 bg-orange-500/15 text-orange-700 dark:text-orange-300"
        : severity === "medium"
          ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
          : severity === "low"
            ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
            : "border-line bg-surface-alt text-ink-muted";

  return (
    <span
      className={`rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider ${tone}`}
    >
      {severity}
    </span>
  );
}

function BlacklistTable({
  title,
  entries,
  emptyMessage,
}: {
  title: string;
  entries: BlacklistEntry[];
  emptyMessage: string;
}) {
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-surface">
      <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5">
        <span className="text-xs font-semibold text-ink">{title}</span>
        <span className="font-mono text-[11px] text-ink-muted">
          {entries.length} check{entries.length === 1 ? "" : "s"}
        </span>
      </div>

      {entries.length === 0 ? (
        <div className="px-4 py-6 text-center text-xs text-ink-muted">
          {emptyMessage}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-line bg-canvas/70 text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                <th className="px-4 py-2.5">Blacklist</th>
                <th className="px-4 py-2.5">Target</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Details / Delist</th>
                <th className="px-4 py-2.5 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {entries.map((entry, idx) => (
                <tr
                  key={`${entry.zone}-${entry.target}-${idx}`}
                  className={
                    entry.status === "listed"
                      ? "bg-rose-500/[0.06]"
                      : "hover:bg-surface-alt/70"
                  }
                >
                  <td className="px-4 py-2.5 align-top">
                    <div className="font-medium text-ink">{entry.list_name}</div>
                    <div className="font-mono text-[11px] text-ink-muted">
                      {entry.zone}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 align-top">
                    <div className="font-mono text-ink-secondary">
                      {entry.target}
                    </div>
                    <div className="text-[11px] text-ink-muted">
                      {entry.target_role}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 align-top">
                    <BlacklistBadge status={entry.status} />
                  </td>
                  <td className="px-4 py-2.5 align-top text-ink-secondary">
                    {entry.detail ? (
                      <div>{entry.detail}</div>
                    ) : (
                      <span className="text-ink-muted">Not listed</span>
                    )}
                    {entry.return_codes.length > 0 && (
                      <div className="mt-0.5 font-mono text-[11px] text-ink-muted">
                        {entry.return_codes.join(", ")}
                      </div>
                    )}
                    {entry.status === "listed" && entry.delist_url && (
                      <a
                        href={entry.delist_url}
                        target="_blank"
                        rel="noreferrer"
                        className="mt-1 inline-flex items-center gap-1 text-[11px] font-medium text-rose-700 underline decoration-rose-500/40 hover:text-rose-600 dark:text-rose-300"
                      >
                        Delisting portal
                        <ExternalLink className="h-3 w-3" />
                      </a>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right align-top font-mono text-ink-muted">
                    {entry.latency_ms}ms
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

interface DomainHealthPanelProps {
  health: DomainHealthReport;
  report: DnsQueryReport;
  onNotify: (msg: string) => void;
}

export function DomainHealthPanel({
  health,
  report,
  onNotify,
}: DomainHealthPanelProps) {
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [checkFilter, setCheckFilter] = useState<"all" | "needs_fix" | "passed">(
    "all",
  );

  const actionableFixes = useMemo(() => {
    return health.checks
      .filter((c) => c.status === "fail" || c.status === "warn")
      .sort((a, b) => {
        const sd =
          (SEVERITY_ORDER[a.severity] ?? 9) - (SEVERITY_ORDER[b.severity] ?? 9);
        if (sd !== 0) return sd;
        return b.max_points - b.points - (a.max_points - a.points);
      });
  }, [health.checks]);

  const categoryScores = useMemo(() => {
    const map = new Map<string, { pts: number; max: number }>();
    for (const chk of health.checks) {
      const cur = map.get(chk.category) ?? { pts: 0, max: 0 };
      cur.pts += chk.points;
      cur.max += chk.max_points;
      map.set(chk.category, cur);
    }
    return Array.from(map.entries());
  }, [health.checks]);

  const filteredChecks = useMemo(() => {
    if (checkFilter === "needs_fix") {
      return health.checks.filter(
        (c) => c.status === "fail" || c.status === "warn",
      );
    }
    if (checkFilter === "passed") {
      return health.checks.filter(
        (c) => c.status === "pass" || c.status === "info",
      );
    }
    return health.checks;
  }, [health.checks, checkFilter]);

  const handleCopySnippet = async (id: string, snippet: string) => {
    await copyToClipboard(snippet);
    setCopiedId(id);
    onNotify("Copied remediation snippet");
    setTimeout(() => setCopiedId((prev) => (prev === id ? null : prev)), 1500);
  };

  const handleExportAudit = async (ext: "md" | "html") => {
    const content =
      ext === "md" ? formatAsAuditMarkdown(report) : formatAsAuditHtml(report);
    const filename = `${report.domain}-audit.${ext}`;
    try {
      const ok = await saveExport(filename, ext, content);
      if (ok) onNotify(`Saved ${filename}`);
    } catch (err) {
      onNotify(`Export failed: ${String(err)}`);
    }
  };

  const gradeTone =
    health.overall_status === "healthy"
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
      : health.overall_status === "caution"
        ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
        : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300";

  const statusLabel =
    health.overall_status === "healthy"
      ? "Healthy & Safe"
      : health.overall_status === "caution"
        ? "Caution"
        : "At Risk";

  const spamBadge =
    health.spam_status === "clean" ? (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-3 py-1 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
        <ShieldCheck className="h-4 w-4" />
        Spam Status: Clean
      </span>
    ) : health.spam_status === "caution" ? (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-700 dark:text-amber-300">
        <ShieldAlert className="h-4 w-4" />
        Spam Status: Caution
      </span>
    ) : (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/15 px-3 py-1 text-xs font-semibold text-rose-700 dark:text-rose-300">
        <ShieldX className="h-4 w-4" />
        Spam Status: Listed
      </span>
    );

  return (
    <div className="space-y-4">
      {/* Top Hero Cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="flex flex-col justify-between gap-3 rounded-xl border border-line bg-surface p-4">
          <div className="flex items-center gap-4">
            <div
              className={`flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-2xl border ${gradeTone}`}
            >
              <span className="font-mono text-2xl font-bold leading-none">
                {health.grade}
              </span>
              <span className="mt-1 font-mono text-[11px] opacity-85">
                {health.score}/100
              </span>
            </div>
            <div className="min-w-0 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <HeartPulse className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                <h3 className="text-sm font-semibold text-ink">
                  Overall Domain Health
                </h3>
                <span
                  className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${gradeTone}`}
                >
                  {statusLabel}
                </span>
              </div>
              <p className="mt-1.5 text-xs leading-relaxed text-ink-muted">
                {health.summary}
              </p>
              <div className="mt-2.5 flex flex-wrap items-center gap-2">
                <button
                  type="button"
                  onClick={() => void handleExportAudit("md")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/50 hover:text-ink"
                >
                  <Download className="h-3 w-3 text-sky-600 dark:text-sky-400" />
                  Export Audit (.md)
                </button>
                <button
                  type="button"
                  onClick={() => void handleExportAudit("html")}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/50 hover:text-ink"
                >
                  <Download className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
                  Export Audit (.html)
                </button>
              </div>
            </div>
          </div>

          {/* Category mini-bars */}
          <div className="grid grid-cols-2 gap-2 border-t border-line pt-3 sm:grid-cols-5">
            {categoryScores.map(([cat, val]) => {
              const pct = val.max > 0 ? Math.round((val.pts / val.max) * 100) : 100;
              const barColor =
                pct >= 80
                  ? "bg-emerald-500"
                  : pct >= 55
                    ? "bg-amber-500"
                    : "bg-rose-500";
              return (
                <div key={cat} className="space-y-1">
                  <div className="flex items-center justify-between text-[10px]">
                    <span className="truncate font-medium text-ink-secondary">
                      {cat}
                    </span>
                    <span className="font-mono text-ink-muted">
                      {val.pts}/{val.max}
                    </span>
                  </div>
                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-alt">
                    <div
                      className={`h-full rounded-full ${barColor}`}
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            {spamBadge}
            <span className="font-mono text-xs text-ink-secondary">
              {health.blacklists_listed} / {health.blacklists_checked} listed
            </span>
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-ink-muted">
            {health.spam_summary}
          </p>
          {health.checked_ips.length > 0 && (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px] text-ink-muted">
              <span>Checked IPs:</span>
              {health.checked_ips.map((ip) => (
                <span
                  key={ip}
                  className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-ink-secondary"
                >
                  {ip}
                </span>
              ))}
            </div>
          )}
          {health.blacklists_blocked > 0 && (
            <div className="mt-2 text-[11px] text-ink-muted">
              Note: {health.blacklists_blocked} blacklist check(s) were blocked by
              the upstream DNS resolver&apos;s open-resolver policy.
            </div>
          )}
        </div>
      </div>

      {/* Prioritized "Fix First" Action Plan */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5">
          <div className="flex items-center gap-2">
            <Wrench className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            <span className="text-xs font-semibold text-ink">
              Actionable Remediation Plan (&ldquo;Fix First&rdquo;)
            </span>
          </div>
          <span className="font-mono text-[11px] text-ink-muted">
            {actionableFixes.length === 0
              ? "0 issues found"
              : `${actionableFixes.length} item${actionableFixes.length === 1 ? "" : "s"} prioritized by risk & impact`}
          </span>
        </div>

        {actionableFixes.length === 0 ? (
          <div className="flex items-center gap-2.5 px-4 py-5 text-xs text-emerald-700 dark:text-emerald-300">
            <CheckCircle2 className="h-4 w-4 shrink-0" />
            <span>
              All audited checks passed. No immediate remediations are needed for{" "}
              <span className="font-mono font-semibold">{report.domain}</span>.
            </span>
          </div>
        ) : (
          <div className="divide-y divide-line">
            {actionableFixes.map((chk) => {
              const gain = chk.max_points - chk.points;
              return (
                <div key={chk.id} className="space-y-2.5 p-4">
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <SeverityBadge severity={chk.severity} />
                      <span className="text-xs font-semibold text-ink">
                        {chk.title}
                      </span>
                      <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-ink-muted">
                        {chk.category}
                      </span>
                    </div>
                    <div className="flex items-center gap-2">
                      {gain > 0 && (
                        <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                          +{gain} pts
                        </span>
                      )}
                      {chk.reference_url && (
                        <a
                          href={chk.reference_url}
                          target="_blank"
                          rel="noreferrer"
                          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                        >
                          Docs / Delist
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      )}
                    </div>
                  </div>

                  <p className="text-xs text-ink-secondary">{chk.detail}</p>

                  {chk.why_it_matters && (
                    <p className="text-[11px] leading-relaxed text-ink-muted">
                      <span className="font-semibold text-ink-secondary">
                        Why it matters:{" "}
                      </span>
                      {chk.why_it_matters}
                    </p>
                  )}

                  {chk.remediation_steps.length > 0 && (
                    <ol className="list-decimal space-y-1 pl-5 text-xs text-ink-secondary">
                      {chk.remediation_steps.map((step, idx) => (
                        <li key={idx}>{step}</li>
                      ))}
                    </ol>
                  )}

                  {chk.suggested_snippet && (
                    <div className="overflow-hidden rounded-lg border border-line bg-canvas">
                      <div className="flex items-center justify-between border-b border-line bg-surface-alt px-3 py-1.5">
                        <span className="text-[11px] font-medium text-ink-secondary">
                          {chk.snippet_label ?? "Recommended Configuration"}
                        </span>
                        <button
                          type="button"
                          onClick={() =>
                            void handleCopySnippet(chk.id, chk.suggested_snippet!)
                          }
                          className="inline-flex items-center gap-1 rounded px-2 py-0.5 text-[11px] font-medium text-ink-secondary hover:bg-surface hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          {copiedId === chk.id ? (
                            <>
                              <Check className="h-3 w-3 text-emerald-500" />
                              Copied
                            </>
                          ) : (
                            <>
                              <Copy className="h-3 w-3" />
                              Copy Snippet
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="overflow-x-auto p-3 font-mono text-[11px] leading-relaxed text-ink">
                        {chk.suggested_snippet}
                      </pre>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Blacklist Tables */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <BlacklistTable
          title="Domain Blacklists (RHSBL)"
          entries={health.domain_blacklists}
          emptyMessage="No domain blacklists were checked."
        />
        <BlacklistTable
          title="Web & Mail IP Blacklists (DNSBL)"
          entries={health.ip_blacklists}
          emptyMessage="No IPv4 A or MX mail server IPs were resolved for IP blacklist checking."
        />
      </div>

      {/* Full Health Audit Checklist */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5">
          <span className="text-xs font-semibold text-ink">
            Health &amp; Safety Audit Breakdown ({health.checks.length} checks)
          </span>
          <div className="inline-flex rounded-lg border border-line bg-canvas p-0.5 text-[11px]">
            {(
              [
                ["all", "All"],
                ["needs_fix", `Needs Fix (${actionableFixes.length})`],
                ["passed", "Passed / Info"],
              ] as const
            ).map(([id, label]) => (
              <button
                key={id}
                type="button"
                onClick={() => setCheckFilter(id)}
                className={`rounded-md px-2.5 py-0.5 font-medium transition ${
                  checkFilter === id
                    ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                {label}
              </button>
            ))}
          </div>
        </div>
        <div className="divide-y divide-line">
          {filteredChecks.map((chk) => {
            const icon =
              chk.status === "pass" ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-600 dark:text-emerald-400" />
              ) : chk.status === "warn" ? (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              ) : chk.status === "fail" ? (
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
              ) : (
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
              );

            return (
              <div
                key={chk.id}
                className="flex items-start justify-between gap-4 px-4 py-3"
              >
                <div className="flex items-start gap-3">
                  {icon}
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-xs font-semibold text-ink">
                        {chk.title}
                      </span>
                      <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-ink-muted">
                        {chk.category}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs text-ink-muted">{chk.detail}</p>
                  </div>
                </div>
                <div className="shrink-0 font-mono text-xs text-ink-secondary">
                  {chk.points}/{chk.max_points}
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
