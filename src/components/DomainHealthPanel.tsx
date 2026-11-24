import {
  AlertTriangle,
  CheckCircle2,
  HeartPulse,
  Info,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  XCircle,
} from "lucide-react";
import type { BlacklistEntry, DomainHealthReport } from "../types/dns";

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
                <th className="px-4 py-2.5">Details / Code</th>
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
                    <div className="font-medium text-ink">
                      {entry.list_name}
                    </div>
                    <div className="font-mono text-[11px] text-ink-muted">
                      {entry.zone}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 align-top">
                    <div className="font-mono text-ink-secondary">{entry.target}</div>
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

export function DomainHealthPanel({ health }: { health: DomainHealthReport }) {
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
        <div className="flex items-center gap-4 rounded-xl border border-line bg-surface p-4">
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

      {/* Health Audit Checklist */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="border-b border-line bg-surface-alt px-4 py-2.5 text-xs font-semibold text-ink">
          Health &amp; Safety Audit Breakdown
        </div>
        <div className="divide-y divide-line">
          {health.checks.map((chk) => {
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
