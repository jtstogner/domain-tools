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
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-300">
          <CheckCircle2 className="h-3 w-3" />
          Clean
        </span>
      );
    case "listed":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-300">
          <ShieldX className="h-3 w-3" />
          Listed
        </span>
      );
    case "policy":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-medium text-amber-300">
          <AlertTriangle className="h-3 w-3" />
          Policy
        </span>
      );
    case "blocked":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] font-medium text-slate-300">
          <Info className="h-3 w-3" />
          Blocked
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2 py-0.5 text-[11px] font-medium text-slate-400">
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
    <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
      <div className="flex items-center justify-between border-b border-slate-800 bg-[#0d131f] px-4 py-2.5">
        <span className="text-xs font-semibold text-slate-200">{title}</span>
        <span className="font-mono text-[11px] text-slate-400">
          {entries.length} check{entries.length === 1 ? "" : "s"}
        </span>
      </div>

      {entries.length === 0 ? (
        <div className="px-4 py-6 text-center text-xs text-slate-500">
          {emptyMessage}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 bg-[#0b0f17]/60 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <th className="px-4 py-2.5">Blacklist</th>
                <th className="px-4 py-2.5">Target</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Details / Code</th>
                <th className="px-4 py-2.5 text-right">Latency</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {entries.map((entry, idx) => (
                <tr
                  key={`${entry.zone}-${entry.target}-${idx}`}
                  className={
                    entry.status === "listed"
                      ? "bg-rose-500/[0.06]"
                      : "hover:bg-slate-800/30"
                  }
                >
                  <td className="px-4 py-2.5 align-top">
                    <div className="font-medium text-slate-100">
                      {entry.list_name}
                    </div>
                    <div className="font-mono text-[11px] text-slate-500">
                      {entry.zone}
                    </div>
                  </td>
                  <td className="px-4 py-2.5 align-top">
                    <div className="font-mono text-slate-200">{entry.target}</div>
                    <div className="text-[11px] text-slate-500">
                      {entry.target_role}
                    </div>
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 align-top">
                    <BlacklistBadge status={entry.status} />
                  </td>
                  <td className="px-4 py-2.5 align-top text-slate-300">
                    {entry.detail ? (
                      <div>{entry.detail}</div>
                    ) : (
                      <span className="text-slate-500">Not listed</span>
                    )}
                    {entry.return_codes.length > 0 && (
                      <div className="mt-0.5 font-mono text-[11px] text-slate-400">
                        {entry.return_codes.join(", ")}
                      </div>
                    )}
                  </td>
                  <td className="whitespace-nowrap px-4 py-2.5 text-right align-top font-mono text-slate-400">
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
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
      : health.overall_status === "caution"
        ? "border-amber-500/40 bg-amber-500/15 text-amber-300"
        : "border-rose-500/40 bg-rose-500/15 text-rose-300";

  const statusLabel =
    health.overall_status === "healthy"
      ? "Healthy & Safe"
      : health.overall_status === "caution"
        ? "Caution"
        : "At Risk";

  const spamBadge =
    health.spam_status === "clean" ? (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-3 py-1 text-xs font-semibold text-emerald-300">
        <ShieldCheck className="h-4 w-4" />
        Spam Status: Clean
      </span>
    ) : health.spam_status === "caution" ? (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-amber-500/40 bg-amber-500/15 px-3 py-1 text-xs font-semibold text-amber-300">
        <ShieldAlert className="h-4 w-4" />
        Spam Status: Caution
      </span>
    ) : (
      <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-500/40 bg-rose-500/15 px-3 py-1 text-xs font-semibold text-rose-300">
        <ShieldX className="h-4 w-4" />
        Spam Status: Listed
      </span>
    );

  return (
    <div className="space-y-4">
      {/* Top Hero Cards */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="flex items-center gap-4 rounded-xl border border-slate-800 bg-[#111827] p-4">
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
              <HeartPulse className="h-4 w-4 text-sky-400" />
              <h3 className="text-sm font-semibold text-slate-100">
                Overall Domain Health
              </h3>
              <span
                className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${gradeTone}`}
              >
                {statusLabel}
              </span>
            </div>
            <p className="mt-1.5 text-xs leading-relaxed text-slate-400">
              {health.summary}
            </p>
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            {spamBadge}
            <span className="font-mono text-xs text-slate-300">
              {health.blacklists_listed} / {health.blacklists_checked} listed
            </span>
          </div>
          <p className="mt-2.5 text-xs leading-relaxed text-slate-400">
            {health.spam_summary}
          </p>
          {health.checked_ips.length > 0 && (
            <div className="mt-2.5 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-400">
              <span>Checked IPs:</span>
              {health.checked_ips.map((ip) => (
                <span
                  key={ip}
                  className="rounded border border-slate-800 bg-[#0b0f17] px-2 py-0.5 font-mono text-slate-300"
                >
                  {ip}
                </span>
              ))}
            </div>
          )}
          {health.blacklists_blocked > 0 && (
            <div className="mt-2 text-[11px] text-slate-400">
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
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
        <div className="border-b border-slate-800 bg-[#0d131f] px-4 py-2.5 text-xs font-semibold text-slate-200">
          Health &amp; Safety Audit Breakdown
        </div>
        <div className="divide-y divide-slate-800/70">
          {health.checks.map((chk) => {
            const icon =
              chk.status === "pass" ? (
                <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-400" />
              ) : chk.status === "warn" ? (
                <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
              ) : chk.status === "fail" ? (
                <XCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              ) : (
                <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-400" />
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
                      <span className="text-xs font-semibold text-slate-100">
                        {chk.title}
                      </span>
                      <span className="rounded border border-slate-800 bg-[#0b0f17] px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wider text-slate-400">
                        {chk.category}
                      </span>
                    </div>
                    <p className="mt-0.5 text-xs text-slate-400">{chk.detail}</p>
                  </div>
                </div>
                <div className="shrink-0 font-mono text-xs text-slate-300">
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
