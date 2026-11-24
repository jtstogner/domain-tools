import { CheckCircle2, AlertTriangle, MinusCircle, XCircle, Server } from "lucide-react";
import type { DnsQueryReport, PropagationRow } from "../types/dns";

function StatusBadge({ status }: { status: PropagationRow["status"] }) {
  switch (status) {
    case "consistent":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-xs font-medium text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="h-3.5 w-3.5" />
          Consistent
        </span>
      );
    case "divergent":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-xs font-medium text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-3.5 w-3.5" />
          Divergent
        </span>
      );
    case "partial_error":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-xs font-medium text-rose-700 dark:text-rose-300">
          <XCircle className="h-3.5 w-3.5" />
          Partial Error
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2.5 py-0.5 text-xs font-medium text-ink-muted">
          <MinusCircle className="h-3.5 w-3.5" />
          No Records
        </span>
      );
  }
}

export function PropagationView({ report }: { report: DnsQueryReport }) {
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        {report.resolvers.map((res) => (
          <div
            key={res.id}
            className="rounded-xl border border-line bg-surface p-3.5"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Server className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                <span className="text-sm font-semibold text-ink">
                  {res.label}
                </span>
              </div>
              <span
                className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                  res.status === "ok"
                    ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                    : "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                }`}
              >
                {res.status === "ok" ? "Online" : "Error"}
              </span>
            </div>
            <div className="mt-2 flex items-center justify-between text-xs text-ink-muted">
              <span className="font-mono">{res.address}</span>
              <span className="font-mono text-sky-600 dark:text-sky-300">
                {res.total_latency_ms}ms
              </span>
            </div>
          </div>
        ))}
      </div>

      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-line bg-surface-alt text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                <th className="px-4 py-3">Record</th>
                <th className="px-4 py-3">Consensus</th>
                {report.resolvers.map((res) => (
                  <th key={res.id} className="px-4 py-3">
                    <div>{res.label}</div>
                    <div className="font-mono text-[10px] font-normal text-ink-muted">
                      {res.address}
                    </div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {report.propagation.map((row) => (
                <tr
                  key={row.record_type}
                  className={
                    row.status === "divergent"
                      ? "bg-amber-500/[0.06]"
                      : "hover:bg-surface-alt/70"
                  }
                >
                  <td className="whitespace-nowrap px-4 py-3 align-top font-mono text-xs font-semibold text-sky-600 dark:text-sky-300">
                    {row.record_type}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 align-top">
                    <StatusBadge status={row.status} />
                  </td>
                  {report.resolvers.map((res) => {
                    const answers = row.answers_by_resolver[res.id] ?? [];
                    const rStatus = row.status_by_resolver[res.id] ?? "no_records";
                    const latency = row.latency_by_resolver[res.id];

                    return (
                      <td
                        key={res.id}
                        className="max-w-xs px-4 py-3 align-top"
                      >
                        {rStatus === "error" ? (
                          <span className="text-rose-600 dark:text-rose-400">Query error</span>
                        ) : rStatus === "nxdomain" ? (
                          <span className="text-amber-700 dark:text-amber-300">NXDOMAIN</span>
                        ) : answers.length === 0 ? (
                          <span className="text-ink-muted">—</span>
                        ) : (
                          <div className="space-y-1">
                            {answers.map((ans, idx) => (
                              <div
                                key={idx}
                                className="break-all rounded bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
                              >
                                {ans}
                              </div>
                            ))}
                          </div>
                        )}
                        {typeof latency === "number" && (
                          <div className="mt-1 font-mono text-[10px] text-ink-muted">
                            {latency}ms
                          </div>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
