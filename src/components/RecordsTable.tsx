import { Copy, Check, Search, AlertTriangle, Info } from "lucide-react";
import { useMemo, useState } from "react";
import type { DnsQueryReport, DnsRecordItem } from "../types/dns";
import { copyToClipboard } from "../lib/api";

const TYPE_COLORS: Record<string, string> = {
  A: "bg-sky-500/15 text-sky-300 border-sky-500/30",
  AAAA: "bg-indigo-500/15 text-indigo-300 border-indigo-500/30",
  CNAME: "bg-violet-500/15 text-violet-300 border-violet-500/30",
  MX: "bg-emerald-500/15 text-emerald-300 border-emerald-500/30",
  TXT: "bg-amber-500/15 text-amber-300 border-amber-500/30",
  NS: "bg-cyan-500/15 text-cyan-300 border-cyan-500/30",
  SOA: "bg-rose-500/15 text-rose-300 border-rose-500/30",
  CAA: "bg-fuchsia-500/15 text-fuchsia-300 border-fuchsia-500/30",
  SRV: "bg-teal-500/15 text-teal-300 border-teal-500/30",
};

function formatTtl(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${seconds}s (${Math.round(seconds / 60)}m)`;
  if (seconds < 86400) return `${seconds}s (${(seconds / 3600).toFixed(1).replace(/\.0$/, "")}h)`;
  return `${seconds}s (${(seconds / 86400).toFixed(1).replace(/\.0$/, "")}d)`;
}

interface RecordsTableProps {
  report: DnsQueryReport;
  selectedResolverId: string;
  onSelectResolverId: (id: string) => void;
  onNotify: (msg: string) => void;
}

export function RecordsTable({
  report,
  selectedResolverId,
  onSelectResolverId,
  onNotify,
}: RecordsTableProps) {
  const [typeFilter, setTypeFilter] = useState<string>("ALL");
  const [searchText, setSearchText] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const activeResolver = useMemo(
    () =>
      report.resolvers.find((r) => r.id === selectedResolverId) ??
      report.resolvers[0],
    [report.resolvers, selectedResolverId],
  );

  const typeCounts = useMemo(() => {
    const map: Record<string, number> = {};
    if (!activeResolver) return map;
    for (const r of activeResolver.results) {
      map[r.record_type] = r.records.length;
    }
    return map;
  }, [activeResolver]);

  const rows = useMemo(() => {
    if (!activeResolver) return [];
    const needle = searchText.trim().toLowerCase();
    const list: { record: DnsRecordItem; latencyMs: number }[] = [];
    for (const typeResult of activeResolver.results) {
      if (typeFilter !== "ALL" && typeResult.record_type !== typeFilter) continue;
      for (const rec of typeResult.records) {
        if (
          needle &&
          !rec.value.toLowerCase().includes(needle) &&
          !rec.name.toLowerCase().includes(needle) &&
          !rec.record_type.toLowerCase().includes(needle)
        ) {
          continue;
        }
        list.push({ record: rec, latencyMs: typeResult.latency_ms });
      }
    }
    return list;
  }, [activeResolver, typeFilter, searchText]);

  const totalRecords = useMemo(
    () =>
      activeResolver?.results.reduce((acc, r) => acc + r.records.length, 0) ?? 0,
    [activeResolver],
  );

  const handleCopy = async (key: string, value: string) => {
    await copyToClipboard(value);
    setCopiedKey(key);
    onNotify("Copied record value");
    setTimeout(() => setCopiedKey((prev) => (prev === key ? null : prev)), 1500);
  };

  if (!activeResolver) return null;

  const isNxDomain =
    activeResolver.results.length > 0 &&
    activeResolver.results.every((r) => r.status === "nxdomain");

  const errorResults = activeResolver.results.filter((r) => r.status === "error");

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-slate-800 bg-[#111827] p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {report.resolvers.map((res) => {
            const active = res.id === activeResolver.id;
            return (
              <button
                key={res.id}
                type="button"
                onClick={() => onSelectResolverId(res.id)}
                className={`inline-flex items-center gap-2 rounded-lg border px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? "border-sky-500/60 bg-sky-500/15 text-sky-200"
                    : "border-slate-800 bg-[#0b0f17] text-slate-400 hover:border-slate-700 hover:text-slate-200"
                }`}
              >
                <span
                  className={`h-2 w-2 rounded-full ${
                    res.status === "ok" ? "bg-emerald-400" : "bg-rose-400"
                  }`}
                />
                <span>{res.label}</span>
                <span className="font-mono text-[11px] text-slate-400">
                  {res.total_latency_ms}ms
                </span>
              </button>
            );
          })}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-500" />
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Filter records..."
            className="w-full rounded-lg border border-slate-700 bg-[#0b0f17] py-1.5 pl-8 pr-3 text-xs text-slate-200 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={() => setTypeFilter("ALL")}
          className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
            typeFilter === "ALL"
              ? "border-sky-500/60 bg-sky-500/15 text-sky-300"
              : "border-slate-800 bg-[#111827] text-slate-400 hover:text-slate-200"
          }`}
        >
          All ({totalRecords})
        </button>
        {activeResolver.results.map((r) => {
          const count = typeCounts[r.record_type] ?? 0;
          const active = typeFilter === r.record_type;
          return (
            <button
              key={r.record_type}
              type="button"
              onClick={() => setTypeFilter(r.record_type)}
              className={`rounded-md border px-2.5 py-1 font-mono text-xs font-medium transition ${
                active
                  ? "border-sky-500/60 bg-sky-500/15 text-sky-300"
                  : "border-slate-800 bg-[#111827] text-slate-400 hover:text-slate-200"
              }`}
            >
              {r.record_type} ({count})
            </button>
          );
        })}
      </div>

      {activeResolver.status === "error" && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div>
            <div className="font-semibold">
              Resolver {activeResolver.label} ({activeResolver.address}) failed
            </div>
            <div className="mt-0.5 text-xs text-rose-300/90">
              {activeResolver.error ?? "All record queries errored."}
            </div>
          </div>
        </div>
      )}

      {isNxDomain && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div>
            <div className="font-semibold">NXDOMAIN — Domain Does Not Exist</div>
            <div className="mt-0.5 text-xs text-amber-300/90">
              {activeResolver.label} reported that{" "}
              <span className="font-mono">{report.domain}</span> does not exist.
            </div>
          </div>
        </div>
      )}

      {!activeResolver.error && errorResults.length > 0 && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-200">
          {errorResults.map((er) => (
            <div key={er.record_type}>
              <span className="font-mono font-semibold">{er.record_type}:</span>{" "}
              {er.error ?? "Query failed"}
            </div>
          ))}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
        {rows.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-slate-400">
            No matching DNS records returned for this selection.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-slate-800 bg-[#0d131f] text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">TTL</th>
                  <th className="px-4 py-3">Value / Data</th>
                  <th className="px-4 py-3 text-right">Copy</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/70">
                {rows.map(({ record }, idx) => {
                  const rowKey = `${record.record_type}-${record.name}-${idx}`;
                  const badgeStyle =
                    TYPE_COLORS[record.record_type] ??
                    "bg-slate-800 text-slate-300 border-slate-700";

                  return (
                    <tr
                      key={rowKey}
                      className="transition hover:bg-slate-800/35"
                    >
                      <td className="whitespace-nowrap px-4 py-3 align-top">
                        <span
                          className={`inline-block rounded border px-2 py-0.5 font-mono text-xs font-semibold ${badgeStyle}`}
                        >
                          {record.record_type}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 align-top font-mono text-xs text-slate-300">
                        {record.name}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 align-top font-mono text-xs text-slate-400">
                        {formatTtl(record.ttl)}
                      </td>
                      <td className="px-4 py-3 align-top">
                        <div className="break-all font-mono text-xs leading-relaxed text-slate-100">
                          {record.value}
                        </div>
                        {record.details && record.record_type === "SOA" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-slate-400">
                            <span>Primary: {String(record.details.mname)}</span>
                            <span>Serial: {String(record.details.serial)}</span>
                            <span>Refresh: {String(record.details.refresh)}s</span>
                            <span>Retry: {String(record.details.retry)}s</span>
                            <span>Expire: {String(record.details.expire)}s</span>
                          </div>
                        )}
                        {record.details && record.record_type === "MX" && (
                          <div className="mt-1 text-[11px] text-slate-400">
                            Priority {String(record.details.priority)} →{" "}
                            {String(record.details.exchange)}
                          </div>
                        )}
                        {record.details && record.record_type === "SRV" && (
                          <div className="mt-1 text-[11px] text-slate-400">
                            Priority {String(record.details.priority)} · Weight{" "}
                            {String(record.details.weight)} · Port{" "}
                            {String(record.details.port)}
                          </div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right align-top">
                        <button
                          type="button"
                          onClick={() => handleCopy(rowKey, record.value)}
                          title="Copy value"
                          className="inline-flex items-center justify-center rounded-md border border-slate-700/80 bg-slate-800/60 p-1.5 text-slate-300 transition hover:border-sky-500/50 hover:text-sky-300"
                        >
                          {copiedKey === rowKey ? (
                            <Check className="h-3.5 w-3.5 text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
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
  );
}
