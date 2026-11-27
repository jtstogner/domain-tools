import { Copy, Check, Search, AlertTriangle, Info, Lock } from "lucide-react";
import { useMemo, useState } from "react";
import type { DnsQueryReport, DnsRecordItem } from "../types/dns";
import { copyToClipboard } from "../lib/api";

const TYPE_COLORS: Record<string, string> = {
  A: "bg-sky-500/15 text-sky-700 dark:text-sky-300 border-sky-500/30",
  AAAA: "bg-indigo-500/15 text-indigo-700 dark:text-indigo-300 border-indigo-500/30",
  CNAME: "bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30",
  MX: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30",
  TXT: "bg-amber-500/15 text-amber-700 dark:text-amber-300 border-amber-500/30",
  NS: "bg-cyan-500/15 text-cyan-700 dark:text-cyan-300 border-cyan-500/30",
  SOA: "bg-rose-500/15 text-rose-700 dark:text-rose-300 border-rose-500/30",
  CAA: "bg-fuchsia-500/15 text-fuchsia-700 dark:text-fuchsia-300 border-fuchsia-500/30",
  SRV: "bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30",
  HTTPS: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300 border-emerald-500/30",
  SVCB: "bg-teal-500/15 text-teal-700 dark:text-teal-300 border-teal-500/30",
  PTR: "bg-slate-500/15 text-slate-700 dark:text-slate-300 border-slate-500/30",
  TLSA: "bg-purple-500/15 text-purple-700 dark:text-purple-300 border-purple-500/30",
  SSHFP: "bg-orange-500/15 text-orange-700 dark:text-orange-300 border-orange-500/30",
  NAPTR: "bg-pink-500/15 text-pink-700 dark:text-pink-300 border-pink-500/30",
  DNSKEY: "bg-violet-500/15 text-violet-700 dark:text-violet-300 border-violet-500/30",
  DS: "bg-blue-500/15 text-blue-700 dark:text-blue-300 border-blue-500/30",
};

const ENCRYPTED_RESOLVER_IDS = new Set([
  "cloudflare_doh",
  "google_doh",
  "quad9_dot",
]);

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
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-3">
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
                    ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-200"
                    : "border-line bg-canvas text-ink-muted hover:border-line-strong hover:text-ink"
                }`}
              >
                <span
                  className={`h-2 w-2 rounded-full ${
                    res.status === "ok"
                      ? "bg-emerald-500 dark:bg-emerald-400"
                      : "bg-rose-500 dark:bg-rose-400"
                  }`}
                />
                {ENCRYPTED_RESOLVER_IDS.has(res.id) && (
                  <Lock className="h-3 w-3 text-teal-600 dark:text-teal-400" />
                )}
                <span>{res.label}</span>
                <span className="font-mono text-[11px] text-ink-muted">
                  {res.total_latency_ms}ms
                </span>
              </button>
            );
          })}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
          <input
            type="text"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            placeholder="Filter records..."
            className="w-full rounded-lg border border-line-strong bg-canvas py-1.5 pl-8 pr-3 text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
          />
        </div>
      </div>

      <div className="flex flex-wrap items-center gap-1.5">
        <button
          type="button"
          onClick={() => setTypeFilter("ALL")}
          className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
            typeFilter === "ALL"
              ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
              : "border-line bg-surface text-ink-muted hover:text-ink"
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
                  ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                  : "border-line bg-surface text-ink-muted hover:text-ink"
              }`}
            >
              {r.record_type} ({count})
            </button>
          );
        })}
      </div>

      {activeResolver.status === "error" && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-900 dark:text-rose-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
          <div>
            <div className="font-semibold">
              Resolver {activeResolver.label} ({activeResolver.address}) failed
            </div>
            <div className="mt-0.5 text-xs text-rose-800 dark:text-rose-300/90">
              {activeResolver.error ?? "All record queries errored."}
            </div>
          </div>
        </div>
      )}

      {isNxDomain && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-900 dark:text-amber-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <div>
            <div className="font-semibold">NXDOMAIN — Domain Does Not Exist</div>
            <div className="mt-0.5 text-xs text-amber-800 dark:text-amber-300/90">
              {activeResolver.label} reported that{" "}
              <span className="font-mono">{report.domain}</span> does not exist.
            </div>
          </div>
        </div>
      )}

      {!activeResolver.error && errorResults.length > 0 && (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-900 dark:text-rose-200">
          {errorResults.map((er) => (
            <div key={er.record_type}>
              <span className="font-mono font-semibold">{er.record_type}:</span>{" "}
              {er.error ?? "Query failed"}
            </div>
          ))}
        </div>
      )}

      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        {rows.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-ink-muted">
            No matching DNS records returned for this selection.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-sm">
              <thead>
                <tr className="border-b border-line bg-surface-alt text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Name</th>
                  <th className="px-4 py-3">TTL</th>
                  <th className="px-4 py-3">Value / Data</th>
                  <th className="px-4 py-3 text-right">Copy</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {rows.map(({ record }, idx) => {
                  const rowKey = `${record.record_type}-${record.name}-${idx}`;
                  const badgeStyle =
                    TYPE_COLORS[record.record_type] ??
                    "bg-surface-alt text-ink-secondary border-line-strong";

                  return (
                    <tr
                      key={rowKey}
                      className="transition hover:bg-surface-alt/70"
                    >
                      <td className="whitespace-nowrap px-4 py-3 align-top">
                        <span
                          className={`inline-block rounded border px-2 py-0.5 font-mono text-xs font-semibold ${badgeStyle}`}
                        >
                          {record.record_type}
                        </span>
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 align-top font-mono text-xs text-ink-secondary">
                        {record.name}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 align-top font-mono text-xs text-ink-muted">
                        {formatTtl(record.ttl)}
                      </td>
                      <td className="px-4 py-3 align-top">
                        <div className="break-all font-mono text-xs leading-relaxed text-ink">
                          {record.value}
                        </div>
                        {record.details && record.record_type === "SOA" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            <span>Primary: {String(record.details.mname)}</span>
                            <span>Serial: {String(record.details.serial)}</span>
                            <span>Refresh: {String(record.details.refresh)}s</span>
                            <span>Retry: {String(record.details.retry)}s</span>
                            <span>Expire: {String(record.details.expire)}s</span>
                          </div>
                        )}
                        {record.details && record.record_type === "MX" && (
                          <div className="mt-1 text-[11px] text-ink-muted">
                            Priority {String(record.details.priority)} →{" "}
                            {String(record.details.exchange)}
                          </div>
                        )}
                        {record.details && record.record_type === "SRV" && (
                          <div className="mt-1 text-[11px] text-ink-muted">
                            Priority {String(record.details.priority)} · Weight{" "}
                            {String(record.details.weight)} · Port{" "}
                            {String(record.details.port)}
                          </div>
                        )}
                        {record.details &&
                          (record.record_type === "HTTPS" ||
                            record.record_type === "SVCB") && (
                            <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                              {record.details.mode !== undefined && (
                                <span>Mode: {String(record.details.mode)}</span>
                              )}
                              {record.details.priority !== undefined && (
                                <span>Priority: {String(record.details.priority)}</span>
                              )}
                              {record.details.target !== undefined && (
                                <span>Target: {String(record.details.target)}</span>
                              )}
                              {Array.isArray(record.details.params) &&
                                record.details.params.length > 0 && (
                                  <span>
                                    Params:{" "}
                                    {(record.details.params as unknown[])
                                      .map((p) => String(p))
                                      .join(" · ")}
                                  </span>
                                )}
                              {typeof record.details.params === "string" &&
                                record.details.params && (
                                  <span>Params: {record.details.params}</span>
                                )}
                              {record.details.params !== null &&
                                typeof record.details.params === "object" &&
                                !Array.isArray(record.details.params) &&
                                Object.keys(
                                  record.details.params as Record<string, unknown>,
                                ).length > 0 && (
                                  <span>
                                    Params:{" "}
                                    {Object.entries(
                                      record.details.params as Record<string, unknown>,
                                    )
                                      .map(([k, v]) => `${k}=${String(v)}`)
                                      .join(" · ")}
                                  </span>
                                )}
                            </div>
                          )}
                        {record.details && record.record_type === "TLSA" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            {record.details.usage !== undefined && (
                              <span>
                                Usage: {String(record.details.usage)}
                                {record.details.usage_label
                                  ? ` (${String(record.details.usage_label)})`
                                  : ""}
                              </span>
                            )}
                            {record.details.selector !== undefined && (
                              <span>
                                Selector: {String(record.details.selector)}
                                {record.details.selector_label
                                  ? ` (${String(record.details.selector_label)})`
                                  : ""}
                              </span>
                            )}
                            {record.details.matching_type !== undefined && (
                              <span>
                                Matching: {String(record.details.matching_type)}
                                {record.details.matching_type_label
                                  ? ` (${String(record.details.matching_type_label)})`
                                  : ""}
                              </span>
                            )}
                          </div>
                        )}
                        {record.details && record.record_type === "SSHFP" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            {record.details.algorithm !== undefined && (
                              <span>
                                Algorithm:{" "}
                                {record.details.algorithm_label
                                  ? `${String(record.details.algorithm_label)} (${String(record.details.algorithm)})`
                                  : String(record.details.algorithm)}
                              </span>
                            )}
                            {record.details.fp_type !== undefined && (
                              <span>
                                Hash:{" "}
                                {record.details.fp_type_label
                                  ? `${String(record.details.fp_type_label)} (${String(record.details.fp_type)})`
                                  : String(record.details.fp_type)}
                              </span>
                            )}
                          </div>
                        )}
                        {record.details && record.record_type === "DS" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            {record.details.key_tag !== undefined && (
                              <span>Key Tag: {String(record.details.key_tag)}</span>
                            )}
                            {record.details.algorithm !== undefined && (
                              <span>Algorithm: {String(record.details.algorithm)}</span>
                            )}
                            {record.details.digest_type !== undefined && (
                              <span>Digest: {String(record.details.digest_type)}</span>
                            )}
                          </div>
                        )}
                        {record.details && record.record_type === "DNSKEY" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            {record.details.role !== undefined && (
                              <span>Role: {String(record.details.role)}</span>
                            )}
                            {record.details.key_tag !== undefined && (
                              <span>Key Tag: {String(record.details.key_tag)}</span>
                            )}
                            {record.details.flags !== undefined && (
                              <span>Flags: {String(record.details.flags)}</span>
                            )}
                            {record.details.algorithm !== undefined && (
                              <span>Algorithm: {String(record.details.algorithm)}</span>
                            )}
                            {record.details.revoked === true && (
                              <span className="font-semibold text-rose-600 dark:text-rose-400">
                                REVOKED
                              </span>
                            )}
                          </div>
                        )}
                        {record.details && record.record_type === "NAPTR" && (
                          <div className="mt-1.5 flex flex-wrap gap-x-4 gap-y-1 text-[11px] text-ink-muted">
                            {record.details.order !== undefined && (
                              <span>Order: {String(record.details.order)}</span>
                            )}
                            {record.details.preference !== undefined && (
                              <span>Preference: {String(record.details.preference)}</span>
                            )}
                            {record.details.flags !== undefined && (
                              <span>Flags: {String(record.details.flags)}</span>
                            )}
                            {record.details.services !== undefined && (
                              <span>Services: {String(record.details.services)}</span>
                            )}
                            {record.details.replacement !== undefined &&
                              String(record.details.replacement) !== "." && (
                                <span>
                                  Replacement: {String(record.details.replacement)}
                                </span>
                              )}
                          </div>
                        )}
                      </td>
                      <td className="whitespace-nowrap px-4 py-3 text-right align-top">
                        <button
                          type="button"
                          onClick={() => handleCopy(rowKey, record.value)}
                          title="Copy value"
                          className="inline-flex items-center justify-center rounded-md border border-line-strong bg-surface-alt p-1.5 text-ink-secondary transition hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          {copiedKey === rowKey ? (
                            <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
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
