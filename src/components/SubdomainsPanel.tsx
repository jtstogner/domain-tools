import {
  AlertTriangle,
  ArrowUpRight,
  Check,
  CheckCircle2,
  Copy,
  Info,
  Network,
  Search,
  ShieldAlert,
} from "lucide-react";
import { useMemo, useState } from "react";
import type { SubdomainDiscoveryReport } from "../types/dns";
import { copyToClipboard } from "../lib/api";

type FilterMode = "all" | "live" | "ct_only" | "takeover";

interface SubdomainsPanelProps {
  report: SubdomainDiscoveryReport;
  onInspectSubdomain: (subdomain: string) => void;
  onNotify: (msg: string) => void;
}

export function SubdomainsPanel({
  report,
  onInspectSubdomain,
  onNotify,
}: SubdomainsPanelProps) {
  const [filterMode, setFilterMode] = useState<FilterMode>("all");
  const [searchText, setSearchText] = useState("");
  const [copiedSub, setCopiedSub] = useState<string | null>(null);
  const [copiedAll, setCopiedAll] = useState(false);

  const takeoverCount =
    report.takeover_count ??
    report.subdomains.filter((s) => Boolean(s.takeover_risk)).length;

  const filtered = useMemo(() => {
    const needle = searchText.trim().toLowerCase();
    return report.subdomains.filter((item) => {
      if (filterMode === "live" && !item.live) return false;
      if (filterMode === "ct_only" && item.live) return false;
      if (filterMode === "takeover" && !item.takeover_risk) return false;
      if (needle) {
        const hitSub = item.subdomain.toLowerCase().includes(needle);
        const hitTarget =
          item.cname?.toLowerCase().includes(needle) ||
          item.a_records.some((ip) => ip.includes(needle)) ||
          item.aaaa_records.some((ip) => ip.includes(needle));
        if (!hitSub && !hitTarget) return false;
      }
      return true;
    });
  }, [report.subdomains, filterMode, searchText]);

  const handleCopyOne = async (sub: string) => {
    await copyToClipboard(sub);
    setCopiedSub(sub);
    onNotify(`Copied ${sub}`);
    setTimeout(() => setCopiedSub((prev) => (prev === sub ? null : prev)), 1400);
  };

  const handleCopyAll = async () => {
    if (filtered.length === 0) return;
    await copyToClipboard(filtered.map((s) => s.subdomain).join("\n"));
    setCopiedAll(true);
    onNotify(`Copied ${filtered.length} subdomain(s)`);
    setTimeout(() => setCopiedAll(false), 1500);
  };

  return (
    <div className="space-y-4">
      {/* Top Summary Cards */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-5">
        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Total Discovered
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-ink">
            {report.total_found}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Apex: <span className="font-mono text-ink-secondary">{report.apex_domain}</span>
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Live in DNS
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-emerald-700 dark:text-emerald-300">
            {report.live_count}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Resolved A / AAAA / CNAME
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Passive-Only / Historical
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-ink-secondary">
            {report.ct_only_count}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Found in passive datasets only
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Takeover Risks
          </div>
          <div
            className={`mt-1.5 font-mono text-2xl font-bold ${
              takeoverCount > 0
                ? "text-rose-700 dark:text-rose-300"
                : "text-emerald-700 dark:text-emerald-300"
            }`}
          >
            {takeoverCount}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Dangling CNAME / unclaimed cloud
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Discovery Sources
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px]">
            {report.passive_sources.map((src) => (
              <span
                key={src.name}
                className={`rounded-full border px-2 py-0.5 font-medium ${
                  src.status === "ok"
                    ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                    : src.status === "timeout" || src.status === "rate_limited"
                      ? "border-line-strong bg-surface-alt text-ink-muted"
                      : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                }`}
              >
                {src.name}: {src.status === "ok" ? src.count : src.status}
              </span>
            ))}
            <span className="rounded-full border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-sky-700 dark:text-sky-300">
              {report.probe_count} probed
            </span>
          </div>
          <div className="mt-1.5 font-mono text-[11px] text-ink-muted">
            {report.latency_ms}ms total
          </div>
        </div>
      </div>

      {takeoverCount > 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/40 bg-rose-500/10 p-3.5 text-xs text-rose-900 dark:text-rose-200">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
          <div>
            <span className="font-semibold">
              {takeoverCount} Subdomain Takeover Risk(s) Detected:
            </span>{" "}
            One or more subdomains delegate via CNAME to an unclaimed cloud service or NXDOMAIN target. Remove the dangling CNAME record or reclaim the target resource immediately.
          </div>
        </div>
      )}

      {report.wildcard_detected && (
        <div className="flex items-start gap-3 rounded-xl border border-sky-500/30 bg-sky-500/10 p-3.5 text-xs text-sky-900 dark:text-sky-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
          <div>
            <span className="font-semibold">Wildcard DNS detected:</span>{" "}
            <span className="font-mono">*.{report.apex_domain}</span> resolves
            to {report.wildcard_ips.join(", ")}. Wildcard-only probe hits were
            automatically filtered out so only real subdomains are shown.
          </div>
        </div>
      )}

      {report.ct_note && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-3.5 text-xs text-amber-900 dark:text-amber-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <div>{report.ct_note}</div>
        </div>
      )}

      {/* Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <button
            type="button"
            onClick={() => setFilterMode("all")}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
              filterMode === "all"
                ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                : "border-line bg-canvas text-ink-muted hover:text-ink"
            }`}
          >
            All ({report.total_found})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode("live")}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
              filterMode === "live"
                ? "border-emerald-500/60 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                : "border-line bg-canvas text-ink-muted hover:text-ink"
            }`}
          >
            Live DNS ({report.live_count})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode("ct_only")}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
              filterMode === "ct_only"
                ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                : "border-line bg-canvas text-ink-muted hover:text-ink"
            }`}
          >
            Passive-Only ({report.ct_only_count})
          </button>
          <button
            type="button"
            onClick={() => setFilterMode("takeover")}
            className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
              filterMode === "takeover"
                ? "border-rose-500/60 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                : "border-line bg-canvas text-ink-muted hover:text-ink"
            }`}
          >
            Takeover Risk ({takeoverCount})
          </button>
        </div>

        <div className="flex w-full items-center gap-2 sm:w-auto">
          <div className="relative flex-1 sm:w-64">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Filter subdomains or IPs..."
              className="w-full rounded-lg border border-line-strong bg-canvas py-1.5 pl-8 pr-3 text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <button
            type="button"
            disabled={filtered.length === 0}
            onClick={handleCopyAll}
            className="inline-flex shrink-0 items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300 disabled:opacity-40"
          >
            {copiedAll ? (
              <>
                <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                Copied
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                Copy All
              </>
            )}
          </button>
        </div>
      </div>

      {/* Subdomains Table */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        {filtered.length === 0 ? (
          <div className="px-6 py-12 text-center text-xs text-ink-muted">
            <Network className="mx-auto mb-2 h-6 w-6 text-ink-muted/60" />
            No subdomains matched this filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-line bg-surface-alt text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  <th className="px-4 py-3">Subdomain</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Resolved Targets</th>
                  <th className="px-4 py-3">Sources</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filtered.map((item) => (
                  <tr
                    key={item.subdomain}
                    className={
                      item.takeover_risk
                        ? "bg-rose-500/[0.06]"
                        : "hover:bg-surface-alt/70"
                    }
                  >
                    <td className="px-4 py-2.5 align-top">
                      <button
                        type="button"
                        onClick={() => onInspectSubdomain(item.subdomain)}
                        title={`Query ${item.subdomain}`}
                        className="font-mono font-medium text-sky-700 hover:text-sky-600 hover:underline dark:text-sky-300 dark:hover:text-sky-200"
                      >
                        {item.subdomain}
                      </button>
                      {item.takeover_risk && (
                        <div className="mt-1.5 rounded-lg border border-rose-500/40 bg-rose-500/10 p-2 text-[11px] text-rose-900 dark:text-rose-200">
                          <div className="flex items-center gap-1.5 font-semibold">
                            <AlertTriangle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
                            Takeover Risk ({item.takeover_risk.provider} · {item.takeover_risk.confidence})
                          </div>
                          <div className="mt-0.5">{item.takeover_risk.evidence}</div>
                          <div className="mt-0.5 text-ink-secondary">
                            Fix: {item.takeover_risk.remediation}
                          </div>
                        </div>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 align-top">
                      {item.takeover_risk ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-300">
                          <AlertTriangle className="h-3 w-3" />
                          Takeover Risk
                        </span>
                      ) : item.live ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          Live
                        </span>
                      ) : (
                        <span className="inline-flex items-center rounded-full border border-line-strong bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-muted">
                          Passive
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-2.5 align-top font-mono text-[11px]">
                      {item.cname && (
                        <div className="text-violet-700 dark:text-violet-300">
                          CNAME → {item.cname}
                        </div>
                      )}
                      {item.a_records.length > 0 && (
                        <div className="text-ink">
                          A: {item.a_records.join(", ")}
                        </div>
                      )}
                      {item.aaaa_records.length > 0 && (
                        <div className="text-indigo-700 dark:text-indigo-300">
                          AAAA: {item.aaaa_records.join(", ")}
                        </div>
                      )}
                      {!item.cname &&
                        item.a_records.length === 0 &&
                        item.aaaa_records.length === 0 && (
                          <span className="text-ink-muted">—</span>
                        )}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 align-top">
                      <div className="flex flex-wrap gap-1">
                        {item.sources.map((src) => (
                          <span
                            key={src}
                            className="rounded border border-line-strong bg-canvas px-1.5 py-0.5 text-[10px] text-ink-secondary"
                          >
                            {src}
                          </span>
                        ))}
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right align-top">
                      <div className="inline-flex items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => onInspectSubdomain(item.subdomain)}
                          title="Inspect this subdomain"
                          className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2 py-1 text-[11px] text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          Inspect
                          <ArrowUpRight className="h-3 w-3" />
                        </button>
                        <button
                          type="button"
                          onClick={() => handleCopyOne(item.subdomain)}
                          title="Copy subdomain"
                          className="inline-flex items-center justify-center rounded-md border border-line-strong bg-surface-alt p-1 text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          {copiedSub === item.subdomain ? (
                            <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                          ) : (
                            <Copy className="h-3.5 w-3.5" />
                          )}
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
