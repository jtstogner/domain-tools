import {
  Calculator,
  CheckCircle2,
  Cloud,
  Copy,
  Globe2,
  MapPin,
  Network,
  Play,
  RefreshCw,
  Route,
  Server,
  ShieldAlert,
  ShieldCheck,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard, runTraceroute } from "../lib/api";
import type { NetworkReport, TracerouteReport } from "../types/dns";
import { CidrCalculator } from "./CidrCalculator";

interface NetworkPanelProps {
  network: NetworkReport;
  defaultTarget: string;
  initialTraceroutes?: Record<string, TracerouteReport>;
  onTracerouteResult?: (target: string, report: TracerouteReport) => void;
  onNotify: (msg: string) => void;
}

export function NetworkPanel({
  network,
  defaultTarget,
  initialTraceroutes,
  onTracerouteResult,
  onNotify,
}: NetworkPanelProps) {
  const [subTab, setSubTab] = useState<"ips" | "cidr" | "traceroute">("ips");

  // CIDR Calculator seed values
  const [cidrSeed, setCidrSeed] = useState<string>(
    () => network.ips.find((i) => i.cidr)?.cidr ?? "104.16.0.0/14",
  );
  const [testIpSeed, setTestIpSeed] = useState<string>(
    () => network.ips[0]?.ip ?? "104.16.132.229",
  );

  // Traceroute state (cached per target)
  const [tracesByTarget, setTracesByTarget] = useState<Record<string, TracerouteReport>>(
    () => initialTraceroutes ?? {},
  );
  const [traceTarget, setTraceTarget] = useState<string>(() => {
    if (initialTraceroutes && !initialTraceroutes[defaultTarget]) {
      const firstKey = Object.keys(initialTraceroutes)[0];
      if (firstKey) return firstKey;
    }
    return defaultTarget;
  });
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceError, setTraceError] = useState<string | null>(null);

  useEffect(() => {
    const nextTraces = initialTraceroutes ?? {};
    setTraceError(null);
    if (nextTraces[defaultTarget]) {
      setTraceTarget(defaultTarget);
    } else {
      const firstCachedTarget = Object.keys(nextTraces)[0];
      setTraceTarget(firstCachedTarget ?? defaultTarget);
    }
    // Only reset target selection when switching domains (not when appending new traces for the active domain)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [defaultTarget]);

  useEffect(() => {
    const firstCidr = network.ips.find((i) => i.cidr)?.cidr;
    const firstIp = network.ips[0]?.ip;
    if (firstCidr) setCidrSeed(firstCidr);
    if (firstIp) setTestIpSeed(firstIp);
  }, [defaultTarget, network.ips]);

  useEffect(() => {
    setTracesByTarget(initialTraceroutes ?? {});
  }, [initialTraceroutes]);

  const traceReport = tracesByTarget[traceTarget.trim()] ?? null;

  const handleRunTrace = async (customTarget?: string) => {
    const tgt = (customTarget ?? traceTarget).trim();
    if (!tgt) return;
    setTraceTarget(tgt);
    setTraceLoading(true);
    setTraceError(null);
    try {
      const res = await runTraceroute(tgt);
      setTracesByTarget((prev) => ({ ...prev, [tgt]: res }));
      onTracerouteResult?.(tgt, res);
    } catch (err) {
      setTraceError(String(err));
    } finally {
      setTraceLoading(false);
    }
  };

  const maxHopAvg = useMemo(() => {
    if (!traceReport) return 100;
    const vals = traceReport.hops
      .map((h) => h.avg_ms ?? 0)
      .filter((v) => v > 0);
    return vals.length > 0 ? Math.max(...vals, 10) : 100;
  }, [traceReport]);

  return (
    <div className="space-y-4">
      {/* Sub-tab Switcher */}
      <div className="inline-flex items-center rounded-lg border border-line bg-surface-alt p-0.5">
        <button
          type="button"
          onClick={() => setSubTab("ips")}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
            subTab === "ips"
              ? "bg-surface text-ink shadow-sm ring-1 ring-line"
              : "text-ink-muted hover:text-ink"
          }`}
        >
          <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
          Domain IPs &amp; RPKI
        </button>
        <button
          type="button"
          onClick={() => setSubTab("cidr")}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
            subTab === "cidr"
              ? "bg-surface text-ink shadow-sm ring-1 ring-line"
              : "text-ink-muted hover:text-ink"
          }`}
        >
          <Calculator className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
          IP / CIDR Calculator
        </button>
        <button
          type="button"
          onClick={() => setSubTab("traceroute")}
          className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
            subTab === "traceroute"
              ? "bg-surface text-ink shadow-sm ring-1 ring-line"
              : "text-ink-muted hover:text-ink"
          }`}
        >
          <Route className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
          Traceroute
        </button>
      </div>

      {subTab === "ips" && (
        network.ips.length === 0 ? (
          <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
            {network.error ?? "No IPv4, IPv6, or MX host IPs found to analyze."}
          </div>
        ) : (
          <div className="space-y-4">
            {/* Summary Cards */}
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-xl border border-line bg-surface p-3.5">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  Resolved IPs
                </div>
                <div className="mt-1 font-mono text-lg font-semibold text-ink">
                  {network.ips.length}
                </div>
              </div>

              <div className="rounded-xl border border-line bg-surface p-3.5">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Network className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
                  Unique ASNs
                </div>
                <div className="mt-1 font-mono text-lg font-semibold text-ink">
                  {network.unique_asns}
                </div>
              </div>

              <div className="rounded-xl border border-line bg-surface p-3.5">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Globe2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  Locations
                </div>
                <div className="mt-1 truncate text-sm font-semibold text-ink">
                  {network.countries.length > 0 ? network.countries.join(", ") : "Unknown"}
                </div>
              </div>

              <div className="rounded-xl border border-line bg-surface p-3.5">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Cloud className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                  CDN / Edge
                </div>
                <div className="mt-1 truncate text-sm font-semibold text-ink">
                  {network.cdn_detected ?? "Direct Origin"}
                </div>
              </div>
            </div>

            {/* Per-IP Network Details */}
            <div className="space-y-3">
              {network.ips.map((item) => {
                const locationParts = [item.city, item.region, item.country].filter(Boolean);
                const providerTone = item.is_anycast_cdn
                  ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                  : item.provider_type === "Mail Provider"
                    ? "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300"
                    : item.provider_type === "Cloud / Hosting"
                      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                      : "border-line bg-surface-alt text-ink-secondary";

                const rpkiBadge =
                  item.rpki_status === "valid" ? (
                    <span
                      title={item.rpki_detail ?? "Valid RPKI ROA"}
                      className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-300"
                    >
                      <ShieldCheck className="h-3 w-3" />
                      RPKI Valid
                    </span>
                  ) : item.rpki_status === "invalid" ? (
                    <span
                      title={item.rpki_detail ?? "RPKI Invalid"}
                      className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[10px] font-semibold text-rose-700 dark:text-rose-300"
                    >
                      <ShieldAlert className="h-3 w-3" />
                      RPKI Invalid
                    </span>
                  ) : item.rpki_status === "not_found" ? (
                    <span
                      title={item.rpki_detail ?? "No RPKI ROA"}
                      className="rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[10px] font-medium text-ink-muted"
                    >
                      No RPKI ROA
                    </span>
                  ) : null;

                return (
                  <div
                    key={item.ip}
                    className="rounded-xl border border-line bg-surface p-4"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="font-mono text-sm font-semibold text-ink">
                          {item.ip}
                        </span>
                        <button
                          type="button"
                          onClick={() => {
                            void copyToClipboard(item.ip);
                            onNotify(`Copied ${item.ip}`);
                          }}
                          title="Copy IP"
                          className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
                        >
                          <Copy className="h-3 w-3" />
                        </button>
                        <span className="rounded bg-surface-alt px-1.5 py-0.5 font-mono text-[10px] font-medium text-ink-secondary">
                          {item.ip_version}
                        </span>
                        {item.roles.map((role) => (
                          <span
                            key={role}
                            className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-secondary"
                          >
                            {role}
                          </span>
                        ))}
                        {rpkiBadge}
                      </div>

                      <div className="flex flex-wrap items-center gap-1.5">
                        <button
                          type="button"
                          onClick={() => {
                            setCidrSeed(item.cidr ?? item.ip);
                            setTestIpSeed(item.ip);
                            setSubTab("cidr");
                          }}
                          className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                        >
                          CIDR Calc
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setSubTab("traceroute");
                            void handleRunTrace(item.ip);
                          }}
                          className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                        >
                          Traceroute
                        </button>
                        <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${providerTone}`}>
                          {item.provider_name ? `${item.provider_type}: ${item.provider_name}` : item.provider_type}
                        </span>
                      </div>
                    </div>

                    <div className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2.5 text-xs md:grid-cols-3">
                      <div>
                        <div className="text-[11px] text-ink-muted">ASN &amp; Network</div>
                        <div className="font-mono text-ink">
                          {item.asn ? `AS${item.asn}` : "ASN N/A"}
                          {item.cidr ? ` (${item.cidr})` : ""}
                        </div>
                        <div className="text-[11px] text-ink-secondary">
                          {item.as_org ?? item.isp ?? "Organization unknown"}
                        </div>
                      </div>

                      <div>
                        <div className="text-[11px] text-ink-muted">Geolocation</div>
                        <div className="flex items-center gap-1 text-ink">
                          <MapPin className="h-3.5 w-3.5 shrink-0 text-ink-muted" />
                          <span>
                            {locationParts.length > 0
                              ? locationParts.join(", ")
                              : item.country_code ?? "Location unknown"}
                          </span>
                        </div>
                      </div>

                      <div>
                        <div className="text-[11px] text-ink-muted">Reverse DNS (PTR)</div>
                        {item.ptr_records.length > 0 ? (
                          <div className="space-y-0.5 font-mono text-[11px] text-ink-secondary">
                            {item.ptr_records.map((ptr) => (
                              <div key={ptr} className="truncate" title={ptr}>
                                {ptr}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="text-[11px] italic text-ink-muted">
                            No PTR record
                          </div>
                        )}
                      </div>
                    </div>

                    {item.hostnames.length > 0 && (
                      <div className="mt-2.5 border-t border-line pt-2 text-[11px] text-ink-muted">
                        Associated Hostnames:{" "}
                        <span className="font-mono text-ink-secondary">
                          {item.hostnames.join(", ")}
                        </span>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )
      )}

      {subTab === "cidr" && (
        <CidrCalculator
          initialCidr={cidrSeed}
          initialTestIp={testIpSeed}
          onNotify={onNotify}
        />
      )}

      {subTab === "traceroute" && (
        <div className="space-y-4">
          <div className="flex flex-wrap items-end gap-3 rounded-xl border border-line bg-surface p-4">
            <div className="min-w-[200px] flex-1">
              <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                Target Domain or IP
              </label>
              <input
                type="text"
                value={traceTarget}
                onChange={(e) => setTraceTarget(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                placeholder={defaultTarget}
              />
            </div>
            <button
              type="button"
              disabled={traceLoading}
              onClick={() => void handleRunTrace()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
            >
              {traceLoading ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              {traceLoading ? "Tracing Route..." : "Run Traceroute"}
            </button>
          </div>

          {traceError && (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
              {traceError}
            </div>
          )}

          {traceReport && (
            <div className="overflow-hidden rounded-xl border border-line bg-surface">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5 text-xs">
                <div className="flex items-center gap-2 font-semibold text-ink">
                  <Route className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                  Path to {traceReport.target}
                  {traceReport.resolved_ip && (
                    <span className="font-mono text-ink-muted">
                      ({traceReport.resolved_ip})
                    </span>
                  )}
                </div>
                <div className="flex items-center gap-2 font-mono text-[11px] text-ink-muted">
                  <span>tool: {traceReport.tool_used}</span>
                  <span>·</span>
                  <span>{traceReport.hops.length} hops</span>
                  <span>·</span>
                  <span>{traceReport.latency_ms}ms</span>
                  {traceReport.completed && (
                    <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-300">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      Reached
                    </span>
                  )}
                </div>
              </div>

              {traceReport.error && (
                <div className="border-b border-line bg-amber-500/10 px-4 py-2.5 text-xs text-amber-900 dark:text-amber-200">
                  {traceReport.error}
                </div>
              )}

              {traceReport.hops.length > 0 && (
                <div className="overflow-x-auto">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                        <th className="px-4 py-2">Hop</th>
                        <th className="px-4 py-2">Router IP</th>
                        <th className="px-4 py-2">RTT Probes</th>
                        <th className="px-4 py-2 w-48">Latency Bar</th>
                        <th className="px-4 py-2 text-right">Avg</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line font-mono">
                      {traceReport.hops.map((hop) => {
                        const pct =
                          hop.avg_ms !== null
                            ? Math.max(4, Math.min(100, Math.round((hop.avg_ms / maxHopAvg) * 100)))
                            : 0;
                        return (
                          <tr key={hop.hop} className="hover:bg-surface-alt/70">
                            <td className="px-4 py-2 font-semibold text-ink-muted">
                              #{hop.hop}
                            </td>
                            <td className="px-4 py-2 text-ink">
                              {hop.timed_out ? (
                                <span className="italic text-ink-muted">* * * (timeout)</span>
                              ) : (
                                hop.ip ?? "—"
                              )}
                            </td>
                            <td className="px-4 py-2 text-[11px] text-ink-secondary">
                              {hop.rtt_ms.length > 0
                                ? hop.rtt_ms.map((v) => `${v}ms`).join(" · ")
                                : "—"}
                            </td>
                            <td className="px-4 py-2">
                              {hop.avg_ms !== null && (
                                <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-alt">
                                  <div
                                    className="h-full rounded-full bg-sky-500"
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                              )}
                            </td>
                            <td className="px-4 py-2 text-right text-ink">
                              {hop.avg_ms !== null ? `${hop.avg_ms}ms` : "—"}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
