import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  Building2,
  Calculator,
  CheckCircle2,
  Clock,
  Copy,
  Download,
  ExternalLink,
  FileText,
  Globe2,
  Info,
  Lock,
  MapPin,
  Network,
  Play,
  Plug,
  Radar,
  RefreshCw,
  Route,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { type FormEvent, useCallback, useEffect, useMemo, useState } from "react";
import {
  copyToClipboard,
  deepScanIp,
  runTraceroute,
  saveExport,
} from "../lib/api";
import {
  type CacheTtlOption,
  type CachedIpScanEntry,
  formatRelativeAge,
  getCachedIpScan,
  isIpCacheFresh,
  listCachedIpScans,
  saveCachedIpScan,
  saveCachedIpTraceroute,
} from "../lib/domainCache";
import { formatIpScanAsMarkdown } from "../lib/export";
import type {
  IpDeepScanReport,
  QueryProgressEvent,
  TracerouteReport,
} from "../types/dns";
import { CidrCalculator } from "./CidrCalculator";
import {
  type ProgressStageState,
  QueryProgressBanner,
} from "./QueryProgressBanner";

export interface IpDeepScanPanelProps {
  initialIp?: string;
  autoRunNonce?: number;
  cacheTtl: CacheTtlOption;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type IpSubTab =
  | "overview"
  | "bgp"
  | "ports"
  | "tls_http"
  | "reputation"
  | "cidr_trace";

const IP_SCAN_STAGES: ProgressStageState[] = [
  { id: "meta", label: "Classification & PTR", status: "pending" },
  { id: "bgp", label: "BGP / ASN / RPKI", status: "pending" },
  { id: "rdap", label: "RDAP / Registry", status: "pending" },
  { id: "geo", label: "Geolocation", status: "pending" },
  { id: "reputation", label: "Reputation & Intel", status: "pending" },
  { id: "ports", label: "Deep Port Scan", status: "pending" },
  { id: "tls", label: "TLS Certificates", status: "pending" },
  { id: "http", label: "HTTP & Latency", status: "pending" },
];

const EXAMPLE_IPS = [
  { ip: "1.1.1.1", label: "1.1.1.1 (Cloudflare)" },
  { ip: "8.8.8.8", label: "8.8.8.8 (Google)" },
  { ip: "9.9.9.9", label: "9.9.9.9 (Quad9)" },
  { ip: "2606:4700:4700::1111", label: "2606:4700:4700::1111 (IPv6)" },
];

function parseCustomPortsInput(raw: string): number[] {
  const out: number[] = [];
  for (const part of raw.split(/[\s,;]+/)) {
    const trimmed = part.trim();
    if (!trimmed) continue;
    const n = Number.parseInt(trimmed, 10);
    if (Number.isInteger(n) && n >= 1 && n <= 65535 && !out.includes(n)) {
      out.push(n);
    }
  }
  return out.slice(0, 32);
}

function postureStyle(posture: string): { label: string; tone: string } {
  switch (posture) {
    case "elevated_risk":
      return {
        label: "Elevated Risk",
        tone: "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300",
      };
    case "caution":
      return {
        label: "Caution",
        tone: "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300",
      };
    default:
      return {
        label: "Clean",
        tone: "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
      };
  }
}

function severityTone(sev: string): string {
  switch (sev) {
    case "critical":
    case "high":
      return "border-rose-500/35 bg-rose-500/10 text-rose-900 dark:text-rose-200";
    case "medium":
      return "border-amber-500/35 bg-amber-500/10 text-amber-900 dark:text-amber-200";
    default:
      return "border-sky-500/30 bg-sky-500/10 text-sky-900 dark:text-sky-200";
  }
}

export function IpDeepScanPanel({
  initialIp,
  autoRunNonce,
  cacheTtl,
  onInspectDomain,
  onNotify,
}: IpDeepScanPanelProps) {
  const [target, setTarget] = useState(initialIp || "1.1.1.1");
  const [extraPortsInput, setExtraPortsInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [scanTargetLabel, setScanTargetLabel] = useState("");
  const [startedAt, setStartedAt] = useState<number | null>(null);
  const [stages, setStages] = useState<ProgressStageState[]>(IP_SCAN_STAGES);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<IpDeepScanReport | null>(null);
  const [fromCache, setFromCache] = useState(false);
  const [cachedAt, setCachedAt] = useState<number | null>(null);
  const [cachedIps, setCachedIps] = useState<CachedIpScanEntry[]>(() =>
    listCachedIpScans(),
  );

  const [subTab, setSubTab] = useState<IpSubTab>("overview");
  const [portFilter, setPortFilter] = useState<"open" | "all" | "risky">("open");
  const [dnsblFilter, setDnsblFilter] = useState<
    "all" | "listed" | "blocked" | "clean"
  >("all");
  const [hostSearch, setHostSearch] = useState("");
  const [expandedHttpScheme, setExpandedHttpScheme] = useState<string | null>(
    null,
  );

  // Traceroute state
  const [traceLoading, setTraceLoading] = useState(false);
  const [traceReport, setTraceReport] = useState<TracerouteReport | null>(null);
  const [traceError, setTraceError] = useState<string | null>(null);

  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
      return;
    }
    let active = true;
    let unlisten: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen<QueryProgressEvent>("ip-scan-progress", ({ payload }) => {
          setStages((prev) =>
            prev.map((item) =>
              item.id === payload.stage
                ? {
                    ...item,
                    label: payload.label || item.label,
                    status: payload.status,
                    elapsedMs: payload.elapsed_ms,
                  }
                : item,
            ),
          );
        }),
      )
      .then((fn) => {
        if (!active) fn();
        else unlisten = fn;
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const refreshCachedIpList = useCallback(() => {
    setCachedIps(listCachedIpScans());
  }, []);

  const runScan = useCallback(
    async (overrideIp?: string, options?: { forceRefresh?: boolean }) => {
      const clean = (overrideIp ?? target).trim();
      if (!clean) return;

      const customPorts = parseCustomPortsInput(extraPortsInput);
      const isSameActive =
        !overrideIp &&
        Boolean(report && report.ip.toLowerCase() === clean.toLowerCase());
      const force =
        Boolean(options?.forceRefresh) ||
        customPorts.length > 0 ||
        (isSameActive && options?.forceRefresh !== false);

      const cached = getCachedIpScan(clean);
      if (!force && cacheTtl !== "off" && cached && isIpCacheFresh(cached, cacheTtl)) {
        setError(null);
        setReport(cached.report);
        setTarget(cached.report.ip);
        setFromCache(true);
        setCachedAt(cached.cachedAt);
        setTraceReport(cached.traceroute ?? null);
        setTraceError(null);
        refreshCachedIpList();
        onNotify(
          `Loaded ${cached.report.ip} from cache (${formatRelativeAge(cached.cachedAt)})`,
        );
        return;
      }

      setLoading(true);
      setScanTargetLabel(clean);
      setStartedAt(Date.now());
      setStages(IP_SCAN_STAGES.map((s) => ({ ...s })));
      setError(null);

      try {
        const res = await deepScanIp(clean, customPorts);
        const saved = await saveCachedIpScan(res);
        setReport(res);
        setTarget(res.ip);
        setFromCache(false);
        setCachedAt(saved.cachedAt);
        setTraceReport(saved.traceroute ?? null);
        setTraceError(null);
        refreshCachedIpList();
      } catch (err) {
        setError(String(err));
      } finally {
        setLoading(false);
        setStartedAt(null);
      }
    },
    [
      cacheTtl,
      extraPortsInput,
      onNotify,
      refreshCachedIpList,
      report,
      target,
    ],
  );

  useEffect(() => {
    if (initialIp && initialIp.trim() && autoRunNonce && autoRunNonce > 0) {
      const nextIp = initialIp.trim();
      setTarget(nextIp);
      void runScan(nextIp);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialIp, autoRunNonce]);

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault();
    void runScan();
  };

  const handleRunTraceroute = async () => {
    if (!report) return;
    setTraceLoading(true);
    setTraceError(null);
    try {
      const res = await runTraceroute(report.ip);
      setTraceReport(res);
      await saveCachedIpTraceroute(report.ip, res);
      refreshCachedIpList();
    } catch (err) {
      setTraceError(String(err));
    } finally {
      setTraceLoading(false);
    }
  };

  const handleExport = async (kind: "md" | "json") => {
    if (!report) return;
    const content =
      kind === "md"
        ? formatIpScanAsMarkdown(report)
        : JSON.stringify(report, null, 2);
    const filename = `${report.ip.replace(/:/g, "_")}-ip-scan.${kind}`;
    const saved = await saveExport(filename, kind, content);
    if (saved) onNotify(`Saved ${filename}`);
  };

  const copyText = async (val: string, label: string) => {
    await copyToClipboard(val);
    onNotify(`Copied ${label}`);
  };

  const filteredPorts = useMemo(() => {
    if (!report) return [];
    if (portFilter === "open") {
      return report.ports.ports.filter((p) => p.status === "open");
    }
    if (portFilter === "risky") {
      return report.ports.ports.filter(
        (p) => p.status === "open" && p.risk_level !== "normal",
      );
    }
    return report.ports.ports;
  }, [report, portFilter]);

  const filteredDnsbls = useMemo(() => {
    if (!report) return [];
    if (dnsblFilter === "all") return report.reputation.blacklists;
    if (dnsblFilter === "blocked") {
      return report.reputation.blacklists.filter(
        (b) => b.status === "blocked" || b.status === "policy",
      );
    }
    return report.reputation.blacklists.filter((b) => b.status === dnsblFilter);
  }, [report, dnsblFilter]);

  const filteredHosts = useMemo(() => {
    if (!report) return [];
    const q = hostSearch.trim().toLowerCase();
    if (!q) return report.associated_hosts;
    return report.associated_hosts.filter(
      (h) =>
        h.hostname.toLowerCase().includes(q) ||
        h.sources.some((s) => s.toLowerCase().includes(q)),
    );
  }, [report, hostSearch]);

  const maxTraceAvg = useMemo(() => {
    if (!traceReport) return 100;
    const vals = traceReport.hops.map((h) => h.avg_ms ?? 0).filter((v) => v > 0);
    return vals.length > 0 ? Math.max(...vals, 10) : 100;
  }, [traceReport]);

  const pBadge = report ? postureStyle(report.posture) : null;
  const openPortsCount = report?.ports.open_count ?? 0;
  const cveCount = report?.reputation.internetdb?.vulns.length ?? 0;
  const locationText = report
    ? [report.geo.city, report.geo.region, report.geo.country]
        .filter(Boolean)
        .join(", ") ||
      report.geo.country_code ||
      report.rdap.country ||
      "Unknown"
    : "";

  return (
    <div className="space-y-4">
      {/* Search Bar */}
      <form
        onSubmit={handleSubmit}
        className="rounded-xl border border-line bg-surface p-4 shadow-sm"
      >
        <div className="flex flex-col gap-3 lg:flex-row lg:items-end">
          <div className="flex-1">
            <label className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-ink">
              <Radar className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
              IP Address Deep Scan (IPv4 or IPv6)
            </label>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
              <input
                type="text"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                placeholder="e.g. 1.1.1.1, 8.8.8.8, or 2606:4700:4700::1111"
                spellCheck={false}
                autoCapitalize="none"
                autoComplete="off"
                className="w-full rounded-lg border border-line-strong bg-canvas py-2 pl-9 pr-3 font-mono text-sm text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/20"
              />
            </div>
          </div>

          <div className="w-full lg:w-56">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Extra TCP Ports (optional)
            </label>
            <input
              type="text"
              value={extraPortsInput}
              onChange={(e) => setExtraPortsInput(e.target.value)}
              placeholder="e.g. 8008, 9000"
              className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-2">
            <button
              type="submit"
              disabled={loading || !target.trim()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
            >
              {loading ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Radar className="h-3.5 w-3.5" />
              )}
              {loading ? "Scanning..." : "Deep Scan IP"}
            </button>
            {report && (
              <button
                type="button"
                disabled={loading}
                onClick={() => void runScan(report.ip, { forceRefresh: true })}
                title="Force live re-scan (bypass cache)"
                className="inline-flex items-center gap-1 rounded-lg border border-line-strong bg-surface-alt px-3 py-2 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink disabled:opacity-50"
              >
                <RefreshCw className="h-3.5 w-3.5" />
                Refresh
              </button>
            )}
          </div>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-2 border-t border-line pt-2.5 text-[11px] text-ink-muted">
          <span>Examples:</span>
          {EXAMPLE_IPS.map((ex) => (
            <button
              key={ex.ip}
              type="button"
              onClick={() => {
                setTarget(ex.ip);
                void runScan(ex.ip);
              }}
              className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              {ex.label}
            </button>
          ))}
          {cachedIps.length > 0 && (
            <>
              <span className="ml-2 text-ink-muted">Cached:</span>
              {cachedIps.slice(0, 6).map((c) => (
                <button
                  key={c.ip}
                  type="button"
                  onClick={() => {
                    setTarget(c.ip);
                    void runScan(c.ip);
                  }}
                  className="inline-flex items-center gap-1 rounded border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 font-mono text-emerald-700 hover:border-emerald-500/50 dark:text-emerald-300"
                >
                  {c.ip}
                </button>
              ))}
            </>
          )}
        </div>
      </form>

      {error && (
        <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
          <div>{error}</div>
        </div>
      )}

      {loading && (
        <QueryProgressBanner
          domain={scanTargetLabel}
          stages={stages}
          startedAt={startedAt}
        />
      )}

      {!report && !loading && !error && (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-14 text-center">
          <Radar className="mx-auto h-10 w-10 text-ink-muted/60" />
          <h2 className="mt-3 text-base font-semibold text-ink">
            Deep-scan any IPv4 or IPv6 address
          </h2>
          <p className="mx-auto mt-1 max-w-xl text-xs leading-relaxed text-ink-muted">
            Retrieves PTR &amp; FCrDNS verification, BGP/ASN routing &amp; RPKI validity,
            RDAP registry ownership &amp; abuse contacts, geolocation, 41-port service &amp; banner
            scan, TLS certificates, direct HTTP/HTTPS headers, Tor/DNSBL reputation, Shodan
            InternetDB CVEs, and co-hosted domains.
          </p>
        </div>
      )}

      {report && (
        <div className={`space-y-4 ${loading ? "pointer-events-none opacity-50" : ""}`}>
          {/* Top Header & Summary Strip */}
          <div className="rounded-xl border border-line bg-surface p-4 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-lg font-bold text-ink">
                  {report.ip}
                </span>
                <button
                  type="button"
                  onClick={() => void copyText(report.ip, "IP address")}
                  className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
                  title="Copy IP"
                >
                  <Copy className="h-3.5 w-3.5" />
                </button>
                <span className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-[11px] font-medium text-ink-secondary">
                  {report.meta.ip_version}
                </span>
                <span className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary">
                  {report.meta.scope}
                </span>
                {pBadge && (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${pBadge.tone}`}
                  >
                    {report.posture === "clean" ? (
                      <ShieldCheck className="h-3 w-3" />
                    ) : (
                      <ShieldAlert className="h-3 w-3" />
                    )}
                    {pBadge.label}
                  </span>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-2 text-xs">
                <span
                  className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 font-mono text-[11px] ${
                    fromCache
                      ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                      : "border-sky-500/35 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                  }`}
                >
                  <Clock className="h-3 w-3" />
                  {fromCache ? "Cached" : "Live"} ·{" "}
                  {cachedAt ? formatRelativeAge(cachedAt) : "just now"}
                </span>
                <button
                  type="button"
                  onClick={() =>
                    void copyText(
                      formatIpScanAsMarkdown(report),
                      "Markdown IP report",
                    )
                  }
                  className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
                >
                  <FileText className="h-3 w-3" /> Copy MD
                </button>
                <button
                  type="button"
                  onClick={() => void handleExport("md")}
                  className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
                >
                  <Download className="h-3 w-3" /> .md
                </button>
                <button
                  type="button"
                  onClick={() => void handleExport("json")}
                  className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
                >
                  <Download className="h-3 w-3" /> .json
                </button>
              </div>
            </div>

            <p className="text-xs text-ink-secondary">{report.summary}</p>

            {/* 4 KPI Cards */}
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
              <div className="rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Network className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  ASN &amp; Provider
                </div>
                <div className="mt-1 truncate font-mono text-xs font-semibold text-ink">
                  {report.bgp.asn ? `AS${report.bgp.asn}` : "ASN N/A"}
                  {report.bgp.provider_name
                    ? ` · ${report.bgp.provider_name}`
                    : ""}
                </div>
                <div className="mt-0.5 truncate text-[11px] text-ink-muted">
                  {report.bgp.as_org ??
                    report.rdap.org_name ??
                    report.bgp.provider_type}
                </div>
              </div>

              <div className="rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <MapPin className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  Location &amp; Prefix
                </div>
                <div className="mt-1 truncate text-xs font-semibold text-ink">
                  {locationText}
                </div>
                <div className="mt-0.5 truncate font-mono text-[11px] text-ink-muted">
                  {report.bgp.prefix ??
                    report.rdap.cidrs[0] ??
                    "Prefix unavailable"}
                </div>
              </div>

              <div className="rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <Plug className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
                  Ports &amp; Latency
                </div>
                <div className="mt-1 font-mono text-xs font-semibold text-ink">
                  {openPortsCount} open / {report.ports.total_checked} checked
                </div>
                <div className="mt-0.5 font-mono text-[11px] text-ink-muted">
                  {report.reachability.avg_ms != null
                    ? `TCP ${report.reachability.avg_ms}ms avg (port ${report.reachability.probe_port})`
                    : "No open probe port"}
                </div>
              </div>

              <div className="rounded-lg border border-line bg-canvas p-3">
                <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                  <ShieldAlert className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                  Reputation &amp; CVEs
                </div>
                <div className="mt-1 font-mono text-xs font-semibold text-ink">
                  {report.reputation.blacklists_listed}/
                  {report.reputation.blacklists_checked} DNSBL · {cveCount}{" "}
                  CVE{cveCount === 1 ? "" : "s"}
                </div>
                <div className="mt-0.5 text-[11px] text-ink-muted">
                  {report.reputation.is_tor_exit
                    ? "Active Tor Exit Node"
                    : report.associated_hosts.length > 0
                      ? `${report.associated_hosts.length} associated host(s)`
                      : "No Tor exit signal"}
                </div>
              </div>
            </div>
          </div>

          {/* Warnings */}
          {report.warnings.map((w, i) => (
            <div
              key={i}
              className="flex items-center gap-2 rounded-xl border border-amber-500/30 bg-amber-500/10 px-4 py-2.5 text-xs text-amber-900 dark:text-amber-200"
            >
              <Info className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
              <span>{w}</span>
            </div>
          ))}

          {/* Findings */}
          {report.findings.length > 0 && (
            <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
              {report.findings.map((f, idx) => (
                <div
                  key={idx}
                  className={`rounded-xl border p-3 text-xs ${severityTone(f.severity)}`}
                >
                  <div className="flex items-center justify-between gap-2 font-semibold">
                    <span>{f.title}</span>
                    <span className="rounded bg-black/10 px-1.5 py-0.5 font-mono text-[10px] uppercase dark:bg-white/10">
                      {f.severity} · {f.category}
                    </span>
                  </div>
                  <div className="mt-1 opacity-90">{f.detail}</div>
                </div>
              ))}
            </div>
          )}

          {/* Sub-Tabs */}
          <div className="flex flex-wrap items-center gap-1 border-b border-line pb-2">
            {(
              [
                ["overview", "Overview & Hosts", Globe2],
                ["bgp", "BGP, ASN & RDAP", Building2],
                ["ports", `Ports (${openPortsCount})`, Plug],
                ["tls_http", "TLS & HTTP", Lock],
                ["reputation", "Reputation & Intel", Shield],
                ["cidr_trace", "CIDR & Traceroute", Calculator],
              ] as const
            ).map(([id, label, Icon]) => {
              const active = subTab === id;
              return (
                <button
                  key={id}
                  type="button"
                  onClick={() => setSubTab(id)}
                  className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                    active
                      ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                      : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {label}
                </button>
              );
            })}
          </div>

          {/* Sub-Tab 1: Overview & Identity */}
          {subTab === "overview" && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                {/* Address Representations */}
                <div className="rounded-xl border border-line bg-surface p-4 space-y-2.5 text-xs">
                  <div className="font-semibold text-ink">
                    Address Representations &amp; Scope
                  </div>
                  <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                    {[
                      ["Normalized", report.meta.normalized],
                      ["Reverse PTR Zone", report.meta.reverse_ptr_zone],
                      ["Hexadecimal", report.meta.hex],
                      ["Decimal Integer", report.meta.integer],
                      ...(report.meta.expanded
                        ? [["Expanded IPv6", report.meta.expanded]]
                        : []),
                      ...(report.meta.binary
                        ? [["Binary (32-bit)", report.meta.binary]]
                        : []),
                    ].map(([k, v]) => (
                      <div
                        key={k}
                        className="rounded-lg border border-line bg-canvas p-2.5"
                      >
                        <div className="flex items-center justify-between text-[10px] text-ink-muted">
                          <span>{k}</span>
                          <button
                            type="button"
                            onClick={() => void copyText(v, k)}
                            className="hover:text-sky-600 dark:hover:text-sky-400"
                          >
                            <Copy className="h-3 w-3" />
                          </button>
                        </div>
                        <div className="mt-1 break-all font-mono text-[11px] font-medium text-ink">
                          {v}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Geolocation & Network Traits */}
                <div className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-semibold text-ink">
                      Geolocation &amp; Classification
                    </span>
                    {report.geo.source && (
                      <span className="font-mono text-[10px] text-ink-muted">
                        via {report.geo.source}
                      </span>
                    )}
                  </div>
                  <div className="grid grid-cols-2 gap-2.5">
                    <div>
                      <div className="text-[11px] text-ink-muted">Location</div>
                      <div className="font-medium text-ink">{locationText}</div>
                      {report.geo.postal && (
                        <div className="text-[11px] text-ink-muted">
                          Postal: {report.geo.postal}
                        </div>
                      )}
                    </div>
                    <div>
                      <div className="text-[11px] text-ink-muted">
                        Coordinates &amp; Timezone
                      </div>
                      <div className="font-mono text-[11px] text-ink">
                        {report.geo.latitude != null &&
                        report.geo.longitude != null
                          ? `${report.geo.latitude.toFixed(4)}, ${report.geo.longitude.toFixed(4)}`
                          : "N/A"}
                      </div>
                      <div className="text-[11px] text-ink-muted">
                        {report.geo.timezone ?? "Timezone N/A"}
                        {report.geo.utc_offset
                          ? ` (${report.geo.utc_offset})`
                          : ""}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-ink-muted">ISP / Org</div>
                      <div className="font-medium text-ink">
                        {report.geo.isp ?? report.bgp.as_org ?? "Unknown"}
                      </div>
                    </div>
                    <div>
                      <div className="text-[11px] text-ink-muted">
                        Network Domain
                      </div>
                      <div className="font-mono text-[11px] text-ink">
                        {report.geo.domain ?? "—"}
                      </div>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1.5 border-t border-line pt-2.5">
                    {report.bgp.is_anycast_cdn && (
                      <span className="rounded-full border border-sky-500/35 bg-sky-500/10 px-2.5 py-0.5 text-[11px] font-medium text-sky-700 dark:text-sky-300">
                        Anycast / CDN
                      </span>
                    )}
                    {report.geo.is_hosting && (
                      <span className="rounded-full border border-violet-500/35 bg-violet-500/10 px-2.5 py-0.5 text-[11px] font-medium text-violet-700 dark:text-violet-300">
                        Cloud / Hosting
                      </span>
                    )}
                    {report.geo.is_proxy_or_vpn && (
                      <span className="rounded-full border border-amber-500/35 bg-amber-500/10 px-2.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
                        Proxy / VPN / Tor
                      </span>
                    )}
                    <span className="rounded-full border border-line bg-surface-alt px-2.5 py-0.5 text-[11px] text-ink-secondary">
                      {report.bgp.provider_type}
                    </span>
                  </div>
                </div>
              </div>

              {/* Reverse DNS & FCrDNS */}
              <div className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="font-semibold text-ink">
                    Reverse DNS (PTR) &amp; Forward-Confirmed rDNS (FCrDNS)
                  </div>
                  {report.fcrdns_overall !== null && (
                    <span
                      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                        report.fcrdns_overall
                          ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                      }`}
                    >
                      {report.fcrdns_overall ? (
                        <CheckCircle2 className="h-3 w-3" />
                      ) : (
                        <AlertTriangle className="h-3 w-3" />
                      )}
                      {report.fcrdns_overall
                        ? "FCrDNS Verified"
                        : "FCrDNS Mismatch"}
                    </span>
                  )}
                </div>

                {report.ptr_records.length === 0 ? (
                  <p className="text-ink-muted">
                    No PTR record returned for {report.meta.reverse_ptr_zone}.
                  </p>
                ) : (
                  <div className="space-y-2">
                    {report.ptr_records.map((ptr) => (
                      <div
                        key={ptr.hostname}
                        className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-canvas p-2.5"
                      >
                        <div className="space-y-0.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono font-semibold text-ink">
                              {ptr.hostname}
                            </span>
                            {ptr.fcrdns_valid ? (
                              <span className="rounded bg-emerald-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-300">
                                FCrDNS Match
                              </span>
                            ) : (
                              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                                Forward Mismatch
                              </span>
                            )}
                            {ptr.generic_pattern && (
                              <span className="rounded border border-line bg-surface-alt px-1.5 py-0.5 text-[10px] text-ink-muted">
                                {ptr.generic_pattern}
                              </span>
                            )}
                          </div>
                          <div className="font-mono text-[11px] text-ink-muted">
                            Forward IPs:{" "}
                            {ptr.forward_ips.length > 0
                              ? ptr.forward_ips.join(", ")
                              : "None"}
                          </div>
                        </div>
                        <button
                          type="button"
                          onClick={() => onInspectDomain(ptr.hostname)}
                          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-sky-700 hover:border-sky-500/40 dark:text-sky-300"
                        >
                          Inspect Domain
                          <ArrowUpRight className="h-3 w-3" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Associated / Co-Hosted Domains */}
              <div className="rounded-xl border border-line bg-surface overflow-hidden">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5">
                  <div className="text-xs font-semibold text-ink">
                    Associated &amp; Co-Hosted Hostnames (
                    {report.associated_hosts.length})
                  </div>
                  <input
                    type="text"
                    value={hostSearch}
                    onChange={(e) => setHostSearch(e.target.value)}
                    placeholder="Filter hostnames or source..."
                    className="w-56 rounded-md border border-line-strong bg-canvas px-2.5 py-1 text-xs text-ink"
                  />
                </div>
                {filteredHosts.length === 0 ? (
                  <div className="p-6 text-center text-xs text-ink-muted">
                    No associated hostnames discovered for this IP.
                  </div>
                ) : (
                  <div className="max-h-80 overflow-y-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-line bg-surface-alt/60 text-[11px] uppercase tracking-wider text-ink-muted">
                        <tr>
                          <th className="px-4 py-2">Hostname</th>
                          <th className="px-4 py-2">Discovery Sources</th>
                          <th className="px-4 py-2 text-right">Action</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {filteredHosts.map((h) => {
                          const inspectable = h.hostname.replace(/^\*\./, "");
                          return (
                            <tr
                              key={h.hostname}
                              className="hover:bg-surface-alt/50"
                            >
                              <td className="px-4 py-2 font-mono font-medium text-ink">
                                {h.hostname}
                              </td>
                              <td className="px-4 py-2">
                                <div className="flex flex-wrap gap-1">
                                  {h.sources.map((src) => (
                                    <span
                                      key={src}
                                      className="rounded border border-line bg-surface-alt px-1.5 py-0.5 text-[10px] text-ink-secondary"
                                    >
                                      {src}
                                    </span>
                                  ))}
                                </div>
                              </td>
                              <td className="px-4 py-2 text-right">
                                <button
                                  type="button"
                                  onClick={() => onInspectDomain(inspectable)}
                                  className="inline-flex items-center gap-1 text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
                                >
                                  Inspect
                                  <ArrowUpRight className="h-3 w-3" />
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
          )}

          {/* Sub-Tab 2: BGP, ASN & RDAP */}
          {subTab === "bgp" && (
            <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
              <div className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
                <div className="flex items-center justify-between border-b border-line pb-2.5">
                  <span className="font-semibold text-ink">
                    BGP Routing &amp; RPKI Origin Validation
                  </span>
                  {report.bgp.rpki_status && (
                    <span
                      className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                        report.bgp.rpki_status === "valid"
                          ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : report.bgp.rpki_status === "invalid"
                            ? "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                            : "border-line bg-surface-alt text-ink-muted"
                      }`}
                    >
                      RPKI: {report.bgp.rpki_status.toUpperCase()}
                    </span>
                  )}
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <div className="text-[11px] text-ink-muted">Origin ASN</div>
                    <div className="font-mono font-semibold text-ink">
                      {report.bgp.asn ? `AS${report.bgp.asn}` : "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">
                      Announced Prefix
                    </div>
                    <div className="font-mono font-semibold text-ink">
                      {report.bgp.prefix ?? "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">AS Org / Holder</div>
                    <div className="font-medium text-ink">
                      {report.bgp.as_org ?? report.bgp.as_holder ?? "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">
                      RIR / Allocated
                    </div>
                    <div className="font-mono text-ink">
                      {report.bgp.rir ?? "—"}
                      {report.bgp.allocated_date
                        ? ` · ${report.bgp.allocated_date}`
                        : ""}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">
                      BGP Announced
                    </div>
                    <div className="font-medium text-ink">
                      {report.bgp.announced === true
                        ? "Yes (Visible in DFZ)"
                        : report.bgp.announced === false
                          ? "No"
                          : "Unknown"}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">
                      ASN Neighbors (Up / Down / Peer)
                    </div>
                    <div className="font-mono text-ink">
                      {report.bgp.neighbors_left ?? "—"} /{" "}
                      {report.bgp.neighbors_right ?? "—"} /{" "}
                      {report.bgp.neighbors_uncertain ?? "—"}
                    </div>
                  </div>
                </div>

                {report.bgp.rpki_detail && (
                  <div className="rounded-lg border border-line bg-canvas p-2.5 text-[11px] text-ink-secondary">
                    {report.bgp.rpki_detail}
                  </div>
                )}

                {report.bgp.related_prefixes.length > 0 && (
                  <div>
                    <div className="mb-1.5 text-[11px] text-ink-muted">
                      Sample Announced Prefixes (AS{report.bgp.asn})
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {report.bgp.related_prefixes.map((pfx) => (
                        <span
                          key={pfx}
                          className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                        >
                          {pfx}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* RDAP Ownership */}
              <div className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
                <div className="flex items-center justify-between border-b border-line pb-2.5">
                  <span className="font-semibold text-ink">
                    RDAP Registry Allocation
                  </span>
                  {report.rdap.rdap_server && (
                    <span className="font-mono text-[10px] text-ink-muted">
                      {report.rdap.rdap_server}
                    </span>
                  )}
                </div>

                {report.rdap.status !== "ok" ? (
                  <p className="text-ink-muted">
                    {report.rdap.error ?? "RDAP record unavailable."}
                  </p>
                ) : (
                  <div className="space-y-3">
                    <div className="grid grid-cols-2 gap-3">
                      <div>
                        <div className="text-[11px] text-ink-muted">
                          Net Name / Handle
                        </div>
                        <div className="font-mono font-semibold text-ink">
                          {report.rdap.net_name ?? "—"}
                        </div>
                        <div className="font-mono text-[11px] text-ink-muted">
                          {report.rdap.handle ?? ""}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-ink-muted">
                          Organization
                        </div>
                        <div className="font-medium text-ink">
                          {report.rdap.org_name ?? "—"}
                        </div>
                        <div className="text-[11px] text-ink-muted">
                          {report.rdap.net_type ?? ""}
                          {report.rdap.country ? ` · ${report.rdap.country}` : ""}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-ink-muted">
                          IP Range
                        </div>
                        <div className="break-all font-mono text-[11px] text-ink">
                          {report.rdap.start_address ?? "?"} –{" "}
                          {report.rdap.end_address ?? "?"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-ink-muted">CIDRs</div>
                        <div className="font-mono text-[11px] text-ink">
                          {report.rdap.cidrs.join(", ") || "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-ink-muted">
                          Registered / Updated
                        </div>
                        <div className="font-mono text-[11px] text-ink">
                          {report.rdap.registered_date?.slice(0, 10) ?? "—"} /{" "}
                          {report.rdap.last_changed_date?.slice(0, 10) ?? "—"}
                        </div>
                      </div>
                      <div>
                        <div className="text-[11px] text-ink-muted">
                          Tech / NOC Email
                        </div>
                        <div className="break-all font-mono text-[11px] text-ink">
                          {report.rdap.tech_email ?? "—"}
                        </div>
                      </div>
                    </div>

                    {(report.rdap.abuse_email || report.rdap.abuse_phone) && (
                      <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5">
                        <div>
                          <div className="text-[10px] font-semibold uppercase tracking-wider text-amber-800 dark:text-amber-300">
                            Abuse Contact
                          </div>
                          <div className="font-mono text-xs text-ink">
                            {report.rdap.abuse_email ?? "—"}
                            {report.rdap.abuse_phone
                              ? ` · ${report.rdap.abuse_phone}`
                              : ""}
                          </div>
                        </div>
                        {report.rdap.abuse_email && (
                          <button
                            type="button"
                            onClick={() =>
                              void copyText(
                                report.rdap.abuse_email!,
                                "abuse email",
                              )
                            }
                            className="inline-flex items-center gap-1 rounded border border-line bg-surface px-2 py-1 text-[11px] text-ink-secondary hover:text-ink"
                          >
                            <Copy className="h-3 w-3" /> Copy
                          </button>
                        )}
                      </div>
                    )}

                    {report.rdap.remarks.length > 0 && (
                      <div className="space-y-1 text-[11px] text-ink-muted">
                        {report.rdap.remarks.map((r, i) => (
                          <p key={i} className="rounded bg-canvas p-2">
                            {r}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sub-Tab 3: Ports & Reachability */}
          {subTab === "ports" && (
            <div className="space-y-4">
              {/* TCP Reachability */}
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4 text-xs">
                <div className="flex items-center gap-2">
                  <Activity className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                  <div>
                    <div className="font-semibold text-ink">
                      TCP Reachability &amp; RTT Sampling
                    </div>
                    <div className="text-[11px] text-ink-muted">
                      {report.reachability.probe_port
                        ? `3 TCP connect probes to port ${report.reachability.probe_port}`
                        : "No open TCP port found to sample RTT"}
                    </div>
                  </div>
                </div>
                {report.reachability.reachable && (
                  <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
                    <span>
                      Min: <strong>{report.reachability.min_ms}ms</strong>
                    </span>
                    <span>
                      Avg: <strong>{report.reachability.avg_ms}ms</strong>
                    </span>
                    <span>
                      Max: <strong>{report.reachability.max_ms}ms</strong>
                    </span>
                    <span>
                      Loss:{" "}
                      <strong>{report.reachability.packet_loss_pct}%</strong>
                    </span>
                  </div>
                )}
              </div>

              {report.reputation.internetdb?.indexed &&
                report.reputation.internetdb.ports.length > 0 && (
                  <div className="rounded-xl border border-line bg-surface px-4 py-3 text-xs">
                    <span className="font-semibold text-ink">
                      Shodan InternetDB Historically Observed Ports:{" "}
                    </span>
                    <span className="font-mono text-sky-700 dark:text-sky-300">
                      {report.reputation.internetdb.ports.join(", ")}
                    </span>
                  </div>
                )}

              <div className="overflow-hidden rounded-xl border border-line bg-surface">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5 text-xs">
                  <div className="flex items-center gap-1.5">
                    {(
                      [
                        ["open", `Open (${report.ports.open_count})`],
                        ["risky", "Caution / High Risk"],
                        ["all", `All Scanned (${report.ports.total_checked})`],
                      ] as const
                    ).map(([id, label]) => (
                      <button
                        key={id}
                        type="button"
                        onClick={() => setPortFilter(id)}
                        className={`rounded-md px-2.5 py-1 font-medium transition ${
                          portFilter === id
                            ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                            : "text-ink-muted hover:text-ink"
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                  <span className="font-mono text-[11px] text-ink-muted">
                    Closed: {report.ports.closed_count} · Filtered:{" "}
                    {report.ports.filtered_count} · {report.ports.latency_ms}ms
                  </span>
                </div>

                {filteredPorts.length === 0 ? (
                  <div className="p-6 text-center text-xs text-ink-muted">
                    No ports match this filter.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-line bg-surface-alt/60 text-[11px] uppercase tracking-wider text-ink-muted">
                        <tr>
                          <th className="px-4 py-2">Port</th>
                          <th className="px-4 py-2">Service</th>
                          <th className="px-4 py-2">Status</th>
                          <th className="px-4 py-2">Risk</th>
                          <th className="px-4 py-2">Latency</th>
                          <th className="px-4 py-2">Banner / Note</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {filteredPorts.map((p) => (
                          <tr key={p.port} className="hover:bg-surface-alt/40">
                            <td className="px-4 py-2 font-mono font-semibold text-ink">
                              {p.port}/tcp
                            </td>
                            <td className="px-4 py-2">
                              <span className="font-medium text-ink">
                                {p.service}
                              </span>
                              <span className="ml-1.5 text-[11px] text-ink-muted">
                                ({p.category})
                              </span>
                            </td>
                            <td className="px-4 py-2">
                              <span
                                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                                  p.status === "open"
                                    ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                                    : p.status === "closed"
                                      ? "bg-surface-alt text-ink-muted"
                                      : "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                }`}
                              >
                                {p.status}
                              </span>
                            </td>
                            <td className="px-4 py-2">
                              <span
                                className={`rounded-full px-2 py-0.5 text-[10px] font-semibold uppercase ${
                                  p.risk_level === "high"
                                    ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                                    : p.risk_level === "caution"
                                      ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                      : "bg-surface-alt text-ink-muted"
                                }`}
                              >
                                {p.risk_level}
                              </span>
                            </td>
                            <td className="px-4 py-2 font-mono text-[11px] text-ink-muted">
                              {p.latency_ms}ms
                            </td>
                            <td className="max-w-md truncate px-4 py-2 font-mono text-[11px] text-ink-secondary">
                              {p.banner ?? p.note ?? "—"}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sub-Tab 4: TLS & HTTP */}
          {subTab === "tls_http" && (
            <div className="space-y-4">
              {/* TLS Reports */}
              <div className="space-y-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                  TLS Certificates ({report.tls_reports.length} port
                  {report.tls_reports.length === 1 ? "" : "s"} probed)
                </div>
                {report.tls_reports.length === 0 ? (
                  <div className="rounded-xl border border-line bg-surface p-5 text-xs text-ink-muted">
                    No TLS-capable ports were open to inspect.
                  </div>
                ) : (
                  report.tls_reports.map((tls, idx) => {
                    const leaf = tls.certificates[0];
                    return (
                      <div
                        key={`${tls.port}-${idx}`}
                        className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                          <div className="flex flex-wrap items-center gap-2">
                            <span className="font-mono font-semibold text-ink">
                              Port {tls.port}
                              {tls.starttls ? ` (${tls.starttls.toUpperCase()})` : ""}
                            </span>
                            {tls.protocol_version && (
                              <span className="rounded bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-secondary">
                                {tls.protocol_version}
                              </span>
                            )}
                            {tls.cipher_suite && (
                              <span className="rounded bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-muted">
                                {tls.cipher_suite}
                              </span>
                            )}
                          </div>
                          {leaf ? (
                            <span
                              className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                                tls.chain_valid && leaf.days_remaining > 0
                                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                                  : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                              }`}
                            >
                              {tls.chain_valid ? "Chain Trusted" : "Untrusted Chain"}{" "}
                              · {leaf.days_remaining}d left
                            </span>
                          ) : (
                            <span className="text-rose-600 dark:text-rose-400">
                              {tls.error ?? "No certificate returned"}
                            </span>
                          )}
                        </div>

                        {leaf && (
                          <div className="space-y-2.5">
                            <div className="grid grid-cols-1 gap-2 sm:grid-cols-3">
                              <div>
                                <div className="text-[11px] text-ink-muted">
                                  Common Name / Subject
                                </div>
                                <div className="break-all font-mono text-[11px] font-semibold text-ink">
                                  {leaf.common_name ?? leaf.subject}
                                </div>
                              </div>
                              <div>
                                <div className="text-[11px] text-ink-muted">
                                  Issuer
                                </div>
                                <div className="text-[11px] text-ink">
                                  {leaf.issuer_org ?? leaf.issuer}
                                </div>
                              </div>
                              <div>
                                <div className="text-[11px] text-ink-muted">
                                  Key &amp; Validity
                                </div>
                                <div className="font-mono text-[11px] text-ink">
                                  {leaf.public_key_algorithm}{" "}
                                  {leaf.public_key_bits
                                    ? `${leaf.public_key_bits}-bit`
                                    : ""}{" "}
                                  · exp {leaf.not_after.slice(0, 10)}
                                </div>
                              </div>
                            </div>

                            {leaf.sans.length > 0 && (
                              <div>
                                <div className="mb-1 text-[11px] text-ink-muted">
                                  Subject Alternative Names ({leaf.sans.length})
                                </div>
                                <div className="flex flex-wrap gap-1.5">
                                  {leaf.sans.slice(0, 24).map((san) => {
                                    const clean = san.replace(/^\*\./, "");
                                    const isDomain =
                                      clean.includes(".") &&
                                      !/^\d+\.\d+\.\d+\.\d+$/.test(clean) &&
                                      !clean.includes(":");
                                    return isDomain ? (
                                      <button
                                        key={san}
                                        type="button"
                                        onClick={() => onInspectDomain(clean)}
                                        className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-sky-700 hover:border-sky-500/40 dark:text-sky-300"
                                      >
                                        {san}
                                      </button>
                                    ) : (
                                      <span
                                        key={san}
                                        className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                                      >
                                        {san}
                                      </span>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>

              {/* HTTP Probes */}
              <div className="space-y-3">
                <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
                  Direct HTTP / HTTPS Probes
                </div>
                <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
                  {report.http_probes.map((probe) => (
                    <div
                      key={probe.scheme}
                      className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs"
                    >
                      <div className="flex items-center justify-between border-b border-line pb-2">
                        <span className="font-mono font-semibold text-ink">
                          {probe.url}
                        </span>
                        {probe.reachable ? (
                          <span className="rounded-full bg-emerald-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                            HTTP {probe.http_status} · {probe.latency_ms}ms
                          </span>
                        ) : (
                          <span className="rounded-full bg-surface-alt px-2 py-0.5 text-[11px] text-ink-muted">
                            Unreachable
                          </span>
                        )}
                      </div>

                      {!probe.reachable ? (
                        <p className="text-[11px] text-ink-muted">
                          {probe.error ?? "Connection failed."}
                        </p>
                      ) : (
                        <div className="space-y-2">
                          <div className="grid grid-cols-2 gap-2 text-[11px]">
                            <div>
                              <span className="text-ink-muted">Server: </span>
                              <span className="font-mono text-ink">
                                {probe.server ?? "—"}
                              </span>
                            </div>
                            <div>
                              <span className="text-ink-muted">HTTP/3: </span>
                              <span className="font-mono text-ink">
                                {probe.http3_supported ? "Advertised" : "No"}
                              </span>
                            </div>
                            {probe.title && (
                              <div className="col-span-2 truncate">
                                <span className="text-ink-muted">Title: </span>
                                <span className="text-ink">{probe.title}</span>
                              </div>
                            )}
                            {probe.location && (
                              <div className="col-span-2 truncate">
                                <span className="text-ink-muted">Redirect: </span>
                                <span className="font-mono text-sky-700 dark:text-sky-300">
                                  {probe.location}
                                </span>
                              </div>
                            )}
                          </div>

                          {probe.waf_or_cdn_headers.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              {probe.waf_or_cdn_headers.map((w) => (
                                <span
                                  key={w}
                                  className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-[10px] text-sky-700 dark:text-sky-300"
                                >
                                  {w}
                                </span>
                              ))}
                            </div>
                          )}

                          <button
                            type="button"
                            onClick={() =>
                              setExpandedHttpScheme((prev) =>
                                prev === probe.scheme ? null : probe.scheme,
                              )
                            }
                            className="text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
                          >
                            {expandedHttpScheme === probe.scheme
                              ? "Hide raw headers"
                              : `Show ${probe.headers.length} response header(s)`}
                          </button>

                          {expandedHttpScheme === probe.scheme && (
                            <div className="max-h-48 overflow-y-auto rounded-lg border border-line bg-canvas p-2 font-mono text-[11px]">
                              {probe.headers.map((h, i) => (
                                <div key={i} className="break-all">
                                  <span className="text-ink-muted">
                                    {h.name}:{" "}
                                  </span>
                                  <span className="text-ink">{h.value}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Sub-Tab 5: Reputation & Threat Intel */}
          {subTab === "reputation" && (
            <div className="space-y-4">
              {/* Shodan InternetDB & Tor */}
              <div className="rounded-xl border border-line bg-surface p-4 space-y-3 text-xs">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                  <div className="font-semibold text-ink">
                    Threat Intelligence (Shodan InternetDB &amp; Tor Exit)
                  </div>
                  <span
                    className={`rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                      report.reputation.is_tor_exit
                        ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                        : "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                    }`}
                  >
                    {report.reputation.is_tor_exit
                      ? "Tor Exit Node: YES"
                      : "Tor Exit Node: No"}
                  </span>
                </div>

                {report.reputation.internetdb ? (
                  report.reputation.internetdb.indexed ? (
                    <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                      <div>
                        <div className="mb-1 text-[11px] text-ink-muted">
                          Observed Ports (InternetDB)
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {report.reputation.internetdb.ports.map((p) => (
                            <span
                              key={p}
                              className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink"
                            >
                              {p}
                            </span>
                          ))}
                        </div>
                      </div>
                      <div>
                        <div className="mb-1 text-[11px] text-ink-muted">
                          Tags
                        </div>
                        <div className="flex flex-wrap gap-1">
                          {report.reputation.internetdb.tags.length > 0 ? (
                            report.reputation.internetdb.tags.map((t) => (
                              <span
                                key={t}
                                className="rounded border border-sky-500/30 bg-sky-500/10 px-2 py-0.5 font-mono text-[11px] text-sky-700 dark:text-sky-300"
                              >
                                {t}
                              </span>
                            ))
                          ) : (
                            <span className="text-ink-muted">None</span>
                          )}
                        </div>
                      </div>
                      <div>
                        <div className="mb-1 text-[11px] text-ink-muted">
                          Software CPEs (
                          {report.reputation.internetdb.cpes.length})
                        </div>
                        {report.reputation.internetdb.cpes.length > 0 ? (
                          <div className="space-y-1 font-mono text-[11px] text-ink-secondary">
                            {report.reputation.internetdb.cpes.map((c) => (
                              <div key={c}>{c}</div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-ink-muted">None reported</span>
                        )}
                      </div>
                      <div>
                        <div className="mb-1 text-[11px] text-ink-muted">
                          Associated CVEs (
                          {report.reputation.internetdb.vulns.length})
                        </div>
                        {report.reputation.internetdb.vulns.length > 0 ? (
                          <div className="flex flex-wrap gap-1.5">
                            {report.reputation.internetdb.vulns.map((cve) => (
                              <a
                                key={cve}
                                href={`https://nvd.nist.gov/vuln/detail/${encodeURIComponent(cve)}`}
                                target="_blank"
                                rel="noreferrer"
                                className="inline-flex items-center gap-1 rounded border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold text-rose-700 hover:underline dark:text-rose-300"
                              >
                                {cve}
                                <ExternalLink className="h-2.5 w-2.5" />
                              </a>
                            ))}
                          </div>
                        ) : (
                          <span className="text-emerald-600 dark:text-emerald-400">
                            No CVEs reported
                          </span>
                        )}
                      </div>
                    </div>
                  ) : (
                    <p className="text-ink-muted">
                      {report.reputation.internetdb.error ??
                        "Not indexed in Shodan InternetDB."}
                    </p>
                  )
                ) : (
                  <p className="text-ink-muted">
                    InternetDB lookup skipped for non-public IP.
                  </p>
                )}
              </div>

              {/* DNSBLs */}
              <div className="overflow-hidden rounded-xl border border-line bg-surface">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5 text-xs">
                  <div className="flex items-center gap-1.5">
                    {(
                      [
                        [
                          "all",
                          `All (${report.reputation.blacklists.length})`,
                        ],
                        [
                          "listed",
                          `Listed (${report.reputation.blacklists_listed})`,
                        ],
                        [
                          "blocked",
                          `Blocked (${report.reputation.blacklists_blocked})`,
                        ],
                        ["clean", "Clean"],
                      ] as const
                    ).map(([id, label]) => (
                      <button
                        key={id}
                        type="button"
                        onClick={() => setDnsblFilter(id)}
                        className={`rounded-md px-2.5 py-1 font-medium transition ${
                          dnsblFilter === id
                            ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                            : "text-ink-muted hover:text-ink"
                        }`}
                      >
                        {label}
                      </button>
                    ))}
                  </div>
                </div>

                {report.reputation.blacklists.length === 0 ? (
                  <div className="p-6 text-center text-xs text-ink-muted">
                    DNSBL checks apply to public IPv4 addresses.
                  </div>
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-line bg-surface-alt/60 text-[11px] uppercase tracking-wider text-ink-muted">
                        <tr>
                          <th className="px-4 py-2">Blacklist</th>
                          <th className="px-4 py-2">Status</th>
                          <th className="px-4 py-2">Return Codes / Detail</th>
                          <th className="px-4 py-2 text-right">Latency</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line">
                        {filteredDnsbls.map((b) => (
                          <tr
                            key={`${b.zone}-${b.target}`}
                            className="hover:bg-surface-alt/40"
                          >
                            <td className="px-4 py-2">
                              <div className="font-medium text-ink">
                                {b.list_name}
                              </div>
                              <div className="font-mono text-[10px] text-ink-muted">
                                {b.zone}
                              </div>
                            </td>
                            <td className="px-4 py-2">
                              {b.status === "listed" ? (
                                <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[10px] font-semibold text-rose-700 dark:text-rose-300">
                                  <XCircle className="h-3 w-3" /> Listed
                                </span>
                              ) : b.status === "blocked" ||
                                b.status === "policy" ? (
                                <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                                  <AlertTriangle className="h-3 w-3" />{" "}
                                  {b.status}
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[10px] font-semibold text-emerald-700 dark:text-emerald-300">
                                  <CheckCircle2 className="h-3 w-3" /> Clean
                                </span>
                              )}
                            </td>
                            <td className="px-4 py-2 text-[11px] text-ink-secondary">
                              {b.return_codes.length > 0 && (
                                <span className="mr-2 font-mono text-ink">
                                  {b.return_codes.join(", ")}
                                </span>
                              )}
                              {b.detail ?? "—"}
                              {b.status === "listed" && b.delist_url && (
                                <a
                                  href={b.delist_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="ml-2 inline-flex items-center gap-0.5 text-sky-600 hover:underline dark:text-sky-400"
                                >
                                  Delist <ExternalLink className="h-2.5 w-2.5" />
                                </a>
                              )}
                            </td>
                            <td className="px-4 py-2 text-right font-mono text-[11px] text-ink-muted">
                              {b.latency_ms}ms
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Sub-Tab 6: CIDR & Traceroute */}
          {subTab === "cidr_trace" && (
            <div className="space-y-4">
              <CidrCalculator
                initialCidr={
                  report.bgp.prefix ?? report.rdap.cidrs[0] ?? report.ip
                }
                initialTestIp={report.ip}
                onNotify={onNotify}
              />

              <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-2">
                    <Route className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
                    <div>
                      <div className="text-xs font-semibold text-ink">
                        Network Path Traceroute to {report.ip}
                      </div>
                      <div className="text-[11px] text-ink-muted">
                        Runs OS traceroute / tracepath and caches hops for this IP.
                      </div>
                    </div>
                  </div>
                  <button
                    type="button"
                    disabled={traceLoading}
                    onClick={() => void handleRunTraceroute()}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
                  >
                    {traceLoading ? (
                      <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                    ) : (
                      <Play className="h-3.5 w-3.5" />
                    )}
                    {traceLoading ? "Tracing..." : "Run Traceroute"}
                  </button>
                </div>

                {traceError && (
                  <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-800 dark:text-rose-200">
                    {traceError}
                  </div>
                )}

                {traceReport && (
                  <div className="overflow-x-auto rounded-lg border border-line">
                    <table className="w-full text-left text-xs">
                      <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                        <tr>
                          <th className="px-3 py-2">Hop</th>
                          <th className="px-3 py-2">IP / Host</th>
                          <th className="px-3 py-2">Avg RTT</th>
                          <th className="px-3 py-2">Latency Bar</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-line font-mono text-[11px]">
                        {traceReport.hops.map((hop) => {
                          const pct =
                            hop.avg_ms != null
                              ? Math.max(
                                  6,
                                  Math.min(100, (hop.avg_ms / maxTraceAvg) * 100),
                                )
                              : 0;
                          return (
                            <tr key={hop.hop}>
                              <td className="px-3 py-1.5 text-ink-muted">
                                {hop.hop}
                              </td>
                              <td className="px-3 py-1.5 text-ink">
                                {hop.timed_out
                                  ? "* * * (timeout)"
                                  : hop.hostname && hop.ip
                                    ? `${hop.hostname} (${hop.ip})`
                                    : hop.ip ?? hop.hostname ?? "—"}
                              </td>
                              <td className="px-3 py-1.5 text-ink-secondary">
                                {hop.avg_ms != null
                                  ? `${hop.avg_ms.toFixed(1)} ms`
                                  : "—"}
                              </td>
                              <td className="w-40 px-3 py-1.5">
                                {hop.avg_ms != null && (
                                  <div className="h-1.5 w-full overflow-hidden rounded-full bg-surface-alt">
                                    <div
                                      className="h-full rounded-full bg-sky-500"
                                      style={{ width: `${pct}%` }}
                                    />
                                  </div>
                                )}
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
          )}
        </div>
      )}
    </div>
  );
}
