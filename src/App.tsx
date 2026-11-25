import {
  Activity,
  AlertCircle,
  Bookmark,
  Copy,
  Database,
  FileCode2,
  FileDiff,
  FileSearch,
  GitBranch,
  Globe2,
  HeartPulse,
  Layers,
  ListChecks,
  Lock,
  Monitor,
  Moon,
  Network,
  Plug,
  Radio,
  Route,
  Server,
  Shield,
  ShieldAlert,
  Sun,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BulkCheckerPanel } from "./components/BulkCheckerPanel";
import { DnsDiffPanel } from "./components/DnsDiffPanel";
import { DnsTracePanel } from "./components/DnsTracePanel";
import { DomainHealthPanel } from "./components/DomainHealthPanel";
import { ExportMenu } from "./components/ExportMenu";
import { HistorySidebar } from "./components/HistorySidebar";
import { LiveMonitorPanel } from "./components/LiveMonitorPanel";
import { NetworkPanel } from "./components/NetworkPanel";
import { PortsPanel } from "./components/PortsPanel";
import { PropagationView } from "./components/PropagationView";
import { ALL_RECORD_TYPES, QueryBar } from "./components/QueryBar";
import {
  INITIAL_PROGRESS_STAGES,
  type ProgressStageState,
  QueryProgressBanner,
} from "./components/QueryProgressBanner";
import { RecordsTable } from "./components/RecordsTable";
import { RedirectsPanel } from "./components/RedirectsPanel";
import { SecurityPanel } from "./components/SecurityPanel";
import { SubdomainsPanel } from "./components/SubdomainsPanel";
import { TlsPanel } from "./components/TlsPanel";
import { TyposquatPanel } from "./components/TyposquatPanel";
import { WatchlistPanel } from "./components/WatchlistPanel";
import { WebsitePanel } from "./components/WebsitePanel";
import { WhoisPanel } from "./components/WhoisPanel";
import { copyToClipboard, queryDomain } from "./lib/api";
import { formatAsZoneFile } from "./lib/export";
import { type ThemePreference, useTheme } from "./lib/theme";
import {
  computeDrifts,
  loadWatchlist,
  saveWatchlist,
  snapshotFromReport,
  type WatchlistEntry,
} from "./lib/watchlist";
import type {
  DnsQueryReport,
  HistoryEntry,
  QueryProgressEvent,
  RecordTypeName,
  ResolverId,
} from "./types/dns";

type WorkspaceMode = "inspector" | "watchlist" | "bulk" | "monitor";

type ActiveTab =
  | "records"
  | "propagation"
  | "trace"
  | "security"
  | "tls"
  | "network"
  | "redirects"
  | "health"
  | "subdomains"
  | "typosquat"
  | "ports"
  | "whois"
  | "website"
  | "diff"
  | "zone";

const HISTORY_KEY = "domain_tools_history_v1";
const LEGACY_HISTORY_KEY = "dns_verifier_history_v1";

function loadHistory(): HistoryEntry[] {
  try {
    const raw =
      localStorage.getItem(HISTORY_KEY) ??
      localStorage.getItem(LEGACY_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

const THEME_OPTIONS: { id: ThemePreference; label: string; Icon: typeof Monitor }[] = [
  { id: "system", label: "System", Icon: Monitor },
  { id: "light", label: "Light", Icon: Sun },
  { id: "dark", label: "Dark", Icon: Moon },
];

export function App() {
  const { preference, setPreference } = useTheme();
  const [workspace, setWorkspace] = useState<WorkspaceMode>("inspector");
  const [domain, setDomain] = useState("");
  const [recordTypes, setRecordTypes] =
    useState<RecordTypeName[]>(ALL_RECORD_TYPES);
  const [resolvers, setResolvers] = useState<ResolverId[]>([
    "cloudflare",
    "google",
    "quad9",
    "system",
  ]);
  const [customResolver, setCustomResolver] = useState("");
  const [dkimSelectorsInput, setDkimSelectorsInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [queryDomainLabel, setQueryDomainLabel] = useState("");
  const [queryStartedAt, setQueryStartedAt] = useState<number | null>(null);
  const [progressStages, setProgressStages] = useState<ProgressStageState[]>(
    INITIAL_PROGRESS_STAGES,
  );
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<DnsQueryReport | null>(null);
  const [selectedResolverId, setSelectedResolverId] = useState("cloudflare");
  const [activeTab, setActiveTab] = useState<ActiveTab>("records");
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [watchlist, setWatchlist] = useState<WatchlistEntry[]>(loadWatchlist);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const domainInputRef = useRef<HTMLInputElement>(null);

  const notify = useCallback((message: string) => {
    setToast(message);
    setTimeout(() => {
      setToast((prev) => (prev === message ? null : prev));
    }, 2400);
  }, []);

  const updateWatchlist = useCallback((next: WatchlistEntry[]) => {
    setWatchlist(next);
    saveWatchlist(next);
  }, []);

  const watchlistAlertsCount = useMemo(
    () => watchlist.reduce((acc, item) => acc + item.drifts.length, 0),
    [watchlist],
  );

  const isCurrentWatched = useMemo(
    () => Boolean(report && watchlist.some((w) => w.domain === report.domain)),
    [report, watchlist],
  );

  const toggleWatchCurrent = useCallback(() => {
    if (!report) return;
    const exists = watchlist.some((w) => w.domain === report.domain);
    if (exists) {
      updateWatchlist(watchlist.filter((w) => w.domain !== report.domain));
      notify(`Removed ${report.domain} from Watchlist`);
    } else {
      const snap = snapshotFromReport(report);
      const drifts = computeDrifts(snap, snap);
      const entry: WatchlistEntry = {
        domain: report.domain,
        addedAt: new Date().toISOString(),
        baseline: snap,
        latest: snap,
        drifts,
      };
      updateWatchlist([entry, ...watchlist]);
      notify(`Added ${report.domain} to Watchlist`);
    }
  }, [notify, report, updateWatchlist, watchlist]);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        domainInputRef.current?.focus();
        domainInputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  useEffect(() => {
    if (typeof window === "undefined" || !("__TAURI_INTERNALS__" in window)) {
      return;
    }
    let active = true;
    let unlisten: (() => void) | undefined;

    void import("@tauri-apps/api/event")
      .then(({ listen }) =>
        listen<QueryProgressEvent>("query-progress", ({ payload }) => {
          setProgressStages((prev) =>
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
        if (!active) {
          fn();
        } else {
          unlisten = fn;
        }
      })
      .catch(() => {});

    return () => {
      active = false;
      unlisten?.();
    };
  }, []);

  const runLookup = useCallback(
    async (overrideDomain?: string) => {
      const targetDomain = (overrideDomain ?? domain).trim();
      if (!targetDomain) return;

      setLoading(true);
      setQueryDomainLabel(targetDomain);
      setQueryStartedAt(Date.now());
      setProgressStages(INITIAL_PROGRESS_STAGES.map((s) => ({ ...s })));
      setError(null);

      const dkimSelectors = dkimSelectorsInput
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      try {
        const res = await queryDomain({
          domain: targetDomain,
          record_types: recordTypes,
          resolvers,
          custom_resolver: customResolver.trim() || null,
          dkim_selectors: dkimSelectors,
        });

        setReport(res);
        setDomain(res.domain);
        const firstOk =
          res.resolvers.find((r) => r.status === "ok") ?? res.resolvers[0];
        if (firstOk) {
          setSelectedResolverId(firstOk.id);
        }

        const totalRecords =
          firstOk?.results.reduce((acc, r) => acc + r.records.length, 0) ?? 0;

        const entry: HistoryEntry = {
          domain: res.domain,
          queried_at: res.queried_at,
          spfStatus: res.security.spf.status,
          dmarcStatus: res.security.dmarc.status,
          dkimStatus: res.security.dkim.status,
          dnssecStatus: res.security.dnssec.status,
          totalRecords,
        };

        setHistory((prev) => {
          const next = [
            entry,
            ...prev.filter((item) => item.domain !== res.domain),
          ].slice(0, 25);
          localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
          return next;
        });

        // Update Watchlist snapshot automatically if this domain is watched
        setWatchlist((prev) => {
          if (!prev.some((w) => w.domain === res.domain)) return prev;
          const snap = snapshotFromReport(res);
          const next = prev.map((w) => {
            if (w.domain !== res.domain) return w;
            const baseline = w.baseline ?? snap;
            return {
              ...w,
              baseline,
              latest: snap,
              drifts: computeDrifts(baseline, snap),
            };
          });
          saveWatchlist(next);
          return next;
        });
      } catch (err) {
        setError(String(err));
      } finally {
        setLoading(false);
        setQueryStartedAt(null);
      }
    },
    [customResolver, dkimSelectorsInput, domain, recordTypes, resolvers],
  );

  const zoneOutput = useMemo(
    () => (report ? formatAsZoneFile(report, selectedResolverId) : ""),
    [report, selectedResolverId],
  );

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-canvas text-ink">
      <HistorySidebar
        history={history}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
        onSelectDomain={(d) => {
          setWorkspace("inspector");
          setDomain(d);
          void runLookup(d);
        }}
        onClearHistory={() => {
          setHistory([]);
          localStorage.removeItem(HISTORY_KEY);
        }}
        activeDomain={report?.domain}
      />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex items-center justify-between gap-3 border-b border-line bg-chrome px-6 py-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-500/30">
              <Globe2 className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-ink">
                Domain Tools
              </h1>
              <p className="text-[11px] text-ink-muted">
                DNS, health audit, SSL/TLS, trace, lookalikes, watchlist &amp; live monitor
              </p>
            </div>
          </div>

          <div
            className="inline-flex items-center rounded-lg border border-line bg-surface-alt p-0.5"
            role="tablist"
            aria-label="Workspace mode"
          >
            {(
              [
                ["inspector", "Domain Inspector", Globe2],
                ["watchlist", "Watchlist", Bookmark],
                ["bulk", "Bulk Checker", ListChecks],
                ["monitor", "Live Monitor", Radio],
              ] as const
            ).map(([id, label, Icon]) => {
              const active = workspace === id;
              return (
                <button
                  key={id}
                  type="button"
                  role="tab"
                  aria-selected={active}
                  onClick={() => setWorkspace(id)}
                  className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                    active
                      ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                      : "text-ink-muted hover:text-ink"
                  }`}
                >
                  <Icon className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  <span className="hidden md:inline">{label}</span>
                  {id === "watchlist" && watchlistAlertsCount > 0 && (
                    <span className="rounded-full bg-amber-500/20 px-1.5 py-0.2 font-mono text-[10px] font-bold text-amber-700 dark:text-amber-300">
                      {watchlistAlertsCount}
                    </span>
                  )}
                </button>
              );
            })}
          </div>

          <div className="flex items-center gap-2.5">
            <div
              className="inline-flex items-center rounded-lg border border-line bg-surface-alt p-0.5"
              role="group"
              aria-label="Theme"
            >
              {THEME_OPTIONS.map(({ id, label, Icon }) => {
                const active = preference === id;
                return (
                  <button
                    key={id}
                    type="button"
                    onClick={() => setPreference(id)}
                    title={`Theme: ${label}`}
                    className={`inline-flex items-center gap-1 rounded-md px-2 py-1 text-[11px] font-medium transition ${
                      active
                        ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    <Icon className="h-3 w-3" />
                    <span className="hidden sm:inline">{label}</span>
                  </button>
                );
              })}
            </div>

            {report && workspace === "inspector" && (
              <ExportMenu
                report={report}
                selectedResolverId={selectedResolverId}
                onNotify={notify}
              />
            )}
          </div>
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-7xl space-y-5">
            {workspace === "watchlist" && (
              <WatchlistPanel
                entries={watchlist}
                onUpdateEntries={updateWatchlist}
                onInspectDomain={(d) => {
                  setWorkspace("inspector");
                  setDomain(d);
                  setActiveTab("health");
                  void runLookup(d);
                }}
                onNotify={notify}
              />
            )}

            {workspace === "bulk" && (
              <BulkCheckerPanel
                onInspectDomain={(d) => {
                  setWorkspace("inspector");
                  setDomain(d);
                  setActiveTab("records");
                  void runLookup(d);
                }}
                onNotify={notify}
              />
            )}

            {workspace === "monitor" && (
              <LiveMonitorPanel
                initialTarget={report?.domain || domain || "cloudflare.com"}
              />
            )}

            {workspace === "inspector" && (
              <>
                <QueryBar
                  domain={domain}
                  onDomainChange={setDomain}
                  recordTypes={recordTypes}
                  onRecordTypesChange={setRecordTypes}
                  resolvers={resolvers}
                  onResolversChange={setResolvers}
                  customResolver={customResolver}
                  onCustomResolverChange={setCustomResolver}
                  dkimSelectorsInput={dkimSelectorsInput}
                  onDkimSelectorsInputChange={setDkimSelectorsInput}
                  loading={loading}
                  onSubmit={runLookup}
                  inputRef={domainInputRef}
                />

                {error && (
                  <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-900 dark:text-rose-200">
                    <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
                    <div>
                      <div className="font-semibold">DNS Lookup Failed</div>
                      <div className="mt-0.5 text-xs text-rose-800 dark:text-rose-300/90">
                        {error}
                      </div>
                    </div>
                  </div>
                )}

                {loading && (
                  <QueryProgressBanner
                    domain={queryDomainLabel}
                    stages={progressStages}
                    startedAt={queryStartedAt}
                  />
                )}

                {!report && !loading && !error && (
                  <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-16 text-center">
                    <Globe2 className="mx-auto h-10 w-10 text-ink-muted/60" />
                    <h2 className="mt-3 text-base font-semibold text-ink">
                      Query any domain&apos;s DNS records
                    </h2>
                    <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-ink-muted">
                      Enter a domain above to inspect DNS, SPF/DMARC/DKIM/MTA-STS,
                      SSL/TLS &amp; CT logs, RPKI/ASN, redirects, actionable health remediation,
                      delegation trace, lookalikes, subdomains, and open ports.
                    </p>
                  </div>
                )}

                {report && (
                  <div
                    className={`space-y-4 transition-opacity ${
                      loading ? "pointer-events-none opacity-50" : ""
                    }`}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line pb-2">
                      <div className="flex flex-wrap items-center gap-1">
                        <button
                          type="button"
                          onClick={() => setActiveTab("records")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "records"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Database className="h-3.5 w-3.5" />
                          Records
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("propagation")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "propagation"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Activity className="h-3.5 w-3.5" />
                          Propagation
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("trace")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "trace"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Route className="h-3.5 w-3.5" />
                          DNS Trace
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("security")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "security"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Shield className="h-3.5 w-3.5" />
                          Email &amp; Security
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("tls")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "tls"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Lock className="h-3.5 w-3.5" />
                          SSL / TLS
                          {report.tls?.days_remaining != null && (
                            <span
                              className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] font-semibold ${
                                report.tls.status === "ok"
                                  ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                                  : report.tls.status === "warning"
                                    ? "bg-amber-500/20 text-amber-700 dark:text-amber-300"
                                    : "bg-rose-500/20 text-rose-700 dark:text-rose-300"
                              }`}
                            >
                              {report.tls.days_remaining}d
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("network")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "network"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Server className="h-3.5 w-3.5" />
                          Network / IP
                          {(report.network?.ips?.length ?? 0) > 0 && (
                            <span className="rounded-full bg-surface-alt px-1.5 py-0.2 font-mono text-[10px] text-ink-secondary">
                              {report.network.ips.length}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("redirects")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "redirects"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <GitBranch className="h-3.5 w-3.5" />
                          Redirects
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("health")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "health"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <HeartPulse className="h-3.5 w-3.5" />
                          Domain Health
                          {report.health && (
                            <span
                              className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] font-semibold ${
                                report.health.overall_status === "healthy"
                                  ? "bg-emerald-500/20 text-emerald-700 dark:text-emerald-300"
                                  : report.health.overall_status === "caution"
                                    ? "bg-amber-500/20 text-amber-700 dark:text-amber-300"
                                    : "bg-rose-500/20 text-rose-700 dark:text-rose-300"
                              }`}
                            >
                              {report.health.grade}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("subdomains")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "subdomains"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Network className="h-3.5 w-3.5" />
                          Subdomains
                          {(report.subdomains?.total_found ?? 0) > 0 && (
                            <span className="rounded-full bg-surface-alt px-1.5 py-0.2 font-mono text-[10px] text-ink-secondary">
                              {report.subdomains.total_found}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("typosquat")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "typosquat"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <ShieldAlert className="h-3.5 w-3.5" />
                          Lookalikes
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("ports")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "ports"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Plug className="h-3.5 w-3.5" />
                          Ports
                          {report.ports && (
                            <span className="rounded-full bg-surface-alt px-1.5 py-0.2 font-mono text-[10px] text-ink-secondary">
                              {report.ports.open_count}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("whois")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "whois"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <FileSearch className="h-3.5 w-3.5" />
                          WHOIS
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("website")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "website"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <Layers className="h-3.5 w-3.5" />
                          Website
                          {(report.website?.technologies?.length ?? 0) > 0 && (
                            <span className="rounded-full bg-surface-alt px-1.5 py-0.2 font-mono text-[10px] text-ink-secondary">
                              {report.website.technologies.length}
                            </span>
                          )}
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("diff")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "diff"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <FileDiff className="h-3.5 w-3.5" />
                          DNS Diff
                        </button>
                        <button
                          type="button"
                          onClick={() => setActiveTab("zone")}
                          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                            activeTab === "zone"
                              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
                          }`}
                        >
                          <FileCode2 className="h-3.5 w-3.5" />
                          Zone Output
                        </button>
                      </div>

                      <div className="flex items-center gap-2 font-mono text-xs text-ink-muted">
                        <button
                          type="button"
                          onClick={toggleWatchCurrent}
                          className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 font-sans text-[11px] font-medium transition ${
                            isCurrentWatched
                              ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                              : "border-line-strong bg-surface-alt text-ink-secondary hover:text-ink"
                          }`}
                        >
                          <Bookmark className="h-3 w-3" />
                          {isCurrentWatched ? "Watching" : "Watch"}
                        </button>
                        <span>
                          Target:{" "}
                          <span className="font-semibold text-ink">
                            {report.domain}
                          </span>
                        </span>
                      </div>
                    </div>

                    {activeTab === "records" && (
                      <RecordsTable
                        report={report}
                        selectedResolverId={selectedResolverId}
                        onSelectResolverId={setSelectedResolverId}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "propagation" && (
                      <PropagationView report={report} />
                    )}

                    {activeTab === "trace" && (
                      <DnsTracePanel domain={report.domain} onNotify={notify} />
                    )}

                    {activeTab === "security" && (
                      <SecurityPanel
                        domain={report.domain}
                        security={report.security}
                        dkimSelectorsInput={dkimSelectorsInput}
                        onDkimSelectorsInputChange={setDkimSelectorsInput}
                        onRecheckDkim={() => void runLookup(report.domain)}
                        loading={loading}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "tls" &&
                      (report.tls ? (
                        <TlsPanel
                          tls={report.tls}
                          defaultHost={report.domain}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>SSL / TLS data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "network" &&
                      (report.network ? (
                        <NetworkPanel
                          network={report.network}
                          defaultTarget={report.domain}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Network / ASN data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "redirects" &&
                      (report.redirects ? (
                        <RedirectsPanel
                          redirects={report.redirects}
                          defaultDomain={report.domain}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Redirect &amp; Waterfall data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "health" &&
                      (report.health ? (
                        <DomainHealthPanel
                          health={report.health}
                          report={report}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Domain Health data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "subdomains" &&
                      (report.subdomains ? (
                        <SubdomainsPanel
                          report={report.subdomains}
                          onInspectSubdomain={(sub) => {
                            setDomain(sub);
                            setActiveTab("records");
                            void runLookup(sub);
                          }}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Subdomain data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "typosquat" && (
                      <TyposquatPanel
                        domain={report.domain}
                        onInspectDomain={(d) => {
                          setDomain(d);
                          setActiveTab("records");
                          void runLookup(d);
                        }}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "ports" &&
                      (report.ports ? (
                        <PortsPanel report={report.ports} onNotify={notify} />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Port scan data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "whois" &&
                      (report.whois ? (
                        <WhoisPanel
                          whois={report.whois}
                          queriedTarget={report.domain}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>WHOIS data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "website" &&
                      (report.website ? (
                        <WebsitePanel website={report.website} onNotify={notify} />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Website stack data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() => void runLookup(report.domain)}
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "diff" && (
                      <DnsDiffPanel
                        report={report}
                        selectedResolverId={selectedResolverId}
                        onSelectResolverId={setSelectedResolverId}
                        historyDomains={history.map((h) => h.domain)}
                        customResolver={customResolver}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "zone" && (
                      <div className="overflow-hidden rounded-xl border border-line bg-surface">
                        <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5">
                          <span className="text-xs font-medium text-ink-secondary">
                            BIND Zone Style Output
                          </span>
                          <button
                            type="button"
                            onClick={async () => {
                              await copyToClipboard(zoneOutput);
                              notify("Copied zone output");
                            }}
                            className="inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2.5 py-1 text-xs text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
                          >
                            <Copy className="h-3.5 w-3.5" />
                            Copy Zone
                          </button>
                        </div>
                        <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-ink">
                          {zoneOutput}
                        </pre>
                      </div>
                    )}
                  </div>
                )}
              </>
            )}
          </div>
        </main>
      </div>

      {toast && (
        <div className="fixed bottom-4 right-4 z-50 rounded-lg border border-sky-500/40 bg-surface px-3.5 py-2 text-xs font-medium text-sky-700 shadow-xl shadow-slate-900/10 dark:text-sky-200 dark:shadow-black/50">
          {toast}
        </div>
      )}
    </div>
  );
}

export default App;
