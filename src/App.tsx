import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  Bell,
  Bookmark,
  Clock,
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
  Radar,
  Radio,
  RefreshCw,
  Route,
  Server,
  Shield,
  ShieldAlert,
  Sparkles,
  Sun,
  Trash2,
  Wrench,
  X,
  Zap,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { BulkCheckerPanel } from "./components/BulkCheckerPanel";
import { DnsDiffPanel } from "./components/DnsDiffPanel";
import { DnsTracePanel } from "./components/DnsTracePanel";
import { DomainHealthPanel } from "./components/DomainHealthPanel";
import { ExportMenu } from "./components/ExportMenu";
import { HistorySidebar } from "./components/HistorySidebar";
import { IpDeepScanPanel } from "./components/IpDeepScanPanel";
import { LiveMonitorPanel } from "./components/LiveMonitorPanel";
import { NetworkPanel } from "./components/NetworkPanel";
import { PortsPanel } from "./components/PortsPanel";
import { PropagationView } from "./components/PropagationView";
import { QueryBar, STANDARD_RECORD_TYPES } from "./components/QueryBar";
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
import { UtilitiesPanel } from "./components/UtilitiesPanel";
import { WatchlistPanel } from "./components/WatchlistPanel";
import { WebsitePanel } from "./components/WebsitePanel";
import { WhoisPanel } from "./components/WhoisPanel";
import {
  copyToClipboard,
  queryDomain,
  recheckSecurity,
  runBulkCheck,
} from "./lib/api";
import {
  buildOptionsKey,
  type CachedSubResults,
  type CacheTtlOption,
  clearDomainCache,
  computeReportDiff,
  formatRelativeAge,
  getCachedDomain,
  getCacheStats,
  getCacheTtlSetting,
  initDomainCache,
  isCacheFresh,
  listCachedDomains,
  type ReportChangeItem,
  saveCachedReport,
  saveCachedSubResult,
  setCacheTtlSetting,
  updateCachedSecurity,
} from "./lib/domainCache";
import { formatAsZoneFile } from "./lib/export";
import { type ThemePreference, useTheme } from "./lib/theme";
import {
  computeDrifts,
  driftKey,
  findNewDrifts,
  isEntryDueForCheck,
  loadWatchlist,
  loadWatchlistAlerts,
  loadWatchlistSettings,
  normalizeWatchDomain,
  playAlertChime,
  saveWatchlist,
  saveWatchlistAlerts,
  saveWatchlistSettings,
  sendDesktopNotification,
  snapshotFromBulk,
  snapshotFromReport,
  type WatchlistAlertEvent,
  type WatchlistEntry,
  type WatchlistSettings,
  type WatchlistSnapshot,
} from "./lib/watchlist";
import type {
  BulkDomainResult,
  DnsQueryReport,
  HistoryEntry,
  QueryProgressEvent,
  RecordTypeName,
  ResolverId,
} from "./types/dns";

type WorkspaceMode =
  | "inspector"
  | "ip-scan"
  | "watchlist"
  | "bulk"
  | "monitor"
  | "utilities";

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

const CACHE_TTL_OPTIONS: { id: CacheTtlOption; label: string }[] = [
  { id: "5m", label: "5m" },
  { id: "15m", label: "15m" },
  { id: "1h", label: "1h" },
  { id: "session", label: "Session" },
  { id: "off", label: "Off" },
];

function normalizeDomainForCache(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

function isValidIpv4Literal(candidate: string): boolean {
  const parts = candidate.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) return false;
    const n = Number(p);
    return n >= 0 && n <= 255;
  });
}

function isValidIpv6Literal(candidate: string): boolean {
  if (!candidate.includes(":")) return false;
  // Quick syntactic check + URL host parser validation for IPv6
  if (!/^[0-9a-fA-F:]+$/.test(candidate)) return false;
  try {
    new URL(`http://[${candidate}]/`);
    return true;
  } catch {
    return false;
  }
}

function extractLiteralIp(raw: string): string | null {
  let s = raw.trim();
  if (!s) return null;
  s = s.replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
  if (s.startsWith("[")) {
    const end = s.indexOf("]");
    if (end !== -1) {
      const inner = s.slice(1, end);
      if (isValidIpv6Literal(inner)) return inner;
    }
  }
  if (isValidIpv6Literal(s)) return s;
  const withoutPort = s.replace(/:\d+$/, "");
  if (isValidIpv4Literal(withoutPort)) return withoutPort;
  return null;
}

export function App() {
  const { preference, setPreference } = useTheme();
  const [workspace, setWorkspace] = useState<WorkspaceMode>("inspector");
  const [domain, setDomain] = useState("");
  const [recordTypes, setRecordTypes] =
    useState<RecordTypeName[]>(STANDARD_RECORD_TYPES);
  const [resolvers, setResolvers] = useState<ResolverId[]>([
    "cloudflare",
    "google",
    "quad9",
    "system",
  ]);
  const [customResolver, setCustomResolver] = useState("");
  const [dkimSelectorsInput, setDkimSelectorsInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [recheckingDkim, setRecheckingDkim] = useState(false);
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

  // Per-domain cache state
  const [cacheTtl, setCacheTtl] = useState<CacheTtlOption>(getCacheTtlSetting);
  const [cachedDomainsMap, setCachedDomainsMap] = useState<
    Record<string, { cachedAt: number; fresh: boolean }>
  >({});
  const [cacheCount, setCacheCount] = useState(0);
  const [isReportFromCache, setIsReportFromCache] = useState(false);
  const [reportCachedAt, setReportCachedAt] = useState<number | null>(null);
  const [activeSubResults, setActiveSubResults] = useState<CachedSubResults>({});
  const [reportChanges, setReportChanges] = useState<ReportChangeItem[]>([]);
  const [, setAgeTick] = useState(0);
  const [ipScanTarget, setIpScanTarget] = useState<string>("");
  const [ipScanNonce, setIpScanNonce] = useState(0);

  // Watchlist periodic monitoring & alerts
  const [watchlistSettings, setWatchlistSettings] = useState<WatchlistSettings>(
    loadWatchlistSettings,
  );
  const [watchlistAlerts, setWatchlistAlerts] = useState<WatchlistAlertEvent[]>(
    loadWatchlistAlerts,
  );
  const [watchlistChecking, setWatchlistChecking] = useState(false);
  const [watchlistCheckingDomains, setWatchlistCheckingDomains] = useState<
    string[]
  >([]);
  const [alertMenuOpen, setAlertMenuOpen] = useState(false);
  const [activeAlertBanner, setActiveAlertBanner] =
    useState<WatchlistAlertEvent | null>(null);

  const domainInputRef = useRef<HTMLInputElement>(null);
  const alertMenuRef = useRef<HTMLDivElement>(null);
  const watchlistRef = useRef<WatchlistEntry[]>(watchlist);
  const watchlistSettingsRef = useRef<WatchlistSettings>(watchlistSettings);
  const watchlistInFlightRef = useRef(false);

  useEffect(() => {
    watchlistRef.current = watchlist;
  }, [watchlist]);

  useEffect(() => {
    watchlistSettingsRef.current = watchlistSettings;
  }, [watchlistSettings]);

  const refreshCacheIndex = useCallback(() => {
    setCachedDomainsMap(listCachedDomains());
    setCacheCount(getCacheStats().count);
  }, []);

  useEffect(() => {
    let mounted = true;
    void initDomainCache().then(() => {
      if (mounted) {
        refreshCacheIndex();
      }
    });
    const timer = window.setInterval(() => {
      setAgeTick((t) => t + 1);
      refreshCacheIndex();
    }, 30000);
    return () => {
      mounted = false;
      window.clearInterval(timer);
    };
  }, [refreshCacheIndex]);

  const handleChangeCacheTtl = useCallback(
    (nextTtl: CacheTtlOption) => {
      setCacheTtl(nextTtl);
      setCacheTtlSetting(nextTtl);
      refreshCacheIndex();
    },
    [refreshCacheIndex],
  );

  const handleClearCache = useCallback(async () => {
    await clearDomainCache();
    refreshCacheIndex();
    setIsReportFromCache(false);
    setReportCachedAt(null);
    setToast("Cleared cached domain reports");
    setTimeout(() => {
      setToast((prev) => (prev === "Cleared cached domain reports" ? null : prev));
    }, 2400);
  }, [refreshCacheIndex]);

  const notify = useCallback((message: string) => {
    setToast(message);
    setTimeout(() => {
      setToast((prev) => (prev === message ? null : prev));
    }, 2400);
  }, []);

  const handleDeepScanIp = useCallback((ip: string) => {
    const clean = ip.trim();
    if (!clean) return;
    setIpScanTarget(clean);
    setIpScanNonce((n) => n + 1);
    setWorkspace("ip-scan");
  }, []);

  const updateWatchlist = useCallback((next: WatchlistEntry[]) => {
    watchlistRef.current = next;
    setWatchlist(next);
    saveWatchlist(next);
  }, []);

  const updateWatchlistSettings = useCallback((next: WatchlistSettings) => {
    watchlistSettingsRef.current = next;
    setWatchlistSettings(next);
    saveWatchlistSettings(next);
  }, []);

  const updateWatchlistAlerts = useCallback(
    (updater: (prev: WatchlistAlertEvent[]) => WatchlistAlertEvent[]) => {
      setWatchlistAlerts((prev) => {
        const next = updater(prev).slice(0, 100);
        saveWatchlistAlerts(next);
        return next;
      });
    },
    [],
  );

  const watchedDomainsSet = useMemo(
    () => new Set(watchlist.map((w) => w.domain.toLowerCase())),
    [watchlist],
  );

  const watchlistAlertsCount = useMemo(
    () => watchlist.reduce((acc, item) => acc + item.drifts.length, 0),
    [watchlist],
  );

  const unreadAlertsCount = useMemo(
    () => watchlistAlerts.filter((a) => !a.read).length,
    [watchlistAlerts],
  );

  useEffect(() => {
    document.title =
      unreadAlertsCount > 0
        ? `(${unreadAlertsCount}) Domain Tools`
        : "Domain Tools";
  }, [unreadAlertsCount]);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (
        alertMenuRef.current &&
        !alertMenuRef.current.contains(e.target as Node)
      ) {
        setAlertMenuOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const isCurrentWatched = useMemo(
    () => Boolean(report && watchlist.some((w) => w.domain === report.domain)),
    [report, watchlist],
  );

  const runWatchlistCheck = useCallback(
    async (targetDomains: string[], source: "auto" | "manual") => {
      const cleanTargets = Array.from(
        new Set(targetDomains.map(normalizeWatchDomain).filter(Boolean)),
      );
      if (cleanTargets.length === 0 || watchlistInFlightRef.current) return;

      watchlistInFlightRef.current = true;
      setWatchlistChecking(true);
      setWatchlistCheckingDomains(cleanTargets);

      try {
        const results = await runBulkCheck(cleanTargets);
        const byDomain = new Map(results.map((r) => [r.domain.toLowerCase(), r]));
        const nowIso = new Date().toISOString();
        const generatedEvents: WatchlistAlertEvent[] = [];
        let totalDrifts = 0;

        const updated = watchlistRef.current.map((entry) => {
          const res = byDomain.get(entry.domain.toLowerCase());
          if (!res) return entry;
          const snap = snapshotFromBulk(res);
          const baseline = entry.baseline ?? snap;
          const drifts = computeDrifts(baseline, snap);
          totalDrifts += drifts.length;

          const newDrifts = findNewDrifts(drifts, entry.lastNotifiedDriftKeys);
          if (newDrifts.length > 0) {
            generatedEvents.push({
              id: `${entry.domain}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
              domain: entry.domain,
              detectedAt: nowIso,
              read: false,
              source,
              drifts: newDrifts,
            });
          }

          return {
            ...entry,
            baseline,
            latest: snap,
            drifts,
            lastCheckedAt: nowIso,
            lastNotifiedDriftKeys: drifts.map(driftKey),
          };
        });

        updateWatchlist(updated);

        if (generatedEvents.length > 0) {
          updateWatchlistAlerts((prev) => [...generatedEvents, ...prev]);
          setActiveAlertBanner(generatedEvents[0]);

          const curSettings = watchlistSettingsRef.current;
          if (curSettings.soundAlerts) {
            playAlertChime();
          }

          const totalNewDrifts = generatedEvents.reduce(
            (acc, ev) => acc + ev.drifts.length,
            0,
          );
          const first = generatedEvents[0];
          const firstMsg = first.drifts[0]?.message ?? "Configuration drift";
          const summaryBody =
            generatedEvents.length === 1
              ? `${first.domain}: ${firstMsg}`
              : `${generatedEvents.length} watched domains changed (${totalNewDrifts} new alert(s))`;

          if (curSettings.desktopNotifications) {
            sendDesktopNotification(
              "Domain Tools Watchlist Alert",
              summaryBody,
              () => {
                setWorkspace("watchlist");
              },
            );
          }

          notify(`Watchlist alert: ${summaryBody}`);
        } else if (source === "manual") {
          if (totalDrifts > 0) {
            notify(
              `Checked ${results.length} domain(s) — ${totalDrifts} existing drift alert(s)`,
            );
          } else {
            notify(`Checked ${results.length} watched domain(s) — all clean`);
          }
        }
      } catch (err) {
        if (source === "manual") {
          notify(`Watchlist check failed: ${String(err)}`);
        }
      } finally {
        watchlistInFlightRef.current = false;
        setWatchlistChecking(false);
        setWatchlistCheckingDomains([]);
      }
    },
    [notify, updateWatchlist, updateWatchlistAlerts],
  );

  // Periodic background scheduler (15s tick checks due entries)
  useEffect(() => {
    const tick = () => {
      const cfg = watchlistSettingsRef.current;
      if (!cfg.autoCheckEnabled || watchlistInFlightRef.current) return;
      const nowMs = Date.now();
      const dueDomains = watchlistRef.current
        .filter((entry) => isEntryDueForCheck(entry, cfg, nowMs))
        .map((entry) => entry.domain);
      if (dueDomains.length > 0) {
        void runWatchlistCheck(dueDomains, "auto");
      }
    };

    const startupTimer = window.setTimeout(() => {
      if (watchlistSettingsRef.current.checkOnStartup) {
        tick();
      }
    }, 3000);

    const intervalId = window.setInterval(tick, 15000);
    return () => {
      window.clearTimeout(startupTimer);
      window.clearInterval(intervalId);
    };
  }, [runWatchlistCheck]);

  const addDomainsToWatchlist = useCallback(
    (
      rawDomains: string[],
      opts?: {
        initialSnapshots?: Map<string, WatchlistSnapshot>;
        autoCheckNew?: boolean;
      },
    ) => {
      const existing = new Set(
        watchlistRef.current.map((w) => w.domain.toLowerCase()),
      );
      const nowIso = new Date().toISOString();
      const addedEntries: WatchlistEntry[] = [];
      const needBaselineDomains: string[] = [];

      for (const raw of rawDomains) {
        const clean = normalizeWatchDomain(raw);
        if (!clean || !clean.includes(".") || existing.has(clean)) continue;
        existing.add(clean);
        const snap = opts?.initialSnapshots?.get(clean) ?? null;
        const drifts = snap ? computeDrifts(snap, snap) : [];
        addedEntries.push({
          domain: clean,
          addedAt: nowIso,
          baseline: snap,
          latest: snap,
          lastCheckedAt: snap ? nowIso : null,
          lastNotifiedDriftKeys: drifts.map(driftKey),
          drifts,
        });
        if (!snap) {
          needBaselineDomains.push(clean);
        }
      }

      if (addedEntries.length === 0) {
        notify("All selected domains are already in Watchlist");
        return;
      }

      updateWatchlist([...addedEntries, ...watchlistRef.current]);
      notify(
        addedEntries.length === 1
          ? `Added ${addedEntries[0].domain} to Watchlist`
          : `Added ${addedEntries.length} domains to Watchlist`,
      );

      if (opts?.autoCheckNew !== false && needBaselineDomains.length > 0) {
        void runWatchlistCheck(needBaselineDomains, "manual");
      }
    },
    [notify, runWatchlistCheck, updateWatchlist],
  );

  const toggleWatchDomain = useCallback(
    (rawDomain: string) => {
      const clean = normalizeWatchDomain(rawDomain);
      if (!clean) return;
      const exists = watchlistRef.current.some(
        (w) => w.domain.toLowerCase() === clean,
      );
      if (exists) {
        updateWatchlist(
          watchlistRef.current.filter((w) => w.domain.toLowerCase() !== clean),
        );
        notify(`Removed ${clean} from Watchlist`);
        return;
      }

      const snapshots = new Map<string, WatchlistSnapshot>();
      if (report && normalizeWatchDomain(report.domain) === clean) {
        snapshots.set(clean, snapshotFromReport(report));
      } else {
        const cached = getCachedDomain(clean);
        if (cached) {
          snapshots.set(clean, snapshotFromReport(cached.report));
        }
      }
      addDomainsToWatchlist([clean], { initialSnapshots: snapshots });
    },
    [addDomainsToWatchlist, notify, report, updateWatchlist],
  );

  const handleSaveBulkToWatchlist = useCallback(
    (items: BulkDomainResult[]) => {
      if (items.length === 0) return;
      const snapshots = new Map<string, WatchlistSnapshot>();
      const domains: string[] = [];
      for (const item of items) {
        const clean = normalizeWatchDomain(item.domain);
        if (!clean) continue;
        domains.push(clean);
        snapshots.set(clean, snapshotFromBulk(item));
      }
      addDomainsToWatchlist(domains, {
        initialSnapshots: snapshots,
        autoCheckNew: false,
      });
    },
    [addDomainsToWatchlist],
  );

  const toggleWatchCurrent = useCallback(() => {
    if (!report) return;
    toggleWatchDomain(report.domain);
  }, [report, toggleWatchDomain]);

  const markAlertRead = useCallback(
    (id: string) => {
      updateWatchlistAlerts((prev) =>
        prev.map((a) => (a.id === id ? { ...a, read: true } : a)),
      );
    },
    [updateWatchlistAlerts],
  );

  const markAllAlertsRead = useCallback(() => {
    updateWatchlistAlerts((prev) => prev.map((a) => ({ ...a, read: true })));
  }, [updateWatchlistAlerts]);

  const clearAlerts = useCallback(() => {
    updateWatchlistAlerts(() => []);
    setActiveAlertBanner(null);
  }, [updateWatchlistAlerts]);

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
    async (
      overrideDomain?: string,
      options?: {
        forceRefresh?: boolean;
        dkimSelectorsOverride?: string;
        fromNavigation?: boolean;
      },
    ) => {
      const targetDomain = (overrideDomain ?? domain).trim();
      if (!targetDomain) return;

      const literalIp = extractLiteralIp(targetDomain);
      if (literalIp) {
        handleDeepScanIp(literalIp);
        notify(`Detected IP ${literalIp} — opened in IP Deep Scan`);
        return;
      }

      const normalized = normalizeDomainForCache(targetDomain);
      const effectiveDkimInput =
        options?.dkimSelectorsOverride ?? dkimSelectorsInput;
      const dkimSelectors = effectiveDkimInput
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      const optionsKey = buildOptionsKey({
        record_types: recordTypes,
        resolvers,
        custom_resolver: customResolver.trim() || null,
        dkim_selectors: dkimSelectors,
      });

      const isSubmittingActiveDomain =
        !overrideDomain &&
        Boolean(report && normalizeDomainForCache(report.domain) === normalized);

      const shouldForceRefresh =
        Boolean(options?.forceRefresh) ||
        (isSubmittingActiveDomain && options?.forceRefresh !== false);

      const existingCached = normalized ? getCachedDomain(normalized) : null;

      if (
        !shouldForceRefresh &&
        cacheTtl !== "off" &&
        existingCached &&
        isCacheFresh(existingCached, cacheTtl) &&
        (Boolean(options?.fromNavigation) ||
          existingCached.optionsKey === optionsKey)
      ) {
        setError(null);
        setReport(existingCached.report);
        setDomain(existingCached.report.domain);
        setActiveSubResults(existingCached.subResults ?? {});
        setIsReportFromCache(true);
        setReportCachedAt(existingCached.cachedAt);
        setReportChanges([]);

        const firstOk =
          existingCached.report.resolvers.find((r) => r.status === "ok") ??
          existingCached.report.resolvers[0];
        if (firstOk) {
          setSelectedResolverId(firstOk.id);
        }
        refreshCacheIndex();
        notify(
          `Loaded ${existingCached.report.domain} from cache (${formatRelativeAge(existingCached.cachedAt)})`,
        );
        return;
      }

      const previousReport =
        existingCached?.report ??
        (report && normalizeDomainForCache(report.domain) === normalized
          ? report
          : null);

      setLoading(true);
      setQueryDomainLabel(targetDomain);
      setQueryStartedAt(Date.now());
      setProgressStages(INITIAL_PROGRESS_STAGES.map((s) => ({ ...s })));
      setError(null);

      try {
        const res = await queryDomain({
          domain: targetDomain,
          record_types: recordTypes,
          resolvers,
          custom_resolver: customResolver.trim() || null,
          dkim_selectors: dkimSelectors,
        });

        const savedEntry = await saveCachedReport(res, optionsKey);
        const changes = previousReport
          ? computeReportDiff(previousReport, res)
          : [];

        setReport(res);
        setDomain(res.domain);
        setActiveSubResults(savedEntry.subResults ?? {});
        setIsReportFromCache(false);
        setReportCachedAt(savedEntry.cachedAt);
        setReportChanges(changes);
        refreshCacheIndex();

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
        const inspectTarget = watchlistRef.current.find(
          (w) => w.domain.toLowerCase() === res.domain.toLowerCase(),
        );
        if (inspectTarget) {
          const snap = snapshotFromReport(res);
          const baseline = inspectTarget.baseline ?? snap;
          const drifts = computeDrifts(baseline, snap);
          const newDrifts = findNewDrifts(
            drifts,
            inspectTarget.lastNotifiedDriftKeys,
          );
          const nowIso = new Date().toISOString();
          const nextWatchlist = watchlistRef.current.map((w) =>
            w.domain.toLowerCase() === res.domain.toLowerCase()
              ? {
                  ...w,
                  baseline,
                  latest: snap,
                  drifts,
                  lastCheckedAt: nowIso,
                  lastNotifiedDriftKeys: drifts.map(driftKey),
                }
              : w,
          );
          updateWatchlist(nextWatchlist);

          if (newDrifts.length > 0) {
            const evt: WatchlistAlertEvent = {
              id: `${res.domain}-${Date.now()}`,
              domain: res.domain,
              detectedAt: nowIso,
              read: false,
              source: "inspect",
              drifts: newDrifts,
            };
            updateWatchlistAlerts((prev) => [evt, ...prev]);
            setActiveAlertBanner(evt);
            if (watchlistSettingsRef.current.soundAlerts) {
              playAlertChime();
            }
          }
        }
      } catch (err) {
        setError(String(err));
      } finally {
        setLoading(false);
        setQueryStartedAt(null);
      }
    },
    [
      cacheTtl,
      customResolver,
      dkimSelectorsInput,
      domain,
      notify,
      recordTypes,
      refreshCacheIndex,
      report,
      resolvers,
    ],
  );

  const handleRecheckDkim = useCallback(
    async (overrideDomain?: string, overrideSelectorsStr?: string) => {
      const target = (overrideDomain ?? report?.domain ?? "").trim();
      if (!target) return;

      const selectors = (overrideSelectorsStr ?? dkimSelectorsInput)
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      setRecheckingDkim(true);
      try {
        const updatedSecurity = await recheckSecurity(target, selectors);
        setReport((prev) =>
          prev &&
          normalizeDomainForCache(prev.domain) === normalizeDomainForCache(target)
            ? { ...prev, security: updatedSecurity }
            : prev,
        );
        await updateCachedSecurity(target, updatedSecurity);
        refreshCacheIndex();
        notify(
          selectors.length > 0
            ? `Rechecked DKIM (${selectors.join(", ")}) for ${target}`
            : `Rechecked email security for ${target}`,
        );
      } catch (err) {
        notify(`Security recheck failed: ${String(err)}`);
      } finally {
        setRecheckingDkim(false);
      }
    },
    [dkimSelectorsInput, notify, refreshCacheIndex, report?.domain],
  );

  const handleInspectFromUtility = useCallback(
    (d: string, opts?: { dkimSelectors?: string }) => {
      const normalized = normalizeDomainForCache(d);
      setWorkspace("inspector");
      setDomain(d);

      if (opts?.dkimSelectors) {
        setDkimSelectorsInput(opts.dkimSelectors);
        setActiveTab("security");

        const existingCached = normalized ? getCachedDomain(normalized) : null;
        if (
          report &&
          normalizeDomainForCache(report.domain) === normalized
        ) {
          void handleRecheckDkim(report.domain, opts.dkimSelectors);
          return;
        }
        if (existingCached && cacheTtl !== "off" && isCacheFresh(existingCached, cacheTtl)) {
          setError(null);
          setReport(existingCached.report);
          setDomain(existingCached.report.domain);
          setActiveSubResults(existingCached.subResults ?? {});
          setIsReportFromCache(true);
          setReportCachedAt(existingCached.cachedAt);
          setReportChanges([]);
          const firstOk =
            existingCached.report.resolvers.find((r) => r.status === "ok") ??
            existingCached.report.resolvers[0];
          if (firstOk) setSelectedResolverId(firstOk.id);
          void handleRecheckDkim(existingCached.report.domain, opts.dkimSelectors);
          return;
        }

        void runLookup(d, { dkimSelectorsOverride: opts.dkimSelectors });
        return;
      }

      setActiveTab("records");
      void runLookup(d, { fromNavigation: true });
    },
    [cacheTtl, handleRecheckDkim, report, runLookup],
  );

  const freshnessInfo = useMemo(() => {
    if (!report) return null;
    const entry = getCachedDomain(report.domain);
    const ts = reportCachedAt ?? entry?.cachedAt ?? Date.parse(report.queried_at);
    const ageLabel = Number.isFinite(ts) ? formatRelativeAge(ts) : "just now";
    const isStale =
      cacheTtl !== "off" && entry ? !isCacheFresh(entry, cacheTtl) : false;

    if (isStale) {
      return {
        label: `Stale · ${ageLabel}`,
        tone: "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300",
        kind: "stale" as const,
      };
    }
    if (isReportFromCache) {
      return {
        label: `Cached · ${ageLabel}`,
        tone: "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
        kind: "cached" as const,
      };
    }
    return {
      label: `Live · ${ageLabel}`,
      tone: "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300",
      kind: "live" as const,
    };
  }, [report, reportCachedAt, cacheTtl, isReportFromCache, cachedDomainsMap]);

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
        onSelectDomain={(d, opts) => {
          setWorkspace("inspector");
          setDomain(d);
          void runLookup(d, {
            forceRefresh: opts?.forceRefresh,
            fromNavigation: !opts?.forceRefresh,
          });
        }}
        onClearHistory={() => {
          setHistory([]);
          localStorage.removeItem(HISTORY_KEY);
        }}
        cachedDomains={cachedDomainsMap}
        cacheCount={cacheCount}
        onClearCache={() => void handleClearCache()}
        watchedDomains={watchedDomainsSet}
        onToggleWatchDomain={toggleWatchDomain}
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
                ["ip-scan", "IP Deep Scan", Radar],
                ["watchlist", "Watchlist", Bookmark],
                ["bulk", "Bulk Checker", ListChecks],
                ["monitor", "Live Monitor", Radio],
                ["utilities", "Utilities", Wrench],
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
            {/* Global Watchlist Alert Bell */}
            <div ref={alertMenuRef} className="relative">
              <button
                type="button"
                onClick={() => setAlertMenuOpen((v) => !v)}
                title={
                  watchlistSettings.autoCheckEnabled
                    ? `Watchlist alerts (auto-check every ${watchlistSettings.intervalMinutes}m)`
                    : "Watchlist alerts (auto-check paused)"
                }
                className="relative inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition hover:border-sky-500/50 hover:text-ink"
              >
                <Bell
                  className={`h-3.5 w-3.5 ${
                    unreadAlertsCount > 0
                      ? "text-rose-600 dark:text-rose-400"
                      : watchlistChecking
                        ? "animate-pulse text-sky-600 dark:text-sky-400"
                        : "text-ink-muted"
                  }`}
                />
                {unreadAlertsCount > 0 && (
                  <span className="rounded-full bg-rose-600 px-1.5 py-0.2 font-mono text-[10px] font-bold text-white dark:bg-rose-500">
                    {unreadAlertsCount}
                  </span>
                )}
                {watchlistSettings.autoCheckEnabled && unreadAlertsCount === 0 && (
                  <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
                )}
              </button>

              {alertMenuOpen && (
                <div className="absolute right-0 z-40 mt-2 w-80 overflow-hidden rounded-xl border border-line-strong bg-surface shadow-2xl shadow-slate-900/15 sm:w-96 dark:shadow-black/60">
                  <div className="flex items-center justify-between border-b border-line bg-surface-alt px-3.5 py-2.5">
                    <div>
                      <div className="text-xs font-semibold text-ink">
                        Watchlist Change Alerts
                      </div>
                      <div className="text-[10px] text-ink-muted">
                        {watchlistChecking
                          ? "Checking watched domains now..."
                          : watchlistSettings.autoCheckEnabled
                            ? `Auto-check active (${watchlistSettings.intervalMinutes}m)`
                            : "Auto-check paused"}
                      </div>
                    </div>
                    <div className="flex items-center gap-2 text-[11px]">
                      {unreadAlertsCount > 0 && (
                        <button
                          type="button"
                          onClick={markAllAlertsRead}
                          className="font-medium text-sky-600 hover:underline dark:text-sky-400"
                        >
                          Mark read
                        </button>
                      )}
                      {watchlistAlerts.length > 0 && (
                        <button
                          type="button"
                          onClick={clearAlerts}
                          className="text-ink-muted hover:text-rose-600 dark:hover:text-rose-300"
                        >
                          Clear
                        </button>
                      )}
                    </div>
                  </div>

                  <div className="max-h-80 overflow-y-auto divide-y divide-line">
                    {watchlistAlerts.length === 0 ? (
                      <div className="px-4 py-8 text-center text-xs text-ink-muted">
                        No watchlist change alerts yet.
                      </div>
                    ) : (
                      watchlistAlerts.slice(0, 15).map((evt) => (
                        <div
                          key={evt.id}
                          className={`p-3 text-xs ${
                            evt.read ? "" : "bg-amber-500/[0.07]"
                          }`}
                        >
                          <div className="flex items-center justify-between gap-2">
                            <button
                              type="button"
                              onClick={() => {
                                markAlertRead(evt.id);
                                setAlertMenuOpen(false);
                                setWorkspace("inspector");
                                setDomain(evt.domain);
                                setActiveTab("health");
                                void runLookup(evt.domain, { fromNavigation: true });
                              }}
                              className="font-mono font-semibold text-sky-700 hover:underline dark:text-sky-300"
                            >
                              {evt.domain}
                            </button>
                            <span className="text-[10px] text-ink-muted">
                              {formatRelativeAge(Date.parse(evt.detectedAt))}
                            </span>
                          </div>
                          <div className="mt-1 space-y-0.5 text-[11px] text-ink-secondary">
                            {evt.drifts.slice(0, 3).map((d, i) => (
                              <div key={i} className="truncate">
                                • <span className="font-medium">{d.field}:</span>{" "}
                                {d.message}
                              </div>
                            ))}
                            {evt.drifts.length > 3 && (
                              <div className="text-[10px] text-ink-muted">
                                +{evt.drifts.length - 3} more change(s)
                              </div>
                            )}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  <div className="border-t border-line bg-surface-alt px-3.5 py-2 text-right">
                    <button
                      type="button"
                      onClick={() => {
                        setAlertMenuOpen(false);
                        setWorkspace("watchlist");
                      }}
                      className="text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
                    >
                      Open Watchlist &amp; Settings →
                    </button>
                  </div>
                </div>
              )}
            </div>

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
            {activeAlertBanner && (
              <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-xs text-amber-950 dark:text-amber-100">
                <div className="flex items-start gap-2.5">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  <div>
                    <div className="font-semibold">
                      Watchlist change detected on{" "}
                      <span className="font-mono">{activeAlertBanner.domain}</span>
                    </div>
                    <div className="mt-0.5 text-[11px] opacity-90">
                      {activeAlertBanner.drifts
                        .slice(0, 2)
                        .map((d) => `[${d.field}] ${d.message}`)
                        .join(" · ")}
                      {activeAlertBanner.drifts.length > 2
                        ? ` (+${activeAlertBanner.drifts.length - 2} more)`
                        : ""}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => {
                      markAlertRead(activeAlertBanner.id);
                      const d = activeAlertBanner.domain;
                      setActiveAlertBanner(null);
                      setWorkspace("inspector");
                      setDomain(d);
                      setActiveTab("health");
                      void runLookup(d, { fromNavigation: true });
                    }}
                    className="rounded-md border border-amber-500/40 bg-surface px-2.5 py-1 text-[11px] font-medium text-ink hover:border-sky-500/50"
                  >
                    Inspect Domain
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      markAlertRead(activeAlertBanner.id);
                      setActiveAlertBanner(null);
                      setWorkspace("watchlist");
                    }}
                    className="rounded-md bg-amber-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-amber-500 dark:bg-amber-500 dark:text-slate-950"
                  >
                    View Watchlist
                  </button>
                  <button
                    type="button"
                    onClick={() => setActiveAlertBanner(null)}
                    className="rounded p-1 text-ink-muted hover:text-ink"
                    title="Dismiss alert"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
            )}

            {workspace === "ip-scan" && (
              <IpDeepScanPanel
                initialIp={ipScanTarget}
                autoRunNonce={ipScanNonce}
                cacheTtl={cacheTtl}
                onInspectDomain={(d) => handleInspectFromUtility(d)}
                onNotify={notify}
              />
            )}

            {workspace === "watchlist" && (
              <WatchlistPanel
                entries={watchlist}
                settings={watchlistSettings}
                alerts={watchlistAlerts}
                checking={watchlistChecking}
                checkingDomains={watchlistCheckingDomains}
                onUpdateEntries={updateWatchlist}
                onUpdateSettings={updateWatchlistSettings}
                onAddDomains={(domains) => addDomainsToWatchlist(domains)}
                onCheckDomains={(domains) =>
                  void runWatchlistCheck(domains, "manual")
                }
                onMarkAlertRead={markAlertRead}
                onMarkAllAlertsRead={markAllAlertsRead}
                onClearAlerts={clearAlerts}
                onInspectDomain={(d) => {
                  setWorkspace("inspector");
                  setDomain(d);
                  setActiveTab("health");
                  void runLookup(d, { fromNavigation: true });
                }}
                onNotify={notify}
              />
            )}

            {workspace === "bulk" && (
              <BulkCheckerPanel
                watchedDomains={watchedDomainsSet}
                onSaveBulkToWatchlist={handleSaveBulkToWatchlist}
                onInspectDomain={(d) => {
                  setWorkspace("inspector");
                  setDomain(d);
                  setActiveTab("records");
                  void runLookup(d, { fromNavigation: true });
                }}
                onNotify={notify}
              />
            )}

            {workspace === "monitor" && (
              <LiveMonitorPanel
                initialTarget={report?.domain || domain || "cloudflare.com"}
              />
            )}

            {workspace === "utilities" && (
              <UtilitiesPanel
                defaultDomain={report?.domain || domain}
                currentReport={report}
                onInspectDomain={handleInspectFromUtility}
                onDeepScanIp={handleDeepScanIp}
                onNotify={notify}
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
                  activeDomain={report?.domain}
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

                      <div className="flex flex-wrap items-center gap-2 font-mono text-xs text-ink-muted">
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

                        {freshnessInfo && (
                          <span
                            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-sans text-[11px] font-medium ${freshnessInfo.tone}`}
                            title={
                              freshnessInfo.kind === "cached"
                                ? "Loaded instantly from local domain cache"
                                : freshnessInfo.kind === "stale"
                                  ? "Cached result exceeds TTL — click Refresh for live data"
                                  : "Fresh live DNS lookup"
                            }
                          >
                            {freshnessInfo.kind === "cached" ? (
                              <Zap className="h-3 w-3" />
                            ) : (
                              <Clock className="h-3 w-3" />
                            )}
                            {freshnessInfo.label}
                          </span>
                        )}

                        <button
                          type="button"
                          disabled={loading}
                          onClick={() =>
                            void runLookup(report.domain, { forceRefresh: true })
                          }
                          title="Run fresh live lookup bypassing cache"
                          className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2 py-1 font-sans text-[11px] font-medium text-ink-secondary transition hover:border-sky-500/50 hover:text-sky-600 disabled:opacity-50 dark:hover:text-sky-300"
                        >
                          <RefreshCw
                            className={`h-3 w-3 ${loading ? "animate-spin" : ""}`}
                          />
                          Refresh
                        </button>

                        <label
                          className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-0.5 font-sans text-[11px] text-ink-muted"
                          title="Local result cache TTL"
                        >
                          <span>TTL</span>
                          <select
                            value={cacheTtl}
                            onChange={(e) =>
                              handleChangeCacheTtl(e.target.value as CacheTtlOption)
                            }
                            aria-label="Cache TTL"
                            className="bg-transparent font-mono text-[11px] font-medium text-ink focus:outline-none"
                          >
                            {CACHE_TTL_OPTIONS.map((opt) => (
                              <option key={opt.id} value={opt.id}>
                                {opt.label}
                              </option>
                            ))}
                          </select>
                        </label>

                        {cacheCount > 0 && (
                          <button
                            type="button"
                            onClick={() => void handleClearCache()}
                            title={`Clear cache (${cacheCount} cached)`}
                            className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-1.5 py-1 font-sans text-[11px] text-ink-muted transition hover:border-rose-500/40 hover:text-rose-600 dark:hover:text-rose-300"
                          >
                            <Trash2 className="h-3 w-3" />
                          </button>
                        )}
                      </div>
                    </div>

                    {reportChanges.length > 0 && (
                      <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3.5 text-xs">
                        <div className="flex items-center justify-between gap-2">
                          <div className="flex items-center gap-2 font-semibold text-amber-900 dark:text-amber-200">
                            <Sparkles className="h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                            <span>
                              Changes since previous query ({reportChanges.length})
                            </span>
                          </div>
                          <button
                            type="button"
                            onClick={() => setReportChanges([])}
                            title="Dismiss changes summary"
                            className="rounded p-1 text-amber-800/80 transition hover:bg-amber-500/15 hover:text-amber-950 dark:text-amber-300 dark:hover:text-amber-100"
                          >
                            <X className="h-3.5 w-3.5" />
                          </button>
                        </div>
                        <div className="mt-2.5 grid grid-cols-1 gap-1.5 md:grid-cols-2">
                          {reportChanges.map((chg, idx) => {
                            const sevTone =
                              chg.severity === "good"
                                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-800 dark:text-emerald-200"
                                : chg.severity === "warn"
                                  ? "border-rose-500/30 bg-rose-500/10 text-rose-800 dark:text-rose-200"
                                  : "border-sky-500/30 bg-sky-500/10 text-sky-800 dark:text-sky-200";
                            return (
                              <div
                                key={`${chg.category}-${chg.label}-${idx}`}
                                className="flex flex-wrap items-center gap-1.5 rounded-lg border border-line bg-surface/90 px-2.5 py-1.5 text-[11px]"
                              >
                                <span
                                  className={`rounded border px-1.5 py-0.2 font-mono text-[10px] font-semibold ${sevTone}`}
                                >
                                  {chg.category}
                                </span>
                                <span className="font-medium text-ink">
                                  {chg.label}:
                                </span>
                                <span className="truncate font-mono text-ink-muted line-through">
                                  {chg.before}
                                </span>
                                <ArrowRight className="h-3 w-3 shrink-0 text-ink-muted" />
                                <span className="truncate font-mono font-medium text-ink">
                                  {chg.after}
                                </span>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    )}

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
                      <DnsTracePanel
                        domain={report.domain}
                        initialTraces={activeSubResults.dnsTrace}
                        onTraceResult={(recordType, traceRes) => {
                          setActiveSubResults((prev) => ({
                            ...prev,
                            dnsTrace: {
                              ...(prev.dnsTrace ?? {}),
                              [recordType]: traceRes,
                            },
                          }));
                          void saveCachedSubResult(report.domain, "dnsTrace", {
                            [recordType]: traceRes,
                          });
                        }}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "security" && (
                      <SecurityPanel
                        domain={report.domain}
                        security={report.security}
                        dkimSelectorsInput={dkimSelectorsInput}
                        onDkimSelectorsInputChange={setDkimSelectorsInput}
                        onRecheckDkim={() => void handleRecheckDkim()}
                        loading={loading}
                        recheckingDkim={recheckingDkim}
                        initialSmtpReport={activeSubResults.smtpProbe}
                        onSmtpResult={(smtpRes) => {
                          setActiveSubResults((prev) => ({
                            ...prev,
                            smtpProbe: smtpRes,
                          }));
                          void saveCachedSubResult(
                            report.domain,
                            "smtpProbe",
                            smtpRes,
                          );
                        }}
                        onNotify={notify}
                      />
                    )}

                    {activeTab === "tls" &&
                      (report.tls ? (
                        <TlsPanel
                          tls={report.tls}
                          defaultHost={report.domain}
                          initialCtHistory={activeSubResults.ctHistory}
                          onCtHistoryResult={(ctRes) => {
                            setActiveSubResults((prev) => ({
                              ...prev,
                              ctHistory: ctRes,
                            }));
                            void saveCachedSubResult(
                              report.domain,
                              "ctHistory",
                              ctRes,
                            );
                          }}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>SSL / TLS data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                          initialTraceroutes={activeSubResults.traceroute}
                          onTracerouteResult={(target, trRes) => {
                            setActiveSubResults((prev) => ({
                              ...prev,
                              traceroute: {
                                ...(prev.traceroute ?? {}),
                                [target]: trRes,
                              },
                            }));
                            void saveCachedSubResult(report.domain, "traceroute", {
                              [target]: trRes,
                            });
                          }}
                          onDeepScanIp={handleDeepScanIp}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Network / ASN data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                            void runLookup(sub, { fromNavigation: true });
                          }}
                          onNotify={notify}
                        />
                      ) : (
                        <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
                          <p>Subdomain data is not in this cached result.</p>
                          <button
                            type="button"
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
                            className="mt-3 rounded-lg bg-sky-600 px-3 py-1.5 font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                          >
                            Re-run Lookup
                          </button>
                        </div>
                      ))}

                    {activeTab === "typosquat" && (
                      <TyposquatPanel
                        domain={report.domain}
                        initialReport={activeSubResults.typosquats}
                        onScanResult={(typoRes) => {
                          setActiveSubResults((prev) => ({
                            ...prev,
                            typosquats: typoRes,
                          }));
                          void saveCachedSubResult(
                            report.domain,
                            "typosquats",
                            typoRes,
                          );
                        }}
                        onInspectDomain={(d) => {
                          setDomain(d);
                          setActiveTab("records");
                          void runLookup(d, { fromNavigation: true });
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
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
                            onClick={() =>
                              void runLookup(report.domain, { forceRefresh: true })
                            }
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
