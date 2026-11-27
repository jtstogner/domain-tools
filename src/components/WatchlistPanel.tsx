import {
  AlertTriangle,
  ArrowUpRight,
  Bell,
  BellOff,
  Bookmark,
  CheckCircle2,
  Clock,
  Download,
  FileText,
  History,
  Pause,
  Play,
  Plus,
  RefreshCw,
  Trash2,
  Upload,
  Volume2,
  VolumeX,
} from "lucide-react";
import { type ChangeEvent, useMemo, useRef, useState } from "react";
import { saveExport } from "../lib/api";
import { formatRelativeAge } from "../lib/domainCache";
import {
  computeDrifts,
  formatCountdown,
  getEffectiveIntervalMinutes,
  getNextCheckTimestamp,
  normalizeWatchDomain,
  playAlertChime,
  WATCHLIST_INTERVAL_OPTIONS,
  type WatchlistAlertEvent,
  type WatchlistEntry,
  type WatchlistIntervalMinutes,
  type WatchlistSettings,
} from "../lib/watchlist";

interface WatchlistPanelProps {
  entries: WatchlistEntry[];
  settings: WatchlistSettings;
  alerts: WatchlistAlertEvent[];
  checking: boolean;
  checkingDomains: string[];
  onUpdateEntries: (next: WatchlistEntry[]) => void;
  onUpdateSettings: (next: WatchlistSettings) => void;
  onAddDomains: (domains: string[]) => void;
  onCheckDomains: (domains: string[]) => void;
  onMarkAlertRead: (id: string) => void;
  onMarkAllAlertsRead: () => void;
  onClearAlerts: () => void;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type WatchlistSubTab = "domains" | "alerts";

function parseDomainsInput(raw: string): string[] {
  const parts = raw
    .split(/[\n,;\s]+/)
    .map(normalizeWatchDomain)
    .filter((d) => d.length > 0 && d.includes("."));
  return Array.from(new Set(parts));
}

export function WatchlistPanel({
  entries,
  settings,
  alerts,
  checking,
  checkingDomains,
  onUpdateEntries,
  onUpdateSettings,
  onAddDomains,
  onCheckDomains,
  onMarkAlertRead,
  onMarkAllAlertsRead,
  onClearAlerts,
  onInspectDomain,
  onNotify,
}: WatchlistPanelProps) {
  const [subTab, setSubTab] = useState<WatchlistSubTab>("domains");
  const [newDomain, setNewDomain] = useState("");
  const [showBulkAdd, setShowBulkAdd] = useState(false);
  const [bulkText, setBulkText] = useState("");
  const [editingNoteDomain, setEditingNoteDomain] = useState<string | null>(null);
  const [noteDraft, setNoteDraft] = useState("");
  const [alertFilter, setAlertFilter] = useState<"all" | "unread">("all");
  const [notifPerm, setNotifPerm] = useState<string>(() => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      return "unavailable";
    }
    return window.Notification.permission;
  });

  const importRef = useRef<HTMLInputElement>(null);

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseDomainsInput(newDomain);
    if (parsed.length === 0) {
      onNotify("Enter a valid domain name (e.g. example.com)");
      return;
    }
    onAddDomains(parsed);
    setNewDomain("");
  };

  const handleBulkAdd = () => {
    const parsed = parseDomainsInput(bulkText);
    if (parsed.length === 0) {
      onNotify("Paste one or more valid domains");
      return;
    }
    onAddDomains(parsed);
    setBulkText("");
    setShowBulkAdd(false);
  };

  const handleAcceptBaseline = (domain: string) => {
    const updated = entries.map((e) => {
      if (e.domain !== domain || !e.latest) return e;
      return {
        ...e,
        baseline: e.latest,
        lastNotifiedDriftKeys: [],
        drifts: computeDrifts(e.latest, e.latest),
      };
    });
    onUpdateEntries(updated);
    onNotify(`Updated baseline for ${domain}`);
  };

  const handleTogglePause = (domain: string) => {
    const updated = entries.map((e) =>
      e.domain === domain ? { ...e, paused: !e.paused } : e,
    );
    onUpdateEntries(updated);
  };

  const handleEntryIntervalChange = (
    domain: string,
    rawVal: string,
  ) => {
    const intervalMinutes =
      rawVal === "global" ? null : Number.parseInt(rawVal, 10);
    const updated = entries.map((e) =>
      e.domain === domain ? { ...e, intervalMinutes } : e,
    );
    onUpdateEntries(updated);
  };

  const handleSaveNote = (domain: string) => {
    const trimmed = noteDraft.trim();
    const updated = entries.map((e) =>
      e.domain === domain ? { ...e, notes: trimmed || undefined } : e,
    );
    onUpdateEntries(updated);
    setEditingNoteDomain(null);
    onNotify(trimmed ? `Saved note for ${domain}` : `Cleared note for ${domain}`);
  };

  const handleRemove = (domain: string) => {
    onUpdateEntries(entries.filter((e) => e.domain !== domain));
    onNotify(`Removed ${domain} from Watchlist`);
  };

  const handleEnableAlerts = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      setNotifPerm("unavailable");
      onNotify("Desktop notifications are unavailable in this runtime");
      return;
    }
    const perm = await window.Notification.requestPermission();
    setNotifPerm(perm);
    if (perm === "granted") {
      onUpdateSettings({ ...settings, desktopNotifications: true });
      onNotify("Desktop drift alerts enabled");
    } else {
      onNotify(`Notification permission: ${perm}`);
    }
  };

  const handleExportWatchlist = async () => {
    const json = JSON.stringify(entries, null, 2);
    const saved = await saveExport("domain-watchlist.json", "json", json);
    if (saved) onNotify("Exported watchlist backup");
  };

  const handleImportJson = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    try {
      const text = await file.text();
      const parsed = JSON.parse(text);
      if (Array.isArray(parsed)) {
        const existingSet = new Set(entries.map((x) => x.domain));
        const incoming: WatchlistEntry[] = [];
        for (const item of parsed) {
          if (item && typeof item.domain === "string") {
            const d = normalizeWatchDomain(item.domain);
            if (d && !existingSet.has(d)) {
              existingSet.add(d);
              incoming.push({
                domain: d,
                addedAt: item.addedAt || new Date().toISOString(),
                notes: typeof item.notes === "string" ? item.notes : undefined,
                paused: Boolean(item.paused),
                intervalMinutes:
                  typeof item.intervalMinutes === "number"
                    ? item.intervalMinutes
                    : null,
                lastCheckedAt: item.lastCheckedAt ?? null,
                baseline: item.baseline ?? null,
                latest: item.latest ?? null,
                drifts: Array.isArray(item.drifts) ? item.drifts : [],
              });
            }
          }
        }
        if (incoming.length > 0) {
          onUpdateEntries([...incoming, ...entries]);
          onNotify(`Imported ${incoming.length} domain(s) into Watchlist`);
        } else {
          onNotify("No new domains found in JSON file");
        }
      }
    } catch {
      onNotify("Invalid watchlist JSON file");
    } finally {
      e.target.value = "";
    }
  };

  const totalAlerts = entries.reduce((acc, e) => acc + e.drifts.length, 0);
  const unreadAlertsCount = alerts.filter((a) => !a.read).length;

  const expiringDomains = entries.filter(
    (e) =>
      e.latest?.domainDaysRemaining !== null &&
      e.latest?.domainDaysRemaining !== undefined &&
      e.latest.domainDaysRemaining <= 30,
  ).length;
  const expiringSsl = entries.filter(
    (e) =>
      e.latest?.sslDaysRemaining !== null &&
      e.latest?.sslDaysRemaining !== undefined &&
      e.latest.sslDaysRemaining <= 14,
  ).length;

  const nextAutoCheckSummary = useMemo(() => {
    if (!settings.autoCheckEnabled) return "Auto-check paused globally";
    const activeEntries = entries.filter((e) => !e.paused);
    if (activeEntries.length === 0) return "No active domains scheduled";
    const nextTimes = activeEntries
      .map((e) => getNextCheckTimestamp(e, settings))
      .filter((t): t is number => t !== null);
    if (nextTimes.length === 0) return "Scheduled";
    const earliest = Math.min(...nextTimes);
    return `Next auto-check ${formatCountdown(earliest)}`;
  }, [entries, settings]);

  const filteredAlerts = useMemo(() => {
    if (alertFilter === "unread") {
      return alerts.filter((a) => !a.read);
    }
    return alerts;
  }, [alerts, alertFilter]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2.5">
          <Bookmark className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <div>
            <h2 className="text-sm font-semibold text-ink">
              Domain Watchlist &amp; Periodic Monitoring
            </h2>
            <p className="text-xs text-ink-muted">
              Saves domains locally, periodically checks DNS/SSL/WHOIS/HTTP for changes, and alerts you on drift.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            ref={importRef}
            type="file"
            accept=".json,application/json"
            onChange={(e) => void handleImportJson(e)}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => importRef.current?.click()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
          >
            <Upload className="h-3.5 w-3.5" />
            Import
          </button>
          <button
            type="button"
            disabled={entries.length === 0}
            onClick={() => void handleExportWatchlist()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink disabled:opacity-40"
          >
            <Download className="h-3.5 w-3.5" />
            Export
          </button>
          <button
            type="button"
            disabled={checking || entries.length === 0}
            onClick={() => onCheckDomains(entries.map((e) => e.domain))}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} />
            {checking
              ? `Checking (${checkingDomains.length})...`
              : "Check All Now"}
          </button>
        </div>
      </div>

      {/* Periodic Scheduler & Alert Preferences Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-3.5 text-xs">
        <div className="flex flex-wrap items-center gap-3">
          <label className="inline-flex cursor-pointer items-center gap-2 font-medium text-ink">
            <input
              type="checkbox"
              checked={settings.autoCheckEnabled}
              onChange={(e) =>
                onUpdateSettings({
                  ...settings,
                  autoCheckEnabled: e.target.checked,
                })
              }
              className="rounded border-line-strong"
            />
            <span>Periodic Auto-Check</span>
          </label>

          <select
            value={settings.intervalMinutes}
            disabled={!settings.autoCheckEnabled}
            onChange={(e) =>
              onUpdateSettings({
                ...settings,
                intervalMinutes: Number(e.target.value) as WatchlistIntervalMinutes,
              })
            }
            className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1 font-mono text-xs text-ink disabled:opacity-50"
          >
            {WATCHLIST_INTERVAL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>

          <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
            <input
              type="checkbox"
              checked={settings.checkOnStartup}
              onChange={(e) =>
                onUpdateSettings({
                  ...settings,
                  checkOnStartup: e.target.checked,
                })
              }
            />
            Check on startup
          </label>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span
            className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${
              checking
                ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                : settings.autoCheckEnabled
                  ? "border-emerald-500/35 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                  : "border-line bg-surface-alt text-ink-muted"
            }`}
          >
            <Clock className="h-3 w-3" />
            {checking ? "Running scheduled check..." : nextAutoCheckSummary}
          </span>

          <button
            type="button"
            onClick={() => {
              if (notifPerm !== "granted") {
                void handleEnableAlerts();
              } else {
                onUpdateSettings({
                  ...settings,
                  desktopNotifications: !settings.desktopNotifications,
                });
              }
            }}
            className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition ${
              notifPerm === "granted" && settings.desktopNotifications
                ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "border-line-strong bg-surface-alt text-ink-secondary hover:text-ink"
            }`}
          >
            {notifPerm === "granted" && settings.desktopNotifications ? (
              <Bell className="h-3 w-3" />
            ) : (
              <BellOff className="h-3 w-3" />
            )}
            {notifPerm === "granted"
              ? settings.desktopNotifications
                ? "Desktop Alerts: On"
                : "Desktop Alerts: Off"
              : notifPerm === "denied"
                ? "Notifications Blocked"
                : "Enable Desktop Alerts"}
          </button>

          <button
            type="button"
            onClick={() => {
              const nextSound = !settings.soundAlerts;
              onUpdateSettings({ ...settings, soundAlerts: nextSound });
              if (nextSound) playAlertChime();
            }}
            title="Toggle audible alert chime when changes are detected"
            className={`inline-flex items-center gap-1 rounded-lg border px-2.5 py-1 text-[11px] font-medium transition ${
              settings.soundAlerts
                ? "border-sky-500/40 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                : "border-line-strong bg-surface-alt text-ink-muted hover:text-ink"
            }`}
          >
            {settings.soundAlerts ? (
              <Volume2 className="h-3 w-3" />
            ) : (
              <VolumeX className="h-3 w-3" />
            )}
            Chime {settings.soundAlerts ? "On" : "Off"}
          </button>
        </div>
      </div>

      {/* Add Domain Form & Summary */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-5">
        <div className="space-y-2 rounded-xl border border-line bg-surface p-3 lg:col-span-2">
          <form onSubmit={handleAdd} className="flex items-center gap-2">
            <input
              type="text"
              value={newDomain}
              onChange={(e) => setNewDomain(e.target.value)}
              placeholder="Add domain(s) to watch (e.g. example.com)"
              className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
            <button
              type="submit"
              className="inline-flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
            >
              <Plus className="h-3.5 w-3.5" />
              Watch
            </button>
            <button
              type="button"
              onClick={() => setShowBulkAdd((v) => !v)}
              className="rounded-lg border border-line bg-surface-alt px-2 py-1.5 text-[11px] text-ink-secondary hover:text-ink"
            >
              Bulk
            </button>
          </form>

          {showBulkAdd && (
            <div className="space-y-2 border-t border-line pt-2">
              <textarea
                rows={3}
                value={bulkText}
                onChange={(e) => setBulkText(e.target.value)}
                placeholder="Paste multiple domains separated by newlines, commas, or spaces..."
                className="w-full rounded-lg border border-line-strong bg-canvas p-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
              />
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowBulkAdd(false)}
                  className="rounded-md px-2.5 py-1 text-[11px] text-ink-muted hover:text-ink"
                >
                  Cancel
                </button>
                <button
                  type="button"
                  onClick={handleBulkAdd}
                  className="rounded-md bg-sky-600 px-3 py-1 text-[11px] font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                >
                  Add All &amp; Capture Baseline
                </button>
              </div>
            </div>
          )}
        </div>

        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Watched Domains</div>
          <div className="mt-0.5 font-mono text-lg font-bold text-ink">
            {entries.length}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Active Drift Alerts</div>
          <div
            className={`mt-0.5 font-mono text-lg font-bold ${
              totalAlerts > 0
                ? "text-rose-700 dark:text-rose-300"
                : "text-emerald-700 dark:text-emerald-300"
            }`}
          >
            {totalAlerts}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Expiring (WHOIS / SSL)</div>
          <div className="mt-0.5 font-mono text-lg font-bold text-amber-700 dark:text-amber-300">
            {expiringDomains} / {expiringSsl}
          </div>
        </div>
      </div>

      {/* Sub-tab switcher */}
      <div className="flex items-center gap-1 border-b border-line pb-2">
        <button
          type="button"
          onClick={() => setSubTab("domains")}
          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
            subTab === "domains"
              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
          }`}
        >
          <Bookmark className="h-3.5 w-3.5" />
          Watched Domains ({entries.length})
        </button>
        <button
          type="button"
          onClick={() => setSubTab("alerts")}
          className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
            subTab === "alerts"
              ? "bg-sky-500/15 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
              : "text-ink-muted hover:bg-surface-alt hover:text-ink"
          }`}
        >
          <History className="h-3.5 w-3.5" />
          Alert History ({alerts.length})
          {unreadAlertsCount > 0 && (
            <span className="rounded-full bg-rose-500/20 px-1.5 py-0.2 font-mono text-[10px] font-bold text-rose-700 dark:text-rose-300">
              {unreadAlertsCount}
            </span>
          )}
        </button>
      </div>

      {/* Sub-Tab 1: Watched Domains */}
      {subTab === "domains" &&
        (entries.length === 0 ? (
          <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center text-xs text-ink-muted">
            No domains in your watchlist yet. Add a domain above or click{" "}
            <span className="font-semibold text-ink">Watch</span> while inspecting
            any domain, in Recent Lookups, or in Bulk Checker.
          </div>
        ) : (
          <div className="space-y-3">
            {entries.map((entry) => {
              const snap = entry.latest ?? entry.baseline;
              const hasDrifts = entry.drifts.length > 0;
              const isCheckingThis = checking && checkingDomains.includes(entry.domain);
              const nextCheckMs = getNextCheckTimestamp(entry, settings);
              const lastCheckedRaw = entry.lastCheckedAt ?? snap?.capturedAt ?? null;
              const lastCheckedTs = lastCheckedRaw ? Date.parse(lastCheckedRaw) : NaN;
              const effectiveInterval = getEffectiveIntervalMinutes(entry, settings);

              return (
                <div
                  key={entry.domain}
                  className={`rounded-xl border bg-surface p-4 ${
                    entry.paused
                      ? "border-line opacity-80"
                      : hasDrifts
                        ? "border-amber-500/40"
                        : "border-line"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      <button
                        type="button"
                        onClick={() => onInspectDomain(entry.domain)}
                        className="font-mono text-sm font-semibold text-sky-700 hover:underline dark:text-sky-300"
                      >
                        {entry.domain}
                      </button>

                      {entry.paused && (
                        <span className="rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[10px] font-semibold uppercase text-ink-muted">
                          Paused
                        </span>
                      )}

                      {hasDrifts ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
                          <AlertTriangle className="h-3 w-3" />
                          {entry.drifts.length} Alert{entry.drifts.length === 1 ? "" : "s"}
                        </span>
                      ) : snap ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          Matches Baseline
                        </span>
                      ) : (
                        <span className="rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-muted">
                          Capturing Baseline...
                        </span>
                      )}

                      {snap?.healthGrade && (
                        <span className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] font-semibold text-ink">
                          Grade {snap.healthGrade}
                        </span>
                      )}

                      {nextCheckMs !== null && (
                        <span className="font-mono text-[10px] text-ink-muted">
                          Next: {formatCountdown(nextCheckMs)}
                        </span>
                      )}
                    </div>

                    <div className="flex flex-wrap items-center gap-1.5">
                      <select
                        value={entry.intervalMinutes ?? "global"}
                        onChange={(e) =>
                          handleEntryIntervalChange(entry.domain, e.target.value)
                        }
                        title="Check frequency for this domain"
                        className="rounded-md border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink-secondary"
                      >
                        <option value="global">
                          Global ({settings.intervalMinutes}m)
                        </option>
                        {WATCHLIST_INTERVAL_OPTIONS.map((opt) => (
                          <option key={opt.value} value={opt.value}>
                            {opt.shortLabel}
                          </option>
                        ))}
                      </select>

                      <button
                        type="button"
                        onClick={() => handleTogglePause(entry.domain)}
                        title={
                          entry.paused
                            ? "Resume periodic checks"
                            : "Pause periodic checks for this domain"
                        }
                        className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2 py-1 text-[11px] text-ink-secondary hover:text-ink"
                      >
                        {entry.paused ? (
                          <>
                            <Play className="h-3 w-3 text-emerald-600 dark:text-emerald-400" />
                            Resume
                          </>
                        ) : (
                          <>
                            <Pause className="h-3 w-3" />
                            Pause
                          </>
                        )}
                      </button>

                      <button
                        type="button"
                        disabled={checking}
                        onClick={() => onCheckDomains([entry.domain])}
                        className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2.5 py-1 text-[11px] text-ink-secondary hover:text-ink disabled:opacity-40"
                      >
                        <RefreshCw
                          className={`h-3 w-3 ${isCheckingThis ? "animate-spin" : ""}`}
                        />
                        {isCheckingThis ? "Checking..." : "Check Now"}
                      </button>

                      {entry.latest && hasDrifts && (
                        <button
                          type="button"
                          onClick={() => handleAcceptBaseline(entry.domain)}
                          className="rounded-md border border-sky-500/40 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 hover:bg-sky-500/20 dark:text-sky-300"
                        >
                          Accept Baseline
                        </button>
                      )}

                      <button
                        type="button"
                        onClick={() => onInspectDomain(entry.domain)}
                        className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2.5 py-1 text-[11px] text-ink-secondary hover:text-ink"
                      >
                        Inspect
                        <ArrowUpRight className="h-3 w-3" />
                      </button>

                      <button
                        type="button"
                        onClick={() => handleRemove(entry.domain)}
                        title="Remove from watchlist"
                        className="rounded-md border border-line-strong bg-surface-alt p-1 text-ink-muted hover:text-rose-600 dark:hover:text-rose-300"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  </div>

                  {/* Inline Notes */}
                  <div className="mt-2 flex items-center gap-2 text-[11px]">
                    {editingNoteDomain === entry.domain ? (
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          handleSaveNote(entry.domain);
                        }}
                        className="flex flex-1 items-center gap-1.5"
                      >
                        <input
                          type="text"
                          value={noteDraft}
                          onChange={(e) => setNoteDraft(e.target.value)}
                          placeholder="Add note (e.g. Prod API, primary mail domain)..."
                          autoFocus
                          className="flex-1 rounded border border-line-strong bg-canvas px-2 py-0.5 text-[11px] text-ink focus:border-sky-500 focus:outline-none"
                        />
                        <button
                          type="submit"
                          className="rounded bg-sky-600 px-2 py-0.5 text-[11px] font-medium text-white dark:bg-sky-500 dark:text-slate-950"
                        >
                          Save
                        </button>
                        <button
                          type="button"
                          onClick={() => setEditingNoteDomain(null)}
                          className="px-1.5 py-0.5 text-[11px] text-ink-muted hover:text-ink"
                        >
                          Cancel
                        </button>
                      </form>
                    ) : (
                      <button
                        type="button"
                        onClick={() => {
                          setEditingNoteDomain(entry.domain);
                          setNoteDraft(entry.notes ?? "");
                        }}
                        className="inline-flex items-center gap-1 text-ink-muted hover:text-ink"
                      >
                        <FileText className="h-3 w-3" />
                        {entry.notes ? (
                          <span className="text-ink-secondary">{entry.notes}</span>
                        ) : (
                          <span className="italic">Add note...</span>
                        )}
                      </button>
                    )}
                    <span className="ml-auto font-mono text-[10px] text-ink-muted">
                      Interval: {effectiveInterval}m
                    </span>
                  </div>

                  {snap && (
                    <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-6">
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">A / AAAA</div>
                        <div className="truncate font-mono text-ink">
                          {snap.aRecords.length > 0 ? snap.aRecords.join(", ") : "—"}
                          {snap.aaaaRecords && snap.aaaaRecords.length > 0
                            ? ` (+${snap.aaaaRecords.length} v6)`
                            : ""}
                        </div>
                      </div>
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">NS / MX</div>
                        <div className="truncate font-mono text-ink">
                          {snap.nsCount} NS · {snap.mxCount} MX
                        </div>
                      </div>
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">HTTP</div>
                        <div className="font-mono text-ink">
                          {snap.httpStatus != null ? `HTTP ${snap.httpStatus}` : "—"}
                        </div>
                      </div>
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">SSL Expiry</div>
                        <div className="font-mono text-ink">
                          {snap.sslDaysRemaining !== null
                            ? `${snap.sslDaysRemaining}d`
                            : "N/A"}
                        </div>
                      </div>
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">WHOIS Expiry</div>
                        <div className="font-mono text-ink">
                          {snap.domainDaysRemaining !== null
                            ? `${snap.domainDaysRemaining}d`
                            : "N/A"}
                        </div>
                      </div>
                      <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                        <div className="text-ink-muted">Last Checked</div>
                        <div className="font-mono text-ink">
                          {Number.isFinite(lastCheckedTs)
                            ? formatRelativeAge(lastCheckedTs)
                            : "—"}
                        </div>
                      </div>
                    </div>
                  )}

                  {hasDrifts && (
                    <div className="mt-3 space-y-1 rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs">
                      {entry.drifts.map((d, idx) => (
                        <div
                          key={idx}
                          className={
                            d.severity === "critical"
                              ? "font-medium text-rose-800 dark:text-rose-200"
                              : "text-amber-900 dark:text-amber-200"
                          }
                        >
                          • <span className="font-semibold">[{d.field}]</span> {d.message}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        ))}

      {/* Sub-Tab 2: Alert History */}
      {subTab === "alerts" && (
        <div className="space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface p-3 text-xs">
            <div className="flex items-center gap-1.5">
              {(
                [
                  ["all", `All (${alerts.length})`],
                  ["unread", `Unread (${unreadAlertsCount})`],
                ] as const
              ).map(([id, label]) => (
                <button
                  key={id}
                  type="button"
                  onClick={() => setAlertFilter(id)}
                  className={`rounded-md px-2.5 py-1 font-medium transition ${
                    alertFilter === id
                      ? "bg-surface-alt text-ink ring-1 ring-line"
                      : "text-ink-muted hover:text-ink"
                  }`}
                >
                  {label}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-2">
              {unreadAlertsCount > 0 && (
                <button
                  type="button"
                  onClick={onMarkAllAlertsRead}
                  className="rounded-md border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
                >
                  Mark All Read
                </button>
              )}
              {alerts.length > 0 && (
                <button
                  type="button"
                  onClick={onClearAlerts}
                  className="rounded-md border border-line bg-surface-alt px-2.5 py-1 text-[11px] text-ink-muted hover:text-rose-600 dark:hover:text-rose-300"
                >
                  Clear History
                </button>
              )}
            </div>
          </div>

          {filteredAlerts.length === 0 ? (
            <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center text-xs text-ink-muted">
              No change alerts recorded yet. When a watched domain drifts from its baseline, alerts appear here.
            </div>
          ) : (
            <div className="space-y-2">
              {filteredAlerts.map((evt) => (
                <div
                  key={evt.id}
                  onClick={() => {
                    if (!evt.read) onMarkAlertRead(evt.id);
                  }}
                  className={`rounded-xl border p-3.5 text-xs transition ${
                    evt.read
                      ? "border-line bg-surface"
                      : "border-amber-500/40 bg-amber-500/[0.06]"
                  }`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className="flex flex-wrap items-center gap-2">
                      {!evt.read && (
                        <span className="h-2 w-2 rounded-full bg-rose-500" />
                      )}
                      <button
                        type="button"
                        onClick={() => {
                          onMarkAlertRead(evt.id);
                          onInspectDomain(evt.domain);
                        }}
                        className="font-mono text-sm font-semibold text-sky-700 hover:underline dark:text-sky-300"
                      >
                        {evt.domain}
                      </button>
                      <span className="rounded border border-line bg-surface-alt px-1.5 py-0.5 font-mono text-[10px] uppercase text-ink-muted">
                        {evt.source}
                      </span>
                      <span className="text-[11px] text-ink-muted">
                        {formatRelativeAge(Date.parse(evt.detectedAt))} ·{" "}
                        {new Date(evt.detectedAt).toLocaleString()}
                      </span>
                    </div>

                    <button
                      type="button"
                      onClick={() => {
                        onMarkAlertRead(evt.id);
                        onInspectDomain(evt.domain);
                      }}
                      className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2.5 py-1 text-[11px] text-ink-secondary hover:text-ink"
                    >
                      Inspect Domain
                      <ArrowUpRight className="h-3 w-3" />
                    </button>
                  </div>

                  <div className="mt-2 space-y-1">
                    {evt.drifts.map((d, i) => (
                      <div
                        key={i}
                        className={
                          d.severity === "critical"
                            ? "font-medium text-rose-700 dark:text-rose-300"
                            : "text-amber-800 dark:text-amber-200"
                        }
                      >
                        • <span className="font-semibold">[{d.field}]</span> {d.message}
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
