import {
  AlertTriangle,
  ArrowUpRight,
  Bell,
  Bookmark,
  CheckCircle2,
  Download,
  Loader2,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { runBulkCheck, saveExport } from "../lib/api";
import {
  computeDrifts,
  sendDesktopNotification,
  snapshotFromBulk,
  type WatchlistEntry,
} from "../lib/watchlist";

interface WatchlistPanelProps {
  entries: WatchlistEntry[];
  onChangeEntries: (next: WatchlistEntry[]) => void;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

export function WatchlistPanel({
  entries,
  onChangeEntries,
  onInspectDomain,
  onNotify,
}: WatchlistPanelProps) {
  const [newDomain, setNewDomain] = useState("");
  const [checking, setChecking] = useState(false);
  const [checkingDomain, setCheckingDomain] = useState<string | null>(null);
  const [notifPermission, setNotifPermission] = useState<string>(() =>
    typeof window !== "undefined" && "Notification" in window
      ? window.Notification.permission
      : "unsupported",
  );

  useEffect(() => {
    if (typeof window !== "undefined" && "Notification" in window) {
      setNotifPermission(window.Notification.permission);
    }
  }, []);

  const stats = useMemo(() => {
    let activeDrifts = 0;
    let expiringDomains = 0;
    let expiringSsl = 0;
    for (const e of entries) {
      if (e.drifts.length > 0) activeDrifts++;
      const dDays = e.latest?.domainDaysRemaining ?? e.baseline?.domainDaysRemaining;
      if (dDays !== null && dDays !== undefined && dDays <= 30) {
        expiringDomains++;
      }
      const sDays = e.latest?.sslDaysRemaining ?? e.baseline?.sslDaysRemaining;
      if (sDays !== null && sDays !== undefined && sDays <= 14) {
        expiringSsl++;
      }
    }
    return {
      total: entries.length,
      activeDrifts,
      expiringDomains,
      expiringSsl,
    };
  }, [entries]);

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = newDomain
      .trim()
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .replace(/\.+$/, "")
      .toLowerCase();
    if (!cleaned) return;
    if (entries.some((item) => item.domain === cleaned)) {
      onNotify(`${cleaned} is already in Watchlist`);
      setNewDomain("");
      return;
    }
    const created: WatchlistEntry = {
      domain: cleaned,
      addedAt: new Date().toISOString(),
      baseline: null,
      latest: null,
      drifts: [],
    };
    onChangeEntries([created, ...entries]);
    setNewDomain("");
    onNotify(`Added ${cleaned} to Watchlist`);
  };

  const handleCheckDomains = async (targets: string[]) => {
    if (targets.length === 0) return;
    setChecking(true);
    if (targets.length === 1) {
      setCheckingDomain(targets[0]);
    }
    try {
      const results = await runBulkCheck(targets);
      const resultMap = new Map(results.map((r) => [r.domain, r]));
      let totalAlerts = 0;

      const updated = entries.map((entry) => {
        const res = resultMap.get(entry.domain);
        if (!res) return entry;
        const snap = snapshotFromBulk(res);
        const baseline = entry.baseline ?? snap;
        const drifts = computeDrifts(baseline, snap);
        if (drifts.some((d) => d.severity === "critical" || d.severity === "warning")) {
          totalAlerts++;
        }
        return {
          ...entry,
          baseline,
          latest: snap,
          drifts,
        };
      });

      onChangeEntries(updated);
      if (totalAlerts > 0) {
        sendDesktopNotification(
          "Domain Tools Watchlist Alert",
          `${totalAlerts} watched domain(s) reported DNS/SSL/WHOIS drift or expiry warnings.`,
        );
        onNotify(`Checked ${targets.length} domain(s) — ${totalAlerts} alert(s) found`);
      } else {
        onNotify(`Checked ${targets.length} domain(s) — all clear`);
      }
    } catch (err) {
      onNotify(`Watchlist check failed: ${String(err)}`);
    } finally {
      setChecking(false);
      setCheckingDomain(null);
    }
  };

  const handleAcceptBaseline = (domain: string) => {
    onChangeEntries(
      entries.map((entry) => {
        if (entry.domain !== domain || !entry.latest) return entry;
        const drifts = computeDrifts(entry.latest, entry.latest);
        return { ...entry, baseline: entry.latest, drifts };
      }),
    );
    onNotify(`Updated baseline for ${domain}`);
  };

  const handleRemove = (domain: string) => {
    onChangeEntries(entries.filter((e) => e.domain !== domain));
    onNotify(`Removed ${domain} from Watchlist`);
  };

  const handleRequestNotifications = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      onNotify("Desktop notifications are not supported in this runtime");
      return;
    }
    const perm = await window.Notification.requestPermission();
    setNotifPermission(perm);
    if (perm === "granted") {
      sendDesktopNotification(
        "Domain Tools Alerts Enabled",
        "You will be notified when watched domains drift or near expiration.",
      );
    }
  };

  const handleExportWatchlist = async () => {
    try {
      const saved = await saveExport(
        "domain-tools-watchlist.json",
        "json",
        JSON.stringify(entries, null, 2),
      );
      if (saved) onNotify("Exported watchlist JSON");
    } catch (err) {
      onNotify(`Export failed: ${String(err)}`);
    }
  };

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div>
          <div className="flex items-center gap-2">
            <Bookmark className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <h2 className="text-sm font-semibold text-ink">
              Domain Watchlist &amp; Drift Monitor
            </h2>
          </div>
          <p className="mt-0.5 text-xs text-ink-muted">
            Track DNS, SSL, email security, and WHOIS expiry baselines across
            your domains and detect unexpected changes.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          {notifPermission !== "unsupported" && notifPermission !== "granted" && (
            <button
              type="button"
              onClick={() => void handleRequestNotifications()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
            >
              <Bell className="h-3.5 w-3.5 text-amber-500" />
              Enable Alerts
            </button>
          )}
          {entries.length > 0 && (
            <>
              <button
                type="button"
                onClick={() => void handleExportWatchlist()}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
              >
                <Download className="h-3.5 w-3.5" />
                Export JSON
              </button>
              <button
                type="button"
                disabled={checking}
                onClick={() =>
                  void handleCheckDomains(entries.map((e) => e.domain))
                }
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
              >
                {checking ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <RefreshCw className="h-3.5 w-3.5" />
                )}
                {checking ? "Checking All..." : "Check All Now"}
              </button>
            </>
          )}
        </div>
      </div>

      {/* Add domain form + summary cards */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-5">
        <form
          onSubmit={handleAdd}
          className="flex items-center gap-2 rounded-xl border border-line bg-surface p-3 lg:col-span-2"
        >
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="Add domain (e.g. example.com)"
            className="min-w-0 flex-1 rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
          />
          <button
            type="submit"
            disabled={!newDomain.trim()}
            className="inline-flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            <Plus className="h-3.5 w-3.5" />
            Watch
          </button>
        </form>

        <div className="grid grid-cols-3 gap-3 lg:col-span-3">
          <div className="rounded-xl border border-line bg-surface p-3">
            <div className="text-[11px] text-ink-muted">Watched</div>
            <div className="mt-0.5 font-mono text-lg font-bold text-ink">
              {stats.total}
            </div>
          </div>
          <div className="rounded-xl border border-line bg-surface p-3">
            <div className="text-[11px] text-ink-muted">Drifts / Alerts</div>
            <div
              className={`mt-0.5 font-mono text-lg font-bold ${
                stats.activeDrifts > 0
                  ? "text-amber-700 dark:text-amber-300"
                  : "text-emerald-700 dark:text-emerald-300"
              }`}
            >
              {stats.activeDrifts}
            </div>
          </div>
          <div className="rounded-xl border border-line bg-surface p-3">
            <div className="text-[11px] text-ink-muted">Expiring Soon</div>
            <div
              className={`mt-0.5 font-mono text-lg font-bold ${
                stats.expiringDomains + stats.expiringSsl > 0
                  ? "text-rose-700 dark:text-rose-300"
                  : "text-ink-secondary"
              }`}
            >
              {stats.expiringDomains}d / {stats.expiringSsl}ssl
            </div>
          </div>
        </div>
      </div>

      {entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-14 text-center text-xs text-ink-muted">
          No domains in your Watchlist yet. Add one above or click{" "}
          <span className="font-semibold text-ink">Watch</span> while inspecting
          any domain to save its baseline snapshot.
        </div>
      ) : (
        <div className="space-y-3">
          {entries.map((entry) => {
            const snap = entry.latest ?? entry.baseline;
            const hasCritical = entry.drifts.some(
              (d) => d.severity === "critical",
            );
            const hasWarning = entry.drifts.some(
              (d) => d.severity === "warning",
            );

            return (
              <div
                key={entry.domain}
                className="rounded-xl border border-line bg-surface p-4"
              >
                <div className="flex flex-wrap items-start justify-between gap-3">
                  <div>
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="font-mono text-sm font-semibold text-ink">
                        {entry.domain}
                      </span>
                      {entry.drifts.length === 0 && snap ? (
                        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          No Drift
                        </span>
                      ) : entry.drifts.length > 0 ? (
                        <span
                          className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${
                            hasCritical
                              ? "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                              : hasWarning
                                ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                : "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                          }`}
                        >
                          <AlertTriangle className="h-3 w-3" />
                          {entry.drifts.length} Alert
                          {entry.drifts.length === 1 ? "" : "s"}
                        </span>
                      ) : (
                        <span className="rounded-full border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-muted">
                          Pending Initial Check
                        </span>
                      )}
                      {snap?.healthGrade && (
                        <span className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] font-semibold text-ink-secondary">
                          Grade {snap.healthGrade} ({snap.healthScore}/100)
                        </span>
                      )}
                    </div>
                    <div className="mt-1 text-[11px] text-ink-muted">
                      {snap
                        ? `Last checked: ${new Date(snap.capturedAt).toLocaleString()}`
                        : `Added: ${new Date(entry.addedAt).toLocaleDateString()}`}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      disabled={checking}
                      onClick={() => void handleCheckDomains([entry.domain])}
                      className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink disabled:opacity-50"
                    >
                      {checkingDomain === entry.domain ? (
                        <Loader2 className="h-3 w-3 animate-spin" />
                      ) : (
                        <RefreshCw className="h-3 w-3" />
                      )}
                      Re-check
                    </button>
                    {entry.drifts.length > 0 && entry.latest && (
                      <button
                        type="button"
                        onClick={() => handleAcceptBaseline(entry.domain)}
                        className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 hover:bg-sky-500/20 dark:text-sky-300"
                      >
                        Accept Baseline
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => onInspectDomain(entry.domain)}
                      className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                    >
                      Inspect
                      <ArrowUpRight className="h-3 w-3" />
                    </button>
                    <button
                      type="button"
                      onClick={() => handleRemove(entry.domain)}
                      title="Remove from Watchlist"
                      className="rounded-lg p-1.5 text-ink-muted hover:bg-surface-alt hover:text-rose-600 dark:hover:text-rose-300"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>

                {snap && (
                  <div className="mt-3 grid grid-cols-2 gap-2 border-t border-line pt-3 text-[11px] sm:grid-cols-5">
                    <div>
                      <span className="text-ink-muted">A Records: </span>
                      <span className="font-mono text-ink-secondary">
                        {snap.aRecords.slice(0, 2).join(", ") || "None"}
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">NS / MX: </span>
                      <span className="font-mono text-ink-secondary">
                        {snap.nsCount} NS / {snap.mxCount} MX
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">SSL: </span>
                      <span className="font-mono text-ink-secondary">
                        {snap.sslDaysRemaining !== null
                          ? `${snap.sslDaysRemaining}d left`
                          : "N/A"}
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">WHOIS Expiry: </span>
                      <span className="font-mono text-ink-secondary">
                        {snap.domainDaysRemaining !== null
                          ? `${snap.domainDaysRemaining}d left`
                          : "N/A"}
                      </span>
                    </div>
                    <div>
                      <span className="text-ink-muted">Email/DNSSEC: </span>
                      <span className="font-mono text-ink-secondary">
                        {snap.spfStatus}/{snap.dmarcStatus}/{snap.dnssecStatus}
                      </span>
                    </div>
                  </div>
                )}

                {entry.drifts.length > 0 && (
                  <div className="mt-3 space-y-1 rounded-lg border border-amber-500/30 bg-amber-500/5 p-2.5 text-[11px]">
                    {entry.drifts.map((d, idx) => (
                      <div key={idx} className="flex items-start gap-2">
                        <span
                          className={`mt-0.5 rounded px-1.5 py-0.2 text-[10px] font-bold uppercase ${
                            d.severity === "critical"
                              ? "bg-rose-500/20 text-rose-700 dark:text-rose-300"
                              : d.severity === "warning"
                                ? "bg-amber-500/20 text-amber-700 dark:text-amber-300"
                                : "bg-sky-500/20 text-sky-700 dark:text-sky-300"
                          }`}
                        >
                          {d.field}
                        </span>
                        <span className="text-ink-secondary">{d.message}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
