import {
  AlertTriangle,
  ArrowUpRight,
  Bell,
  Bookmark,
  CheckCircle2,
  Download,
  Plus,
  RefreshCw,
  Trash2,
} from "lucide-react";
import { useState } from "react";
import { runBulkCheck, saveExport } from "../lib/api";
import {
  computeDrifts,
  sendDesktopNotification,
  snapshotFromBulk,
  type WatchlistEntry,
} from "../lib/watchlist";

interface WatchlistPanelProps {
  entries: WatchlistEntry[];
  onUpdateEntries: (next: WatchlistEntry[]) => void;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

export function WatchlistPanel({
  entries,
  onUpdateEntries,
  onInspectDomain,
  onNotify,
}: WatchlistPanelProps) {
  const [newDomain, setNewDomain] = useState("");
  const [checking, setChecking] = useState(false);

  const handleAdd = (e: React.FormEvent) => {
    e.preventDefault();
    const cleaned = newDomain
      .trim()
      .replace(/^https?:\/\//i, "")
      .split("/")[0]
      .toLowerCase();
    if (!cleaned) return;
    if (entries.some((item) => item.domain === cleaned)) {
      onNotify(`${cleaned} is already in Watchlist`);
      return;
    }
    const next: WatchlistEntry = {
      domain: cleaned,
      addedAt: new Date().toISOString(),
      baseline: null,
      latest: null,
      drifts: [],
    };
    onUpdateEntries([next, ...entries]);
    setNewDomain("");
    onNotify(`Added ${cleaned} to Watchlist`);
  };

  const handleCheckDomains = async (targetDomains: string[]) => {
    if (targetDomains.length === 0) return;
    setChecking(true);
    try {
      const results = await runBulkCheck(targetDomains);
      const byDomain = new Map(results.map((r) => [r.domain, r]));
      let totalDrifts = 0;

      const updated = entries.map((entry) => {
        const res = byDomain.get(entry.domain);
        if (!res) return entry;
        const snap = snapshotFromBulk(res);
        const baseline = entry.baseline ?? snap;
        const drifts = computeDrifts(baseline, snap);
        totalDrifts += drifts.length;
        return {
          ...entry,
          baseline,
          latest: snap,
          drifts,
        };
      });

      onUpdateEntries(updated);
      if (totalDrifts > 0) {
        sendDesktopNotification(
          "Domain Tools Watchlist Alert",
          `${totalDrifts} drift or expiry alert(s) detected across your watched domains.`,
        );
        onNotify(`Check complete: ${totalDrifts} alert(s) detected`);
      } else {
        onNotify(`Checked ${results.length} watched domain(s) — all clean`);
      }
    } catch (err) {
      onNotify(`Watchlist check failed: ${String(err)}`);
    } finally {
      setChecking(false);
    }
  };

  const handleAcceptBaseline = (domain: string) => {
    const updated = entries.map((e) => {
      if (e.domain !== domain || !e.latest) return e;
      return {
        ...e,
        baseline: e.latest,
        drifts: computeDrifts(e.latest, e.latest),
      };
    });
    onUpdateEntries(updated);
    onNotify(`Updated baseline for ${domain}`);
  };

  const handleRemove = (domain: string) => {
    onUpdateEntries(entries.filter((e) => e.domain !== domain));
    onNotify(`Removed ${domain} from Watchlist`);
  };

  const handleEnableAlerts = async () => {
    if (typeof window === "undefined" || !("Notification" in window)) {
      onNotify("Desktop notifications are unavailable in this runtime");
      return;
    }
    const perm = await window.Notification.requestPermission();
    onNotify(
      perm === "granted"
        ? "Desktop drift alerts enabled"
        : `Notification permission: ${perm}`,
    );
  };

  const handleExportWatchlist = async () => {
    const json = JSON.stringify(entries, null, 2);
    const saved = await saveExport("domain-watchlist.json", "json", json);
    if (saved) onNotify("Exported watchlist backup");
  };

  const totalAlerts = entries.reduce((acc, e) => acc + e.drifts.length, 0);
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

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2.5">
          <Bookmark className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <div>
            <h2 className="text-sm font-semibold text-ink">
              Domain Watchlist &amp; Drift Alerts
            </h2>
            <p className="text-xs text-ink-muted">
              Tracks DNS, SSL, WHOIS expiry, and email security baselines locally and alerts on unexpected drift.
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => void handleEnableAlerts()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink"
          >
            <Bell className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
            Desktop Alerts
          </button>
          <button
            type="button"
            disabled={entries.length === 0}
            onClick={() => void handleExportWatchlist()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:text-ink disabled:opacity-40"
          >
            <Download className="h-3.5 w-3.5" />
            Export JSON
          </button>
          <button
            type="button"
            disabled={checking || entries.length === 0}
            onClick={() => void handleCheckDomains(entries.map((e) => e.domain))}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${checking ? "animate-spin" : ""}`} />
            {checking ? "Checking..." : "Check All Now"}
          </button>
        </div>
      </div>

      {/* Add Domain Form & Summary */}
      <div className="grid grid-cols-1 gap-3 lg:grid-cols-5">
        <form
          onSubmit={handleAdd}
          className="flex items-center gap-2 rounded-xl border border-line bg-surface p-3 lg:col-span-2"
        >
          <input
            type="text"
            value={newDomain}
            onChange={(e) => setNewDomain(e.target.value)}
            placeholder="Add domain to watch (e.g. example.com)"
            className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
          />
          <button
            type="submit"
            className="inline-flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
          >
            <Plus className="h-3.5 w-3.5" />
            Watch
          </button>
        </form>

        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Watched Domains</div>
          <div className="mt-0.5 font-mono text-lg font-bold text-ink">
            {entries.length}
          </div>
        </div>
        <div className="rounded-xl border border-line bg-surface p-3">
          <div className="text-[11px] text-ink-muted">Active Alerts</div>
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

      {/* Watchlist Items */}
      {entries.length === 0 ? (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center text-xs text-ink-muted">
          No domains in your watchlist yet. Add a domain above or click <span className="font-semibold text-ink">Watch</span> while inspecting any domain.
        </div>
      ) : (
        <div className="space-y-3">
          {entries.map((entry) => {
            const snap = entry.latest ?? entry.baseline;
            const hasDrifts = entry.drifts.length > 0;
            return (
              <div
                key={entry.domain}
                className={`rounded-xl border bg-surface p-4 ${
                  hasDrifts ? "border-amber-500/40" : "border-line"
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
                        Not Checked Yet
                      </span>
                    )}
                    {snap?.healthGrade && (
                      <span className="rounded border border-line bg-canvas px-1.5 py-0.5 font-mono text-[11px] font-semibold text-ink">
                        Grade {snap.healthGrade}
                      </span>
                    )}
                  </div>

                  <div className="flex flex-wrap items-center gap-1.5">
                    <button
                      type="button"
                      disabled={checking}
                      onClick={() => void handleCheckDomains([entry.domain])}
                      className="inline-flex items-center gap-1 rounded-md border border-line-strong bg-surface-alt px-2.5 py-1 text-[11px] text-ink-secondary hover:text-ink disabled:opacity-40"
                    >
                      <RefreshCw className="h-3 w-3" />
                      Re-check
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

                {snap && (
                  <div className="mt-3 grid grid-cols-2 gap-2 text-[11px] sm:grid-cols-5">
                    <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                      <div className="text-ink-muted">A Records</div>
                      <div className="truncate font-mono text-ink">
                        {snap.aRecords.length > 0 ? snap.aRecords.join(", ") : "—"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                      <div className="text-ink-muted">SSL Expiry</div>
                      <div className="font-mono text-ink">
                        {snap.sslDaysRemaining !== null ? `${snap.sslDaysRemaining}d` : "N/A"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                      <div className="text-ink-muted">WHOIS Expiry</div>
                      <div className="font-mono text-ink">
                        {snap.domainDaysRemaining !== null ? `${snap.domainDaysRemaining}d` : "N/A"}
                      </div>
                    </div>
                    <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                      <div className="text-ink-muted">SPF / DMARC</div>
                      <div className="font-mono text-ink">
                        {snap.spfStatus} / {snap.dmarcStatus}
                      </div>
                    </div>
                    <div className="rounded-lg border border-line bg-canvas px-2.5 py-1.5">
                      <div className="text-ink-muted">Last Checked</div>
                      <div className="font-mono text-ink">
                        {new Date(snap.capturedAt).toLocaleDateString()}
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
      )}
    </div>
  );
}
