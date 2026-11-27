import type { BulkDomainResult, DnsQueryReport } from "../types/dns";

export interface WatchlistSnapshot {
  capturedAt: string;
  aRecords: string[];
  aaaaRecords?: string[];
  mxRecords?: string[];
  nsRecords?: string[];
  nsCount: number;
  mxCount: number;
  sslValid: boolean | null;
  sslDaysRemaining: number | null;
  sslIssuer: string | null;
  spfStatus: string;
  spfRecord?: string | null;
  dmarcStatus: string;
  dmarcRecord?: string | null;
  dnssecStatus: string;
  domainDaysRemaining: number | null;
  registrar: string | null;
  httpStatus?: number | null;
  finalUrl?: string | null;
  healthGrade?: string;
  healthScore?: number;
}

export interface WatchlistDrift {
  field: string;
  severity: "critical" | "warning" | "info";
  message: string;
}

export interface WatchlistEntry {
  domain: string;
  addedAt: string;
  notes?: string;
  paused?: boolean;
  intervalMinutes?: number | null;
  lastCheckedAt?: string | null;
  lastNotifiedDriftKeys?: string[];
  baseline: WatchlistSnapshot | null;
  latest: WatchlistSnapshot | null;
  drifts: WatchlistDrift[];
}

export type WatchlistIntervalMinutes = 1 | 5 | 15 | 30 | 60 | 360 | 1440;

export interface WatchlistSettings {
  autoCheckEnabled: boolean;
  intervalMinutes: WatchlistIntervalMinutes;
  desktopNotifications: boolean;
  soundAlerts: boolean;
  checkOnStartup: boolean;
}

export interface WatchlistAlertEvent {
  id: string;
  domain: string;
  detectedAt: string;
  read: boolean;
  source: "auto" | "manual" | "inspect";
  drifts: WatchlistDrift[];
}

export const WATCHLIST_INTERVAL_OPTIONS: {
  value: WatchlistIntervalMinutes;
  label: string;
  shortLabel: string;
}[] = [
  { value: 1, label: "Every 1 minute", shortLabel: "1m" },
  { value: 5, label: "Every 5 minutes", shortLabel: "5m" },
  { value: 15, label: "Every 15 minutes", shortLabel: "15m" },
  { value: 30, label: "Every 30 minutes", shortLabel: "30m" },
  { value: 60, label: "Every 1 hour", shortLabel: "1h" },
  { value: 360, label: "Every 6 hours", shortLabel: "6h" },
  { value: 1440, label: "Every 24 hours", shortLabel: "24h" },
];

const WATCHLIST_KEY = "domain_tools_watchlist_v1";
const WATCHLIST_SETTINGS_KEY = "domain_tools_watchlist_settings_v1";
const WATCHLIST_ALERTS_KEY = "domain_tools_watchlist_alerts_v1";
const MAX_ALERT_EVENTS = 100;

const DEFAULT_WATCHLIST_SETTINGS: WatchlistSettings = {
  autoCheckEnabled: true,
  intervalMinutes: 15,
  desktopNotifications: true,
  soundAlerts: true,
  checkOnStartup: true,
};

export function normalizeWatchDomain(raw: string): string {
  return raw
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

export function loadWatchlist(): WatchlistEntry[] {
  try {
    const raw = localStorage.getItem(WATCHLIST_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as WatchlistEntry[]) : [];
  } catch {
    return [];
  }
}

export function saveWatchlist(entries: WatchlistEntry[]): void {
  try {
    localStorage.setItem(WATCHLIST_KEY, JSON.stringify(entries));
  } catch {
    // Ignore storage quota errors
  }
}

export function loadWatchlistSettings(): WatchlistSettings {
  try {
    const raw = localStorage.getItem(WATCHLIST_SETTINGS_KEY);
    if (!raw) return { ...DEFAULT_WATCHLIST_SETTINGS };
    const parsed = JSON.parse(raw) as Partial<WatchlistSettings>;
    const validIntervals = new Set([1, 5, 15, 30, 60, 360, 1440]);
    const interval =
      parsed.intervalMinutes && validIntervals.has(parsed.intervalMinutes)
        ? parsed.intervalMinutes
        : DEFAULT_WATCHLIST_SETTINGS.intervalMinutes;
    return {
      autoCheckEnabled:
        typeof parsed.autoCheckEnabled === "boolean"
          ? parsed.autoCheckEnabled
          : DEFAULT_WATCHLIST_SETTINGS.autoCheckEnabled,
      intervalMinutes: interval,
      desktopNotifications:
        typeof parsed.desktopNotifications === "boolean"
          ? parsed.desktopNotifications
          : DEFAULT_WATCHLIST_SETTINGS.desktopNotifications,
      soundAlerts:
        typeof parsed.soundAlerts === "boolean"
          ? parsed.soundAlerts
          : DEFAULT_WATCHLIST_SETTINGS.soundAlerts,
      checkOnStartup:
        typeof parsed.checkOnStartup === "boolean"
          ? parsed.checkOnStartup
          : DEFAULT_WATCHLIST_SETTINGS.checkOnStartup,
    };
  } catch {
    return { ...DEFAULT_WATCHLIST_SETTINGS };
  }
}

export function saveWatchlistSettings(settings: WatchlistSettings): void {
  try {
    localStorage.setItem(WATCHLIST_SETTINGS_KEY, JSON.stringify(settings));
  } catch {
    // Ignore storage quota errors
  }
}

export function loadWatchlistAlerts(): WatchlistAlertEvent[] {
  try {
    const raw = localStorage.getItem(WATCHLIST_ALERTS_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as WatchlistAlertEvent[]) : [];
  } catch {
    return [];
  }
}

export function saveWatchlistAlerts(alerts: WatchlistAlertEvent[]): void {
  try {
    localStorage.setItem(
      WATCHLIST_ALERTS_KEY,
      JSON.stringify(alerts.slice(0, MAX_ALERT_EVENTS)),
    );
  } catch {
    // Ignore storage quota errors
  }
}

export function snapshotFromReport(report: DnsQueryReport): WatchlistSnapshot {
  const firstOk =
    report.resolvers.find((r) => r.status === "ok") ?? report.resolvers[0];
  const aRecords = Array.from(
    new Set(
      firstOk?.results
        .find((r) => r.record_type === "A")
        ?.records.map((r) => r.value.trim()) ?? [],
    ),
  ).sort();
  const aaaaRecords = Array.from(
    new Set(
      firstOk?.results
        .find((r) => r.record_type === "AAAA")
        ?.records.map((r) => r.value.trim()) ?? [],
    ),
  ).sort();
  const nsRecords = Array.from(
    new Set(
      firstOk?.results
        .find((r) => r.record_type === "NS")
        ?.records.map((r) => r.value.trim().replace(/\.$/, "").toLowerCase()) ?? [],
    ),
  ).sort();
  const mxRecords = Array.from(
    new Set(
      firstOk?.results
        .find((r) => r.record_type === "MX")
        ?.records.map((r) => r.value.trim().replace(/\.$/, "").toLowerCase()) ?? [],
    ),
  ).sort();

  return {
    capturedAt: report.queried_at,
    aRecords,
    aaaaRecords,
    nsRecords,
    mxRecords,
    nsCount: nsRecords.length,
    mxCount: mxRecords.length,
    sslValid: report.tls ? report.tls.chain_valid && report.tls.hostname_match : null,
    sslDaysRemaining: report.tls?.days_remaining ?? null,
    sslIssuer: report.tls?.certificates?.[0]?.issuer_org ?? null,
    spfStatus: report.security.spf.status,
    spfRecord: report.security.spf.raw_record ?? null,
    dmarcStatus: report.security.dmarc.status,
    dmarcRecord: report.security.dmarc.raw_record ?? null,
    dnssecStatus: report.security.dnssec.status,
    domainDaysRemaining: report.whois?.days_until_expiry ?? null,
    registrar: report.whois?.registrar ?? null,
    httpStatus: report.website?.http_status ?? null,
    finalUrl: report.website?.final_url ?? report.redirects?.canonical_url ?? null,
    healthGrade: report.health?.grade,
    healthScore: report.health?.score,
  };
}

export function snapshotFromBulk(res: BulkDomainResult): WatchlistSnapshot {
  return {
    capturedAt: new Date().toISOString(),
    aRecords: Array.from(new Set(res.a_records)).sort(),
    aaaaRecords: res.aaaa_records ? Array.from(new Set(res.aaaa_records)).sort() : undefined,
    mxRecords: res.mx_records ? Array.from(new Set(res.mx_records)).sort() : undefined,
    nsRecords: res.ns_records ? Array.from(new Set(res.ns_records)).sort() : undefined,
    nsCount: res.ns_count,
    mxCount: res.mx_count,
    sslValid: res.ssl_valid,
    sslDaysRemaining: res.ssl_days_remaining,
    sslIssuer: res.ssl_issuer,
    spfStatus: res.spf_status,
    spfRecord: res.spf_record ?? null,
    dmarcStatus: res.dmarc_status,
    dmarcRecord: res.dmarc_record ?? null,
    dnssecStatus: res.dnssec_status,
    domainDaysRemaining: res.domain_days_remaining,
    registrar: res.registrar,
    httpStatus: res.http_status,
    finalUrl: res.final_url,
  };
}

export function computeDrifts(
  baseline: WatchlistSnapshot | null,
  next: WatchlistSnapshot,
): WatchlistDrift[] {
  const drifts: WatchlistDrift[] = [];

  if (next.domainDaysRemaining !== null) {
    if (next.domainDaysRemaining < 0) {
      drifts.push({
        field: "WHOIS Expiry",
        severity: "critical",
        message: `Domain expired ${Math.abs(next.domainDaysRemaining)} day(s) ago`,
      });
    } else if (next.domainDaysRemaining <= 30) {
      drifts.push({
        field: "WHOIS Expiry",
        severity: "warning",
        message: `Domain expires in ${next.domainDaysRemaining} day(s)`,
      });
    }
  }

  if (next.sslDaysRemaining !== null) {
    if (next.sslDaysRemaining < 0) {
      drifts.push({
        field: "SSL Expiry",
        severity: "critical",
        message: `SSL certificate expired ${Math.abs(next.sslDaysRemaining)} day(s) ago`,
      });
    } else if (next.sslDaysRemaining <= 14) {
      drifts.push({
        field: "SSL Expiry",
        severity: "warning",
        message: `SSL certificate expires in ${next.sslDaysRemaining} day(s)`,
      });
    }
  }

  if (next.sslValid === false) {
    drifts.push({
      field: "SSL Chain",
      severity: "critical",
      message: "SSL certificate chain or hostname validation failed",
    });
  }

  if (!baseline) return drifts;

  const baseA = [...baseline.aRecords].sort().join(",");
  const nextA = [...next.aRecords].sort().join(",");
  if (baseA !== nextA) {
    drifts.push({
      field: "A Records",
      severity: "warning",
      message: `A records changed: [${baseA || "none"}] -> [${nextA || "none"}]`,
    });
  }

  if (baseline.aaaaRecords !== undefined && next.aaaaRecords !== undefined) {
    const baseAaaa = [...baseline.aaaaRecords].sort().join(",");
    const nextAaaa = [...next.aaaaRecords].sort().join(",");
    if (baseAaaa !== nextAaaa) {
      drifts.push({
        field: "AAAA Records",
        severity: "warning",
        message: `AAAA records changed: [${baseAaaa || "none"}] -> [${nextAaaa || "none"}]`,
      });
    }
  }

  if (baseline.nsRecords !== undefined && next.nsRecords !== undefined) {
    const baseNs = [...baseline.nsRecords].sort().join(",");
    const nextNs = [...next.nsRecords].sort().join(",");
    if (baseNs !== nextNs) {
      drifts.push({
        field: "Nameservers",
        severity: "critical",
        message: `NS records changed: [${baseNs || "none"}] -> [${nextNs || "none"}]`,
      });
    }
  } else if (baseline.nsCount !== next.nsCount) {
    drifts.push({
      field: "Nameservers",
      severity: "warning",
      message: `NS record count changed from ${baseline.nsCount} to ${next.nsCount}`,
    });
  }

  if (baseline.mxRecords !== undefined && next.mxRecords !== undefined) {
    const baseMx = [...baseline.mxRecords].sort().join(",");
    const nextMx = [...next.mxRecords].sort().join(",");
    if (baseMx !== nextMx) {
      drifts.push({
        field: "MX Records",
        severity: "critical",
        message: `MX records changed: [${baseMx || "none"}] -> [${nextMx || "none"}]`,
      });
    }
  } else if (baseline.mxCount !== next.mxCount) {
    drifts.push({
      field: "MX Records",
      severity: "warning",
      message: `MX record count changed from ${baseline.mxCount} to ${next.mxCount}`,
    });
  }

  if (baseline.spfStatus !== next.spfStatus) {
    drifts.push({
      field: "SPF",
      severity: next.spfStatus === "fail" || next.spfStatus === "missing" ? "critical" : "info",
      message: `SPF status changed: ${baseline.spfStatus} -> ${next.spfStatus}`,
    });
  } else if (
    baseline.spfRecord !== undefined &&
    next.spfRecord !== undefined &&
    (baseline.spfRecord ?? "") !== (next.spfRecord ?? "")
  ) {
    drifts.push({
      field: "SPF Record",
      severity: "warning",
      message: `SPF TXT record modified`,
    });
  }

  if (baseline.dmarcStatus !== next.dmarcStatus) {
    drifts.push({
      field: "DMARC",
      severity: next.dmarcStatus === "fail" || next.dmarcStatus === "missing" ? "critical" : "info",
      message: `DMARC status changed: ${baseline.dmarcStatus} -> ${next.dmarcStatus}`,
    });
  } else if (
    baseline.dmarcRecord !== undefined &&
    next.dmarcRecord !== undefined &&
    (baseline.dmarcRecord ?? "") !== (next.dmarcRecord ?? "")
  ) {
    drifts.push({
      field: "DMARC Record",
      severity: "warning",
      message: `DMARC TXT record modified`,
    });
  }

  if (baseline.dnssecStatus !== next.dnssecStatus) {
    drifts.push({
      field: "DNSSEC",
      severity: next.dnssecStatus === "fail" ? "critical" : "info",
      message: `DNSSEC status changed: ${baseline.dnssecStatus} -> ${next.dnssecStatus}`,
    });
  }

  if (baseline.sslIssuer && next.sslIssuer && baseline.sslIssuer !== next.sslIssuer) {
    drifts.push({
      field: "SSL Issuer",
      severity: "info",
      message: `SSL issuer changed: ${baseline.sslIssuer} -> ${next.sslIssuer}`,
    });
  }

  if (baseline.httpStatus !== undefined && next.httpStatus !== undefined) {
    const baseOk = baseline.httpStatus !== null && baseline.httpStatus < 400;
    if (baseOk && (next.httpStatus === null || next.httpStatus >= 500)) {
      drifts.push({
        field: "HTTP Status",
        severity: "critical",
        message: `HTTP availability degraded: ${baseline.httpStatus} -> ${next.httpStatus ?? "unreachable"}`,
      });
    } else if (baseOk && next.httpStatus !== null && next.httpStatus >= 400) {
      drifts.push({
        field: "HTTP Status",
        severity: "warning",
        message: `HTTP status changed: ${baseline.httpStatus} -> ${next.httpStatus}`,
      });
    }
  }

  if (baseline.registrar && next.registrar && baseline.registrar !== next.registrar) {
    drifts.push({
      field: "Registrar",
      severity: "critical",
      message: `Registrar changed: ${baseline.registrar} -> ${next.registrar}`,
    });
  }

  return drifts;
}

export function driftKey(drift: WatchlistDrift): string {
  return `${drift.field}|${drift.severity}|${drift.message}`;
}

export function findNewDrifts(
  drifts: WatchlistDrift[],
  lastNotifiedKeys?: string[],
): WatchlistDrift[] {
  if (!lastNotifiedKeys || lastNotifiedKeys.length === 0) {
    return drifts;
  }
  const seen = new Set(lastNotifiedKeys);
  return drifts.filter((d) => !seen.has(driftKey(d)));
}

export function getEffectiveIntervalMinutes(
  entry: WatchlistEntry,
  settings: WatchlistSettings,
): number {
  return entry.intervalMinutes ?? settings.intervalMinutes;
}

export function getNextCheckTimestamp(
  entry: WatchlistEntry,
  settings: WatchlistSettings,
): number | null {
  if (!settings.autoCheckEnabled || entry.paused) return null;
  const lastRaw = entry.lastCheckedAt ?? entry.latest?.capturedAt ?? null;
  if (!lastRaw) return Date.now();
  const lastMs = Date.parse(lastRaw);
  if (!Number.isFinite(lastMs)) return Date.now();
  const intervalMs = getEffectiveIntervalMinutes(entry, settings) * 60 * 1000;
  return lastMs + intervalMs;
}

export function isEntryDueForCheck(
  entry: WatchlistEntry,
  settings: WatchlistSettings,
  nowMs = Date.now(),
): boolean {
  const nextMs = getNextCheckTimestamp(entry, settings);
  if (nextMs === null) return false;
  return nowMs >= nextMs;
}

export function formatCountdown(targetMs: number, nowMs = Date.now()): string {
  const diffSec = Math.round((targetMs - nowMs) / 1000);
  if (diffSec <= 15) return "due now";
  if (diffSec < 60) return `in ${diffSec}s`;
  const mins = Math.round(diffSec / 60);
  if (mins < 60) return `in ${mins}m`;
  const hrs = Math.floor(mins / 60);
  const remMins = mins % 60;
  return remMins > 0 ? `in ${hrs}h ${remMins}m` : `in ${hrs}h`;
}

export function playAlertChime(): void {
  if (typeof window === "undefined") return;
  try {
    const AudioCtx =
      window.AudioContext ||
      (window as unknown as { webkitAudioContext?: typeof AudioContext })
        .webkitAudioContext;
    if (!AudioCtx) return;
    const ctx = new AudioCtx();
    const now = ctx.currentTime;

    const notes = [880, 1174.66];
    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = "sine";
      osc.frequency.setValueAtTime(freq, now + idx * 0.14);
      gain.gain.setValueAtTime(0.0001, now + idx * 0.14);
      gain.gain.exponentialRampToValueAtTime(0.08, now + idx * 0.14 + 0.02);
      gain.gain.exponentialRampToValueAtTime(0.0001, now + idx * 0.14 + 0.22);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(now + idx * 0.14);
      osc.stop(now + idx * 0.14 + 0.24);
    });

    setTimeout(() => {
      void ctx.close().catch(() => {});
    }, 650);
  } catch {
    // Ignore audio context errors in headless/restricted environments
  }
}

export function sendDesktopNotification(
  title: string,
  body: string,
  onClick?: () => void,
): void {
  if (typeof window === "undefined" || !("Notification" in window)) return;
  if (window.Notification.permission === "granted") {
    try {
      const notif = new window.Notification(title, { body });
      if (onClick) {
        notif.onclick = () => {
          try {
            window.focus();
          } catch {
            // Ignore focus error
          }
          onClick();
        };
      }
    } catch {
      // Ignore notification errors in restricted webviews
    }
  }
}
