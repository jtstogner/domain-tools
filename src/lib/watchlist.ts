import type { BulkDomainResult, DnsQueryReport } from "../types/dns";

export interface WatchlistSnapshot {
  capturedAt: string;
  aRecords: string[];
  nsCount: number;
  mxCount: number;
  sslValid: boolean | null;
  sslDaysRemaining: number | null;
  sslIssuer: string | null;
  spfStatus: string;
  dmarcStatus: string;
  dnssecStatus: string;
  domainDaysRemaining: number | null;
  registrar: string | null;
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
  baseline: WatchlistSnapshot | null;
  latest: WatchlistSnapshot | null;
  drifts: WatchlistDrift[];
}

const WATCHLIST_KEY = "domain_tools_watchlist_v1";

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

export function snapshotFromReport(report: DnsQueryReport): WatchlistSnapshot {
  const firstOk =
    report.resolvers.find((r) => r.status === "ok") ?? report.resolvers[0];
  const aRecords =
    firstOk?.results
      .find((r) => r.record_type === "A")
      ?.records.map((r) => r.value)
      .sort() ?? [];
  const nsCount =
    firstOk?.results.find((r) => r.record_type === "NS")?.records.length ?? 0;
  const mxCount =
    firstOk?.results.find((r) => r.record_type === "MX")?.records.length ?? 0;

  return {
    capturedAt: report.queried_at,
    aRecords,
    nsCount,
    mxCount,
    sslValid: report.tls ? report.tls.chain_valid && report.tls.hostname_match : null,
    sslDaysRemaining: report.tls?.days_remaining ?? null,
    sslIssuer: report.tls?.certificates?.[0]?.issuer_org ?? null,
    spfStatus: report.security.spf.status,
    dmarcStatus: report.security.dmarc.status,
    dnssecStatus: report.security.dnssec.status,
    domainDaysRemaining: report.whois?.days_until_expiry ?? null,
    registrar: report.whois?.registrar ?? null,
    healthGrade: report.health?.grade,
    healthScore: report.health?.score,
  };
}

export function snapshotFromBulk(res: BulkDomainResult): WatchlistSnapshot {
  return {
    capturedAt: new Date().toISOString(),
    aRecords: [...res.a_records].sort(),
    nsCount: res.ns_count,
    mxCount: res.mx_count,
    sslValid: res.ssl_valid,
    sslDaysRemaining: res.ssl_days_remaining,
    sslIssuer: res.ssl_issuer,
    spfStatus: res.spf_status,
    dmarcStatus: res.dmarc_status,
    dnssecStatus: res.dnssec_status,
    domainDaysRemaining: res.domain_days_remaining,
    registrar: res.registrar,
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

  if (baseline.nsCount !== next.nsCount) {
    drifts.push({
      field: "Nameservers",
      severity: "warning",
      message: `NS record count changed from ${baseline.nsCount} to ${next.nsCount}`,
    });
  }

  if (baseline.mxCount !== next.mxCount) {
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
  }

  if (baseline.dmarcStatus !== next.dmarcStatus) {
    drifts.push({
      field: "DMARC",
      severity: next.dmarcStatus === "fail" || next.dmarcStatus === "missing" ? "critical" : "info",
      message: `DMARC status changed: ${baseline.dmarcStatus} -> ${next.dmarcStatus}`,
    });
  }

  if (baseline.dnssecStatus !== next.dnssecStatus) {
    drifts.push({
      field: "DNSSEC",
      severity: next.dnssecStatus === "fail" ? "critical" : "info",
      message: `DNSSEC status changed: ${baseline.dnssecStatus} -> ${next.dnssecStatus}`,
    });
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

export function sendDesktopNotification(title: string, body: string): void {
  if (typeof window === "undefined" || !("Notification" in window)) return;
  if (window.Notification.permission === "granted") {
    try {
      new window.Notification(title, { body });
    } catch {
      // Ignore notification errors in restricted webviews
    }
  }
}
