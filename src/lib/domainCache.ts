import type {
  CtHistoryReport,
  DnsQueryReport,
  DnsTraceReport,
  ResolverResult,
  SecurityReport,
  SmtpDeliverabilityReport,
  TracerouteReport,
  TyposquatReport,
} from "../types/dns";

export type CacheTtlOption = "5m" | "15m" | "1h" | "session" | "off";

export interface CachedSubResults {
  dnsTrace?: Record<string, DnsTraceReport>;
  typosquats?: TyposquatReport;
  ctHistory?: CtHistoryReport;
  smtpProbe?: SmtpDeliverabilityReport;
  traceroute?: Record<string, TracerouteReport>;
}

export interface CachedDomainEntry {
  domain: string;
  optionsKey: string;
  report: DnsQueryReport;
  previousReport: DnsQueryReport | null;
  cachedAt: number;
  subResults: CachedSubResults;
}

export interface ReportChangeItem {
  category: "DNS" | "TLS" | "Health" | "Security" | "Ports" | "WHOIS";
  label: string;
  before: string;
  after: string;
  severity: "info" | "warn" | "good";
}

const DB_NAME = "domain_tools_cache_v1";
const DB_VERSION = 1;
const STORE_NAME = "domains";
const MAX_LRU_ENTRIES = 50;
const TTL_STORAGE_KEY = "domain_tools_cache_ttl_v1";

const VALID_TTL_OPTIONS: ReadonlySet<string> = new Set<CacheTtlOption>([
  "5m",
  "15m",
  "1h",
  "session",
  "off",
]);

/** In-memory LRU cache: oldest entry first, most-recently-used entry last. */
const memoryCache = new Map<string, CachedDomainEntry>();
let dbPromise: Promise<IDBDatabase | null> | null = null;
let idbDisabled = false;

function normalizeDomainKey(domain: string): string {
  return domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//i, "")
    .replace(/\/.*$/, "")
    .replace(/:\d+$/, "")
    .replace(/\.$/, "");
}

function openCacheDb(): Promise<IDBDatabase | null> {
  if (idbDisabled || typeof indexedDB === "undefined") {
    return Promise.resolve(null);
  }
  if (dbPromise) return dbPromise;

  dbPromise = new Promise<IDBDatabase | null>((resolve) => {
    try {
      const request = indexedDB.open(DB_NAME, DB_VERSION);

      request.onupgradeneeded = () => {
        const db = request.result;
        if (!db.objectStoreNames.contains(STORE_NAME)) {
          db.createObjectStore(STORE_NAME, { keyPath: "domain" });
        }
      };

      request.onsuccess = () => {
        const db = request.result;
        db.onversionchange = () => {
          db.close();
          dbPromise = null;
        };
        resolve(db);
      };

      request.onerror = () => {
        idbDisabled = true;
        dbPromise = null;
        resolve(null);
      };

      request.onblocked = () => {
        resolve(null);
      };
    } catch {
      idbDisabled = true;
      dbPromise = null;
      resolve(null);
    }
  });

  return dbPromise;
}

async function idbGetAll(): Promise<CachedDomainEntry[]> {
  const db = await openCacheDb();
  if (!db) return [];

  return new Promise<CachedDomainEntry[]>((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readonly");
      const store = tx.objectStore(STORE_NAME);
      const req = store.getAll();
      req.onsuccess = () => {
        const result = Array.isArray(req.result) ? (req.result as CachedDomainEntry[]) : [];
        resolve(result);
      };
      req.onerror = () => resolve([]);
    } catch {
      resolve([]);
    }
  });
}

async function idbPut(entry: CachedDomainEntry): Promise<void> {
  const db = await openCacheDb();
  if (!db) return;

  return new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).put(entry);
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
}

async function idbDeleteMany(domains: string[]): Promise<void> {
  if (domains.length === 0) return;
  const db = await openCacheDb();
  if (!db) return;

  return new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      const store = tx.objectStore(STORE_NAME);
      for (const domain of domains) {
        store.delete(domain);
      }
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
}

async function idbClear(): Promise<void> {
  const db = await openCacheDb();
  if (!db) return;

  return new Promise<void>((resolve) => {
    try {
      const tx = db.transaction(STORE_NAME, "readwrite");
      tx.objectStore(STORE_NAME).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => resolve();
      tx.onabort = () => resolve();
    } catch {
      resolve();
    }
  });
}

function touchLru(key: string, entry: CachedDomainEntry): string[] {
  memoryCache.delete(key);
  memoryCache.set(key, entry);

  const evicted: string[] = [];
  while (memoryCache.size > MAX_LRU_ENTRIES) {
    const oldestKey = memoryCache.keys().next().value;
    if (oldestKey === undefined) break;
    memoryCache.delete(oldestKey);
    evicted.push(oldestKey);
  }
  return evicted;
}

export function buildOptionsKey(opts: {
  record_types: string[];
  resolvers: string[];
  custom_resolver: string | null;
  dkim_selectors: string[];
}): string {
  const recordTypes = Array.from(
    new Set(opts.record_types.map((r) => r.trim().toUpperCase()).filter(Boolean)),
  ).sort();
  const resolvers = Array.from(
    new Set(opts.resolvers.map((r) => r.trim().toLowerCase()).filter(Boolean)),
  ).sort();
  const customResolver = (opts.custom_resolver ?? "").trim().toLowerCase();
  const dkimSelectors = Array.from(
    new Set(opts.dkim_selectors.map((s) => s.trim().toLowerCase()).filter(Boolean)),
  ).sort();

  return JSON.stringify({
    r: recordTypes,
    ns: resolvers,
    c: customResolver,
    d: dkimSelectors,
  });
}

export function getCacheTtlSetting(): CacheTtlOption {
  try {
    if (typeof localStorage === "undefined") return "15m";
    const stored = localStorage.getItem(TTL_STORAGE_KEY);
    if (stored && VALID_TTL_OPTIONS.has(stored)) {
      return stored as CacheTtlOption;
    }
  } catch {
    // Ignore storage access errors
  }
  return "15m";
}

export function setCacheTtlSetting(ttl: CacheTtlOption): void {
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(TTL_STORAGE_KEY, ttl);
    }
  } catch {
    // Ignore storage access errors
  }
}

export function getTtlMs(ttl: CacheTtlOption): number | null {
  switch (ttl) {
    case "5m":
      return 5 * 60 * 1000;
    case "15m":
      return 15 * 60 * 1000;
    case "1h":
      return 60 * 60 * 1000;
    case "session":
      return null;
    case "off":
      return 0;
  }
}

export async function initDomainCache(): Promise<void> {
  const persisted = await idbGetAll();
  if (persisted.length === 0) return;

  // Sort oldest -> newest so Map insertion order reflects LRU recency
  const valid = persisted
    .filter((item): item is CachedDomainEntry => Boolean(item && typeof item.domain === "string" && item.report))
    .sort((a, b) => a.cachedAt - b.cachedAt);

  const evicted: string[] = [];
  for (const rawEntry of valid) {
    const key = normalizeDomainKey(rawEntry.domain);
    if (!key) continue;
    const normalizedEntry: CachedDomainEntry = {
      ...rawEntry,
      domain: key,
      previousReport: rawEntry.previousReport ?? null,
      subResults: rawEntry.subResults ?? {},
    };
    const existing = memoryCache.get(key);
    if (!existing || normalizedEntry.cachedAt >= existing.cachedAt) {
      evicted.push(...touchLru(key, normalizedEntry));
    }
  }

  if (evicted.length > 0) {
    await idbDeleteMany(evicted);
  }
}

export function getCachedDomain(domain: string): CachedDomainEntry | null {
  const key = normalizeDomainKey(domain);
  if (!key) return null;
  const entry = memoryCache.get(key);
  if (!entry) return null;
  // Refresh LRU recency
  memoryCache.delete(key);
  memoryCache.set(key, entry);
  return entry;
}

export function isCacheFresh(entry: CachedDomainEntry, ttl?: CacheTtlOption): boolean {
  const effectiveTtl = ttl ?? getCacheTtlSetting();
  if (effectiveTtl === "off") return false;
  if (effectiveTtl === "session") return true;
  const ttlMs = getTtlMs(effectiveTtl);
  if (ttlMs === null) return true;
  return Date.now() - entry.cachedAt < ttlMs;
}

export async function saveCachedReport(
  report: DnsQueryReport,
  optionsKey: string,
): Promise<CachedDomainEntry> {
  const key = normalizeDomainKey(report.domain);
  const existing = memoryCache.get(key);

  const entry: CachedDomainEntry = {
    domain: key,
    optionsKey,
    report,
    previousReport: existing ? existing.report : null,
    cachedAt: Date.now(),
    subResults: existing ? { ...existing.subResults } : {},
  };

  const evicted = touchLru(key, entry);
  await idbPut(entry);
  if (evicted.length > 0) {
    await idbDeleteMany(evicted);
  }
  return entry;
}

export async function updateCachedSecurity(
  domain: string,
  security: SecurityReport,
): Promise<CachedDomainEntry | null> {
  const key = normalizeDomainKey(domain);
  const existing = memoryCache.get(key);
  if (!existing) return null;

  const updated: CachedDomainEntry = {
    ...existing,
    report: {
      ...existing.report,
      security,
    },
  };

  touchLru(key, updated);
  await idbPut(updated);
  return updated;
}

export async function saveCachedSubResult<K extends keyof CachedSubResults>(
  domain: string,
  key: K,
  value: CachedSubResults[K],
): Promise<void> {
  const domainKey = normalizeDomainKey(domain);
  const existing = memoryCache.get(domainKey);
  if (!existing) return;

  let mergedSubValue: CachedSubResults[K] = value;
  if (
    (key === "dnsTrace" || key === "traceroute") &&
    value &&
    typeof value === "object" &&
    existing.subResults[key] &&
    typeof existing.subResults[key] === "object"
  ) {
    mergedSubValue = {
      ...(existing.subResults[key] as Record<string, unknown>),
      ...(value as Record<string, unknown>),
    } as CachedSubResults[K];
  }

  const updated: CachedDomainEntry = {
    ...existing,
    subResults: {
      ...existing.subResults,
      [key]: mergedSubValue,
    },
  };

  touchLru(domainKey, updated);
  await idbPut(updated);
}

export function listCachedDomains(): Record<string, { cachedAt: number; fresh: boolean }> {
  const ttl = getCacheTtlSetting();
  const out: Record<string, { cachedAt: number; fresh: boolean }> = {};
  for (const [domain, entry] of memoryCache.entries()) {
    out[domain] = {
      cachedAt: entry.cachedAt,
      fresh: isCacheFresh(entry, ttl),
    };
  }
  return out;
}

export function getCacheStats(): { count: number } {
  return { count: memoryCache.size };
}

export async function clearDomainCache(): Promise<void> {
  memoryCache.clear();
  await idbClear();
}

export function formatRelativeAge(timestampMs: number): string {
  const diffSec = Math.max(0, Math.floor((Date.now() - timestampMs) / 1000));
  if (diffSec < 45) return "just now";
  if (diffSec < 3600) {
    const mins = Math.max(1, Math.floor(diffSec / 60));
    return `${mins}m ago`;
  }
  if (diffSec < 86400) {
    const hours = Math.floor(diffSec / 3600);
    return `${hours}h ago`;
  }
  const days = Math.floor(diffSec / 86400);
  return `${days}d ago`;
}

function getPrimaryResolver(report: DnsQueryReport): ResolverResult | null {
  return report.resolvers.find((r) => r.status === "ok") ?? report.resolvers[0] ?? null;
}

function getRecordValues(resolver: ResolverResult | null, recordType: string): string[] {
  if (!resolver) return [];
  const res = resolver.results.find((r) => r.record_type.toUpperCase() === recordType);
  if (!res || res.records.length === 0) return [];
  return Array.from(new Set(res.records.map((rec) => rec.value.trim()))).sort();
}

function formatRecordSummary(values: string[]): string {
  if (values.length === 0) return "(none)";
  if (values.length <= 3) return values.join(", ");
  return `${values.slice(0, 3).join(", ")} (+${values.length - 3} more)`;
}

function securityStatusRank(status: string): number {
  switch (status) {
    case "pass":
      return 3;
    case "warn":
      return 2;
    case "unsigned":
    case "missing":
      return 1;
    case "fail":
      return 0;
    default:
      return 1;
  }
}

export function computeReportDiff(
  prev: DnsQueryReport,
  next: DnsQueryReport,
): ReportChangeItem[] {
  const changes: ReportChangeItem[] = [];

  // 1. DNS records on primary resolver
  const prevResolver = getPrimaryResolver(prev);
  const nextResolver = getPrimaryResolver(next);
  const trackedTypes = ["A", "AAAA", "MX", "NS", "TXT", "SOA"] as const;

  for (const rtype of trackedTypes) {
    const beforeVals = getRecordValues(prevResolver, rtype);
    const afterVals = getRecordValues(nextResolver, rtype);
    if (
      beforeVals.length !== afterVals.length ||
      beforeVals.some((v, idx) => v !== afterVals[idx])
    ) {
      const severity: ReportChangeItem["severity"] =
        afterVals.length === 0 && beforeVals.length > 0
          ? "warn"
          : rtype === "NS" || rtype === "MX"
            ? "warn"
            : "info";
      changes.push({
        category: "DNS",
        label: `${rtype} records`,
        before: formatRecordSummary(beforeVals),
        after: formatRecordSummary(afterVals),
        severity,
      });
    }
  }

  // 2. Email & DNS Security statuses
  const secChecks: { label: string; before: string; after: string }[] = [
    { label: "SPF status", before: prev.security.spf.status, after: next.security.spf.status },
    { label: "DMARC status", before: prev.security.dmarc.status, after: next.security.dmarc.status },
    { label: "DKIM status", before: prev.security.dkim.status, after: next.security.dkim.status },
    { label: "DNSSEC status", before: prev.security.dnssec.status, after: next.security.dnssec.status },
  ];

  for (const item of secChecks) {
    if (item.before !== item.after) {
      const beforeRank = securityStatusRank(item.before);
      const afterRank = securityStatusRank(item.after);
      changes.push({
        category: "Security",
        label: item.label,
        before: item.before,
        after: item.after,
        severity: afterRank > beforeRank ? "good" : afterRank < beforeRank ? "warn" : "info",
      });
    }
  }

  // 3. TLS certificate & chain
  if (prev.tls.chain_valid !== next.tls.chain_valid) {
    changes.push({
      category: "TLS",
      label: "Certificate chain validity",
      before: prev.tls.chain_valid ? "Valid" : "Invalid",
      after: next.tls.chain_valid ? "Valid" : "Invalid",
      severity: next.tls.chain_valid ? "good" : "warn",
    });
  }

  const prevIssuer = prev.tls.certificates[0]?.issuer_org || prev.tls.certificates[0]?.issuer || null;
  const nextIssuer = next.tls.certificates[0]?.issuer_org || next.tls.certificates[0]?.issuer || null;
  if (prevIssuer !== nextIssuer && (prevIssuer || nextIssuer)) {
    changes.push({
      category: "TLS",
      label: "TLS certificate issuer",
      before: prevIssuer ?? "(none)",
      after: nextIssuer ?? "(none)",
      severity: "info",
    });
  }

  if (prev.tls.days_remaining !== next.tls.days_remaining) {
    const beforeDays = prev.tls.days_remaining;
    const afterDays = next.tls.days_remaining;
    if (
      beforeDays === null ||
      afterDays === null ||
      Math.abs(afterDays - beforeDays) >= 1
    ) {
      let severity: ReportChangeItem["severity"] = "info";
      if (afterDays !== null && beforeDays !== null && afterDays > beforeDays + 1) {
        severity = "good"; // Certificate renewed
      } else if (afterDays !== null && afterDays <= 14) {
        severity = "warn";
      }
      changes.push({
        category: "TLS",
        label: "TLS days remaining",
        before: beforeDays !== null ? `${beforeDays}d` : "N/A",
        after: afterDays !== null ? `${afterDays}d` : "N/A",
        severity,
      });
    }
  }

  // 4. Health score & grade
  if (prev.health.score !== next.health.score || prev.health.grade !== next.health.grade) {
    changes.push({
      category: "Health",
      label: "Health score",
      before: `${prev.health.score}/100 (${prev.health.grade})`,
      after: `${next.health.score}/100 (${next.health.grade})`,
      severity:
        next.health.score > prev.health.score
          ? "good"
          : next.health.score < prev.health.score
            ? "warn"
            : "info",
    });
  }

  // 5. Open ports
  const prevOpen = prev.ports.ports
    .filter((p) => p.status === "open")
    .map((p) => `${p.port}/${p.service}`)
    .sort();
  const nextOpen = next.ports.ports
    .filter((p) => p.status === "open")
    .map((p) => `${p.port}/${p.service}`)
    .sort();

  if (
    prevOpen.length !== nextOpen.length ||
    prevOpen.some((val, idx) => val !== nextOpen[idx])
  ) {
    const addedPorts = nextOpen.filter((p) => !prevOpen.includes(p));
    changes.push({
      category: "Ports",
      label: "Open ports",
      before: prevOpen.length > 0 ? prevOpen.join(", ") : "(none)",
      after: nextOpen.length > 0 ? nextOpen.join(", ") : "(none)",
      severity: addedPorts.length > 0 ? "warn" : "info",
    });
  }

  // 6. WHOIS registrar & expiry
  if ((prev.whois.registrar ?? "") !== (next.whois.registrar ?? "")) {
    changes.push({
      category: "WHOIS",
      label: "Registrar",
      before: prev.whois.registrar ?? "(unknown)",
      after: next.whois.registrar ?? "(unknown)",
      severity: "warn",
    });
  }

  if ((prev.whois.expiry_date ?? "") !== (next.whois.expiry_date ?? "")) {
    changes.push({
      category: "WHOIS",
      label: "Domain expiry",
      before: prev.whois.expiry_date ?? "(unknown)",
      after: next.whois.expiry_date ?? "(unknown)",
      severity: "info",
    });
  }

  return changes;
}
