export interface TtlPreset {
  label: string;
  seconds: number;
  useCase: string;
}

export const COMMON_TTL_PRESETS: TtlPreset[] = [
  { label: "1m", seconds: 60, useCase: "Active cutover / rapid failover" },
  { label: "5m", seconds: 300, useCase: "Pre-migration / dynamic cloud endpoints" },
  { label: "15m", seconds: 900, useCase: "Balanced agility & cache efficiency" },
  { label: "1h", seconds: 3600, useCase: "Standard production A/AAAA/CNAME/TXT" },
  { label: "4h", seconds: 14400, useCase: "Stable web & MX records" },
  { label: "1d", seconds: 86400, useCase: "Static NS, CAA, and rarely changing zones" },
];

export function formatDuration(seconds: number): string {
  if (!Number.isFinite(seconds)) return "0s";
  const sign = seconds < 0 ? "-" : "";
  let rem = Math.round(Math.abs(seconds));
  if (rem === 0) return "0s";

  const units: [string, number][] = [
    ["w", 604800],
    ["d", 86400],
    ["h", 3600],
    ["m", 60],
    ["s", 1],
  ];

  const parts: string[] = [];
  for (const [suffix, unitSec] of units) {
    if (rem >= unitSec) {
      const count = Math.floor(rem / unitSec);
      rem %= unitSec;
      parts.push(`${count}${suffix}`);
    }
  }
  return sign + parts.join(" ");
}

export function parseDuration(input: string): number | null {
  const trimmed = input.trim().toLowerCase();
  if (!trimmed) return null;

  // Plain numeric seconds
  if (/^\d+(?:\.\d+)?$/.test(trimmed)) {
    const val = Number(trimmed);
    return Number.isFinite(val) && val >= 0 ? Math.round(val) : null;
  }

  const unitMultipliers: Record<string, number> = {
    s: 1,
    sec: 1,
    secs: 1,
    second: 1,
    seconds: 1,
    m: 60,
    min: 60,
    mins: 60,
    minute: 60,
    minutes: 60,
    h: 3600,
    hr: 3600,
    hrs: 3600,
    hour: 3600,
    hours: 3600,
    d: 86400,
    day: 86400,
    days: 86400,
    w: 604800,
    wk: 604800,
    wks: 604800,
    week: 604800,
    weeks: 604800,
  };

  const tokenRegex = /(\d+(?:\.\d+)?)\s*([a-z]+)/g;
  let total = 0;
  let matchedChars = 0;
  let match: RegExpExecArray | null;

  while ((match = tokenRegex.exec(trimmed)) !== null) {
    const num = Number(match[1]);
    const mult = unitMultipliers[match[2]];
    if (!Number.isFinite(num) || !mult) return null;
    total += num * mult;
    matchedChars += match[0].length;
  }

  // Ensure there were no unrecognized leftover non-whitespace/comma characters
  const stripped = trimmed.replace(/[\s,]+/g, "");
  const matchedNoSpace = trimmed
    .match(/(\d+(?:\.\d+)?)\s*([a-z]+)/g)
    ?.join("")
    .replace(/\s+/g, "");

  if (matchedChars === 0 || stripped !== matchedNoSpace) {
    return null;
  }

  return Math.round(total);
}

export function generateSoaSerial(date: Date = new Date(), rev = 1): number {
  const year = date.getUTCFullYear();
  const month = String(date.getUTCMonth() + 1).padStart(2, "0");
  const day = String(date.getUTCDate()).padStart(2, "0");
  const revision = String(Math.max(0, Math.min(99, Math.round(rev)))).padStart(2, "0");
  return Number(`${year}${month}${day}${revision}`);
}

export interface SoaSerialInfo {
  raw: string;
  validFormat: boolean;
  dateStr: string | null;
  year: number | null;
  month: number | null;
  day: number | null;
  revision: number | null;
  nextSerial: number;
  isToday: boolean;
}

export function parseSoaSerial(serial: number | string): SoaSerialInfo {
  const raw = String(serial).trim();
  const todaySerialBase = generateSoaSerial(new Date(), 1);
  const todayPrefix = String(todaySerialBase).slice(0, 8);

  if (/^\d{10}$/.test(raw)) {
    const year = Number(raw.slice(0, 4));
    const month = Number(raw.slice(4, 6));
    const day = Number(raw.slice(6, 8));
    const revision = Number(raw.slice(8, 10));

    const validDate =
      year >= 1970 &&
      year <= 2199 &&
      month >= 1 &&
      month <= 12 &&
      day >= 1 &&
      day <= 31;

    if (validDate) {
      const datePrefix = raw.slice(0, 8);
      const dateStr = `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}`;
      const currentNum = Number(raw);
      const nextSerial =
        currentNum >= todaySerialBase ? currentNum + 1 : todaySerialBase;

      return {
        raw,
        validFormat: true,
        dateStr,
        year,
        month,
        day,
        revision,
        nextSerial,
        isToday: datePrefix === todayPrefix,
      };
    }
  }

  const parsedInt = Number(raw);
  const nextSerial =
    Number.isInteger(parsedInt) && parsedInt > 0
      ? Math.max(parsedInt + 1, todaySerialBase)
      : todaySerialBase;

  return {
    raw,
    validFormat: false,
    dateStr: null,
    year: null,
    month: null,
    day: null,
    revision: null,
    nextSerial,
    isToday: false,
  };
}

export interface CutoverStep {
  id: string;
  phase: "prep" | "verify" | "cutover" | "drain" | "restore";
  title: string;
  timestampIso: string;
  offsetFromCutoverSec: number;
  offsetLabel: string;
  detail: string;
}

export interface CutoverPlan {
  currentTtlSec: number;
  migrationTtlSec: number;
  cutoverIso: string;
  totalWindowSec: number;
  steps: CutoverStep[];
  warnings: string[];
}

function formatOffsetLabel(offsetSec: number): string {
  if (offsetSec === 0) return "T+0 (Cutover)";
  const prefix = offsetSec < 0 ? "T-" : "T+";
  return `${prefix}${formatDuration(Math.abs(offsetSec))}`;
}

export function planCutoverSchedule(opts: {
  currentTtlSec: number;
  migrationTtlSec: number;
  cutoverIso: string;
}): CutoverPlan {
  const currentTtlSec = Math.max(0, Math.round(opts.currentTtlSec));
  const migrationTtlSec = Math.max(0, Math.round(opts.migrationTtlSec));
  const parsedCutover = Date.parse(opts.cutoverIso);
  const cutoverMs = Number.isNaN(parsedCutover) ? Date.now() + 86400_000 : parsedCutover;
  const cutoverIso = new Date(cutoverMs).toISOString();

  const warnings: string[] = [];
  if (Number.isNaN(parsedCutover)) {
    warnings.push("Invalid cutover timestamp provided; defaulted to 24 hours from now.");
  }
  if (migrationTtlSec >= currentTtlSec && currentTtlSec > 0) {
    warnings.push(
      `Migration TTL (${formatDuration(migrationTtlSec)}) is not lower than current TTL (${formatDuration(currentTtlSec)}); lower it to 60s–300s to minimize cutover convergence time.`,
    );
  }
  if (migrationTtlSec < 30) {
    warnings.push(
      "TTL below 30s may be clamped upward by recursive resolvers and increases authoritative DNS query volume.",
    );
  }

  const lowerOffsetSec = -Math.max(currentTtlSec, 60);
  const lowerAtMs = cutoverMs + lowerOffsetSec * 1000;
  if (lowerAtMs < Date.now()) {
    warnings.push(
      `To guarantee all old ${formatDuration(currentTtlSec)} caches expire before cutover, you should have lowered the TTL by ${new Date(lowerAtMs).toISOString()} (in the past). Consider postponing cutover or accepting gradual convergence.`,
    );
  }

  const verifyOffsetSec = -Math.min(Math.max(migrationTtlSec, 300), Math.abs(lowerOffsetSec));
  const drainOffsetSec = Math.max(migrationTtlSec, 60);
  const restoreOffsetSec = Math.max(migrationTtlSec * 2, 3600);

  const makeStep = (
    id: string,
    phase: CutoverStep["phase"],
    title: string,
    offsetSec: number,
    detail: string,
  ): CutoverStep => ({
    id,
    phase,
    title,
    timestampIso: new Date(cutoverMs + offsetSec * 1000).toISOString(),
    offsetFromCutoverSec: offsetSec,
    offsetLabel: formatOffsetLabel(offsetSec),
    detail,
  });

  const steps: CutoverStep[] = [
    makeStep(
      "lower-ttl",
      "prep",
      `Lower TTL to ${formatDuration(migrationTtlSec)}`,
      lowerOffsetSec,
      `Update the target DNS record's TTL from ${formatDuration(currentTtlSec)} to ${formatDuration(migrationTtlSec)} without changing the record value yet. Wait at least one full previous TTL (${formatDuration(currentTtlSec)}) so every cached copy expires.`,
    ),
    makeStep(
      "verify-prep",
      "verify",
      "Verify propagation & pre-flight checks",
      verifyOffsetSec,
      `Confirm authoritative and public resolvers (Cloudflare, Google, Quad9) return TTL <= ${formatDuration(migrationTtlSec)} and that the new destination responds cleanly over TLS.`,
    ),
    makeStep(
      "execute-cutover",
      "cutover",
      "Execute DNS record cutover",
      0,
      `Swap the DNS record value (A/AAAA/CNAME/MX) to the new target while keeping TTL at ${formatDuration(migrationTtlSec)}. Increment the zone SOA serial if managing BIND zones.`,
    ),
    makeStep(
      "old-cache-expiry",
      "drain",
      "Worst-case old cache expiry",
      drainOffsetSec,
      `All RFC-compliant recursive resolvers should now serve the new record. Keep old infrastructure online slightly longer to accommodate non-compliant clients that ignore short TTLs.`,
    ),
    makeStep(
      "restore-ttl",
      "restore",
      `Verify health & restore TTL to ${formatDuration(currentTtlSec)}`,
      restoreOffsetSec,
      `Once traffic, error rates, and TLS handshakes on the new target are stable, raise TTL back to ${formatDuration(currentTtlSec)} to restore normal DNS caching efficiency.`,
    ),
  ];

  return {
    currentTtlSec,
    migrationTtlSec,
    cutoverIso,
    totalWindowSec: restoreOffsetSec - lowerOffsetSec,
    steps,
    warnings,
  };
}
