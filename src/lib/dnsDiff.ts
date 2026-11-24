import type { DnsRecordItem, RecordTypeName, ResolverResult } from "../types/dns";

export type ExpectedMatchMode = "exact" | "contains" | "any";

export interface ExpectedRecordRule {
  id: string;
  record_type: RecordTypeName;
  match_mode: ExpectedMatchMode;
  expected_value: string;
  label?: string;
}

export interface DiffRuleResult {
  rule: ExpectedRecordRule;
  status: "matched" | "missing" | "mismatched";
  live_values: string[];
  note: string;
}

export interface DnsDiffSummary {
  matched: number;
  missing: number;
  mismatched: number;
  extra: number;
  total_rules: number;
  readiness_pct: number;
  results: DiffRuleResult[];
  extra_records: DnsRecordItem[];
}

export interface DiffPreset {
  id: string;
  name: string;
  description: string;
  rules: ExpectedRecordRule[];
}

const VALID_TYPES: ReadonlySet<string> = new Set([
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "CAA",
  "SRV",
]);

function normalizeValue(value: string): string {
  return value.trim().replace(/\.$/, "").toLowerCase();
}

function makeRuleId(): string {
  return `rule_${Math.random().toString(36).slice(2, 9)}`;
}

export function getBuiltInPresets(domain: string): DiffPreset[] {
  const cleanDomain = domain || "example.com";
  return [
    {
      id: "google-workspace",
      name: "Google Workspace",
      description: `Google SMTP MX + SPF include for ${cleanDomain}`,
      rules: [
        {
          id: "gw_mx",
          record_type: "MX",
          match_mode: "contains",
          expected_value: "smtp.google.com",
          label: "Google MX (or ASPMX)",
        },
        {
          id: "gw_spf",
          record_type: "TXT",
          match_mode: "contains",
          expected_value: "_spf.google.com",
          label: "SPF includes Google",
        },
      ],
    },
    {
      id: "microsoft-365",
      name: "Microsoft 365",
      description: "Exchange Online MX + SPF protection.outlook.com",
      rules: [
        {
          id: "ms_mx",
          record_type: "MX",
          match_mode: "contains",
          expected_value: "mail.protection.outlook.com",
          label: "Exchange Online MX",
        },
        {
          id: "ms_spf",
          record_type: "TXT",
          match_mode: "contains",
          expected_value: "spf.protection.outlook.com",
          label: "SPF includes Outlook",
        },
      ],
    },
    {
      id: "vercel",
      name: "Vercel Hosting",
      description: "Standard Vercel apex A record 76.76.21.21",
      rules: [
        {
          id: "vercel_a",
          record_type: "A",
          match_mode: "exact",
          expected_value: "76.76.21.21",
          label: "Vercel Edge Anycast IP",
        },
      ],
    },
    {
      id: "netlify",
      name: "Netlify Load Balancer",
      description: "Standard Netlify apex A record 75.2.60.5",
      rules: [
        {
          id: "netlify_a",
          record_type: "A",
          match_mode: "exact",
          expected_value: "75.2.60.5",
          label: "Netlify Apex IP",
        },
      ],
    },
    {
      id: "github-pages",
      name: "GitHub Pages",
      description: "All four GitHub Pages apex Anycast IPs",
      rules: [
        "185.199.108.153",
        "185.199.109.153",
        "185.199.110.153",
        "185.199.111.153",
      ].map((ip, i) => ({
        id: `gh_${i}`,
        record_type: "A",
        match_mode: "exact",
        expected_value: ip,
        label: `GitHub Pages IP #${i + 1}`,
      })),
    },
    {
      id: "email-baseline",
      name: "Email Security Baseline",
      description: "Requires SPF, MX, and at least one A/AAAA record",
      rules: [
        {
          id: "base_a",
          record_type: "A",
          match_mode: "any",
          expected_value: "*",
          label: "At least one A record",
        },
        {
          id: "base_mx",
          record_type: "MX",
          match_mode: "any",
          expected_value: "*",
          label: "At least one MX record",
        },
        {
          id: "base_spf",
          record_type: "TXT",
          match_mode: "contains",
          expected_value: "v=spf1",
          label: "SPF TXT policy",
        },
      ],
    },
  ];
}

export function parseExpectedRecordsText(text: string): ExpectedRecordRule[] {
  const rules: ExpectedRecordRule[] = [];
  const lines = text.split(/\r?\n/);

  for (const rawLine of lines) {
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith(";") || trimmed.startsWith("#")) {
      continue;
    }

    const tokens = trimmed.split(/\s+/);
    if (tokens.length < 2) continue;

    // Support both "A 1.2.3.4", "TXT contains v=spf1", and BIND lines like "@ 3600 IN A 1.2.3.4"
    let typeIdx = -1;
    for (let i = 0; i < Math.min(tokens.length - 1, 4); i += 1) {
      const candidate = tokens[i].toUpperCase();
      if (VALID_TYPES.has(candidate)) {
        typeIdx = i;
        break;
      }
    }
    if (typeIdx === -1) continue;

    const recordType = tokens[typeIdx].toUpperCase() as RecordTypeName;
    let rest = tokens.slice(typeIdx + 1).join(" ").trim();
    if (!rest) continue;

    let matchMode: ExpectedMatchMode = "exact";
    if (rest.toLowerCase().startsWith("contains ")) {
      matchMode = "contains";
      rest = rest.slice("contains ".length).trim();
    } else if (rest === "*") {
      matchMode = "any";
    }

    if (
      (rest.startsWith('"') && rest.endsWith('"')) ||
      (rest.startsWith("'") && rest.endsWith("'"))
    ) {
      rest = rest.slice(1, -1);
    }

    if (!rest) continue;
    rules.push({
      id: makeRuleId(),
      record_type: recordType,
      match_mode: matchMode,
      expected_value: rest,
    });
  }

  return rules;
}

export function captureRulesFromResolver(resolver: ResolverResult): ExpectedRecordRule[] {
  const out: ExpectedRecordRule[] = [];
  for (const tr of resolver.results) {
    for (const rec of tr.records) {
      const upper = rec.record_type.toUpperCase();
      if (!VALID_TYPES.has(upper)) continue;
      out.push({
        id: makeRuleId(),
        record_type: upper as RecordTypeName,
        match_mode: "exact",
        expected_value: rec.value,
      });
    }
  }
  return out;
}

export function evaluateDnsDiff(
  rules: ExpectedRecordRule[],
  resolver: ResolverResult | undefined,
): DnsDiffSummary {
  const byType = new Map<string, DnsRecordItem[]>();
  if (resolver) {
    for (const tr of resolver.results) {
      byType.set(tr.record_type.toUpperCase(), tr.records);
    }
  }

  const matchedLiveKeys = new Set<string>();
  const results: DiffRuleResult[] = [];
  let matched = 0;
  let missing = 0;
  let mismatched = 0;

  for (const rule of rules) {
    const recs = byType.get(rule.record_type) ?? [];
    const liveValues = recs.map((r) => r.value);
    const expNorm = normalizeValue(rule.expected_value);

    if (recs.length === 0) {
      missing += 1;
      results.push({
        rule,
        status: "missing",
        live_values: [],
        note: `No live ${rule.record_type} records found`,
      });
      continue;
    }

    let hitIdx = -1;
    if (rule.match_mode === "any") {
      hitIdx = 0;
    } else if (rule.match_mode === "contains") {
      hitIdx = recs.findIndex((r) =>
        normalizeValue(r.value).includes(expNorm),
      );
    } else {
      hitIdx = recs.findIndex((r) => normalizeValue(r.value) === expNorm);
    }

    if (hitIdx >= 0) {
      matched += 1;
      if (rule.match_mode === "any") {
        recs.forEach((_, idx) => matchedLiveKeys.add(`${rule.record_type}:${idx}`));
      } else {
        matchedLiveKeys.add(`${rule.record_type}:${hitIdx}`);
      }
      results.push({
        rule,
        status: "matched",
        live_values: liveValues,
        note: `Matched live ${rule.record_type} record`,
      });
    } else {
      mismatched += 1;
      results.push({
        rule,
        status: "mismatched",
        live_values: liveValues,
        note: `Found ${recs.length} ${rule.record_type} record(s), none match expected value`,
      });
    }
  }

  // Unexpected extra records in record types that have at least one rule
  const checkedTypes = new Set(rules.map((r) => r.record_type));
  const extraRecords: DnsRecordItem[] = [];
  for (const rtype of checkedTypes) {
    const recs = byType.get(rtype) ?? [];
    recs.forEach((rec, idx) => {
      if (!matchedLiveKeys.has(`${rtype}:${idx}`)) {
        extraRecords.push(rec);
      }
    });
  }

  const totalRules = rules.length;
  const readinessPct =
    totalRules > 0 ? Math.round((matched / totalRules) * 100) : 100;

  return {
    matched,
    missing,
    mismatched,
    extra: extraRecords.length,
    total_rules: totalRules,
    readiness_pct: readinessPct,
    results,
    extra_records: extraRecords,
  };
}

export function formatDiffAsMarkdown(
  domain: string,
  resolverLabel: string,
  summary: DnsDiffSummary,
): string {
  const lines = [
    `# DNS Diff Report — ${domain}`,
    `- Resolver: ${resolverLabel}`,
    `- Readiness: ${summary.readiness_pct}% (${summary.matched}/${summary.total_rules} rules matched, ${summary.missing} missing, ${summary.mismatched} mismatched, ${summary.extra} extra)`,
    "",
    "| Status | Type | Mode | Expected | Live Values |",
    "| --- | --- | --- | --- | --- |",
  ];

  for (const row of summary.results) {
    const live = row.live_values.length > 0 ? row.live_values.join("; ") : "(none)";
    lines.push(
      `| ${row.status.toUpperCase()} | ${row.rule.record_type} | ${row.rule.match_mode} | \`${row.rule.expected_value}\` | \`${live}\` |`,
    );
  }

  if (summary.extra_records.length > 0) {
    lines.push("", "## Unexpected / Extra Live Records");
    for (const rec of summary.extra_records) {
      lines.push(`- ${rec.record_type} \`${rec.value}\` (TTL ${rec.ttl}s)`);
    }
  }

  return lines.join("\n") + "\n";
}

export type SiteDiffStatus =
  | "identical"
  | "different"
  | "missing_on_b"
  | "missing_on_a"
  | "both_empty";

export interface SiteRecordEntry {
  value: string;
  ttl?: number;
  normalized: string;
}

export interface SiteRecordTypeDiff {
  record_type: string;
  status: SiteDiffStatus;
  shared: SiteRecordEntry[];
  only_on_a: SiteRecordEntry[];
  only_on_b: SiteRecordEntry[];
  all_a: SiteRecordEntry[];
  all_b: SiteRecordEntry[];
}

export interface SiteComparisonSummary {
  domain_a: string;
  domain_b: string;
  resolver_label: string;
  identical_types: number;
  different_types: number;
  missing_on_b_types: number;
  missing_on_a_types: number;
  empty_types: number;
  only_on_a_count: number;
  only_on_b_count: number;
  shared_count: number;
  rows: SiteRecordTypeDiff[];
}

const ORDERED_SITE_DIFF_TYPES = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "CAA",
  "SRV",
  "DMARC",
];

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function normalizeSiteRecordValue(
  value: string,
  domain: string,
  ignoreSelfDomain: boolean,
): string {
  let s = value.trim().replace(/\s+/g, " ").toLowerCase();
  // Strip trailing dot on standalone hostnames or space-separated tokens
  s = s.replace(/\.(?=\s|$)/g, "");
  if (ignoreSelfDomain && domain.trim()) {
    const cleanDom = domain.trim().toLowerCase().replace(/\.$/, "");
    if (cleanDom) {
      s = s.replace(new RegExp(escapeRegExp(cleanDom), "gi"), "<domain>");
    }
  }
  return s;
}

function extractNormalizedEntries(
  resolver: ResolverResult,
  domain: string,
  dmarcFallback: string | null | undefined,
  ignoreSelfDomain: boolean,
): Map<string, SiteRecordEntry[]> {
  const byType = new Map<string, SiteRecordEntry[]>();

  for (const tr of resolver.results) {
    const rtype = tr.record_type.toUpperCase();
    const list: SiteRecordEntry[] = [];
    const seen = new Set<string>();
    for (const rec of tr.records) {
      const normalized = normalizeSiteRecordValue(
        rec.value,
        domain,
        ignoreSelfDomain,
      );
      if (!normalized || seen.has(normalized)) continue;
      seen.add(normalized);
      list.push({
        value: rec.value,
        ttl: rec.ttl,
        normalized,
      });
    }
    byType.set(rtype, list);
  }

  if ((!byType.has("DMARC") || (byType.get("DMARC")?.length ?? 0) === 0) && dmarcFallback) {
    const normalized = normalizeSiteRecordValue(
      dmarcFallback,
      domain,
      ignoreSelfDomain,
    );
    byType.set("DMARC", [
      {
        value: dmarcFallback,
        normalized,
      },
    ]);
  }

  return byType;
}

export function compareSitesDns(
  domainA: string,
  resolverA: ResolverResult,
  domainB: string,
  resolverB: ResolverResult,
  options?: {
    dmarcA?: string | null;
    dmarcB?: string | null;
    ignoreSelfDomain?: boolean;
  },
): SiteComparisonSummary {
  const ignoreSelfDomain = options?.ignoreSelfDomain ?? false;
  const mapA = extractNormalizedEntries(
    resolverA,
    domainA,
    options?.dmarcA,
    ignoreSelfDomain,
  );
  const mapB = extractNormalizedEntries(
    resolverB,
    domainB,
    options?.dmarcB,
    ignoreSelfDomain,
  );

  const typeSet = new Set<string>(ORDERED_SITE_DIFF_TYPES);
  for (const k of mapA.keys()) typeSet.add(k);
  for (const k of mapB.keys()) typeSet.add(k);

  const orderedTypes = [
    ...ORDERED_SITE_DIFF_TYPES.filter((t) => typeSet.has(t)),
    ...Array.from(typeSet).filter((t) => !ORDERED_SITE_DIFF_TYPES.includes(t)),
  ];

  const rows: SiteRecordTypeDiff[] = [];
  let identicalTypes = 0;
  let differentTypes = 0;
  let missingOnBTypes = 0;
  let missingOnATypes = 0;
  let emptyTypes = 0;
  let onlyOnACount = 0;
  let onlyOnBCount = 0;
  let sharedCount = 0;

  for (const rtype of orderedTypes) {
    const allA = mapA.get(rtype) ?? [];
    const allB = mapB.get(rtype) ?? [];

    const setA = new Set(allA.map((e) => e.normalized));
    const setB = new Set(allB.map((e) => e.normalized));

    const shared = allA.filter((e) => setB.has(e.normalized));
    const onlyOnA = allA.filter((e) => !setB.has(e.normalized));
    const onlyOnB = allB.filter((e) => !setA.has(e.normalized));

    let status: SiteDiffStatus;
    if (allA.length === 0 && allB.length === 0) {
      status = "both_empty";
      emptyTypes += 1;
    } else if (allA.length > 0 && allB.length === 0) {
      status = "missing_on_b";
      missingOnBTypes += 1;
    } else if (allA.length === 0 && allB.length > 0) {
      status = "missing_on_a";
      missingOnATypes += 1;
    } else if (onlyOnA.length === 0 && onlyOnB.length === 0) {
      status = "identical";
      identicalTypes += 1;
    } else {
      status = "different";
      differentTypes += 1;
    }

    sharedCount += shared.length;
    onlyOnACount += onlyOnA.length;
    onlyOnBCount += onlyOnB.length;

    rows.push({
      record_type: rtype,
      status,
      shared,
      only_on_a: onlyOnA,
      only_on_b: onlyOnB,
      all_a: allA,
      all_b: allB,
    });
  }

  return {
    domain_a: domainA,
    domain_b: domainB,
    resolver_label: resolverB.label || resolverA.label || "Resolver",
    identical_types: identicalTypes,
    different_types: differentTypes,
    missing_on_b_types: missingOnBTypes,
    missing_on_a_types: missingOnATypes,
    empty_types: emptyTypes,
    only_on_a_count: onlyOnACount,
    only_on_b_count: onlyOnBCount,
    shared_count: sharedCount,
    rows,
  };
}

export function formatSiteComparisonAsMarkdown(
  summary: SiteComparisonSummary,
): string {
  const lines = [
    `# Site-to-Site DNS Comparison: ${summary.domain_a} vs ${summary.domain_b}`,
    `- Resolver: ${summary.resolver_label}`,
    `- Identical Types: ${summary.identical_types} | Different: ${summary.different_types} | Missing on ${summary.domain_b}: ${summary.missing_on_b_types} | Missing on ${summary.domain_a}: ${summary.missing_on_a_types}`,
    "",
    `| Type | Status | ${summary.domain_a} (Site A) | ${summary.domain_b} (Site B) |`,
    "| --- | --- | --- | --- |",
  ];

  for (const row of summary.rows) {
    if (row.status === "both_empty") continue;
    const aText =
      row.all_a.length > 0
        ? row.all_a.map((e) => e.value).join("; ")
        : "*(missing)*";
    const bText =
      row.all_b.length > 0
        ? row.all_b.map((e) => e.value).join("; ")
        : "*(missing)*";
    lines.push(
      `| ${row.record_type} | ${row.status.replace(/_/g, " ").toUpperCase()} | ${aText} | ${bText} |`,
    );
  }

  return lines.join("\n") + "\n";
}
