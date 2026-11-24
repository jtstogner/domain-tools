import {
  AlertCircle,
  AlertTriangle,
  ArrowLeftRight,
  Camera,
  CheckCircle2,
  ClipboardCopy,
  FileDiff,
  GitCompare,
  Loader2,
  Plus,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { copyToClipboard, queryDnsOnly } from "../lib/api";
import {
  captureRulesFromResolver,
  compareSitesDns,
  evaluateDnsDiff,
  type ExpectedMatchMode,
  type ExpectedRecordRule,
  formatDiffAsMarkdown,
  formatSiteComparisonAsMarkdown,
  getBuiltInPresets,
  parseExpectedRecordsText,
  type SiteDiffStatus,
} from "../lib/dnsDiff";
import type { DnsOnlyResult, DnsQueryReport, RecordTypeName } from "../types/dns";

interface DnsDiffPanelProps {
  report: DnsQueryReport;
  selectedResolverId: string;
  onSelectResolverId: (id: string) => void;
  historyDomains?: string[];
  customResolver?: string;
  onNotify: (msg: string) => void;
}

type DiffPanelMode = "sites" | "rules";
type SiteFilterMode =
  | "all"
  | "differences"
  | "missing_b"
  | "missing_a"
  | "identical";

const DIFF_STORAGE_PREFIX = "domain_tools_diff_rules_v1:";
const RECORD_TYPES: RecordTypeName[] = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "CAA",
  "SRV",
];

function siteStatusBadge(
  status: SiteDiffStatus,
  domainA: string,
  domainB: string,
): { label: string; tone: string } {
  switch (status) {
    case "identical":
      return {
        label: "Identical",
        tone: "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300",
      };
    case "missing_on_b":
      return {
        label: `Missing on ${domainB}`,
        tone: "bg-rose-500/15 text-rose-700 dark:text-rose-300",
      };
    case "missing_on_a":
      return {
        label: `Missing on ${domainA}`,
        tone: "bg-sky-500/15 text-sky-700 dark:text-sky-300",
      };
    case "different":
      return {
        label: "Values Differ",
        tone: "bg-amber-500/15 text-amber-700 dark:text-amber-300",
      };
    default:
      return {
        label: "Both Empty",
        tone: "bg-surface-alt text-ink-muted",
      };
  }
}

function loadSavedRules(domain: string): ExpectedRecordRule[] {
  try {
    const raw = localStorage.getItem(`${DIFF_STORAGE_PREFIX}${domain}`);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function DnsDiffPanel({
  report,
  selectedResolverId,
  onSelectResolverId,
  historyDomains = [],
  customResolver,
  onNotify,
}: DnsDiffPanelProps) {
  const [diffMode, setDiffMode] = useState<DiffPanelMode>("sites");

  // --- Site-to-Site Comparison state ---
  const [siteA, setSiteA] = useState(report.domain);
  const [siteB, setSiteB] = useState(
    () =>
      historyDomains.find(
        (d) => d.toLowerCase() !== report.domain.toLowerCase(),
      ) ?? "",
  );
  const [compareResolverId, setCompareResolverId] = useState(
    selectedResolverId || "cloudflare",
  );
  const [hideEmptyTypes, setHideEmptyTypes] = useState(true);
  const [ignoreSelfDomain, setIgnoreSelfDomain] = useState(false);
  const [siteFilter, setSiteFilter] = useState<SiteFilterMode>("all");
  const [comparing, setComparing] = useState(false);
  const [compareError, setCompareError] = useState<string | null>(null);
  const [sitePair, setSitePair] = useState<{
    a: DnsOnlyResult;
    b: DnsOnlyResult;
  } | null>(null);

  useEffect(() => {
    setSiteA(report.domain);
  }, [report.domain]);

  useEffect(() => {
    if (selectedResolverId) {
      setCompareResolverId(selectedResolverId);
    }
  }, [selectedResolverId]);

  const runSiteCompare = useCallback(
    async (overrideA?: string, overrideB?: string) => {
      const targetA = (overrideA ?? siteA).trim();
      const targetB = (overrideB ?? siteB).trim();
      if (!targetA || !targetB) {
        setCompareError("Enter both Site A and Site B domains to compare.");
        return;
      }

      setComparing(true);
      setCompareError(null);
      try {
        const [resA, resB] = await Promise.all([
          queryDnsOnly(targetA, RECORD_TYPES, compareResolverId, customResolver),
          queryDnsOnly(targetB, RECORD_TYPES, compareResolverId, customResolver),
        ]);
        setSiteA(resA.domain);
        setSiteB(resB.domain);
        setSitePair({ a: resA, b: resB });
      } catch (err) {
        setCompareError(String(err));
      } finally {
        setComparing(false);
      }
    },
    [siteA, siteB, compareResolverId, customResolver],
  );

  const handleSwapSites = () => {
    const nextA = siteB;
    const nextB = siteA;
    setSiteA(nextA);
    setSiteB(nextB);
    setSitePair((prev) => (prev ? { a: prev.b, b: prev.a } : null));
  };

  const siteSummary = useMemo(() => {
    if (!sitePair) return null;
    return compareSitesDns(
      sitePair.a.domain,
      sitePair.a.resolver,
      sitePair.b.domain,
      sitePair.b.resolver,
      { ignoreSelfDomain },
    );
  }, [sitePair, ignoreSelfDomain]);

  const filteredSiteRows = useMemo(() => {
    if (!siteSummary) return [];
    return siteSummary.rows.filter((row) => {
      if (hideEmptyTypes && row.status === "both_empty") return false;
      if (siteFilter === "differences") {
        return row.status !== "identical" && row.status !== "both_empty";
      }
      if (siteFilter === "missing_b") return row.status === "missing_on_b";
      if (siteFilter === "missing_a") return row.status === "missing_on_a";
      if (siteFilter === "identical") return row.status === "identical";
      return true;
    });
  }, [siteSummary, hideEmptyTypes, siteFilter]);

  const otherHistoryDomains = useMemo(
    () =>
      historyDomains
        .filter((d) => d.toLowerCase() !== siteA.trim().toLowerCase())
        .slice(0, 8),
    [historyDomains, siteA],
  );

  // --- Expected Rules & Presets state ---
  const [rules, setRules] = useState<ExpectedRecordRule[]>(() =>
    loadSavedRules(report.domain),
  );
  const [newType, setNewType] = useState<RecordTypeName>("A");
  const [newMode, setNewMode] = useState<ExpectedMatchMode>("exact");
  const [newValue, setNewValue] = useState("");
  const [bulkOpen, setBulkOpen] = useState(false);
  const [bulkText, setBulkText] = useState("");

  useEffect(() => {
    setRules(loadSavedRules(report.domain));
  }, [report.domain]);

  useEffect(() => {
    try {
      localStorage.setItem(
        `${DIFF_STORAGE_PREFIX}${report.domain}`,
        JSON.stringify(rules),
      );
    } catch {
      // ignore storage quota errors
    }
  }, [report.domain, rules]);

  const activeResolver = useMemo(
    () =>
      report.resolvers.find((r) => r.id === selectedResolverId) ??
      report.resolvers.find((r) => r.status === "ok") ??
      report.resolvers[0],
    [report.resolvers, selectedResolverId],
  );

  const summary = useMemo(
    () => evaluateDnsDiff(rules, activeResolver),
    [rules, activeResolver],
  );

  const presets = useMemo(
    () => getBuiltInPresets(report.domain),
    [report.domain],
  );

  const addRule = () => {
    const val = newValue.trim();
    if (!val && newMode !== "any") return;
    const rule: ExpectedRecordRule = {
      id: `rule_${Math.random().toString(36).slice(2, 9)}`,
      record_type: newType,
      match_mode: newMode,
      expected_value: newMode === "any" ? "*" : val,
    };
    setRules((prev) => [...prev, rule]);
    setNewValue("");
  };

  const applyBulkPaste = () => {
    const parsed = parseExpectedRecordsText(bulkText);
    if (parsed.length === 0) {
      onNotify("No valid DNS rules found in pasted text");
      return;
    }
    setRules((prev) => [...prev, ...parsed]);
    setBulkText("");
    setBulkOpen(false);
    onNotify(`Added ${parsed.length} expected rule(s)`);
  };

  const handleCaptureSnapshot = () => {
    if (!activeResolver) return;
    const captured = captureRulesFromResolver(activeResolver);
    setRules(captured);
    onNotify(
      `Captured ${captured.length} live record(s) from ${activeResolver.label}`,
    );
  };

  return (
    <div className="space-y-4">
      {/* Mode Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface px-4 py-2.5">
        <div className="inline-flex items-center rounded-lg border border-line bg-surface-alt p-0.5">
          <button
            type="button"
            onClick={() => setDiffMode("sites")}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
              diffMode === "sites"
                ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <GitCompare className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            Compare Two Sites
          </button>
          <button
            type="button"
            onClick={() => setDiffMode("rules")}
            className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
              diffMode === "rules"
                ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                : "text-ink-muted hover:text-ink"
            }`}
          >
            <FileDiff className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            Expected Rules &amp; Presets
          </button>
        </div>

        <span className="text-[11px] text-ink-muted">
          {diffMode === "sites"
            ? "Compare DNS records side-by-side between two domains"
            : "Verify live records against expected rules or provider presets"}
        </span>
      </div>

      {diffMode === "sites" && (
        <div className="space-y-4">
          {/* Site Comparison Controls */}
          <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
            <div className="grid grid-cols-1 gap-2.5 md:grid-cols-12 md:items-end">
              <div className="md:col-span-4">
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Site A (Reference)
                </label>
                <input
                  type="text"
                  value={siteA}
                  onChange={(e) => setSiteA(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void runSiteCompare();
                  }}
                  placeholder="example.com"
                  className="w-full rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
                />
              </div>

              <div className="flex justify-center md:col-span-1">
                <button
                  type="button"
                  onClick={handleSwapSites}
                  title="Swap Site A and Site B"
                  className="rounded-lg border border-line bg-surface-alt p-2 text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
                >
                  <ArrowLeftRight className="h-3.5 w-3.5" />
                </button>
              </div>

              <div className="md:col-span-4">
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Site B (Compare Target)
                </label>
                <input
                  type="text"
                  value={siteB}
                  onChange={(e) => setSiteB(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter") void runSiteCompare();
                  }}
                  placeholder="staging.example.com or competitor.com"
                  className="w-full rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
                />
              </div>

              <div className="md:col-span-3 flex items-end gap-2">
                <div className="min-w-0 flex-1">
                  <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                    Resolver
                  </label>
                  <select
                    value={compareResolverId}
                    onChange={(e) => setCompareResolverId(e.target.value)}
                    className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
                  >
                    <option value="cloudflare">Cloudflare</option>
                    <option value="google">Google</option>
                    <option value="quad9">Quad9</option>
                    <option value="system">System</option>
                    {customResolver?.trim() && (
                      <option value="custom">Custom ({customResolver.trim()})</option>
                    )}
                  </select>
                </div>

                <button
                  type="button"
                  disabled={comparing}
                  onClick={() => void runSiteCompare()}
                  className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
                >
                  {comparing ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <GitCompare className="h-3.5 w-3.5" />
                  )}
                  {comparing ? "Comparing..." : "Compare"}
                </button>
              </div>
            </div>

            {otherHistoryDomains.length > 0 && (
              <div className="flex flex-wrap items-center gap-1.5 border-t border-line pt-2.5">
                <span className="text-[11px] text-ink-muted">
                  Recent sites:
                </span>
                {otherHistoryDomains.map((dom) => (
                  <button
                    key={dom}
                    type="button"
                    onClick={() => {
                      setSiteB(dom);
                      void runSiteCompare(siteA, dom);
                    }}
                    className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
                  >
                    vs {dom}
                  </button>
                ))}
              </div>
            )}

            <div className="flex flex-wrap items-center gap-4 border-t border-line pt-2.5 text-xs text-ink-secondary">
              <label className="inline-flex cursor-pointer items-center gap-1.5">
                <input
                  type="checkbox"
                  checked={hideEmptyTypes}
                  onChange={(e) => setHideEmptyTypes(e.target.checked)}
                  className="rounded border-line"
                />
                <span>Hide record types empty on both sites</span>
              </label>
              <label
                className="inline-flex cursor-pointer items-center gap-1.5"
                title="Replace each site's own domain name with <domain> before comparing TXT/MX/SOA values"
              >
                <input
                  type="checkbox"
                  checked={ignoreSelfDomain}
                  onChange={(e) => setIgnoreSelfDomain(e.target.checked)}
                  className="rounded border-line"
                />
                <span>Normalize self-referencing domain names</span>
              </label>
            </div>
          </div>

          {compareError && (
            <div className="flex items-start gap-2.5 rounded-xl border border-rose-500/30 bg-rose-500/10 p-3.5 text-xs text-rose-900 dark:text-rose-200">
              <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
              <span>{compareError}</span>
            </div>
          )}

          {!siteSummary ? (
            <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center">
              <GitCompare className="mx-auto h-9 w-9 text-ink-muted/60" />
              <h3 className="mt-2.5 text-sm font-semibold text-ink">
                Compare DNS records between two domains
              </h3>
              <p className="mx-auto mt-1 max-w-md text-xs text-ink-muted">
                Enter a second site above (or click one of your recent lookups)
                and click <strong>Compare</strong> to highlight identical
                records, differing values, and missing record types on either
                site.
              </p>
            </div>
          ) : (
            <>
              {/* 4 Summary Cards */}
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3">
                  <div className="text-[11px] text-emerald-700 dark:text-emerald-300">
                    Identical Types
                  </div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-emerald-700 dark:text-emerald-200">
                    {siteSummary.identical_types}
                  </div>
                </div>
                <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-3">
                  <div className="text-[11px] text-amber-700 dark:text-amber-300">
                    Values Differ
                  </div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-amber-700 dark:text-amber-200">
                    {siteSummary.different_types}
                  </div>
                </div>
                <div className="rounded-xl border border-rose-500/25 bg-rose-500/10 p-3">
                  <div className="truncate text-[11px] text-rose-700 dark:text-rose-300">
                    Only on {siteSummary.domain_a}
                  </div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-rose-700 dark:text-rose-200">
                    {siteSummary.only_on_a_count}{" "}
                    <span className="text-[11px] font-normal">
                      ({siteSummary.missing_on_b_types} missing types on B)
                    </span>
                  </div>
                </div>
                <div className="rounded-xl border border-sky-500/25 bg-sky-500/10 p-3">
                  <div className="truncate text-[11px] text-sky-700 dark:text-sky-300">
                    Only on {siteSummary.domain_b}
                  </div>
                  <div className="mt-0.5 font-mono text-lg font-semibold text-sky-700 dark:text-sky-200">
                    {siteSummary.only_on_b_count}{" "}
                    <span className="text-[11px] font-normal">
                      ({siteSummary.missing_on_a_types} missing types on A)
                    </span>
                  </div>
                </div>
              </div>

              {/* Filter & Copy Toolbar */}
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex flex-wrap items-center gap-1.5">
                  {(
                    [
                      ["all", "All"],
                      ["differences", "Differences Only"],
                      ["missing_b", `Missing on ${siteSummary.domain_b}`],
                      ["missing_a", `Missing on ${siteSummary.domain_a}`],
                      ["identical", "Identical"],
                    ] as const
                  ).map(([id, label]) => (
                    <button
                      key={id}
                      type="button"
                      onClick={() => setSiteFilter(id)}
                      className={`rounded-lg border px-2.5 py-1 text-xs font-medium transition ${
                        siteFilter === id
                          ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                          : "border-line bg-surface text-ink-muted hover:text-ink"
                      }`}
                    >
                      {label}
                    </button>
                  ))}
                </div>

                <button
                  type="button"
                  onClick={() => {
                    const md = formatSiteComparisonAsMarkdown(siteSummary);
                    void copyToClipboard(md);
                    onNotify("Copied site comparison Markdown");
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface px-2.5 py-1 text-xs font-medium text-ink-secondary hover:text-ink"
                >
                  <ClipboardCopy className="h-3.5 w-3.5" />
                  Copy Markdown Diff
                </button>
              </div>

              {/* Side-by-Side Comparison Table */}
              <div className="overflow-x-auto rounded-xl border border-line bg-surface">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                    <tr>
                      <th className="w-20 px-4 py-2.5">Type</th>
                      <th className="w-40 px-3 py-2.5">Status</th>
                      <th className="px-3 py-2.5 font-mono normal-case text-ink">
                        Site A: {siteSummary.domain_a}
                      </th>
                      <th className="px-3 py-2.5 font-mono normal-case text-ink">
                        Site B: {siteSummary.domain_b}
                      </th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line align-top">
                    {filteredSiteRows.length === 0 ? (
                      <tr>
                        <td
                          colSpan={4}
                          className="px-4 py-8 text-center text-ink-muted"
                        >
                          No record types match the current filter.
                        </td>
                      </tr>
                    ) : (
                      filteredSiteRows.map((row) => {
                        const badge = siteStatusBadge(
                          row.status,
                          siteSummary.domain_a,
                          siteSummary.domain_b,
                        );
                        return (
                          <tr
                            key={row.record_type}
                            className="hover:bg-surface-alt/40"
                          >
                            <td className="px-4 py-3 font-mono font-semibold text-ink">
                              {row.record_type}
                            </td>
                            <td className="px-3 py-3">
                              <span
                                className={`inline-block rounded-full px-2 py-0.5 text-[10px] font-semibold ${badge.tone}`}
                              >
                                {badge.label}
                              </span>
                            </td>
                            <td className="px-3 py-3">
                              {row.all_a.length === 0 ? (
                                <span className="inline-block rounded border border-dashed border-line px-2 py-0.5 text-[11px] italic text-ink-muted">
                                  No {row.record_type} records (Missing on A)
                                </span>
                              ) : (
                                <div className="space-y-1.5">
                                  {row.only_on_a.map((rec, i) => (
                                    <div
                                      key={`only-a-${i}`}
                                      className="rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1.5 font-mono text-[11px] text-rose-900 dark:text-rose-200"
                                    >
                                      <div className="mb-0.5 flex items-center justify-between gap-2 text-[10px] font-sans font-semibold text-rose-700 dark:text-rose-300">
                                        <span>Only on A (missing on B)</span>
                                        {rec.ttl != null && (
                                          <span className="font-mono font-normal opacity-80">
                                            TTL {rec.ttl}s
                                          </span>
                                        )}
                                      </div>
                                      <div className="break-all">{rec.value}</div>
                                    </div>
                                  ))}
                                  {row.shared.map((rec, i) => (
                                    <div
                                      key={`shared-a-${i}`}
                                      className="flex items-start gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 font-mono text-[11px] text-ink-secondary"
                                    >
                                      <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-400" />
                                      <span className="flex-1 break-all">
                                        {rec.value}
                                      </span>
                                      {rec.ttl != null && (
                                        <span className="shrink-0 text-[10px] text-ink-muted">
                                          {rec.ttl}s
                                        </span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </td>
                            <td className="px-3 py-3">
                              {row.all_b.length === 0 ? (
                                <span className="inline-block rounded border border-dashed border-line px-2 py-0.5 text-[11px] italic text-ink-muted">
                                  No {row.record_type} records (Missing on B)
                                </span>
                              ) : (
                                <div className="space-y-1.5">
                                  {row.only_on_b.map((rec, i) => (
                                    <div
                                      key={`only-b-${i}`}
                                      className="rounded-lg border border-sky-500/30 bg-sky-500/10 px-2.5 py-1.5 font-mono text-[11px] text-sky-900 dark:text-sky-200"
                                    >
                                      <div className="mb-0.5 flex items-center justify-between gap-2 text-[10px] font-sans font-semibold text-sky-700 dark:text-sky-300">
                                        <span>Only on B (missing on A)</span>
                                        {rec.ttl != null && (
                                          <span className="font-mono font-normal opacity-80">
                                            TTL {rec.ttl}s
                                          </span>
                                        )}
                                      </div>
                                      <div className="break-all">{rec.value}</div>
                                    </div>
                                  ))}
                                  {row.shared.map((rec, i) => (
                                    <div
                                      key={`shared-b-${i}`}
                                      className="flex items-start gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 font-mono text-[11px] text-ink-secondary"
                                    >
                                      <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-emerald-600 dark:text-emerald-400" />
                                      <span className="flex-1 break-all">
                                        {rec.value}
                                      </span>
                                      {rec.ttl != null && (
                                        <span className="shrink-0 text-[10px] text-ink-muted">
                                          {rec.ttl}s
                                        </span>
                                      )}
                                    </div>
                                  ))}
                                </div>
                              )}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </div>
      )}

      {diffMode === "rules" && (
        <>
          {/* Top Toolbar: Resolver + Presets + Snapshot */}
          <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs font-medium text-ink-muted">
              Compare against resolver:
            </span>
            <select
              value={activeResolver?.id ?? ""}
              onChange={(e) => onSelectResolverId(e.target.value)}
              className="rounded-lg border border-line bg-canvas px-2.5 py-1 text-xs text-ink outline-none focus:border-sky-500"
            >
              {report.resolvers.map((r) => (
                <option key={r.id} value={r.id}>
                  {r.label} ({r.address})
                </option>
              ))}
            </select>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={handleCaptureSnapshot}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-xs font-medium text-ink-secondary hover:text-ink"
            >
              <Camera className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
              Capture Live Snapshot
            </button>
            <button
              type="button"
              onClick={() => setBulkOpen((v) => !v)}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-xs font-medium text-ink-secondary hover:text-ink"
            >
              <Upload className="h-3.5 w-3.5" />
              Bulk Paste
            </button>
            {rules.length > 0 && (
              <>
                <button
                  type="button"
                  onClick={() => {
                    const md = formatDiffAsMarkdown(
                      report.domain,
                      activeResolver?.label ?? "Unknown",
                      summary,
                    );
                    void copyToClipboard(md);
                    onNotify("Copied DNS diff report as Markdown");
                  }}
                  className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-xs font-medium text-ink-secondary hover:text-ink"
                >
                  <ClipboardCopy className="h-3.5 w-3.5" />
                  Copy Report
                </button>
                <button
                  type="button"
                  onClick={() => setRules([])}
                  className="inline-flex items-center gap-1 rounded-lg border border-rose-500/30 bg-rose-500/10 px-2.5 py-1 text-xs font-medium text-rose-700 hover:bg-rose-500/20 dark:text-rose-300"
                >
                  <Trash2 className="h-3.5 w-3.5" />
                  Clear
                </button>
              </>
            )}
          </div>
        </div>

        {/* Presets */}
        <div className="flex flex-wrap items-center gap-1.5 border-t border-line pt-2.5">
          <span className="text-[11px] font-medium text-ink-muted">Presets:</span>
          {presets.map((preset) => (
            <button
              key={preset.id}
              type="button"
              title={preset.description}
              onClick={() => {
                setRules((prev) => [...prev, ...preset.rules]);
                onNotify(`Added ${preset.name} rules`);
              }}
              className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
            >
              + {preset.name}
            </button>
          ))}
        </div>

        {/* Add Single Rule Row */}
        <div className="flex flex-wrap items-center gap-2 border-t border-line pt-2.5">
          <select
            value={newType}
            onChange={(e) => setNewType(e.target.value as RecordTypeName)}
            className="rounded-lg border border-line bg-canvas px-2 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
          >
            {RECORD_TYPES.map((t) => (
              <option key={t} value={t}>
                {t}
              </option>
            ))}
          </select>
          <select
            value={newMode}
            onChange={(e) => setNewMode(e.target.value as ExpectedMatchMode)}
            className="rounded-lg border border-line bg-canvas px-2 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
          >
            <option value="exact">Exact Match</option>
            <option value="contains">Contains Substring</option>
            <option value="any">Any Non-Empty Record</option>
          </select>
          <input
            type="text"
            disabled={newMode === "any"}
            value={newMode === "any" ? "*" : newValue}
            onChange={(e) => setNewValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") addRule();
            }}
            placeholder={
              newType === "TXT"
                ? "v=spf1 include:_spf.google.com"
                : newType === "A"
                  ? "76.76.21.21"
                  : "Expected record value..."
            }
            className="min-w-[220px] flex-1 rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500 disabled:opacity-50"
          />
          <button
            type="button"
            onClick={addRule}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
          >
            <Plus className="h-3.5 w-3.5" />
            Add Rule
          </button>
        </div>

        {bulkOpen && (
          <div className="space-y-2 border-t border-line pt-3">
            <div className="text-[11px] text-ink-muted">
              Paste expected lines (supports{" "}
              <code className="font-mono">A 76.76.21.21</code>,{" "}
              <code className="font-mono">TXT contains _spf.google.com</code>,
              or BIND zone format <code className="font-mono">@ 3600 IN MX 10 mail.example.com</code>):
            </div>
            <textarea
              rows={4}
              value={bulkText}
              onChange={(e) => setBulkText(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas p-2.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
              placeholder={"A 76.76.21.21\nTXT contains _spf.google.com\nMX contains smtp.google.com"}
            />
            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => setBulkOpen(false)}
                className="rounded-lg border border-line bg-surface-alt px-3 py-1 text-xs text-ink-secondary"
              >
                Cancel
              </button>
              <button
                type="button"
                onClick={applyBulkPaste}
                className="rounded-lg bg-sky-600 px-3 py-1 text-xs font-semibold text-white dark:bg-sky-500 dark:text-slate-950"
              >
                Parse &amp; Add Rules
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Summary & Diff Results */}
      {rules.length === 0 ? (
        <div className="rounded-xl border border-dashed border-line bg-surface/60 px-6 py-12 text-center">
          <FileDiff className="mx-auto h-9 w-9 text-ink-muted/60" />
          <h3 className="mt-2.5 text-sm font-semibold text-ink">
            Verify expected records or migration cutovers
          </h3>
          <p className="mx-auto mt-1 max-w-md text-xs text-ink-muted">
            Click a preset above, capture the current DNS state before making
            changes, or add custom expected record rules for{" "}
            <span className="font-mono">{report.domain}</span>.
          </p>
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            <div className="rounded-xl border border-line bg-surface p-3">
              <div className="text-[11px] text-ink-muted">Migration Readiness</div>
              <div className="mt-0.5 font-mono text-lg font-semibold text-ink">
                {summary.readiness_pct}%
              </div>
            </div>
            <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/10 p-3">
              <div className="text-[11px] text-emerald-700 dark:text-emerald-300">Matched</div>
              <div className="mt-0.5 font-mono text-lg font-semibold text-emerald-700 dark:text-emerald-200">
                {summary.matched}
              </div>
            </div>
            <div className="rounded-xl border border-rose-500/25 bg-rose-500/10 p-3">
              <div className="text-[11px] text-rose-700 dark:text-rose-300">Missing</div>
              <div className="mt-0.5 font-mono text-lg font-semibold text-rose-700 dark:text-rose-200">
                {summary.missing}
              </div>
            </div>
            <div className="rounded-xl border border-amber-500/25 bg-amber-500/10 p-3">
              <div className="text-[11px] text-amber-700 dark:text-amber-300">Mismatched</div>
              <div className="mt-0.5 font-mono text-lg font-semibold text-amber-700 dark:text-amber-200">
                {summary.mismatched}
              </div>
            </div>
            <div className="rounded-xl border border-line bg-surface p-3">
              <div className="text-[11px] text-ink-muted">Extra Live Records</div>
              <div className="mt-0.5 font-mono text-lg font-semibold text-ink">
                {summary.extra}
              </div>
            </div>
          </div>

          <div className="overflow-x-auto rounded-xl border border-line bg-surface">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                <tr>
                  <th className="px-4 py-2.5">Status</th>
                  <th className="px-3 py-2.5">Type</th>
                  <th className="px-3 py-2.5">Expected Rule</th>
                  <th className="px-3 py-2.5">Live Values</th>
                  <th className="px-3 py-2.5 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {summary.results.map((row) => (
                  <tr key={row.rule.id} className="hover:bg-surface-alt/50">
                    <td className="px-4 py-2.5">
                      {row.status === "matched" ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                          <CheckCircle2 className="h-3 w-3" />
                          Matched
                        </span>
                      ) : row.status === "mismatched" ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
                          <AlertTriangle className="h-3 w-3" />
                          Mismatch
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
                          <XCircle className="h-3 w-3" />
                          Missing
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono font-semibold text-ink">
                      {row.rule.record_type}
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="font-mono text-ink">
                        <span className="mr-1.5 rounded bg-surface-alt px-1.5 py-0.5 text-[10px] text-ink-muted">
                          {row.rule.match_mode}
                        </span>
                        {row.rule.expected_value}
                      </div>
                      {row.rule.label && (
                        <div className="mt-0.5 text-[10px] text-ink-muted">
                          {row.rule.label}
                        </div>
                      )}
                    </td>
                    <td className="px-3 py-2.5 font-mono text-[11px] text-ink-secondary">
                      {row.live_values.length > 0 ? (
                        <div className="space-y-0.5">
                          {row.live_values.map((v, i) => (
                            <div key={`${v}-${i}`} className="break-all">
                              {v}
                            </div>
                          ))}
                        </div>
                      ) : (
                        <span className="italic text-ink-muted">(none)</span>
                      )}
                    </td>
                    <td className="px-3 py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() =>
                          setRules((prev) =>
                            prev.filter((r) => r.id !== row.rule.id),
                          )
                        }
                        title="Remove rule"
                        className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-rose-600 dark:hover:text-rose-300"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {summary.extra_records.length > 0 && (
            <div className="rounded-xl border border-amber-500/30 bg-surface p-4">
              <div className="flex items-center gap-2 text-xs font-semibold text-amber-700 dark:text-amber-300">
                <AlertTriangle className="h-4 w-4" />
                Unexpected / Extra Live Records ({summary.extra_records.length})
              </div>
              <p className="mt-0.5 text-[11px] text-ink-muted">
                These live records exist under checked record types but did not
                match any expected rule (possible stale records left over from
                old hosting).
              </p>
              <div className="mt-2.5 space-y-1 font-mono text-xs">
                {summary.extra_records.map((rec, i) => (
                  <div
                    key={`${rec.record_type}-${rec.value}-${i}`}
                    className="flex items-center gap-3 rounded-lg border border-line bg-surface-alt px-3 py-1.5"
                  >
                    <span className="w-12 font-semibold text-ink">
                      {rec.record_type}
                    </span>
                    <span className="flex-1 break-all text-ink-secondary">
                      {rec.value}
                    </span>
                    <span className="text-[11px] text-ink-muted">
                      TTL {rec.ttl}s
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </>
      )}
        </>
      )}
    </div>
  );
}
