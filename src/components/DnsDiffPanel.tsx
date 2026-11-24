import {
  AlertTriangle,
  Camera,
  CheckCircle2,
  ClipboardCopy,
  FileDiff,
  Plus,
  Trash2,
  Upload,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard } from "../lib/api";
import {
  captureRulesFromResolver,
  evaluateDnsDiff,
  type ExpectedMatchMode,
  type ExpectedRecordRule,
  formatDiffAsMarkdown,
  getBuiltInPresets,
  parseExpectedRecordsText,
} from "../lib/dnsDiff";
import type { DnsQueryReport, RecordTypeName } from "../types/dns";

interface DnsDiffPanelProps {
  report: DnsQueryReport;
  selectedResolverId: string;
  onSelectResolverId: (id: string) => void;
  onNotify: (msg: string) => void;
}

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
  onNotify,
}: DnsDiffPanelProps) {
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
    </div>
  );
}
