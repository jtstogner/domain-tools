import {
  AlertTriangle,
  CalendarClock,
  CheckCircle2,
  Clock,
  Copy,
  Hash,
  Sparkles,
} from "lucide-react";
import { useMemo, useState } from "react";
import { copyToClipboard } from "../../lib/api";
import {
  COMMON_TTL_PRESETS,
  formatDuration,
  generateSoaSerial,
  parseDuration,
  parseSoaSerial,
  planCutoverSchedule,
} from "../../lib/ttlPlanner";
import type { DnsQueryReport } from "../../types/dns";

export interface TtlPlannerTabProps {
  currentReport?: DnsQueryReport | null;
  onNotify: (msg: string) => void;
}

function defaultCutoverLocalString(): string {
  const target = new Date(Date.now() + 24 * 3600 * 1000);
  target.setMinutes(0, 0, 0);
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${target.getFullYear()}-${pad(target.getMonth() + 1)}-${pad(target.getDate())}T${pad(
    target.getHours(),
  )}:${pad(target.getMinutes())}`;
}

function extractSoaSerialFromReport(report?: DnsQueryReport | null): string | null {
  if (!report) return null;
  for (const res of report.resolvers) {
    const soaGroup = res.results.find((r) => r.record_type === "SOA");
    const first = soaGroup?.records[0];
    if (!first) continue;
    if (first.details && typeof first.details.serial === "number") {
      return String(first.details.serial);
    }
    const tokens = first.value.trim().split(/\s+/);
    if (tokens.length >= 3 && /^\d+$/.test(tokens[2])) {
      return tokens[2];
    }
  }
  return null;
}

export function TtlPlannerTab({ currentReport, onNotify }: TtlPlannerTabProps) {
  // TTL Converter state
  const [ttlInput, setTtlInput] = useState("1h 30m");

  // SOA Serial state
  const [soaInput, setSoaInput] = useState(() => String(generateSoaSerial(new Date(), 1)));

  // Cutover Planner state
  const [currentTtlSec, setCurrentTtlSec] = useState("3600");
  const [migrationTtlSec, setMigrationTtlSec] = useState("60");
  const [cutoverLocal, setCutoverLocal] = useState(defaultCutoverLocalString);

  const parsedSeconds = useMemo(() => parseDuration(ttlInput), [ttlInput]);
  const soaInfo = useMemo(() => parseSoaSerial(soaInput), [soaInput]);
  const liveSoaSerial = useMemo(() => extractSoaSerialFromReport(currentReport), [currentReport]);

  const cutoverPlan = useMemo(() => {
    const dt = new Date(cutoverLocal);
    const iso = Number.isNaN(dt.getTime()) ? new Date(Date.now() + 86400_000).toISOString() : dt.toISOString();
    return planCutoverSchedule({
      currentTtlSec: Number(currentTtlSec) || 3600,
      migrationTtlSec: Number(migrationTtlSec) || 60,
      cutoverIso: iso,
    });
  }, [currentTtlSec, migrationTtlSec, cutoverLocal]);

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  const copyRunbook = async () => {
    const lines = [
      `# DNS Migration Cutover Plan`,
      `- Previous TTL: ${formatDuration(cutoverPlan.currentTtlSec)} (${cutoverPlan.currentTtlSec}s)`,
      `- Migration TTL: ${formatDuration(cutoverPlan.migrationTtlSec)} (${cutoverPlan.migrationTtlSec}s)`,
      `- Target Cutover (UTC): ${cutoverPlan.cutoverIso}`,
      "",
      ...cutoverPlan.steps.map(
        (s, i) =>
          `${i + 1}. **${s.offsetLabel}** (${s.timestampIso}) — **${s.title}**\n   ${s.detail}`,
      ),
    ];
    await copyText(lines.join("\n"), "cutover runbook Markdown");
  };

  const phaseBadge = (phase: string) => {
    switch (phase) {
      case "cutover":
        return "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300";
      case "verify":
        return "border-violet-500/40 bg-violet-500/15 text-violet-700 dark:text-violet-300";
      case "restore":
        return "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";
      case "drain":
        return "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300";
      default:
        return "border-line bg-surface-alt text-ink-secondary";
    }
  };

  return (
    <div className="space-y-4">
      {/* Row 1: TTL Duration Converter & SOA Serial Calculator */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* TTL Duration Converter */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4">
          <div className="flex items-center gap-2 border-b border-line pb-2.5">
            <Clock className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">TTL Duration Converter</h3>
              <p className="text-[11px] text-ink-muted">
                Convert between seconds and human durations (e.g. `3600`, `1h 30m`, `7d`, `2w`).
              </p>
            </div>
          </div>

          <input
            type="text"
            value={ttlInput}
            onChange={(e) => setTtlInput(e.target.value)}
            placeholder="e.g. 3600 or 1d 12h"
            className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          />

          {parsedSeconds !== null ? (
            <div className="grid grid-cols-2 gap-2.5 text-xs">
              <div className="rounded-lg border border-line bg-canvas p-2.5">
                <div className="flex items-center justify-between text-[11px] text-ink-muted">
                  <span>DNS TTL (Seconds)</span>
                  <button
                    type="button"
                    onClick={() => void copyText(String(parsedSeconds), "TTL seconds")}
                    className="text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" />
                  </button>
                </div>
                <div className="mt-1 font-mono text-sm font-bold text-ink">
                  {parsedSeconds.toLocaleString()}s
                </div>
              </div>
              <div className="rounded-lg border border-line bg-canvas p-2.5">
                <div className="text-[11px] text-ink-muted">Canonical Breakdown</div>
                <div className="mt-1 font-mono text-sm font-semibold text-sky-700 dark:text-sky-300">
                  {formatDuration(parsedSeconds)}
                </div>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-2.5 text-xs text-amber-800 dark:text-amber-200">
              Unrecognized duration format. Try e.g. `300`, `15m`, `1h 30m`, or `7d`.
            </div>
          )}

          <div className="space-y-1.5 pt-1">
            <div className="text-[11px] font-medium text-ink-muted">Common DNS TTL Presets</div>
            <div className="grid grid-cols-2 gap-1.5 sm:grid-cols-3">
              {COMMON_TTL_PRESETS.map((p) => (
                <button
                  key={p.seconds}
                  type="button"
                  onClick={() => setTtlInput(String(p.seconds))}
                  className="rounded-lg border border-line bg-canvas p-2 text-left transition hover:border-sky-500/40"
                >
                  <div className="flex items-center justify-between font-mono text-xs font-semibold text-ink">
                    <span>{p.label}</span>
                    <span className="text-[10px] text-sky-700 dark:text-sky-300">{p.seconds}s</span>
                  </div>
                  <div className="mt-0.5 line-clamp-1 text-[10px] text-ink-muted" title={p.useCase}>
                    {p.useCase}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* SOA Serial Calculator */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
            <div className="flex items-center gap-2">
              <Hash className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              <div>
                <h3 className="text-sm font-semibold text-ink">
                  SOA Serial Calculator (`YYYYMMDDnn`)
                </h3>
                <p className="text-[11px] text-ink-muted">
                  Parse RFC 1912 zone serials and compute the next monotonic serial number.
                </p>
              </div>
            </div>

            {liveSoaSerial && (
              <button
                type="button"
                onClick={() => {
                  setSoaInput(liveSoaSerial);
                  onNotify(`Loaded SOA serial ${liveSoaSerial} from ${currentReport?.domain}`);
                }}
                className="inline-flex items-center gap-1 rounded-lg border border-sky-500/35 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 dark:text-sky-300"
              >
                <Sparkles className="h-3 w-3" />
                Load {currentReport?.domain}
              </button>
            )}
          </div>

          <div className="flex items-center gap-2">
            <input
              type="text"
              value={soaInput}
              onChange={(e) => setSoaInput(e.target.value)}
              placeholder="2026051501"
              className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={() => setSoaInput(String(generateSoaSerial(new Date(), 1)))}
              className="rounded-lg border border-line bg-surface-alt px-2.5 py-2 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              Today (#01)
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2.5 text-xs">
            <div className="rounded-lg border border-line bg-canvas p-2.5">
              <div className="text-[11px] text-ink-muted">Parsed Date &amp; Revision</div>
              {soaInfo.validFormat ? (
                <div className="mt-1 space-y-0.5">
                  <div className="font-mono font-semibold text-ink">
                    {soaInfo.dateStr} · Rev #{String(soaInfo.revision ?? 0).padStart(2, "0")}
                  </div>
                  <div className="text-[10px] text-emerald-700 dark:text-emerald-300">
                    Valid RFC 1912 YYYYMMDDnn {soaInfo.isToday ? "(Today)" : ""}
                  </div>
                </div>
              ) : (
                <div className="mt-1 text-[11px] text-amber-700 dark:text-amber-300">
                  Non-date format (e.g. Unix epoch or counter)
                </div>
              )}
            </div>

            <div className="rounded-lg border border-emerald-500/35 bg-emerald-500/[0.06] p-2.5">
              <div className="flex items-center justify-between text-[11px] text-ink-muted">
                <span>Recommended Next Serial</span>
                <button
                  type="button"
                  onClick={() => void copyText(String(soaInfo.nextSerial), "next SOA serial")}
                  className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                >
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>
              <div className="mt-1 font-mono text-sm font-bold text-emerald-700 dark:text-emerald-300">
                {soaInfo.nextSerial}
              </div>
              <button
                type="button"
                onClick={() => setSoaInput(String(soaInfo.nextSerial))}
                className="mt-1 text-[10px] text-ink-muted hover:text-ink hover:underline"
              >
                Increment again →
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Row 2: DNS Migration Cutover Timeline */}
      <div className="space-y-4 rounded-xl border border-line bg-surface p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
          <div className="flex items-center gap-2">
            <CalendarClock className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">DNS Migration Cutover Planner</h3>
              <p className="text-[11px] text-ink-muted">
                Calculate exact pre-cutover TTL lowering, verification, switchover, and restoration timestamps.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => void copyRunbook()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
          >
            <Copy className="h-3.5 w-3.5" />
            Copy Markdown Runbook
          </button>
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
          <div>
            <label className="mb-1 block text-[11px] text-ink-muted">
              Current Production TTL (sec)
            </label>
            <div className="flex items-center gap-1.5">
              <input
                type="number"
                min={0}
                value={currentTtlSec}
                onChange={(e) => setCurrentTtlSec(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
              />
              <span className="shrink-0 font-mono text-[11px] text-ink-muted">
                ({formatDuration(Number(currentTtlSec) || 0)})
              </span>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-[11px] text-ink-muted">
              Migration Cutover TTL (sec)
            </label>
            <div className="flex items-center gap-1.5">
              <input
                type="number"
                min={0}
                value={migrationTtlSec}
                onChange={(e) => setMigrationTtlSec(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
              />
              <span className="shrink-0 font-mono text-[11px] text-ink-muted">
                ({formatDuration(Number(migrationTtlSec) || 0)})
              </span>
            </div>
          </div>

          <div>
            <label className="mb-1 block text-[11px] text-ink-muted">
              Target Cutover Time (Local)
            </label>
            <input
              type="datetime-local"
              value={cutoverLocal}
              onChange={(e) => setCutoverLocal(e.target.value)}
              className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
            />
          </div>
        </div>

        {cutoverPlan.warnings.length > 0 && (
          <div className="space-y-1.5 rounded-lg border border-amber-500/35 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
            {cutoverPlan.warnings.map((w, idx) => (
              <div key={idx} className="flex items-start gap-2">
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                <span>{w}</span>
              </div>
            ))}
          </div>
        )}

        {/* Timeline Steps */}
        <div className="space-y-2.5">
          {cutoverPlan.steps.map((step, idx) => (
            <div
              key={step.id}
              className="flex flex-col gap-2 rounded-xl border border-line bg-canvas p-3.5 sm:flex-row sm:items-start sm:justify-between"
            >
              <div className="space-y-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-[11px] font-bold text-ink-muted">
                    Step {idx + 1}
                  </span>
                  <span
                    className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold ${phaseBadge(
                      step.phase,
                    )}`}
                  >
                    {step.offsetLabel}
                  </span>
                  <span className="text-xs font-semibold text-ink">{step.title}</span>
                </div>
                <p className="text-xs text-ink-secondary">{step.detail}</p>
              </div>

              <div className="shrink-0 text-left sm:text-right">
                <div className="font-mono text-[11px] font-semibold text-ink">
                  {new Date(step.timestampIso).toLocaleString()}
                </div>
                <div className="font-mono text-[10px] text-ink-muted">
                  UTC: {step.timestampIso.slice(0, 19).replace("T", " ")}Z
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="flex items-center justify-between text-[11px] text-ink-muted">
          <span className="inline-flex items-center gap-1">
            <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            Total migration window: {formatDuration(cutoverPlan.totalWindowSec)}
          </span>
          <span>Keep old origin online until T+{formatDuration(Math.max(cutoverPlan.migrationTtlSec * 2, 3600))}</span>
        </div>
      </div>
    </div>
  );
}
