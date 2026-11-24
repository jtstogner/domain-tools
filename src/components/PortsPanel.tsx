import {
  AlertTriangle,
  CheckCircle2,
  Loader2,
  Lock,
  Plug,
  RefreshCw,
  Search,
  Server,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { scanPorts } from "../lib/api";
import type { PortScanItem, PortScanReport } from "../types/dns";

type PortFilter = "all" | "open" | "closed" | "filtered";

function StatusBadge({ status }: { status: PortScanItem["status"] }) {
  switch (status) {
    case "open":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
          <CheckCircle2 className="h-3 w-3" />
          Open
        </span>
      );
    case "closed":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2.5 py-0.5 text-[11px] font-medium text-ink-muted">
          <XCircle className="h-3 w-3" />
          Closed
        </span>
      );
    case "filtered":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-[11px] font-medium text-amber-700 dark:text-amber-300">
          <Lock className="h-3 w-3" />
          Filtered
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-[11px] font-medium text-rose-700 dark:text-rose-300">
          <AlertTriangle className="h-3 w-3" />
          Error
        </span>
      );
  }
}

interface PortsPanelProps {
  report: PortScanReport;
  onNotify: (msg: string) => void;
}

export function PortsPanel({ report, onNotify }: PortsPanelProps) {
  const [currentReport, setCurrentReport] = useState<PortScanReport>(report);
  const [selectedIp, setSelectedIp] = useState<string>(report.target_ip ?? "");
  const [customPortsInput, setCustomPortsInput] = useState("");
  const [scanning, setScanning] = useState(false);
  const [filterStatus, setFilterStatus] = useState<PortFilter>("all");
  const [searchText, setSearchText] = useState("");

  useEffect(() => {
    setCurrentReport(report);
    setSelectedIp(report.target_ip ?? "");
  }, [report]);

  const availableIps =
    (report.available_ips?.length ?? 0) > 0
      ? report.available_ips
      : (currentReport.available_ips ?? []);

  const parseCustomPorts = (): number[] => {
    const parsed = customPortsInput
      .split(/[,\s]+/)
      .map((s) => Number.parseInt(s.trim(), 10))
      .filter((n) => Number.isInteger(n) && n >= 1 && n <= 65535);
    return Array.from(new Set(parsed));
  };

  const runRescan = async (overrideIp?: string) => {
    const target = overrideIp ?? (selectedIp || currentReport.target_host);
    if (!target) return;
    setScanning(true);
    try {
      const next = await scanPorts(target, parseCustomPorts());
      setCurrentReport({
        ...next,
        available_ips: availableIps.length > 0 ? availableIps : next.available_ips,
      });
      if (next.target_ip) {
        setSelectedIp(next.target_ip);
      }
      onNotify(`Scanned ${next.total_checked} ports on ${next.target_ip ?? target}`);
    } catch (err) {
      onNotify(`Port scan failed: ${String(err)}`);
    } finally {
      setScanning(false);
    }
  };

  const filteredPorts = useMemo(() => {
    const needle = searchText.trim().toLowerCase();
    return (currentReport.ports ?? []).filter((item) => {
      if (filterStatus !== "all" && item.status !== filterStatus) return false;
      if (needle) {
        const hitPort = String(item.port).includes(needle);
        const hitService = item.service.toLowerCase().includes(needle);
        const hitCat = item.category.toLowerCase().includes(needle);
        const hitBanner = item.banner?.toLowerCase().includes(needle) ?? false;
        if (!hitPort && !hitService && !hitCat && !hitBanner) return false;
      }
      return true;
    });
  }, [currentReport.ports, filterStatus, searchText]);

  const highRiskOpen = useMemo(
    () =>
      (currentReport.ports ?? []).filter(
        (p) => p.status === "open" && p.risk_level === "high",
      ),
    [currentReport.ports],
  );

  return (
    <div className="space-y-4">
      {currentReport.error && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-900 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
          <div>
            <div className="font-semibold">Port Scan Unavailable</div>
            <div className="mt-0.5 text-xs text-amber-800 dark:text-amber-300/90">
              {currentReport.error}
            </div>
          </div>
        </div>
      )}

      {/* Summary Cards */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            Target Server IP
          </div>
          <div className="mt-1.5 truncate font-mono text-sm font-semibold text-ink">
            {currentReport.target_ip ?? "—"}
          </div>
          {availableIps.length > 1 ? (
            <div className="mt-2 flex flex-wrap gap-1">
              {availableIps.map((ip) => (
                <button
                  key={ip}
                  type="button"
                  disabled={scanning}
                  onClick={() => {
                    setSelectedIp(ip);
                    void runRescan(ip);
                  }}
                  className={`rounded border px-1.5 py-0.5 font-mono text-[10px] transition ${
                    ip === currentReport.target_ip
                      ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                      : "border-line bg-canvas text-ink-muted hover:text-ink"
                  }`}
                >
                  {ip}
                </button>
              ))}
            </div>
          ) : (
            <div className="mt-1 font-mono text-[11px] text-ink-muted">
              {currentReport.latency_ms}ms scan time
            </div>
          )}
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Open Ports
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-emerald-700 dark:text-emerald-300">
            {currentReport.open_count}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Accepting TCP connections
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Closed / Refused
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-ink-secondary">
            {currentReport.closed_count}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            Host refused connection
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-4">
          <div className="text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Filtered / Timed Out
          </div>
          <div className="mt-1.5 font-mono text-2xl font-bold text-amber-700 dark:text-amber-300">
            {currentReport.filtered_count}
          </div>
          <div className="mt-1 text-[11px] text-ink-muted">
            {currentReport.total_checked} total checked
          </div>
        </div>
      </div>

      {highRiskOpen.length > 0 && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-900 dark:text-rose-200">
          <ShieldAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
          <div>
            <div className="font-semibold">
              High-Risk Ports Exposed Publicly (
              {highRiskOpen.map((p) => `${p.port}/${p.service}`).join(", ")})
            </div>
            <div className="mt-0.5 text-rose-800 dark:text-rose-300/90">
              Consider restricting access to database or unencrypted management
              ports via firewall rules or VPN.
            </div>
          </div>
        </div>
      )}

      {/* Custom Port Rescan + Filter Bar */}
      <div className="flex flex-col gap-3 rounded-xl border border-line bg-surface p-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          {(
            [
              ["all", `All (${currentReport.total_checked})`],
              ["open", `Open (${currentReport.open_count})`],
              ["closed", `Closed (${currentReport.closed_count})`],
              ["filtered", `Filtered (${currentReport.filtered_count})`],
            ] as [PortFilter, string][]
          ).map(([id, label]) => (
            <button
              key={id}
              type="button"
              onClick={() => setFilterStatus(id)}
              className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
                filterStatus === id
                  ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                  : "border-line bg-canvas text-ink-muted hover:text-ink"
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <div className="relative w-48">
            <Search className="pointer-events-none absolute left-3 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-muted" />
            <input
              type="text"
              value={searchText}
              onChange={(e) => setSearchText(e.target.value)}
              placeholder="Filter port/service..."
              className="w-full rounded-lg border border-line-strong bg-canvas py-1.5 pl-8 pr-3 text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
          </div>

          <input
            type="text"
            value={customPortsInput}
            onChange={(e) => setCustomPortsInput(e.target.value)}
            placeholder="Extra ports (e.g. 2222, 3000)"
            className="w-48 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
          />

          <button
            type="button"
            disabled={scanning || !currentReport.target_ip}
            onClick={() => void runRescan()}
            className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary transition hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300 disabled:opacity-50"
          >
            {scanning ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <RefreshCw className="h-3.5 w-3.5" />
            )}
            Rescan
          </button>
        </div>
      </div>

      {/* Ports Table */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        {filteredPorts.length === 0 ? (
          <div className="px-6 py-12 text-center text-xs text-ink-muted">
            <Plug className="mx-auto mb-2 h-6 w-6 text-ink-muted/60" />
            No ports matched this filter.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-left text-xs">
              <thead>
                <tr className="border-b border-line bg-surface-alt text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                  <th className="px-4 py-3">Port</th>
                  <th className="px-4 py-3">Service</th>
                  <th className="px-4 py-3">Category</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Banner / Notes</th>
                  <th className="px-4 py-3 text-right">Latency</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-line">
                {filteredPorts.map((item) => (
                  <tr
                    key={item.port}
                    className={
                      item.status === "open" && item.risk_level === "high"
                        ? "bg-rose-500/[0.06]"
                        : item.status === "open"
                          ? "bg-emerald-500/[0.03] hover:bg-surface-alt/70"
                          : "hover:bg-surface-alt/70"
                    }
                  >
                    <td className="whitespace-nowrap px-4 py-2.5 align-top font-mono font-semibold text-ink">
                      {item.port}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 align-top font-medium text-ink">
                      {item.service}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 align-top">
                      <span className="rounded border border-line bg-canvas px-2 py-0.5 text-[11px] text-ink-secondary">
                        {item.category}
                      </span>
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 align-top">
                      <StatusBadge status={item.status} />
                    </td>
                    <td className="px-4 py-2.5 align-top">
                      {item.banner && (
                        <div className="mb-1 break-all rounded bg-canvas px-2 py-1 font-mono text-[11px] text-ink">
                          {item.banner}
                        </div>
                      )}
                      {item.note ? (
                        <span
                          className={
                            item.risk_level === "high"
                              ? "font-medium text-rose-700 dark:text-rose-300"
                              : item.risk_level === "caution"
                                ? "text-amber-700 dark:text-amber-300"
                                : "text-ink-muted"
                          }
                        >
                          {item.note}
                        </span>
                      ) : !item.banner ? (
                        <span className="text-ink-muted">—</span>
                      ) : null}
                    </td>
                    <td className="whitespace-nowrap px-4 py-2.5 text-right align-top font-mono text-ink-muted">
                      {item.latency_ms}ms
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
