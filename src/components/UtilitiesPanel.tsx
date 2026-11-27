import {
  ArrowRight,
  Bot,
  Calculator,
  CalendarClock,
  Copy,
  FileCode2,
  FileKey2,
  FileSpreadsheet,
  Globe2,
  Languages,
  MailSearch,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Wrench,
} from "lucide-react";
import { type ComponentType, useMemo, useState } from "react";
import { copyToClipboard } from "../lib/api";
import { inspectDomainScripts, toAsciiDomain, toUnicodeDomain } from "../lib/punycode";
import type { DnsQueryReport } from "../types/dns";
import { CidrCalculator } from "./CidrCalculator";
import { DmarcReportViewerTab } from "./utilities/DmarcReportViewerTab";
import { DnsblCheckerTab } from "./utilities/DnsblCheckerTab";
import { EmailHeaderAnalyzerTab } from "./utilities/EmailHeaderAnalyzerTab";
import { PemDecoderTab } from "./utilities/PemDecoderTab";
import { RecordBuilderTab } from "./utilities/RecordBuilderTab";
import { RobotsTesterTab } from "./utilities/RobotsTesterTab";
import { SecurityHeadersTab } from "./utilities/SecurityHeadersTab";
import { TldCheckerTab } from "./utilities/TldCheckerTab";
import { TtlPlannerTab } from "./utilities/TtlPlannerTab";

export interface UtilitiesPanelProps {
  defaultDomain: string;
  currentReport?: DnsQueryReport | null;
  onInspectDomain: (domain: string, options?: { dkimSelectors?: string }) => void;
  onDeepScanIp?: (ip: string) => void;
  onNotify: (msg: string) => void;
}

type UtilToolId =
  | "builder"
  | "ttl"
  | "punycode"
  | "email-headers"
  | "dmarc-viewer"
  | "security-headers"
  | "pem"
  | "robots"
  | "cidr"
  | "dnsbl"
  | "tld";

interface ToolDef {
  id: UtilToolId;
  label: string;
  shortDesc: string;
  icon: ComponentType<{ className?: string }>;
  badge?: "Live" | "Offline";
}

interface ToolGroup {
  title: string;
  items: ToolDef[];
}

const TOOL_GROUPS: ToolGroup[] = [
  {
    title: "DNS & Records",
    items: [
      {
        id: "builder",
        label: "Record Builder & Linter",
        shortDesc: "SPF, DMARC, CAA, SRV, MTA-STS, BIMI, DKIM keygen, TLSA & TXT splitter",
        icon: FileCode2,
      },
      {
        id: "ttl",
        label: "TTL & SOA Planner",
        shortDesc: "Duration converter, YYYYMMDDnn SOA serials & migration cutover timeline",
        icon: CalendarClock,
      },
      {
        id: "punycode",
        label: "IDN / Punycode",
        shortDesc: "Unicode ↔ xn-- conversion & homoglyph script spoof detector",
        icon: Languages,
      },
    ],
  },
  {
    title: "Email",
    items: [
      {
        id: "email-headers",
        label: "Email Header Analyzer",
        shortDesc: "Trace Received hops, SPF/DKIM/DMARC/ARC results & alignment",
        icon: MailSearch,
      },
      {
        id: "dmarc-viewer",
        label: "DMARC / TLS-RPT Viewer",
        shortDesc: "Parse DMARC XML (.xml/.xml.gz) & SMTP TLS-RPT JSON reports",
        icon: FileSpreadsheet,
      },
    ],
  },
  {
    title: "Security & Web",
    items: [
      {
        id: "security-headers",
        label: "Security Headers & CSP",
        shortDesc: "CSP builder/grader, HSTS preload, Permissions-Policy & server configs",
        icon: Shield,
      },
      {
        id: "pem",
        label: "PEM / CSR Decoder",
        shortDesc: "Decode X.509 certs, chains, CSRs & generate 1-click DANE TLSA",
        icon: FileKey2,
      },
      {
        id: "robots",
        label: "Robots.txt Tester",
        shortDesc: "Fetch live robots.txt & simulate Search / AI crawler path rules",
        icon: Bot,
        badge: "Live",
      },
    ],
  },
  {
    title: "Network & Recon",
    items: [
      {
        id: "cidr",
        label: "CIDR & Reverse PTR",
        shortDesc: "IPv4/IPv6 subnetting, membership test, PTR zones & SPF tokens",
        icon: Calculator,
      },
      {
        id: "dnsbl",
        label: "DNSBL Reputation",
        shortDesc: "Check any IPv4 address or domain across major spam blacklists",
        icon: ShieldAlert,
        badge: "Live",
      },
      {
        id: "tld",
        label: "TLD Availability",
        shortDesc: "Check domain registration availability across up to 24 TLDs",
        icon: Sparkles,
        badge: "Live",
      },
    ],
  },
];

const ALL_TOOLS: ToolDef[] = TOOL_GROUPS.flatMap((g) => g.items);

export function UtilitiesPanel({
  defaultDomain,
  currentReport,
  onInspectDomain,
  onDeepScanIp,
  onNotify,
}: UtilitiesPanelProps) {
  const [activeTool, setActiveTool] = useState<UtilToolId>("builder");
  const [toolFilter, setToolFilter] = useState("");

  // Cross-jump state for DNSBL tab
  const [dnsblJumpTarget, setDnsblJumpTarget] = useState<string | undefined>(undefined);
  const [dnsblAutoRunNonce, setDnsblAutoRunNonce] = useState(0);

  // Punycode / IDN State
  const [idnInput, setIdnInput] = useState("münchen.de");
  const trimmedIdn = idnInput.trim();
  const isPunyInput = trimmedIdn.toLowerCase().includes("xn--");
  const asciiConv = useMemo(() => toAsciiDomain(trimmedIdn), [trimmedIdn]);
  const unicodeConv = useMemo(
    () => toUnicodeDomain(isPunyInput ? trimmedIdn : asciiConv.ascii),
    [trimmedIdn, isPunyInput, asciiConv.ascii],
  );
  const scriptAudit = useMemo(
    () => inspectDomainScripts(unicodeConv.unicode || trimmedIdn),
    [unicodeConv.unicode, trimmedIdn],
  );

  const activeToolDef = useMemo(
    () => ALL_TOOLS.find((t) => t.id === activeTool) ?? ALL_TOOLS[0],
    [activeTool],
  );

  const filteredGroups = useMemo(() => {
    const q = toolFilter.trim().toLowerCase();
    if (!q) return TOOL_GROUPS;
    return TOOL_GROUPS.map((group) => ({
      ...group,
      items: group.items.filter(
        (item) =>
          item.label.toLowerCase().includes(q) ||
          item.shortDesc.toLowerCase().includes(q) ||
          group.title.toLowerCase().includes(q),
      ),
    })).filter((g) => g.items.length > 0);
  }, [toolFilter]);

  const handleJumpToDnsbl = (target: string) => {
    setDnsblJumpTarget(target);
    setDnsblAutoRunNonce((n) => n + 1);
    setActiveTool("dnsbl");
    onNotify(`Running DNSBL reputation check for ${target}`);
  };

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:items-start">
      {/* Left Navigation Rail (Desktop) + Grouped Pill Bar (Compact) */}
      <aside className="w-full shrink-0 rounded-xl border border-line bg-surface p-3 lg:sticky lg:top-4 lg:w-60">
        <div className="mb-2.5 flex items-center gap-2 border-b border-line pb-2.5">
          <Wrench className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <div>
            <h2 className="text-xs font-semibold text-ink">Utilities Suite</h2>
            <p className="text-[10px] text-ink-muted">11 DNS, Email, Security &amp; Net tools</p>
          </div>
        </div>

        {/* Quick tool filter on desktop */}
        <div className="relative mb-3 hidden lg:block">
          <Search className="pointer-events-none absolute left-2.5 top-2 h-3.5 w-3.5 text-ink-muted" />
          <input
            type="text"
            value={toolFilter}
            onChange={(e) => setToolFilter(e.target.value)}
            placeholder="Filter utilities..."
            className="w-full rounded-lg border border-line bg-canvas py-1.5 pl-8 pr-2.5 text-[11px] text-ink placeholder:text-ink-muted focus:border-sky-500 focus:outline-none"
          />
        </div>

        {/* Grouped nav */}
        <nav className="space-y-3">
          {filteredGroups.map((group) => (
            <div key={group.title}>
              <div className="mb-1 px-2 text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                {group.title}
              </div>
              <div className="flex flex-wrap gap-1 lg:flex-col lg:gap-0.5">
                {group.items.map((tool) => {
                  const Icon = tool.icon;
                  const active = activeTool === tool.id;
                  return (
                    <button
                      key={tool.id}
                      type="button"
                      onClick={() => setActiveTool(tool.id)}
                      className={`inline-flex items-center justify-between gap-2 rounded-lg px-2.5 py-1.5 text-left text-xs font-medium transition lg:w-full ${
                        active
                          ? "bg-sky-500/12 text-sky-700 ring-1 ring-sky-500/30 dark:text-sky-300"
                          : "text-ink-secondary hover:bg-surface-alt hover:text-ink"
                      }`}
                    >
                      <span className="flex items-center gap-2 truncate">
                        <Icon
                          className={`h-3.5 w-3.5 shrink-0 ${
                            active ? "text-sky-600 dark:text-sky-400" : "text-ink-muted"
                          }`}
                        />
                        <span className="truncate">{tool.label}</span>
                      </span>
                      {tool.badge && (
                        <span className="hidden rounded bg-surface-alt px-1.5 py-0.5 text-[9px] font-semibold uppercase text-ink-muted lg:inline">
                          {tool.badge}
                        </span>
                      )}
                    </button>
                  );
                })}
              </div>
            </div>
          ))}
        </nav>
      </aside>

      {/* Active Utility Workspace */}
      <div className="min-w-0 flex-1 space-y-4">
        {/* Compact Tool Header */}
        <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-4 py-3">
          <div className="flex items-center gap-2.5">
            <activeToolDef.icon className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">{activeToolDef.label}</h3>
              <p className="text-[11px] text-ink-muted">{activeToolDef.shortDesc}</p>
            </div>
          </div>
          {defaultDomain && (
            <span className="rounded-full border border-line bg-surface-alt px-2.5 py-0.5 font-mono text-[11px] text-ink-secondary">
              Context: {defaultDomain}
            </span>
          )}
        </div>

        {/* Tool Views */}
        {activeTool === "builder" && (
          <RecordBuilderTab defaultDomain={defaultDomain} onNotify={onNotify} />
        )}

        {activeTool === "ttl" && (
          <TtlPlannerTab currentReport={currentReport} onNotify={onNotify} />
        )}

        {activeTool === "punycode" && (
          <div className="space-y-4">
            <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
              <div className="flex flex-wrap items-end gap-3">
                <div className="min-w-[240px] flex-1">
                  <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                    Enter Unicode IDN Domain or Punycode (`xn--...`)
                  </label>
                  <input
                    type="text"
                    value={idnInput}
                    onChange={(e) => setIdnInput(e.target.value)}
                    placeholder="münchen.de or xn--mnchen-3ya.de"
                    className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                  />
                </div>

                {asciiConv.ascii && (
                  <button
                    type="button"
                    onClick={() => onInspectDomain(asciiConv.ascii)}
                    className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                  >
                    <Globe2 className="h-3.5 w-3.5" />
                    Inspect in Domain Inspector
                  </button>
                )}
              </div>

              <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                <span className="text-ink-muted">Examples:</span>
                {[
                  ["münchen.de", "German umlaut IDN"],
                  ["аррӏе.com", "Cyrillic homoglyph spoof of apple.com"],
                  ["xn--bcher-kva.example", "Punycode decode test"],
                ].map(([sample, title]) => (
                  <button
                    key={sample}
                    type="button"
                    title={title}
                    onClick={() => setIdnInput(sample)}
                    className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                  >
                    {sample}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
              <div className="rounded-xl border border-line bg-surface p-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-ink">DNS ASCII (Punycode A-Label)</span>
                  <button
                    type="button"
                    onClick={() => void copyText(asciiConv.ascii, "Punycode domain")}
                    className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                  >
                    <Copy className="h-3 w-3" /> Copy
                  </button>
                </div>
                <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-3 font-mono text-sm font-semibold text-sky-700 dark:text-sky-300">
                  {asciiConv.ascii || "—"}
                </div>
                {asciiConv.error && (
                  <div className="mt-1 text-xs text-rose-600 dark:text-rose-400">
                    {asciiConv.error}
                  </div>
                )}
              </div>

              <div className="rounded-xl border border-line bg-surface p-4">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-ink">Unicode Display (U-Label)</span>
                  <button
                    type="button"
                    onClick={() => void copyText(unicodeConv.unicode, "Unicode domain")}
                    className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                  >
                    <Copy className="h-3 w-3" /> Copy
                  </button>
                </div>
                <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-3 font-mono text-sm font-semibold text-ink">
                  {unicodeConv.unicode || "—"}
                </div>
                {unicodeConv.error && (
                  <div className="mt-1 text-xs text-rose-600 dark:text-rose-400">
                    {unicodeConv.error}
                  </div>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-sm font-semibold text-ink">
                  Script &amp; Homoglyph Spoof Analysis
                </div>
                <div className="flex items-center gap-2 text-xs">
                  <span className="text-ink-muted">
                    Scripts: {scriptAudit.scripts.join(", ") || "None"}
                  </span>
                  {scriptAudit.mixedScript ||
                  scriptAudit.confusables.some((c) => c.lookalikeLatin) ? (
                    <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 font-semibold text-rose-700 dark:text-rose-300">
                      <ShieldAlert className="h-3.5 w-3.5" />
                      Homoglyph / Spoof Risk
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 font-semibold text-emerald-700 dark:text-emerald-300">
                      <ShieldCheck className="h-3.5 w-3.5" />
                      Clean Single-Script Label
                    </span>
                  )}
                </div>
              </div>

              {scriptAudit.confusables.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                      <tr>
                        <th className="px-3 py-2">Character</th>
                        <th className="px-3 py-2">Unicode Code Point</th>
                        <th className="px-3 py-2">Script</th>
                        <th className="px-3 py-2">Visual Spoof Target</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line font-mono">
                      {scriptAudit.confusables.map((c, idx) => (
                        <tr key={idx}>
                          <td className="px-3 py-2 text-sm font-bold text-ink">{c.char}</td>
                          <td className="px-3 py-2 text-ink-secondary">{c.codePoint}</td>
                          <td className="px-3 py-2 text-ink-secondary">{c.script}</td>
                          <td className="px-3 py-2">
                            {c.lookalikeLatin ? (
                              <span className="inline-flex items-center gap-1 text-rose-700 dark:text-rose-300">
                                Imitates ASCII <ArrowRight className="h-3 w-3" /> &apos;
                                {c.lookalikeLatin}&apos;
                              </span>
                            ) : (
                              <span className="text-ink-muted">Non-ASCII IDN character</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-ink-muted">
                  No non-ASCII characters found — standard ASCII hostname.
                </p>
              )}
            </div>
          </div>
        )}

        {activeTool === "email-headers" && (
          <EmailHeaderAnalyzerTab
            onInspectDomain={onInspectDomain}
            onCheckDnsbl={handleJumpToDnsbl}
            onDeepScanIp={onDeepScanIp}
            onNotify={onNotify}
          />
        )}

        {activeTool === "dmarc-viewer" && (
          <DmarcReportViewerTab
            onInspectDomain={(d) => onInspectDomain(d)}
            onCheckDnsbl={handleJumpToDnsbl}
            onDeepScanIp={onDeepScanIp}
            onNotify={onNotify}
          />
        )}

        {activeTool === "security-headers" && (
          <SecurityHeadersTab currentReport={currentReport} onNotify={onNotify} />
        )}

        {activeTool === "pem" && <PemDecoderTab onNotify={onNotify} />}

        {activeTool === "robots" && (
          <RobotsTesterTab defaultDomain={defaultDomain} onNotify={onNotify} />
        )}

        {activeTool === "cidr" && <CidrCalculator onNotify={onNotify} />}

        {activeTool === "dnsbl" && (
          <DnsblCheckerTab
            defaultDomain={defaultDomain}
            initialTarget={dnsblJumpTarget}
            autoRunNonce={dnsblAutoRunNonce}
            onInspectDomain={(d) => onInspectDomain(d)}
            onDeepScanIp={onDeepScanIp}
            onNotify={onNotify}
          />
        )}

        {activeTool === "tld" && (
          <TldCheckerTab
            defaultDomain={defaultDomain}
            onInspectDomain={(d) => onInspectDomain(d)}
            onNotify={onNotify}
          />
        )}
      </div>
    </div>
  );
}
