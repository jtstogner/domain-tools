import {
  Activity,
  Copy,
  Database,
  FileCode2,
  FileSearch,
  Globe2,
  HeartPulse,
  Layers,
  Network,
  Shield,
  AlertCircle,
} from "lucide-react";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { DomainHealthPanel } from "./components/DomainHealthPanel";
import { ExportMenu } from "./components/ExportMenu";
import { HistorySidebar } from "./components/HistorySidebar";
import { PropagationView } from "./components/PropagationView";
import { ALL_RECORD_TYPES, QueryBar } from "./components/QueryBar";
import { RecordsTable } from "./components/RecordsTable";
import { SecurityPanel } from "./components/SecurityPanel";
import { SubdomainsPanel } from "./components/SubdomainsPanel";
import { WebsitePanel } from "./components/WebsitePanel";
import { WhoisPanel } from "./components/WhoisPanel";
import { copyToClipboard, queryDomain } from "./lib/api";
import { formatAsZoneFile } from "./lib/export";
import type {
  DnsQueryReport,
  HistoryEntry,
  RecordTypeName,
  ResolverId,
} from "./types/dns";

type ActiveTab =
  | "records"
  | "propagation"
  | "security"
  | "health"
  | "subdomains"
  | "whois"
  | "website"
  | "zone";

const HISTORY_KEY = "domain_tools_history_v1";
const LEGACY_HISTORY_KEY = "dns_verifier_history_v1";

function loadHistory(): HistoryEntry[] {
  try {
    const raw =
      localStorage.getItem(HISTORY_KEY) ??
      localStorage.getItem(LEGACY_HISTORY_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function App() {
  const [domain, setDomain] = useState("");
  const [recordTypes, setRecordTypes] =
    useState<RecordTypeName[]>(ALL_RECORD_TYPES);
  const [resolvers, setResolvers] = useState<ResolverId[]>([
    "cloudflare",
    "google",
    "quad9",
    "system",
  ]);
  const [customResolver, setCustomResolver] = useState("");
  const [dkimSelectorsInput, setDkimSelectorsInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<DnsQueryReport | null>(null);
  const [selectedResolverId, setSelectedResolverId] = useState("cloudflare");
  const [activeTab, setActiveTab] = useState<ActiveTab>("records");
  const [history, setHistory] = useState<HistoryEntry[]>(loadHistory);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [toast, setToast] = useState<string | null>(null);

  const domainInputRef = useRef<HTMLInputElement>(null);

  const notify = useCallback((message: string) => {
    setToast(message);
    setTimeout(() => {
      setToast((prev) => (prev === message ? null : prev));
    }, 2400);
  }, []);

  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        domainInputRef.current?.focus();
        domainInputRef.current?.select();
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, []);

  const runLookup = useCallback(
    async (overrideDomain?: string) => {
      const targetDomain = (overrideDomain ?? domain).trim();
      if (!targetDomain) return;

      setLoading(true);
      setError(null);

      const dkimSelectors = dkimSelectorsInput
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean);

      try {
        const res = await queryDomain({
          domain: targetDomain,
          record_types: recordTypes,
          resolvers,
          custom_resolver: customResolver.trim() || null,
          dkim_selectors: dkimSelectors,
        });

        setReport(res);
        setDomain(res.domain);
        const firstOk =
          res.resolvers.find((r) => r.status === "ok") ?? res.resolvers[0];
        if (firstOk) {
          setSelectedResolverId(firstOk.id);
        }

        const totalRecords =
          firstOk?.results.reduce((acc, r) => acc + r.records.length, 0) ?? 0;

        const entry: HistoryEntry = {
          domain: res.domain,
          queried_at: res.queried_at,
          spfStatus: res.security.spf.status,
          dmarcStatus: res.security.dmarc.status,
          dkimStatus: res.security.dkim.status,
          dnssecStatus: res.security.dnssec.status,
          totalRecords,
        };

        setHistory((prev) => {
          const next = [
            entry,
            ...prev.filter((item) => item.domain !== res.domain),
          ].slice(0, 25);
          localStorage.setItem(HISTORY_KEY, JSON.stringify(next));
          return next;
        });
      } catch (err) {
        setError(String(err));
      } finally {
        setLoading(false);
      }
    },
    [customResolver, dkimSelectorsInput, domain, recordTypes, resolvers],
  );

  const zoneOutput = useMemo(
    () => (report ? formatAsZoneFile(report, selectedResolverId) : ""),
    [report, selectedResolverId],
  );

  return (
    <div className="flex h-screen w-screen overflow-hidden bg-[#0b0f17] text-slate-100">
      <HistorySidebar
        history={history}
        collapsed={sidebarCollapsed}
        onToggleCollapse={() => setSidebarCollapsed((v) => !v)}
        onSelectDomain={(d) => {
          setDomain(d);
          void runLookup(d);
        }}
        onClearHistory={() => {
          setHistory([]);
          localStorage.removeItem(HISTORY_KEY);
        }}
        activeDomain={report?.domain}
      />

      <div className="flex min-w-0 flex-1 flex-col overflow-hidden">
        <header className="flex items-center justify-between border-b border-slate-800 bg-[#0e1420] px-6 py-3">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-sky-500/15 ring-1 ring-sky-500/30">
              <Globe2 className="h-4 w-4 text-sky-400" />
            </div>
            <div>
              <h1 className="text-sm font-semibold tracking-tight text-slate-100">
                Domain Tools
              </h1>
              <p className="text-[11px] text-slate-400">
                DNS records, propagation, security, health, subdomains, WHOIS &amp; web stack
              </p>
            </div>
          </div>

          {report && (
            <ExportMenu
              report={report}
              selectedResolverId={selectedResolverId}
              onNotify={notify}
            />
          )}
        </header>

        <main className="flex-1 overflow-y-auto p-6">
          <div className="mx-auto max-w-7xl space-y-5">
            <QueryBar
              domain={domain}
              onDomainChange={setDomain}
              recordTypes={recordTypes}
              onRecordTypesChange={setRecordTypes}
              resolvers={resolvers}
              onResolversChange={setResolvers}
              customResolver={customResolver}
              onCustomResolverChange={setCustomResolver}
              dkimSelectorsInput={dkimSelectorsInput}
              onDkimSelectorsInputChange={setDkimSelectorsInput}
              loading={loading}
              onSubmit={runLookup}
              inputRef={domainInputRef}
            />

            {error && (
              <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
                <AlertCircle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
                <div>
                  <div className="font-semibold">DNS Lookup Failed</div>
                  <div className="mt-0.5 text-xs text-rose-300/90">{error}</div>
                </div>
              </div>
            )}

            {!report && !loading && !error && (
              <div className="rounded-xl border border-dashed border-slate-800 bg-[#111827]/50 px-6 py-16 text-center">
                <Globe2 className="mx-auto h-10 w-10 text-slate-600" />
                <h2 className="mt-3 text-base font-semibold text-slate-200">
                  Query any domain&apos;s DNS records
                </h2>
                <p className="mx-auto mt-1 max-w-md text-xs leading-relaxed text-slate-400">
                  Enter a domain above to query A, AAAA, CNAME, MX, TXT, NS, SOA,
                  CAA, and SRV records across Cloudflare, Google, Quad9, and your
                  local system resolver, plus verify SPF, DMARC, DKIM, and DNSSEC.
                </p>
              </div>
            )}

            {report && (
              <div className="space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-3 border-b border-slate-800 pb-2">
                  <div className="flex flex-wrap items-center gap-1">
                    <button
                      type="button"
                      onClick={() => setActiveTab("records")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "records"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <Database className="h-3.5 w-3.5" />
                      Records
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("propagation")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "propagation"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <Activity className="h-3.5 w-3.5" />
                      Propagation
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("security")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "security"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <Shield className="h-3.5 w-3.5" />
                      Email &amp; Security
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("health")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "health"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <HeartPulse className="h-3.5 w-3.5" />
                      Domain Health
                      <span
                        className={`rounded-full px-1.5 py-0.2 font-mono text-[10px] font-semibold ${
                          report.health.overall_status === "healthy"
                            ? "bg-emerald-500/20 text-emerald-300"
                            : report.health.overall_status === "caution"
                              ? "bg-amber-500/20 text-amber-300"
                              : "bg-rose-500/20 text-rose-300"
                        }`}
                      >
                        {report.health.grade}
                      </span>
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("subdomains")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "subdomains"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <Network className="h-3.5 w-3.5" />
                      Subdomains
                      {report.subdomains.total_found > 0 && (
                        <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-300">
                          {report.subdomains.total_found}
                        </span>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("whois")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "whois"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <FileSearch className="h-3.5 w-3.5" />
                      WHOIS
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("website")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "website"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <Layers className="h-3.5 w-3.5" />
                      Website
                      {report.website.technologies.length > 0 && (
                        <span className="rounded-full bg-slate-800 px-1.5 py-0.2 font-mono text-[10px] text-slate-300">
                          {report.website.technologies.length}
                        </span>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={() => setActiveTab("zone")}
                      className={`inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-xs font-medium transition ${
                        activeTab === "zone"
                          ? "bg-sky-500/15 text-sky-300 ring-1 ring-sky-500/30"
                          : "text-slate-400 hover:bg-slate-800/60 hover:text-slate-200"
                      }`}
                    >
                      <FileCode2 className="h-3.5 w-3.5" />
                      Zone Output
                    </button>
                  </div>

                  <div className="font-mono text-xs text-slate-400">
                    Target:{" "}
                    <span className="font-semibold text-slate-200">
                      {report.domain}
                    </span>
                  </div>
                </div>

                {activeTab === "records" && (
                  <RecordsTable
                    report={report}
                    selectedResolverId={selectedResolverId}
                    onSelectResolverId={setSelectedResolverId}
                    onNotify={notify}
                  />
                )}

                {activeTab === "propagation" && (
                  <PropagationView report={report} />
                )}

                {activeTab === "security" && (
                  <SecurityPanel
                    security={report.security}
                    dkimSelectorsInput={dkimSelectorsInput}
                    onDkimSelectorsInputChange={setDkimSelectorsInput}
                    onRecheckDkim={() => void runLookup(report.domain)}
                    loading={loading}
                    onNotify={notify}
                  />
                )}

                {activeTab === "health" && (
                  <DomainHealthPanel health={report.health} />
                )}

                {activeTab === "subdomains" && (
                  <SubdomainsPanel
                    report={report.subdomains}
                    onInspectSubdomain={(sub) => {
                      setDomain(sub);
                      setActiveTab("records");
                      void runLookup(sub);
                    }}
                    onNotify={notify}
                  />
                )}

                {activeTab === "whois" && (
                  <WhoisPanel
                    whois={report.whois}
                    queriedTarget={report.domain}
                    onNotify={notify}
                  />
                )}

                {activeTab === "website" && (
                  <WebsitePanel website={report.website} onNotify={notify} />
                )}

                {activeTab === "zone" && (
                  <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
                    <div className="flex items-center justify-between border-b border-slate-800 bg-[#0d131f] px-4 py-2.5">
                      <span className="text-xs font-medium text-slate-300">
                        BIND Zone Style Output
                      </span>
                      <button
                        type="button"
                        onClick={async () => {
                          await copyToClipboard(zoneOutput);
                          notify("Copied zone output");
                        }}
                        className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:border-sky-500/50 hover:text-sky-300"
                      >
                        <Copy className="h-3.5 w-3.5" />
                        Copy Zone
                      </button>
                    </div>
                    <pre className="overflow-x-auto p-4 font-mono text-xs leading-relaxed text-slate-200">
                      {zoneOutput}
                    </pre>
                  </div>
                )}
              </div>
            )}
          </div>
        </main>
      </div>

      {toast && (
        <div className="fixed bottom-4 right-4 z-50 rounded-lg border border-sky-500/40 bg-[#111827] px-3.5 py-2 text-xs font-medium text-sky-200 shadow-xl shadow-black/50">
          {toast}
        </div>
      )}
    </div>
  );
}

export default App;
