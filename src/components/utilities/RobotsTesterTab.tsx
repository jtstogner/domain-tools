import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Copy,
  Download,
  ExternalLink,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard, fetchRobotsTxt } from "../../lib/api";
import {
  COMMON_BOT_PRESETS,
  parseRobotsTxt,
  testRobotsPath,
} from "../../lib/robotsParser";
import type { RobotsFetchResult } from "../../types/dns";

export interface RobotsTesterTabProps {
  defaultDomain: string;
  onNotify: (msg: string) => void;
}

const SAMPLE_ROBOTS_TXT = `# Example robots.txt with Search & AI Crawler rules
User-agent: *
Allow: /
Disallow: /admin/
Disallow: /internal/
Disallow: /*?token=*
Crawl-delay: 2

User-agent: Googlebot
Allow: /
Disallow: /admin/

User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /private/
Allow: /docs/

Sitemap: https://example.com/sitemap.xml`;

export function RobotsTesterTab({ defaultDomain, onNotify }: RobotsTesterTabProps) {
  const [domainInput, setDomainInput] = useState(defaultDomain || "example.com");
  const [robotsContent, setRobotsContent] = useState(SAMPLE_ROBOTS_TXT);
  const [fetchResult, setFetchResult] = useState<RobotsFetchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const [testPath, setTestPath] = useState("/docs/getting-started");
  const [userAgent, setUserAgent] = useState("Googlebot");

  useEffect(() => {
    if (defaultDomain) {
      setDomainInput(defaultDomain);
    }
  }, [defaultDomain]);

  const handleFetch = async () => {
    const clean = domainInput.trim();
    if (!clean) {
      setFetchError("Enter a domain name to fetch /robots.txt.");
      return;
    }
    setLoading(true);
    setFetchError(null);
    try {
      const res = await fetchRobotsTxt(clean);
      setFetchResult(res);
      if (res.error) {
        setFetchError(res.error);
      } else if (res.found) {
        setRobotsContent(res.content);
        onNotify(`Fetched ${res.url} (${res.latency_ms}ms)`);
      } else {
        setRobotsContent("");
        onNotify(`No robots.txt found at ${res.url} (HTTP ${res.http_status ?? "N/A"})`);
      }
    } catch (err) {
      setFetchError(String(err));
    } finally {
      setLoading(false);
    }
  };

  const parsed = useMemo(() => parseRobotsTxt(robotsContent), [robotsContent]);
  const testResult = useMemo(
    () => testRobotsPath(robotsContent, userAgent, testPath),
    [robotsContent, userAgent, testPath],
  );

  const botMatrix = useMemo(
    () =>
      COMMON_BOT_PRESETS.map((bot) => ({
        bot,
        result: testRobotsPath(robotsContent, bot.name, testPath),
      })),
    [robotsContent, testPath],
  );

  const allSitemaps = useMemo(() => {
    const set = new Set<string>([...parsed.sitemaps, ...(fetchResult?.sitemaps ?? [])]);
    return Array.from(set);
  }, [parsed.sitemaps, fetchResult]);

  return (
    <div className="space-y-4">
      {/* Live Fetch Bar */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          void handleFetch();
        }}
        className="rounded-xl border border-line bg-surface p-4 space-y-3"
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <Bot className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">
                Robots.txt Fetcher &amp; Crawler Rule Tester
              </h3>
              <p className="text-[11px] text-ink-muted">
                Fetch a live domain&apos;s `/robots.txt` or edit rules below to simulate RFC 9309 matching for Search &amp; AI bots.
              </p>
            </div>
          </div>

          <button
            type="button"
            onClick={() => {
              setRobotsContent(SAMPLE_ROBOTS_TXT);
              setFetchResult(null);
              setFetchError(null);
              onNotify("Loaded sample robots.txt");
            }}
            className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
          >
            <Sparkles className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            Load Sample
          </button>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <input
            type="text"
            value={domainInput}
            onChange={(e) => setDomainInput(e.target.value)}
            placeholder="example.com"
            className="min-w-[200px] flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          />
          <button
            type="submit"
            disabled={loading}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-4 py-2 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {loading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Download className="h-3.5 w-3.5" />
            )}
            {loading ? "Fetching..." : "Fetch Live robots.txt"}
          </button>
        </div>

        {fetchResult && (
          <div className="flex flex-wrap items-center gap-2 text-[11px] text-ink-muted">
            <span
              className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 font-semibold ${
                fetchResult.found
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                  : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
              }`}
            >
              {fetchResult.found ? "Found" : "Not Found"} · HTTP {fetchResult.http_status ?? "—"}
            </span>
            <span className="font-mono text-ink-secondary">{fetchResult.url}</span>
            <span className="font-mono">({fetchResult.latency_ms}ms)</span>
          </div>
        )}

        {fetchError && (
          <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 p-2.5 text-xs text-rose-800 dark:text-rose-200">
            {fetchError}
          </div>
        )}
      </form>

      {/* Main Split: Editor + Live Tester */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        {/* Left: robots.txt Editor & Sitemaps */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4 xl:col-span-5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-semibold text-ink">
              robots.txt Content ({parsed.groups.length} group
              {parsed.groups.length === 1 ? "" : "s"})
            </span>
            <button
              type="button"
              onClick={() => {
                void copyToClipboard(robotsContent);
                onNotify("Copied robots.txt content");
              }}
              className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
            >
              <Copy className="h-3 w-3" />
              Copy
            </button>
          </div>

          <textarea
            rows={14}
            value={robotsContent}
            onChange={(e) => setRobotsContent(e.target.value)}
            placeholder="User-agent: *&#10;Disallow: /admin/"
            className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
          />

          {parsed.warnings.length > 0 && (
            <div className="space-y-1 rounded-lg border border-amber-500/35 bg-amber-500/10 p-2.5 text-[11px] text-amber-900 dark:text-amber-200">
              {parsed.warnings.map((w, i) => (
                <div key={i} className="flex items-start gap-1.5">
                  <AlertTriangle className="mt-0.5 h-3 w-3 shrink-0 text-amber-600 dark:text-amber-400" />
                  <span>{w}</span>
                </div>
              ))}
            </div>
          )}

          {/* Sitemaps */}
          <div className="border-t border-line pt-3">
            <div className="mb-1.5 text-[11px] font-semibold text-ink">
              Declared Sitemaps ({allSitemaps.length})
            </div>
            {allSitemaps.length > 0 ? (
              <div className="space-y-1">
                {allSitemaps.map((sm) => (
                  <div
                    key={sm}
                    className="flex items-center justify-between gap-2 rounded-lg border border-line bg-canvas px-2.5 py-1.5 font-mono text-[11px]"
                  >
                    <a
                      href={sm}
                      target="_blank"
                      rel="noreferrer"
                      className="inline-flex items-center gap-1 truncate text-sky-700 hover:underline dark:text-sky-300"
                    >
                      <span className="truncate">{sm}</span>
                      <ExternalLink className="h-3 w-3 shrink-0" />
                    </a>
                    <button
                      type="button"
                      onClick={() => {
                        void copyToClipboard(sm);
                        onNotify("Copied Sitemap URL");
                      }}
                      className="shrink-0 text-ink-muted hover:text-ink"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                  </div>
                ))}
              </div>
            ) : (
              <div className="text-xs italic text-ink-muted">No Sitemap directives declared.</div>
            )}
          </div>
        </div>

        {/* Right: Path Simulator & Bot Comparison Matrix */}
        <div className="space-y-4 xl:col-span-7">
          <div className="space-y-3 rounded-xl border border-line bg-surface p-4">
            <div className="text-xs font-semibold text-ink">Simulate URL Path &amp; User-Agent</div>

            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">URL or Path to Test</label>
                <input
                  type="text"
                  value={testPath}
                  onChange={(e) => setTestPath(e.target.value)}
                  placeholder="/admin/login or https://example.com/docs"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">User-Agent</label>
                <input
                  type="text"
                  value={userAgent}
                  onChange={(e) => setUserAgent(e.target.value)}
                  placeholder="Googlebot"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                />
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-ink-muted">Quick paths:</span>
              {["/", "/docs/getting-started", "/admin/", "/private/data", "/search?token=123"].map(
                (p) => (
                  <button
                    key={p}
                    type="button"
                    onClick={() => setTestPath(p)}
                    className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                  >
                    {p}
                  </button>
                ),
              )}
            </div>

            {/* Single-Bot Verdict Banner */}
            <div
              className={`rounded-xl border p-3.5 ${
                testResult.allowed
                  ? "border-emerald-500/35 bg-emerald-500/[0.07]"
                  : "border-rose-500/35 bg-rose-500/[0.08]"
              }`}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  {testResult.allowed ? (
                    <ShieldCheck className="h-5 w-5 text-emerald-600 dark:text-emerald-400" />
                  ) : (
                    <ShieldAlert className="h-5 w-5 text-rose-600 dark:text-rose-400" />
                  )}
                  <span
                    className={`text-sm font-bold ${
                      testResult.allowed
                        ? "text-emerald-700 dark:text-emerald-300"
                        : "text-rose-700 dark:text-rose-300"
                    }`}
                  >
                    {testResult.allowed ? "ALLOWED" : "BLOCKED (DISALLOWED)"}
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 font-mono text-[11px] text-ink-secondary">
                  <span>Group: {testResult.matchedGroup ?? "(none)"}</span>
                  {testResult.matchedRule && (
                    <span>
                      · Rule: {testResult.matchedRule.type}: {testResult.matchedRule.path}
                    </span>
                  )}
                  {testResult.crawlDelay !== undefined && (
                    <span>· Crawl-delay: {testResult.crawlDelay}s</span>
                  )}
                </div>
              </div>
              <p className="mt-1.5 text-xs text-ink-secondary">{testResult.reason}</p>
            </div>
          </div>

          {/* All-Bots Matrix */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <div className="border-b border-line bg-surface-alt px-4 py-2.5 text-xs font-semibold text-ink">
              Crawler Matrix for <span className="font-mono text-sky-700 dark:text-sky-300">{testPath || "/"}</span>
            </div>
            <div className="divide-y divide-line">
              {botMatrix.map(({ bot, result }) => (
                <button
                  key={bot.id}
                  type="button"
                  onClick={() => setUserAgent(bot.name)}
                  className={`flex w-full items-center justify-between gap-3 px-4 py-2.5 text-left text-xs transition hover:bg-surface-alt/70 ${
                    userAgent.toLowerCase() === bot.name.toLowerCase() ? "bg-sky-500/[0.06]" : ""
                  }`}
                >
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono font-semibold text-ink">{bot.name}</span>
                      <span className="rounded border border-line bg-canvas px-1.5 py-0.5 text-[10px] uppercase text-ink-muted">
                        {bot.category}
                      </span>
                    </div>
                    <div className="text-[11px] text-ink-muted">{bot.description}</div>
                  </div>

                  <div className="flex shrink-0 items-center gap-2">
                    {result.matchedRule && (
                      <span className="hidden font-mono text-[10px] text-ink-muted sm:inline">
                        {result.matchedRule.type}: {result.matchedRule.path}
                      </span>
                    )}
                    {result.allowed ? (
                      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                        <CheckCircle2 className="h-3 w-3" />
                        Allow
                      </span>
                    ) : (
                      <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
                        <XCircle className="h-3 w-3" />
                        Block
                      </span>
                    )}
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
