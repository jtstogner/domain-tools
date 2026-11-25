import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Code2,
  Copy,
  FileCode,
  FileSearch,
  Globe,
  Info,
  Layers,
  Lock,
  LockOpen,
  Puzzle,
  Shield,
  ShieldAlert,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import type { DetectedTech, WebsiteInfo } from "../types/dns";
import { copyToClipboard } from "../lib/api";

const CATEGORY_ORDER = [
  "JS Framework",
  "CSS Framework",
  "UI & Plugins",
  "CMS & Platform",
  "Server & Backend",
  "CDN & Hosting",
  "Analytics & Services",
];

const CATEGORY_COLORS: Record<string, string> = {
  "JS Framework": "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300",
  "CSS Framework": "border-indigo-500/30 bg-indigo-500/10 text-indigo-700 dark:text-indigo-300",
  "UI & Plugins": "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300",
  "CMS & Platform": "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300",
  "Server & Backend": "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300",
  "CDN & Hosting": "border-cyan-500/30 bg-cyan-500/10 text-cyan-700 dark:text-cyan-300",
  "Analytics & Services": "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300",
};

type AssetSubTab = "scripts" | "styles" | "headers";

interface WebsitePanelProps {
  website: WebsiteInfo;
  onNotify: (msg: string) => void;
}

export function WebsitePanel({ website, onNotify }: WebsitePanelProps) {
  const [assetTab, setAssetTab] = useState<AssetSubTab>("scripts");
  const [copiedHeaders, setCopiedHeaders] = useState(false);
  const [expandedFile, setExpandedFile] = useState<string | null>(null);

  const groupedTech = useMemo(() => {
    const groups = new Map<string, DetectedTech[]>();
    for (const cat of CATEGORY_ORDER) {
      groups.set(cat, []);
    }
    for (const tech of website.technologies) {
      const list = groups.get(tech.category) ?? [];
      list.push(tech);
      groups.set(tech.category, list);
    }
    return Array.from(groups.entries()).filter(([, items]) => items.length > 0);
  }, [website.technologies]);

  if (website.status === "no_website") {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-line bg-surface p-6 text-sm text-ink-secondary">
        <Info className="mt-0.5 h-5 w-5 shrink-0 text-ink-muted" />
        <div>
          <div className="font-semibold text-ink">
            No Website Detected
          </div>
          <p className="mt-1 text-xs text-ink-muted">
            {website.error ??
              "No HTTP or HTTPS web server responded at this domain."}
          </p>
        </div>
      </div>
    );
  }

  if (website.status === "error") {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-900 dark:text-rose-200">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
        <div>
          <div className="font-semibold">Website Inspection Failed</div>
          <div className="mt-0.5 text-xs text-rose-800 dark:text-rose-300/90">
            {website.error ?? "Unable to inspect website."}
          </div>
        </div>
      </div>
    );
  }

  const statusTone =
    website.http_status && website.http_status < 300
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
      : website.http_status && website.http_status < 400
        ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
        : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300";

  const copyHeaders = async () => {
    const text = website.response_headers
      .map((h) => `${h.name}: ${h.value}`)
      .join("\n");
    await copyToClipboard(text);
    setCopiedHeaders(true);
    onNotify("Copied HTTP response headers");
    setTimeout(() => setCopiedHeaders(false), 1500);
  };

  const audit = website.security_audit;

  return (
    <div className="space-y-4">
      {/* Site Overview Card */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <Globe className="h-4 w-4 shrink-0 text-sky-600 dark:text-sky-400" />
              <h3 className="truncate text-base font-semibold text-ink">
                {website.title ?? website.final_url ?? website.url}
              </h3>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
              <span className="inline-flex items-center gap-1 font-mono text-ink-secondary">
                {website.https ? (
                  <Lock className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <LockOpen className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
                )}
                {website.final_url ?? website.url}
              </span>
            </div>
            {website.description && (
              <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-ink-muted">
                {website.description}
              </p>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-2">
            {website.http_status !== null && (
              <span
                className={`rounded-full border px-2.5 py-0.5 font-mono text-xs font-semibold ${statusTone}`}
              >
                HTTP {website.http_status}
              </span>
            )}
            {website.http3_supported && (
              <span
                title={website.alt_svc ?? "Alt-Svc advertises HTTP/3 (QUIC)"}
                className="rounded-full border border-cyan-500/40 bg-cyan-500/15 px-2.5 py-0.5 font-mono text-xs font-semibold text-cyan-700 dark:text-cyan-300"
              >
                HTTP/3 (QUIC)
              </span>
            )}
            <span className="rounded-full border border-line-strong bg-canvas px-2.5 py-0.5 font-mono text-xs text-ink-secondary">
              {website.latency_ms}ms
            </span>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2 border-t border-line pt-3 text-xs">
          {website.server && (
            <span className="rounded-md border border-line bg-canvas px-2.5 py-1 text-ink-secondary">
              <span className="text-ink-muted">Server: </span>
              <span className="font-mono">{website.server}</span>
            </span>
          )}
          {website.powered_by && (
            <span className="rounded-md border border-line bg-canvas px-2.5 py-1 text-ink-secondary">
              <span className="text-ink-muted">Powered-By: </span>
              <span className="font-mono">{website.powered_by}</span>
            </span>
          )}
          {website.generator && (
            <span className="rounded-md border border-line bg-canvas px-2.5 py-1 text-ink-secondary">
              <span className="text-ink-muted">Generator: </span>
              <span className="font-mono">{website.generator}</span>
            </span>
          )}
          {website.content_type && (
            <span className="rounded-md border border-line bg-canvas px-2.5 py-1 text-ink-secondary">
              <span className="text-ink-muted">Content-Type: </span>
              <span className="font-mono">{website.content_type}</span>
            </span>
          )}
        </div>
      </div>

      {/* Detected Stack & Frontend Plugins */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-sm font-semibold text-ink">
            <Layers className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            Detected Stack &amp; Frontend Plugins ({website.technologies.length})
          </div>
        </div>

        {groupedTech.length === 0 ? (
          <div className="mt-3 rounded-lg border border-line bg-canvas p-4 text-xs text-ink-muted">
            No recognizable frontend frameworks, CSS libraries, or CMS markers
            were detected in the initial HTML/headers (the site may use an
            opaque bundled SPA or block automated requests).
          </div>
        ) : (
          <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
            {groupedTech.map(([category, items]) => (
              <div
                key={category}
                className="rounded-lg border border-line bg-surface-alt p-3"
              >
                <div className="mb-2.5 flex items-center justify-between">
                  <span
                    className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${
                      CATEGORY_COLORS[category] ??
                      "border-line-strong bg-surface text-ink-secondary"
                    }`}
                  >
                    {category}
                  </span>
                  <span className="font-mono text-[11px] text-ink-muted">
                    {items.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {items.map((tech) => (
                    <div
                      key={tech.name}
                      className="rounded-md border border-line bg-canvas px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-ink">
                            {tech.name}
                          </span>
                          {tech.version && (
                            <span className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-[10px] text-sky-700 dark:text-sky-300">
                              v{tech.version}
                            </span>
                          )}
                        </div>
                        <span
                          className={`text-[10px] uppercase tracking-wider ${
                            tech.confidence === "high"
                              ? "text-emerald-700 dark:text-emerald-400"
                              : "text-amber-700 dark:text-amber-300"
                          }`}
                        >
                          {tech.confidence}
                        </span>
                      </div>
                      <div className="mt-1 truncate font-mono text-[11px] text-ink-muted" title={tech.evidence}>
                        {tech.evidence}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )}

        {website.wordpress_plugins.length > 0 && (
          <div className="mt-3 border-t border-line pt-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-ink">
              <Puzzle className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
              WordPress Plugins Detected ({website.wordpress_plugins.length})
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {website.wordpress_plugins.map((slug) => (
                <span
                  key={slug}
                  className="rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 font-mono text-[11px] text-violet-700 dark:text-violet-200"
                >
                  {slug}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* HTTP Security Headers */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-ink">
          <Shield className="h-4 w-4 text-emerald-600 dark:text-emerald-400" />
          HTTP Security Headers
        </div>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {website.security_headers.map((hdr) => (
            <div
              key={hdr.name}
              title={hdr.value ?? "Header not present"}
              className="flex items-center justify-between gap-2 rounded-lg border border-line bg-canvas px-3 py-2"
            >
              <span className="truncate font-mono text-xs text-ink-secondary">
                {hdr.name}
              </span>
              {hdr.present ? (
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-medium text-emerald-700 dark:text-emerald-300">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Present
                </span>
              ) : (
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-medium text-ink-muted">
                  <XCircle className="h-3.5 w-3.5" />
                  Missing
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Web Security Files, Cookies, CORS & Exposure Audit */}
      {audit && (
        <div className="space-y-4 rounded-xl border border-line bg-surface p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-sm font-semibold text-ink">
              <FileSearch className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              Security Files, Cookies &amp; Exposure Audit
            </div>
            {audit.exposed_count > 0 ? (
              <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
                <ShieldAlert className="h-3.5 w-3.5" />
                {audit.exposed_count} Sensitive Exposure(s)
              </span>
            ) : (
              <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
                <CheckCircle2 className="h-3.5 w-3.5" />
                No Dotfile Exposures
              </span>
            )}
          </div>

          {audit.exposed_count > 0 && (
            <div className="flex items-start gap-2.5 rounded-lg border border-rose-500/40 bg-rose-500/10 p-3 text-xs text-rose-900 dark:text-rose-200">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-600 dark:text-rose-400" />
              <div>
                <span className="font-semibold">CRITICAL EXPOSURE DETECTED:</span> Sensitive repository or environment files are publicly readable over HTTP. Block access immediately and rotate any exposed secrets.
              </div>
            </div>
          )}

          {audit.files.length > 0 && (
            <div className="grid grid-cols-1 gap-2.5 md:grid-cols-2">
              {audit.files.map((f) => {
                const badgeTone =
                  f.status === "exposed"
                    ? "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                    : f.status === "warn"
                      ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                      : f.status === "found"
                        ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                        : "border-line bg-surface-alt text-ink-muted";
                const isExp = expandedFile === f.path;
                return (
                  <div
                    key={f.path}
                    className={`rounded-lg border p-3 text-xs ${
                      f.status === "exposed"
                        ? "border-rose-500/40 bg-rose-500/[0.06]"
                        : f.status === "warn"
                          ? "border-amber-500/40 bg-amber-500/[0.05]"
                          : "border-line bg-canvas"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <div className="font-semibold text-ink">{f.label}</div>
                        <div className="font-mono text-[11px] text-ink-muted">
                          {f.path}
                          {f.http_status !== null ? ` · HTTP ${f.http_status}` : ""}
                        </div>
                      </div>
                      <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${badgeTone}`}>
                        {f.status}
                      </span>
                    </div>
                    <p className="mt-1.5 text-[11px] text-ink-secondary">{f.summary}</p>
                    {f.preview && (
                      <div className="mt-2">
                        <button
                          type="button"
                          onClick={() => setExpandedFile(isExp ? null : f.path)}
                          className="text-[11px] font-medium text-sky-600 hover:underline dark:text-sky-400"
                        >
                          {isExp ? "Hide preview" : "Show preview"}
                        </button>
                        {isExp && (
                          <pre className="mt-1.5 overflow-x-auto rounded border border-line bg-surface p-2 font-mono text-[10px] text-ink-secondary">
                            {f.preview}
                          </pre>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {/* CORS & Mixed Content */}
          {(audit.cors_acao || audit.cors_issue || audit.mixed_content_urls.length > 0) && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {(audit.cors_acao || audit.cors_issue) && (
                <div className="rounded-lg border border-line bg-canvas p-3 text-xs">
                  <div className="font-semibold text-ink">CORS Headers</div>
                  <div className="mt-1 font-mono text-[11px] text-ink-secondary">
                    ACAO: {audit.cors_acao ?? "none"} · Credentials: {String(audit.cors_acac)}
                  </div>
                  {audit.cors_issue && (
                    <div className="mt-1 text-[11px] text-amber-700 dark:text-amber-300">
                      {audit.cors_issue}
                    </div>
                  )}
                </div>
              )}

              {audit.mixed_content_urls.length > 0 && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs">
                  <div className="font-semibold text-amber-900 dark:text-amber-200">
                    Mixed Content ({audit.mixed_content_urls.length} HTTP asset(s) on HTTPS)
                  </div>
                  <ul className="mt-1 space-y-0.5 font-mono text-[11px] text-amber-800 dark:text-amber-300">
                    {audit.mixed_content_urls.slice(0, 5).map((u, idx) => (
                      <li key={idx} className="truncate">
                        {u}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}

          {/* Cookie Security Flags */}
          <div>
            <div className="mb-2 text-xs font-semibold text-ink">
              Set-Cookie Security Flags ({audit.cookies.length})
            </div>
            {audit.cookies.length === 0 ? (
              <div className="rounded-lg border border-line bg-canvas px-3 py-2 text-[11px] text-ink-muted">
                No Set-Cookie headers returned on initial page load.
              </div>
            ) : (
              <div className="overflow-x-auto rounded-lg border border-line">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-surface-alt text-[10px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-3 py-2">Cookie</th>
                      <th className="px-3 py-2">Secure</th>
                      <th className="px-3 py-2">HttpOnly</th>
                      <th className="px-3 py-2">SameSite</th>
                      <th className="px-3 py-2">Issues</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line bg-canvas">
                    {audit.cookies.map((c, idx) => (
                      <tr key={`${c.name}-${idx}`}>
                        <td className="px-3 py-2 font-mono font-medium text-ink">
                          {c.name}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px]">
                          {c.secure ? (
                            <span className="text-emerald-700 dark:text-emerald-300">Yes</span>
                          ) : (
                            <span className="text-rose-700 dark:text-rose-300">No</span>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px]">
                          {c.http_only ? (
                            <span className="text-emerald-700 dark:text-emerald-300">Yes</span>
                          ) : (
                            <span className="text-amber-700 dark:text-amber-300">No</span>
                          )}
                        </td>
                        <td className="px-3 py-2 font-mono text-[11px] text-ink-secondary">
                          {c.same_site ?? "missing"}
                        </td>
                        <td className="px-3 py-2 text-[11px] text-amber-700 dark:text-amber-300">
                          {c.issues.length > 0 ? (
                            c.issues.join(" ")
                          ) : (
                            <span className="text-emerald-700 dark:text-emerald-300">OK</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Assets & Headers Inspector */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line bg-surface-alt px-4 py-2.5">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setAssetTab("scripts")}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                assetTab === "scripts"
                  ? "bg-sky-500/15 text-sky-700 dark:text-sky-300"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <Code2 className="h-3.5 w-3.5" />
              Scripts ({website.script_urls.length})
            </button>
            <button
              type="button"
              onClick={() => setAssetTab("styles")}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                assetTab === "styles"
                  ? "bg-sky-500/15 text-sky-700 dark:text-sky-300"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              <FileCode className="h-3.5 w-3.5" />
              Stylesheets ({website.stylesheet_urls.length})
            </button>
            <button
              type="button"
              onClick={() => setAssetTab("headers")}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                assetTab === "headers"
                  ? "bg-sky-500/15 text-sky-700 dark:text-sky-300"
                  : "text-ink-muted hover:text-ink"
              }`}
            >
              Response Headers ({website.response_headers.length})
            </button>
          </div>

          {assetTab === "headers" && website.response_headers.length > 0 && (
            <button
              type="button"
              onClick={copyHeaders}
              className="inline-flex items-center gap-1.5 rounded-md border border-line-strong bg-surface px-2.5 py-1 text-xs text-ink-secondary hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300"
            >
              {copiedHeaders ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  Copy Headers
                </>
              )}
            </button>
          )}
        </div>

        <div className="max-h-72 overflow-y-auto p-4">
          {assetTab === "scripts" && (
            website.script_urls.length === 0 ? (
              <div className="text-xs text-ink-muted">No external script tags found.</div>
            ) : (
              <ul className="space-y-1.5 font-mono text-xs text-ink-secondary">
                {website.script_urls.map((u, idx) => (
                  <li key={idx} className="break-all rounded bg-canvas px-2.5 py-1.5">
                    {u}
                  </li>
                ))}
              </ul>
            )
          )}

          {assetTab === "styles" && (
            website.stylesheet_urls.length === 0 ? (
              <div className="text-xs text-ink-muted">No external stylesheet links found.</div>
            ) : (
              <ul className="space-y-1.5 font-mono text-xs text-ink-secondary">
                {website.stylesheet_urls.map((u, idx) => (
                  <li key={idx} className="break-all rounded bg-canvas px-2.5 py-1.5">
                    {u}
                  </li>
                ))}
              </ul>
            )
          )}

          {assetTab === "headers" && (
            <div className="divide-y divide-line font-mono text-xs">
              {website.response_headers.map((h, idx) => (
                <div key={`${h.name}-${idx}`} className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-3">
                  <span className="font-semibold text-sky-700 dark:text-sky-300">{h.name}</span>
                  <span className="break-all text-ink-secondary sm:col-span-2">{h.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
