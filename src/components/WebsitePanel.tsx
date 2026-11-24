import {
  AlertTriangle,
  Check,
  CheckCircle2,
  Code2,
  Copy,
  FileCode,
  Globe,
  Info,
  Layers,
  Lock,
  LockOpen,
  Puzzle,
  Shield,
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
  "JS Framework": "border-sky-500/30 bg-sky-500/10 text-sky-300",
  "CSS Framework": "border-indigo-500/30 bg-indigo-500/10 text-indigo-300",
  "UI & Plugins": "border-amber-500/30 bg-amber-500/10 text-amber-300",
  "CMS & Platform": "border-violet-500/30 bg-violet-500/10 text-violet-300",
  "Server & Backend": "border-emerald-500/30 bg-emerald-500/10 text-emerald-300",
  "CDN & Hosting": "border-cyan-500/30 bg-cyan-500/10 text-cyan-300",
  "Analytics & Services": "border-rose-500/30 bg-rose-500/10 text-rose-300",
};

type AssetSubTab = "scripts" | "styles" | "headers";

interface WebsitePanelProps {
  website: WebsiteInfo;
  onNotify: (msg: string) => void;
}

export function WebsitePanel({ website, onNotify }: WebsitePanelProps) {
  const [assetTab, setAssetTab] = useState<AssetSubTab>("scripts");
  const [copiedHeaders, setCopiedHeaders] = useState(false);

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
      <div className="flex items-start gap-3 rounded-xl border border-slate-800 bg-[#111827] p-6 text-sm text-slate-300">
        <Info className="mt-0.5 h-5 w-5 shrink-0 text-slate-400" />
        <div>
          <div className="font-semibold text-slate-100">
            No Website Detected
          </div>
          <p className="mt-1 text-xs text-slate-400">
            {website.error ??
              "No HTTP or HTTPS web server responded at this domain."}
          </p>
        </div>
      </div>
    );
  }

  if (website.status === "error") {
    return (
      <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
        <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
        <div>
          <div className="font-semibold">Website Inspection Failed</div>
          <div className="mt-0.5 text-xs text-rose-300/90">
            {website.error ?? "Unable to inspect website."}
          </div>
        </div>
      </div>
    );
  }

  const statusTone =
    website.http_status && website.http_status < 300
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-300"
      : website.http_status && website.http_status < 400
        ? "border-sky-500/40 bg-sky-500/15 text-sky-300"
        : "border-amber-500/40 bg-amber-500/15 text-amber-300";

  const copyHeaders = async () => {
    const text = website.response_headers
      .map((h) => `${h.name}: ${h.value}`)
      .join("\n");
    await copyToClipboard(text);
    setCopiedHeaders(true);
    onNotify("Copied HTTP response headers");
    setTimeout(() => setCopiedHeaders(false), 1500);
  };

  return (
    <div className="space-y-4">
      {/* Site Overview Card */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <Globe className="h-4 w-4 shrink-0 text-sky-400" />
              <h3 className="truncate text-base font-semibold text-slate-100">
                {website.title ?? website.final_url ?? website.url}
              </h3>
            </div>
            <div className="mt-1.5 flex flex-wrap items-center gap-2 text-xs">
              <span className="inline-flex items-center gap-1 font-mono text-slate-300">
                {website.https ? (
                  <Lock className="h-3.5 w-3.5 text-emerald-400" />
                ) : (
                  <LockOpen className="h-3.5 w-3.5 text-amber-400" />
                )}
                {website.final_url ?? website.url}
              </span>
            </div>
            {website.description && (
              <p className="mt-2 line-clamp-2 text-xs leading-relaxed text-slate-400">
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
            <span className="rounded-full border border-slate-700 bg-[#0b0f17] px-2.5 py-0.5 font-mono text-xs text-slate-300">
              {website.latency_ms}ms
            </span>
          </div>
        </div>

        <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-800/80 pt-3 text-xs">
          {website.server && (
            <span className="rounded-md border border-slate-800 bg-[#0b0f17] px-2.5 py-1 text-slate-300">
              <span className="text-slate-500">Server: </span>
              <span className="font-mono">{website.server}</span>
            </span>
          )}
          {website.powered_by && (
            <span className="rounded-md border border-slate-800 bg-[#0b0f17] px-2.5 py-1 text-slate-300">
              <span className="text-slate-500">Powered-By: </span>
              <span className="font-mono">{website.powered_by}</span>
            </span>
          )}
          {website.generator && (
            <span className="rounded-md border border-slate-800 bg-[#0b0f17] px-2.5 py-1 text-slate-300">
              <span className="text-slate-500">Generator: </span>
              <span className="font-mono">{website.generator}</span>
            </span>
          )}
          {website.content_type && (
            <span className="rounded-md border border-slate-800 bg-[#0b0f17] px-2.5 py-1 text-slate-300">
              <span className="text-slate-500">Content-Type: </span>
              <span className="font-mono">{website.content_type}</span>
            </span>
          )}
        </div>
      </div>

      {/* Detected Stack & Frontend Plugins */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-center justify-between gap-2">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Layers className="h-4 w-4 text-sky-400" />
            Detected Stack &amp; Frontend Plugins ({website.technologies.length})
          </div>
        </div>

        {groupedTech.length === 0 ? (
          <div className="mt-3 rounded-lg border border-slate-800/80 bg-[#0b0f17] p-4 text-xs text-slate-400">
            No recognizable frontend frameworks, CSS libraries, or CMS markers
            were detected in the initial HTML/headers (the site may use an
            opaque bundled SPA or block automated requests).
          </div>
        ) : (
          <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
            {groupedTech.map(([category, items]) => (
              <div
                key={category}
                className="rounded-lg border border-slate-800/90 bg-[#0d131f] p-3"
              >
                <div className="mb-2.5 flex items-center justify-between">
                  <span
                    className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${
                      CATEGORY_COLORS[category] ??
                      "border-slate-700 bg-slate-800 text-slate-300"
                    }`}
                  >
                    {category}
                  </span>
                  <span className="font-mono text-[11px] text-slate-500">
                    {items.length}
                  </span>
                </div>
                <div className="space-y-2">
                  {items.map((tech) => (
                    <div
                      key={tech.name}
                      className="rounded-md border border-slate-800/80 bg-[#0b0f17] px-3 py-2"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-semibold text-slate-100">
                            {tech.name}
                          </span>
                          {tech.version && (
                            <span className="rounded bg-sky-500/15 px-1.5 py-0.5 font-mono text-[10px] text-sky-300">
                              v{tech.version}
                            </span>
                          )}
                        </div>
                        <span
                          className={`text-[10px] uppercase tracking-wider ${
                            tech.confidence === "high"
                              ? "text-emerald-400"
                              : "text-amber-300"
                          }`}
                        >
                          {tech.confidence}
                        </span>
                      </div>
                      <div className="mt-1 truncate font-mono text-[11px] text-slate-400" title={tech.evidence}>
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
          <div className="mt-3 border-t border-slate-800/80 pt-3">
            <div className="flex items-center gap-2 text-xs font-semibold text-slate-200">
              <Puzzle className="h-3.5 w-3.5 text-violet-400" />
              WordPress Plugins Detected ({website.wordpress_plugins.length})
            </div>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {website.wordpress_plugins.map((slug) => (
                <span
                  key={slug}
                  className="rounded-md border border-violet-500/30 bg-violet-500/10 px-2 py-0.5 font-mono text-[11px] text-violet-200"
                >
                  {slug}
                </span>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* HTTP Security Headers */}
      <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
          <Shield className="h-4 w-4 text-emerald-400" />
          HTTP Security Headers
        </div>
        <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {website.security_headers.map((hdr) => (
            <div
              key={hdr.name}
              title={hdr.value ?? "Header not present"}
              className="flex items-center justify-between gap-2 rounded-lg border border-slate-800 bg-[#0b0f17] px-3 py-2"
            >
              <span className="truncate font-mono text-xs text-slate-200">
                {hdr.name}
              </span>
              {hdr.present ? (
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-medium text-emerald-300">
                  <CheckCircle2 className="h-3.5 w-3.5" />
                  Present
                </span>
              ) : (
                <span className="inline-flex shrink-0 items-center gap-1 text-[11px] font-medium text-slate-500">
                  <XCircle className="h-3.5 w-3.5" />
                  Missing
                </span>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Assets & Headers Inspector */}
      <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 bg-[#0d131f] px-4 py-2.5">
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setAssetTab("scripts")}
              className={`inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs font-medium transition ${
                assetTab === "scripts"
                  ? "bg-sky-500/15 text-sky-300"
                  : "text-slate-400 hover:text-slate-200"
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
                  ? "bg-sky-500/15 text-sky-300"
                  : "text-slate-400 hover:text-slate-200"
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
                  ? "bg-sky-500/15 text-sky-300"
                  : "text-slate-400 hover:text-slate-200"
              }`}
            >
              Response Headers ({website.response_headers.length})
            </button>
          </div>

          {assetTab === "headers" && website.response_headers.length > 0 && (
            <button
              type="button"
              onClick={copyHeaders}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:border-sky-500/50 hover:text-sky-300"
            >
              {copiedHeaders ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
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
              <div className="text-xs text-slate-500">No external script tags found.</div>
            ) : (
              <ul className="space-y-1.5 font-mono text-xs text-slate-300">
                {website.script_urls.map((u, idx) => (
                  <li key={idx} className="break-all rounded bg-[#0b0f17] px-2.5 py-1.5">
                    {u}
                  </li>
                ))}
              </ul>
            )
          )}

          {assetTab === "styles" && (
            website.stylesheet_urls.length === 0 ? (
              <div className="text-xs text-slate-500">No external stylesheet links found.</div>
            ) : (
              <ul className="space-y-1.5 font-mono text-xs text-slate-300">
                {website.stylesheet_urls.map((u, idx) => (
                  <li key={idx} className="break-all rounded bg-[#0b0f17] px-2.5 py-1.5">
                    {u}
                  </li>
                ))}
              </ul>
            )
          )}

          {assetTab === "headers" && (
            <div className="divide-y divide-slate-800/70 font-mono text-xs">
              {website.response_headers.map((h, idx) => (
                <div key={`${h.name}-${idx}`} className="grid grid-cols-1 gap-1 py-1.5 sm:grid-cols-3">
                  <span className="font-semibold text-sky-300">{h.name}</span>
                  <span className="break-all text-slate-300 sm:col-span-2">{h.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
