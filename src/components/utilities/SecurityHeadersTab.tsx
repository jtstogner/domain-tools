import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Lock,
  ServerCog,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { copyToClipboard } from "../../lib/api";
import {
  buildHsts,
  buildPermissionsPolicy,
  buildSecurityHeadersMap,
  CSP_DIRECTIVE_NAMES,
  CSP_PRESETS,
  type CspDirectives,
  type CspPresetId,
  DEFAULT_SECURITY_HEADERS,
  evaluateCsp,
  generateServerConfig,
  parseCsp,
  PERMISSIONS_FEATURES,
  type PermissionsPolicyConfig,
  serializeCsp,
  type ServerConfigFormat,
} from "../../lib/securityHeaders";
import type { DnsQueryReport } from "../../types/dns";

export interface SecurityHeadersTabProps {
  currentReport?: DnsQueryReport | null;
  onNotify: (msg: string) => void;
}

const SERVER_FORMATS: Array<{ id: ServerConfigFormat; label: string }> = [
  { id: "nginx", label: "Nginx" },
  { id: "apache", label: "Apache" },
  { id: "caddy", label: "Caddy" },
  { id: "cloudflare", label: "Cloudflare Pages" },
  { id: "iis", label: "IIS web.config" },
];

export function SecurityHeadersTab({ currentReport, onNotify }: SecurityHeadersTabProps) {
  const [cspMode, setCspMode] = useState<"builder" | "raw">("builder");
  const [directives, setDirectives] = useState<CspDirectives>(() => ({
    ...CSP_PRESETS["strict-spa"].directives,
  }));
  const [rawCsp, setRawCsp] = useState(() => serializeCsp(CSP_PRESETS["strict-spa"].directives));

  // HSTS state
  const [hstsMaxAge, setHstsMaxAge] = useState("63072000");
  const [hstsIncludeSub, setHstsIncludeSub] = useState(true);
  const [hstsPreload, setHstsPreload] = useState(true);

  // Permissions-Policy state
  const [permissions, setPermissions] = useState<PermissionsPolicyConfig>(() => {
    const init: PermissionsPolicyConfig = {};
    for (const f of PERMISSIONS_FEATURES) {
      init[f.id] = f.defaultValue;
    }
    return init;
  });

  // Other headers
  const [xContentType, setXContentType] = useState(DEFAULT_SECURITY_HEADERS.xContentTypeOptions);
  const [xFrame, setXFrame] = useState(DEFAULT_SECURITY_HEADERS.xFrameOptions);
  const [referrerPolicy, setReferrerPolicy] = useState(DEFAULT_SECURITY_HEADERS.referrerPolicy);
  const [coop, setCoop] = useState(DEFAULT_SECURITY_HEADERS.coop);
  const [corp, setCorp] = useState(DEFAULT_SECURITY_HEADERS.corp);

  // Server output format
  const [serverFormat, setServerFormat] = useState<ServerConfigFormat>("nginx");

  const activeCspValue = useMemo(
    () => (cspMode === "builder" ? serializeCsp(directives) : rawCsp.trim()),
    [cspMode, directives, rawCsp],
  );

  const cspEval = useMemo(() => evaluateCsp(activeCspValue), [activeCspValue]);

  const hstsEval = useMemo(
    () =>
      buildHsts({
        maxAge: Number(hstsMaxAge) || 0,
        includeSubDomains: hstsIncludeSub,
        preload: hstsPreload,
      }),
    [hstsMaxAge, hstsIncludeSub, hstsPreload],
  );

  const permissionsValue = useMemo(() => buildPermissionsPolicy(permissions), [permissions]);

  const headersMap = useMemo(
    () =>
      buildSecurityHeadersMap({
        csp: activeCspValue,
        hsts: hstsEval.headerValue,
        permissionsPolicy: permissionsValue,
        xContentTypeOptions: xContentType,
        xFrameOptions: xFrame,
        referrerPolicy,
        coop,
        corp,
      }),
    [
      activeCspValue,
      hstsEval.headerValue,
      permissionsValue,
      xContentType,
      xFrame,
      referrerPolicy,
      coop,
      corp,
    ],
  );

  const serverConfig = useMemo(
    () => generateServerConfig(serverFormat, headersMap),
    [serverFormat, headersMap],
  );

  const applyPreset = (id: CspPresetId) => {
    const next = { ...CSP_PRESETS[id].directives };
    setDirectives(next);
    setRawCsp(serializeCsp(next));
    onNotify(`Applied ${CSP_PRESETS[id].label} CSP preset`);
  };

  const updateDirective = (name: string, text: string) => {
    const tokens = text.split(/\s+/).filter(Boolean);
    setDirectives((prev) => {
      const next = { ...prev };
      if (tokens.length === 0) {
        delete next[name];
      } else {
        next[name] = tokens;
      }
      setRawCsp(serializeCsp(next));
      return next;
    });
  };

  const toggleUpgradeInsecure = (checked: boolean) => {
    setDirectives((prev) => {
      const next = { ...prev };
      if (checked) {
        next["upgrade-insecure-requests"] = [];
      } else {
        delete next["upgrade-insecure-requests"];
      }
      setRawCsp(serializeCsp(next));
      return next;
    });
  };

  const importFromCurrentReport = () => {
    const respHeaders = currentReport?.website?.response_headers;
    if (!respHeaders || respHeaders.length === 0) return;

    const findHeader = (name: string) =>
      respHeaders.find((h) => h.name.toLowerCase() === name.toLowerCase())?.value ?? null;

    const liveCsp = findHeader("content-security-policy");
    const liveHsts = findHeader("strict-transport-security");

    if (liveCsp) {
      setRawCsp(liveCsp);
      setDirectives(parseCsp(liveCsp));
      setCspMode("raw");
    }
    if (liveHsts) {
      const ageMatch = liveHsts.match(/max-age\s*=\s*(\d+)/i);
      if (ageMatch) setHstsMaxAge(ageMatch[1]);
      setHstsIncludeSub(/includesubdomains/i.test(liveHsts));
      setHstsPreload(/preload/i.test(liveHsts));
    }
    onNotify(`Imported live headers from ${currentReport.domain}`);
  };

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  const gradeTone =
    cspEval.grade === "A+" || cspEval.grade === "A"
      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
      : cspEval.grade === "B"
        ? "border-sky-500/40 bg-sky-500/15 text-sky-700 dark:text-sky-300"
        : cspEval.grade === "C"
          ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
          : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300";

  const hasLiveHeaders = (currentReport?.website?.response_headers?.length ?? 0) > 0;

  return (
    <div className="space-y-4">
      {/* CSP Builder & Live Grader */}
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4 xl:col-span-7">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
            <div>
              <h3 className="text-sm font-semibold text-ink">
                Content-Security-Policy (CSP) Builder
              </h3>
              <p className="text-[11px] text-ink-muted">
                Build directives interactively or paste a live CSP header to grade XSS &amp; clickjacking defense.
              </p>
            </div>
            <div className="flex items-center gap-1.5">
              {hasLiveHeaders && (
                <button
                  type="button"
                  onClick={importFromCurrentReport}
                  className="inline-flex items-center gap-1 rounded-lg border border-sky-500/35 bg-sky-500/10 px-2.5 py-1 text-[11px] font-medium text-sky-700 hover:bg-sky-500/15 dark:text-sky-300"
                >
                  <Download className="h-3 w-3" />
                  Import {currentReport?.domain}
                </button>
              )}
              <div className="inline-flex rounded-lg border border-line bg-surface-alt p-0.5 text-[11px]">
                <button
                  type="button"
                  onClick={() => setCspMode("builder")}
                  className={`rounded-md px-2.5 py-1 font-medium ${
                    cspMode === "builder"
                      ? "bg-surface text-ink shadow-sm"
                      : "text-ink-muted hover:text-ink"
                  }`}
                >
                  Builder
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setRawCsp(serializeCsp(directives));
                    setCspMode("raw");
                  }}
                  className={`rounded-md px-2.5 py-1 font-medium ${
                    cspMode === "raw"
                      ? "bg-surface text-ink shadow-sm"
                      : "text-ink-muted hover:text-ink"
                  }`}
                >
                  Raw / Audit
                </button>
              </div>
            </div>
          </div>

          {/* Presets */}
          <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
            <span className="text-ink-muted">Presets:</span>
            {(Object.keys(CSP_PRESETS) as CspPresetId[]).map((id) => (
              <button
                key={id}
                type="button"
                title={CSP_PRESETS[id].description}
                onClick={() => applyPreset(id)}
                className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
              >
                {CSP_PRESETS[id].label}
              </button>
            ))}
          </div>

          {cspMode === "builder" ? (
            <div className="space-y-2 text-xs">
              <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                {CSP_DIRECTIVE_NAMES.filter((d) => d !== "upgrade-insecure-requests").map(
                  (dir) => (
                    <div key={dir}>
                      <label className="mb-0.5 block font-mono text-[11px] text-ink-muted">
                        {dir}
                      </label>
                      <input
                        type="text"
                        value={(directives[dir] ?? []).join(" ")}
                        onChange={(e) => updateDirective(dir, e.target.value)}
                        placeholder="(omitted)"
                        className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1 font-mono text-[11px] text-ink focus:border-sky-500 focus:outline-none"
                      />
                    </div>
                  ),
                )}
              </div>

              <label className="inline-flex cursor-pointer items-center gap-2 pt-1 text-xs text-ink-secondary">
                <input
                  type="checkbox"
                  checked={"upgrade-insecure-requests" in directives}
                  onChange={(e) => toggleUpgradeInsecure(e.target.checked)}
                />
                Include <span className="font-mono text-ink">upgrade-insecure-requests</span>
              </label>
            </div>
          ) : (
            <div className="space-y-2">
              <textarea
                rows={6}
                value={rawCsp}
                onChange={(e) => {
                  setRawCsp(e.target.value);
                  setDirectives(parseCsp(e.target.value));
                }}
                placeholder="default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none'"
                className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
              />
            </div>
          )}

          {/* Live Header Preview */}
          <div className="rounded-lg border border-line bg-canvas p-2.5">
            <div className="flex items-center justify-between text-[11px] text-ink-muted">
              <span className="font-mono">Content-Security-Policy</span>
              <button
                type="button"
                onClick={() => void copyText(activeCspValue, "CSP header value")}
                className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
              >
                <Copy className="h-3 w-3" /> Copy Value
              </button>
            </div>
            <div className="mt-1 break-all font-mono text-[11px] text-ink">
              {activeCspValue || "(empty)"}
            </div>
          </div>
        </div>

        {/* CSP Grader Card */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4 xl:col-span-5">
          <div className="flex items-center justify-between gap-2 border-b border-line pb-3">
            <div>
              <div className="text-sm font-semibold text-ink">CSP Security Grade</div>
              <div className="text-[11px] text-ink-muted">
                Static analysis for unsafe directives &amp; missing protections
              </div>
            </div>
            <div
              className={`inline-flex items-center gap-1.5 rounded-xl border px-3 py-1 font-mono text-sm font-bold ${gradeTone}`}
            >
              <span>{cspEval.grade}</span>
              <span className="text-xs font-medium opacity-80">{cspEval.score}/100</span>
            </div>
          </div>

          <div className="max-h-[360px] space-y-2 overflow-y-auto pr-1">
            {cspEval.issues.map((issue, idx) => (
              <div
                key={idx}
                className={`flex items-start gap-2 rounded-lg border p-2.5 text-xs ${
                  issue.level === "pass"
                    ? "border-emerald-500/25 bg-emerald-500/[0.06] text-emerald-800 dark:text-emerald-200"
                    : issue.level === "warn"
                      ? "border-amber-500/30 bg-amber-500/[0.07] text-amber-800 dark:text-amber-200"
                      : "border-rose-500/35 bg-rose-500/[0.08] text-rose-800 dark:text-rose-200"
                }`}
              >
                {issue.level === "pass" ? (
                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                ) : issue.level === "warn" ? (
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                ) : (
                  <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
                )}
                <div>
                  <span className="font-mono font-semibold">{issue.directive}: </span>
                  <span>{issue.message}</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* HSTS + Permissions-Policy + Core Headers */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* HSTS Preload Checker */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4 text-xs">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
            <div className="flex items-center gap-1.5 font-semibold text-ink">
              <Lock className="h-4 w-4 text-sky-600 dark:text-sky-400" />
              HSTS &amp; Preload Checker
            </div>
            <span
              className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                hstsEval.preloadEligible
                  ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                  : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
              }`}
            >
              {hstsEval.preloadEligible ? (
                <ShieldCheck className="h-3 w-3" />
              ) : (
                <ShieldAlert className="h-3 w-3" />
              )}
              {hstsEval.preloadEligible ? "Preload Eligible" : "Not Preload Ready"}
            </span>
          </div>

          <div className="flex flex-wrap items-end gap-2">
            <div className="flex-1 min-w-[140px]">
              <label className="mb-1 block text-[11px] text-ink-muted">max-age (seconds)</label>
              <input
                type="number"
                min={0}
                value={hstsMaxAge}
                onChange={(e) => setHstsMaxAge(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
              />
            </div>
            <div className="flex flex-wrap gap-1">
              {[
                ["1d", "86400"],
                ["1y", "31536000"],
                ["2y", "63072000"],
              ].map(([label, val]) => (
                <button
                  key={label}
                  type="button"
                  onClick={() => setHstsMaxAge(val)}
                  className="rounded-md border border-line bg-surface-alt px-2 py-1.5 font-mono text-[11px] text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          <div className="flex flex-wrap gap-4">
            <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
              <input
                type="checkbox"
                checked={hstsIncludeSub}
                onChange={(e) => setHstsIncludeSub(e.target.checked)}
              />
              <span className="font-mono">includeSubDomains</span>
            </label>
            <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
              <input
                type="checkbox"
                checked={hstsPreload}
                onChange={(e) => setHstsPreload(e.target.checked)}
              />
              <span className="font-mono">preload</span>
            </label>
          </div>

          <div className="space-y-1.5">
            {hstsEval.checks.map((c, idx) => (
              <div
                key={idx}
                className="flex items-start gap-2 rounded-lg border border-line bg-canvas px-2.5 py-2 text-[11px]"
              >
                {c.pass ? (
                  <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                ) : (
                  <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                )}
                <div>
                  <div className="font-semibold text-ink">{c.label}</div>
                  <div className="text-ink-muted">{c.detail}</div>
                </div>
              </div>
            ))}
          </div>

          <div className="rounded-lg border border-line bg-canvas p-2.5">
            <div className="flex items-center justify-between text-[11px] text-ink-muted">
              <span className="font-mono">Strict-Transport-Security</span>
              <button
                type="button"
                onClick={() => void copyText(hstsEval.headerValue, "HSTS header")}
                className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
              >
                <Copy className="h-3 w-3" /> Copy
              </button>
            </div>
            <div className="mt-1 font-mono text-xs text-ink">{hstsEval.headerValue}</div>
          </div>
        </div>

        {/* Permissions-Policy & Core Headers */}
        <div className="space-y-3 rounded-xl border border-line bg-surface p-4 text-xs">
          <div className="border-b border-line pb-2.5 font-semibold text-ink">
            Permissions-Policy &amp; Core Browser Headers
          </div>

          <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
            {PERMISSIONS_FEATURES.map((feat) => (
              <div key={feat.id}>
                <label className="mb-0.5 block text-[11px] text-ink-muted">{feat.label}</label>
                <select
                  value={permissions[feat.id] ?? "()"}
                  onChange={(e) =>
                    setPermissions((prev) => ({ ...prev, [feat.id]: e.target.value }))
                  }
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
                >
                  <option value="()">Disabled ()</option>
                  <option value="self">Same-Origin (self)</option>
                  <option value="*">Allow All (*)</option>
                </select>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 gap-2 border-t border-line pt-3 sm:grid-cols-2">
            <div>
              <label className="mb-0.5 block text-[11px] text-ink-muted">
                X-Content-Type-Options
              </label>
              <select
                value={xContentType}
                onChange={(e) => setXContentType(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
              >
                <option value="nosniff">nosniff</option>
                <option value="">(omit)</option>
              </select>
            </div>
            <div>
              <label className="mb-0.5 block text-[11px] text-ink-muted">X-Frame-Options</label>
              <select
                value={xFrame}
                onChange={(e) => setXFrame(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
              >
                <option value="DENY">DENY</option>
                <option value="SAMEORIGIN">SAMEORIGIN</option>
                <option value="">(omit)</option>
              </select>
            </div>
            <div>
              <label className="mb-0.5 block text-[11px] text-ink-muted">Referrer-Policy</label>
              <select
                value={referrerPolicy}
                onChange={(e) => setReferrerPolicy(e.target.value)}
                className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
              >
                <option value="strict-origin-when-cross-origin">
                  strict-origin-when-cross-origin
                </option>
                <option value="no-referrer">no-referrer</option>
                <option value="same-origin">same-origin</option>
                <option value="strict-origin">strict-origin</option>
                <option value="">(omit)</option>
              </select>
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <div>
                <label className="mb-0.5 block text-[11px] text-ink-muted">COOP</label>
                <select
                  value={coop}
                  onChange={(e) => setCoop(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
                >
                  <option value="same-origin">same-origin</option>
                  <option value="same-origin-allow-popups">allow-popups</option>
                  <option value="">(omit)</option>
                </select>
              </div>
              <div>
                <label className="mb-0.5 block text-[11px] text-ink-muted">CORP</label>
                <select
                  value={corp}
                  onChange={(e) => setCorp(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1 font-mono text-[11px] text-ink"
                >
                  <option value="same-origin">same-origin</option>
                  <option value="same-site">same-site</option>
                  <option value="cross-origin">cross-origin</option>
                  <option value="">(omit)</option>
                </select>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Server Config Generator */}
      <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <ServerCog className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <span className="text-sm font-semibold text-ink">
              Ready-to-Deploy Server Configuration
            </span>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <div className="inline-flex flex-wrap rounded-lg border border-line bg-surface-alt p-0.5 text-[11px]">
              {SERVER_FORMATS.map((fmt) => (
                <button
                  key={fmt.id}
                  type="button"
                  onClick={() => setServerFormat(fmt.id)}
                  className={`rounded-md px-2.5 py-1 font-medium transition ${
                    serverFormat === fmt.id
                      ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                      : "text-ink-muted hover:text-ink"
                  }`}
                >
                  {fmt.label}
                </button>
              ))}
            </div>

            <button
              type="button"
              onClick={() => void copyText(serverConfig, `${serverFormat} security headers config`)}
              className="inline-flex items-center gap-1 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
            >
              <Copy className="h-3.5 w-3.5" />
              Copy Config
            </button>
          </div>
        </div>

        <pre className="overflow-x-auto rounded-lg border border-line bg-canvas p-3.5 font-mono text-xs text-ink">
          {serverConfig}
        </pre>
      </div>
    </div>
  );
}
