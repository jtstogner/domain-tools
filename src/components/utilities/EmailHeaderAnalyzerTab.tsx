import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Clock,
  Globe2,
  KeyRound,
  MailSearch,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  XCircle,
} from "lucide-react";
import { useMemo, useState } from "react";
import { parseEmailHeaders } from "../../lib/emailHeaders";

export interface EmailHeaderAnalyzerTabProps {
  onInspectDomain: (domain: string, options?: { dkimSelectors?: string }) => void;
  onCheckDnsbl: (target: string) => void;
  onNotify: (msg: string) => void;
}

const SAMPLE_EMAIL_HEADERS = `Delivered-To: security@example.com
Received: by 2002:a05:620a:1702:b0:79c:1234:5678 with SMTP id a2csp184290qkl;
        Thu, 15 May 2026 14:22:48 -0700 (PDT)
Return-Path: <bounces+9182@mail.acme-corp.example>
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])
        by mx.google.com with SMTPS id d2e1a72fcca58-702c1a49e1bsor812340b3a.12.2026.05.15.14.22.45
        for <security@example.com>;
        Thu, 15 May 2026 14:22:45 -0700 (PDT)
Received: from app-mailer-01.internal.acme-corp.example ([198.51.100.42])
        by mail-sor-f41.google.com with ESMTPSA id k18-20020a170902d212;
        Thu, 15 May 2026 14:22:02 -0700 (PDT)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@acme-corp.example header.s=google header.b=k9LmN1pQ;
       spf=pass (google.com: domain of bounces+9182@mail.acme-corp.example designates 209.85.220.41 as permitted sender) smtp.mailfrom=bounces+9182@mail.acme-corp.example;
       dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=acme-corp.example
DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed;
        d=acme-corp.example; s=google;
        h=from:to:subject:date:message-id:mime-version;
        bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=;
        b=k9LmN1pQexampleSignaturePayload==
From: Acme Billing <billing@acme-corp.example>
To: Security Team <security@example.com>
Subject: Monthly Invoice #2026-05
Date: Thu, 15 May 2026 14:22:00 -0700
Message-ID: <inv-202605-9182@acme-corp.example>`;

function formatDelay(sec: number | null): string {
  if (sec === null) return "—";
  if (sec < 0) return `${sec}s (skew)`;
  if (sec < 60) return `+${sec}s`;
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  return `+${m}m ${s}s`;
}

export function EmailHeaderAnalyzerTab({
  onInspectDomain,
  onCheckDnsbl,
  onNotify,
}: EmailHeaderAnalyzerTabProps) {
  const [rawHeaders, setRawHeaders] = useState("");
  const [showRawTable, setShowRawTable] = useState(false);
  const [headerFilter, setHeaderFilter] = useState("");

  const parsed = useMemo(() => {
    if (!rawHeaders.trim()) return null;
    return parseEmailHeaders(rawHeaders);
  }, [rawHeaders]);

  const filteredRawHeaders = useMemo(() => {
    if (!parsed) return [];
    const q = headerFilter.trim().toLowerCase();
    if (!q) return parsed.headers;
    return parsed.headers.filter(
      (h) => h.name.toLowerCase().includes(q) || h.value.toLowerCase().includes(q),
    );
  }, [parsed, headerFilter]);

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <MailSearch className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">Email Header Analyzer</h3>
              <p className="text-[11px] text-ink-muted">
                Paste raw RFC 5322 email headers (&quot;Show Original&quot; / &quot;View Source&quot;) to trace Received hops, SPF/DKIM/DMARC/ARC results, and alignment locally.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => {
                setRawHeaders(SAMPLE_EMAIL_HEADERS);
                onNotify("Loaded sample email headers");
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              <Sparkles className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
              Load Sample
            </button>
            {rawHeaders && (
              <button
                type="button"
                onClick={() => setRawHeaders("")}
                className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs text-ink-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </button>
            )}
          </div>
        </div>

        <textarea
          rows={6}
          value={rawHeaders}
          onChange={(e) => setRawHeaders(e.target.value)}
          placeholder="Paste raw email headers here (Received:, Authentication-Results:, DKIM-Signature:, From:, Return-Path:, etc.)..."
          className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
        />
      </div>

      {parsed && (
        <div className="space-y-4">
          {/* Suspicious Findings */}
          {parsed.suspiciousFindings.length > 0 && (
            <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-3.5 space-y-1.5">
              <div className="flex items-center gap-1.5 text-xs font-semibold text-amber-800 dark:text-amber-200">
                <AlertTriangle className="h-4 w-4" />
                Notable / Suspicious Findings ({parsed.suspiciousFindings.length})
              </div>
              {parsed.suspiciousFindings.map((finding, idx) => (
                <div key={idx} className="text-xs text-amber-900 dark:text-amber-200/90">
                  • {finding}
                </div>
              ))}
            </div>
          )}

          {/* Envelope & Key Metadata Cards */}
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">From</div>
              <div className="mt-1 break-all font-mono text-xs font-semibold text-ink">
                {parsed.from ?? "—"}
              </div>
              {parsed.fromDomain && (
                <button
                  type="button"
                  onClick={() => onInspectDomain(parsed.fromDomain!)}
                  className="mt-1.5 inline-flex items-center gap-1 text-[11px] text-sky-600 hover:underline dark:text-sky-400"
                >
                  <Globe2 className="h-3 w-3" />
                  Inspect {parsed.fromDomain}
                </button>
              )}
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Return-Path (Envelope)</div>
              <div className="mt-1 break-all font-mono text-xs font-semibold text-ink">
                {parsed.returnPath ?? "—"}
              </div>
              {parsed.replyTo && (
                <div className="mt-1 truncate font-mono text-[10px] text-ink-muted" title={parsed.replyTo}>
                  Reply-To: {parsed.replyTo}
                </div>
              )}
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Originating IP</div>
              <div className="mt-1 font-mono text-xs font-semibold text-ink">
                {parsed.originatingIp ?? "Not detected"}
              </div>
              {parsed.originatingIp && (
                <button
                  type="button"
                  onClick={() => onCheckDnsbl(parsed.originatingIp!)}
                  className="mt-1.5 inline-flex items-center gap-1 text-[11px] text-sky-600 hover:underline dark:text-sky-400"
                >
                  <ShieldAlert className="h-3 w-3" />
                  Check IP in DNSBL
                </button>
              )}
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Delivery Summary</div>
              <div className="mt-1 font-mono text-xs font-semibold text-ink">
                {parsed.hops.length} hop{parsed.hops.length === 1 ? "" : "s"} ·{" "}
                {parsed.totalTransitSeconds !== null
                  ? `${parsed.totalTransitSeconds}s total`
                  : "Transit N/A"}
              </div>
              {parsed.subject && (
                <div className="mt-1 truncate text-[11px] text-ink-secondary" title={parsed.subject}>
                  Subj: {parsed.subject}
                </div>
              )}
            </div>
          </div>

          {/* Auth Results + Alignment */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <div className="rounded-xl border border-line bg-surface p-4 space-y-2.5">
              <div className="text-xs font-semibold text-ink">
                Authentication Results ({parsed.authVerdicts.length})
              </div>
              {parsed.authVerdicts.length > 0 ? (
                <div className="space-y-2">
                  {parsed.authVerdicts.map((v, idx) => (
                    <div
                      key={idx}
                      className={`rounded-lg border p-2.5 text-xs ${
                        v.status === "pass"
                          ? "border-emerald-500/30 bg-emerald-500/[0.06]"
                          : v.status === "fail"
                            ? "border-rose-500/35 bg-rose-500/[0.08]"
                            : v.status === "warn"
                              ? "border-amber-500/35 bg-amber-500/[0.07]"
                              : "border-line bg-canvas"
                      }`}
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono text-xs font-semibold uppercase text-ink">
                          {v.mechanism}
                        </span>
                        <span
                          className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 font-mono text-[10px] font-semibold uppercase ${
                            v.status === "pass"
                              ? "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                              : v.status === "fail"
                                ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                                : v.status === "warn"
                                  ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                  : "bg-surface-alt text-ink-secondary"
                          }`}
                        >
                          {v.status === "pass" ? (
                            <CheckCircle2 className="h-3 w-3" />
                          ) : v.status === "fail" ? (
                            <XCircle className="h-3 w-3" />
                          ) : (
                            <AlertTriangle className="h-3 w-3" />
                          )}
                          {v.result}
                        </span>
                      </div>
                      <div className="mt-1 break-all font-mono text-[11px] text-ink-secondary">
                        {v.detail}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs italic text-ink-muted">
                  No Authentication-Results or Received-SPF headers found.
                </p>
              )}
            </div>

            <div className="space-y-4">
              {/* Alignment Checks */}
              <div className="rounded-xl border border-line bg-surface p-4 space-y-2.5">
                <div className="text-xs font-semibold text-ink">
                  Domain Alignment &amp; Spoofing Checks
                </div>
                {parsed.alignmentChecks.length > 0 ? (
                  <div className="space-y-2">
                    {parsed.alignmentChecks.map((chk, idx) => (
                      <div
                        key={idx}
                        className="flex items-start gap-2 rounded-lg border border-line bg-canvas p-2.5 text-xs"
                      >
                        {chk.status === "pass" ? (
                          <ShieldCheck className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
                        ) : chk.status === "fail" ? (
                          <ShieldAlert className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
                        ) : (
                          <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                        )}
                        <div>
                          <div className="font-semibold text-ink">{chk.label}</div>
                          <div className="text-[11px] text-ink-secondary">{chk.detail}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs italic text-ink-muted">
                    No From/Return-Path domains detected to check alignment.
                  </p>
                )}
              </div>

              {/* DKIM Signatures + 1-Click Selector Inspect */}
              <div className="rounded-xl border border-line bg-surface p-4 space-y-2.5">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-ink">
                  <KeyRound className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                  DKIM Signatures ({parsed.dkimSignatures.length})
                </div>
                {parsed.dkimSignatures.length > 0 ? (
                  <div className="space-y-2">
                    {parsed.dkimSignatures.map((sig, idx) => (
                      <div
                        key={idx}
                        className="rounded-lg border border-line bg-canvas p-2.5 text-xs space-y-1.5"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="font-mono text-xs text-ink">
                            d=<span className="font-semibold">{sig.domain ?? "?"}</span> · s=
                            <span className="font-semibold text-sky-700 dark:text-sky-300">
                              {sig.selector ?? "?"}
                            </span>
                            {sig.algorithm && (
                              <span className="ml-1.5 text-[10px] text-ink-muted">
                                ({sig.algorithm})
                              </span>
                            )}
                          </div>
                          {sig.domain && sig.selector && (
                            <button
                              type="button"
                              onClick={() =>
                                onInspectDomain(sig.domain!, { dkimSelectors: sig.selector! })
                              }
                              className="inline-flex items-center gap-1 rounded-md bg-sky-600 px-2.5 py-1 text-[11px] font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                            >
                              <Globe2 className="h-3 w-3" />
                              Inspect DKIM Selector
                            </button>
                          )}
                        </div>
                        {sig.signedHeaders.length > 0 && (
                          <div className="text-[10px] text-ink-muted">
                            Signed headers:{" "}
                            <span className="font-mono text-ink-secondary">
                              {sig.signedHeaders.join(", ")}
                            </span>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs italic text-ink-muted">No DKIM-Signature headers found.</p>
                )}
              </div>
            </div>
          </div>

          {/* Received Hop Timeline */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5 text-xs">
              <span className="inline-flex items-center gap-1.5 font-semibold text-ink">
                <Clock className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                Received Hop Timeline (Oldest → Delivered)
              </span>
              <span className="font-mono text-[11px] text-ink-muted">
                {parsed.hops.length} hop{parsed.hops.length === 1 ? "" : "s"}
              </span>
            </div>

            {parsed.hops.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-3 py-2">Hop</th>
                      <th className="px-3 py-2">From → By</th>
                      <th className="px-3 py-2">IP</th>
                      <th className="px-3 py-2">Protocol</th>
                      <th className="px-3 py-2">Timestamp</th>
                      <th className="px-3 py-2 text-right">Delay</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {parsed.hops.map((hop) => (
                      <tr key={hop.index} className="hover:bg-surface-alt/60">
                        <td className="px-3 py-2.5 font-mono font-semibold text-ink-muted">
                          #{hop.index}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px]">
                          <div className="text-ink-secondary">from: {hop.from ?? "—"}</div>
                          <div className="font-semibold text-ink">by: {hop.by ?? "—"}</div>
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px]">
                          {hop.ip ? (
                            <div className="flex items-center gap-1.5">
                              <span className="text-ink">{hop.ip}</span>
                              {!hop.ip.includes(":") && (
                                <button
                                  type="button"
                                  onClick={() => onCheckDnsbl(hop.ip!)}
                                  title="Check this IP in DNSBL"
                                  className="rounded border border-line bg-surface-alt px-1.5 py-0.5 text-[10px] text-sky-700 hover:border-sky-500/40 dark:text-sky-300"
                                >
                                  DNSBL
                                </button>
                              )}
                            </div>
                          ) : (
                            <span className="text-ink-muted">—</span>
                          )}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-ink-secondary">
                          {hop.withProtocol ?? "—"}
                        </td>
                        <td className="px-3 py-2.5 font-mono text-[11px] text-ink-muted">
                          {hop.timestamp ?? "—"}
                        </td>
                        <td className="px-3 py-2.5 text-right font-mono text-[11px]">
                          <span
                            className={`rounded-full px-2 py-0.5 font-semibold ${
                              hop.flag === "clock_skew"
                                ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                                : hop.flag === "slow"
                                  ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                  : "text-ink-secondary"
                            }`}
                          >
                            {formatDelay(hop.delaySeconds)}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="p-4 text-xs italic text-ink-muted">No Received headers found.</div>
            )}
          </div>

          {/* Collapsible All Unfolded Headers */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <button
              type="button"
              onClick={() => setShowRawTable((s) => !s)}
              className="flex w-full items-center justify-between bg-surface-alt px-4 py-2.5 text-xs font-semibold text-ink hover:bg-surface-alt/80"
            >
              <span className="inline-flex items-center gap-1.5">
                {showRawTable ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
                All Unfolded Headers ({parsed.headers.length})
              </span>
              <span className="text-[11px] font-normal text-ink-muted">
                {showRawTable ? "Click to collapse" : "Click to inspect"}
              </span>
            </button>

            {showRawTable && (
              <div className="p-3 space-y-2.5">
                <input
                  type="text"
                  value={headerFilter}
                  onChange={(e) => setHeaderFilter(e.target.value)}
                  placeholder="Filter header name or value..."
                  className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                />
                <div className="max-h-72 overflow-auto rounded-lg border border-line">
                  <table className="w-full border-collapse text-left font-mono text-[11px]">
                    <tbody className="divide-y divide-line">
                      {filteredRawHeaders.map((h, idx) => (
                        <tr key={idx} className="hover:bg-surface-alt/50">
                          <td className="w-44 align-top px-3 py-1.5 font-semibold text-sky-700 dark:text-sky-300">
                            {h.name}
                          </td>
                          <td className="break-all px-3 py-1.5 text-ink-secondary">{h.value}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
