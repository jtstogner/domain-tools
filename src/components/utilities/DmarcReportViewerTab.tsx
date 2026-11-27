import {
  AlertTriangle,
  CheckCircle2,
  FileSpreadsheet,
  Globe2,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Trash2,
  Upload,
} from "lucide-react";
import { type DragEvent, useRef, useState } from "react";
import {
  decompressGzipBytes,
  parseDmarcOrTlsRpt,
  type ParsedEmailReport,
} from "../../lib/dmarcReportParser";

export interface DmarcReportViewerTabProps {
  onInspectDomain: (domain: string) => void;
  onCheckDnsbl: (target: string) => void;
  onNotify: (msg: string) => void;
}

const SAMPLE_DMARC_XML = `<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata>
    <org_name>google.com</org_name>
    <email>noreply-dmarc-support@google.com</email>
    <report_id>14829304829103</report_id>
    <date_range>
      <begin>1778716800</begin>
      <end>1778803199</end>
    </date_range>
  </report_metadata>
  <policy_published>
    <domain>example.com</domain>
    <adkim>r</adkim>
    <aspf>r</aspf>
    <p>quarantine</p>
    <sp>quarantine</sp>
    <pct>100</pct>
  </policy_published>
  <record>
    <row>
      <source_ip>209.85.220.41</source_ip>
      <count>142</count>
      <policy_evaluated>
        <disposition>none</disposition>
        <dkim>pass</dkim>
        <spf>pass</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>example.com</envelope_from>
    </identifiers>
    <auth_results>
      <dkim><domain>example.com</domain><result>pass</result></dkim>
      <spf><domain>example.com</domain><result>pass</result></spf>
    </auth_results>
  </record>
  <record>
    <row>
      <source_ip>198.51.100.77</source_ip>
      <count>19</count>
      <policy_evaluated>
        <disposition>quarantine</disposition>
        <dkim>fail</dkim>
        <spf>fail</spf>
      </policy_evaluated>
    </row>
    <identifiers>
      <header_from>example.com</header_from>
      <envelope_from>spoof-mailer.invalid</envelope_from>
    </identifiers>
    <auth_results>
      <spf><domain>spoof-mailer.invalid</domain><result>fail</result></spf>
    </auth_results>
  </record>
</feedback>`;

const SAMPLE_TLS_RPT_JSON = JSON.stringify(
  {
    "organization-name": "Google Inc.",
    "date-range": {
      "start-datetime": "2026-05-14T00:00:00Z",
      "end-datetime": "2026-05-14T23:59:59Z",
    },
    "contact-info": "smtp-tls-reporting@google.com",
    "report-id": "2026-05-14T00:00:00Z_example.com",
    policies: [
      {
        policy: {
          "policy-type": "sts",
          "policy-string": ["version: STSv1", "mode: enforce", "mx: mail.example.com", "max_age: 604800"],
          "policy-domain": "example.com",
          "mx-host": ["mail.example.com"],
        },
        summary: {
          "total-successful-session-count": 482,
          "total-failure-session-count": 3,
        },
        "failure-details": [
          {
            "result-type": "certificate-expired",
            "sending-mta-ip": "209.85.215.44",
            "receiving-mx-hostname": "mail.example.com",
            "receiving-ip": "203.0.113.25",
            "failed-session-count": 3,
          },
        ],
      },
    ],
  },
  null,
  2,
);

export function DmarcReportViewerTab({
  onInspectDomain,
  onCheckDnsbl,
  onNotify,
}: DmarcReportViewerTabProps) {
  const [rawText, setRawText] = useState("");
  const [parsed, setParsed] = useState<ParsedEmailReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [showRawRows, setShowRawRows] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const parseContent = (text: string) => {
    setRawText(text);
    if (!text.trim()) {
      setParsed(null);
      setError(null);
      return;
    }
    try {
      const res = parseDmarcOrTlsRpt(text);
      setParsed(res);
      setError(null);
    } catch (err) {
      setParsed(null);
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleFile = async (file: File) => {
    try {
      const buf = await file.arrayBuffer();
      const text = await decompressGzipBytes(buf);
      parseContent(text);
      onNotify(`Loaded ${file.name}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) void handleFile(file);
  };

  return (
    <div className="space-y-4">
      {/* Input / Dropzone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        className={`rounded-xl border bg-surface p-4 space-y-3 transition ${
          dragging ? "border-sky-500 bg-sky-500/5" : "border-line"
        }`}
      >
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <FileSpreadsheet className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">
                DMARC Aggregate XML &amp; SMTP TLS-RPT Viewer
              </h3>
              <p className="text-[11px] text-ink-muted">
                Drop a `.xml`, `.xml.gz`, `.json`, or `.json.gz` report file — or paste raw XML/JSON below. Parsed 100% offline.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <input
              ref={fileInputRef}
              type="file"
              accept=".xml,.gz,.json,.txt"
              className="hidden"
              onChange={(e) => {
                const f = e.target.files?.[0];
                if (f) void handleFile(f);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
            >
              <Upload className="h-3.5 w-3.5" />
              Open File (.xml / .gz / .json)
            </button>
            <button
              type="button"
              onClick={() => {
                parseContent(SAMPLE_DMARC_XML);
                onNotify("Loaded sample DMARC XML");
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              <Sparkles className="h-3 w-3 text-sky-600 dark:text-sky-400" />
              Sample DMARC
            </button>
            <button
              type="button"
              onClick={() => {
                parseContent(SAMPLE_TLS_RPT_JSON);
                onNotify("Loaded sample TLS-RPT JSON");
              }}
              className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
            >
              Sample TLS-RPT
            </button>
            {rawText && (
              <button
                type="button"
                onClick={() => parseContent("")}
                className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2 py-1.5 text-xs text-ink-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>

        <textarea
          rows={5}
          value={rawText}
          onChange={(e) => parseContent(e.target.value)}
          placeholder="Paste DMARC <feedback>...</feedback> XML or RFC 8460 TLS-RPT JSON here, or drag & drop a .xml.gz / .json.gz file..."
          className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
        />
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-3.5 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {/* DMARC View */}
      {parsed && parsed.kind === "dmarc" && (
        <div className="space-y-4">
          {/* Summary Cards */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Domain &amp; Reporter</div>
              <div className="mt-1 flex items-center justify-between gap-2">
                <span className="truncate font-mono text-sm font-semibold text-ink">
                  {parsed.domain}
                </span>
                <button
                  type="button"
                  onClick={() => onInspectDomain(parsed.domain)}
                  title="Inspect domain"
                  className="shrink-0 text-sky-600 hover:text-sky-500 dark:text-sky-400"
                >
                  <Globe2 className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="mt-0.5 truncate text-[11px] text-ink-secondary">
                {parsed.orgName}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">DMARC Pass Rate</div>
              <div
                className={`mt-1 font-mono text-lg font-bold ${
                  parsed.passRate >= 95
                    ? "text-emerald-600 dark:text-emerald-400"
                    : parsed.passRate >= 80
                      ? "text-amber-600 dark:text-amber-400"
                      : "text-rose-600 dark:text-rose-400"
                }`}
              >
                {parsed.passRate}%
              </div>
              <div className="text-[11px] text-ink-muted">
                {parsed.dmarcPassCount.toLocaleString()} / {parsed.totalMessages.toLocaleString()}{" "}
                msgs
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Alignment Breakdown</div>
              <div className="mt-1 space-y-0.5 font-mono text-xs text-ink">
                <div>DKIM aligned: {parsed.dkimAlignedCount.toLocaleString()}</div>
                <div>SPF aligned: {parsed.spfAlignedCount.toLocaleString()}</div>
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Published Policy</div>
              <div className="mt-1 font-mono text-xs font-semibold text-ink">
                p={parsed.publishedPolicy.p} · sp={parsed.publishedPolicy.sp} · pct=
                {parsed.publishedPolicy.pct}%
              </div>
              <div className="mt-0.5 font-mono text-[10px] text-ink-muted">
                adkim={parsed.publishedPolicy.adkim} · aspf={parsed.publishedPolicy.aspf}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-line bg-surface px-4 py-2.5 text-[11px] text-ink-muted">
            <span>
              Report ID: <span className="font-mono text-ink-secondary">{parsed.reportId}</span>
            </span>
            <span className="font-mono">
              {parsed.dateRange.begin.slice(0, 19).replace("T", " ")} →{" "}
              {parsed.dateRange.end.slice(0, 19).replace("T", " ")} UTC
            </span>
          </div>

          {/* Source IP Breakdown Table */}
          <div className="overflow-hidden rounded-xl border border-line bg-surface">
            <div className="flex items-center justify-between border-b border-line bg-surface-alt px-4 py-2.5 text-xs">
              <span className="font-semibold text-ink">
                Sending Source IPs ({parsed.bySourceIp.length})
              </span>
              <button
                type="button"
                onClick={() => setShowRawRows((s) => !s)}
                className="text-[11px] text-sky-600 hover:underline dark:text-sky-400"
              >
                {showRawRows
                  ? "Show Grouped by IP"
                  : `Show All Raw Records (${parsed.records.length})`}
              </button>
            </div>

            {!showRawRows ? (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2">Source IP</th>
                      <th className="px-4 py-2 text-right">Volume</th>
                      <th className="px-4 py-2">DMARC Pass / Fail</th>
                      <th className="px-4 py-2">SPF / DKIM Aligned</th>
                      <th className="px-4 py-2">Dispositions</th>
                      <th className="px-4 py-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line">
                    {parsed.bySourceIp.map((src) => {
                      const passPct =
                        src.totalCount > 0 ? Math.round((src.passCount / src.totalCount) * 100) : 0;
                      return (
                        <tr key={src.sourceIp} className="hover:bg-surface-alt/60">
                          <td className="px-4 py-2.5">
                            <div className="font-mono font-semibold text-ink">{src.sourceIp}</div>
                            <div className="text-[10px] text-ink-muted">
                              From: {src.headerFroms.join(", ")}
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-right font-mono font-semibold text-ink">
                            {src.totalCount.toLocaleString()}
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex items-center gap-2 font-mono text-[11px]">
                              <span className="text-emerald-600 dark:text-emerald-400">
                                {src.passCount} pass
                              </span>
                              {src.failCount > 0 && (
                                <span className="text-rose-600 dark:text-rose-400">
                                  {src.failCount} fail
                                </span>
                              )}
                            </div>
                            <div className="mt-1 h-1.5 w-28 overflow-hidden rounded-full bg-rose-500/25">
                              <div
                                className="h-full bg-emerald-500"
                                style={{ width: `${passPct}%` }}
                              />
                            </div>
                          </td>
                          <td className="px-4 py-2.5 font-mono text-[11px] text-ink-secondary">
                            SPF: {src.spfAlignedCount} · DKIM: {src.dkimAlignedCount}
                          </td>
                          <td className="px-4 py-2.5">
                            <div className="flex flex-wrap gap-1">
                              {Object.entries(src.dispositions).map(([disp, cnt]) => (
                                <span
                                  key={disp}
                                  className={`rounded-full border px-2 py-0.5 font-mono text-[10px] font-semibold ${
                                    disp === "reject"
                                      ? "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                                      : disp === "quarantine"
                                        ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                                        : "border-line bg-surface-alt text-ink-secondary"
                                  }`}
                                >
                                  {disp}: {cnt}
                                </span>
                              ))}
                            </div>
                          </td>
                          <td className="px-4 py-2.5 text-right">
                            <button
                              type="button"
                              onClick={() => onCheckDnsbl(src.sourceIp)}
                              className="inline-flex items-center gap-1 rounded-md border border-line bg-surface-alt px-2 py-1 text-[11px] font-medium text-sky-700 hover:border-sky-500/40 dark:text-sky-300"
                            >
                              <ShieldAlert className="h-3 w-3" />
                              DNSBL
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2">Source IP</th>
                      <th className="px-4 py-2 text-right">Count</th>
                      <th className="px-4 py-2">Status</th>
                      <th className="px-4 py-2">Disposition</th>
                      <th className="px-4 py-2">DKIM / SPF</th>
                      <th className="px-4 py-2">Domains</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line font-mono text-[11px]">
                    {parsed.records.map((rec, idx) => (
                      <tr key={idx} className="hover:bg-surface-alt/60">
                        <td className="px-4 py-2 text-ink">{rec.sourceIp}</td>
                        <td className="px-4 py-2 text-right text-ink">{rec.count}</td>
                        <td className="px-4 py-2">
                          {rec.dmarcPass ? (
                            <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                              <CheckCircle2 className="h-3 w-3" /> Pass
                            </span>
                          ) : (
                            <span className="inline-flex items-center gap-1 text-rose-600 dark:text-rose-400">
                              <AlertTriangle className="h-3 w-3" /> Fail
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-2 text-ink-secondary">{rec.disposition}</td>
                        <td className="px-4 py-2 text-ink-secondary">
                          dkim={rec.dkimResult} · spf={rec.spfResult}
                        </td>
                        <td className="px-4 py-2 text-ink-muted">
                          from={rec.headerFrom}
                          {rec.envelopeFrom ? ` · env=${rec.envelopeFrom}` : ""}
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

      {/* TLS-RPT View */}
      {parsed && parsed.kind === "tls-rpt" && (
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Domain &amp; Reporter</div>
              <div className="mt-1 flex items-center justify-between gap-2">
                <span className="truncate font-mono text-sm font-semibold text-ink">
                  {parsed.domain}
                </span>
                <button
                  type="button"
                  onClick={() => onInspectDomain(parsed.domain)}
                  className="shrink-0 text-sky-600 hover:text-sky-500 dark:text-sky-400"
                >
                  <Globe2 className="h-3.5 w-3.5" />
                </button>
              </div>
              <div className="mt-0.5 truncate text-[11px] text-ink-secondary">
                {parsed.orgName}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">TLS Success Rate</div>
              <div
                className={`mt-1 font-mono text-lg font-bold ${
                  parsed.successRate >= 99
                    ? "text-emerald-600 dark:text-emerald-400"
                    : parsed.successRate >= 90
                      ? "text-amber-600 dark:text-amber-400"
                      : "text-rose-600 dark:text-rose-400"
                }`}
              >
                {parsed.successRate}%
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Successful Sessions</div>
              <div className="mt-1 font-mono text-lg font-semibold text-emerald-600 dark:text-emerald-400">
                {parsed.totalSuccessful.toLocaleString()}
              </div>
            </div>

            <div className="rounded-xl border border-line bg-surface p-3.5">
              <div className="text-[11px] text-ink-muted">Failed Sessions</div>
              <div
                className={`mt-1 font-mono text-lg font-semibold ${
                  parsed.totalFailed > 0
                    ? "text-rose-600 dark:text-rose-400"
                    : "text-ink-secondary"
                }`}
              >
                {parsed.totalFailed.toLocaleString()}
              </div>
            </div>
          </div>

          {parsed.policies.map((pol, idx) => (
            <div key={idx} className="rounded-xl border border-line bg-surface p-4 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                <div className="flex items-center gap-2">
                  <span className="rounded bg-sky-500/15 px-2 py-0.5 font-mono text-[11px] font-semibold uppercase text-sky-700 dark:text-sky-300">
                    {pol.policyType}
                  </span>
                  <span className="font-mono text-sm font-semibold text-ink">
                    {pol.policyDomain}
                  </span>
                </div>
                <div className="flex items-center gap-3 font-mono text-xs">
                  <span className="inline-flex items-center gap-1 text-emerald-600 dark:text-emerald-400">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    {pol.totalSuccessfulSessions} ok
                  </span>
                  <span
                    className={
                      pol.totalFailedSessions > 0
                        ? "text-rose-600 dark:text-rose-400"
                        : "text-ink-muted"
                    }
                  >
                    {pol.totalFailedSessions} failed
                  </span>
                </div>
              </div>

              {pol.policyStrings.length > 0 && (
                <pre className="overflow-x-auto rounded-lg border border-line bg-canvas p-2.5 font-mono text-[11px] text-ink-secondary">
                  {pol.policyStrings.join("\n")}
                </pre>
              )}

              {pol.failureDetails.length > 0 ? (
                <div className="overflow-x-auto rounded-lg border border-line">
                  <table className="w-full border-collapse text-left text-xs">
                    <thead>
                      <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                        <th className="px-3 py-2">Failure Reason</th>
                        <th className="px-3 py-2">Sending MTA IP</th>
                        <th className="px-3 py-2">Receiving MX / IP</th>
                        <th className="px-3 py-2 text-right">Failed Count</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-line font-mono text-[11px]">
                      {pol.failureDetails.map((f, fIdx) => (
                        <tr key={fIdx} className="hover:bg-surface-alt/60">
                          <td className="px-3 py-2 font-semibold text-rose-700 dark:text-rose-300">
                            {f.resultType}
                          </td>
                          <td className="px-3 py-2 text-ink">
                            {f.sendingMtaIp ? (
                              <span className="inline-flex items-center gap-1.5">
                                {f.sendingMtaIp}
                                <button
                                  type="button"
                                  onClick={() => onCheckDnsbl(f.sendingMtaIp!)}
                                  className="rounded border border-line bg-surface-alt px-1.5 py-0.5 text-[10px] text-sky-700 dark:text-sky-300"
                                >
                                  DNSBL
                                </button>
                              </span>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td className="px-3 py-2 text-ink-secondary">
                            {f.receivingMxHostname ?? "—"}
                            {f.receivingIp ? ` (${f.receivingIp})` : ""}
                          </td>
                          <td className="px-3 py-2 text-right font-semibold text-rose-600 dark:text-rose-400">
                            {f.failedSessionCount}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p className="text-xs text-emerald-700 dark:text-emerald-300">
                  No TLS negotiation failures reported for this policy.
                </p>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
