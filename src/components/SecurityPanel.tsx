import {
  AlertTriangle,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Copy,
  Mail,
  Play,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  ShieldX,
  XCircle,
} from "lucide-react";
import { useState } from "react";
import { copyToClipboard, probeSmtpDeliverability } from "../lib/api";
import type {
  SecurityReport,
  SmtpDeliverabilityReport,
  SpfLookupNode,
} from "../types/dns";

function SecurityBadge({ status }: { status: string }) {
  switch (status) {
    case "pass":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-xs font-semibold text-emerald-700 dark:text-emerald-300">
          <ShieldCheck className="h-3.5 w-3.5" />
          Pass
        </span>
      );
    case "warn":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-xs font-semibold text-amber-700 dark:text-amber-300">
          <ShieldAlert className="h-3.5 w-3.5" />
          Warning
        </span>
      );
    case "fail":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-xs font-semibold text-rose-700 dark:text-rose-300">
          <ShieldX className="h-3.5 w-3.5" />
          Fail
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-line-strong bg-surface-alt px-2.5 py-0.5 text-xs font-semibold text-ink-secondary">
          <ShieldQuestion className="h-3.5 w-3.5" />
          {status === "unsigned" ? "Unsigned" : "Missing"}
        </span>
      );
  }
}

function SpfTreeNodeView({ node }: { node: SpfLookupNode }) {
  return (
    <div className="space-y-1.5 border-l border-line pl-3">
      <div className="flex flex-wrap items-center justify-between gap-2 text-[11px]">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="rounded border border-line-strong bg-canvas px-1.5 py-0.5 font-mono text-sky-700 dark:text-sky-300">
            {node.mechanism}
          </span>
          <span className="font-mono text-ink-secondary">{node.target}</span>
        </div>
        <span className="rounded bg-surface-alt px-1.5 py-0.5 font-mono text-[10px] text-ink-muted">
          +{node.lookups_added} lookup{node.lookups_added === 1 ? "" : "s"}
        </span>
      </div>
      {node.raw_record && (
        <div className="break-all rounded bg-canvas px-2 py-1 font-mono text-[10px] text-ink-muted">
          {node.raw_record}
        </div>
      )}
      {node.error && (
        <div className="text-[11px] text-amber-700 dark:text-amber-300">
          {node.error}
        </div>
      )}
      {node.children.length > 0 && (
        <div className="space-y-1.5 pt-0.5">
          {node.children.map((child, idx) => (
            <SpfTreeNodeView key={`${child.target}-${idx}`} node={child} />
          ))}
        </div>
      )}
    </div>
  );
}

interface SecurityPanelProps {
  domain: string;
  security: SecurityReport;
  dkimSelectorsInput: string;
  onDkimSelectorsInputChange: (v: string) => void;
  onRecheckDkim: () => void;
  loading: boolean;
  onNotify: (msg: string) => void;
}

export function SecurityPanel({
  domain,
  security,
  dkimSelectorsInput,
  onDkimSelectorsInputChange,
  onRecheckDkim,
  loading,
  onNotify,
}: SecurityPanelProps) {
  const [localCopied, setLocalCopied] = useState<string | null>(null);
  const [showSpfTree, setShowSpfTree] = useState(false);
  const [smtpLoading, setSmtpLoading] = useState(false);
  const [smtpReport, setSmtpReport] = useState<SmtpDeliverabilityReport | null>(null);
  const [smtpError, setSmtpError] = useState<string | null>(null);

  const copyRaw = async (id: string, text: string) => {
    await copyToClipboard(text);
    setLocalCopied(id);
    onNotify(`Copied ${id.toUpperCase()} record`);
    setTimeout(() => setLocalCopied(null), 1500);
  };

  const handleRunSmtpProbe = async () => {
    setSmtpLoading(true);
    setSmtpError(null);
    try {
      const res = await probeSmtpDeliverability(domain);
      setSmtpReport(res);
    } catch (err) {
      setSmtpError(String(err));
    } finally {
      setSmtpLoading(false);
    }
  };

  const { spf, dmarc, dkim, dnssec, mta_sts, tls_rpt, bimi } = security;
  const foundDkim = dkim.results.filter((r) => r.found);
  const effectiveLookups = spf.recursive_lookup_count ?? spf.dns_lookup_count;

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        {/* SPF Card */}
        <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-ink">
                SPF (Sender Policy Framework)
              </h3>
              <p className="mt-1 text-xs text-ink-muted">{spf.summary}</p>
            </div>
            <SecurityBadge status={spf.status} />
          </div>

          {spf.raw_record && (
            <div className="mt-3 rounded-lg border border-line bg-canvas p-3">
              <div className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wider text-ink-muted">
                <span>Raw Record</span>
                <button
                  type="button"
                  onClick={() => copyRaw("spf", spf.raw_record!)}
                  className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                >
                  <Copy className="h-3 w-3" />
                  {localCopied === "spf" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="break-all font-mono text-xs text-ink">
                {spf.raw_record}
              </div>
            </div>
          )}

          <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Direct Lookups</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {spf.dns_lookup_count}
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Recursive Budget</div>
              <div
                className={`mt-0.5 font-mono font-semibold ${
                  effectiveLookups > 10
                    ? "text-amber-700 dark:text-amber-300"
                    : "text-ink"
                }`}
              >
                {effectiveLookups} / 10 max
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Qualifier</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {spf.all_qualifier ?? "None"}
              </div>
            </div>
          </div>

          {spf.mechanisms.length > 0 && (
            <div className="mt-3 flex flex-wrap gap-1.5">
              {spf.mechanisms.map((m, i) => (
                <span
                  key={i}
                  className="rounded border border-line-strong bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                >
                  {m}
                </span>
              ))}
            </div>
          )}

          {spf.lookup_tree && spf.lookup_tree.length > 0 && (
            <div className="mt-3 rounded-lg border border-line bg-surface-alt p-2.5">
              <button
                type="button"
                onClick={() => setShowSpfTree((v) => !v)}
                className="flex w-full items-center justify-between text-xs font-semibold text-ink-secondary hover:text-ink"
              >
                <span>
                  Recursive SPF Lookup Tree ({effectiveLookups}/10 lookups)
                </span>
                {showSpfTree ? (
                  <ChevronDown className="h-3.5 w-3.5" />
                ) : (
                  <ChevronRight className="h-3.5 w-3.5" />
                )}
              </button>
              {showSpfTree && (
                <div className="mt-2.5 space-y-2">
                  {spf.lookup_tree.map((node, idx) => (
                    <SpfTreeNodeView key={`${node.target}-${idx}`} node={node} />
                  ))}
                </div>
              )}
            </div>
          )}

          {spf.issues.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-amber-700 dark:text-amber-300">
              {spf.issues.map((issue, idx) => (
                <li key={idx}>• {issue}</li>
              ))}
            </ul>
          )}
        </div>

        {/* DMARC Card */}
        <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-ink">
                DMARC (_dmarc policy)
              </h3>
              <p className="mt-1 text-xs text-ink-muted">{dmarc.summary}</p>
            </div>
            <SecurityBadge status={dmarc.status} />
          </div>

          {dmarc.raw_record && (
            <div className="mt-3 rounded-lg border border-line bg-canvas p-3">
              <div className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wider text-ink-muted">
                <span>Raw Record</span>
                <button
                  type="button"
                  onClick={() => copyRaw("dmarc", dmarc.raw_record!)}
                  className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                >
                  <Copy className="h-3 w-3" />
                  {localCopied === "dmarc" ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="break-all font-mono text-xs text-ink">
                {dmarc.raw_record}
              </div>
            </div>
          )}

          <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Policy (p)</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {dmarc.policy ?? "—"}
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Subdomain (sp)</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {dmarc.subdomain_policy ?? "inherit"}
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Applied (pct)</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {dmarc.pct !== null ? `${dmarc.pct}%` : "100%"}
              </div>
            </div>
          </div>

          {(dmarc.rua.length > 0 || dmarc.ruf.length > 0) && (
            <div className="mt-3 space-y-1 rounded-lg border border-line bg-surface-alt p-2.5 text-xs">
              {dmarc.rua.length > 0 && (
                <div className="break-all">
                  <span className="text-ink-muted">RUA: </span>
                  <span className="font-mono text-ink-secondary">
                    {dmarc.rua.join(", ")}
                  </span>
                </div>
              )}
              {dmarc.ruf.length > 0 && (
                <div className="break-all">
                  <span className="text-ink-muted">RUF: </span>
                  <span className="font-mono text-ink-secondary">
                    {dmarc.ruf.join(", ")}
                  </span>
                </div>
              )}
            </div>
          )}

          {dmarc.issues.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-amber-700 dark:text-amber-300">
              {dmarc.issues.map((issue, idx) => (
                <li key={idx}>• {issue}</li>
              ))}
            </ul>
          )}
        </div>

        {/* DKIM Card */}
        <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-ink">
                DKIM (DomainKeys Identified Mail)
              </h3>
              <p className="mt-1 text-xs text-ink-muted">{dkim.summary}</p>
            </div>
            <SecurityBadge status={dkim.status} />
          </div>

          <div className="mt-3 flex gap-2">
            <input
              type="text"
              value={dkimSelectorsInput}
              onChange={(e) => onDkimSelectorsInputChange(e.target.value)}
              placeholder="Custom selectors (e.g. s1, google, mandrill)"
              className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
            <button
              type="button"
              disabled={loading}
              onClick={onRecheckDkim}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-1.5 text-xs font-medium text-ink-secondary transition hover:border-sky-500/50 hover:text-sky-600 dark:hover:text-sky-300 disabled:opacity-50"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              Check
            </button>
          </div>

          <div className="mt-3 text-[11px] text-ink-muted">
            Checked selectors:{" "}
            <span className="font-mono text-ink-secondary">
              {dkim.checked_selectors.join(", ")}
            </span>
          </div>

          {foundDkim.length > 0 && (
            <div className="mt-3 space-y-2">
              {foundDkim.map((sel) => (
                <div
                  key={sel.selector}
                  className="rounded-lg border border-line bg-canvas p-3 text-xs"
                >
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-semibold text-sky-700 dark:text-sky-300">
                      {sel.selector}._domainkey
                    </span>
                    <SecurityBadge status={sel.status} />
                  </div>
                  {sel.cname_target && (
                    <div className="mt-1 font-mono text-[11px] text-ink-muted">
                      CNAME → {sel.cname_target}
                    </div>
                  )}
                  {sel.raw_record && (
                    <div className="mt-1.5 break-all font-mono text-[11px] text-ink-secondary">
                      {sel.raw_record}
                    </div>
                  )}
                  {sel.notes.length > 0 && (
                    <div className="mt-1 text-[11px] text-amber-700 dark:text-amber-300">
                      {sel.notes.join(" ")}
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}

          {dkim.issues.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-amber-700 dark:text-amber-300">
              {dkim.issues.map((issue, idx) => (
                <li key={idx}>• {issue}</li>
              ))}
            </ul>
          )}
        </div>

        {/* DNSSEC Card */}
        <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
          <div className="flex items-start justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-ink">
                DNSSEC (Chain of Trust)
              </h3>
              <p className="mt-1 text-xs text-ink-muted">{dnssec.summary}</p>
            </div>
            <SecurityBadge status={dnssec.status} />
          </div>

          <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">DS Records</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {dnssec.ds_records.length}
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">DNSKEY Records</div>
              <div className="mt-0.5 font-mono font-semibold text-ink">
                {dnssec.dnskey_records.length}
              </div>
            </div>
            <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
              <div className="text-[11px] text-ink-muted">Validation</div>
              <div
                className={`mt-0.5 font-mono font-semibold ${
                  dnssec.validated
                    ? "text-emerald-700 dark:text-emerald-300"
                    : "text-ink-secondary"
                }`}
              >
                {dnssec.validated ? "Verified" : "Not Verified"}
              </div>
            </div>
          </div>

          {dnssec.ds_records.length > 0 && (
            <div className="mt-3 rounded-lg border border-line bg-canvas p-3">
              <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-muted">
                Delegation Signer (DS)
              </div>
              <div className="space-y-1 font-mono text-[11px] text-ink">
                {dnssec.ds_records.map((ds, i) => (
                  <div key={i} className="break-all">
                    {ds}
                  </div>
                ))}
              </div>
            </div>
          )}

          {dnssec.dnskey_records.length > 0 && (
            <div className="mt-2 rounded-lg border border-line bg-canvas p-3">
              <div className="mb-1 text-[11px] uppercase tracking-wider text-ink-muted">
                Zone Keys (DNSKEY)
              </div>
              <div className="space-y-1 font-mono text-[11px] text-ink">
                {dnssec.dnskey_records.map((k, i) => (
                  <div key={i} className="break-all">
                    {k}
                  </div>
                ))}
              </div>
            </div>
          )}

          {dnssec.validation_error && (
            <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 font-mono text-[11px] text-rose-900 dark:text-rose-200">
              {dnssec.validation_error}
            </div>
          )}

          {dnssec.issues.length > 0 && (
            <ul className="mt-3 space-y-1 text-xs text-ink-secondary">
              {dnssec.issues.map((issue, idx) => (
                <li key={idx}>• {issue}</li>
              ))}
            </ul>
          )}
        </div>

        {/* MTA-STS Card */}
        {mta_sts && (
          <div className="flex flex-col rounded-xl border border-line bg-surface p-4">
            <div className="flex items-start justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold text-ink">
                  MTA-STS (Strict Mail Transport Security)
                </h3>
                <p className="mt-1 text-xs text-ink-muted">{mta_sts.summary}</p>
              </div>
              <SecurityBadge status={mta_sts.status} />
            </div>

            {mta_sts.dns_record && (
              <div className="mt-3 rounded-lg border border-line bg-canvas p-2.5 font-mono text-[11px] text-ink">
                _mta-sts: {mta_sts.dns_record}
              </div>
            )}

            {mta_sts.policy_fetched && (
              <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
                <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
                  <div className="text-[11px] text-ink-muted">Mode</div>
                  <div className="mt-0.5 font-mono font-semibold text-ink">
                    {mta_sts.mode ?? "—"}
                  </div>
                </div>
                <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
                  <div className="text-[11px] text-ink-muted">Max Age</div>
                  <div className="mt-0.5 font-mono font-semibold text-ink">
                    {mta_sts.max_age !== null ? `${mta_sts.max_age}s` : "—"}
                  </div>
                </div>
                <div className="rounded-lg border border-line bg-surface-alt px-3 py-2">
                  <div className="text-[11px] text-ink-muted">MX Patterns</div>
                  <div className="mt-0.5 font-mono font-semibold text-ink">
                    {mta_sts.mx_patterns.length}
                  </div>
                </div>
              </div>
            )}

            {mta_sts.mx_patterns.length > 0 && (
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {mta_sts.mx_patterns.map((mx, i) => (
                  <span
                    key={i}
                    className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                  >
                    {mx}
                  </span>
                ))}
              </div>
            )}

            {mta_sts.issues.length > 0 && (
              <ul className="mt-3 space-y-1 text-xs text-amber-700 dark:text-amber-300">
                {mta_sts.issues.map((issue, idx) => (
                  <li key={idx}>• {issue}</li>
                ))}
              </ul>
            )}
          </div>
        )}

        {/* TLS-RPT & BIMI Card */}
        {(tls_rpt || bimi) && (
          <div className="flex flex-col gap-4 rounded-xl border border-line bg-surface p-4">
            {tls_rpt && (
              <div>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-ink">
                      SMTP TLS-RPT (_smtp._tls)
                    </h3>
                    <p className="mt-1 text-xs text-ink-muted">{tls_rpt.summary}</p>
                  </div>
                  <SecurityBadge status={tls_rpt.status} />
                </div>
                {tls_rpt.raw_record && (
                  <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-2.5 font-mono text-[11px] text-ink">
                    {tls_rpt.raw_record}
                  </div>
                )}
                {tls_rpt.issues.length > 0 && (
                  <ul className="mt-2 space-y-1 text-xs text-amber-700 dark:text-amber-300">
                    {tls_rpt.issues.map((issue, idx) => (
                      <li key={idx}>• {issue}</li>
                    ))}
                  </ul>
                )}
              </div>
            )}

            {bimi && (
              <div className="border-t border-line pt-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <h3 className="text-sm font-semibold text-ink">
                      BIMI (Brand Indicators for Message Identification)
                    </h3>
                    <p className="mt-1 text-xs text-ink-muted">{bimi.summary}</p>
                  </div>
                  <SecurityBadge status={bimi.status} />
                </div>
                {bimi.raw_record && (
                  <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-2.5 font-mono text-[11px] text-ink">
                    {bimi.raw_record}
                  </div>
                )}
                {(bimi.logo_url || bimi.authority_url) && (
                  <div className="mt-2 space-y-1 text-[11px] text-ink-muted">
                    {bimi.logo_url && (
                      <div className="break-all">
                        Logo SVG: <span className="font-mono text-ink-secondary">{bimi.logo_url}</span>
                      </div>
                    )}
                    {bimi.authority_url && (
                      <div className="break-all">
                        VMC Cert: <span className="font-mono text-ink-secondary">{bimi.authority_url}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Deep SMTP & Mail Server Deliverability Tester */}
      <div className="overflow-hidden rounded-xl border border-line bg-surface">
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line bg-surface-alt px-4 py-3">
          <div className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-xs font-semibold text-ink">
                Live SMTP / MX Deliverability Probe (TCP Port 25)
              </h3>
              <p className="text-[11px] text-ink-muted">
                Tests MX greeting banner, FCrDNS (forward-confirmed PTR), EHLO capabilities, and STARTTLS certificate
              </p>
            </div>
          </div>
          <button
            type="button"
            disabled={smtpLoading}
            onClick={() => void handleRunSmtpProbe()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {smtpLoading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Play className="h-3.5 w-3.5" />
            )}
            {smtpLoading ? "Probing MX..." : "Test MX Servers (Port 25)"}
          </button>
        </div>

        <div className="p-4">
          {smtpError && (
            <div className="rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-xs text-rose-800 dark:text-rose-200">
              {smtpError}
            </div>
          )}

          {!smtpReport && !smtpLoading && !smtpError && (
            <div className="text-center text-xs text-ink-muted py-4">
              Click &quot;Test MX Servers (Port 25)&quot; to run a live non-intrusive SMTP/STARTTLS &amp; FCrDNS check against {domain}&apos;s mail exchangers.
            </div>
          )}

          {smtpReport && (
            <div className="space-y-3">
              {smtpReport.port25_blocked_suspected && (
                <div className="flex items-start gap-2.5 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
                  <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-600 dark:text-amber-400" />
                  <div>
                    All MX hosts timed out on TCP/25. Many residential ISPs and cloud VMs block outbound port 25 by default.
                  </div>
                </div>
              )}

              {smtpReport.issues.length > 0 && !smtpReport.port25_blocked_suspected && (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-900 dark:text-amber-200">
                  {smtpReport.issues.join(" ")}
                </div>
              )}

              <div className="space-y-3">
                {smtpReport.servers.map((srv) => (
                  <div
                    key={`${srv.mx_host}-${srv.priority}`}
                    className="rounded-xl border border-line bg-canvas p-3.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2">
                      <div className="flex flex-wrap items-center gap-2">
                        <span className="rounded bg-surface-alt px-1.5 py-0.5 font-mono text-[11px] font-semibold text-ink-secondary">
                          MX {srv.priority}
                        </span>
                        <span className="font-mono text-xs font-semibold text-ink">
                          {srv.mx_host}
                        </span>
                        {srv.ip && (
                          <span className="font-mono text-[11px] text-ink-muted">
                            ({srv.ip})
                          </span>
                        )}
                      </div>
                      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
                        {srv.reachable ? (
                          <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 font-medium text-emerald-700 dark:text-emerald-300">
                            <CheckCircle2 className="h-3 w-3" />
                            Reachable ({srv.latency_ms}ms)
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-medium text-rose-700 dark:text-rose-300">
                            <XCircle className="h-3 w-3" />
                            Unreachable
                          </span>
                        )}
                        <span
                          className={`rounded-full border px-2 py-0.5 font-medium ${
                            srv.fcrdns_valid
                              ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                              : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                          }`}
                        >
                          FCrDNS: {srv.fcrdns_valid ? "Valid" : "Mismatch"}
                        </span>
                        {srv.reachable && (
                          <span
                            className={`rounded-full border px-2 py-0.5 font-medium ${
                              srv.starttls_negotiated
                                ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                                : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                            }`}
                          >
                            STARTTLS:{" "}
                            {srv.starttls_negotiated
                              ? srv.tls_version ?? "Active"
                              : "Not Supported"}
                          </span>
                        )}
                      </div>
                    </div>

                    <div className="mt-2.5 grid grid-cols-1 gap-2 text-[11px] sm:grid-cols-2">
                      <div>
                        <span className="text-ink-muted">PTR Records: </span>
                        <span className="font-mono text-ink-secondary">
                          {srv.ptr_records.length > 0 ? srv.ptr_records.join(", ") : "None"}
                        </span>
                      </div>
                      {srv.tls_cert_valid !== null && (
                        <div>
                          <span className="text-ink-muted">STARTTLS Cert: </span>
                          <span
                            className={`font-mono font-medium ${
                              srv.tls_cert_valid
                                ? "text-emerald-700 dark:text-emerald-300"
                                : "text-rose-700 dark:text-rose-300"
                            }`}
                          >
                            {srv.tls_cert_valid ? "Valid" : "Invalid"}
                            {srv.tls_cert_cn ? ` (CN=${srv.tls_cert_cn})` : ""}
                            {srv.tls_days_remaining !== null ? ` · ${srv.tls_days_remaining}d left` : ""}
                          </span>
                        </div>
                      )}
                    </div>

                    {srv.banner && (
                      <div className="mt-2 break-all rounded border border-line bg-surface px-2.5 py-1.5 font-mono text-[11px] text-ink-secondary">
                        Banner: {srv.banner}
                      </div>
                    )}

                    {srv.ehlo_extensions.length > 0 && (
                      <div className="mt-2 flex flex-wrap gap-1">
                        {srv.ehlo_extensions.map((ext, i) => (
                          <span
                            key={i}
                            className="rounded border border-line bg-surface px-1.5 py-0.5 font-mono text-[10px] text-ink-muted"
                          >
                            {ext}
                          </span>
                        ))}
                      </div>
                    )}

                    {srv.error && (
                      <div className="mt-2 text-[11px] text-rose-700 dark:text-rose-300">
                        {srv.error}
                      </div>
                    )}
                    {srv.issues.length > 0 && (
                      <ul className="mt-2 space-y-0.5 text-[11px] text-amber-700 dark:text-amber-300">
                        {srv.issues.map((iss, idx) => (
                          <li key={idx}>• {iss}</li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
