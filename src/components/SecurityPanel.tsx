import {
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldQuestion,
  Copy,
  RefreshCw,
} from "lucide-react";
import { useState } from "react";
import type { SecurityReport } from "../types/dns";
import { copyToClipboard } from "../lib/api";

function SecurityBadge({ status }: { status: string }) {
  switch (status) {
    case "pass":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 text-xs font-semibold text-emerald-300">
          <ShieldCheck className="h-3.5 w-3.5" />
          Pass
        </span>
      );
    case "warn":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2.5 py-0.5 text-xs font-semibold text-amber-300">
          <ShieldAlert className="h-3.5 w-3.5" />
          Warning
        </span>
      );
    case "fail":
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 text-xs font-semibold text-rose-300">
          <ShieldX className="h-3.5 w-3.5" />
          Fail
        </span>
      );
    default:
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-slate-700 bg-slate-800 px-2.5 py-0.5 text-xs font-semibold text-slate-300">
          <ShieldQuestion className="h-3.5 w-3.5" />
          {status === "unsigned" ? "Unsigned" : "Missing"}
        </span>
      );
  }
}

interface SecurityPanelProps {
  security: SecurityReport;
  dkimSelectorsInput: string;
  onDkimSelectorsInputChange: (v: string) => void;
  onRecheckDkim: () => void;
  loading: boolean;
  onNotify: (msg: string) => void;
}

export function SecurityPanel({
  security,
  dkimSelectorsInput,
  onDkimSelectorsInputChange,
  onRecheckDkim,
  loading,
  onNotify,
}: SecurityPanelProps) {
  const [localCopied, setLocalCopied] = useState<string | null>(null);

  const copyRaw = async (id: string, text: string) => {
    await copyToClipboard(text);
    setLocalCopied(id);
    onNotify(`Copied ${id.toUpperCase()} record`);
    setTimeout(() => setLocalCopied(null), 1500);
  };

  const { spf, dmarc, dkim, dnssec } = security;
  const foundDkim = dkim.results.filter((r) => r.found);

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
      {/* SPF Card */}
      <div className="flex flex-col rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              SPF (Sender Policy Framework)
            </h3>
            <p className="mt-1 text-xs text-slate-400">{spf.summary}</p>
          </div>
          <SecurityBadge status={spf.status} />
        </div>

        {spf.raw_record && (
          <div className="mt-3 rounded-lg border border-slate-800 bg-[#0b0f17] p-3">
            <div className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wider text-slate-500">
              <span>Raw Record</span>
              <button
                type="button"
                onClick={() => copyRaw("spf", spf.raw_record!)}
                className="inline-flex items-center gap-1 text-slate-400 hover:text-sky-300"
              >
                <Copy className="h-3 w-3" />
                {localCopied === "spf" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="break-all font-mono text-xs text-slate-200">
              {spf.raw_record}
            </div>
          </div>
        )}

        <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">DNS Lookups</div>
            <div
              className={`mt-0.5 font-mono font-semibold ${
                spf.dns_lookup_count > 10 ? "text-amber-300" : "text-slate-100"
              }`}
            >
              {spf.dns_lookup_count} / 10 max
            </div>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">Qualifier</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {spf.all_qualifier ?? "None"}
            </div>
          </div>
        </div>

        {spf.mechanisms.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-1.5">
            {spf.mechanisms.map((m, i) => (
              <span
                key={i}
                className="rounded border border-slate-700/80 bg-[#0b0f17] px-2 py-0.5 font-mono text-[11px] text-slate-300"
              >
                {m}
              </span>
            ))}
          </div>
        )}

        {spf.issues.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-amber-300">
            {spf.issues.map((issue, idx) => (
              <li key={idx}>• {issue}</li>
            ))}
          </ul>
        )}
      </div>

      {/* DMARC Card */}
      <div className="flex flex-col rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              DMARC (_dmarc policy)
            </h3>
            <p className="mt-1 text-xs text-slate-400">{dmarc.summary}</p>
          </div>
          <SecurityBadge status={dmarc.status} />
        </div>

        {dmarc.raw_record && (
          <div className="mt-3 rounded-lg border border-slate-800 bg-[#0b0f17] p-3">
            <div className="mb-1 flex items-center justify-between text-[11px] uppercase tracking-wider text-slate-500">
              <span>Raw Record</span>
              <button
                type="button"
                onClick={() => copyRaw("dmarc", dmarc.raw_record!)}
                className="inline-flex items-center gap-1 text-slate-400 hover:text-sky-300"
              >
                <Copy className="h-3 w-3" />
                {localCopied === "dmarc" ? "Copied" : "Copy"}
              </button>
            </div>
            <div className="break-all font-mono text-xs text-slate-200">
              {dmarc.raw_record}
            </div>
          </div>
        )}

        <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">Policy (p)</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {dmarc.policy ?? "—"}
            </div>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">Subdomain (sp)</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {dmarc.subdomain_policy ?? "inherit"}
            </div>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">Applied (pct)</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {dmarc.pct !== null ? `${dmarc.pct}%` : "100%"}
            </div>
          </div>
        </div>

        {(dmarc.rua.length > 0 || dmarc.ruf.length > 0) && (
          <div className="mt-3 space-y-1 rounded-lg border border-slate-800/80 bg-[#0d131f] p-2.5 text-xs">
            {dmarc.rua.length > 0 && (
              <div className="break-all">
                <span className="text-slate-400">RUA: </span>
                <span className="font-mono text-slate-200">
                  {dmarc.rua.join(", ")}
                </span>
              </div>
            )}
            {dmarc.ruf.length > 0 && (
              <div className="break-all">
                <span className="text-slate-400">RUF: </span>
                <span className="font-mono text-slate-200">
                  {dmarc.ruf.join(", ")}
                </span>
              </div>
            )}
          </div>
        )}

        {dmarc.issues.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-amber-300">
            {dmarc.issues.map((issue, idx) => (
              <li key={idx}>• {issue}</li>
            ))}
          </ul>
        )}
      </div>

      {/* DKIM Card */}
      <div className="flex flex-col rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              DKIM (DomainKeys Identified Mail)
            </h3>
            <p className="mt-1 text-xs text-slate-400">{dkim.summary}</p>
          </div>
          <SecurityBadge status={dkim.status} />
        </div>

        <div className="mt-3 flex gap-2">
          <input
            type="text"
            value={dkimSelectorsInput}
            onChange={(e) => onDkimSelectorsInputChange(e.target.value)}
            placeholder="Custom selectors (e.g. s1, google, mandrill)"
            className="flex-1 rounded-lg border border-slate-700 bg-[#0b0f17] px-3 py-1.5 font-mono text-xs text-slate-100 placeholder:text-slate-500 focus:border-sky-500 focus:outline-none"
          />
          <button
            type="button"
            disabled={loading}
            onClick={onRecheckDkim}
            className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-sky-500/50 hover:text-sky-300 disabled:opacity-50"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Check
          </button>
        </div>

        <div className="mt-3 text-[11px] text-slate-500">
          Checked selectors:{" "}
          <span className="font-mono text-slate-400">
            {dkim.checked_selectors.join(", ")}
          </span>
        </div>

        {foundDkim.length > 0 && (
          <div className="mt-3 space-y-2">
            {foundDkim.map((sel) => (
              <div
                key={sel.selector}
                className="rounded-lg border border-slate-800 bg-[#0b0f17] p-3 text-xs"
              >
                <div className="flex items-center justify-between">
                  <span className="font-mono font-semibold text-sky-300">
                    {sel.selector}._domainkey
                  </span>
                  <SecurityBadge status={sel.status} />
                </div>
                {sel.cname_target && (
                  <div className="mt-1 font-mono text-[11px] text-slate-400">
                    CNAME → {sel.cname_target}
                  </div>
                )}
                {sel.raw_record && (
                  <div className="mt-1.5 break-all font-mono text-[11px] text-slate-300">
                    {sel.raw_record}
                  </div>
                )}
                {sel.notes.length > 0 && (
                  <div className="mt-1 text-[11px] text-amber-300">
                    {sel.notes.join(" ")}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {dkim.issues.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-amber-300">
            {dkim.issues.map((issue, idx) => (
              <li key={idx}>• {issue}</li>
            ))}
          </ul>
        )}
      </div>

      {/* DNSSEC Card */}
      <div className="flex flex-col rounded-xl border border-slate-800 bg-[#111827] p-4">
        <div className="flex items-start justify-between gap-3">
          <div>
            <h3 className="text-sm font-semibold text-slate-100">
              DNSSEC (Chain of Trust)
            </h3>
            <p className="mt-1 text-xs text-slate-400">{dnssec.summary}</p>
          </div>
          <SecurityBadge status={dnssec.status} />
        </div>

        <div className="mt-3 grid grid-cols-3 gap-2 text-xs">
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">DS Records</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {dnssec.ds_records.length}
            </div>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">DNSKEY Records</div>
            <div className="mt-0.5 font-mono font-semibold text-slate-100">
              {dnssec.dnskey_records.length}
            </div>
          </div>
          <div className="rounded-lg border border-slate-800/80 bg-[#0d131f] px-3 py-2">
            <div className="text-[11px] text-slate-500">Validation</div>
            <div
              className={`mt-0.5 font-mono font-semibold ${
                dnssec.validated ? "text-emerald-300" : "text-slate-300"
              }`}
            >
              {dnssec.validated ? "Verified" : "Not Verified"}
            </div>
          </div>
        </div>

        {dnssec.ds_records.length > 0 && (
          <div className="mt-3 rounded-lg border border-slate-800 bg-[#0b0f17] p-3">
            <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">
              Delegation Signer (DS)
            </div>
            <div className="space-y-1 font-mono text-[11px] text-slate-200">
              {dnssec.ds_records.map((ds, i) => (
                <div key={i} className="break-all">
                  {ds}
                </div>
              ))}
            </div>
          </div>
        )}

        {dnssec.dnskey_records.length > 0 && (
          <div className="mt-2 rounded-lg border border-slate-800 bg-[#0b0f17] p-3">
            <div className="mb-1 text-[11px] uppercase tracking-wider text-slate-500">
              Zone Keys (DNSKEY)
            </div>
            <div className="space-y-1 font-mono text-[11px] text-slate-200">
              {dnssec.dnskey_records.map((k, i) => (
                <div key={i} className="break-all">
                  {k}
                </div>
              ))}
            </div>
          </div>
        )}

        {dnssec.validation_error && (
          <div className="mt-3 rounded-lg border border-rose-500/30 bg-rose-500/10 p-2.5 font-mono text-[11px] text-rose-200">
            {dnssec.validation_error}
          </div>
        )}

        {dnssec.issues.length > 0 && (
          <ul className="mt-3 space-y-1 text-xs text-slate-300">
            {dnssec.issues.map((issue, idx) => (
              <li key={idx}>• {issue}</li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}
