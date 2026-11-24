import {
  AlertTriangle,
  Building2,
  Calendar,
  Check,
  Clock,
  Copy,
  Globe,
  Info,
  Server,
  Shield,
} from "lucide-react";
import { useState } from "react";
import type { WhoisInfo } from "../types/dns";
import { copyToClipboard } from "../lib/api";

function formatDateDisplay(raw: string | null): string {
  if (!raw) return "—";
  const parsed = new Date(raw);
  if (!Number.isNaN(parsed.getTime()) && /^\d{4}-\d{2}-\d{2}/.test(raw.trim())) {
    return parsed.toISOString().slice(0, 10);
  }
  return raw;
}

function cleanStatusLabel(status: string): { label: string; url: string | null } {
  const parts = status.trim().split(/\s+/);
  const label = parts[0] ?? status;
  const url = parts.find((p) => p.startsWith("http://") || p.startsWith("https://")) ?? null;
  return { label, url };
}

interface WhoisPanelProps {
  whois: WhoisInfo;
  queriedTarget: string;
  onNotify: (msg: string) => void;
}

export function WhoisPanel({ whois, queriedTarget, onNotify }: WhoisPanelProps) {
  const [copied, setCopied] = useState(false);

  const handleCopyRaw = async () => {
    if (!whois.raw_text) return;
    await copyToClipboard(whois.raw_text);
    setCopied(true);
    onNotify("Copied raw WHOIS output");
    setTimeout(() => setCopied(false), 1500);
  };

  const expiryBadge = () => {
    if (whois.days_until_expiry === null) return null;
    const days = whois.days_until_expiry;
    if (days < 0) {
      return (
        <span className="rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 font-mono text-[11px] font-medium text-rose-300">
          Expired {Math.abs(days)}d ago
        </span>
      );
    }
    if (days <= 30) {
      return (
        <span className="rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 font-mono text-[11px] font-medium text-amber-300">
          {days}d left
        </span>
      );
    }
    return (
      <span className="rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 font-mono text-[11px] font-medium text-emerald-300">
        {days}d left
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {whois.status === "error" && (
        <div className="flex items-start gap-3 rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-sm text-rose-200">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
          <div>
            <div className="font-semibold">WHOIS Lookup Failed</div>
            <div className="mt-0.5 text-xs text-rose-300/90">
              {whois.error ?? "Unable to query WHOIS server for this domain."}
            </div>
          </div>
        </div>
      )}

      {whois.status === "not_found" && (
        <div className="flex items-start gap-3 rounded-xl border border-amber-500/30 bg-amber-500/10 p-4 text-sm text-amber-200">
          <Info className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
          <div>
            <div className="font-semibold">No WHOIS Record Found</div>
            <div className="mt-0.5 text-xs text-amber-300/90">
              Registry returned no registration match for{" "}
              <span className="font-mono">{whois.queried_domain}</span>.
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-400">
            <Building2 className="h-3.5 w-3.5 text-sky-400" />
            Registrar
          </div>
          <div className="mt-2 truncate text-sm font-semibold text-slate-100" title={whois.registrar ?? ""}>
            {whois.registrar ?? "—"}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2 text-[11px] text-slate-400">
            {whois.registrar_iana_id && (
              <span className="font-mono">IANA #{whois.registrar_iana_id}</span>
            )}
            {whois.registrar_url && (
              <span className="truncate font-mono text-slate-500" title={whois.registrar_url}>
                {whois.registrar_url}
              </span>
            )}
          </div>
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-400">
            <Calendar className="h-3.5 w-3.5 text-emerald-400" />
            Created
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-slate-100">
            {formatDateDisplay(whois.created_date)}
          </div>
          {whois.created_date && (
            <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={whois.created_date}>
              {whois.created_date}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-400">
            <Clock className="h-3.5 w-3.5 text-indigo-400" />
            Updated
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-slate-100">
            {formatDateDisplay(whois.updated_date)}
          </div>
          {whois.updated_date && (
            <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={whois.updated_date}>
              {whois.updated_date}
            </div>
          )}
        </div>

        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex items-center justify-between gap-2">
            <div className="flex items-center gap-2 text-[11px] font-medium uppercase tracking-wider text-slate-400">
              <Calendar className="h-3.5 w-3.5 text-amber-400" />
              Expires
            </div>
            {expiryBadge()}
          </div>
          <div className="mt-2 font-mono text-sm font-semibold text-slate-100">
            {formatDateDisplay(whois.expiry_date)}
          </div>
          {whois.expiry_date && (
            <div className="mt-1 truncate font-mono text-[11px] text-slate-500" title={whois.expiry_date}>
              {whois.expiry_date}
            </div>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
        <div className="rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
            <Globe className="h-4 w-4 text-sky-400" />
            Registration Metadata
          </div>

          <dl className="mt-3 divide-y divide-slate-800/70 text-xs">
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">WHOIS Domain</dt>
              <dd className="flex items-center gap-2 font-mono text-slate-100">
                <span>{whois.queried_domain}</span>
                {whois.queried_domain !== queriedTarget && (
                  <span className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-[10px] text-sky-300">
                    apex
                  </span>
                )}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">WHOIS Servers</dt>
              <dd className="text-right font-mono text-slate-200">
                {whois.servers_queried.length > 0
                  ? `${whois.servers_queried.join(" → ")} (${whois.latency_ms}ms)`
                  : `${whois.latency_ms}ms`}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">Registrant Org</dt>
              <dd className="text-right text-slate-200">
                {whois.registrant_org ?? "—"}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">Registrant Country</dt>
              <dd className="font-mono text-slate-200">
                {whois.registrant_country ?? "—"}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">Registry DNSSEC</dt>
              <dd className="font-mono text-slate-200">
                {whois.dnssec ?? "—"}
              </dd>
            </div>
            <div className="flex items-center justify-between gap-4 py-2">
              <dt className="text-slate-400">Abuse Contact</dt>
              <dd className="text-right font-mono text-slate-200">
                {[whois.abuse_email, whois.abuse_phone].filter(Boolean).join(" · ") || "—"}
              </dd>
            </div>
          </dl>
        </div>

        <div className="space-y-4 rounded-xl border border-slate-800 bg-[#111827] p-4">
          <div>
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Server className="h-4 w-4 text-emerald-400" />
              Name Servers ({whois.name_servers.length})
            </div>
            {whois.name_servers.length === 0 ? (
              <div className="mt-2 text-xs text-slate-500">
                No name servers reported in WHOIS output.
              </div>
            ) : (
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {whois.name_servers.map((ns) => (
                  <span
                    key={ns}
                    className="rounded-md border border-slate-700/80 bg-[#0b0f17] px-2.5 py-1 font-mono text-xs text-slate-200"
                  >
                    {ns}
                  </span>
                ))}
              </div>
            )}
          </div>

          <div className="border-t border-slate-800/80 pt-3">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Shield className="h-4 w-4 text-amber-400" />
              Domain Statuses ({whois.statuses.length})
            </div>
            {whois.statuses.length === 0 ? (
              <div className="mt-2 text-xs text-slate-500">
                No EPP status flags reported.
              </div>
            ) : (
              <div className="mt-2.5 flex flex-wrap gap-1.5">
                {whois.statuses.map((st, idx) => {
                  const { label, url } = cleanStatusLabel(st);
                  return (
                    <span
                      key={`${label}-${idx}`}
                      title={url ?? st}
                      className="rounded-md border border-slate-700/80 bg-[#0b0f17] px-2.5 py-1 font-mono text-[11px] text-slate-300"
                    >
                      {label}
                    </span>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>

      {whois.raw_text && (
        <div className="overflow-hidden rounded-xl border border-slate-800 bg-[#111827]">
          <div className="flex items-center justify-between border-b border-slate-800 bg-[#0d131f] px-4 py-2.5">
            <span className="text-xs font-medium text-slate-300">
              Raw WHOIS Output
            </span>
            <button
              type="button"
              onClick={handleCopyRaw}
              className="inline-flex items-center gap-1.5 rounded-md border border-slate-700 bg-slate-800 px-2.5 py-1 text-xs text-slate-200 hover:border-sky-500/50 hover:text-sky-300"
            >
              {copied ? (
                <>
                  <Check className="h-3.5 w-3.5 text-emerald-400" />
                  Copied
                </>
              ) : (
                <>
                  <Copy className="h-3.5 w-3.5" />
                  Copy Raw WHOIS
                </>
              )}
            </button>
          </div>
          <pre className="max-h-96 overflow-auto p-4 font-mono text-xs leading-relaxed text-slate-300">
            {whois.raw_text}
          </pre>
        </div>
      )}
    </div>
  );
}
