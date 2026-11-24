import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  KeyRound,
  Lock,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useState } from "react";
import { copyToClipboard, inspectTls } from "../lib/api";
import type { TlsReport } from "../types/dns";

interface TlsPanelProps {
  tls: TlsReport;
  defaultHost: string;
  onNotify: (msg: string) => void;
}

const PORT_PRESETS = [
  { label: "HTTPS (443)", port: 443, starttls: "none" },
  { label: "HTTPS Alt (8443)", port: 8443, starttls: "none" },
  { label: "SMTPS (465)", port: 465, starttls: "none" },
  { label: "SMTP (587 STARTTLS)", port: 587, starttls: "smtp" },
  { label: "SMTP (25 STARTTLS)", port: 25, starttls: "smtp" },
  { label: "IMAPS (993)", port: 993, starttls: "none" },
];

export function TlsPanel({ tls, defaultHost, onNotify }: TlsPanelProps) {
  const [activeReport, setActiveReport] = useState<TlsReport>(tls);
  const [probeHost, setProbeHost] = useState(tls.host || defaultHost);
  const [probePort, setProbePort] = useState(String(tls.port || 443));
  const [probeStarttls, setProbeStarttls] = useState(tls.starttls ?? "auto");
  const [probing, setProbing] = useState(false);

  useEffect(() => {
    setActiveReport(tls);
    setProbeHost(tls.host || defaultHost);
    setProbePort(String(tls.port || 443));
    setProbeStarttls(tls.starttls ?? "auto");
  }, [tls, defaultHost]);

  const handleProbe = async (hostVal?: string, portVal?: number, stls?: string) => {
    const h = (hostVal ?? probeHost).trim();
    const p = portVal ?? (Number.parseInt(probePort, 10) || 443);
    const mode = stls ?? probeStarttls;
    if (!h) return;
    setProbing(true);
    try {
      const res = await inspectTls(h, p, mode);
      setActiveReport(res);
    } catch (err) {
      onNotify(`TLS probe failed: ${String(err)}`);
    } finally {
      setProbing(false);
    }
  };

  const statusTone =
    activeReport.status === "ok"
      ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
      : activeReport.status === "warning"
        ? "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-300"
        : "border-rose-500/30 bg-rose-500/10 text-rose-700 dark:text-rose-300";

  const copyText = (val: string, label: string) => {
    void copyToClipboard(val);
    onNotify(`Copied ${label}`);
  };

  return (
    <div className="space-y-4">
      {/* Custom Host / Port / STARTTLS Probe Bar */}
      <div className="rounded-xl border border-line bg-surface p-4">
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[180px] flex-1">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Target Host (e.g. apex, mail.domain.com)
            </label>
            <input
              type="text"
              value={probeHost}
              onChange={(e) => setProbeHost(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas px-3 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
              placeholder={defaultHost}
            />
          </div>

          <div className="w-24">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Port
            </label>
            <input
              type="number"
              min={1}
              max={65535}
              value={probePort}
              onChange={(e) => setProbePort(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink outline-none focus:border-sky-500"
            />
          </div>

          <div className="w-32">
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              STARTTLS
            </label>
            <select
              value={probeStarttls}
              onChange={(e) => setProbeStarttls(e.target.value)}
              className="w-full rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs text-ink outline-none focus:border-sky-500"
            >
              <option value="auto">Auto</option>
              <option value="none">Direct TLS</option>
              <option value="smtp">SMTP STARTTLS</option>
              <option value="imap">IMAP STARTTLS</option>
            </select>
          </div>

          <button
            type="button"
            disabled={probing}
            onClick={() => void handleProbe()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${probing ? "animate-spin" : ""}`} />
            {probing ? "Inspecting..." : "Inspect TLS"}
          </button>
        </div>

        <div className="mt-3 flex flex-wrap items-center gap-1.5">
          <span className="text-[11px] text-ink-muted">Quick Presets:</span>
          {PORT_PRESETS.map((p) => (
            <button
              key={p.port}
              type="button"
              onClick={() => {
                setProbePort(String(p.port));
                setProbeStarttls(p.starttls);
                void handleProbe(probeHost, p.port, p.starttls);
              }}
              className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {/* Summary Banner */}
      <div className={`rounded-xl border p-4 ${statusTone}`}>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-2.5">
            {activeReport.status === "ok" ? (
              <ShieldCheck className="h-5 w-5 shrink-0" />
            ) : activeReport.status === "warning" ? (
              <AlertTriangle className="h-5 w-5 shrink-0" />
            ) : (
              <ShieldAlert className="h-5 w-5 shrink-0" />
            )}
            <div>
              <div className="text-sm font-semibold">
                {activeReport.host}:{activeReport.port}
                {activeReport.starttls ? ` (${activeReport.starttls.toUpperCase()} STARTTLS)` : ""}
              </div>
              <div className="text-xs opacity-90">
                {activeReport.error
                  ? activeReport.error
                  : activeReport.verification_error
                    ? `Verification issue: ${activeReport.verification_error}`
                    : activeReport.hostname_match
                      ? "Trusted certificate chain and valid hostname match"
                      : "Certificate hostname does not match queried domain"}
              </div>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2 font-mono text-xs">
            {activeReport.protocol_version && (
              <span className="rounded-md border border-current/25 bg-surface/70 px-2 py-0.5 text-ink">
                {activeReport.protocol_version}
              </span>
            )}
            {activeReport.days_remaining != null && (
              <span className="rounded-md border border-current/25 bg-surface/70 px-2 py-0.5 font-semibold text-ink">
                {activeReport.days_remaining > 0
                  ? `${activeReport.days_remaining}d left`
                  : `Expired (${Math.abs(activeReport.days_remaining)}d ago)`}
              </span>
            )}
            <span className="rounded-md border border-current/25 bg-surface/70 px-2 py-0.5 text-ink">
              {activeReport.handshake_ms}ms
            </span>
          </div>
        </div>

        {!activeReport.error && (
          <div className="mt-3 grid grid-cols-1 gap-2 border-t border-current/15 pt-3 text-xs sm:grid-cols-3">
            <div className="flex items-center gap-1.5">
              {activeReport.chain_valid ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <XCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
              )}
              <span>Chain Trust: {activeReport.chain_valid ? "Valid" : "Untrusted"}</span>
            </div>
            <div className="flex items-center gap-1.5">
              {activeReport.hostname_match ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
              ) : (
                <XCircle className="h-3.5 w-3.5 text-rose-600 dark:text-rose-400" />
              )}
              <span>Hostname Match: {activeReport.hostname_match ? "Match" : "Mismatch"}</span>
            </div>
            <div className="truncate font-mono text-[11px]">
              Cipher: {activeReport.cipher_suite ?? "N/A"}
            </div>
          </div>
        )}
      </div>

      {/* Certificate Chain Cards */}
      {activeReport.certificates.length > 0 && (
        <div className="space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-ink-muted">
            Certificate Chain ({activeReport.certificates.length})
          </div>
          {activeReport.certificates.map((cert, idx) => {
            const roleLabel =
              idx === 0
                ? "Leaf Certificate"
                : cert.is_self_signed
                  ? "Root Certificate"
                  : "Intermediate CA";
            const expiryTone =
              cert.days_remaining <= 0
                ? "bg-rose-500/15 text-rose-700 dark:text-rose-300"
                : cert.days_remaining <= 30
                  ? "bg-amber-500/15 text-amber-700 dark:text-amber-300"
                  : "bg-emerald-500/15 text-emerald-700 dark:text-emerald-300";

            return (
              <div
                key={`${cert.sha256_fingerprint}-${idx}`}
                className="rounded-xl border border-line bg-surface p-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                  <div className="flex items-center gap-2">
                    <Lock className="h-4 w-4 text-sky-600 dark:text-sky-400" />
                    <span className="text-xs font-semibold text-ink">
                      #{idx + 1} {roleLabel}
                    </span>
                    {cert.common_name && (
                      <span className="rounded bg-surface-alt px-2 py-0.5 font-mono text-xs text-ink">
                        {cert.common_name}
                      </span>
                    )}
                    {cert.is_ca && (
                      <span className="rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] font-semibold text-sky-700 dark:text-sky-300">
                        CA
                      </span>
                    )}
                  </div>
                  <span className={`rounded-full px-2 py-0.5 font-mono text-[11px] font-semibold ${expiryTone}`}>
                    {cert.days_remaining}d remaining
                  </span>
                </div>

                <div className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2 text-xs md:grid-cols-2">
                  <div>
                    <div className="text-[11px] text-ink-muted">Subject</div>
                    <div className="break-all font-mono text-[11px] text-ink">
                      {cert.subject}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">Issuer</div>
                    <div className="break-all font-mono text-[11px] text-ink">
                      {cert.issuer}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">Validity Period</div>
                    <div className="font-mono text-[11px] text-ink-secondary">
                      {new Date(cert.not_before).toLocaleDateString()} →{" "}
                      {new Date(cert.not_after).toLocaleDateString()}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">Key &amp; Signature</div>
                    <div className="flex items-center gap-1.5 font-mono text-[11px] text-ink-secondary">
                      <KeyRound className="h-3 w-3 text-ink-muted" />
                      {cert.public_key_algorithm}
                      {cert.public_key_bits ? ` ${cert.public_key_bits}-bit` : ""} •{" "}
                      {cert.signature_algorithm}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">Serial Number</div>
                    <div className="truncate font-mono text-[11px] text-ink-secondary">
                      {cert.serial_hex}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11px] text-ink-muted">SHA-256 Fingerprint</div>
                    <div className="flex items-center gap-1.5">
                      <span className="truncate font-mono text-[11px] text-ink-secondary">
                        {cert.sha256_fingerprint}
                      </span>
                      <button
                        type="button"
                        onClick={() => copyText(cert.sha256_fingerprint, "SHA-256 fingerprint")}
                        className="shrink-0 rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
                        title="Copy fingerprint"
                      >
                        <Copy className="h-3 w-3" />
                      </button>
                    </div>
                  </div>
                </div>

                {cert.sans.length > 0 && (
                  <div className="mt-3 border-t border-line pt-2.5">
                    <div className="mb-1.5 text-[11px] text-ink-muted">
                      Subject Alternative Names ({cert.sans.length})
                    </div>
                    <div className="flex max-h-28 flex-wrap gap-1.5 overflow-y-auto">
                      {cert.sans.map((san) => (
                        <span
                          key={san}
                          className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                        >
                          {san}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
