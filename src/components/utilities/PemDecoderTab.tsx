import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  FileKey2,
  KeyRound,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import { type DragEvent, useRef, useState } from "react";
import { copyToClipboard, decodePem } from "../../lib/api";
import type { PemDecodeReport, PemDecodedItem } from "../../types/dns";

export interface PemDecoderTabProps {
  onNotify: (msg: string) => void;
}

export function PemDecoderTab({ onNotify }: PemDecoderTabProps) {
  const [pemInput, setPemInput] = useState("");
  const [tlsaHost, setTlsaHost] = useState("_443._tcp.example.com");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<PemDecodeReport | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const runDecode = async (textOverride?: string) => {
    const raw = (textOverride ?? pemInput).trim();
    if (!raw) {
      setError("Paste a PEM certificate, certificate chain, or CSR to decode.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const res = await decodePem(raw);
      setReport(res);
      if (res.error) {
        setError(res.error);
      }
      const firstCn = res.items[0]?.common_name || res.items[0]?.sans[0];
      if (firstCn && !firstCn.startsWith("*")) {
        setTlsaHost(`_443._tcp.${firstCn.replace(/^\*\./, "")}`);
      }
    } catch (err) {
      setError(String(err));
      setReport(null);
    } finally {
      setLoading(false);
    }
  };

  const handleFile = async (file: File) => {
    try {
      const text = await file.text();
      setPemInput(text);
      onNotify(`Loaded ${file.name}`);
      await runDecode(text);
    } catch (err) {
      setError(`Failed to read file: ${String(err)}`);
    }
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      void handleFile(file);
    }
  };

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  const renderExpiryBadge = (item: PemDecodedItem) => {
    if (item.days_remaining === null) return null;
    if (item.days_remaining < 0) {
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2 py-0.5 text-[11px] font-semibold text-rose-700 dark:text-rose-300">
          <ShieldAlert className="h-3 w-3" />
          Expired ({Math.abs(item.days_remaining)}d ago)
        </span>
      );
    }
    if (item.days_remaining <= 30) {
      return (
        <span className="inline-flex items-center gap-1 rounded-full border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[11px] font-semibold text-amber-700 dark:text-amber-300">
          <AlertTriangle className="h-3 w-3" />
          Expires in {item.days_remaining}d
        </span>
      );
    }
    return (
      <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2 py-0.5 text-[11px] font-semibold text-emerald-700 dark:text-emerald-300">
        <ShieldCheck className="h-3 w-3" />
        Valid · {item.days_remaining}d left
      </span>
    );
  };

  return (
    <div className="space-y-4">
      {/* Input & Dropzone Card */}
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
            <FileKey2 className="h-4 w-4 text-sky-600 dark:text-sky-400" />
            <div>
              <h3 className="text-sm font-semibold text-ink">
                PEM Certificate, Chain &amp; CSR Decoder
              </h3>
              <p className="text-[11px] text-ink-muted">
                Decode X.509 certificates, full chains, or PKCS#10 CSRs locally via Rust x509-parser — nothing leaves your machine.
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".pem,.crt,.cer,.csr,.key,.txt"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0];
                if (file) void handleFile(file);
                e.target.value = "";
              }}
            />
            <button
              type="button"
              onClick={() => fileInputRef.current?.click()}
              className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs font-medium text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
            >
              <Upload className="h-3.5 w-3.5" />
              Load File
            </button>
            {pemInput && (
              <button
                type="button"
                onClick={() => {
                  setPemInput("");
                  setReport(null);
                  setError(null);
                }}
                className="inline-flex items-center gap-1 rounded-lg border border-line bg-surface-alt px-2.5 py-1.5 text-xs text-ink-muted hover:text-rose-600 dark:hover:text-rose-400"
              >
                <Trash2 className="h-3.5 w-3.5" />
                Clear
              </button>
            )}
          </div>
        </div>

        <textarea
          rows={7}
          value={pemInput}
          onChange={(e) => setPemInput(e.target.value)}
          placeholder={
            "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----\n\n(Drop a .pem / .crt / .csr file here or paste one or more PEM blocks)"
          }
          className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
        />

        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <label className="text-[11px] text-ink-muted">TLSA Host Prefix:</label>
            <input
              type="text"
              value={tlsaHost}
              onChange={(e) => setTlsaHost(e.target.value)}
              placeholder="_443._tcp.example.com"
              className="w-56 rounded-lg border border-line-strong bg-canvas px-2.5 py-1 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
            />
          </div>

          <button
            type="button"
            disabled={loading}
            onClick={() => void runDecode()}
            className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
          >
            {loading ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <KeyRound className="h-3.5 w-3.5" />
            )}
            {loading ? "Decoding..." : "Decode PEM"}
          </button>
        </div>
      </div>

      {error && (
        <div className="rounded-xl border border-rose-500/35 bg-rose-500/10 p-3.5 text-xs text-rose-800 dark:text-rose-200">
          {error}
        </div>
      )}

      {report && (
        <div className="space-y-4">
          {/* Chain Check & Warnings */}
          {(report.chain_order_valid !== null || report.warnings.length > 0) && (
            <div className="rounded-xl border border-line bg-surface p-4 space-y-2.5">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <span className="text-xs font-semibold text-ink">
                  Decoded {report.items.length} PEM block{report.items.length === 1 ? "" : "s"}
                </span>
                {report.chain_order_valid !== null && (
                  <span
                    className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold ${
                      report.chain_order_valid
                        ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                        : "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                    }`}
                  >
                    {report.chain_order_valid ? (
                      <CheckCircle2 className="h-3 w-3" />
                    ) : (
                      <AlertTriangle className="h-3 w-3" />
                    )}
                    {report.chain_order_valid
                      ? "Chain Order Valid (Leaf → Issuer)"
                      : "Chain Order Issue Detected"}
                  </span>
                )}
              </div>

              {report.warnings.length > 0 && (
                <div className="space-y-1.5">
                  {report.warnings.map((w, idx) => (
                    <div
                      key={idx}
                      className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-xs text-amber-900 dark:text-amber-200"
                    >
                      <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
                      <span>{w}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Decoded PEM Blocks */}
          {report.items.map((item, idx) => {
            const hostClean = tlsaHost.trim() || "_443._tcp.example.com";
            const formatTlsaBind = (raw: string, fallbackPrefix: string) => {
              const trimmed = raw.trim();
              const rdata = /^[0-3]\s+[01]\s+[0-2]\s+/.test(trimmed)
                ? trimmed
                : `${fallbackPrefix} ${trimmed}`;
              return `${hostClean}. 3600 IN TLSA ${rdata}`;
            };
            const tlsa311Bind = item.tlsa_3_1_1
              ? formatTlsaBind(item.tlsa_3_1_1, "3 1 1")
              : null;
            const tlsa301Bind = item.tlsa_3_0_1
              ? formatTlsaBind(item.tlsa_3_0_1, "3 0 1")
              : null;

            return (
              <div
                key={`${item.sha256_fingerprint}-${idx}`}
                className="rounded-xl border border-line bg-surface p-4 space-y-3"
              >
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="rounded bg-surface-alt px-2 py-0.5 font-mono text-[11px] font-semibold text-sky-700 dark:text-sky-300">
                      #{idx + 1} · {item.kind}
                    </span>
                    <span className="font-mono text-sm font-semibold text-ink">
                      {item.common_name || item.subject}
                    </span>
                    {item.is_ca && (
                      <span className="rounded-full border border-violet-500/35 bg-violet-500/10 px-2 py-0.5 text-[10px] font-semibold text-violet-700 dark:text-violet-300">
                        CA
                      </span>
                    )}
                    {item.is_self_signed && (
                      <span className="rounded-full border border-amber-500/35 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-700 dark:text-amber-300">
                        Self-Signed
                      </span>
                    )}
                  </div>
                  {renderExpiryBadge(item)}
                </div>

                {/* Metadata Grid */}
                <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2 lg:grid-cols-3">
                  <div className="rounded-lg border border-line bg-canvas p-2.5">
                    <div className="text-[11px] text-ink-muted">Subject</div>
                    <div className="mt-0.5 break-all font-mono text-[11px] text-ink">
                      {item.subject}
                    </div>
                  </div>
                  <div className="rounded-lg border border-line bg-canvas p-2.5">
                    <div className="text-[11px] text-ink-muted">Issuer</div>
                    <div className="mt-0.5 break-all font-mono text-[11px] text-ink">
                      {item.issuer ?? "N/A (CSR)"}
                    </div>
                    {item.issuer_org && (
                      <div className="mt-0.5 text-[11px] text-ink-secondary">
                        Org: {item.issuer_org}
                      </div>
                    )}
                  </div>
                  <div className="rounded-lg border border-line bg-canvas p-2.5">
                    <div className="text-[11px] text-ink-muted">Validity Window</div>
                    <div className="mt-0.5 font-mono text-[11px] text-ink">
                      {item.not_before && item.not_after
                        ? `${item.not_before} → ${item.not_after}`
                        : "Not applicable"}
                    </div>
                    {item.serial_hex && (
                      <div className="mt-0.5 truncate font-mono text-[10px] text-ink-muted" title={item.serial_hex}>
                        Serial: {item.serial_hex}
                      </div>
                    )}
                  </div>
                  <div className="rounded-lg border border-line bg-canvas p-2.5">
                    <div className="text-[11px] text-ink-muted">Public Key &amp; Signature</div>
                    <div className="mt-0.5 font-mono text-[11px] text-ink">
                      {item.public_key_algorithm}
                      {item.public_key_bits ? ` (${item.public_key_bits}-bit)` : ""}
                    </div>
                    <div className="mt-0.5 font-mono text-[10px] text-ink-muted">
                      Sig: {item.signature_algorithm}
                    </div>
                  </div>
                  <div className="rounded-lg border border-line bg-canvas p-2.5 lg:col-span-2">
                    <div className="flex items-center justify-between text-[11px] text-ink-muted">
                      <span>SHA-256 Fingerprints</span>
                      <button
                        type="button"
                        onClick={() => void copyText(item.sha256_fingerprint, "SHA-256 fingerprint")}
                        className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                      >
                        <Copy className="h-3 w-3" /> Cert SHA-256
                      </button>
                    </div>
                    <div className="mt-0.5 break-all font-mono text-[11px] text-ink-secondary">
                      Cert: {item.sha256_fingerprint}
                    </div>
                    {item.spki_sha256 && (
                      <div className="mt-0.5 flex items-center justify-between gap-2">
                        <span className="break-all font-mono text-[10px] text-ink-muted">
                          SPKI: {item.spki_sha256}
                        </span>
                        <button
                          type="button"
                          onClick={() => void copyText(item.spki_sha256!, "SPKI SHA-256")}
                          className="shrink-0 text-[10px] text-sky-600 hover:underline dark:text-sky-400"
                        >
                          Copy SPKI
                        </button>
                      </div>
                    )}
                  </div>
                </div>

                {/* SANs */}
                <div>
                  <div className="mb-1.5 flex items-center justify-between text-[11px] text-ink-muted">
                    <span>Subject Alternative Names ({item.sans.length})</span>
                    {item.sans.length > 0 && (
                      <button
                        type="button"
                        onClick={() => void copyText(item.sans.join("\n"), "SAN list")}
                        className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                      >
                        <Copy className="h-3 w-3" /> Copy SANs
                      </button>
                    )}
                  </div>
                  {item.sans.length > 0 ? (
                    <div className="flex flex-wrap gap-1.5">
                      {item.sans.map((san) => (
                        <span
                          key={san}
                          className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-[11px] text-ink-secondary"
                        >
                          {san}
                        </span>
                      ))}
                    </div>
                  ) : (
                    <span className="text-xs italic text-ink-muted">No SAN entries present.</span>
                  )}
                </div>

                {/* 1-Click DANE / TLSA Records */}
                {(item.tlsa_3_1_1 || item.tlsa_3_0_1) && (
                  <div className="rounded-lg border border-line bg-canvas p-3 space-y-2">
                    <div className="text-[11px] font-semibold text-ink">
                      1-Click DANE / TLSA Records (RFC 6698)
                    </div>
                    <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
                      {item.tlsa_3_1_1 && tlsa311Bind && (
                        <div className="rounded border border-line bg-surface p-2.5 text-xs">
                          <div className="flex items-center justify-between gap-2 text-[11px]">
                            <span className="font-semibold text-emerald-700 dark:text-emerald-300">
                              TLSA 3 1 1 (DANE-EE · SPKI · SHA-256)
                            </span>
                            <button
                              type="button"
                              onClick={() => void copyText(tlsa311Bind, "TLSA 3 1 1 record")}
                              className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                            >
                              <Copy className="h-3 w-3" /> Copy BIND
                            </button>
                          </div>
                          <div className="mt-1 break-all font-mono text-[10px] text-ink-secondary">
                            {tlsa311Bind}
                          </div>
                        </div>
                      )}
                      {item.tlsa_3_0_1 && tlsa301Bind && (
                        <div className="rounded border border-line bg-surface p-2.5 text-xs">
                          <div className="flex items-center justify-between gap-2 text-[11px]">
                            <span className="font-semibold text-sky-700 dark:text-sky-300">
                              TLSA 3 0 1 (DANE-EE · Full Cert · SHA-256)
                            </span>
                            <button
                              type="button"
                              onClick={() => void copyText(tlsa301Bind, "TLSA 3 0 1 record")}
                              className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                            >
                              <Copy className="h-3 w-3" /> Copy BIND
                            </button>
                          </div>
                          <div className="mt-1 break-all font-mono text-[10px] text-ink-secondary">
                            {tlsa301Bind}
                          </div>
                        </div>
                      )}
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
