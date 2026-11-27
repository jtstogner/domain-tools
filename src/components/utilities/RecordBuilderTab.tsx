import {
  AlertTriangle,
  CheckCircle2,
  Copy,
  Download,
  Eye,
  EyeOff,
  KeyRound,
  RefreshCw,
  Scissors,
  ShieldAlert,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard, saveExport } from "../../lib/api";
import {
  buildBimiRecord,
  buildCaaRecords,
  buildDmarcRecord,
  buildMtaStsRecords,
  buildSpfRecord,
  buildSrvRecord,
  CAA_PROVIDERS,
  computeTlsaFromPem,
  type DkimKeypairResult,
  generateDkimKeypair,
  lintDnsRecord,
  type LintKindHint,
  SPF_PROVIDERS,
  splitTxtChunks,
  type TlsaComputeResult,
} from "../../lib/recordBuilder";

export interface RecordBuilderTabProps {
  defaultDomain: string;
  onNotify: (msg: string) => void;
}

type BuilderType =
  | "spf"
  | "dmarc"
  | "caa"
  | "srv"
  | "mta-sts"
  | "bimi"
  | "dkim"
  | "tlsa"
  | "txt-split";

const BUILDER_TABS: Array<{ id: BuilderType; label: string }> = [
  { id: "spf", label: "SPF" },
  { id: "dmarc", label: "DMARC" },
  { id: "caa", label: "CAA" },
  { id: "srv", label: "SRV" },
  { id: "mta-sts", label: "MTA-STS" },
  { id: "bimi", label: "BIMI" },
  { id: "dkim", label: "DKIM Keygen" },
  { id: "tlsa", label: "DANE / TLSA" },
  { id: "txt-split", label: "TXT Splitter" },
];

export function RecordBuilderTab({ defaultDomain, onNotify }: RecordBuilderTabProps) {
  const [builderType, setBuilderType] = useState<BuilderType>("spf");
  const [builderDomain, setBuilderDomain] = useState(defaultDomain || "example.com");

  // SPF options
  const [spfProviders, setSpfProviders] = useState<string[]>(["google"]);
  const [spfCustomIncludes, setSpfCustomIncludes] = useState("");
  const [spfIp4, setSpfIp4] = useState("");
  const [spfIp6, setSpfIp6] = useState("");
  const [spfIncludeA, setSpfIncludeA] = useState(false);
  const [spfIncludeMx, setSpfIncludeMx] = useState(true);
  const [spfAllPolicy, setSpfAllPolicy] = useState<"-all" | "~all" | "?all">("-all");

  // DMARC options
  const [dmarcPolicy, setDmarcPolicy] = useState<"none" | "quarantine" | "reject">("quarantine");
  const [dmarcSubPolicy, setDmarcSubPolicy] = useState<"" | "none" | "quarantine" | "reject">("");
  const [dmarcPct, setDmarcPct] = useState("100");
  const [dmarcAdkim, setDmarcAdkim] = useState<"r" | "s">("r");
  const [dmarcAspf, setDmarcAspf] = useState<"r" | "s">("r");
  const [dmarcRua, setDmarcRua] = useState(`dmarc@${defaultDomain || "example.com"}`);
  const [dmarcRuf, setDmarcRuf] = useState("");

  // CAA options
  const [caaSelected, setCaaSelected] = useState<string[]>(["letsencrypt.org"]);
  const [caaWildcard, setCaaWildcard] = useState(true);
  const [caaIodef, setCaaIodef] = useState("");

  // SRV options
  const [srvService, setSrvService] = useState("_sip");
  const [srvProtocol, setSrvProtocol] = useState<"_tcp" | "_udp" | "_tls">("_tls");
  const [srvPriority, setSrvPriority] = useState("10");
  const [srvWeight, setSrvWeight] = useState("60");
  const [srvPort, setSrvPort] = useState("5061");
  const [srvTarget, setSrvTarget] = useState(`sip.${defaultDomain || "example.com"}`);

  // MTA-STS / TLS-RPT options
  const [stsPolicyId, setStsPolicyId] = useState(() => {
    const d = new Date();
    return `${d.getUTCFullYear()}${String(d.getUTCMonth() + 1).padStart(2, "0")}${String(
      d.getUTCDate(),
    ).padStart(2, "0")}01`;
  });
  const [stsMode, setStsMode] = useState<"testing" | "enforce" | "none">("testing");
  const [stsMaxAge, setStsMaxAge] = useState("604800");
  const [stsMxPatterns, setStsMxPatterns] = useState(
    `*.mail.protection.outlook.com\nmail.${defaultDomain || "example.com"}`,
  );
  const [stsTlsRptEmail, setStsTlsRptEmail] = useState(
    `tls-reports@${defaultDomain || "example.com"}`,
  );

  // BIMI options
  const [bimiSelector, setBimiSelector] = useState("default");
  const [bimiLogoUrl, setBimiLogoUrl] = useState(
    `https://${defaultDomain || "example.com"}/brand/logo.svg`,
  );
  const [bimiAuthorityUrl, setBimiAuthorityUrl] = useState(
    `https://${defaultDomain || "example.com"}/brand/vmc.pem`,
  );

  // DKIM Keypair Generator options
  const [dkimSelector, setDkimSelector] = useState("s1");
  const [dkimAlg, setDkimAlg] = useState<"rsa2048" | "ed25519">("rsa2048");
  const [dkimGenerating, setDkimGenerating] = useState(false);
  const [dkimError, setDkimError] = useState<string | null>(null);
  const [dkimResult, setDkimResult] = useState<DkimKeypairResult | null>(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);

  // DANE / TLSA Generator options
  const [tlsaPem, setTlsaPem] = useState("");
  const [tlsaHost, setTlsaHost] = useState(`mail.${defaultDomain || "example.com"}`);
  const [tlsaPort, setTlsaPort] = useState("25");
  const [tlsaProtocol, setTlsaProtocol] = useState<"tcp" | "udp">("tcp");
  const [tlsaUsage, setTlsaUsage] = useState<0 | 1 | 2 | 3>(3);
  const [tlsaSelector, setTlsaSelector] = useState<0 | 1>(1);
  const [tlsaMatching, setTlsaMatching] = useState<1 | 2>(1);
  const [tlsaLoading, setTlsaLoading] = useState(false);
  const [tlsaError, setTlsaError] = useState<string | null>(null);
  const [tlsaResult, setTlsaResult] = useState<TlsaComputeResult | null>(null);

  // TXT Splitter options
  const [txtSplitInput, setTxtSplitInput] = useState(
    "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA0exampleLongPublicKeyValueThatExceeds255BytesSoYouCanPreviewAutomaticChunkSplittingForBINDCloudflareAndRoute53ZoneFilesWithoutManualCountingOfCharactersOrUtf8ByteBoundaries1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
  );
  const [txtMaxBytes, setTxtMaxBytes] = useState("255");

  // Linter state
  const [lintHint, setLintHint] = useState<LintKindHint>("auto");
  const [lintInput, setLintInput] = useState("v=spf1 include:_spf.google.com ~all");

  useEffect(() => {
    if (defaultDomain) {
      setBuilderDomain(defaultDomain);
    }
  }, [defaultDomain]);

  const spfBuilt = useMemo(
    () =>
      buildSpfRecord({
        domain: builderDomain,
        providerIds: spfProviders,
        customIncludes: spfCustomIncludes.split(/[\s,]+/).filter(Boolean),
        ip4List: spfIp4.split(/[\s,]+/).filter(Boolean),
        ip6List: spfIp6.split(/[\s,]+/).filter(Boolean),
        includeA: spfIncludeA,
        includeMx: spfIncludeMx,
        allPolicy: spfAllPolicy,
      }),
    [
      builderDomain,
      spfProviders,
      spfCustomIncludes,
      spfIp4,
      spfIp6,
      spfIncludeA,
      spfIncludeMx,
      spfAllPolicy,
    ],
  );

  const dmarcBuilt = useMemo(
    () =>
      buildDmarcRecord({
        domain: builderDomain,
        policy: dmarcPolicy,
        subdomainPolicy: dmarcSubPolicy,
        pct: Number(dmarcPct) || 100,
        adkim: dmarcAdkim,
        aspf: dmarcAspf,
        ruaEmail: dmarcRua,
        rufEmail: dmarcRuf,
        fo: "0",
      }),
    [
      builderDomain,
      dmarcPolicy,
      dmarcSubPolicy,
      dmarcPct,
      dmarcAdkim,
      dmarcAspf,
      dmarcRua,
      dmarcRuf,
    ],
  );

  const caaBuilt = useMemo(
    () =>
      buildCaaRecords({
        domain: builderDomain,
        caDomains: caaSelected,
        allowWildcard: caaWildcard,
        iodefEmail: caaIodef,
      }),
    [builderDomain, caaSelected, caaWildcard, caaIodef],
  );

  const srvBuilt = useMemo(
    () =>
      buildSrvRecord({
        domain: builderDomain,
        service: srvService,
        protocol: srvProtocol,
        priority: Number(srvPriority) || 0,
        weight: Number(srvWeight) || 0,
        port: Number(srvPort) || 0,
        target: srvTarget,
      }),
    [builderDomain, srvService, srvProtocol, srvPriority, srvWeight, srvPort, srvTarget],
  );

  const mtaStsBuilt = useMemo(
    () =>
      buildMtaStsRecords({
        domain: builderDomain,
        policyId: stsPolicyId,
        mode: stsMode,
        maxAge: Number(stsMaxAge) || 604800,
        mxPatterns: stsMxPatterns.split(/[\r\n,]+/).filter(Boolean),
        tlsRptEmail: stsTlsRptEmail,
      }),
    [builderDomain, stsPolicyId, stsMode, stsMaxAge, stsMxPatterns, stsTlsRptEmail],
  );

  const bimiBuilt = useMemo(
    () =>
      buildBimiRecord({
        domain: builderDomain,
        selector: bimiSelector,
        logoUrl: bimiLogoUrl,
        authorityUrl: bimiAuthorityUrl,
      }),
    [builderDomain, bimiSelector, bimiLogoUrl, bimiAuthorityUrl],
  );

  const txtSplitResult = useMemo(
    () => splitTxtChunks(txtSplitInput, Number(txtMaxBytes) || 255),
    [txtSplitInput, txtMaxBytes],
  );

  const lintResult = useMemo(() => lintDnsRecord(lintHint, lintInput), [lintHint, lintInput]);

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  const handleGenerateDkim = async () => {
    setDkimGenerating(true);
    setDkimError(null);
    try {
      const res = await generateDkimKeypair({
        domain: builderDomain,
        selector: dkimSelector,
        algorithm: dkimAlg,
      });
      setDkimResult(res);
      setShowPrivateKey(false);
      onNotify(`Generated ${dkimAlg.toUpperCase()} DKIM keypair`);
    } catch (err) {
      setDkimError(String(err));
    } finally {
      setDkimGenerating(false);
    }
  };

  const handleComputeTlsa = async () => {
    if (!tlsaPem.trim()) {
      setTlsaError("Paste a PEM CERTIFICATE or PUBLIC KEY block first.");
      return;
    }
    setTlsaLoading(true);
    setTlsaError(null);
    try {
      const res = await computeTlsaFromPem(tlsaPem, {
        host: tlsaHost,
        port: Number(tlsaPort) || 25,
        protocol: tlsaProtocol,
        usage: tlsaUsage,
        selector: tlsaSelector,
        matchingType: tlsaMatching,
      });
      setTlsaResult(res);
    } catch (err) {
      setTlsaError(String(err));
      setTlsaResult(null);
    } finally {
      setTlsaLoading(false);
    }
  };

  const loadFromGenerator = () => {
    switch (builderType) {
      case "spf":
        setLintHint("spf");
        setLintInput(spfBuilt.value);
        break;
      case "dmarc":
        setLintHint("dmarc");
        setLintInput(dmarcBuilt.value);
        break;
      case "caa":
        setLintHint("caa");
        if (caaBuilt[0]) setLintInput(caaBuilt[0].value);
        break;
      case "mta-sts":
        setLintHint("mta-sts");
        setLintInput(mtaStsBuilt.mtaStsDns.value);
        break;
      case "bimi":
        setLintHint("bimi");
        setLintInput(bimiBuilt.value);
        break;
      case "dkim":
        setLintHint("dkim");
        if (dkimResult) setLintInput(dkimResult.txtValue);
        break;
      case "tlsa":
        setLintHint("tlsa");
        if (tlsaResult) setLintInput(tlsaResult.value);
        break;
      case "txt-split":
        setLintHint("auto");
        setLintInput(txtSplitInput);
        break;
      default:
        break;
    }
  };

  return (
    <div className="grid grid-cols-1 gap-4 xl:grid-cols-12">
      {/* Builder Card */}
      <div className="space-y-4 rounded-xl border border-line bg-surface p-4 xl:col-span-7">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
          <div className="text-sm font-semibold text-ink">DNS Record Generator</div>
          <div className="flex flex-wrap gap-1 rounded-lg border border-line bg-surface-alt p-0.5 text-[11px]">
            {BUILDER_TABS.map((t) => (
              <button
                key={t.id}
                type="button"
                onClick={() => setBuilderType(t.id)}
                className={`rounded-md px-2 py-1 font-medium transition ${
                  builderType === t.id
                    ? "bg-surface font-semibold text-ink shadow-sm ring-1 ring-line"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        {builderType !== "txt-split" && builderType !== "tlsa" && (
          <div>
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Domain Name
            </label>
            <input
              type="text"
              value={builderDomain}
              onChange={(e) => setBuilderDomain(e.target.value)}
              className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
              placeholder="example.com"
            />
          </div>
        )}

        {/* SPF */}
        {builderType === "spf" && (
          <div className="space-y-3 text-xs">
            <div>
              <div className="mb-1.5 text-[11px] font-medium text-ink-muted">
                Authorized Mail Providers
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {SPF_PROVIDERS.map((p) => {
                  const active = spfProviders.includes(p.id);
                  return (
                    <label
                      key={p.id}
                      className={`flex cursor-pointer items-center justify-between rounded-lg border px-2.5 py-1.5 transition ${
                        active
                          ? "border-sky-500/40 bg-sky-500/10 text-ink"
                          : "border-line bg-canvas text-ink-secondary"
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() =>
                            setSpfProviders((prev) =>
                              prev.includes(p.id)
                                ? prev.filter((x) => x !== p.id)
                                : [...prev, p.id],
                            )
                          }
                        />
                        {p.label}
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted">
                        +{p.estimatedLookups}
                      </span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  Extra include: domains
                </label>
                <input
                  type="text"
                  value={spfCustomIncludes}
                  onChange={(e) => setSpfCustomIncludes(e.target.value)}
                  placeholder="spf.example.net"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  Enforcement (`all`)
                </label>
                <select
                  value={spfAllPolicy}
                  onChange={(e) => setSpfAllPolicy(e.target.value as "-all" | "~all" | "?all")}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="-all">-all (Hard Fail — Recommended)</option>
                  <option value="~all">~all (Soft Fail)</option>
                  <option value="?all">?all (Neutral)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  Explicit IPv4 / CIDRs
                </label>
                <input
                  type="text"
                  value={spfIp4}
                  onChange={(e) => setSpfIp4(e.target.value)}
                  placeholder="203.0.113.10 198.51.100.0/24"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  Explicit IPv6 / CIDRs
                </label>
                <input
                  type="text"
                  value={spfIp6}
                  onChange={(e) => setSpfIp6(e.target.value)}
                  placeholder="2001:db8::/48"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <div className="flex flex-wrap gap-4">
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
                <input
                  type="checkbox"
                  checked={spfIncludeMx}
                  onChange={(e) => setSpfIncludeMx(e.target.checked)}
                />
                Authorize domain `mx` hosts (+1 lookup)
              </label>
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
                <input
                  type="checkbox"
                  checked={spfIncludeA}
                  onChange={(e) => setSpfIncludeA(e.target.checked)}
                />
                Authorize apex `a` IP (+1 lookup)
              </label>
            </div>

            <div className="rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                <span>
                  Host: <span className="font-mono text-ink">@</span> · TXT · Est. Lookups:{" "}
                  <span
                    className={`font-mono font-semibold ${
                      (spfBuilt.lookupCount ?? 0) > 10
                        ? "text-rose-600 dark:text-rose-400"
                        : "text-emerald-600 dark:text-emerald-400"
                    }`}
                  >
                    {spfBuilt.lookupCount ?? 0}/10
                  </span>
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void copyText(spfBuilt.value, "SPF record")}
                    className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" /> Value
                  </button>
                  <button
                    type="button"
                    onClick={() => void copyText(spfBuilt.bindLine, "SPF BIND line")}
                    className="inline-flex items-center gap-1 text-ink-secondary hover:underline"
                  >
                    BIND
                  </button>
                </div>
              </div>
              <div className="mt-1.5 break-all font-mono text-xs text-ink">
                {spfBuilt.value}
              </div>
              {spfBuilt.warnings.map((w, i) => (
                <div key={i} className="mt-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                  • {w}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DMARC */}
        {builderType === "dmarc" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Policy (p)</label>
                <select
                  value={dmarcPolicy}
                  onChange={(e) =>
                    setDmarcPolicy(e.target.value as "none" | "quarantine" | "reject")
                  }
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="none">none (Monitor)</option>
                  <option value="quarantine">quarantine</option>
                  <option value="reject">reject (Strict)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Subdomains (sp)</label>
                <select
                  value={dmarcSubPolicy}
                  onChange={(e) =>
                    setDmarcSubPolicy(e.target.value as "" | "none" | "quarantine" | "reject")
                  }
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="">(inherit p=)</option>
                  <option value="none">none</option>
                  <option value="quarantine">quarantine</option>
                  <option value="reject">reject</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Percentage (pct)</label>
                <input
                  type="number"
                  min={0}
                  max={100}
                  value={dmarcPct}
                  onChange={(e) => setDmarcPct(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                <div>
                  <label className="mb-1 block text-[11px] text-ink-muted">DKIM Align</label>
                  <select
                    value={dmarcAdkim}
                    onChange={(e) => setDmarcAdkim(e.target.value as "r" | "s")}
                    className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1.5 font-mono text-xs text-ink"
                  >
                    <option value="r">Relaxed</option>
                    <option value="s">Strict</option>
                  </select>
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-ink-muted">SPF Align</label>
                  <select
                    value={dmarcAspf}
                    onChange={(e) => setDmarcAspf(e.target.value as "r" | "s")}
                    className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1.5 font-mono text-xs text-ink"
                  >
                    <option value="r">Relaxed</option>
                    <option value="s">Strict</option>
                  </select>
                </div>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Aggregate URI (rua)</label>
                <input
                  type="text"
                  value={dmarcRua}
                  onChange={(e) => setDmarcRua(e.target.value)}
                  placeholder="dmarc@example.com"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Forensic URI (ruf)</label>
                <input
                  type="text"
                  value={dmarcRuf}
                  onChange={(e) => setDmarcRuf(e.target.value)}
                  placeholder="Optional email"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <div className="rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                <span>
                  Host: <span className="font-mono text-ink">{dmarcBuilt.host}</span> · TXT
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void copyText(dmarcBuilt.value, "DMARC record")}
                    className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" /> Value
                  </button>
                  <button
                    type="button"
                    onClick={() => void copyText(dmarcBuilt.bindLine, "DMARC BIND line")}
                    className="inline-flex items-center gap-1 text-ink-secondary hover:underline"
                  >
                    BIND
                  </button>
                </div>
              </div>
              <div className="mt-1.5 break-all font-mono text-xs text-ink">
                {dmarcBuilt.value}
              </div>
              {dmarcBuilt.warnings.map((w, i) => (
                <div key={i} className="mt-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                  • {w}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* CAA */}
        {builderType === "caa" && (
          <div className="space-y-3 text-xs">
            <div>
              <div className="mb-1.5 text-[11px] text-ink-muted">
                Authorized Certificate Authorities
              </div>
              <div className="grid grid-cols-2 gap-1.5">
                {CAA_PROVIDERS.map((ca) => {
                  const active = caaSelected.includes(ca.domain);
                  return (
                    <label
                      key={ca.id}
                      className={`flex cursor-pointer items-center justify-between rounded-lg border px-2.5 py-1.5 ${
                        active
                          ? "border-sky-500/40 bg-sky-500/10 text-ink"
                          : "border-line bg-canvas text-ink-secondary"
                      }`}
                    >
                      <span className="flex items-center gap-1.5">
                        <input
                          type="checkbox"
                          checked={active}
                          onChange={() =>
                            setCaaSelected((prev) =>
                              prev.includes(ca.domain)
                                ? prev.filter((x) => x !== ca.domain)
                                : [...prev, ca.domain],
                            )
                          }
                        />
                        {ca.label}
                      </span>
                      <span className="font-mono text-[10px] text-ink-muted">{ca.domain}</span>
                    </label>
                  );
                })}
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              <label className="inline-flex cursor-pointer items-center gap-1.5 text-ink-secondary">
                <input
                  type="checkbox"
                  checked={caaWildcard}
                  onChange={(e) => setCaaWildcard(e.target.checked)}
                />
                Also generate `issuewild` wildcard rules
              </label>
              <input
                type="text"
                value={caaIodef}
                onChange={(e) => setCaaIodef(e.target.value)}
                placeholder="iodef violation email (optional)"
                className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
              />
            </div>

            <div className="space-y-1.5 rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between text-[11px] text-ink-muted">
                <span>Generated CAA Records ({caaBuilt.length})</span>
                {caaBuilt.length > 0 && (
                  <button
                    type="button"
                    onClick={() =>
                      void copyText(caaBuilt.map((r) => r.bindLine).join("\n"), "CAA BIND lines")
                    }
                    className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" /> Copy All BIND
                  </button>
                )}
              </div>
              {caaBuilt.map((rec, i) => (
                <div
                  key={i}
                  className="flex items-center justify-between gap-2 rounded border border-line bg-surface-alt px-2.5 py-1 font-mono text-[11px] text-ink"
                >
                  <span>{rec.bindLine}</span>
                  <button
                    type="button"
                    onClick={() => void copyText(rec.value, "CAA value")}
                    className="text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                  >
                    <Copy className="h-3 w-3" />
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* SRV */}
        {builderType === "srv" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-2.5">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Service</label>
                <input
                  type="text"
                  value={srvService}
                  onChange={(e) => setSrvService(e.target.value)}
                  placeholder="_sip"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Protocol</label>
                <select
                  value={srvProtocol}
                  onChange={(e) => setSrvProtocol(e.target.value as "_tcp" | "_udp" | "_tls")}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="_tcp">_tcp</option>
                  <option value="_tls">_tls</option>
                  <option value="_udp">_udp</option>
                </select>
              </div>
              <div className="grid grid-cols-3 gap-1.5">
                <div>
                  <label className="mb-1 block text-[11px] text-ink-muted">Priority</label>
                  <input
                    type="number"
                    value={srvPriority}
                    onChange={(e) => setSrvPriority(e.target.value)}
                    className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1.5 font-mono text-xs text-ink"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-ink-muted">Weight</label>
                  <input
                    type="number"
                    value={srvWeight}
                    onChange={(e) => setSrvWeight(e.target.value)}
                    className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1.5 font-mono text-xs text-ink"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-[11px] text-ink-muted">Port</label>
                  <input
                    type="number"
                    value={srvPort}
                    onChange={(e) => setSrvPort(e.target.value)}
                    className="w-full rounded-lg border border-line-strong bg-canvas px-2 py-1.5 font-mono text-xs text-ink"
                  />
                </div>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Target Host</label>
                <input
                  type="text"
                  value={srvTarget}
                  onChange={(e) => setSrvTarget(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <div className="rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between text-[11px] text-ink-muted">
                <span className="font-mono text-ink">{srvBuilt.host}</span>
                <button
                  type="button"
                  onClick={() => void copyText(srvBuilt.bindLine, "SRV record")}
                  className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                >
                  <Copy className="h-3 w-3" /> Copy BIND
                </button>
              </div>
              <div className="mt-1.5 break-all font-mono text-xs text-ink">
                {srvBuilt.bindLine}
              </div>
            </div>
          </div>
        )}

        {/* MTA-STS & TLS-RPT */}
        {builderType === "mta-sts" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Policy ID</label>
                <input
                  type="text"
                  value={stsPolicyId}
                  onChange={(e) => setStsPolicyId(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Mode</label>
                <select
                  value={stsMode}
                  onChange={(e) => setStsMode(e.target.value as "testing" | "enforce" | "none")}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="testing">testing (Report only)</option>
                  <option value="enforce">enforce (Require TLS)</option>
                  <option value="none">none (Disable)</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">max_age (seconds)</label>
                <input
                  type="number"
                  value={stsMaxAge}
                  onChange={(e) => setStsMaxAge(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  Authorized MX Patterns (one per line)
                </label>
                <textarea
                  rows={3}
                  value={stsMxPatterns}
                  onChange={(e) => setStsMxPatterns(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas p-2 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">
                  TLS-RPT Report Email / HTTPS URI
                </label>
                <input
                  type="text"
                  value={stsTlsRptEmail}
                  onChange={(e) => setStsTlsRptEmail(e.target.value)}
                  placeholder="tls-reports@example.com"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
                <p className="mt-1.5 text-[10px] text-ink-muted">
                  Generates `_smtp._tls.{builderDomain || "example.com"}` TXT record alongside `_mta-sts`.
                </p>
              </div>
            </div>

            {/* Output: _mta-sts TXT */}
            <div className="space-y-2 rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between text-[11px] text-ink-muted">
                <span>
                  1. MTA-STS DNS: <span className="font-mono text-ink">{mtaStsBuilt.mtaStsDns.host}</span>
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void copyText(mtaStsBuilt.mtaStsDns.value, "MTA-STS value")}
                    className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" /> Value
                  </button>
                  <button
                    type="button"
                    onClick={() => void copyText(mtaStsBuilt.mtaStsDns.bindLine, "MTA-STS BIND")}
                    className="text-ink-secondary hover:underline"
                  >
                    BIND
                  </button>
                </div>
              </div>
              <div className="font-mono text-xs text-ink">{mtaStsBuilt.mtaStsDns.value}</div>

              {mtaStsBuilt.tlsRptDns && (
                <div className="border-t border-line pt-2">
                  <div className="flex items-center justify-between text-[11px] text-ink-muted">
                    <span>
                      2. TLS-RPT DNS:{" "}
                      <span className="font-mono text-ink">{mtaStsBuilt.tlsRptDns.host}</span>
                    </span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() =>
                          void copyText(mtaStsBuilt.tlsRptDns!.value, "TLS-RPT value")
                        }
                        className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                      >
                        <Copy className="h-3 w-3" /> Value
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setLintHint("tls-rpt");
                          setLintInput(mtaStsBuilt.tlsRptDns!.value);
                        }}
                        className="text-ink-secondary hover:underline"
                      >
                        Lint
                      </button>
                    </div>
                  </div>
                  <div className="mt-1 break-all font-mono text-xs text-ink">
                    {mtaStsBuilt.tlsRptDns.value}
                  </div>
                </div>
              )}

              <div className="border-t border-line pt-2">
                <div className="flex items-center justify-between text-[11px] text-ink-muted">
                  <span className="truncate font-mono text-ink" title={mtaStsBuilt.policyFileUrl}>
                    3. Host at {mtaStsBuilt.policyFileUrl}
                  </span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() =>
                        void copyText(mtaStsBuilt.policyFileBody, "mta-sts.txt policy")
                      }
                      className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                    >
                      <Copy className="h-3 w-3" /> Copy
                    </button>
                    <button
                      type="button"
                      onClick={() =>
                        void saveExport("mta-sts.txt", "txt", mtaStsBuilt.policyFileBody).then(
                          (ok) => ok && onNotify("Saved mta-sts.txt"),
                        )
                      }
                      className="inline-flex items-center gap-1 text-ink-secondary hover:underline"
                    >
                      <Download className="h-3 w-3" /> Save
                    </button>
                  </div>
                </div>
                <pre className="mt-1.5 overflow-x-auto rounded border border-line bg-surface p-2 font-mono text-[11px] text-ink">
                  {mtaStsBuilt.policyFileBody}
                </pre>
              </div>

              {mtaStsBuilt.warnings.map((w, i) => (
                <div key={i} className="text-[11px] text-amber-700 dark:text-amber-300">
                  • {w}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* BIMI */}
        {builderType === "bimi" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Selector</label>
                <input
                  type="text"
                  value={bimiSelector}
                  onChange={(e) => setBimiSelector(e.target.value)}
                  placeholder="default"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="mb-1 block text-[11px] text-ink-muted">
                  SVG Tiny P/S Logo URL (l=)
                </label>
                <input
                  type="text"
                  value={bimiLogoUrl}
                  onChange={(e) => setBimiLogoUrl(e.target.value)}
                  placeholder="https://example.com/logo.svg"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div className="sm:col-span-3">
                <label className="mb-1 block text-[11px] text-ink-muted">
                  VMC / CMC Authority Certificate URL (a=)
                </label>
                <input
                  type="text"
                  value={bimiAuthorityUrl}
                  onChange={(e) => setBimiAuthorityUrl(e.target.value)}
                  placeholder="https://example.com/vmc.pem (optional)"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <div className="rounded-lg border border-line bg-canvas p-3">
              <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                <span>
                  Host: <span className="font-mono text-ink">{bimiBuilt.host}</span> · TXT
                </span>
                <div className="flex gap-2">
                  <button
                    type="button"
                    onClick={() => void copyText(bimiBuilt.value, "BIMI value")}
                    className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                  >
                    <Copy className="h-3 w-3" /> Value
                  </button>
                  <button
                    type="button"
                    onClick={() => void copyText(bimiBuilt.bindLine, "BIMI BIND line")}
                    className="text-ink-secondary hover:underline"
                  >
                    BIND
                  </button>
                </div>
              </div>
              <div className="mt-1.5 break-all font-mono text-xs text-ink">{bimiBuilt.value}</div>
              {bimiBuilt.warnings.map((w, i) => (
                <div key={i} className="mt-1.5 text-[11px] text-amber-700 dark:text-amber-300">
                  • {w}
                </div>
              ))}
            </div>
          </div>
        )}

        {/* DKIM Keypair Generator */}
        {builderType === "dkim" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Selector</label>
                <input
                  type="text"
                  value={dkimSelector}
                  onChange={(e) => setDkimSelector(e.target.value)}
                  placeholder="s1"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Algorithm</label>
                <select
                  value={dkimAlg}
                  onChange={(e) => setDkimAlg(e.target.value as "rsa2048" | "ed25519")}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="rsa2048">RSA-2048 (Universal)</option>
                  <option value="ed25519">Ed25519 (RFC 8463)</option>
                </select>
              </div>
              <div className="flex items-end">
                <button
                  type="button"
                  disabled={dkimGenerating}
                  onClick={() => void handleGenerateDkim()}
                  className="inline-flex w-full items-center justify-center gap-1.5 rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
                >
                  {dkimGenerating ? (
                    <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <KeyRound className="h-3.5 w-3.5" />
                  )}
                  {dkimGenerating ? "Generating..." : "Generate Keypair"}
                </button>
              </div>
            </div>

            {dkimError && (
              <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 p-2.5 text-xs text-rose-800 dark:text-rose-200">
                {dkimError}
              </div>
            )}

            {dkimResult && (
              <div className="space-y-3 rounded-lg border border-line bg-canvas p-3">
                <div>
                  <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                    <span>
                      DNS Host: <span className="font-mono text-ink">{dkimResult.host}</span> (
                      {dkimResult.chunks.length} chunk{dkimResult.chunks.length === 1 ? "" : "s"})
                    </span>
                    <div className="flex gap-2">
                      <button
                        type="button"
                        onClick={() => void copyText(dkimResult.txtValue, "DKIM TXT value")}
                        className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                      >
                        <Copy className="h-3 w-3" /> Raw TXT
                      </button>
                      <button
                        type="button"
                        onClick={() => void copyText(dkimResult.bindLine, "DKIM BIND record")}
                        className="text-ink-secondary hover:underline"
                      >
                        BIND
                      </button>
                    </div>
                  </div>
                  <pre className="mt-1.5 max-h-36 overflow-auto whitespace-pre-wrap break-all rounded border border-line bg-surface p-2 font-mono text-[11px] text-ink">
                    {dkimResult.bindLine}
                  </pre>
                </div>

                <div className="border-t border-line pt-2.5">
                  <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                    <span className="font-semibold text-ink">Private Key (PKCS#8 PEM)</span>
                    <div className="flex items-center gap-2">
                      <button
                        type="button"
                        onClick={() => setShowPrivateKey((s) => !s)}
                        className="inline-flex items-center gap-1 text-ink-secondary hover:text-ink"
                      >
                        {showPrivateKey ? (
                          <EyeOff className="h-3 w-3" />
                        ) : (
                          <Eye className="h-3 w-3" />
                        )}
                        {showPrivateKey ? "Hide" : "Reveal"}
                      </button>
                      <button
                        type="button"
                        onClick={() => void copyText(dkimResult.privateKeyPem, "DKIM private key")}
                        className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                      >
                        <Copy className="h-3 w-3" /> Copy PEM
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          void saveExport(
                            `${dkimSelector || "dkim"}.${builderDomain || "domain"}.private.pem`,
                            "pem",
                            dkimResult.privateKeyPem,
                          ).then((ok) => ok && onNotify("Saved DKIM private key PEM"))
                        }
                        className="inline-flex items-center gap-1 text-ink-secondary hover:underline"
                      >
                        <Download className="h-3 w-3" /> Save .pem
                      </button>
                    </div>
                  </div>
                  {showPrivateKey ? (
                    <pre className="mt-1.5 max-h-40 overflow-auto rounded border border-line bg-surface p-2 font-mono text-[10px] text-ink-secondary">
                      {dkimResult.privateKeyPem}
                    </pre>
                  ) : (
                    <div className="mt-1.5 rounded border border-line bg-surface px-2.5 py-2 font-mono text-[11px] text-ink-muted">
                      Private key hidden — click Reveal, Copy PEM, or Save .pem to export.
                    </div>
                  )}
                </div>

                {dkimResult.warnings.map((w, i) => (
                  <div key={i} className="text-[11px] text-amber-700 dark:text-amber-300">
                    • {w}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* DANE / TLSA Generator */}
        {builderType === "tlsa" && (
          <div className="space-y-3 text-xs">
            <div className="grid grid-cols-2 gap-2.5 sm:grid-cols-3">
              <div className="col-span-2 sm:col-span-1">
                <label className="mb-1 block text-[11px] text-ink-muted">Hostname</label>
                <input
                  type="text"
                  value={tlsaHost}
                  onChange={(e) => setTlsaHost(e.target.value)}
                  placeholder="mail.example.com"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Port</label>
                <input
                  type="number"
                  value={tlsaPort}
                  onChange={(e) => setTlsaPort(e.target.value)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Protocol</label>
                <select
                  value={tlsaProtocol}
                  onChange={(e) => setTlsaProtocol(e.target.value as "tcp" | "udp")}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value="tcp">TCP</option>
                  <option value="udp">UDP</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Usage</label>
                <select
                  value={tlsaUsage}
                  onChange={(e) => setTlsaUsage(Number(e.target.value) as 0 | 1 | 2 | 3)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value={3}>3 — DANE-EE (Leaf)</option>
                  <option value={2}>2 — DANE-TA (Trust Anchor)</option>
                  <option value={1}>1 — PKIX-EE</option>
                  <option value={0}>0 — PKIX-TA</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Selector</label>
                <select
                  value={tlsaSelector}
                  onChange={(e) => setTlsaSelector(Number(e.target.value) as 0 | 1)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value={1}>1 — SPKI (Recommended)</option>
                  <option value={0}>0 — Full Certificate</option>
                </select>
              </div>
              <div>
                <label className="mb-1 block text-[11px] text-ink-muted">Matching Type</label>
                <select
                  value={tlsaMatching}
                  onChange={(e) => setTlsaMatching(Number(e.target.value) as 1 | 2)}
                  className="w-full rounded-lg border border-line-strong bg-canvas px-2.5 py-1.5 font-mono text-xs text-ink"
                >
                  <option value={1}>1 — SHA-256</option>
                  <option value={2}>2 — SHA-512</option>
                </select>
              </div>
            </div>

            <div>
              <label className="mb-1 block text-[11px] text-ink-muted">
                PEM Certificate or Public Key
              </label>
              <textarea
                rows={4}
                value={tlsaPem}
                onChange={(e) => setTlsaPem(e.target.value)}
                placeholder={"-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----"}
                className="w-full rounded-lg border border-line-strong bg-canvas p-2.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
              />
            </div>

            <div className="flex justify-end">
              <button
                type="button"
                disabled={tlsaLoading}
                onClick={() => void handleComputeTlsa()}
                className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-1.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950"
              >
                {tlsaLoading && <RefreshCw className="h-3.5 w-3.5 animate-spin" />}
                Generate TLSA Record
              </button>
            </div>

            {tlsaError && (
              <div className="rounded-lg border border-rose-500/35 bg-rose-500/10 p-2.5 text-xs text-rose-800 dark:text-rose-200">
                {tlsaError}
              </div>
            )}

            {tlsaResult && (
              <div className="rounded-lg border border-line bg-canvas p-3 space-y-2">
                <div className="flex items-center justify-between gap-2 text-[11px] text-ink-muted">
                  <span className="font-mono text-ink">{tlsaResult.host}</span>
                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => void copyText(tlsaResult.value, "TLSA value")}
                      className="inline-flex items-center gap-1 text-sky-600 hover:underline dark:text-sky-400"
                    >
                      <Copy className="h-3 w-3" /> Value
                    </button>
                    <button
                      type="button"
                      onClick={() => void copyText(tlsaResult.bindLine, "TLSA BIND line")}
                      className="text-ink-secondary hover:underline"
                    >
                      BIND
                    </button>
                  </div>
                </div>
                <div className="break-all font-mono text-xs text-ink">{tlsaResult.bindLine}</div>
                {tlsaResult.warnings.map((w, i) => (
                  <div key={i} className="text-[11px] text-amber-700 dark:text-amber-300">
                    • {w}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TXT 255-Byte Chunk Splitter */}
        {builderType === "txt-split" && (
          <div className="space-y-3 text-xs">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
                <Scissors className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                UTF-8 byte-aware splitting for DNS TXT records exceeding 255 bytes
              </div>
              <div className="flex items-center gap-1.5 text-[11px]">
                <span className="text-ink-muted">Max bytes/chunk:</span>
                <input
                  type="number"
                  min={16}
                  max={255}
                  value={txtMaxBytes}
                  onChange={(e) => setTxtMaxBytes(e.target.value)}
                  className="w-16 rounded border border-line-strong bg-canvas px-2 py-0.5 font-mono text-xs text-ink"
                />
              </div>
            </div>

            <textarea
              rows={4}
              value={txtSplitInput}
              onChange={(e) => setTxtSplitInput(e.target.value)}
              placeholder="Paste a long DKIM, SPF, or verification TXT string..."
              className="w-full rounded-lg border border-line-strong bg-canvas p-2.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
            />

            <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-line bg-surface-alt px-3 py-2 text-[11px]">
              <span className="text-ink-secondary">
                Total UTF-8 size:{" "}
                <span className="font-mono font-semibold text-ink">
                  {txtSplitResult.totalBytes} bytes
                </span>{" "}
                ·{" "}
                <span className="font-mono font-semibold text-ink">
                  {txtSplitResult.chunks.length} chunk
                  {txtSplitResult.chunks.length === 1 ? "" : "s"}
                </span>{" "}
                ({txtSplitResult.needsSplit ? "Split required" : "Fits in single string"})
              </span>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => void copyText(txtSplitResult.bindQuoted, "BIND TXT chunks")}
                  className="text-sky-600 hover:underline dark:text-sky-400"
                >
                  Copy BIND
                </button>
                <button
                  type="button"
                  onClick={() =>
                    void copyText(txtSplitResult.cloudflareQuoted, "Cloudflare TXT chunks")
                  }
                  className="text-ink-secondary hover:underline"
                >
                  Cloudflare
                </button>
                <button
                  type="button"
                  onClick={() =>
                    void copyText(txtSplitResult.route53Quoted, "Route 53 TXT chunks")
                  }
                  className="text-ink-secondary hover:underline"
                >
                  Route 53
                </button>
              </div>
            </div>

            <div className="space-y-1.5">
              {txtSplitResult.chunks.map((chunk, idx) => (
                <div
                  key={idx}
                  className="rounded-lg border border-line bg-canvas p-2.5 font-mono text-[11px]"
                >
                  <div className="mb-1 flex items-center justify-between text-[10px] text-ink-muted">
                    <span>
                      Chunk #{idx + 1} · {new TextEncoder().encode(chunk).length} bytes
                    </span>
                    <button
                      type="button"
                      onClick={() => void copyText(`"${chunk}"`, `chunk #${idx + 1}`)}
                      className="text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                    >
                      <Copy className="h-3 w-3" />
                    </button>
                  </div>
                  <div className="break-all text-ink">&quot;{chunk}&quot;</div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Offline Syntax Linter Card */}
      <div className="space-y-4 rounded-xl border border-line bg-surface p-4 xl:col-span-5">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
          <div>
            <div className="text-sm font-semibold text-ink">DNS Record Syntax Linter</div>
            <div className="text-[11px] text-ink-muted">
              Validate SPF, DMARC, DKIM, CAA, MTA-STS, TLS-RPT, BIMI, or TLSA offline.
            </div>
          </div>
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-0.5 text-xs font-semibold ${
              lintResult.status === "pass"
                ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                : lintResult.status === "warn"
                  ? "border-amber-500/40 bg-amber-500/15 text-amber-700 dark:text-amber-300"
                  : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
            }`}
          >
            {lintResult.status === "pass" ? (
              <ShieldCheck className="h-3.5 w-3.5" />
            ) : lintResult.status === "warn" ? (
              <AlertTriangle className="h-3.5 w-3.5" />
            ) : (
              <ShieldAlert className="h-3.5 w-3.5" />
            )}
            {lintResult.detectedKind} · {lintResult.status.toUpperCase()}
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-ink-muted">Type:</span>
          <select
            value={lintHint}
            onChange={(e) => setLintHint(e.target.value as LintKindHint)}
            className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1 text-xs text-ink"
          >
            <option value="auto">Auto-detect</option>
            <option value="spf">SPF (TXT)</option>
            <option value="dmarc">DMARC (TXT)</option>
            <option value="dkim">DKIM (TXT)</option>
            <option value="caa">CAA</option>
            <option value="mta-sts">MTA-STS (TXT)</option>
            <option value="tls-rpt">TLS-RPT (TXT)</option>
            <option value="bimi">BIMI (TXT)</option>
            <option value="tlsa">DANE / TLSA</option>
          </select>
          <button
            type="button"
            onClick={loadFromGenerator}
            className="ml-auto rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:border-sky-500/40 hover:text-ink"
          >
            Load from Generator
          </button>
        </div>

        <textarea
          rows={5}
          value={lintInput}
          onChange={(e) => setLintInput(e.target.value)}
          placeholder='Paste e.g. "v=spf1 include:_spf.google.com -all", "v=STSv1; id=20260101", or "3 1 1 <64-hex-sha256>"'
          className="w-full rounded-lg border border-line-strong bg-canvas p-3 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
        />

        <div className="space-y-2">
          {lintResult.checks.map((c, idx) => (
            <div
              key={idx}
              className={`flex items-start gap-2 rounded-lg border p-2.5 text-xs ${
                c.level === "pass"
                  ? "border-emerald-500/25 bg-emerald-500/[0.06] text-emerald-800 dark:text-emerald-200"
                  : c.level === "warn"
                    ? "border-amber-500/30 bg-amber-500/[0.07] text-amber-800 dark:text-amber-200"
                    : "border-rose-500/35 bg-rose-500/[0.08] text-rose-800 dark:text-rose-200"
              }`}
            >
              {c.level === "pass" ? (
                <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-emerald-600 dark:text-emerald-400" />
              ) : c.level === "warn" ? (
                <AlertTriangle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-amber-600 dark:text-amber-400" />
              ) : (
                <XCircle className="mt-0.5 h-3.5 w-3.5 shrink-0 text-rose-600 dark:text-rose-400" />
              )}
              <span>{c.message}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
