import {
  AlertTriangle,
  ArrowRight,
  Calculator,
  CheckCircle2,
  Copy,
  FileCode2,
  Globe2,
  Languages,
  ShieldAlert,
  ShieldCheck,
  Wrench,
  XCircle,
} from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard } from "../lib/api";
import { calculateCidr, cidrToSpfToken, ipToReversePtr, isIpInCidr } from "../lib/cidr";
import { inspectDomainScripts, toAsciiDomain, toUnicodeDomain } from "../lib/punycode";
import {
  buildCaaRecords,
  buildDmarcRecord,
  buildSpfRecord,
  buildSrvRecord,
  CAA_PROVIDERS,
  lintDnsRecord,
  SPF_PROVIDERS,
} from "../lib/recordBuilder";

interface UtilitiesPanelProps {
  defaultDomain: string;
  onInspectDomain: (domain: string) => void;
  onNotify: (msg: string) => void;
}

type UtilSubTab = "builder" | "punycode" | "cidr";
type BuilderType = "spf" | "dmarc" | "caa" | "srv";

export function UtilitiesPanel({
  defaultDomain,
  onInspectDomain,
  onNotify,
}: UtilitiesPanelProps) {
  const [subTab, setSubTab] = useState<UtilSubTab>("builder");

  // --- Record Builder & Linter State ---
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

  // Linter state
  const [lintHint, setLintHint] = useState<"auto" | "spf" | "dmarc" | "dkim" | "caa">("auto");
  const [lintInput, setLintInput] = useState("v=spf1 include:_spf.google.com ~all");

  // --- Punycode / IDN State ---
  const [idnInput, setIdnInput] = useState("münchen.de");

  // --- CIDR & Reverse PTR State ---
  const [cidrInput, setCidrInput] = useState("192.0.2.0/24");
  const [testIpInput, setTestIpInput] = useState("192.0.2.44");

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

  const lintResult = useMemo(() => lintDnsRecord(lintHint, lintInput), [lintHint, lintInput]);

  // Punycode computations
  const trimmedIdn = idnInput.trim();
  const isPunyInput = trimmedIdn.toLowerCase().includes("xn--");
  const asciiConv = useMemo(() => toAsciiDomain(trimmedIdn), [trimmedIdn]);
  const unicodeConv = useMemo(
    () => toUnicodeDomain(isPunyInput ? trimmedIdn : asciiConv.ascii),
    [trimmedIdn, isPunyInput, asciiConv.ascii],
  );
  const scriptAudit = useMemo(
    () => inspectDomainScripts(unicodeConv.unicode || trimmedIdn),
    [unicodeConv.unicode, trimmedIdn],
  );

  // CIDR computations
  const cidrResult = useMemo(() => calculateCidr(cidrInput), [cidrInput]);
  const ipMatch = useMemo(() => {
    if (!testIpInput.trim()) return null;
    return isIpInCidr(cidrInput, testIpInput);
  }, [cidrInput, testIpInput]);
  const reversePtr = useMemo(
    () => ipToReversePtr(testIpInput.trim() || cidrInput),
    [testIpInput, cidrInput],
  );
  const spfCidrToken = useMemo(() => cidrToSpfToken(cidrInput), [cidrInput]);

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  return (
    <div className="space-y-4">
      {/* Header & Sub-tab Switcher */}
      <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line bg-surface p-4">
        <div className="flex items-center gap-2.5">
          <Wrench className="h-4 w-4 text-sky-600 dark:text-sky-400" />
          <div>
            <h2 className="text-sm font-semibold text-ink">Domain &amp; DNS Utilities</h2>
            <p className="text-xs text-ink-muted">
              Build &amp; lint DNS records, convert IDN Punycode / inspect homoglyphs, and calculate CIDRs &amp; PTR zones.
            </p>
          </div>
        </div>

        <div className="inline-flex items-center rounded-lg border border-line bg-surface-alt p-0.5">
          {(
            [
              ["builder", "Record Builder & Linter", FileCode2],
              ["punycode", "IDN / Punycode", Languages],
              ["cidr", "CIDR & Reverse PTR", Calculator],
            ] as const
          ).map(([id, label, Icon]) => {
            const active = subTab === id;
            return (
              <button
                key={id}
                type="button"
                onClick={() => setSubTab(id)}
                className={`inline-flex items-center gap-1.5 rounded-md px-3 py-1.5 text-xs font-medium transition ${
                  active
                    ? "bg-surface text-ink shadow-sm ring-1 ring-line"
                    : "text-ink-muted hover:text-ink"
                }`}
              >
                <Icon className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
                {label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Tab 1: Record Builder & Linter */}
      {subTab === "builder" && (
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
          {/* Builder Card */}
          <div className="space-y-4 rounded-xl border border-line bg-surface p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
              <div className="text-sm font-semibold text-ink">DNS Record Generator</div>
              <div className="inline-flex rounded-lg border border-line bg-surface-alt p-0.5 text-xs">
                {(["spf", "dmarc", "caa", "srv"] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => setBuilderType(t)}
                    className={`rounded-md px-2.5 py-1 font-mono uppercase transition ${
                      builderType === t
                        ? "bg-surface font-semibold text-ink shadow-sm"
                        : "text-ink-muted hover:text-ink"
                    }`}
                  >
                    {t}
                  </button>
                ))}
              </div>
            </div>

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

            {builderType === "spf" && (
              <div className="space-y-3 text-xs">
                <div>
                  <div className="mb-1.5 text-[11px] font-medium text-ink-muted">
                    Authorized Mail Providers (checks toggle)
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

            {builderType === "dmarc" && (
              <div className="space-y-3 text-xs">
                <div className="grid grid-cols-2 gap-2.5">
                  <div>
                    <label className="mb-1 block text-[11px] text-ink-muted">Policy (p)</label>
                    <select
                      value={dmarcPolicy}
                      onChange={(e) => setDmarcPolicy(e.target.value as "none" | "quarantine" | "reject")}
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
                      onChange={(e) => setDmarcSubPolicy(e.target.value as "" | "none" | "quarantine" | "reject")}
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
          </div>

          {/* Offline Syntax Linter Card */}
          <div className="space-y-4 rounded-xl border border-line bg-surface p-4">
            <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-3">
              <div>
                <div className="text-sm font-semibold text-ink">DNS Record Syntax Linter</div>
                <div className="text-[11px] text-ink-muted">
                  Test draft SPF, DMARC, DKIM, or CAA records offline before publishing.
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

            <div className="flex items-center gap-2">
              <span className="text-xs text-ink-muted">Record Type:</span>
              <select
                value={lintHint}
                onChange={(e) =>
                  setLintHint(e.target.value as "auto" | "spf" | "dmarc" | "dkim" | "caa")
                }
                className="rounded-lg border border-line-strong bg-canvas px-2.5 py-1 text-xs text-ink"
              >
                <option value="auto">Auto-detect</option>
                <option value="spf">SPF (TXT)</option>
                <option value="dmarc">DMARC (TXT)</option>
                <option value="dkim">DKIM (TXT)</option>
                <option value="caa">CAA</option>
              </select>
              <button
                type="button"
                onClick={() =>
                  setLintInput(
                    builderType === "spf"
                      ? spfBuilt.value
                      : builderType === "dmarc"
                        ? dmarcBuilt.value
                        : caaBuilt[0]?.value ?? lintInput,
                  )
                }
                className="ml-auto rounded-lg border border-line bg-surface-alt px-2.5 py-1 text-[11px] font-medium text-ink-secondary hover:text-ink"
              >
                Load from Generator
              </button>
            </div>

            <textarea
              rows={4}
              value={lintInput}
              onChange={(e) => setLintInput(e.target.value)}
              placeholder='Paste e.g. "v=spf1 include:_spf.google.com -all" or "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
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
      )}

      {/* Tab 2: IDN / Punycode & Homoglyph Inspector */}
      {subTab === "punycode" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
            <div className="flex flex-wrap items-end gap-3">
              <div className="min-w-[240px] flex-1">
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Enter Unicode IDN Domain or Punycode (`xn--...`)
                </label>
                <input
                  type="text"
                  value={idnInput}
                  onChange={(e) => setIdnInput(e.target.value)}
                  placeholder="münchen.de or xn--mnchen-3ya.de"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                />
              </div>

              {asciiConv.ascii && (
                <button
                  type="button"
                  onClick={() => onInspectDomain(asciiConv.ascii)}
                  className="inline-flex items-center gap-1.5 rounded-lg bg-sky-600 px-3.5 py-2 text-xs font-semibold text-white hover:bg-sky-500 dark:bg-sky-500 dark:text-slate-950"
                >
                  <Globe2 className="h-3.5 w-3.5" />
                  Inspect in Domain Inspector
                </button>
              )}
            </div>

            <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
              <span className="text-ink-muted">Examples:</span>
              {[
                ["münchen.de", "German umlaut IDN"],
                ["аррӏе.com", "Cyrillic homoglyph spoof of apple.com"],
                ["xn--bcher-kva.example", "Punycode decode test"],
              ].map(([sample, title]) => (
                <button
                  key={sample}
                  type="button"
                  title={title}
                  onClick={() => setIdnInput(sample)}
                  className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-ink-secondary hover:border-sky-500/40 hover:text-ink"
                >
                  {sample}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
            <div className="rounded-xl border border-line bg-surface p-4">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-ink">DNS ASCII (Punycode A-Label)</span>
                <button
                  type="button"
                  onClick={() => void copyText(asciiConv.ascii, "Punycode domain")}
                  className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                >
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>
              <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-3 font-mono text-sm font-semibold text-sky-700 dark:text-sky-300">
                {asciiConv.ascii || "—"}
              </div>
              {asciiConv.error && (
                <div className="mt-1 text-xs text-rose-600 dark:text-rose-400">{asciiConv.error}</div>
              )}
            </div>

            <div className="rounded-xl border border-line bg-surface p-4">
              <div className="flex items-center justify-between text-xs">
                <span className="font-semibold text-ink">Unicode Display (U-Label)</span>
                <button
                  type="button"
                  onClick={() => void copyText(unicodeConv.unicode, "Unicode domain")}
                  className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                >
                  <Copy className="h-3 w-3" /> Copy
                </button>
              </div>
              <div className="mt-2 break-all rounded-lg border border-line bg-canvas p-3 font-mono text-sm font-semibold text-ink">
                {unicodeConv.unicode || "—"}
              </div>
              {unicodeConv.error && (
                <div className="mt-1 text-xs text-rose-600 dark:text-rose-400">{unicodeConv.error}</div>
              )}
            </div>
          </div>

          <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="text-sm font-semibold text-ink">
                Script &amp; Homoglyph Spoof Analysis
              </div>
              <div className="flex items-center gap-2 text-xs">
                <span className="text-ink-muted">
                  Scripts: {scriptAudit.scripts.join(", ") || "None"}
                </span>
                {scriptAudit.mixedScript || scriptAudit.confusables.some((c) => c.lookalikeLatin) ? (
                  <span className="inline-flex items-center gap-1 rounded-full border border-rose-500/40 bg-rose-500/15 px-2.5 py-0.5 font-semibold text-rose-700 dark:text-rose-300">
                    <ShieldAlert className="h-3.5 w-3.5" />
                    Homoglyph / Spoof Risk
                  </span>
                ) : (
                  <span className="inline-flex items-center gap-1 rounded-full border border-emerald-500/40 bg-emerald-500/15 px-2.5 py-0.5 font-semibold text-emerald-700 dark:text-emerald-300">
                    <ShieldCheck className="h-3.5 w-3.5" />
                    Clean Single-Script Label
                  </span>
                )}
              </div>
            </div>

            {scriptAudit.confusables.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs">
                  <thead className="border-b border-line bg-surface-alt text-[11px] uppercase tracking-wider text-ink-muted">
                    <tr>
                      <th className="px-3 py-2">Character</th>
                      <th className="px-3 py-2">Unicode Code Point</th>
                      <th className="px-3 py-2">Script</th>
                      <th className="px-3 py-2">Visual Spoof Target</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line font-mono">
                    {scriptAudit.confusables.map((c, idx) => (
                      <tr key={idx}>
                        <td className="px-3 py-2 text-sm font-bold text-ink">{c.char}</td>
                        <td className="px-3 py-2 text-ink-secondary">{c.codePoint}</td>
                        <td className="px-3 py-2 text-ink-secondary">{c.script}</td>
                        <td className="px-3 py-2">
                          {c.lookalikeLatin ? (
                            <span className="inline-flex items-center gap-1 text-rose-700 dark:text-rose-300">
                              Imitates ASCII <ArrowRight className="h-3 w-3" /> &apos;{c.lookalikeLatin}&apos;
                            </span>
                          ) : (
                            <span className="text-ink-muted">Non-ASCII IDN character</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-xs text-ink-muted">
                No non-ASCII characters found — standard ASCII hostname.
              </p>
            )}
          </div>
        </div>
      )}

      {/* Tab 3: Standalone CIDR & Reverse PTR Calculator */}
      {subTab === "cidr" && (
        <div className="space-y-4">
          <div className="rounded-xl border border-line bg-surface p-4">
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <div>
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  IPv4 or IPv6 CIDR Block
                </label>
                <input
                  type="text"
                  value={cidrInput}
                  onChange={(e) => setCidrInput(e.target.value)}
                  placeholder="e.g. 192.0.2.0/24 or 2001:db8::/48"
                  className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-[11px] font-medium text-ink-muted">
                  Single IP for Reverse PTR &amp; Membership Test
                </label>
                <div className="flex items-center gap-2">
                  <input
                    type="text"
                    value={testIpInput}
                    onChange={(e) => setTestIpInput(e.target.value)}
                    placeholder="e.g. 192.0.2.44"
                    className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
                  />
                  {ipMatch !== null && (
                    <span
                      className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold ${
                        ipMatch
                          ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                          : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                      }`}
                    >
                      {ipMatch ? "In Subnet" : "Outside"}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>

          {"error" in cidrResult ? (
            <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
              {cidrResult.error}
            </div>
          ) : (
            <>
              <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                {[
                  ["Network Address", `${cidrResult.networkAddress}/${cidrResult.prefix}`],
                  [cidrResult.version === 4 ? "Broadcast Address" : "Last Address", cidrResult.broadcastOrLastAddress],
                  ["Usable Range", `${cidrResult.firstUsable} – ${cidrResult.lastUsable}`],
                  ["Usable Hosts", `${cidrResult.usableHosts} (${cidrResult.totalAddresses} total)`],
                  ["Netmask", cidrResult.netmask],
                  ["Wildcard Mask", cidrResult.wildcardMask ?? "N/A (IPv6)"],
                  ["Address Scope", cidrResult.scope],
                  ["IP Version", `IPv${cidrResult.version}`],
                ].map(([label, val]) => (
                  <div key={label} className="rounded-xl border border-line bg-surface p-3.5">
                    <div className="text-[11px] text-ink-muted">{label}</div>
                    <div className="mt-1 break-all font-mono text-xs font-semibold text-ink">
                      {val}
                    </div>
                  </div>
                ))}
              </div>

              {(reversePtr || spfCidrToken) && (
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  {reversePtr && (
                    <div className="rounded-xl border border-line bg-surface p-4 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-ink">Reverse DNS (PTR Name)</span>
                        <button
                          type="button"
                          onClick={() => void copyText(reversePtr.ptrName, "Reverse PTR name")}
                          className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          <Copy className="h-3 w-3" /> Copy
                        </button>
                      </div>
                      <div className="mt-1.5 break-all rounded border border-line bg-canvas p-2.5 font-mono text-xs text-ink">
                        {reversePtr.ptrName}
                      </div>
                      <div className="mt-1.5 text-[11px] text-ink-muted">
                        Zones: <span className="font-mono">{reversePtr.delegatedZone}</span>
                        {reversePtr.secondaryZone ? ` · ${reversePtr.secondaryZone}` : ""}
                      </div>
                    </div>
                  )}
                  {spfCidrToken && (
                    <div className="rounded-xl border border-line bg-surface p-4 text-xs">
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-ink">SPF Notation Token</span>
                        <button
                          type="button"
                          onClick={() => void copyText(spfCidrToken, "SPF token")}
                          className="inline-flex items-center gap-1 text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                        >
                          <Copy className="h-3 w-3" /> Copy
                        </button>
                      </div>
                      <div className="mt-1.5 break-all rounded border border-line bg-canvas p-2.5 font-mono text-xs text-sky-700 dark:text-sky-300">
                        {spfCidrToken}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  );
}
