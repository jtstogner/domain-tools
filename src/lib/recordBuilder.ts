export interface SpfProviderPreset {
  id: string;
  label: string;
  include: string;
  estimatedLookups: number;
}

export const SPF_PROVIDERS: SpfProviderPreset[] = [
  { id: "google", label: "Google Workspace", include: "_spf.google.com", estimatedLookups: 3 },
  { id: "m365", label: "Microsoft 365", include: "spf.protection.outlook.com", estimatedLookups: 2 },
  { id: "cloudflare", label: "Cloudflare Email", include: "_spf.mx.cloudflare.net", estimatedLookups: 2 },
  { id: "ses", label: "Amazon SES", include: "amazonses.com", estimatedLookups: 1 },
  { id: "sendgrid", label: "SendGrid", include: "sendgrid.net", estimatedLookups: 1 },
  { id: "mailgun", label: "Mailgun", include: "mailgun.org", estimatedLookups: 2 },
  { id: "postmark", label: "Postmark", include: "spf.mtasv.net", estimatedLookups: 1 },
  { id: "zoho", label: "Zoho Mail", include: "zoho.com", estimatedLookups: 1 },
  { id: "fastmail", label: "Fastmail", include: "spf.messagingengine.com", estimatedLookups: 1 },
  { id: "zendesk", label: "Zendesk", include: "mail.zendesk.com", estimatedLookups: 2 },
];

export interface CaaProviderPreset {
  id: string;
  label: string;
  domain: string;
}

export const CAA_PROVIDERS: CaaProviderPreset[] = [
  { id: "letsencrypt", label: "Let's Encrypt", domain: "letsencrypt.org" },
  { id: "digicert", label: "DigiCert", domain: "digicert.com" },
  { id: "sectigo", label: "Sectigo", domain: "sectigo.com" },
  { id: "google", label: "Google Trust Services", domain: "pki.goog" },
  { id: "amazon", label: "Amazon Trust", domain: "amazon.com" },
  { id: "zerossl", label: "ZeroSSL", domain: "zerossl.com" },
  { id: "sslcom", label: "SSL.com", domain: "ssl.com" },
];

export interface BuiltDnsRecord {
  host: string;
  type: "TXT" | "CAA" | "SRV";
  value: string;
  bindLine: string;
  warnings: string[];
  lookupCount?: number;
}

export function buildSpfRecord(opts: {
  domain: string;
  providerIds: string[];
  customIncludes: string[];
  ip4List: string[];
  ip6List: string[];
  includeA: boolean;
  includeMx: boolean;
  allPolicy: "-all" | "~all" | "?all";
}): BuiltDnsRecord {
  const cleanDomain = (opts.domain || "example.com").trim();
  const tokens: string[] = ["v=spf1"];
  let lookupCount = 0;
  const warnings: string[] = [];

  if (opts.includeA) {
    tokens.push("a");
    lookupCount += 1;
  }
  if (opts.includeMx) {
    tokens.push("mx");
    lookupCount += 1;
  }

  for (const id of opts.providerIds) {
    const found = SPF_PROVIDERS.find((p) => p.id === id);
    if (found) {
      tokens.push(`include:${found.include}`);
      lookupCount += found.estimatedLookups;
    }
  }

  for (const raw of opts.customIncludes) {
    const clean = raw.trim().replace(/^include:/i, "").replace(/\.$/, "");
    if (clean) {
      tokens.push(`include:${clean}`);
      lookupCount += 1;
    }
  }

  for (const raw of opts.ip4List) {
    const clean = raw.trim().replace(/^ip4:/i, "");
    if (clean) tokens.push(`ip4:${clean}`);
  }

  for (const raw of opts.ip6List) {
    const clean = raw.trim().replace(/^ip6:/i, "");
    if (clean) tokens.push(`ip6:${clean}`);
  }

  tokens.push(opts.allPolicy);
  const value = tokens.join(" ");

  if (lookupCount > 10) {
    warnings.push(
      `Estimated recursive lookups (${lookupCount}/10) exceed RFC 7208's 10-lookup limit — consider flattening or removing unused providers.`,
    );
  }
  if (value.length > 255) {
    warnings.push(
      `SPF string is ${value.length} chars (>255); many DNS hosts require splitting into multiple quoted TXT strings.`,
    );
  }
  if (opts.allPolicy === "?all") {
    warnings.push("?all (neutral) gives no spoof protection; prefer -all or ~all.");
  }

  return {
    host: `${cleanDomain}.`,
    type: "TXT",
    value,
    bindLine: `@ 3600 IN TXT "${value}"`,
    warnings,
    lookupCount,
  };
}

export function buildDmarcRecord(opts: {
  domain: string;
  policy: "none" | "quarantine" | "reject";
  subdomainPolicy: "" | "none" | "quarantine" | "reject";
  pct: number;
  adkim: "r" | "s";
  aspf: "r" | "s";
  ruaEmail: string;
  rufEmail: string;
  fo: string;
}): BuiltDnsRecord {
  const cleanDomain = (opts.domain || "example.com").trim();
  const parts: string[] = ["v=DMARC1", `p=${opts.policy}`];
  const warnings: string[] = [];

  if (opts.subdomainPolicy) {
    parts.push(`sp=${opts.subdomainPolicy}`);
  }
  if (opts.pct < 100 && opts.pct >= 0) {
    parts.push(`pct=${Math.round(opts.pct)}`);
  }
  if (opts.adkim !== "r") parts.push(`adkim=${opts.adkim}`);
  if (opts.aspf !== "r") parts.push(`aspf=${opts.aspf}`);

  const ruaClean = opts.ruaEmail
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => (s.toLowerCase().startsWith("mailto:") ? s : `mailto:${s}`));
  if (ruaClean.length > 0) {
    parts.push(`rua=${ruaClean.join(",")}`);
  } else {
    warnings.push("Consider adding a rua= aggregate report email address to monitor DMARC alignment.");
  }

  const rufClean = opts.rufEmail
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => (s.toLowerCase().startsWith("mailto:") ? s : `mailto:${s}`));
  if (rufClean.length > 0) {
    parts.push(`ruf=${rufClean.join(",")}`);
  }

  if (opts.fo && opts.fo !== "0") {
    parts.push(`fo=${opts.fo}`);
  }

  if (opts.policy === "none") {
    warnings.push("p=none monitors without blocking spoofed mail; move to p=quarantine or p=reject after verifying alignment.");
  }

  const value = parts.join("; ");
  return {
    host: `_dmarc.${cleanDomain}`,
    type: "TXT",
    value,
    bindLine: `_dmarc 3600 IN TXT "${value}"`,
    warnings,
  };
}

export function buildCaaRecords(opts: {
  domain: string;
  caDomains: string[];
  allowWildcard: boolean;
  iodefEmail: string;
}): BuiltDnsRecord[] {
  const cleanDomain = (opts.domain || "example.com").trim();
  const out: BuiltDnsRecord[] = [];
  const tag = opts.allowWildcard ? "issuewild" : "issue";

  for (const ca of opts.caDomains) {
    const cleanCa = ca.trim().toLowerCase();
    if (!cleanCa) continue;
    if (opts.allowWildcard) {
      out.push({
        host: cleanDomain,
        type: "CAA",
        value: `0 issue "${cleanCa}"`,
        bindLine: `@ 3600 IN CAA 0 issue "${cleanCa}"`,
        warnings: [],
      });
    }
    out.push({
      host: cleanDomain,
      type: "CAA",
      value: `0 ${tag} "${cleanCa}"`,
      bindLine: `@ 3600 IN CAA 0 ${tag} "${cleanCa}"`,
      warnings: [],
    });
  }

  const email = opts.iodefEmail.trim();
  if (email) {
    const uri = email.toLowerCase().startsWith("mailto:") ? email : `mailto:${email}`;
    out.push({
      host: cleanDomain,
      type: "CAA",
      value: `0 iodef "${uri}"`,
      bindLine: `@ 3600 IN CAA 0 iodef "${uri}"`,
      warnings: [],
    });
  }

  return out;
}

export function buildSrvRecord(opts: {
  domain: string;
  service: string;
  protocol: "_tcp" | "_udp" | "_tls";
  priority: number;
  weight: number;
  port: number;
  target: string;
}): BuiltDnsRecord {
  const cleanDomain = (opts.domain || "example.com").trim();
  const svc = opts.service.trim().startsWith("_")
    ? opts.service.trim()
    : `_${opts.service.trim()}`;
  const target = (opts.target || `sip.${cleanDomain}`).trim().replace(/\.$/, "");
  const host = `${svc}.${opts.protocol}.${cleanDomain}`;
  const value = `${opts.priority} ${opts.weight} ${opts.port} ${target}.`;
  const warnings: string[] = [];
  if (opts.port < 1 || opts.port > 65535) {
    warnings.push("SRV port must be between 1 and 65535.");
  }

  return {
    host,
    type: "SRV",
    value,
    bindLine: `${svc}.${opts.protocol} 3600 IN SRV ${value}`,
    warnings,
  };
}

export interface LintFinding {
  level: "pass" | "warn" | "fail";
  message: string;
}

export interface LintReport {
  detectedKind: "SPF" | "DMARC" | "DKIM" | "CAA" | "Unknown";
  status: "pass" | "warn" | "fail";
  checks: LintFinding[];
}

export function lintDnsRecord(
  kindHint: "auto" | "spf" | "dmarc" | "dkim" | "caa",
  rawInput: string,
): LintReport {
  const trimmed = rawInput.trim().replace(/^"(.*)"$/, "$1");
  if (!trimmed) {
    return {
      detectedKind: "Unknown",
      status: "warn",
      checks: [{ level: "warn", message: "Paste a record value above to run syntax checks." }],
    };
  }

  const lower = trimmed.toLowerCase();
  let detected: LintReport["detectedKind"] = "Unknown";
  if (kindHint !== "auto") {
    detected = kindHint.toUpperCase() as LintReport["detectedKind"];
  } else if (lower.startsWith("v=spf1")) {
    detected = "SPF";
  } else if (lower.startsWith("v=dmarc1")) {
    detected = "DMARC";
  } else if (lower.startsWith("v=dkim1") || lower.includes("; p=")) {
    detected = "DKIM";
  } else if (/^\d+\s+(issue|issuewild|iodef)\s+/i.test(trimmed)) {
    detected = "CAA";
  }

  const checks: LintFinding[] = [];

  if (detected === "SPF") {
    const tokens = trimmed.split(/\s+/);
    if (tokens[0]?.toLowerCase() !== "v=spf1") {
      checks.push({ level: "fail", message: "SPF record must begin with exact token 'v=spf1'." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=spf1' version prefix." });
    }

    let lookups = 0;
    const seenIncludes = new Set<string>();
    const dupIncludes: string[] = [];
    for (const tok of tokens.slice(1)) {
      const stripped = tok.toLowerCase().replace(/^[+\-~?]/, "");
      if (
        stripped.startsWith("include:") ||
        stripped === "a" ||
        stripped.startsWith("a:") ||
        stripped.startsWith("a/") ||
        stripped === "mx" ||
        stripped.startsWith("mx:") ||
        stripped.startsWith("mx/") ||
        stripped.startsWith("exists:") ||
        stripped.startsWith("redirect=")
      ) {
        lookups += 1;
      }
      if (stripped.startsWith("include:")) {
        const inc = stripped.slice("include:".length);
        if (seenIncludes.has(inc)) dupIncludes.push(inc);
        seenIncludes.add(inc);
      }
      if (stripped === "ptr" || stripped.startsWith("ptr:")) {
        lookups += 1;
        checks.push({
          level: "warn",
          message: "'ptr' mechanism is deprecated by RFC 7208 (slow and unreliable).",
        });
      }
    }

    if (lookups > 10) {
      checks.push({
        level: "fail",
        message: `Direct DNS-lookup mechanisms = ${lookups} (> 10 RFC 7208 limit — causes PermError!).`,
      });
    } else {
      checks.push({
        level: "pass",
        message: `Direct DNS lookups: ${lookups}/10 (remember nested includes also count toward the 10-lookup budget).`,
      });
    }

    if (dupIncludes.length > 0) {
      checks.push({
        level: "warn",
        message: `Duplicate include mechanism(s): ${dupIncludes.join(", ")}.`,
      });
    }

    const lastToken = tokens[tokens.length - 1]?.toLowerCase() ?? "";
    if (lastToken === "+all" || lastToken === "all") {
      checks.push({ level: "fail", message: "Dangerous '+all' mechanism authorizes ANY IP on the internet to spoof this domain." });
    } else if (lastToken === "-all" || lastToken === "~all") {
      checks.push({ level: "pass", message: `Terminates cleanly with '${lastToken}'.` });
    } else if (!lower.includes("redirect=")) {
      checks.push({ level: "warn", message: "Missing trailing '-all' or '~all' fallback qualifier." });
    }

    if (trimmed.length > 255) {
      checks.push({
        level: "warn",
        message: `Length is ${trimmed.length} chars (>255); ensure TXT value is split into quoted <=255-byte chunks in DNS.`,
      });
    }
  } else if (detected === "DMARC") {
    const tags = trimmed
      .split(";")
      .map((s) => s.trim())
      .filter(Boolean);
    const map = new Map<string, string>();
    for (const tag of tags) {
      const idx = tag.indexOf("=");
      if (idx === -1) {
        checks.push({ level: "fail", message: `Malformed DMARC tag without '=': '${tag}'.` });
      } else {
        map.set(tag.slice(0, idx).trim().toLowerCase(), tag.slice(idx + 1).trim());
      }
    }

    if (map.get("v")?.toUpperCase() !== "DMARC1") {
      checks.push({ level: "fail", message: "DMARC record must start with 'v=DMARC1'." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=DMARC1' tag." });
    }

    const policy = map.get("p")?.toLowerCase();
    if (!policy || !["none", "quarantine", "reject"].includes(policy)) {
      checks.push({ level: "fail", message: "Missing or invalid required 'p=' policy (must be none, quarantine, or reject)." });
    } else if (policy === "none") {
      checks.push({ level: "warn", message: "'p=none' is monitoring-only and does not block spoofing." });
    } else {
      checks.push({ level: "pass", message: `Enforcement policy active: p=${policy}.` });
    }

    const pct = map.get("pct");
    if (pct !== undefined) {
      const n = Number(pct);
      if (!Number.isInteger(n) || n < 0 || n > 100) {
        checks.push({ level: "fail", message: `Invalid 'pct=${pct}' (must be 0–100).` });
      } else if (n < 100) {
        checks.push({ level: "warn", message: `Partial rollout 'pct=${n}%' — raise to 100 when ready.` });
      }
    }

    const rua = map.get("rua");
    if (!rua) {
      checks.push({ level: "warn", message: "No 'rua=' aggregate report URI specified." });
    } else if (!rua.toLowerCase().includes("mailto:")) {
      checks.push({ level: "fail", message: "'rua=' URIs must include the 'mailto:' scheme." });
    } else {
      checks.push({ level: "pass", message: `Aggregate reports configured: ${rua}` });
    }
  } else if (detected === "DKIM") {
    const pMatch = trimmed.match(/(?:^|;)\s*p=([^;\s]*)/i);
    if (!pMatch) {
      checks.push({ level: "fail", message: "Missing 'p=' base64 public key tag." });
    } else if (!pMatch[1]) {
      checks.push({ level: "warn", message: "Empty 'p=' value indicates a revoked DKIM selector key." });
    } else if (pMatch[1].length < 160 && !lower.includes("k=ed25519")) {
      checks.push({ level: "warn", message: "RSA DKIM public key looks short (prefer >= 2048-bit key for modern deliverability)." });
    } else {
      checks.push({ level: "pass", message: "DKIM public key ('p=') is present." });
    }
  } else if (detected === "CAA") {
    const match = trimmed.match(/^(\d+)\s+(issue|issuewild|iodef)\s+"?([^"]+)"?$/i);
    if (!match) {
      checks.push({ level: "fail", message: "Expected CAA syntax: <flags> <issue|issuewild|iodef> \"<value>\"." });
    } else {
      const flags = Number(match[1]);
      if (flags !== 0 && flags !== 128) {
        checks.push({ level: "warn", message: `Unusual CAA flag '${flags}' (standard is 0 or 128).` });
      } else {
        checks.push({ level: "pass", message: `Valid CAA ${match[2].toLowerCase()} directive for "${match[3]}".` });
      }
    }
  } else {
    checks.push({
      level: "warn",
      message: "Could not auto-detect record type (select SPF, DMARC, DKIM, or CAA explicitly).",
    });
  }

  const hasFail = checks.some((c) => c.level === "fail");
  const hasWarn = checks.some((c) => c.level === "warn");

  return {
    detectedKind: detected,
    status: hasFail ? "fail" : hasWarn ? "warn" : "pass",
    checks,
  };
}
