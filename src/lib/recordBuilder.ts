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
  type: "TXT" | "CAA" | "SRV" | "TLSA";
  value: string;
  bindLine: string;
  warnings: string[];
  lookupCount?: number;
}

export interface TxtSplitResult {
  chunks: string[];
  bindQuoted: string;
  cloudflareQuoted: string;
  route53Quoted: string;
  totalBytes: number;
  needsSplit: boolean;
}

function escapeTxtQuotes(str: string): string {
  return str.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function splitTxtChunks(value: string, maxBytes = 255): TxtSplitResult {
  const limit = Math.max(4, Math.floor(maxBytes));
  const encoder = new TextEncoder();
  const totalBytes = encoder.encode(value).length;

  if (!value) {
    return {
      chunks: [""],
      bindQuoted: '""',
      cloudflareQuoted: '""',
      route53Quoted: '""',
      totalBytes: 0,
      needsSplit: false,
    };
  }

  const chunks: string[] = [];
  let current = "";
  let currentBytes = 0;

  for (const ch of value) {
    const chBytes = encoder.encode(ch).length;
    if (currentBytes + chBytes > limit && current.length > 0) {
      chunks.push(current);
      current = ch;
      currentBytes = chBytes;
    } else {
      current += ch;
      currentBytes += chBytes;
    }
  }
  if (current.length > 0) {
    chunks.push(current);
  }

  const quotedChunks = chunks.map((c) => `"${escapeTxtQuotes(c)}"`);
  const bindQuoted =
    quotedChunks.length > 1
      ? `(\n${quotedChunks.map((q) => `  ${q}`).join("\n")}\n)`
      : quotedChunks[0];
  const cloudflareQuoted = quotedChunks.join(" ");
  const route53Quoted = quotedChunks.join(" ");

  return {
    chunks,
    bindQuoted,
    cloudflareQuoted,
    route53Quoted,
    totalBytes,
    needsSplit: totalBytes > limit,
  };
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

export interface MtaStsBuildResult {
  mtaStsDns: BuiltDnsRecord;
  tlsRptDns: BuiltDnsRecord | null;
  policyFileUrl: string;
  policyFileBody: string;
  warnings: string[];
}

export function buildMtaStsRecords(opts: {
  domain: string;
  policyId: string;
  mode: "testing" | "enforce" | "none";
  maxAge: number;
  mxPatterns: string[];
  tlsRptEmail: string;
}): MtaStsBuildResult {
  const cleanDomain = (opts.domain || "example.com").trim().replace(/\.$/, "");
  const warnings: string[] = [];

  const rawId = opts.policyId.trim();
  const sanitizedId = rawId.replace(/[^a-zA-Z0-9]/g, "");
  const now = new Date();
  const defaultId = [
    now.getUTCFullYear(),
    String(now.getUTCMonth() + 1).padStart(2, "0"),
    String(now.getUTCDate()).padStart(2, "0"),
    String(now.getUTCHours()).padStart(2, "0"),
    String(now.getUTCMinutes()).padStart(2, "0"),
    String(now.getUTCSeconds()).padStart(2, "0"),
  ].join("");
  const policyId = sanitizedId || defaultId;

  if (rawId && rawId !== sanitizedId) {
    warnings.push("Policy ID was stripped to alphanumeric characters only per RFC 8461.");
  }
  if (policyId.length > 32) {
    warnings.push("RFC 8461 recommends policy IDs of 32 alphanumeric characters or fewer.");
  }

  const maxAge = Math.max(0, Math.round(opts.maxAge));
  if (maxAge > 31557600) {
    warnings.push("max_age exceeds RFC 8461 maximum of 31557600 seconds (~1 year).");
  }
  if (opts.mode === "enforce" && maxAge < 86400) {
    warnings.push("For 'enforce' mode, RFC 8461 recommends max_age >= 86400 (1 day; typically 604800 / 1 week).");
  }
  if (opts.mode === "testing") {
    warnings.push("'testing' mode collects TLS failure reports without rejecting unencrypted mail; switch to 'enforce' after verifying reports.");
  }

  const cleanedMx = opts.mxPatterns
    .map((m) => m.trim().replace(/\.$/, ""))
    .filter(Boolean);
  if (opts.mode !== "none" && cleanedMx.length === 0) {
    warnings.push("At least one MX hostname pattern (e.g. *.mail.protection.outlook.com or mail.example.com) is required for testing/enforce mode.");
  }

  const mtaStsValue = `v=STSv1; id=${policyId}`;
  const mtaStsDns: BuiltDnsRecord = {
    host: `_mta-sts.${cleanDomain}`,
    type: "TXT",
    value: mtaStsValue,
    bindLine: `_mta-sts 3600 IN TXT "${mtaStsValue}"`,
    warnings: [],
  };

  const ruaTargets = opts.tlsRptEmail
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const lower = s.toLowerCase();
      if (lower.startsWith("mailto:") || lower.startsWith("https://")) {
        return s;
      }
      return `mailto:${s}`;
    });

  let tlsRptDns: BuiltDnsRecord | null = null;
  if (ruaTargets.length > 0) {
    const tlsRptValue = `v=TLSRPTv1; rua=${ruaTargets.join(",")}`;
    tlsRptDns = {
      host: `_smtp._tls.${cleanDomain}`,
      type: "TXT",
      value: tlsRptValue,
      bindLine: `_smtp._tls 3600 IN TXT "${tlsRptValue}"`,
      warnings: [],
    };
  } else {
    warnings.push("Consider configuring an SMTP TLS-RPT (_smtp._tls) email/HTTPS endpoint to receive TLS failure reports.");
  }

  const policyLines = [
    "version: STSv1",
    `mode: ${opts.mode}`,
    ...cleanedMx.map((mx) => `mx: ${mx}`),
    `max_age: ${maxAge}`,
  ];

  return {
    mtaStsDns,
    tlsRptDns,
    policyFileUrl: `https://mta-sts.${cleanDomain}/.well-known/mta-sts.txt`,
    policyFileBody: `${policyLines.join("\n")}\n`,
    warnings,
  };
}

export function buildBimiRecord(opts: {
  domain: string;
  selector: string;
  logoUrl: string;
  authorityUrl: string;
}): BuiltDnsRecord {
  const cleanDomain = (opts.domain || "example.com").trim().replace(/\.$/, "");
  const cleanSelector = (opts.selector || "default").trim() || "default";
  const logo = opts.logoUrl.trim();
  const authority = opts.authorityUrl.trim();
  const warnings: string[] = [];

  if (!logo) {
    warnings.push("Missing SVG logo URL ('l='); BIMI requires an HTTPS URL pointing to an SVG Tiny P/S logo.");
  } else {
    if (!logo.toLowerCase().startsWith("https://")) {
      warnings.push("BIMI logo URL ('l=') must use HTTPS.");
    }
    if (!logo.toLowerCase().includes(".svg")) {
      warnings.push("BIMI logo URL should point to an SVG Tiny Portable/Secure (.svg) file.");
    }
  }

  if (!authority) {
    warnings.push("No VMC/CMC authority certificate URL ('a=') specified — major inbox providers (Gmail, Apple Mail) require a Verified/Common Mark Certificate.");
  } else {
    if (!authority.toLowerCase().startsWith("https://")) {
      warnings.push("BIMI authority URL ('a=') must use HTTPS.");
    }
    if (!authority.toLowerCase().endsWith(".pem")) {
      warnings.push("BIMI VMC/CMC certificate URL ('a=') typically ends with .pem.");
    }
  }

  const parts = ["v=BIMI1", `l=${logo}`];
  if (authority) {
    parts.push(`a=${authority}`);
  } else {
    parts.push("a=");
  }

  const value = parts.join("; ");
  const host = `${cleanSelector}._bimi.${cleanDomain}`;

  return {
    host,
    type: "TXT",
    value,
    bindLine: `${cleanSelector}._bimi 3600 IN TXT "${value}"`,
    warnings,
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

function base64ToBytes(b64: string): Uint8Array {
  const cleaned = b64.replace(/\s+/g, "");
  const binary = atob(cleaned);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

function formatPem(label: string, bytes: Uint8Array): string {
  const b64 = bytesToBase64(bytes);
  const lines = b64.match(/.{1,64}/g) ?? [b64];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

export interface DkimKeypairResult {
  host: string;
  privateKeyPem: string;
  publicKeyBase64: string;
  txtValue: string;
  bindLine: string;
  chunks: string[];
  warnings: string[];
}

export async function generateDkimKeypair(opts: {
  domain: string;
  selector: string;
  algorithm: "rsa2048" | "ed25519";
}): Promise<DkimKeypairResult> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is unavailable in this environment.");
  }

  const cleanDomain = (opts.domain || "example.com").trim().replace(/\.$/, "");
  const cleanSelector = (opts.selector || "selector1").trim() || "selector1";
  const warnings: string[] = [];

  let actualAlg: "rsa2048" | "ed25519" = opts.algorithm;
  let keyPair: CryptoKeyPair;

  if (opts.algorithm === "ed25519") {
    try {
      keyPair = (await crypto.subtle.generateKey(
        { name: "Ed25519" } as AlgorithmIdentifier,
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
    } catch {
      actualAlg = "rsa2048";
      warnings.push(
        "Ed25519 Web Crypto key generation is not supported by this browser/WebView; fell back to RSA-2048.",
      );
      keyPair = (await crypto.subtle.generateKey(
        {
          name: "RSASSA-PKCS1-v1_5",
          modulusLength: 2048,
          publicExponent: new Uint8Array([1, 0, 1]),
          hash: "SHA-256",
        },
        true,
        ["sign", "verify"],
      )) as CryptoKeyPair;
    }
  } else {
    keyPair = (await crypto.subtle.generateKey(
      {
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["sign", "verify"],
    )) as CryptoKeyPair;
  }

  const pkcs8Buf = await crypto.subtle.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyPem = formatPem("PRIVATE KEY", new Uint8Array(pkcs8Buf));

  let publicKeyBase64: string;
  let keyTag: string;

  if (actualAlg === "ed25519") {
    keyTag = "ed25519";
    // RFC 8463: Ed25519 DKIM p= tag uses the raw 32-byte public key.
    try {
      const rawBuf = await crypto.subtle.exportKey("raw", keyPair.publicKey);
      publicKeyBase64 = bytesToBase64(new Uint8Array(rawBuf));
    } catch {
      const spkiBuf = await crypto.subtle.exportKey("spki", keyPair.publicKey);
      const spkiBytes = new Uint8Array(spkiBuf);
      // Ed25519 SPKI is 44 bytes: 12-byte ASN.1 header + 32-byte raw key
      const rawBytes = spkiBytes.length === 44 ? spkiBytes.subarray(12) : spkiBytes;
      publicKeyBase64 = bytesToBase64(rawBytes);
    }
  } else {
    keyTag = "rsa";
    const spkiBuf = await crypto.subtle.exportKey("spki", keyPair.publicKey);
    publicKeyBase64 = bytesToBase64(new Uint8Array(spkiBuf));
  }

  const txtValue = `v=DKIM1; k=${keyTag}; p=${publicKeyBase64}`;
  const split = splitTxtChunks(txtValue, 255);
  const host = `${cleanSelector}._domainkey.${cleanDomain}`;
  const bindLine = `${cleanSelector}._domainkey 3600 IN TXT ${split.bindQuoted}`;

  if (split.needsSplit) {
    warnings.push(
      `DKIM TXT record is ${split.totalBytes} bytes (>255); split into ${split.chunks.length} quoted chunks for BIND/DNS providers that enforce 255-byte string limits.`,
    );
  }
  warnings.push(
    "Keypair generated locally via Web Crypto — store the private key securely and never share it.",
  );

  return {
    host,
    privateKeyPem,
    publicKeyBase64,
    txtValue,
    bindLine,
    chunks: split.chunks,
    warnings,
  };
}

interface Asn1Node {
  tag: number;
  start: number;
  headerLength: number;
  contentStart: number;
  contentLength: number;
  end: number;
}

function readAsn1Node(der: Uint8Array, offset: number): Asn1Node {
  if (offset >= der.length) {
    throw new Error("Unexpected end of ASN.1 DER data.");
  }
  const tag = der[offset];
  if (offset + 1 >= der.length) {
    throw new Error("Truncated ASN.1 length byte.");
  }
  const firstLen = der[offset + 1];
  let contentLength = 0;
  let headerLength = 2;

  if ((firstLen & 0x80) === 0) {
    contentLength = firstLen;
  } else {
    const numOctets = firstLen & 0x7f;
    if (numOctets === 0 || numOctets > 4) {
      throw new Error("Unsupported indefinite or oversized ASN.1 DER length.");
    }
    if (offset + 2 + numOctets > der.length) {
      throw new Error("Truncated multi-byte ASN.1 DER length.");
    }
    for (let i = 0; i < numOctets; i++) {
      contentLength = (contentLength << 8) | der[offset + 2 + i];
    }
    headerLength = 2 + numOctets;
  }

  const contentStart = offset + headerLength;
  const end = contentStart + contentLength;
  if (end > der.length) {
    throw new Error("ASN.1 DER element length exceeds buffer size.");
  }

  return { tag, start: offset, headerLength, contentStart, contentLength, end };
}

/**
 * Extracts raw SubjectPublicKeyInfo (SPKI) DER bytes from an X.509 Certificate DER.
 * Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, ... }
 * TBSCertificate ::= SEQUENCE {
 *   version         [0] EXPLICIT Version DEFAULT v1,
 *   serialNumber         CertificateSerialNumber,
 *   signature            AlgorithmIdentifier,
 *   issuer               Name,
 *   validity             Validity,
 *   subject              Name,
 *   subjectPublicKeyInfo SubjectPublicKeyInfo,
 *   ...
 * }
 */
function extractSpkiFromCertDer(certDer: Uint8Array): Uint8Array {
  const certSeq = readAsn1Node(certDer, 0);
  if (certSeq.tag !== 0x30) {
    throw new Error("Invalid X.509 certificate: outer tag is not SEQUENCE (0x30).");
  }

  const tbsSeq = readAsn1Node(certDer, certSeq.contentStart);
  if (tbsSeq.tag !== 0x30) {
    throw new Error("Invalid X.509 certificate: TBSCertificate is not SEQUENCE (0x30).");
  }

  let cursor = tbsSeq.contentStart;
  const firstField = readAsn1Node(certDer, cursor);
  // Optional explicit [0] version tag (0xa0)
  if (firstField.tag === 0xa0) {
    cursor = firstField.end;
  }

  // Skip: serialNumber, signature, issuer, validity, subject (5 fields)
  for (let i = 0; i < 5; i++) {
    const field = readAsn1Node(certDer, cursor);
    cursor = field.end;
  }

  // Next field is SubjectPublicKeyInfo (SEQUENCE)
  const spkiNode = readAsn1Node(certDer, cursor);
  if (spkiNode.tag !== 0x30) {
    throw new Error("Could not locate SubjectPublicKeyInfo SEQUENCE inside X.509 certificate.");
  }

  return certDer.subarray(spkiNode.start, spkiNode.end);
}

export interface TlsaComputeResult {
  host: string;
  value: string;
  bindLine: string;
  hashHex: string;
  warnings: string[];
}

export async function computeTlsaFromPem(
  pem: string,
  opts: {
    host: string;
    port: number;
    protocol: "tcp" | "udp";
    usage: 0 | 1 | 2 | 3;
    selector: 0 | 1;
    matchingType: 1 | 2;
  },
): Promise<TlsaComputeResult> {
  if (typeof crypto === "undefined" || !crypto.subtle) {
    throw new Error("Web Crypto API (crypto.subtle) is unavailable in this environment.");
  }

  const pemMatch = pem.match(
    /-----BEGIN (CERTIFICATE|PUBLIC KEY)-----([\s\S]*?)-----END \1-----/,
  );
  if (!pemMatch) {
    throw new Error(
      "No valid PEM CERTIFICATE (or PUBLIC KEY) block found. Paste a PEM certificate starting with -----BEGIN CERTIFICATE-----.",
    );
  }

  const blockKind = pemMatch[1];
  const derBytes = base64ToBytes(pemMatch[2]);
  const warnings: string[] = [];

  let payloadToHash: Uint8Array;
  if (opts.selector === 0) {
    if (blockKind !== "CERTIFICATE") {
      throw new Error(
        "Selector 0 (Full Certificate) requires a -----BEGIN CERTIFICATE----- block, not a bare PUBLIC KEY.",
      );
    }
    payloadToHash = derBytes;
  } else {
    payloadToHash = blockKind === "PUBLIC KEY" ? derBytes : extractSpkiFromCertDer(derBytes);
  }

  const digestAlg = opts.matchingType === 1 ? "SHA-256" : "SHA-512";
  // Copy into a standalone ArrayBuffer so TypeScript strict DOM BufferSource matches cleanly
  const hashInput = new Uint8Array(payloadToHash.byteLength);
  hashInput.set(payloadToHash);
  const digestBuf = await crypto.subtle.digest(digestAlg, hashInput);
  const hashHex = Array.from(new Uint8Array(digestBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  const cleanHost = (opts.host || "mail.example.com").trim().replace(/\.$/, "");
  const port = Math.round(opts.port);
  if (port < 1 || port > 65535) {
    warnings.push("Port must be between 1 and 65535.");
  }

  if (opts.usage === 3 && opts.selector === 1) {
    // Best practice for Let's Encrypt / rotating certs with static keys
  } else if (opts.selector === 0) {
    warnings.push(
      "Selector 0 (Full Certificate) changes on every renewal — prefer Selector 1 (SPKI) if you reuse keys, or automate TLSA rollover.",
    );
  }
  warnings.push("DANE TLSA records require DNSSEC to be signed and validated on the domain.");

  const recordHost = `_${port}._${opts.protocol}.${cleanHost}`;
  const value = `${opts.usage} ${opts.selector} ${opts.matchingType} ${hashHex}`;
  const bindLine = `_${port}._${opts.protocol} 3600 IN TLSA ${value}`;

  return {
    host: recordHost,
    value,
    bindLine,
    hashHex,
    warnings,
  };
}

export interface LintFinding {
  level: "pass" | "warn" | "fail";
  message: string;
}

export type LintKindHint =
  | "auto"
  | "spf"
  | "dmarc"
  | "dkim"
  | "caa"
  | "mta-sts"
  | "tls-rpt"
  | "bimi"
  | "tlsa";

export type LintDetectedKind =
  | "SPF"
  | "DMARC"
  | "DKIM"
  | "CAA"
  | "MTA-STS"
  | "TLS-RPT"
  | "BIMI"
  | "TLSA"
  | "Unknown";

export interface LintReport {
  detectedKind: LintDetectedKind;
  status: "pass" | "warn" | "fail";
  checks: LintFinding[];
}

function parseSemicolonTags(trimmed: string, checks: LintFinding[]): Map<string, string> {
  const tags = trimmed
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);
  const map = new Map<string, string>();
  for (const tag of tags) {
    const idx = tag.indexOf("=");
    if (idx === -1) {
      checks.push({ level: "fail", message: `Malformed tag without '=': '${tag}'.` });
    } else {
      map.set(tag.slice(0, idx).trim().toLowerCase(), tag.slice(idx + 1).trim());
    }
  }
  return map;
}

export function lintDnsRecord(kindHint: LintKindHint, rawInput: string): LintReport {
  const trimmed = rawInput.trim().replace(/^"(.*)"$/, "$1");
  if (!trimmed) {
    return {
      detectedKind: "Unknown",
      status: "warn",
      checks: [{ level: "warn", message: "Paste a record value above to run syntax checks." }],
    };
  }

  const lower = trimmed.toLowerCase();
  let detected: LintDetectedKind = "Unknown";
  if (kindHint !== "auto") {
    const mapKind: Record<Exclude<LintKindHint, "auto">, LintDetectedKind> = {
      spf: "SPF",
      dmarc: "DMARC",
      dkim: "DKIM",
      caa: "CAA",
      "mta-sts": "MTA-STS",
      "tls-rpt": "TLS-RPT",
      bimi: "BIMI",
      tlsa: "TLSA",
    };
    detected = mapKind[kindHint];
  } else if (lower.startsWith("v=spf1")) {
    detected = "SPF";
  } else if (lower.startsWith("v=dmarc1")) {
    detected = "DMARC";
  } else if (lower.startsWith("v=stsv1")) {
    detected = "MTA-STS";
  } else if (lower.startsWith("v=tlsrptv1")) {
    detected = "TLS-RPT";
  } else if (lower.startsWith("v=bimi1")) {
    detected = "BIMI";
  } else if (lower.startsWith("v=dkim1") || lower.includes("; p=")) {
    detected = "DKIM";
  } else if (/^\d+\s+(issue|issuewild|iodef)\s+/i.test(trimmed)) {
    detected = "CAA";
  } else if (/^[0-3]\s+[01]\s+[0-2]\s+[0-9a-f]{16,}$/i.test(trimmed)) {
    detected = "TLSA";
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
      checks.push({
        level: "fail",
        message: "Dangerous '+all' mechanism authorizes ANY IP on the internet to spoof this domain.",
      });
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
    const map = parseSemicolonTags(trimmed, checks);

    if (map.get("v")?.toUpperCase() !== "DMARC1") {
      checks.push({ level: "fail", message: "DMARC record must start with 'v=DMARC1'." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=DMARC1' tag." });
    }

    const policy = map.get("p")?.toLowerCase();
    if (!policy || !["none", "quarantine", "reject"].includes(policy)) {
      checks.push({
        level: "fail",
        message: "Missing or invalid required 'p=' policy (must be none, quarantine, or reject).",
      });
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
      checks.push({
        level: "warn",
        message: "RSA DKIM public key looks short (prefer >= 2048-bit key for modern deliverability).",
      });
    } else {
      checks.push({ level: "pass", message: "DKIM public key ('p=') is present." });
    }
  } else if (detected === "CAA") {
    const match = trimmed.match(/^(\d+)\s+(issue|issuewild|iodef)\s+"?([^"]+)"?$/i);
    if (!match) {
      checks.push({
        level: "fail",
        message: 'Expected CAA syntax: <flags> <issue|issuewild|iodef> "<value>".',
      });
    } else {
      const flags = Number(match[1]);
      if (flags !== 0 && flags !== 128) {
        checks.push({ level: "warn", message: `Unusual CAA flag '${flags}' (standard is 0 or 128).` });
      } else {
        checks.push({
          level: "pass",
          message: `Valid CAA ${match[2].toLowerCase()} directive for "${match[3]}".`,
        });
      }
    }
  } else if (detected === "MTA-STS") {
    const map = parseSemicolonTags(trimmed, checks);
    if (map.get("v") !== "STSv1") {
      checks.push({ level: "fail", message: "MTA-STS DNS record must include exact 'v=STSv1' tag." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=STSv1' version tag." });
    }
    const id = map.get("id");
    if (!id) {
      checks.push({ level: "fail", message: "Missing required 'id=' policy version identifier." });
    } else if (!/^[a-zA-Z0-9]{1,32}$/.test(id)) {
      checks.push({
        level: "fail",
        message: `Invalid 'id=${id}': must be 1–32 alphanumeric characters per RFC 8461.`,
      });
    } else {
      checks.push({ level: "pass", message: `Valid alphanumeric policy ID '${id}'.` });
    }
  } else if (detected === "TLS-RPT") {
    const map = parseSemicolonTags(trimmed, checks);
    if (map.get("v") !== "TLSRPTv1") {
      checks.push({ level: "fail", message: "TLS-RPT record must begin with exact 'v=TLSRPTv1'." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=TLSRPTv1' version tag." });
    }
    const rua = map.get("rua");
    if (!rua) {
      checks.push({ level: "fail", message: "Missing required 'rua=' reporting URI." });
    } else {
      const uris = rua
        .split(",")
        .map((u) => u.trim())
        .filter(Boolean);
      const invalidUris = uris.filter(
        (u) => !u.toLowerCase().startsWith("mailto:") && !u.toLowerCase().startsWith("https://"),
      );
      if (invalidUris.length > 0) {
        checks.push({
          level: "fail",
          message: `Invalid TLS-RPT rua URI(s): ${invalidUris.join(", ")} (must use mailto: or https://).`,
        });
      } else {
        checks.push({ level: "pass", message: `Valid TLS-RPT destination(s): ${uris.join(", ")}` });
      }
    }
  } else if (detected === "BIMI") {
    const map = parseSemicolonTags(trimmed, checks);
    if (map.get("v") !== "BIMI1") {
      checks.push({ level: "fail", message: "BIMI record must include exact 'v=BIMI1' tag." });
    } else {
      checks.push({ level: "pass", message: "Valid 'v=BIMI1' version tag." });
    }
    const logo = map.get("l");
    if (!logo) {
      checks.push({ level: "warn", message: "Empty or missing 'l=' SVG logo URL (declines BIMI display)." });
    } else if (!logo.toLowerCase().startsWith("https://")) {
      checks.push({ level: "fail", message: "'l=' logo URL must use https://." });
    } else if (!logo.toLowerCase().includes(".svg")) {
      checks.push({ level: "warn", message: "'l=' logo URL should point to an .svg (SVG Tiny P/S) image." });
    } else {
      checks.push({ level: "pass", message: `HTTPS SVG logo configured: ${logo}` });
    }
    const authority = map.get("a");
    if (!authority) {
      checks.push({ level: "warn", message: "No 'a=' VMC/CMC certificate URL — required by Gmail and Apple Mail." });
    } else if (!authority.toLowerCase().startsWith("https://")) {
      checks.push({ level: "fail", message: "'a=' authority certificate URL must use https://." });
    } else {
      checks.push({ level: "pass", message: `Authority certificate configured: ${authority}` });
    }
  } else if (detected === "TLSA") {
    const match = trimmed.match(/^(\d+)\s+(\d+)\s+(\d+)\s+([0-9a-fA-F]+)$/);
    if (!match) {
      checks.push({
        level: "fail",
        message: "Expected TLSA syntax: <usage 0-3> <selector 0-1> <matching-type 0-2> <hex-data>.",
      });
    } else {
      const usage = Number(match[1]);
      const selector = Number(match[2]);
      const matching = Number(match[3]);
      const hex = match[4];

      if (usage < 0 || usage > 3) {
        checks.push({ level: "fail", message: `Invalid TLSA usage '${usage}' (must be 0–3).` });
      } else {
        const usageNames = ["PKIX-TA (0)", "PKIX-EE (1)", "DANE-TA (2)", "DANE-EE (3)"];
        checks.push({ level: "pass", message: `Usage: ${usageNames[usage]}.` });
      }

      if (selector !== 0 && selector !== 1) {
        checks.push({ level: "fail", message: `Invalid TLSA selector '${selector}' (must be 0=Cert or 1=SPKI).` });
      } else {
        checks.push({
          level: "pass",
          message: `Selector: ${selector === 0 ? "Full Certificate (0)" : "SubjectPublicKeyInfo (1)"}.`,
        });
      }

      if (matching === 1) {
        if (hex.length !== 64) {
          checks.push({
            level: "fail",
            message: `Matching type 1 (SHA-256) expects 64 hex characters, got ${hex.length}.`,
          });
        } else {
          checks.push({ level: "pass", message: "Valid 64-char SHA-256 hex digest." });
        }
      } else if (matching === 2) {
        if (hex.length !== 128) {
          checks.push({
            level: "fail",
            message: `Matching type 2 (SHA-512) expects 128 hex characters, got ${hex.length}.`,
          });
        } else {
          checks.push({ level: "pass", message: "Valid 128-char SHA-512 hex digest." });
        }
      } else if (matching === 0) {
        checks.push({
          level: "warn",
          message: "Matching type 0 (exact full DER) produces very large DNS responses; prefer 1 (SHA-256).",
        });
      } else {
        checks.push({ level: "fail", message: `Invalid TLSA matching type '${matching}' (must be 0, 1, or 2).` });
      }
    }
  } else {
    checks.push({
      level: "warn",
      message: "Could not auto-detect record type (select SPF, DMARC, DKIM, CAA, MTA-STS, TLS-RPT, BIMI, or TLSA explicitly).",
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
