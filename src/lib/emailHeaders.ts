export interface RawEmailHeader {
  name: string;
  value: string;
}

export interface ReceivedHop {
  index: number;
  raw: string;
  from: string | null;
  by: string | null;
  withProtocol: string | null;
  ip: string | null;
  timestamp: string | null;
  timestampMs: number | null;
  delaySeconds: number | null;
  flag: "normal" | "slow" | "clock_skew";
}

export interface AuthVerdict {
  mechanism: "spf" | "dkim" | "dmarc" | "arc";
  result: string;
  status: "pass" | "fail" | "warn" | "info";
  detail: string;
}

export interface DkimSignatureInfo {
  domain: string | null;
  selector: string | null;
  algorithm: string | null;
  bodyHash: string | null;
  signedHeaders: string[];
  raw: string;
}

export interface AlignmentCheck {
  label: string;
  status: "pass" | "warn" | "fail" | "info";
  detail: string;
}

export interface ParsedEmailHeaders {
  headers: RawEmailHeader[];
  from: string | null;
  fromDomain: string | null;
  to: string | null;
  subject: string | null;
  date: string | null;
  messageId: string | null;
  returnPath: string | null;
  returnPathDomain: string | null;
  replyTo: string | null;
  replyToDomain: string | null;
  receivedSpf: string | null;
  authenticationResults: string[];
  arcAuthenticationResults: string[];
  hops: ReceivedHop[];
  totalTransitSeconds: number | null;
  authVerdicts: AuthVerdict[];
  dkimSignatures: DkimSignatureInfo[];
  alignmentChecks: AlignmentCheck[];
  suspiciousFindings: string[];
  originatingIp: string | null;
}

const MULTI_PART_TLDS = new Set([
  "co.uk",
  "org.uk",
  "ac.uk",
  "gov.uk",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.br",
  "com.mx",
  "co.in",
  "com.sg",
  "com.hk",
  "co.za",
  "com.tw",
  "com.cn",
]);

export function getOrganizationalDomain(domain: string): string {
  const clean = domain.trim().toLowerCase().replace(/\.$/, "");
  const parts = clean.split(".").filter(Boolean);
  if (parts.length <= 2) return clean;
  const lastTwo = parts.slice(-2).join(".");
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length >= 3) {
    return parts.slice(-3).join(".");
  }
  return lastTwo;
}

export function extractEmailDomain(headerValue: string | null): string | null {
  if (!headerValue) return null;
  // Prefer address inside <...>
  const angleMatch = headerValue.match(/<[^<>\s@]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>/);
  if (angleMatch) return angleMatch[1].toLowerCase().replace(/\.$/, "");

  const plainMatch = headerValue.match(/[a-zA-Z0-9._%+-]+@([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/);
  if (plainMatch) return plainMatch[1].toLowerCase().replace(/\.$/, "");

  return null;
}

function unfoldHeaders(rawInput: string): RawEmailHeader[] {
  const normalized = rawInput.replace(/\r\n/g, "\n").replace(/\r/g, "\n");
  // Stop at the first blank line (separates headers from message body)
  const headerBlock = normalized.split(/\n\n/)[0] ?? "";
  const lines = headerBlock.split("\n");

  const unfolded: string[] = [];
  for (const line of lines) {
    if (!line.trim()) continue;
    if (/^[ \t]+/.test(line) && unfolded.length > 0) {
      unfolded[unfolded.length - 1] += " " + line.trim();
    } else {
      unfolded.push(line);
    }
  }

  const headers: RawEmailHeader[] = [];
  for (const line of unfolded) {
    const colonIdx = line.indexOf(":");
    if (colonIdx <= 0) continue;
    const name = line.slice(0, colonIdx).trim();
    const value = line.slice(colonIdx + 1).trim();
    if (/^[!-9;-~]+$/.test(name)) {
      headers.push({ name, value });
    }
  }
  return headers;
}

function extractIpFromText(text: string): string | null {
  // Check explicit IPv6 notation first: [IPv6:2001:db8::1]
  const ipv6Tagged = text.match(/\[IPv6:([0-9a-fA-F:]+)\]/i);
  if (ipv6Tagged) return ipv6Tagged[1];

  // Bracketed or parenthesized IPv4
  const ipv4Bracket = text.match(/[\[(](\d{1,3}(?:\.\d{1,3}){3})[\])]/);
  if (ipv4Bracket && isValidIpv4(ipv4Bracket[1])) return ipv4Bracket[1];

  // Bare IPv4
  const ipv4Bare = text.match(/\b(\d{1,3}(?:\.\d{1,3}){3})\b/);
  if (ipv4Bare && isValidIpv4(ipv4Bare[1])) return ipv4Bare[1];

  // Bracketed IPv6 without prefix
  const ipv6Bracket = text.match(/\[([0-9a-fA-F:]*:[0-9a-fA-F:]+)\]/);
  if (ipv6Bracket && ipv6Bracket[1].includes(":")) return ipv6Bracket[1];

  return null;
}

function isValidIpv4(ip: string): boolean {
  const parts = ip.split(".");
  if (parts.length !== 4) return false;
  return parts.every((p) => {
    const n = Number(p);
    return Number.isInteger(n) && n >= 0 && n <= 255;
  });
}

function parseReceivedHeader(raw: string): Omit<ReceivedHop, "index" | "delaySeconds" | "flag"> {
  const fromMatch = raw.match(/\bfrom\s+([^\s(;]+)/i);
  const byMatch = raw.match(/\bby\s+([^\s(;]+)/i);
  const withMatch = raw.match(/\bwith\s+([A-Za-z0-9_+.-]+)/i);

  // Timestamp typically appears after the final semicolon
  let timestamp: string | null = null;
  let timestampMs: number | null = null;
  const semiIdx = raw.lastIndexOf(";");
  if (semiIdx !== -1) {
    const candidate = raw
      .slice(semiIdx + 1)
      .trim()
      // Strip trailing timezone comments like "(UTC)" or "(PDT)" which some parsers choke on
      .replace(/\s*\([^)]*\)\s*$/, "")
      .trim();
    if (candidate) {
      timestamp = candidate;
      const parsed = Date.parse(candidate);
      if (!Number.isNaN(parsed)) {
        timestampMs = parsed;
      }
    }
  }

  return {
    raw,
    from: fromMatch ? fromMatch[1] : null,
    by: byMatch ? byMatch[1] : null,
    withProtocol: withMatch ? withMatch[1] : null,
    ip: extractIpFromText(raw),
    timestamp,
    timestampMs,
  };
}

function classifyAuthStatus(result: string): AuthVerdict["status"] {
  const r = result.toLowerCase();
  if (r === "pass" || r === "bestguesspass") return "pass";
  if (r === "fail" || r === "hardfail" || r === "permerror") return "fail";
  if (r === "softfail" || r === "neutral" || r === "temperror" || r === "policy") return "warn";
  return "info";
}

function parseAuthResultsHeader(
  headerValue: string,
  isArc: boolean,
): AuthVerdict[] {
  const verdicts: AuthVerdict[] = [];
  const segments = headerValue
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);

  // Skip the first segment if it's just the authserv-id (contains no '=')
  for (const seg of segments) {
    const match = seg.match(/\b(spf|dkim|dmarc|arc)\s*=\s*([a-zA-Z0-9_-]+)/i);
    if (!match) continue;
    const mech = (isArc ? "arc" : match[1].toLowerCase()) as AuthVerdict["mechanism"];
    const result = match[2].toLowerCase();
    verdicts.push({
      mechanism: isArc && match[1].toLowerCase() !== "arc" ? (match[1].toLowerCase() as AuthVerdict["mechanism"]) : mech,
      result,
      status: classifyAuthStatus(result),
      detail: isArc ? `[ARC] ${seg}` : seg,
    });
  }
  return verdicts;
}

function parseDkimSignature(raw: string): DkimSignatureInfo {
  const tagMap = new Map<string, string>();
  for (const part of raw.split(";")) {
    const trimmed = part.trim();
    const eq = trimmed.indexOf("=");
    if (eq === -1) continue;
    const key = trimmed.slice(0, eq).trim().toLowerCase();
    const val = trimmed.slice(eq + 1).trim();
    tagMap.set(key, val);
  }

  const hTag = tagMap.get("h") ?? "";
  const signedHeaders = hTag
    .split(":")
    .map((h) => h.trim())
    .filter(Boolean);

  return {
    domain: tagMap.get("d")?.toLowerCase().replace(/\.$/, "") ?? null,
    selector: tagMap.get("s") ?? null,
    algorithm: tagMap.get("a") ?? null,
    bodyHash: tagMap.get("bh") ?? null,
    signedHeaders,
    raw,
  };
}

export function parseEmailHeaders(rawText: string): ParsedEmailHeaders {
  const headers = unfoldHeaders(rawText);

  const getFirst = (name: string): string | null => {
    const lower = name.toLowerCase();
    return headers.find((h) => h.name.toLowerCase() === lower)?.value ?? null;
  };
  const getAll = (name: string): string[] => {
    const lower = name.toLowerCase();
    return headers.filter((h) => h.name.toLowerCase() === lower).map((h) => h.value);
  };

  const from = getFirst("From");
  const to = getFirst("To");
  const subject = getFirst("Subject");
  const date = getFirst("Date");
  const messageId = getFirst("Message-ID");
  const returnPath = getFirst("Return-Path");
  const replyTo = getFirst("Reply-To");
  const receivedSpf = getFirst("Received-SPF");
  const authenticationResults = getAll("Authentication-Results");
  const arcAuthenticationResults = getAll("ARC-Authentication-Results");

  const fromDomain = extractEmailDomain(from);
  const returnPathDomain = extractEmailDomain(returnPath);
  const replyToDomain = extractEmailDomain(replyTo);

  // Parse Received headers in chronological order (bottom-up in raw email -> earliest first)
  const rawReceived = getAll("Received").reverse();
  const hops: ReceivedHop[] = [];
  let prevTimestampMs: number | null = null;

  for (let i = 0; i < rawReceived.length; i++) {
    const parsed = parseReceivedHeader(rawReceived[i]);
    let delaySeconds: number | null = null;
    let flag: ReceivedHop["flag"] = "normal";

    if (parsed.timestampMs !== null && prevTimestampMs !== null) {
      delaySeconds = Math.round((parsed.timestampMs - prevTimestampMs) / 1000);
      if (delaySeconds < 0) {
        flag = "clock_skew";
      } else if (delaySeconds > 30) {
        flag = "slow";
      }
    }

    if (parsed.timestampMs !== null) {
      prevTimestampMs = parsed.timestampMs;
    }

    hops.push({
      ...parsed,
      index: i + 1,
      delaySeconds,
      flag,
    });
  }

  const timedHops = hops.filter((h) => h.timestampMs !== null);
  const totalTransitSeconds =
    timedHops.length >= 2
      ? Math.round(
          ((timedHops[timedHops.length - 1].timestampMs as number) -
            (timedHops[0].timestampMs as number)) /
            1000,
        )
      : null;

  // Originating IP: first public-looking IP in chronological Received hops, or Received-SPF client-ip
  let originatingIp: string | null = null;
  for (const hop of hops) {
    if (hop.ip && !hop.ip.startsWith("127.") && hop.ip !== "::1") {
      originatingIp = hop.ip;
      break;
    }
  }
  if (!originatingIp && receivedSpf) {
    const clientIpMatch = receivedSpf.match(/client-ip=([0-9a-fA-F.:]+)/i);
    if (clientIpMatch) originatingIp = clientIpMatch[1];
  }

  // Auth verdicts
  const authVerdicts: AuthVerdict[] = [];
  for (const ar of authenticationResults) {
    authVerdicts.push(...parseAuthResultsHeader(ar, false));
  }
  for (const arc of arcAuthenticationResults) {
    authVerdicts.push(...parseAuthResultsHeader(arc, true));
  }
  if (receivedSpf && !authVerdicts.some((v) => v.mechanism === "spf")) {
    const spfWord = receivedSpf.trim().split(/[\s(]/)[0]?.toLowerCase() ?? "none";
    authVerdicts.push({
      mechanism: "spf",
      result: spfWord,
      status: classifyAuthStatus(spfWord),
      detail: receivedSpf,
    });
  }

  // DKIM Signatures
  const dkimSignatures = getAll("DKIM-Signature").map(parseDkimSignature);

  // Alignment & Spoofing checks
  const alignmentChecks: AlignmentCheck[] = [];
  const suspiciousFindings: string[] = [];

  if (fromDomain && returnPathDomain) {
    const strict = fromDomain === returnPathDomain;
    const relaxed = getOrganizationalDomain(fromDomain) === getOrganizationalDomain(returnPathDomain);
    if (strict) {
      alignmentChecks.push({
        label: "SPF / Return-Path Alignment",
        status: "pass",
        detail: `Strict match: From (${fromDomain}) matches Return-Path (${returnPathDomain}).`,
      });
    } else if (relaxed) {
      alignmentChecks.push({
        label: "SPF / Return-Path Alignment",
        status: "pass",
        detail: `Relaxed match: From (${fromDomain}) and Return-Path (${returnPathDomain}) share org domain ${getOrganizationalDomain(fromDomain)}.`,
      });
    } else {
      alignmentChecks.push({
        label: "SPF / Return-Path Alignment",
        status: "warn",
        detail: `Unaligned: From (${fromDomain}) differs from Return-Path (${returnPathDomain}). Common for third-party ESPs unless custom bounce domain is configured.`,
      });
    }
  } else if (fromDomain) {
    alignmentChecks.push({
      label: "SPF / Return-Path Alignment",
      status: "info",
      detail: "Return-Path header not present; cannot verify envelope-from alignment.",
    });
  }

  if (fromDomain && replyToDomain) {
    const sameOrg = getOrganizationalDomain(fromDomain) === getOrganizationalDomain(replyToDomain);
    if (sameOrg) {
      alignmentChecks.push({
        label: "From vs Reply-To",
        status: "pass",
        detail: `Reply-To (${replyToDomain}) aligns with From (${fromDomain}).`,
      });
    } else {
      alignmentChecks.push({
        label: "From vs Reply-To",
        status: "fail",
        detail: `Mismatch: replies go to ${replyToDomain}, not ${fromDomain} — verify this is not a phishing/BEC spoof.`,
      });
      suspiciousFindings.push(
        `Reply-To domain (${replyToDomain}) does not match From domain (${fromDomain}).`,
      );
    }
  }

  if (fromDomain && dkimSignatures.length > 0) {
    const dkimDomains = dkimSignatures.map((d) => d.domain).filter((d): d is string => Boolean(d));
    const alignedSig = dkimDomains.find(
      (d) => getOrganizationalDomain(d) === getOrganizationalDomain(fromDomain),
    );
    if (alignedSig) {
      const exact = alignedSig === fromDomain;
      alignmentChecks.push({
        label: "DKIM Alignment",
        status: "pass",
        detail: `${exact ? "Strict" : "Relaxed"} match: DKIM signature d=${alignedSig} aligns with From (${fromDomain}).`,
      });
    } else if (dkimDomains.length > 0) {
      alignmentChecks.push({
        label: "DKIM Alignment",
        status: "warn",
        detail: `DKIM signature domain(s) (${dkimDomains.join(", ")}) do not align with From (${fromDomain}).`,
      });
    }
  } else if (fromDomain) {
    alignmentChecks.push({
      label: "DKIM Alignment",
      status: "warn",
      detail: "No DKIM-Signature header found in message.",
    });
  }

  // Gather suspicious findings from verdicts & hops
  for (const v of authVerdicts) {
    if (v.status === "fail") {
      suspiciousFindings.push(`${v.mechanism.toUpperCase()} failed (${v.result}): ${v.detail}`);
    }
  }
  for (const hop of hops) {
    if (hop.flag === "slow" && hop.delaySeconds !== null) {
      suspiciousFindings.push(
        `Hop #${hop.index} (${hop.by ?? "unknown"}) had a ${hop.delaySeconds}s transit delay.`,
      );
    } else if (hop.flag === "clock_skew" && hop.delaySeconds !== null) {
      suspiciousFindings.push(
        `Hop #${hop.index} (${hop.by ?? "unknown"}) shows clock skew (${hop.delaySeconds}s).`,
      );
    }
  }

  return {
    headers,
    from,
    fromDomain,
    to,
    subject,
    date,
    messageId,
    returnPath,
    returnPathDomain,
    replyTo,
    replyToDomain,
    receivedSpf,
    authenticationResults,
    arcAuthenticationResults,
    hops,
    totalTransitSeconds,
    authVerdicts,
    dkimSignatures,
    alignmentChecks,
    suspiciousFindings,
    originatingIp,
  };
}
