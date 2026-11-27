export interface DmarcPublishedPolicy {
  domain: string;
  adkim: string;
  aspf: string;
  p: string;
  sp: string;
  pct: number;
}

export interface DmarcRecordRow {
  sourceIp: string;
  count: number;
  disposition: string;
  dkimResult: string;
  spfResult: string;
  dmarcPass: boolean;
  spfAligned: boolean;
  dkimAligned: boolean;
  headerFrom: string;
  envelopeFrom: string | null;
  dkimDomains: string[];
  spfDomains: string[];
}

export interface DmarcSourceSummary {
  sourceIp: string;
  totalCount: number;
  passCount: number;
  failCount: number;
  dkimAlignedCount: number;
  spfAlignedCount: number;
  dispositions: Record<string, number>;
  headerFroms: string[];
  envelopeFroms: string[];
  dkimResults: string[];
  spfResults: string[];
}

export interface ParsedDmarcReport {
  kind: "dmarc";
  orgName: string;
  orgEmail: string | null;
  reportId: string;
  domain: string;
  dateRange: {
    begin: string;
    end: string;
    beginMs: number;
    endMs: number;
  };
  publishedPolicy: DmarcPublishedPolicy;
  totalMessages: number;
  dmarcPassCount: number;
  spfAlignedCount: number;
  dkimAlignedCount: number;
  passRate: number;
  records: DmarcRecordRow[];
  bySourceIp: DmarcSourceSummary[];
}

export interface TlsRptFailureDetail {
  resultType: string;
  sendingMtaIp: string | null;
  receivingMxHostname: string | null;
  receivingIp: string | null;
  failedSessionCount: number;
  additionalInfoUri: string | null;
}

export interface TlsRptPolicySummary {
  policyType: string;
  policyDomain: string;
  policyStrings: string[];
  mxHosts: string[];
  totalSuccessfulSessions: number;
  totalFailedSessions: number;
  failureDetails: TlsRptFailureDetail[];
}

export interface ParsedTlsRptReport {
  kind: "tls-rpt";
  orgName: string;
  contactInfo: string | null;
  reportId: string;
  domain: string;
  dateRange: {
    begin: string;
    end: string;
  };
  totalSuccessful: number;
  totalFailed: number;
  successRate: number;
  policies: TlsRptPolicySummary[];
}

export type ParsedEmailReport = ParsedDmarcReport | ParsedTlsRptReport;

export async function decompressGzipBytes(buf: ArrayBuffer): Promise<string> {
  const bytes = new Uint8Array(buf);
  // If not gzip magic bytes (0x1f 0x8b), decode directly as UTF-8 text
  if (bytes.length < 2 || bytes[0] !== 0x1f || bytes[1] !== 0x8b) {
    return new TextDecoder("utf-8").decode(bytes);
  }

  if (typeof DecompressionStream === "undefined") {
    throw new Error(
      "This browser/WebView does not support DecompressionStream('gzip'). Please extract the .xml/.json file first.",
    );
  }

  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream("gzip"));
  return new Response(stream).text();
}

function getChildText(parent: Element | Document | null, tagName: string): string {
  if (!parent) return "";
  const el = parent.getElementsByTagName(tagName)[0];
  return el?.textContent?.trim() ?? "";
}

function epochSecondsToIso(val: string): { iso: string; ms: number } {
  const num = Number(val);
  if (!Number.isFinite(num) || num <= 0) {
    return { iso: val || "Unknown", ms: 0 };
  }
  const ms = num > 1e12 ? num : num * 1000;
  return { iso: new Date(ms).toISOString(), ms };
}

export function parseDmarcXml(xmlText: string): ParsedDmarcReport {
  const trimmed = xmlText.trim();
  if (!trimmed) {
    throw new Error("DMARC XML input is empty.");
  }

  const parser = new DOMParser();
  const doc = parser.parseFromString(trimmed, "application/xml");
  const parserError = doc.getElementsByTagName("parsererror")[0];
  if (parserError) {
    throw new Error(`Invalid XML: ${parserError.textContent?.trim() || "XML syntax error"}`);
  }

  const feedback = doc.getElementsByTagName("feedback")[0];
  if (!feedback) {
    throw new Error("Missing <feedback> root element — not a valid DMARC aggregate XML report.");
  }

  const meta = feedback.getElementsByTagName("report_metadata")[0] ?? null;
  const orgName = getChildText(meta, "org_name") || "Unknown Reporter";
  const orgEmail = getChildText(meta, "email") || null;
  const reportId = getChildText(meta, "report_id") || "N/A";
  const dateRangeEl = meta?.getElementsByTagName("date_range")[0] ?? null;
  const beginParsed = epochSecondsToIso(getChildText(dateRangeEl, "begin"));
  const endParsed = epochSecondsToIso(getChildText(dateRangeEl, "end"));

  const policyEl = feedback.getElementsByTagName("policy_published")[0] ?? null;
  const domain = getChildText(policyEl, "domain") || "unknown";
  const pctRaw = Number(getChildText(policyEl, "pct") || "100");
  const publishedPolicy: DmarcPublishedPolicy = {
    domain,
    adkim: getChildText(policyEl, "adkim") || "r",
    aspf: getChildText(policyEl, "aspf") || "r",
    p: getChildText(policyEl, "p") || "none",
    sp: getChildText(policyEl, "sp") || getChildText(policyEl, "p") || "none",
    pct: Number.isFinite(pctRaw) ? pctRaw : 100,
  };

  const recordEls = Array.from(feedback.getElementsByTagName("record"));
  const records: DmarcRecordRow[] = [];

  let totalMessages = 0;
  let dmarcPassCount = 0;
  let spfAlignedCount = 0;
  let dkimAlignedCount = 0;

  const sourceMap = new Map<
    string,
    {
      sourceIp: string;
      totalCount: number;
      passCount: number;
      failCount: number;
      dkimAlignedCount: number;
      spfAlignedCount: number;
      dispositions: Record<string, number>;
      headerFroms: Set<string>;
      envelopeFroms: Set<string>;
      dkimResults: Set<string>;
      spfResults: Set<string>;
    }
  >();

  for (const recEl of recordEls) {
    const rowEl = recEl.getElementsByTagName("row")[0] ?? null;
    const policyEvalEl = rowEl?.getElementsByTagName("policy_evaluated")[0] ?? null;
    const idsEl = recEl.getElementsByTagName("identifiers")[0] ?? null;
    const authEl = recEl.getElementsByTagName("auth_results")[0] ?? null;

    const sourceIp = getChildText(rowEl, "source_ip") || "unknown";
    const countNum = Number(getChildText(rowEl, "count") || "0");
    const count = Number.isFinite(countNum) && countNum > 0 ? countNum : 0;
    const disposition = (getChildText(policyEvalEl, "disposition") || "none").toLowerCase();
    const dkimResult = (getChildText(policyEvalEl, "dkim") || "fail").toLowerCase();
    const spfResult = (getChildText(policyEvalEl, "spf") || "fail").toLowerCase();

    const dkimAligned = dkimResult === "pass";
    const spfAligned = spfResult === "pass";
    const dmarcPass = dkimAligned || spfAligned;

    const headerFrom = getChildText(idsEl, "header_from") || domain;
    const envelopeFrom = getChildText(idsEl, "envelope_from") || null;

    const dkimDomains = authEl
      ? Array.from(authEl.getElementsByTagName("dkim"))
          .map((d) => getChildText(d, "domain"))
          .filter(Boolean)
      : [];
    const spfDomains = authEl
      ? Array.from(authEl.getElementsByTagName("spf"))
          .map((s) => getChildText(s, "domain"))
          .filter(Boolean)
      : [];

    records.push({
      sourceIp,
      count,
      disposition,
      dkimResult,
      spfResult,
      dmarcPass,
      spfAligned,
      dkimAligned,
      headerFrom,
      envelopeFrom,
      dkimDomains,
      spfDomains,
    });

    totalMessages += count;
    if (dmarcPass) dmarcPassCount += count;
    if (spfAligned) spfAlignedCount += count;
    if (dkimAligned) dkimAlignedCount += count;

    let agg = sourceMap.get(sourceIp);
    if (!agg) {
      agg = {
        sourceIp,
        totalCount: 0,
        passCount: 0,
        failCount: 0,
        dkimAlignedCount: 0,
        spfAlignedCount: 0,
        dispositions: {},
        headerFroms: new Set<string>(),
        envelopeFroms: new Set<string>(),
        dkimResults: new Set<string>(),
        spfResults: new Set<string>(),
      };
      sourceMap.set(sourceIp, agg);
    }

    agg.totalCount += count;
    if (dmarcPass) agg.passCount += count;
    else agg.failCount += count;
    if (dkimAligned) agg.dkimAlignedCount += count;
    if (spfAligned) agg.spfAlignedCount += count;
    agg.dispositions[disposition] = (agg.dispositions[disposition] ?? 0) + count;
    if (headerFrom) agg.headerFroms.add(headerFrom);
    if (envelopeFrom) agg.envelopeFroms.add(envelopeFrom);
    agg.dkimResults.add(dkimResult);
    agg.spfResults.add(spfResult);
  }

  records.sort((a, b) => b.count - a.count);

  const bySourceIp: DmarcSourceSummary[] = Array.from(sourceMap.values())
    .map((s) => ({
      sourceIp: s.sourceIp,
      totalCount: s.totalCount,
      passCount: s.passCount,
      failCount: s.failCount,
      dkimAlignedCount: s.dkimAlignedCount,
      spfAlignedCount: s.spfAlignedCount,
      dispositions: s.dispositions,
      headerFroms: Array.from(s.headerFroms),
      envelopeFroms: Array.from(s.envelopeFroms),
      dkimResults: Array.from(s.dkimResults),
      spfResults: Array.from(s.spfResults),
    }))
    .sort((a, b) => b.totalCount - a.totalCount);

  return {
    kind: "dmarc",
    orgName,
    orgEmail,
    reportId,
    domain,
    dateRange: {
      begin: beginParsed.iso,
      end: endParsed.iso,
      beginMs: beginParsed.ms,
      endMs: endParsed.ms,
    },
    publishedPolicy,
    totalMessages,
    dmarcPassCount,
    spfAlignedCount,
    dkimAlignedCount,
    passRate: totalMessages > 0 ? Math.round((dmarcPassCount / totalMessages) * 1000) / 10 : 100,
    records,
    bySourceIp,
  };
}

interface RawTlsRptJson {
  "organization-name"?: string;
  "contact-info"?: string;
  "report-id"?: string;
  "date-range"?: {
    "start-datetime"?: string;
    "end-datetime"?: string;
  };
  policies?: Array<{
    policy?: {
      "policy-type"?: string;
      "policy-domain"?: string;
      "policy-string"?: string[];
      "mx-host"?: string[];
    };
    summary?: {
      "total-successful-session-count"?: number;
      "total-failure-session-count"?: number;
    };
    "failure-details"?: Array<{
      "result-type"?: string;
      "sending-mta-ip"?: string;
      "receiving-mx-hostname"?: string;
      "receiving-ip"?: string;
      "failed-session-count"?: number;
      "additional-information"?: string;
    }>;
  }>;
}

export function parseTlsRptJson(jsonText: string): ParsedTlsRptReport {
  let parsed: RawTlsRptJson;
  try {
    parsed = JSON.parse(jsonText) as RawTlsRptJson;
  } catch (err) {
    throw new Error(
      `Invalid TLS-RPT JSON: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (!parsed || typeof parsed !== "object" || !Array.isArray(parsed.policies)) {
    throw new Error("Missing 'policies' array — not a valid RFC 8460 SMTP TLS-RPT JSON report.");
  }

  let totalSuccessful = 0;
  let totalFailed = 0;

  const policies: TlsRptPolicySummary[] = parsed.policies.map((entry) => {
    const ok = Number(entry.summary?.["total-successful-session-count"] ?? 0) || 0;
    const fail = Number(entry.summary?.["total-failure-session-count"] ?? 0) || 0;
    totalSuccessful += ok;
    totalFailed += fail;

    const failureDetails: TlsRptFailureDetail[] = (entry["failure-details"] ?? []).map((f) => ({
      resultType: f["result-type"] ?? "unknown",
      sendingMtaIp: f["sending-mta-ip"] ?? null,
      receivingMxHostname: f["receiving-mx-hostname"] ?? null,
      receivingIp: f["receiving-ip"] ?? null,
      failedSessionCount: Number(f["failed-session-count"] ?? 0) || 0,
      additionalInfoUri: f["additional-information"] ?? null,
    }));

    return {
      policyType: entry.policy?.["policy-type"] ?? "no-policy-found",
      policyDomain: entry.policy?.["policy-domain"] ?? "unknown",
      policyStrings: Array.isArray(entry.policy?.["policy-string"])
        ? entry.policy!["policy-string"]!
        : [],
      mxHosts: Array.isArray(entry.policy?.["mx-host"]) ? entry.policy!["mx-host"]! : [],
      totalSuccessfulSessions: ok,
      totalFailedSessions: fail,
      failureDetails,
    };
  });

  const totalSessions = totalSuccessful + totalFailed;
  return {
    kind: "tls-rpt",
    orgName: parsed["organization-name"] ?? "Unknown Reporter",
    contactInfo: parsed["contact-info"] ?? null,
    reportId: parsed["report-id"] ?? "N/A",
    domain: policies[0]?.policyDomain ?? "unknown",
    dateRange: {
      begin: parsed["date-range"]?.["start-datetime"] ?? "Unknown",
      end: parsed["date-range"]?.["end-datetime"] ?? "Unknown",
    },
    totalSuccessful,
    totalFailed,
    successRate:
      totalSessions > 0 ? Math.round((totalSuccessful / totalSessions) * 1000) / 10 : 100,
    policies,
  };
}

export function parseDmarcOrTlsRpt(text: string): ParsedEmailReport {
  const trimmed = text.trim();
  if (!trimmed) {
    throw new Error("Paste or drop a DMARC aggregate XML report or SMTP TLS-RPT JSON report.");
  }
  if (trimmed.startsWith("{")) {
    return parseTlsRptJson(trimmed);
  }
  if (trimmed.startsWith("<")) {
    return parseDmarcXml(trimmed);
  }
  throw new Error("Unrecognized format: expected DMARC XML (starting with '<') or TLS-RPT JSON (starting with '{').");
}
