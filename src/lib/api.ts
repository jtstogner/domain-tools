import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type {
  BulkDomainResult,
  CtHistoryReport,
  DnsOnlyResult,
  DnsQueryReport,
  DnsTraceReport,
  MonitorProbeRequest,
  MonitorProbeResult,
  PemDecodeReport,
  PortScanReport,
  QueryRequest,
  RedirectReport,
  RobotsFetchResult,
  SecurityReport,
  SmtpDeliverabilityReport,
  StandaloneDnsblReport,
  TldAvailabilityReport,
  TlsReport,
  TracerouteReport,
  TyposquatReport,
} from "../types/dns";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function queryDomain(request: QueryRequest): Promise<DnsQueryReport> {
  return invoke<DnsQueryReport>("query_domain", { request });
}

export async function scanPorts(
  target: string,
  customPorts?: number[],
): Promise<PortScanReport> {
  return invoke<PortScanReport>("scan_ports", {
    target,
    customPorts: customPorts && customPorts.length > 0 ? customPorts : null,
  });
}

export async function inspectTls(
  host: string,
  port = 443,
  starttls?: string | null,
): Promise<TlsReport> {
  return invoke<TlsReport>("inspect_tls", {
    host,
    port,
    starttls: starttls && starttls !== "auto" ? starttls : null,
  });
}

export async function traceRedirects(target: string): Promise<RedirectReport> {
  return invoke<RedirectReport>("trace_redirects", { target });
}

export async function runBulkCheck(domains: string[]): Promise<BulkDomainResult[]> {
  return invoke<BulkDomainResult[]>("run_bulk_check", { domains });
}

export async function pingEndpoint(
  request: MonitorProbeRequest,
): Promise<MonitorProbeResult> {
  return invoke<MonitorProbeResult>("ping_endpoint", { request });
}

export async function queryDnsOnly(
  domain: string,
  recordTypes: string[],
  resolverId: string,
  customResolver?: string | null,
): Promise<DnsOnlyResult> {
  return invoke<DnsOnlyResult>("query_dns_only", {
    domain,
    recordTypes,
    resolverId,
    customResolver: customResolver?.trim() || null,
  });
}

export async function probeSmtpDeliverability(
  domain: string,
): Promise<SmtpDeliverabilityReport> {
  return invoke<SmtpDeliverabilityReport>("probe_smtp_deliverability", { domain });
}

export async function runDnsTrace(
  domain: string,
  recordType?: string,
): Promise<DnsTraceReport> {
  return invoke<DnsTraceReport>("run_dns_trace", {
    domain,
    recordType: recordType || null,
  });
}

export async function fetchCtHistory(domain: string): Promise<CtHistoryReport> {
  return invoke<CtHistoryReport>("fetch_ct_history", { domain });
}

export async function scanTyposquats(domain: string): Promise<TyposquatReport> {
  return invoke<TyposquatReport>("scan_typosquats", { domain });
}

export async function runTraceroute(target: string): Promise<TracerouteReport> {
  return invoke<TracerouteReport>("run_traceroute", { target });
}

export async function recheckSecurity(
  domain: string,
  dkimSelectors: string[],
): Promise<SecurityReport> {
  return invoke<SecurityReport>("recheck_security", {
    domain,
    dkimSelectors,
  });
}

export async function checkDnsbl(target: string): Promise<StandaloneDnsblReport> {
  return invoke<StandaloneDnsblReport>("check_dnsbl", { target });
}

export async function checkTldAvailability(
  baseName: string,
  tlds?: string[],
): Promise<TldAvailabilityReport> {
  return invoke<TldAvailabilityReport>("check_tld_availability", {
    baseName,
    tlds: tlds && tlds.length > 0 ? tlds : null,
  });
}

export async function fetchRobotsTxt(domain: string): Promise<RobotsFetchResult> {
  return invoke<RobotsFetchResult>("fetch_robots_txt", { domain });
}

export async function decodePem(pemText: string): Promise<PemDecodeReport> {
  return invoke<PemDecodeReport>("decode_pem", { pemText });
}

export async function saveExport(
  defaultFilename: string,
  extension: string,
  content: string,
): Promise<boolean> {
  if (isTauriRuntime()) {
    const path = await save({
      defaultPath: defaultFilename,
      filters: [{ name: extension.toUpperCase(), extensions: [extension] }],
    });
    if (!path) return false;
    await invoke("save_export_file", { path, content });
    return true;
  }

  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = defaultFilename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  return true;
}

export async function copyToClipboard(text: string): Promise<void> {
  await navigator.clipboard.writeText(text);
}
