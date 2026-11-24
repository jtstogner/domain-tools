import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type {
  BulkDomainResult,
  DnsOnlyResult,
  DnsQueryReport,
  MonitorProbeRequest,
  MonitorProbeResult,
  PortScanReport,
  QueryRequest,
  RedirectReport,
  TlsReport,
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
