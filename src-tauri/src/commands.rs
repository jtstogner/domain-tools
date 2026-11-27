use tauri::Emitter;

use crate::dns;
use crate::models::{
    BulkDomainResult, CtHistoryReport, DnsOnlyResult, DnsQueryReport, DnsTraceReport,
    IpDeepScanReport, MonitorProbeRequest, MonitorProbeResult, PemDecodeReport, PortScanReport,
    QueryRequest, RedirectReport, RobotsFetchResult, SecurityReport, SmtpDeliverabilityReport,
    StandaloneDnsblReport, TldAvailabilityReport, TlsReport, TracerouteReport, TyposquatReport,
};

#[tauri::command]
pub async fn query_domain(
    app: tauri::AppHandle,
    request: QueryRequest,
) -> Result<DnsQueryReport, String> {
    dns::execute_query_with_progress(request, move |evt| {
        let _ = app.emit("query-progress", &evt);
    })
    .await
}

#[tauri::command]
pub async fn scan_ports(
    target: String,
    custom_ports: Option<Vec<u16>>,
) -> Result<PortScanReport, String> {
    dns::ports::scan_custom_target(target, custom_ports).await
}

#[tauri::command]
pub async fn inspect_tls(
    host: String,
    port: u16,
    starttls: Option<String>,
) -> Result<TlsReport, String> {
    Ok(dns::tls::inspect_tls(&host, port, starttls.as_deref()).await)
}

#[tauri::command]
pub async fn trace_redirects(target: String) -> Result<RedirectReport, String> {
    Ok(dns::redirects::trace_custom_url(&target).await)
}

#[tauri::command]
pub async fn run_bulk_check(
    app: tauri::AppHandle,
    domains: Vec<String>,
) -> Result<Vec<BulkDomainResult>, String> {
    Ok(dns::bulk::run_bulk_check(domains, move |evt| {
        let _ = app.emit("bulk-progress", &evt);
    })
    .await)
}

#[tauri::command]
pub async fn ping_endpoint(request: MonitorProbeRequest) -> Result<MonitorProbeResult, String> {
    Ok(dns::monitor::probe_endpoint(request).await)
}

#[tauri::command]
pub async fn query_dns_only(
    domain: String,
    record_types: Vec<String>,
    resolver_id: String,
    custom_resolver: Option<String>,
) -> Result<DnsOnlyResult, String> {
    dns::execute_dns_only(domain, record_types, resolver_id, custom_resolver).await
}

#[tauri::command]
pub async fn probe_smtp_deliverability(domain: String) -> Result<SmtpDeliverabilityReport, String> {
    dns::email_probe::probe_smtp_deliverability(&domain).await
}

#[tauri::command]
pub async fn run_dns_trace(
    domain: String,
    record_type: Option<String>,
) -> Result<DnsTraceReport, String> {
    dns::trace::run_dns_trace(&domain, record_type.as_deref()).await
}

#[tauri::command]
pub async fn fetch_ct_history(domain: String) -> Result<CtHistoryReport, String> {
    dns::ct::fetch_ct_history(&domain).await
}

#[tauri::command]
pub async fn scan_typosquats(domain: String) -> Result<TyposquatReport, String> {
    dns::typosquat::scan_typosquats(&domain).await
}

#[tauri::command]
pub async fn run_traceroute(target: String) -> Result<TracerouteReport, String> {
    dns::traceroute::run_traceroute(&target).await
}

#[tauri::command]
pub async fn save_export_file(path: String, content: String) -> Result<(), String> {
    tokio::fs::write(&path, content.as_bytes())
        .await
        .map_err(|e| format!("Failed to write export file '{path}': {e}"))
}

#[tauri::command]
pub async fn recheck_security(
    domain: String,
    dkim_selectors: Vec<String>,
) -> Result<SecurityReport, String> {
    let normalized = dns::normalize_domain(&domain)?;
    let (_, _, resolver) = dns::build_resolver("cloudflare", None, false)
        .or_else(|_| dns::build_resolver("google", None, false))?;
    Ok(dns::security::run_security_checks(&normalized, &resolver, &dkim_selectors).await)
}

#[tauri::command]
pub async fn check_dnsbl(target: String) -> Result<StandaloneDnsblReport, String> {
    dns::health::check_standalone_dnsbl(&target).await
}

#[tauri::command]
pub async fn check_tld_availability(
    base_name: String,
    tlds: Option<Vec<String>>,
) -> Result<TldAvailabilityReport, String> {
    dns::tld::check_tld_availability(&base_name, tlds).await
}

#[tauri::command]
pub async fn fetch_robots_txt(domain: String) -> Result<RobotsFetchResult, String> {
    dns::robots::fetch_robots_txt(&domain).await
}

#[tauri::command]
pub async fn decode_pem(pem_text: String) -> Result<PemDecodeReport, String> {
    Ok(dns::pem::decode_pem_blocks(&pem_text))
}

#[tauri::command]
pub async fn deep_scan_ip(
    app: tauri::AppHandle,
    target: String,
    custom_ports: Option<Vec<u16>>,
) -> Result<IpDeepScanReport, String> {
    dns::ip_scan::deep_scan_ip_with_progress(&target, custom_ports, move |evt| {
        let _ = app.emit("ip-scan-progress", &evt);
    })
    .await
}
