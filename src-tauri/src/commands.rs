use tauri::Emitter;

use crate::dns;
use crate::models::{
    BulkDomainResult, DnsOnlyResult, DnsQueryReport, MonitorProbeRequest, MonitorProbeResult,
    PortScanReport, QueryRequest, RedirectReport, TlsReport,
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
pub async fn save_export_file(path: String, content: String) -> Result<(), String> {
    tokio::fs::write(&path, content.as_bytes())
        .await
        .map_err(|e| format!("Failed to write export file '{path}': {e}"))
}
