mod commands;
pub mod dns;
pub mod models;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::query_domain,
            commands::scan_ports,
            commands::inspect_tls,
            commands::trace_redirects,
            commands::run_bulk_check,
            commands::ping_endpoint,
            commands::query_dns_only,
            commands::probe_smtp_deliverability,
            commands::run_dns_trace,
            commands::fetch_ct_history,
            commands::scan_typosquats,
            commands::run_traceroute,
            commands::save_export_file,
            commands::recheck_security,
            commands::check_dnsbl,
            commands::check_tld_availability,
            commands::fetch_robots_txt,
            commands::decode_pem,
            commands::deep_scan_ip
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
