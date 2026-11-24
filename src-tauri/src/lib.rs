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
            commands::save_export_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
