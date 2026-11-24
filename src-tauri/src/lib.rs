mod commands;
pub mod dns;
pub mod models;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            commands::query_domain,
            commands::save_export_file
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
