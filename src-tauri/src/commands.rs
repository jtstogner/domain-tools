use crate::dns;
use crate::models::{DnsQueryReport, QueryRequest};

#[tauri::command]
pub async fn query_domain(request: QueryRequest) -> Result<DnsQueryReport, String> {
    dns::execute_query(request).await
}

#[tauri::command]
pub async fn save_export_file(path: String, content: String) -> Result<(), String> {
    tokio::fs::write(&path, content.as_bytes())
        .await
        .map_err(|e| format!("Failed to write export file '{path}': {e}"))
}
