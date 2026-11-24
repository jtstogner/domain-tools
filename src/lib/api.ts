import { invoke } from "@tauri-apps/api/core";
import { save } from "@tauri-apps/plugin-dialog";
import type { DnsQueryReport, QueryRequest } from "../types/dns";

function isTauriRuntime(): boolean {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window;
}

export async function queryDomain(request: QueryRequest): Promise<DnsQueryReport> {
  return invoke<DnsQueryReport>("query_domain", { request });
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
