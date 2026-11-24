import { Download, Copy, FileJson, FileSpreadsheet, FileCode2, ChevronDown } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import type { DnsQueryReport } from "../types/dns";
import { copyToClipboard, saveExport } from "../lib/api";
import { formatAsCsv, formatAsJson, formatAsZoneFile } from "../lib/export";

interface ExportMenuProps {
  report: DnsQueryReport;
  selectedResolverId: string;
  onNotify: (msg: string) => void;
}

export function ExportMenu({
  report,
  selectedResolverId,
  onNotify,
}: ExportMenuProps) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const onDocClick = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, []);

  const handleSave = async (ext: "json" | "csv" | "zone") => {
    setOpen(false);
    const content =
      ext === "json"
        ? formatAsJson(report)
        : ext === "csv"
          ? formatAsCsv(report)
          : formatAsZoneFile(report, selectedResolverId);

    try {
      const saved = await saveExport(`${report.domain}.${ext}`, ext, content);
      if (saved) {
        onNotify(`Saved ${report.domain}.${ext}`);
      }
    } catch (err) {
      onNotify(`Export failed: ${String(err)}`);
    }
  };

  const handleCopy = async (kind: "zone" | "json") => {
    setOpen(false);
    const content =
      kind === "zone"
        ? formatAsZoneFile(report, selectedResolverId)
        : formatAsJson(report);
    await copyToClipboard(content);
    onNotify(kind === "zone" ? "Copied zone output" : "Copied JSON report");
  };

  return (
    <div ref={menuRef} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 rounded-lg border border-slate-700 bg-slate-800/80 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-sky-500/50 hover:text-white"
      >
        <Download className="h-3.5 w-3.5 text-sky-400" />
        Export
        <ChevronDown className="h-3.5 w-3.5 text-slate-400" />
      </button>

      {open && (
        <div className="absolute right-0 z-30 mt-1.5 w-52 overflow-hidden rounded-xl border border-slate-700 bg-[#111827] py-1 shadow-xl shadow-black/50">
          <button
            type="button"
            onClick={() => handleSave("json")}
            className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
          >
            <FileJson className="h-3.5 w-3.5 text-sky-400" />
            Save as JSON (.json)
          </button>
          <button
            type="button"
            onClick={() => handleSave("csv")}
            className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
          >
            <FileSpreadsheet className="h-3.5 w-3.5 text-emerald-400" />
            Save as CSV (.csv)
          </button>
          <button
            type="button"
            onClick={() => handleSave("zone")}
            className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
          >
            <FileCode2 className="h-3.5 w-3.5 text-amber-400" />
            Save Zone File (.zone)
          </button>
          <div className="my-1 border-t border-slate-800" />
          <button
            type="button"
            onClick={() => handleCopy("zone")}
            className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
          >
            <Copy className="h-3.5 w-3.5 text-slate-400" />
            Copy Zone Output
          </button>
          <button
            type="button"
            onClick={() => handleCopy("json")}
            className="flex w-full items-center gap-2.5 px-3.5 py-2 text-left text-xs text-slate-200 hover:bg-slate-800"
          >
            <Copy className="h-3.5 w-3.5 text-slate-400" />
            Copy JSON Report
          </button>
        </div>
      )}
    </div>
  );
}
