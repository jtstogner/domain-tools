import { Cloud, Copy, Globe2, MapPin, Network, Server } from "lucide-react";
import { copyToClipboard } from "../lib/api";
import type { NetworkReport } from "../types/dns";

interface NetworkPanelProps {
  network: NetworkReport;
  onNotify: (msg: string) => void;
}

export function NetworkPanel({ network, onNotify }: NetworkPanelProps) {
  if (network.ips.length === 0) {
    return (
      <div className="rounded-xl border border-line bg-surface p-6 text-center text-xs text-ink-muted">
        {network.error ?? "No IPv4, IPv6, or MX host IPs found to analyze."}
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Summary Cards */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Server className="h-3.5 w-3.5 text-sky-600 dark:text-sky-400" />
            Resolved IPs
          </div>
          <div className="mt-1 font-mono text-lg font-semibold text-ink">
            {network.ips.length}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Network className="h-3.5 w-3.5 text-violet-600 dark:text-violet-400" />
            Unique ASNs
          </div>
          <div className="mt-1 font-mono text-lg font-semibold text-ink">
            {network.unique_asns}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Globe2 className="h-3.5 w-3.5 text-emerald-600 dark:text-emerald-400" />
            Locations
          </div>
          <div className="mt-1 truncate text-sm font-semibold text-ink">
            {network.countries.length > 0 ? network.countries.join(", ") : "Unknown"}
          </div>
        </div>

        <div className="rounded-xl border border-line bg-surface p-3.5">
          <div className="flex items-center gap-1.5 text-[11px] text-ink-muted">
            <Cloud className="h-3.5 w-3.5 text-amber-600 dark:text-amber-400" />
            CDN / Edge
          </div>
          <div className="mt-1 truncate text-sm font-semibold text-ink">
            {network.cdn_detected ?? "Direct Origin"}
          </div>
        </div>
      </div>

      {/* Per-IP Network Details */}
      <div className="space-y-3">
        {network.ips.map((item) => {
          const locationParts = [item.city, item.region, item.country].filter(Boolean);
          const providerTone = item.is_anycast_cdn
            ? "border-sky-500/30 bg-sky-500/10 text-sky-700 dark:text-sky-300"
            : item.provider_type === "Mail Provider"
              ? "border-violet-500/30 bg-violet-500/10 text-violet-700 dark:text-violet-300"
              : item.provider_type === "Cloud / Hosting"
                ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-300"
                : "border-line bg-surface-alt text-ink-secondary";

          return (
            <div
              key={item.ip}
              className="rounded-xl border border-line bg-surface p-4"
            >
              <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line pb-2.5">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm font-semibold text-ink">
                    {item.ip}
                  </span>
                  <button
                    type="button"
                    onClick={() => {
                      void copyToClipboard(item.ip);
                      onNotify(`Copied ${item.ip}`);
                    }}
                    title="Copy IP"
                    className="rounded p-1 text-ink-muted hover:bg-surface-alt hover:text-ink"
                  >
                    <Copy className="h-3 w-3" />
                  </button>
                  <span className="rounded bg-surface-alt px-1.5 py-0.5 font-mono text-[10px] font-medium text-ink-secondary">
                    {item.ip_version}
                  </span>
                  {item.roles.map((role) => (
                    <span
                      key={role}
                      className="rounded-md border border-line bg-surface-alt px-2 py-0.5 text-[11px] font-medium text-ink-secondary"
                    >
                      {role}
                    </span>
                  ))}
                </div>

                <span className={`rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${providerTone}`}>
                  {item.provider_name ? `${item.provider_type}: ${item.provider_name}` : item.provider_type}
                </span>
              </div>

              <div className="mt-3 grid grid-cols-1 gap-x-6 gap-y-2.5 text-xs md:grid-cols-3">
                <div>
                  <div className="text-[11px] text-ink-muted">ASN &amp; Network</div>
                  <div className="font-mono text-ink">
                    {item.asn ? `AS${item.asn}` : "ASN N/A"}
                    {item.cidr ? ` (${item.cidr})` : ""}
                  </div>
                  <div className="text-[11px] text-ink-secondary">
                    {item.as_org ?? item.isp ?? "Organization unknown"}
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-ink-muted">Geolocation</div>
                  <div className="flex items-center gap-1 text-ink">
                    <MapPin className="h-3.5 w-3.5 shrink-0 text-ink-muted" />
                    <span>
                      {locationParts.length > 0
                        ? locationParts.join(", ")
                        : item.country_code ?? "Location unknown"}
                    </span>
                  </div>
                </div>

                <div>
                  <div className="text-[11px] text-ink-muted">Reverse DNS (PTR)</div>
                  {item.ptr_records.length > 0 ? (
                    <div className="space-y-0.5 font-mono text-[11px] text-ink-secondary">
                      {item.ptr_records.map((ptr) => (
                        <div key={ptr} className="truncate" title={ptr}>
                          {ptr}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-[11px] italic text-ink-muted">
                      No PTR record
                    </div>
                  )}
                </div>
              </div>

              {item.hostnames.length > 0 && (
                <div className="mt-2.5 border-t border-line pt-2 text-[11px] text-ink-muted">
                  Associated Hostnames:{" "}
                  <span className="font-mono text-ink-secondary">
                    {item.hostnames.join(", ")}
                  </span>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
