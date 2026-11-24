import type { DnsQueryReport } from "../types/dns";

export function formatAsJson(report: DnsQueryReport): string {
  return JSON.stringify(report, null, 2);
}

function escapeCsvCell(value: string | number): string {
  const str = String(value);
  if (/[",\n\r]/.test(str)) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

export function formatAsCsv(report: DnsQueryReport): string {
  const lines = [
    ["resolver", "resolver_address", "record_type", "name", "ttl", "class", "value", "latency_ms"].join(","),
  ];

  for (const resolver of report.resolvers) {
    for (const typeResult of resolver.results) {
      for (const rec of typeResult.records) {
        lines.push(
          [
            escapeCsvCell(resolver.label),
            escapeCsvCell(resolver.address),
            escapeCsvCell(rec.record_type),
            escapeCsvCell(rec.name),
            escapeCsvCell(rec.ttl),
            escapeCsvCell(rec.class),
            escapeCsvCell(rec.value),
            escapeCsvCell(typeResult.latency_ms),
          ].join(","),
        );
      }
    }
  }

  return lines.join("\n") + "\n";
}

export function formatAsZoneFile(report: DnsQueryReport, resolverId?: string): string {
  const resolver =
    report.resolvers.find((r) => r.id === resolverId) ??
    report.resolvers.find((r) => r.status === "ok") ??
    report.resolvers[0];

  const lines: string[] = [
    `; Zone export for ${report.domain}`,
    `; Queried at: ${report.queried_at}`,
  ];

  if (resolver) {
    lines.push(`; Resolver: ${resolver.label} (${resolver.address})`);
  }

  lines.push(`$ORIGIN ${report.domain}.`);
  lines.push("");

  if (resolver) {
    for (const typeResult of resolver.results) {
      if (typeResult.records.length === 0) continue;
      lines.push(`; --- ${typeResult.record_type} (${typeResult.latency_ms}ms) ---`);
      for (const rec of typeResult.records) {
        const name = rec.name.padEnd(28, " ");
        const ttl = String(rec.ttl).padEnd(8, " ");
        const cls = rec.class.padEnd(4, " ");
        const rtype = rec.record_type.padEnd(8, " ");
        const formattedVal =
          rec.record_type === "TXT"
            ? `"${rec.value.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`
            : rec.value;
        lines.push(`${name} ${ttl} ${cls} ${rtype} ${formattedVal}`);
      }
      lines.push("");
    }
  }

  lines.push("; === Security Verification Summary ===");
  lines.push(`; SPF:    [${report.security.spf.status.toUpperCase()}] ${report.security.spf.summary}`);
  lines.push(`; DMARC:  [${report.security.dmarc.status.toUpperCase()}] ${report.security.dmarc.summary}`);
  lines.push(`; DKIM:   [${report.security.dkim.status.toUpperCase()}] ${report.security.dkim.summary}`);
  lines.push(`; DNSSEC: [${report.security.dnssec.status.toUpperCase()}] ${report.security.dnssec.summary}`);
  lines.push("");
  lines.push("; === WHOIS Summary ===");
  lines.push(`; Domain:    ${report.whois.queried_domain}`);
  lines.push(`; Registrar: ${report.whois.registrar ?? "N/A"}`);
  lines.push(`; Created:   ${report.whois.created_date ?? "N/A"}`);
  lines.push(`; Expires:   ${report.whois.expiry_date ?? "N/A"}`);
  lines.push("");
  lines.push("; === Website Stack Summary ===");
  lines.push(`; Final URL: ${report.website.final_url ?? "N/A"}`);
  lines.push(`; Status:    ${report.website.http_status ?? report.website.status}`);
  lines.push(
    `; Stack:     ${
      report.website.technologies.length > 0
        ? report.website.technologies.map((t) => (t.version ? `${t.name} v${t.version}` : t.name)).join(", ")
        : "None detected"
    }`,
  );
  lines.push("");
  lines.push("; === Domain Health Summary ===");
  lines.push(`; Score:      ${report.health.score}/100 (Grade ${report.health.grade}, ${report.health.overall_status})`);
  lines.push(`; Spam:       ${report.health.spam_status.toUpperCase()} (${report.health.blacklists_listed}/${report.health.blacklists_checked} blacklists listed)`);
  lines.push("");
  lines.push("; === Discovered Subdomains ===");
  lines.push(`; Total:      ${report.subdomains.total_found} (${report.subdomains.live_count} live in DNS, ${report.subdomains.ct_only_count} CT-only)`);

  return lines.join("\n") + "\n";
}
