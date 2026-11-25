import type { DnsQueryReport, HealthCheckItem } from "../types/dns";

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
  lines.push(`; SPF:     [${report.security.spf.status.toUpperCase()}] ${report.security.spf.summary}`);
  lines.push(`; DMARC:   [${report.security.dmarc.status.toUpperCase()}] ${report.security.dmarc.summary}`);
  lines.push(`; DKIM:    [${report.security.dkim.status.toUpperCase()}] ${report.security.dkim.summary}`);
  lines.push(`; DNSSEC:  [${report.security.dnssec.status.toUpperCase()}] ${report.security.dnssec.summary}`);
  if (report.security.mta_sts) {
    lines.push(`; MTA-STS: [${report.security.mta_sts.status.toUpperCase()}] ${report.security.mta_sts.summary}`);
  }
  if (report.security.tls_rpt) {
    lines.push(`; TLS-RPT: [${report.security.tls_rpt.status.toUpperCase()}] ${report.security.tls_rpt.summary}`);
  }
  if (report.whois) {
    lines.push("");
    lines.push("; === WHOIS Summary ===");
    lines.push(`; Domain:    ${report.whois.queried_domain}`);
    lines.push(`; Registrar: ${report.whois.registrar ?? "N/A"}`);
    lines.push(`; Created:   ${report.whois.created_date ?? "N/A"}`);
    lines.push(`; Expires:   ${report.whois.expiry_date ?? "N/A"}`);
  }
  if (report.website) {
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
  }
  if (report.health) {
    lines.push("");
    lines.push("; === Domain Health Summary ===");
    lines.push(`; Score:      ${report.health.score}/100 (Grade ${report.health.grade}, ${report.health.overall_status})`);
    lines.push(`; Spam:       ${report.health.spam_status.toUpperCase()} (${report.health.blacklists_listed}/${report.health.blacklists_checked} blacklists listed)`);
  }
  if (report.subdomains) {
    lines.push("");
    lines.push("; === Discovered Subdomains ===");
    lines.push(`; Total:      ${report.subdomains.total_found} (${report.subdomains.live_count} live in DNS, ${report.subdomains.ct_only_count} CT-only)`);
  }
  if (report.ports) {
    lines.push("");
    lines.push("; === Open Ports ===");
    lines.push(
      `; Target IP:  ${report.ports.target_ip ?? "N/A"} (${report.ports.open_count}/${report.ports.total_checked} open)`,
    );
    const openPorts = report.ports.ports
      .filter((p) => p.status === "open")
      .map((p) => `${p.port}/${p.service}`);
    if (openPorts.length > 0) {
      lines.push(`; Open:       ${openPorts.join(", ")}`);
    }
  }
  if (report.tls) {
    lines.push("");
    lines.push("; === SSL / TLS Summary ===");
    lines.push(
      `; TLS:        ${report.tls.protocol_version ?? "N/A"} | Chain valid: ${report.tls.chain_valid} | Host match: ${report.tls.hostname_match} | Days left: ${report.tls.days_remaining ?? "N/A"}`,
    );
  }
  if (report.network) {
    lines.push("");
    lines.push("; === Network / ASN Summary ===");
    lines.push(
      `; Network:    ${report.network.ips.length} IPs | ${report.network.unique_asns} ASNs${report.network.cdn_detected ? ` | CDN: ${report.network.cdn_detected}` : ""}`,
    );
  }

  return lines.join("\n") + "\n";
}

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function sortActionableChecks(checks: HealthCheckItem[]): HealthCheckItem[] {
  return [...checks]
    .filter((c) => c.status === "fail" || c.status === "warn")
    .sort((a, b) => {
      const sevDiff =
        (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9);
      if (sevDiff !== 0) return sevDiff;
      return b.max_points - b.points - (a.max_points - a.points);
    });
}

export function formatAsAuditMarkdown(report: DnsQueryReport): string {
  const h = report.health;
  const actionable = sortActionableChecks(h.checks);
  const lines: string[] = [
    `# Domain Health & Security Audit: \`${report.domain}\``,
    "",
    `- **Generated:** ${report.queried_at}`,
    `- **Overall Grade:** **${h.grade}** (${h.score}/100) — \`${h.overall_status.toUpperCase()}\``,
    `- **Summary:** ${h.summary}`,
    `- **Blacklist / Spam Status:** \`${h.spam_status.toUpperCase()}\` (${h.blacklists_listed}/${h.blacklists_checked} listed)`,
    "",
    "## Category Score Breakdown",
    "",
    "| Category | Score | Max |",
    "| --- | ---: | ---: |",
  ];

  const categories = new Map<string, { pts: number; max: number }>();
  for (const chk of h.checks) {
    const cur = categories.get(chk.category) ?? { pts: 0, max: 0 };
    cur.pts += chk.points;
    cur.max += chk.max_points;
    categories.set(chk.category, cur);
  }
  for (const [cat, val] of categories.entries()) {
    lines.push(`| ${cat} | ${val.pts} | ${val.max} |`);
  }

  lines.push("");
  lines.push(`## Prioritized Action Plan (${actionable.length} item${actionable.length === 1 ? "" : "s"})`);
  lines.push("");

  if (actionable.length === 0) {
    lines.push("All audited checks passed with no remediation items required.");
  } else {
    actionable.forEach((chk, idx) => {
      const gain = chk.max_points - chk.points;
      lines.push(
        `### ${idx + 1}. [${chk.severity.toUpperCase()}] ${chk.title} (+${gain} pts recoverable)`,
      );
      lines.push(`- **Category:** ${chk.category}`);
      lines.push(`- **Finding:** ${chk.detail}`);
      if (chk.why_it_matters) {
        lines.push(`- **Why it matters:** ${chk.why_it_matters}`);
      }
      if (chk.remediation_steps.length > 0) {
        lines.push("- **How to fix:**");
        chk.remediation_steps.forEach((step, sIdx) => {
          lines.push(`  ${sIdx + 1}. ${step}`);
        });
      }
      if (chk.suggested_snippet) {
        lines.push("");
        if (chk.snippet_label) {
          lines.push(`**${chk.snippet_label}:**`);
        }
        lines.push("```");
        lines.push(chk.suggested_snippet);
        lines.push("```");
      }
      if (chk.reference_url) {
        lines.push(`- **Reference / Delist Portal:** ${chk.reference_url}`);
      }
      lines.push("");
    });
  }

  lines.push("## Technical Snapshot");
  lines.push("");
  lines.push(`- **SPF:** ${report.security.spf.status} — ${report.security.spf.summary}`);
  lines.push(`- **DMARC:** ${report.security.dmarc.status} — ${report.security.dmarc.summary}`);
  lines.push(`- **DKIM:** ${report.security.dkim.status} — ${report.security.dkim.summary}`);
  lines.push(`- **DNSSEC:** ${report.security.dnssec.status} — ${report.security.dnssec.summary}`);
  if (report.security.mta_sts) {
    lines.push(`- **MTA-STS:** ${report.security.mta_sts.status} — ${report.security.mta_sts.summary}`);
  }
  if (report.security.tls_rpt) {
    lines.push(`- **TLS-RPT:** ${report.security.tls_rpt.status} — ${report.security.tls_rpt.summary}`);
  }
  lines.push(
    `- **TLS Certificate:** ${report.tls.protocol_version ?? "N/A"} | Chain valid: ${report.tls.chain_valid} | Host match: ${report.tls.hostname_match} | Days remaining: ${report.tls.days_remaining ?? "N/A"}`,
  );
  lines.push(
    `- **Registrar / Expiry:** ${report.whois.registrar ?? "N/A"} | Expires: ${report.whois.expiry_date ?? "N/A"} (${report.whois.days_until_expiry ?? "N/A"} days)`,
  );
  lines.push(
    `- **Subdomains:** ${report.subdomains.total_found} found (${report.subdomains.live_count} live, ${report.subdomains.takeover_count ?? 0} takeover risk)`,
  );
  lines.push(
    `- **Open Ports:** ${report.ports.open_count}/${report.ports.total_checked} open on ${report.ports.target_ip ?? "N/A"}`,
  );

  return lines.join("\n") + "\n";
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

export function formatAsAuditHtml(report: DnsQueryReport): string {
  const h = report.health;
  const actionable = sortActionableChecks(h.checks);
  const gradeColor =
    h.overall_status === "healthy"
      ? "#059669"
      : h.overall_status === "caution"
        ? "#d97706"
        : "#e11d48";

  const actionHtml =
    actionable.length === 0
      ? `<div class="card"><p>All audited checks passed. No remediation items required.</p></div>`
      : actionable
          .map(
            (chk, idx) => `
      <div class="card">
        <div class="card-head">
          <span class="sev sev-${escapeHtml(chk.severity)}">${escapeHtml(chk.severity.toUpperCase())}</span>
          <strong>${idx + 1}. ${escapeHtml(chk.title)}</strong>
          <span class="pts">+${chk.max_points - chk.points} pts</span>
        </div>
        <p class="finding">${escapeHtml(chk.detail)}</p>
        ${chk.why_it_matters ? `<p class="why"><strong>Why it matters:</strong> ${escapeHtml(chk.why_it_matters)}</p>` : ""}
        ${
          chk.remediation_steps.length > 0
            ? `<ol class="steps">${chk.remediation_steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ol>`
            : ""
        }
        ${
          chk.suggested_snippet
            ? `<div class="snippet-wrap">${chk.snippet_label ? `<div class="snippet-label">${escapeHtml(chk.snippet_label)}</div>` : ""}<pre>${escapeHtml(chk.suggested_snippet)}</pre></div>`
            : ""
        }
        ${chk.reference_url ? `<p class="ref">Reference: <a href="${escapeHtml(chk.reference_url)}">${escapeHtml(chk.reference_url)}</a></p>` : ""}
      </div>`,
          )
          .join("\n");

  const checksRows = h.checks
    .map(
      (chk) => `
      <tr>
        <td>${escapeHtml(chk.category)}</td>
        <td><strong>${escapeHtml(chk.title)}</strong></td>
        <td><span class="badge badge-${escapeHtml(chk.status)}">${escapeHtml(chk.status.toUpperCase())}</span></td>
        <td>${escapeHtml(chk.detail)}</td>
        <td class="mono">${chk.points}/${chk.max_points}</td>
      </tr>`,
    )
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Domain Health Audit — ${escapeHtml(report.domain)}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; color: #0f172a; background: #f8fafc; margin: 0; padding: 32px; line-height: 1.5; }
    .container { max-width: 960px; margin: 0 auto; }
    .hero { display: flex; align-items: center; gap: 20px; background: #fff; border: 1px solid #e2e8f0; border-radius: 12px; padding: 20px; margin-bottom: 24px; }
    .grade { width: 84px; height: 84px; border-radius: 16px; display: flex; flex-direction: column; align-items: center; justify-content: center; color: #fff; background: ${gradeColor}; font-weight: 700; flex-shrink: 0; }
    .grade .letter { font-size: 28px; line-height: 1; }
    .grade .score { font-size: 12px; margin-top: 4px; opacity: 0.9; }
    h1 { margin: 0 0 6px; font-size: 20px; }
    h2 { margin: 28px 0 12px; font-size: 16px; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
    .meta { color: #64748b; font-size: 12px; }
    .card { background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; padding: 16px; margin-bottom: 12px; page-break-inside: avoid; }
    .card-head { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
    .pts { margin-left: auto; font-family: monospace; font-size: 12px; color: #0284c7; font-weight: 600; }
    .sev, .badge { font-size: 10px; font-weight: 700; padding: 2px 8px; border-radius: 999px; text-transform: uppercase; }
    .sev-critical, .badge-fail { background: #ffe4e6; color: #be123c; }
    .sev-high { background: #ffedd5; color: #c2410c; }
    .sev-medium, .badge-warn { background: #fef3c7; color: #b45309; }
    .sev-low, .badge-info { background: #e0f2fe; color: #0369a1; }
    .badge-pass { background: #d1fae5; color: #047857; }
    .finding { margin: 8px 0 4px; font-size: 13px; color: #334155; }
    .why { margin: 4px 0 8px; font-size: 12px; color: #475569; }
    .steps { margin: 6px 0 8px; padding-left: 20px; font-size: 13px; }
    .snippet-wrap { background: #0f172a; color: #e2e8f0; border-radius: 8px; padding: 10px 12px; margin-top: 8px; }
    .snippet-label { font-size: 11px; color: #94a3b8; margin-bottom: 4px; }
    pre { margin: 0; font-family: ui-monospace, monospace; font-size: 12px; white-space: pre-wrap; word-break: break-all; }
    .ref { font-size: 12px; margin: 8px 0 0; }
    table { width: 100%; border-collapse: collapse; background: #fff; border: 1px solid #e2e8f0; border-radius: 10px; overflow: hidden; font-size: 12px; }
    th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid #e2e8f0; vertical-align: top; }
    th { background: #f1f5f9; font-size: 11px; text-transform: uppercase; color: #64748b; }
    .mono { font-family: ui-monospace, monospace; white-space: nowrap; }
    @media print { body { background: #fff; padding: 12px; } }
  </style>
</head>
<body>
  <div class="container">
    <div class="hero">
      <div class="grade">
        <span class="letter">${escapeHtml(h.grade)}</span>
        <span class="score">${h.score}/100</span>
      </div>
      <div>
        <h1>Domain Health Audit: ${escapeHtml(report.domain)}</h1>
        <p style="margin:0 0 6px;font-size:14px;">${escapeHtml(h.summary)}</p>
        <div class="meta">Queried: ${escapeHtml(report.queried_at)} · Spam Status: ${escapeHtml(h.spam_status.toUpperCase())} (${h.blacklists_listed}/${h.blacklists_checked} blacklists listed)</div>
      </div>
    </div>

    <h2>Prioritized Remediation Plan (${actionable.length})</h2>
    ${actionHtml}

    <h2>Full Audit Breakdown (${h.checks.length} checks)</h2>
    <table>
      <thead>
        <tr>
          <th>Category</th>
          <th>Check</th>
          <th>Status</th>
          <th>Finding</th>
          <th>Score</th>
        </tr>
      </thead>
      <tbody>
        ${checksRows}
      </tbody>
    </table>
  </div>
</body>
</html>
`;
}
