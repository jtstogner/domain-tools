use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};

use crate::dns::txt_to_string;
use crate::dns::whois::extract_whois_domain;
use crate::models::{
    BlacklistEntry, DomainHealthReport, HealthCheckItem, NetworkReport, PortScanReport,
    PropagationRow, RedirectReport, ResolverResult, SecurityReport, SubdomainDiscoveryReport,
    TlsReport, WebsiteInfo, WhoisInfo,
};

const DOMAIN_BLACKLISTS: &[(&str, &str)] = &[
    ("Spamhaus DBL", "dbl.spamhaus.org"),
    ("SURBL Multi", "multi.surbl.org"),
    ("URIBL Multi", "multi.uribl.com"),
    ("NordSpam DBL", "dbl.nordspam.com"),
    ("SpamEatingMonkey URI", "uribl.spameatingmonkey.net"),
    ("SpamEatingMonkey Fresh", "fresh.spameatingmonkey.net"),
];

const IP_BLACKLISTS: &[(&str, &str)] = &[
    ("Spamhaus ZEN", "zen.spamhaus.org"),
    ("SpamCop", "bl.spamcop.net"),
    ("SpamEatingMonkey BL", "bl.spameatingmonkey.net"),
    ("PSBL", "psbl.surriel.com"),
    ("NordSpam BL", "bl.nordspam.com"),
    ("CBL (Abuseat)", "cbl.abuseat.org"),
];

pub struct BlacklistScanBundle {
    pub domain_blacklists: Vec<BlacklistEntry>,
    pub ip_blacklists: Vec<BlacklistEntry>,
    pub checked_ips: Vec<String>,
    pub ns_count: usize,
    pub mx_hosts: Vec<String>,
    pub caa_records: Vec<String>,
}

pub fn delist_url_for_zone(zone: &str) -> Option<&'static str> {
    match zone.to_ascii_lowercase().as_str() {
        "dbl.spamhaus.org" | "zen.spamhaus.org" | "cbl.abuseat.org" => {
            Some("https://check.spamhaus.org/")
        }
        "multi.surbl.org" => Some("https://www.surbl.org/surbl-analysis"),
        "multi.uribl.com" => Some("https://admin.uribl.com/"),
        "bl.spamcop.net" => Some("https://www.spamcop.net/bl.shtml"),
        "psbl.surriel.com" => Some("https://psbl.org/remove"),
        "bl.spameatingmonkey.net"
        | "uribl.spameatingmonkey.net"
        | "fresh.spameatingmonkey.net" => Some("https://spameatingmonkey.com/lookup"),
        "dbl.nordspam.com" | "bl.nordspam.com" => Some("https://www.nordspam.com/bl/"),
        _ => None,
    }
}

pub fn reverse_ipv4(ip: Ipv4Addr) -> String {
    let [a, b, c, d] = ip.octets();
    format!("{d}.{c}.{b}.{a}")
}

fn build_dnsbl_resolver() -> Result<TokioResolver, String> {
    let mut builder = match Resolver::builder_tokio() {
        Ok(b) => b,
        Err(_) => Resolver::builder_with_config(
            ResolverConfig::quad9(),
            TokioConnectionProvider::default(),
        ),
    };
    let opts: &mut ResolverOpts = builder.options_mut();
    opts.cache_size = 0;
    opts.timeout = Duration::from_millis(2500);
    opts.attempts = 1;
    opts.edns0 = true;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.validate = false;
    Ok(builder.build())
}

pub fn interpret_dnsbl_codes(zone: &str, codes: &[Ipv4Addr]) -> (&'static str, Option<String>) {
    if codes.is_empty() {
        return ("clean", None);
    }

    let z = zone.to_ascii_lowercase();

    if z == "dbl.spamhaus.org" || z == "zen.spamhaus.org" || z == "cbl.abuseat.org" {
        if codes.iter().all(|ip| {
            let [a, b, c, d] = ip.octets();
            a == 127 && b == 255 && c == 255 && (252..=255).contains(&d)
        }) {
            return (
                "blocked",
                Some("Query blocked/rate-limited by open DNS resolver".to_string()),
            );
        }
    }

    if z == "dbl.spamhaus.org" {
        let mut reasons = Vec::new();
        for ip in codes {
            let [a, b, c, d] = ip.octets();
            if a != 127 || (b == 255 && c == 255 && (252..=255).contains(&d)) {
                continue;
            }
            let reason = match (b, c, d) {
                (0, 1, 2) => "Spam domain",
                (0, 1, 4) => "Phishing domain",
                (0, 1, 5) => "Malware domain",
                (0, 1, 6) => "Botnet C&C domain",
                (0, 1, 102..=106) => "Abused legit domain",
                _ => "Listed on Spamhaus DBL",
            };
            if !reasons.contains(&reason) {
                reasons.push(reason);
            }
        }
        return if reasons.is_empty() {
            (
                "blocked",
                Some("Blocked/unrecognized Spamhaus DBL response".to_string()),
            )
        } else {
            ("listed", Some(reasons.join("; ")))
        };
    }

    if z == "zen.spamhaus.org" || z == "cbl.abuseat.org" {
        let mut hard_reasons = Vec::new();
        let mut has_policy = false;
        for ip in codes {
            let [a, b, c, d] = ip.octets();
            if a != 127 || (b == 255 && c == 255 && (252..=255).contains(&d)) {
                continue;
            }
            if b == 0 && c == 0 {
                match d {
                    2..=3 => {
                        if !hard_reasons.contains(&"SBL (Spamhaus Block List)") {
                            hard_reasons.push("SBL (Spamhaus Block List)");
                        }
                    }
                    4..=7 => {
                        if !hard_reasons.contains(&"XBL (Exploits / Botnet)") {
                            hard_reasons.push("XBL (Exploits / Botnet)");
                        }
                    }
                    10..=11 => has_policy = true,
                    _ => {
                        if !hard_reasons.contains(&"Listed on Spamhaus ZEN") {
                            hard_reasons.push("Listed on Spamhaus ZEN");
                        }
                    }
                }
            }
        }
        if !hard_reasons.is_empty() {
            return ("listed", Some(hard_reasons.join("; ")));
        }
        if has_policy {
            return (
                "policy",
                Some("PBL (Policy Block List — dynamic/unauthenticated IP)".to_string()),
            );
        }
        return (
            "blocked",
            Some("Blocked/unrecognized Spamhaus response".to_string()),
        );
    }

    if z == "multi.surbl.org" {
        if codes.iter().all(|ip| ip.octets() == [127, 0, 0, 1]) {
            return (
                "blocked",
                Some("Query blocked by SURBL open resolver policy".to_string()),
            );
        }
        let mut tags = Vec::new();
        for ip in codes {
            let mask = ip.octets()[3];
            if mask & 8 != 0 {
                tags.push("Phishing");
            }
            if mask & 16 != 0 {
                tags.push("Malware");
            }
            if mask & 64 != 0 {
                tags.push("Abuse");
            }
            if mask & 128 != 0 {
                tags.push("Cracked");
            }
            if mask & 2 != 0 || mask & 4 != 0 {
                tags.push("Spam URI");
            }
        }
        let detail = if tags.is_empty() {
            "Listed on SURBL".to_string()
        } else {
            tags.sort_unstable();
            tags.dedup();
            format!("SURBL: {}", tags.join(", "))
        };
        return ("listed", Some(detail));
    }

    if z == "multi.uribl.com" {
        if codes.iter().all(|ip| ip.octets() == [127, 0, 0, 1]) {
            return (
                "blocked",
                Some("Query blocked by URIBL open resolver policy".to_string()),
            );
        }
        let mut tags = Vec::new();
        for ip in codes {
            let mask = ip.octets()[3];
            if mask & 2 != 0 {
                tags.push("Black (Spam)");
            }
            if mask & 4 != 0 {
                tags.push("Grey");
            }
            if mask & 8 != 0 {
                tags.push("Red");
            }
        }
        let detail = if tags.is_empty() {
            "Listed on URIBL".to_string()
        } else {
            tags.sort_unstable();
            tags.dedup();
            format!("URIBL: {}", tags.join(", "))
        };
        return ("listed", Some(detail));
    }

    if z == "fresh.spameatingmonkey.net" {
        return (
            "policy",
            Some("Recently registered domain (elevated phishing/spam caution)".to_string()),
        );
    }

    if codes.iter().any(|ip| {
        let [a, _, _, d] = ip.octets();
        a == 127 && (2..=254).contains(&d)
    }) {
        return ("listed", Some(format!("Listed on {zone}")));
    }

    ("clean", None)
}

async fn query_dnsbl_entry(
    resolver: &TokioResolver,
    list_name: &str,
    zone: &str,
    target: String,
    target_role: String,
    query_fqdn: String,
) -> BlacklistEntry {
    let start = Instant::now();
    let delist_url = delist_url_for_zone(zone).map(|s| s.to_string());
    match resolver.lookup(&query_fqdn, RecordType::A).await {
        Ok(lookup) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let codes: Vec<Ipv4Addr> = lookup
                .record_iter()
                .filter_map(|r| match r.data() {
                    RData::A(a) => Some(a.0),
                    _ => None,
                })
                .collect();
            let code_strings: Vec<String> = codes.iter().map(|ip| ip.to_string()).collect();
            let (status, mut detail) = interpret_dnsbl_codes(zone, &codes);

            if status == "listed" {
                if let Ok(txt_lookup) = resolver.lookup(&query_fqdn, RecordType::TXT).await {
                    let txt_notes: Vec<String> = txt_lookup
                        .record_iter()
                        .filter_map(|r| match r.data() {
                            RData::TXT(t) => {
                                let s = txt_to_string(t);
                                if s.trim().is_empty() {
                                    None
                                } else {
                                    Some(s)
                                }
                            }
                            _ => None,
                        })
                        .collect();
                    if !txt_notes.is_empty() {
                        let joined = txt_notes.join(" | ");
                        detail = Some(match detail {
                            Some(d) => format!("{d} — {joined}"),
                            None => joined,
                        });
                    }
                }
            }

            BlacklistEntry {
                list_name: list_name.to_string(),
                zone: zone.to_string(),
                target,
                target_role,
                status: status.to_string(),
                return_codes: code_strings,
                detail,
                delist_url,
                latency_ms,
            }
        }
        Err(err) if err.is_nx_domain() || err.is_no_records_found() => BlacklistEntry {
            list_name: list_name.to_string(),
            zone: zone.to_string(),
            target,
            target_role,
            status: "clean".to_string(),
            return_codes: vec![],
            detail: None,
            delist_url,
            latency_ms: start.elapsed().as_millis() as u64,
        },
        Err(err) => BlacklistEntry {
            list_name: list_name.to_string(),
            zone: zone.to_string(),
            target,
            target_role,
            status: "error".to_string(),
            return_codes: vec![],
            detail: Some(err.to_string()),
            delist_url,
            latency_ms: start.elapsed().as_millis() as u64,
        },
    }
}

async fn collect_target_ips(
    domain: &str,
    resolvers: &[ResolverResult],
    dnsbl_resolver: &TokioResolver,
) -> (Vec<(Ipv4Addr, String)>, Vec<String>, Vec<String>, Vec<String>) {
    let mut web_ips: Vec<Ipv4Addr> = Vec::new();
    let mut mx_hosts: Vec<String> = Vec::new();
    let mut ns_records: Vec<String> = Vec::new();
    let mut caa_records: Vec<String> = Vec::new();

    if let Some(primary) = resolvers.iter().find(|r| r.status == "ok") {
        for tr in &primary.results {
            match tr.record_type.as_str() {
                "A" => {
                    for rec in &tr.records {
                        if let Ok(ip) = rec.value.trim().parse::<Ipv4Addr>() {
                            if !web_ips.contains(&ip) {
                                web_ips.push(ip);
                            }
                        }
                    }
                }
                "MX" => {
                    for rec in &tr.records {
                        let exchange = rec
                            .details
                            .as_ref()
                            .and_then(|d| d.get("exchange"))
                            .and_then(|v| v.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| {
                                rec.value.split_whitespace().nth(1).map(|s| s.to_string())
                            });
                        if let Some(host) = exchange {
                            let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
                            if !clean.is_empty() && !mx_hosts.contains(&clean) {
                                mx_hosts.push(clean);
                            }
                        }
                    }
                }
                "NS" => {
                    for rec in &tr.records {
                        let clean = rec.value.trim().trim_end_matches('.').to_ascii_lowercase();
                        if !clean.is_empty() && !ns_records.contains(&clean) {
                            ns_records.push(clean);
                        }
                    }
                }
                "CAA" => {
                    for rec in &tr.records {
                        let clean = rec.value.trim().to_string();
                        if !clean.is_empty() && !caa_records.contains(&clean) {
                            caa_records.push(clean);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    let fqdn = format!("{domain}.");
    if web_ips.is_empty() {
        if let Ok(lookup) = dnsbl_resolver.lookup(&fqdn, RecordType::A).await {
            for rec in lookup.record_iter() {
                if let RData::A(a) = rec.data() {
                    if !web_ips.contains(&a.0) {
                        web_ips.push(a.0);
                    }
                }
            }
        }
    }

    if mx_hosts.is_empty() {
        if let Ok(lookup) = dnsbl_resolver.lookup(&fqdn, RecordType::MX).await {
            for rec in lookup.record_iter() {
                if let RData::MX(mx) = rec.data() {
                    let clean = mx
                        .exchange()
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if !clean.is_empty() && !mx_hosts.contains(&clean) {
                        mx_hosts.push(clean);
                    }
                }
            }
        }
    }

    if ns_records.is_empty() {
        if let Ok(lookup) = dnsbl_resolver.lookup(&fqdn, RecordType::NS).await {
            for rec in lookup.record_iter() {
                if let RData::NS(ns) = rec.data() {
                    let clean = ns.0.to_string().trim_end_matches('.').to_ascii_lowercase();
                    if !clean.is_empty() && !ns_records.contains(&clean) {
                        ns_records.push(clean);
                    }
                }
            }
        }
    }

    if caa_records.is_empty() {
        if let Ok(lookup) = dnsbl_resolver.lookup(&fqdn, RecordType::CAA).await {
            for rec in lookup.record_iter() {
                if let RData::CAA(caa) = rec.data() {
                    let val = String::from_utf8_lossy(caa.raw_value()).into_owned();
                    let formatted = format!("{} {} \"{}\"", caa.flags(), caa.tag().as_str(), val);
                    if !caa_records.contains(&formatted) {
                        caa_records.push(formatted);
                    }
                }
            }
        }
    }

    let mx_futs = mx_hosts.iter().take(2).map(|host| {
        let fqdn_mx = format!("{host}.");
        async move {
            let mut ips = Vec::new();
            if let Ok(lookup) = dnsbl_resolver.lookup(&fqdn_mx, RecordType::A).await {
                for rec in lookup.record_iter() {
                    if let RData::A(a) = rec.data() {
                        ips.push(a.0);
                    }
                }
            }
            ips
        }
    });
    let mx_ip_lists = join_all(mx_futs).await;

    let mut targets: Vec<(Ipv4Addr, String)> = Vec::new();
    let mut seen_ips = BTreeSet::new();

    for ip in web_ips.into_iter().take(2) {
        if seen_ips.insert(ip) {
            targets.push((ip, "Web IP (A)".to_string()));
        }
    }

    for ips in mx_ip_lists {
        for ip in ips.into_iter().take(2) {
            if targets.len() >= 4 {
                break;
            }
            if seen_ips.insert(ip) {
                targets.push((ip, "Mail IP (MX)".to_string()));
            }
        }
    }

    (targets, ns_records, mx_hosts, caa_records)
}

pub async fn run_blacklist_checks(domain: &str, resolvers: &[ResolverResult]) -> BlacklistScanBundle {
    let apex_domain = extract_whois_domain(domain);
    let Ok(dnsbl_resolver) = build_dnsbl_resolver() else {
        return BlacklistScanBundle {
            domain_blacklists: vec![],
            ip_blacklists: vec![],
            checked_ips: vec![],
            ns_count: 0,
            mx_hosts: vec![],
            caa_records: vec![],
        };
    };

    let (target_ips, ns_records, mx_hosts, caa_records) =
        collect_target_ips(domain, resolvers, &dnsbl_resolver).await;
    let checked_ips: Vec<String> = target_ips.iter().map(|(ip, _)| ip.to_string()).collect();

    let domain_futs = DOMAIN_BLACKLISTS.iter().map(|(name, zone)| {
        let q = format!("{apex_domain}.{zone}.");
        query_dnsbl_entry(
            &dnsbl_resolver,
            name,
            zone,
            apex_domain.clone(),
            "Domain".to_string(),
            q,
        )
    });

    let mut ip_futs = Vec::new();
    for (ip, role) in &target_ips {
        let rev = reverse_ipv4(*ip);
        let ip_str = ip.to_string();
        for (name, zone) in IP_BLACKLISTS {
            let q = format!("{rev}.{zone}.");
            ip_futs.push(query_dnsbl_entry(
                &dnsbl_resolver,
                name,
                zone,
                ip_str.clone(),
                role.clone(),
                q,
            ));
        }
    }

    let (domain_blacklists, ip_blacklists) = tokio::join!(join_all(domain_futs), join_all(ip_futs));

    BlacklistScanBundle {
        domain_blacklists,
        ip_blacklists,
        checked_ips,
        ns_count: ns_records.len(),
        mx_hosts,
        caa_records,
    }
}

fn infer_mail_provider_dkim(mx_hosts: &[String]) -> Option<(&'static str, &'static str, &'static str)> {
    let joined = mx_hosts.join(" ").to_ascii_lowercase();
    if joined.contains("google.com") || joined.contains("googlemail.com") {
        Some((
            "Google Workspace",
            "google",
            "Google Admin -> Apps -> Google Workspace -> Gmail -> Authenticate email -> Generate new record",
        ))
    } else if joined.contains("protection.outlook.com") || joined.contains("mail.eo.outlook") {
        Some((
            "Microsoft 365",
            "selector1 / selector2",
            "Microsoft Defender -> Policies -> Threat policies -> Email authentication settings -> DKIM",
        ))
    } else if joined.contains("protonmail.ch") || joined.contains("proton.ch") {
        Some((
            "Proton Mail",
            "protonmail / protonmail2 / protonmail3",
            "Proton Admin -> Domain names -> DKIM -> Publish the 3 CNAME records",
        ))
    } else if joined.contains("messagingengine.com") || joined.contains("fastmail") {
        Some((
            "Fastmail",
            "fm1 / fm2 / fm3",
            "Fastmail Settings -> Domains -> Publish fm1/fm2/fm3._domainkey CNAME records",
        ))
    } else if joined.contains("zoho.") {
        Some((
            "Zoho Mail",
            "zmail",
            "Zoho Mail Admin -> Domains -> Email Configuration -> DKIM",
        ))
    } else if joined.contains("mx.cloudflare.net") {
        Some((
            "Cloudflare Email",
            "cf2024-1",
            "Cloudflare Dashboard -> Email -> Email Routing / DMARC Management",
        ))
    } else if joined.contains("sendgrid") {
        Some((
            "SendGrid",
            "s1 / s2",
            "SendGrid -> Settings -> Sender Authentication -> Authenticate Your Domain",
        ))
    } else if joined.contains("mimecast") {
        Some((
            "Mimecast",
            "mimecast",
            "Mimecast Administration Console -> Services -> Gateway -> Policies -> DNS Authentication",
        ))
    } else {
        None
    }
}

fn infer_caa_domain_from_tls(tls: &TlsReport) -> &'static str {
    let org = tls
        .certificates
        .first()
        .and_then(|c| c.issuer_org.as_deref())
        .unwrap_or("")
        .to_ascii_lowercase();
    if org.contains("let's encrypt") || org.contains("letsencrypt") || org.contains("isrg") {
        "letsencrypt.org"
    } else if org.contains("digicert") {
        "digicert.com"
    } else if org.contains("google") || org.contains("gts") {
        "pki.goog"
    } else if org.contains("sectigo") || org.contains("comodo") {
        "sectigo.com"
    } else if org.contains("globalsign") {
        "globalsign.com"
    } else if org.contains("amazon") {
        "amazon.com"
    } else {
        "letsencrypt.org"
    }
}

fn build_missing_headers_snippet(
    missing_headers: &[&str],
    website: &WebsiteInfo,
    network: &NetworkReport,
) -> (String, String) {
    let server = website.server.as_deref().unwrap_or("").to_ascii_lowercase();
    let cdn = network.cdn_detected.as_deref().unwrap_or("").to_ascii_lowercase();

    let header_value = |name: &str| -> &'static str {
        match name {
            "Strict-Transport-Security" => "max-age=31536000; includeSubDomains",
            "Content-Security-Policy" => {
                "default-src 'self'; object-src 'none'; frame-ancestors 'self'; upgrade-insecure-requests"
            }
            "X-Content-Type-Options" => "nosniff",
            "X-Frame-Options" => "SAMEORIGIN",
            "Referrer-Policy" => "strict-origin-when-cross-origin",
            "Permissions-Policy" => "camera=(), microphone=(), geolocation=()",
            _ => "",
        }
    };

    if cdn.contains("cloudflare") || server.contains("cloudflare") {
        let rules: Vec<String> = missing_headers
            .iter()
            .map(|h| format!("{h}: {}", header_value(h)))
            .collect();
        return (
            "Cloudflare Transform Rules (Response Header Modification)".to_string(),
            rules.join("\n"),
        );
    }

    if server.contains("apache") {
        let lines: Vec<String> = missing_headers
            .iter()
            .map(|h| format!("Header always set {h} \"{}\"", header_value(h)))
            .collect();
        return (
            "Apache (.htaccess / VirtualHost)".to_string(),
            format!("<IfModule mod_headers.c>\n  {}\n</IfModule>", lines.join("\n  ")),
        );
    }

    if server.contains("caddy") {
        let lines: Vec<String> = missing_headers
            .iter()
            .map(|h| format!("  {h} \"{}\"", header_value(h)))
            .collect();
        return (
            "Caddyfile header block".to_string(),
            format!("header {{\n{}\n}}", lines.join("\n")),
        );
    }

    if server.contains("iis") {
        let lines: Vec<String> = missing_headers
            .iter()
            .map(|h| {
                format!(
                    "        <add name=\"{h}\" value=\"{}\" />",
                    header_value(h)
                )
            })
            .collect();
        return (
            "IIS (web.config)".to_string(),
            format!(
                "<system.webServer>\n  <httpProtocol>\n    <customHeaders>\n{}\n    </customHeaders>\n  </httpProtocol>\n</system.webServer>",
                lines.join("\n")
            ),
        );
    }

    // Default: Nginx snippet
    let lines: Vec<String> = missing_headers
        .iter()
        .map(|h| format!("add_header {h} \"{}\" always;", header_value(h)))
        .collect();
    (
        if server.contains("nginx") {
            "Nginx server block".to_string()
        } else {
            "Nginx / Reverse Proxy headers".to_string()
        },
        lines.join("\n"),
    )
}

fn build_fixed_spf_snippet(domain: &str, security: &SecurityReport) -> (String, String) {
    let spf = &security.spf;
    if spf.status == "missing" {
        return (
            format!("TXT record for {domain}"),
            "v=spf1 mx -all".to_string(),
        );
    }
    if let Some(raw) = spf.raw_record.as_deref() {
        if raw.contains(" | ") {
            // Multiple SPF records: merge tokens safely
            let mut merged_tokens: Vec<String> = Vec::new();
            let mut tail = "~all".to_string();
            for rec in raw.split(" | ") {
                for tok in rec.split_whitespace().skip(1) {
                    let low = tok.to_ascii_lowercase();
                    if low.ends_with("all") && low.len() <= 4 {
                        if low == "-all" {
                            tail = "-all".to_string();
                        }
                        continue;
                    }
                    if !merged_tokens.iter().any(|t| t.eq_ignore_ascii_case(tok)) {
                        merged_tokens.push(tok.to_string());
                    }
                }
            }
            merged_tokens.push(tail);
            return (
                format!("Merged single TXT record for {domain}"),
                format!("v=spf1 {}", merged_tokens.join(" ")),
            );
        }

        // Replace +all / ?all or append ~all if missing
        let mut tokens: Vec<String> = raw.split_whitespace().map(|s| s.to_string()).collect();
        if let Some(last) = tokens.last_mut() {
            let low = last.to_ascii_lowercase();
            if low == "+all" || low == "all" || low == "?all" {
                *last = "~all".to_string();
            } else if !low.ends_with("all") && !low.starts_with("redirect=") {
                tokens.push("~all".to_string());
            }
        }
        return (
            format!("Recommended TXT record for {domain}"),
            tokens.join(" "),
        );
    }
    (
        format!("TXT record for {domain}"),
        "v=spf1 mx ~all".to_string(),
    )
}

fn build_dmarc_snippet(domain: &str, security: &SecurityReport) -> (String, String) {
    let apex = extract_whois_domain(domain);
    let rua = security
        .dmarc
        .rua
        .first()
        .cloned()
        .unwrap_or_else(|| format!("mailto:dmarc@{apex}"));

    let snippet = match security.dmarc.policy.as_deref() {
        None => format!("v=DMARC1; p=none; rua={rua}; fo=1; adkim=r; aspf=r; pct=100"),
        Some("none") => format!("v=DMARC1; p=quarantine; rua={rua}; fo=1; adkim=r; aspf=r; pct=25"),
        Some("quarantine") => format!("v=DMARC1; p=reject; rua={rua}; fo=1; pct=100"),
        Some(_) => format!("v=DMARC1; p=reject; rua={rua}; pct=100"),
    };

    (format!("TXT record for _dmarc.{apex}"), snippet)
}

pub fn compute_health_report(
    domain: &str,
    bundle: BlacklistScanBundle,
    propagation: &[PropagationRow],
    security: &SecurityReport,
    tls: &TlsReport,
    redirects: &RedirectReport,
    network: &NetworkReport,
    whois: &WhoisInfo,
    website: &WebsiteInfo,
    subdomains: &SubdomainDiscoveryReport,
    ports: &PortScanReport,
) -> DomainHealthReport {
    let apex = extract_whois_domain(domain);
    let domain_blacklists = bundle.domain_blacklists;
    let ip_blacklists = bundle.ip_blacklists;
    let checked_ips = bundle.checked_ips;
    let ns_count = bundle.ns_count;

    let blacklists_checked = domain_blacklists.len() + ip_blacklists.len();
    let domain_listed_entries: Vec<&BlacklistEntry> = domain_blacklists
        .iter()
        .filter(|b| b.status == "listed")
        .collect();
    let ip_listed_entries: Vec<&BlacklistEntry> = ip_blacklists
        .iter()
        .filter(|b| b.status == "listed")
        .collect();
    let domain_listed = domain_listed_entries.len();
    let ip_listed = ip_listed_entries.len();
    let blacklists_listed = domain_listed + ip_listed;
    let blacklists_blocked = domain_blacklists
        .iter()
        .chain(ip_blacklists.iter())
        .filter(|b| b.status == "blocked")
        .count();
    let has_policy_hit = domain_blacklists
        .iter()
        .chain(ip_blacklists.iter())
        .any(|b| b.status == "policy");

    let mut checks: Vec<HealthCheckItem> = Vec::new();

    // =========================================================
    // 1. REPUTATION (25 pts: 15 + 10)
    // =========================================================
    let domain_rep_pts = if domain_listed > 0 {
        0
    } else if domain_blacklists.iter().any(|b| b.status == "policy") {
        9
    } else {
        15
    };
    let domain_delist = domain_listed_entries
        .first()
        .and_then(|e| e.delist_url.clone())
        .or_else(|| Some("https://check.spamhaus.org/".to_string()));
    checks.push(HealthCheckItem {
        id: "domain_rhsbl".to_string(),
        category: "Reputation".to_string(),
        title: "Domain Blacklists (RHSBL)".to_string(),
        status: if domain_listed > 0 {
            "fail"
        } else if domain_rep_pts < 15 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        severity: if domain_listed > 0 {
            "critical"
        } else if domain_rep_pts < 15 {
            "low"
        } else {
            "info"
        }
        .to_string(),
        detail: if domain_listed > 0 {
            let names: Vec<&str> = domain_listed_entries
                .iter()
                .map(|e| e.list_name.as_str())
                .collect();
            format!(
                "Domain listed on {domain_listed} domain reputation list(s): {}.",
                names.join(", ")
            )
        } else if domain_rep_pts < 15 {
            "Domain flagged on fresh/policy list (newly registered caution).".to_string()
        } else {
            format!("Clean across {} domain blacklists.", domain_blacklists.len())
        },
        why_it_matters: (domain_listed > 0).then(|| {
            "Domain-based blocklists (DBL/SURBL/URIBL) cause major mail providers and browser security filters to quarantine emails or flag links.".to_string()
        }),
        remediation_steps: if domain_listed > 0 {
            vec![
                "Audit recent outbound mail logs and website content for phishing, malware, or compromised forms.".to_string(),
                "Enforce SPF (-all), DKIM, and DMARC so unauthorized senders cannot abuse your domain reputation.".to_string(),
                "Submit a delisting request using the blacklist lookup portal once the root cause is resolved.".to_string(),
            ]
        } else {
            vec![]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: if domain_listed > 0 { domain_delist } else { None },
        points: domain_rep_pts,
        max_points: 15,
    });

    let ip_rep_pts = if ip_listed > 0 {
        0
    } else if ip_blacklists.iter().any(|b| b.status == "policy") {
        6
    } else {
        10
    };
    let ip_delist = ip_listed_entries
        .first()
        .and_then(|e| e.delist_url.clone())
        .or_else(|| Some("https://check.spamhaus.org/".to_string()));
    checks.push(HealthCheckItem {
        id: "ip_dnsbl".to_string(),
        category: "Reputation".to_string(),
        title: "Web & Mail IP Blacklists (DNSBL)".to_string(),
        status: if ip_listed > 0 {
            "fail"
        } else if ip_blacklists.is_empty() {
            "info"
        } else if ip_rep_pts < 10 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        severity: if ip_listed > 0 {
            "critical"
        } else if ip_rep_pts < 10 {
            "medium"
        } else {
            "info"
        }
        .to_string(),
        detail: if ip_blacklists.is_empty() {
            "No public IPv4 A or MX host IPs found to check.".to_string()
        } else if ip_listed > 0 {
            let hits: Vec<String> = ip_listed_entries
                .iter()
                .map(|e| format!("{} ({})", e.target, e.list_name))
                .collect();
            format!("Active IP blacklist listing(s): {}.", hits.join(", "))
        } else if ip_rep_pts < 10 {
            "IP listed on a dynamic/policy block list (PBL).".to_string()
        } else {
            format!(
                "Clean across {} checks on {} IP(s).",
                ip_blacklists.len(),
                checked_ips.len()
            )
        },
        why_it_matters: (ip_listed > 0 || ip_rep_pts < 10).then(|| {
            "Mail servers sending from blocklisted IPs suffer immediate SMTP 550 rejections or spam-folder placement.".to_string()
        }),
        remediation_steps: if ip_listed > 0 {
            vec![
                "Check mail server queue and authenticated SMTP accounts for compromised credentials or open relay.".to_string(),
                "Verify matching forward-confirmed reverse DNS (PTR) and valid HELO/EHLO banner on outbound mail IPs.".to_string(),
                "If on shared hosting, contact your hosting provider or request delisting after securing outbound mail.".to_string(),
            ]
        } else if ip_rep_pts < 10 {
            vec![
                "Ensure outbound email routes through a dedicated relay with static IP + PTR rather than a dynamic residential/DHCP range.".to_string(),
            ]
        } else {
            vec![]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: if ip_listed > 0 { ip_delist } else { None },
        points: ip_rep_pts,
        max_points: 10,
    });

    // =========================================================
    // 2. DNS (18 pts: 6 + 5 + 4 + 3)
    // =========================================================
    let ns_pts = if ns_count >= 2 {
        6
    } else if ns_count == 1 {
        2
    } else {
        0
    };
    checks.push(HealthCheckItem {
        id: "dns_ns".to_string(),
        category: "DNS".to_string(),
        title: "Nameserver Redundancy".to_string(),
        status: if ns_count >= 2 {
            "pass"
        } else if ns_count == 1 {
            "warn"
        } else {
            "fail"
        }
        .to_string(),
        severity: if ns_count == 0 {
            "critical"
        } else if ns_count == 1 {
            "medium"
        } else {
            "info"
        }
        .to_string(),
        detail: if ns_count >= 2 {
            format!("{ns_count} authoritative nameservers configured.")
        } else if ns_count == 1 {
            "Only 1 nameserver found (single point of failure).".to_string()
        } else {
            "No NS records resolved.".to_string()
        },
        why_it_matters: (ns_count < 2).then(|| {
            "RFC 1034 recommends at least 2 geographically diverse nameservers so a single DNS outage does not take down web and email.".to_string()
        }),
        remediation_steps: if ns_count < 2 {
            vec![
                "Add a secondary authoritative nameserver at your DNS provider and update the NS delegation at your domain registrar.".to_string(),
                "Run the DNS Trace tab to verify parent delegation matches child authoritative NS records.".to_string(),
            ]
        } else {
            vec![]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: ns_pts,
        max_points: 6,
    });

    let divergent_types: Vec<&str> = propagation
        .iter()
        .filter(|p| p.status == "divergent")
        .map(|p| p.record_type.as_str())
        .collect();
    let error_count = propagation
        .iter()
        .filter(|p| p.status == "partial_error")
        .count();
    let prop_pts = if divergent_types.is_empty() && error_count == 0 {
        5
    } else if divergent_types.is_empty() {
        3
    } else {
        2
    };
    checks.push(HealthCheckItem {
        id: "dns_propagation".to_string(),
        category: "DNS".to_string(),
        title: "Resolver Consensus".to_string(),
        status: if !divergent_types.is_empty() || error_count > 0 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        severity: if !divergent_types.is_empty() {
            "medium"
        } else if error_count > 0 {
            "low"
        } else {
            "info"
        }
        .to_string(),
        detail: if !divergent_types.is_empty() {
            format!(
                "Divergent answers across resolvers for: {}.",
                divergent_types.join(", ")
            )
        } else if error_count > 0 {
            "Some resolvers encountered transient errors.".to_string()
        } else {
            "All queried resolvers agree on DNS responses.".to_string()
        },
        why_it_matters: (!divergent_types.is_empty()).then(|| {
            "Stale caches or out-of-sync authoritative nameservers cause users in different regions to reach different servers.".to_string()
        }),
        remediation_steps: if !divergent_types.is_empty() {
            vec![
                "Open the DNS Trace tab to compare SOA serial numbers across every authoritative nameserver.".to_string(),
                "Wait for previous TTLs to expire if you recently updated records, or force a zone transfer/sync between primary and secondary NS.".to_string(),
            ]
        } else {
            vec![]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: prop_pts,
        max_points: 5,
    });

    let dnssec_pts = match security.dnssec.status.as_str() {
        "pass" => 4,
        "warn" | "unsigned" => 2,
        _ => 0,
    };
    let dnssec_status = match security.dnssec.status.as_str() {
        "pass" => "pass",
        "fail" => "fail",
        _ => "warn",
    };
    let reg_hint = whois
        .registrar
        .as_deref()
        .map(|r| format!(" ({r})"))
        .unwrap_or_default();
    checks.push(HealthCheckItem {
        id: "dns_dnssec".to_string(),
        category: "DNS".to_string(),
        title: "DNSSEC Validation".to_string(),
        status: dnssec_status.to_string(),
        severity: match dnssec_status {
            "fail" => "high",
            "warn" => "low",
            _ => "info",
        }
        .to_string(),
        detail: security.dnssec.summary.clone(),
        why_it_matters: (dnssec_status != "pass").then(|| {
            "DNSSEC cryptographically signs DNS responses to prevent DNS cache poisoning and BGP/on-path spoofing.".to_string()
        }),
        remediation_steps: match security.dnssec.status.as_str() {
            "unsigned" => vec![
                "Enable DNSSEC signing in your authoritative DNS host (Cloudflare, Route53, etc.).".to_string(),
                format!("Copy the generated DS record into your domain registrar{reg_hint} DNSSEC settings."),
            ],
            "warn" | "fail" => vec![
                format!("Verify the DS record at your registrar{reg_hint} matches the active KSK/DNSKEY in your authoritative DNS zone."),
                "If migrating DNS providers, disable DNSSEC or publish both old/new DS records before switching nameservers.".to_string(),
            ],
            _ => vec![],
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: dnssec_pts,
        max_points: 4,
    });

    let has_caa = !bundle.caa_records.is_empty();
    let caa_ca = infer_caa_domain_from_tls(tls);
    checks.push(HealthCheckItem {
        id: "dns_caa".to_string(),
        category: "DNS".to_string(),
        title: "CAA Certificate Authorization".to_string(),
        status: if has_caa { "pass" } else { "warn" }.to_string(),
        severity: if has_caa { "info" } else { "low" }.to_string(),
        detail: if has_caa {
            format!("{} CAA record(s) restrict certificate issuance.", bundle.caa_records.len())
        } else {
            "No CAA records found — any public CA can issue certificates for this domain.".to_string()
        },
        why_it_matters: (!has_caa).then(|| {
            "RFC 8659 CAA records prevent unauthorized Certificate Authorities from issuing TLS certificates for your domain.".to_string()
        }),
        remediation_steps: if !has_caa {
            vec![
                format!("Publish a CAA record authorizing your active CA (detected: {caa_ca})."),
                "Add a second `issuewild` record if you use wildcard certificates, or `iodef` for violation reports.".to_string(),
            ]
        } else {
            vec![]
        },
        suggested_snippet: (!has_caa).then(|| format!("{apex}. 3600 IN CAA 0 issue \"{caa_ca}\"")),
        snippet_label: (!has_caa).then(|| format!("CAA record for {apex}")),
        reference_url: Some("https://ssl.com/how-to/dns-caa-record/".to_string()),
        points: if has_caa { 3 } else { 1 },
        max_points: 3,
    });

    // =========================================================
    // 3. EMAIL (22 pts: 6 + 6 + 4 + 6)
    // =========================================================
    let spf_pts = match security.spf.status.as_str() {
        "pass" => 6,
        "warn" => 3,
        _ => 0,
    };
    let spf_status = if security.spf.status == "missing" {
        "warn"
    } else {
        security.spf.status.as_str()
    };
    let (spf_snip_lbl, spf_snip) = build_fixed_spf_snippet(&apex, security);
    checks.push(HealthCheckItem {
        id: "email_spf".to_string(),
        category: "Email".to_string(),
        title: "SPF Record & Lookup Budget".to_string(),
        status: spf_status.to_string(),
        severity: match security.spf.status.as_str() {
            "fail" => "high",
            "missing" | "warn" => "medium",
            _ => "info",
        }
        .to_string(),
        detail: security.spf.summary.clone(),
        why_it_matters: (security.spf.status != "pass").then(|| {
            "SPF defines which mail servers may send on behalf of your domain; broken or >10-lookup SPF records cause PermError delivery failures.".to_string()
        }),
        remediation_steps: if security.spf.status == "missing" {
            vec![
                "Publish a single TXT record starting with `v=spf1` listing all authorized mail providers and ending with `~all` or `-all`.".to_string(),
            ]
        } else if security.spf.status != "pass" {
            let mut steps = security.spf.issues.clone();
            if security.spf.recursive_lookup_count > 10 {
                steps.push("Remove unused `include:` services or replace static relay hostnames with `ip4:`/`ip6:` CIDRs to stay under 10 recursive DNS lookups.".to_string());
            } else {
                steps.push("Update your apex TXT record to use a single valid SPF record ending with `~all` or `-all`.".to_string());
            }
            steps
        } else {
            vec![]
        },
        suggested_snippet: (security.spf.status != "pass").then_some(spf_snip),
        snippet_label: (security.spf.status != "pass").then_some(spf_snip_lbl),
        reference_url: Some("https://www.rfc-editor.org/rfc/rfc7208".to_string()),
        points: spf_pts,
        max_points: 6,
    });

    let dmarc_pts = match security.dmarc.status.as_str() {
        "pass" => 6,
        "warn" => 3,
        _ => 0,
    };
    let dmarc_status = if security.dmarc.status == "missing" {
        "warn"
    } else {
        security.dmarc.status.as_str()
    };
    let (dmarc_snip_lbl, dmarc_snip) = build_dmarc_snippet(&apex, security);
    checks.push(HealthCheckItem {
        id: "email_dmarc".to_string(),
        category: "Email".to_string(),
        title: "DMARC Policy".to_string(),
        status: dmarc_status.to_string(),
        severity: match security.dmarc.status.as_str() {
            "fail" => "high",
            "missing" | "warn" => "medium",
            _ => "info",
        }
        .to_string(),
        detail: security.dmarc.summary.clone(),
        why_it_matters: (security.dmarc.status != "pass").then(|| {
            "Without DMARC enforcement (`p=quarantine` or `p=reject`), attackers can spoof your exact domain in phishing emails, and major inbox providers (Gmail/Yahoo) penalize bulk mail.".to_string()
        }),
        remediation_steps: match security.dmarc.status.as_str() {
            "missing" => vec![
                "Start with a monitoring record (`p=none`) and an `rua=` mailbox to collect alignment reports for 1-2 weeks.".to_string(),
                "Once legitimate senders pass SPF/DKIM alignment, step up to `p=quarantine` and then `p=reject`.".to_string(),
            ],
            "warn" | "fail" => vec![
                "Upgrade your `_dmarc` TXT record from monitoring (`p=none`) to enforcement (`p=quarantine` -> `p=reject`) with `pct=100`.".to_string(),
                "Ensure an `rua=mailto:...` aggregate reporting address is set so you can monitor failed alignments.".to_string(),
            ],
            _ => vec![],
        },
        suggested_snippet: (security.dmarc.status != "pass").then_some(dmarc_snip),
        snippet_label: (security.dmarc.status != "pass").then_some(dmarc_snip_lbl),
        reference_url: Some("https://dmarc.org/overview/".to_string()),
        points: dmarc_pts,
        max_points: 6,
    });

    let dkim_pts = if security.dkim.status == "pass" {
        4
    } else {
        1
    };
    let dkim_provider = infer_mail_provider_dkim(&bundle.mx_hosts);
    checks.push(HealthCheckItem {
        id: "email_dkim".to_string(),
        category: "Email".to_string(),
        title: "DKIM Signing".to_string(),
        status: if security.dkim.status == "pass" {
            "pass"
        } else {
            "warn"
        }
        .to_string(),
        severity: if security.dkim.status == "pass" {
            "info"
        } else {
            "medium"
        }
        .to_string(),
        detail: if let Some((prov, sel, _)) = dkim_provider {
            if security.dkim.status != "pass" {
                format!("No active DKIM selector found (MX points to {prov}; expected selector: {sel}).")
            } else {
                security.dkim.summary.clone()
            }
        } else {
            security.dkim.summary.clone()
        },
        why_it_matters: (security.dkim.status != "pass").then(|| {
            "DKIM cryptographically signs outbound messages and survives email forwarding where SPF breaks.".to_string()
        }),
        remediation_steps: if security.dkim.status != "pass" {
            if let Some((prov, sel, steps)) = dkim_provider {
                vec![
                    format!("Detected mail provider {prov} — publish its DKIM key at `{sel}._domainkey.{apex}`."),
                    steps.to_string(),
                    "Re-verify using the custom DKIM selector input in the query bar.".to_string(),
                ]
            } else {
                vec![
                    "Enable DKIM signing in your email provider or ESP and publish the TXT/CNAME record at `<selector>._domainkey`.".to_string(),
                    "If your provider uses a custom selector name, enter it in the DKIM selectors box in the query bar to confirm.".to_string(),
                ]
            }
        } else {
            vec![]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: dkim_pts,
        max_points: 4,
    });

    // Email Transport (6 pts): MTA-STS (2) + TLS-RPT (2) + Mail PTR (2)
    let mta_pts = match security.mta_sts.status.as_str() {
        "pass" => 2,
        "warn" => 1,
        _ => 0,
    };
    let rpt_pts = match security.tls_rpt.status.as_str() {
        "pass" => 2,
        "warn" => 1,
        _ => 0,
    };
    let mail_ips: Vec<_> = network
        .ips
        .iter()
        .filter(|i| i.roles.iter().any(|r| r.contains("Mail")))
        .collect();
    let missing_mail_ptr: Vec<&str> = mail_ips
        .iter()
        .filter(|i| i.ptr_records.is_empty())
        .map(|i| i.ip.as_str())
        .collect();
    let ptr_pts = if mail_ips.is_empty() || missing_mail_ptr.is_empty() {
        2
    } else {
        0
    };
    let transport_pts = mta_pts + rpt_pts + ptr_pts;
    let transport_ok = transport_pts == 6;

    let mut transport_parts = Vec::new();
    transport_parts.push(format!("MTA-STS: {}", security.mta_sts.status));
    transport_parts.push(format!("TLS-RPT: {}", security.tls_rpt.status));
    if !missing_mail_ptr.is_empty() {
        transport_parts.push(format!("Missing PTR on MX IP(s): {}", missing_mail_ptr.join(", ")));
    } else if !mail_ips.is_empty() {
        transport_parts.push("Mail IP PTR present".to_string());
    }

    let mut transport_steps = Vec::new();
    if security.mta_sts.status != "pass" {
        transport_steps.push(format!(
            "Publish `_mta-sts.{apex}` TXT and serve `https://mta-sts.{apex}/.well-known/mta-sts.txt` to enforce STARTTLS for inbound mail."
        ));
    }
    if security.tls_rpt.status != "pass" {
        transport_steps.push(format!(
            "Publish `_smtp._tls.{apex}` TXT to receive daily TLS failure reports."
        ));
    }
    if !missing_mail_ptr.is_empty() {
        transport_steps.push(format!(
            "Configure reverse DNS (PTR) records with your IP/hosting provider for MX IP(s): {}.",
            missing_mail_ptr.join(", ")
        ));
    }

    checks.push(HealthCheckItem {
        id: "email_transport".to_string(),
        category: "Email".to_string(),
        title: "Email Transport (MTA-STS, TLS-RPT & Mail PTR)".to_string(),
        status: if transport_ok {
            "pass"
        } else if !missing_mail_ptr.is_empty() {
            "warn"
        } else {
            "warn"
        }
        .to_string(),
        severity: if !missing_mail_ptr.is_empty() {
            "medium"
        } else if !transport_ok {
            "low"
        } else {
            "info"
        }
        .to_string(),
        detail: transport_parts.join(" | "),
        why_it_matters: (!transport_ok).then(|| {
            "MTA-STS prevents SMTP downgrade attacks to cleartext, TLS-RPT surfaces certificate failures, and PTR records prevent receiving MTAs from rejecting mail.".to_string()
        }),
        remediation_steps: transport_steps,
        suggested_snippet: (security.mta_sts.status != "pass" || security.tls_rpt.status != "pass").then(|| {
            let mut lines = Vec::new();
            if security.mta_sts.status != "pass" {
                lines.push(format!("_mta-sts.{apex}. 300 IN TXT \"v=STSv1; id=20261124\""));
            }
            if security.tls_rpt.status != "pass" {
                lines.push(format!("_smtp._tls.{apex}. 300 IN TXT \"v=TLSRPTv1; rua=mailto:tls-reports@{apex}\""));
            }
            lines.join("\n")
        }),
        snippet_label: (security.mta_sts.status != "pass" || security.tls_rpt.status != "pass")
            .then(|| "MTA-STS & TLS-RPT DNS records".to_string()),
        reference_url: Some("https://www.rfc-editor.org/rfc/rfc8461".to_string()),
        points: transport_pts,
        max_points: 6,
    });

    // =========================================================
    // 4. TLS & WEB (21 pts: 7 + 5 + 5 + 4)
    // =========================================================
    let web_active = website.status == "ok" || tls.status != "unavailable";
    let (tls_pts, tls_status, tls_sev, tls_detail, tls_steps) = if !web_active {
        (
            5,
            "info",
            "info",
            "No public HTTPS endpoint detected (neutral score applied).".to_string(),
            vec![],
        )
    } else if tls.status == "ok" && tls.chain_valid && tls.hostname_match {
        let days = tls.days_remaining.unwrap_or(90);
        if days <= 14 {
            (
                3,
                "warn",
                "high",
                format!("TLS certificate expires in {days} day(s)."),
                vec![
                    "Renew the TLS certificate immediately and verify your ACME/Certbot auto-renewal timer.".to_string(),
                ],
            )
        } else if days <= 30 {
            (
                5,
                "warn",
                "medium",
                format!("TLS certificate expires soon ({days} day(s) remaining)."),
                vec![
                    "Confirm automated certificate renewal (Let's Encrypt / managed SSL) is scheduled before expiry.".to_string(),
                ],
            )
        } else {
            (
                7,
                "pass",
                "info",
                format!(
                    "Valid {} certificate ({days} days remaining).",
                    tls.protocol_version.as_deref().unwrap_or("TLS")
                ),
                vec![],
            )
        }
    } else {
        let mut steps = Vec::new();
        if !tls.chain_valid {
            steps.push("Install the full certificate chain (leaf + intermediate CA bundle / fullchain.pem) on your web server.".to_string());
        }
        if !tls.hostname_match {
            steps.push(format!("Re-issue the certificate with `{domain}` included in the Subject Alternative Names (SANs)."));
        }
        if tls.days_remaining.is_some_and(|d| d < 0) {
            steps.push("The certificate is expired — renew and reload your web server immediately.".to_string());
        }
        if steps.is_empty() {
            steps.push(tls.error.clone().unwrap_or_else(|| "Inspect TLS handshake errors in the SSL / TLS tab.".to_string()));
        }
        (
            0,
            "fail",
            "critical",
            tls.verification_error
                .clone()
                .or_else(|| tls.error.clone())
                .unwrap_or_else(|| "TLS certificate validation failed.".to_string()),
            steps,
        )
    };
    checks.push(HealthCheckItem {
        id: "tls_cert".to_string(),
        category: "TLS & Web".to_string(),
        title: "SSL / TLS Certificate & Chain".to_string(),
        status: tls_status.to_string(),
        severity: tls_sev.to_string(),
        detail: tls_detail,
        why_it_matters: (tls_status == "fail" || tls_status == "warn").then(|| {
            "Invalid, untrusted, or expired certificates trigger full-page browser security warnings and break API integrations.".to_string()
        }),
        remediation_steps: tls_steps,
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: tls_pts,
        max_points: 7,
    });

    // HTTPS & Redirects (5 pts)
    let has_loop = redirects.chains.iter().any(|c| c.has_loop);
    let (redir_pts, redir_status, redir_sev, redir_detail, redir_steps, redir_snippet, redir_snip_lbl) =
        if website.status != "ok" {
            (
                4,
                "info",
                "info",
                "No public website detected (neutral score applied).".to_string(),
                vec![],
                None,
                None,
            )
        } else if has_loop {
            (
                0,
                "fail",
                "critical",
                "HTTP redirect loop detected!".to_string(),
                vec![
                    "Check conflicting HTTPS/www rewrite rules between Cloudflare SSL mode (use Full Strict) and your origin server.".to_string(),
                ],
                None,
                None,
            )
        } else if !website.https {
            (
                0,
                "fail",
                "high",
                "Website responded only over unencrypted HTTP.".to_string(),
                vec![
                    "Enable HTTPS on your web server or CDN and redirect all port 80 HTTP traffic with a permanent 301 redirect.".to_string(),
                ],
                Some(format!("server {{\n  listen 80;\n  server_name {domain} www.{domain};\n  return 301 https://$host$request_uri;\n}}")),
                Some("Nginx HTTP -> HTTPS redirect".to_string()),
            )
        } else if !redirects.http_to_https && redirects.status != "unavailable" {
            (
                3,
                "warn",
                "medium",
                "HTTPS works, but HTTP does not automatically redirect to HTTPS.".to_string(),
                vec![
                    "Configure a 301 redirect from http:// to https:// so users typing the bare domain never stay on plaintext HTTP.".to_string(),
                ],
                Some(format!("server {{\n  listen 80;\n  server_name {domain} www.{domain};\n  return 301 https://$host$request_uri;\n}}")),
                Some("Nginx HTTP -> HTTPS redirect".to_string()),
            )
        } else {
            (
                5,
                "pass",
                "info",
                "HTTPS enabled with clean HTTP -> HTTPS redirection.".to_string(),
                vec![],
                None,
                None,
            )
        };
    checks.push(HealthCheckItem {
        id: "web_https_redirects".to_string(),
        category: "TLS & Web".to_string(),
        title: "HTTPS & Redirect Hygiene".to_string(),
        status: redir_status.to_string(),
        severity: redir_sev.to_string(),
        detail: redir_detail,
        why_it_matters: (redir_status == "fail" || redir_status == "warn").then(|| {
            "Plaintext HTTP allows on-path interception and session hijacking before users reach HTTPS.".to_string()
        }),
        remediation_steps: redir_steps,
        suggested_snippet: redir_snippet,
        snippet_label: redir_snip_lbl,
        reference_url: None,
        points: redir_pts,
        max_points: 5,
    });

    // HTTP Security Headers (5 pts)
    if website.status == "ok" {
        let missing_headers: Vec<&str> = website
            .security_headers
            .iter()
            .filter(|h| !h.present)
            .map(|h| h.name.as_str())
            .collect();
        let present_count = website.security_headers.iter().filter(|h| h.present).count();
        let header_pts = match present_count {
            5..=6 => 5,
            3..=4 => 4,
            1..=2 => 2,
            _ => 0,
        };
        let (hdr_lbl, hdr_snip) = if !missing_headers.is_empty() {
            let (l, s) = build_missing_headers_snippet(&missing_headers, website, network);
            (Some(l), Some(s))
        } else {
            (None, None)
        };
        checks.push(HealthCheckItem {
            id: "web_headers".to_string(),
            category: "TLS & Web".to_string(),
            title: "HTTP Security Headers".to_string(),
            status: if present_count >= 4 { "pass" } else { "warn" }.to_string(),
            severity: if present_count <= 1 {
                "medium"
            } else if present_count < 4 {
                "low"
            } else {
                "info"
            }
            .to_string(),
            detail: if missing_headers.is_empty() {
                format!("All {} recommended security headers present.", website.security_headers.len())
            } else {
                format!(
                    "{present_count}/{} present — missing: {}.",
                    website.security_headers.len(),
                    missing_headers.join(", ")
                )
            },
            why_it_matters: (!missing_headers.is_empty()).then(|| {
                "Security headers mitigate XSS, clickjacking, MIME-sniffing, and TLS downgrade attacks at the browser level.".to_string()
            }),
            remediation_steps: if !missing_headers.is_empty() {
                vec![
                    format!("Add the {} missing HTTP response header(s) to your web server or CDN edge configuration.", missing_headers.len()),
                    "Test Content-Security-Policy in `Content-Security-Policy-Report-Only` first if your site loads third-party scripts.".to_string(),
                ]
            } else {
                vec![]
            },
            suggested_snippet: hdr_snip,
            snippet_label: hdr_lbl,
            reference_url: Some("https://owasp.org/www-project-secure-headers/".to_string()),
            points: header_pts,
            max_points: 5,
        });

        // Web Hygiene, Cookies, CORS & Exposures (4 pts)
        let audit = website.security_audit.as_ref();
        let exposed_paths: Vec<&str> = audit
            .map(|a| {
                a.files
                    .iter()
                    .filter(|f| f.status == "exposed")
                    .map(|f| f.path.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let bad_cookies: Vec<&str> = audit
            .map(|a| {
                a.cookies
                    .iter()
                    .filter(|c| !c.issues.is_empty())
                    .map(|c| c.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        let cors_bad = audit.and_then(|a| a.cors_issue.as_ref()).is_some();
        let mixed_cnt = audit.map(|a| a.mixed_content_urls.len()).unwrap_or(0);
        let has_sec_txt = audit
            .map(|a| {
                a.files
                    .iter()
                    .any(|f| f.path == "/.well-known/security.txt" && f.status == "found")
            })
            .unwrap_or(false);

        let (hyg_pts, hyg_status, hyg_sev, hyg_detail, mut hyg_steps, hyg_snip, hyg_lbl) =
            if !exposed_paths.is_empty() {
                (
                    0,
                    "fail",
                    "critical",
                    format!("CRITICAL: Sensitive path(s) exposed publicly: {}.", exposed_paths.join(", ")),
                    vec![
                        format!("Immediately block public HTTP access to {} in your web server/CDN and rotate any credentials/keys that were exposed.", exposed_paths.join(", ")),
                        "Ensure `.git` and `.env` directories sit outside the web document root.".to_string(),
                    ],
                    Some("location ~ /\\.(git|env) {\n  deny all;\n  return 404;\n}".to_string()),
                    Some("Nginx block rule for dotfiles".to_string()),
                )
            } else if cors_bad || mixed_cnt > 0 || !bad_cookies.is_empty() {
                let mut problems = Vec::new();
                let mut steps = Vec::new();
                if cors_bad {
                    problems.push("permissive CORS wildcard with credentials".to_string());
                    steps.push("Replace `Access-Control-Allow-Origin: *` with an explicit origin allowlist when `Allow-Credentials: true` is set.".to_string());
                }
                if mixed_cnt > 0 {
                    problems.push(format!("{mixed_cnt} mixed-content HTTP asset(s)"));
                    steps.push("Update `http://` script and stylesheet URLs to `https://`.".to_string());
                }
                if !bad_cookies.is_empty() {
                    problems.push(format!("{} cookie(s) missing Secure/HttpOnly/SameSite", bad_cookies.len()));
                    steps.push(format!("Set `Secure; HttpOnly; SameSite=Lax` on cookies ({}).", bad_cookies.join(", ")));
                }
                (
                    2,
                    "warn",
                    "medium",
                    format!("Web hygiene issues: {}.", problems.join("; ")),
                    steps,
                    None,
                    None,
                )
            } else if !has_sec_txt {
                (
                    3,
                    "warn",
                    "low",
                    "No sensitive exposures or cookie issues; missing /.well-known/security.txt.".to_string(),
                    vec![
                        "Publish an RFC 9116 `/.well-known/security.txt` so security researchers know how to report vulnerabilities responsibly.".to_string(),
                    ],
                    Some(format!("Contact: mailto:security@{apex}\nExpires: 2027-12-31T23:59:59Z\nPreferred-Languages: en")),
                    Some("/.well-known/security.txt template".to_string()),
                )
            } else {
                (
                    4,
                    "pass",
                    "info",
                    "No exposed dotfiles, clean cookies/CORS, and security.txt published.".to_string(),
                    vec![],
                    None,
                    None,
                )
            };

        if !exposed_paths.is_empty() && !has_sec_txt {
            hyg_steps.push("Consider also publishing /.well-known/security.txt once exposures are resolved.".to_string());
        }

        checks.push(HealthCheckItem {
            id: "web_hygiene".to_string(),
            category: "TLS & Web".to_string(),
            title: "Web Exposures, Cookies & security.txt".to_string(),
            status: hyg_status.to_string(),
            severity: hyg_sev.to_string(),
            detail: hyg_detail,
            why_it_matters: (hyg_status != "pass").then(|| {
                "Exposed `.env` or `.git` files leak source code and production secrets; weak cookie flags allow XSS session theft.".to_string()
            }),
            remediation_steps: hyg_steps,
            suggested_snippet: hyg_snip,
            snippet_label: hyg_lbl,
            reference_url: Some("https://securitytxt.org/".to_string()),
            points: hyg_pts,
            max_points: 4,
        });
    } else {
        checks.push(HealthCheckItem {
            id: "web_hygiene".to_string(),
            category: "TLS & Web".to_string(),
            title: "Web Exposures, Cookies & security.txt".to_string(),
            status: "info".to_string(),
            severity: "info".to_string(),
            detail: "No public website detected (neutral score applied).".to_string(),
            why_it_matters: None,
            remediation_steps: vec![],
            suggested_snippet: None,
            snippet_label: None,
            reference_url: None,
            points: 3,
            max_points: 4,
        });
    }

    // =========================================================
    // 5. INFRASTRUCTURE & REGISTRATION (14 pts: 5 + 3 + 3 + 3)
    // =========================================================
    let high_risk_ports: Vec<String> = ports
        .ports
        .iter()
        .filter(|p| p.status == "open" && p.risk_level == "high")
        .map(|p| format!("{}/{}", p.port, p.service))
        .collect();
    let (port_pts, port_status, port_sev, port_detail, port_steps) = if !high_risk_ports.is_empty() {
        (
            0,
            "fail",
            "high",
            format!("High-risk service port(s) publicly open: {}.", high_risk_ports.join(", ")),
            vec![
                format!("Restrict public internet access to {} using a host firewall / security group / VPN allowlist.", high_risk_ports.join(", ")),
                "Bind internal databases and caches (MySQL/Postgres/Redis/MongoDB) to 127.0.0.1 or a private VPC interface.".to_string(),
            ],
        )
    } else {
        (
            5,
            "pass",
            "info",
            if ports.open_count > 0 {
                format!("{} open port(s) detected, none classified high-risk.", ports.open_count)
            } else {
                "No high-risk ports exposed on primary host.".to_string()
            },
            vec![],
        )
    };
    checks.push(HealthCheckItem {
        id: "infra_ports".to_string(),
        category: "Infrastructure".to_string(),
        title: "Exposed Service Ports".to_string(),
        status: port_status.to_string(),
        severity: port_sev.to_string(),
        detail: port_detail,
        why_it_matters: (!high_risk_ports.is_empty()).then(|| {
            "Publicly exposed database, remote desktop, or plaintext management ports are prime targets for automated credential stuffing and ransomware.".to_string()
        }),
        remediation_steps: port_steps,
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: port_pts,
        max_points: 5,
    });

    let takeover_subs: Vec<String> = subdomains
        .subdomains
        .iter()
        .filter_map(|s| {
            s.takeover_risk
                .as_ref()
                .map(|t| format!("{} -> {} ({})", s.subdomain, t.cname_target, t.provider))
        })
        .collect();
    checks.push(HealthCheckItem {
        id: "infra_takeover".to_string(),
        category: "Infrastructure".to_string(),
        title: "Dangling Subdomain / Takeover Risk".to_string(),
        status: if takeover_subs.is_empty() { "pass" } else { "fail" }.to_string(),
        severity: if takeover_subs.is_empty() { "info" } else { "critical" }.to_string(),
        detail: if takeover_subs.is_empty() {
            "No dangling cloud CNAME takeover signatures detected.".to_string()
        } else {
            format!("Potential subdomain takeover(s): {}.", takeover_subs.join("; "))
        },
        why_it_matters: (!takeover_subs.is_empty()).then(|| {
            "An attacker can register the unclaimed cloud app/bucket and serve malicious content or steal scoped cookies on your subdomain.".to_string()
        }),
        remediation_steps: if takeover_subs.is_empty() {
            vec![]
        } else {
            vec![
                "Remove the dangling CNAME record(s) from your DNS zone immediately, or re-claim the external cloud resource.".to_string(),
                "Inspect the Subdomains tab for exact provider evidence per affected host.".to_string(),
            ]
        },
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: if takeover_subs.is_empty() { 3 } else { 0 },
        max_points: 3,
    });

    let (expiry_pts, expiry_status, expiry_sev, expiry_detail, expiry_steps) = match whois.days_until_expiry {
        Some(days) if days < 0 => (
            0,
            "fail",
            "critical",
            format!("Domain expired {} day(s) ago.", days.abs()),
            vec![format!("Renew the domain immediately at your registrar{reg_hint} before it enters redemption or drops.")],
        ),
        Some(days) if days <= 30 => (
            1,
            "warn",
            "high",
            format!("Domain expires soon ({days} day(s) left)."),
            vec![format!("Renew the domain and enable auto-renew at your registrar{reg_hint}.")],
        ),
        Some(days) => (
            3,
            "pass",
            "info",
            format!("Valid registration ({days} days remaining)."),
            vec![],
        ),
        None if whois.status == "not_found" => (
            0,
            "fail",
            "high",
            "No WHOIS registration record found.".to_string(),
            vec!["Confirm domain spelling and registrar registration status.".to_string()],
        ),
        None => (
            2,
            "info",
            "info",
            "WHOIS expiry date unavailable from registry.".to_string(),
            vec![],
        ),
    };
    checks.push(HealthCheckItem {
        id: "reg_expiry".to_string(),
        category: "Infrastructure".to_string(),
        title: "Domain Expiration".to_string(),
        status: expiry_status.to_string(),
        severity: expiry_sev.to_string(),
        detail: expiry_detail,
        why_it_matters: (expiry_status != "pass" && expiry_status != "info").then(|| {
            "An expired domain stops resolving worldwide and can be auctioned or registered by an attacker.".to_string()
        }),
        remediation_steps: expiry_steps,
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: expiry_pts,
        max_points: 3,
    });

    let has_hold = whois.statuses.iter().any(|s| {
        let low = s.to_ascii_lowercase();
        low.contains("clienthold") || low.contains("serverhold")
    });
    let has_transfer_lock = whois
        .statuses
        .iter()
        .any(|s| s.to_ascii_lowercase().contains("transferprohibited"));
    let (epp_pts, epp_status, epp_sev, epp_detail, epp_steps) = if has_hold {
        (
            0,
            "fail",
            "critical",
            "Registry/Registrar HOLD status active — domain may not resolve.".to_string(),
            vec![
                format!("Contact your registrar{reg_hint} immediately to clear verification, billing, or abuse holds."),
            ],
        )
    } else if has_transfer_lock {
        (
            3,
            "pass",
            "info",
            "Transfer lock active; no hold flags present.".to_string(),
            vec![],
        )
    } else if whois.status == "ok" {
        (
            2,
            "warn",
            "low",
            "Transfer lock (clientTransferProhibited) not advertised in WHOIS.".to_string(),
            vec![
                format!("Enable Registrar Lock / Domain Transfer Lock in your registrar{reg_hint} control panel to protect against unauthorized hijacking."),
            ],
        )
    } else {
        (2, "info", "info", "EPP status flags unavailable.".to_string(), vec![])
    };
    checks.push(HealthCheckItem {
        id: "reg_status".to_string(),
        category: "Infrastructure".to_string(),
        title: "EPP Lock & Hold Status".to_string(),
        status: epp_status.to_string(),
        severity: epp_sev.to_string(),
        detail: epp_detail,
        why_it_matters: (has_hold || (!has_transfer_lock && whois.status == "ok")).then(|| {
            "Registrar transfer locks block unauthorized domain transfers; EPP Hold flags remove the domain from TLD DNS entirely.".to_string()
        }),
        remediation_steps: epp_steps,
        suggested_snippet: None,
        snippet_label: None,
        reference_url: None,
        points: epp_pts,
        max_points: 3,
    });

    let score: u32 = checks.iter().map(|c| c.points).sum();
    let mut grade = match score {
        93..=100 => "A+",
        85..=92 => "A",
        75..=84 => "B",
        65..=74 => "C",
        50..=64 => "D",
        _ => "F",
    };

    if blacklists_listed >= 2 || !takeover_subs.is_empty() {
        grade = "F";
    } else if blacklists_listed == 1 && !matches!(grade, "D" | "F") {
        grade = "D";
    }

    let spam_status = if blacklists_listed > 0 {
        "listed"
    } else if has_policy_hit
        || matches!(security.spf.status.as_str(), "fail" | "missing")
        || matches!(security.dmarc.status.as_str(), "fail" | "missing")
    {
        "caution"
    } else {
        "clean"
    };

    let spam_summary = if blacklists_listed > 0 {
        format!("Listed on {blacklists_listed} of {blacklists_checked} checked blacklists.")
    } else if has_policy_hit {
        format!("No active spam blacklists ({blacklists_checked} checked), but a policy/fresh-domain flag was raised.")
    } else if spam_status == "caution" {
        format!("Clean on {blacklists_checked} blacklists, but SPF/DMARC protection is incomplete.")
    } else {
        format!("Clean across all {blacklists_checked} domain & IP blacklists with SPF/DMARC protection.")
    };

    let has_critical_fail = checks
        .iter()
        .any(|c| c.status == "fail" && c.severity == "critical");

    let overall_status = if blacklists_listed > 0 || score < 55 || has_hold || has_critical_fail {
        "at_risk"
    } else if score < 80 || spam_status == "caution" {
        "caution"
    } else {
        "healthy"
    };

    let summary = match overall_status {
        "healthy" => format!("Domain is healthy and clean ({score}/100, Grade {grade})."),
        "caution" => format!(
            "Domain has configuration or hygiene improvements available ({score}/100, Grade {grade})."
        ),
        _ => format!(
            "Domain has critical security, reputation, or exposure risks ({score}/100, Grade {grade})."
        ),
    };

    DomainHealthReport {
        score,
        grade: grade.to_string(),
        overall_status: overall_status.to_string(),
        summary,
        spam_status: spam_status.to_string(),
        spam_summary,
        blacklists_checked,
        blacklists_listed,
        blacklists_blocked,
        checked_ips,
        domain_blacklists,
        ip_blacklists,
        checks,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        BimiCheck, CookieAuditItem, DaneCheck, DkimCheck, DmarcCheck, DnssecCheck, IpNetworkInfo,
        MtaStsCheck, PortScanItem, SecurityHeaderStatus, SpfCheck, SubdomainItem, TakeoverFinding,
        TlsCertInfo, TlsRptCheck, WebFileCheck, WebSecurityAudit,
    };

    #[test]
    fn test_reverse_ipv4() {
        assert_eq!(reverse_ipv4(Ipv4Addr::new(192, 0, 2, 44)), "44.2.0.192");
        assert_eq!(reverse_ipv4(Ipv4Addr::new(127, 0, 0, 2)), "2.0.0.127");
    }

    #[test]
    fn test_interpret_dnsbl_codes() {
        let (st, _) = interpret_dnsbl_codes("dbl.spamhaus.org", &[Ipv4Addr::new(127, 0, 1, 4)]);
        assert_eq!(st, "listed");

        let (st_blk, _) =
            interpret_dnsbl_codes("zen.spamhaus.org", &[Ipv4Addr::new(127, 255, 255, 254)]);
        assert_eq!(st_blk, "blocked");

        let (st_pol, _) = interpret_dnsbl_codes("zen.spamhaus.org", &[Ipv4Addr::new(127, 0, 0, 10)]);
        assert_eq!(st_pol, "policy");

        let (st_both, _) = interpret_dnsbl_codes(
            "zen.spamhaus.org",
            &[Ipv4Addr::new(127, 0, 0, 2), Ipv4Addr::new(127, 0, 0, 10)],
        );
        assert_eq!(st_both, "listed");

        let (st_surbl_blk, _) =
            interpret_dnsbl_codes("multi.surbl.org", &[Ipv4Addr::new(127, 0, 0, 1)]);
        assert_eq!(st_surbl_blk, "blocked");

        let (st_surbl_hit, detail) =
            interpret_dnsbl_codes("multi.surbl.org", &[Ipv4Addr::new(127, 0, 0, 24)]);
        assert_eq!(st_surbl_hit, "listed");
        assert!(detail.unwrap().contains("Phishing"));
    }

    fn base_security(spf_status: &str, dmarc_status: &str) -> SecurityReport {
        SecurityReport {
            spf: SpfCheck {
                status: spf_status.to_string(),
                summary: "spf".to_string(),
                raw_record: Some("v=spf1 mx -all".to_string()),
                mechanisms: vec!["mx".to_string(), "-all".to_string()],
                all_qualifier: Some("-all".to_string()),
                dns_lookup_count: 1,
                recursive_lookup_count: 1,
                lookup_tree: vec![],
                flattened_ips: vec![],
                flattened_record: None,
                duplicate_includes: vec![],
                issues: vec![],
            },
            dmarc: DmarcCheck {
                status: dmarc_status.to_string(),
                summary: "dmarc".to_string(),
                raw_record: Some("v=DMARC1; p=reject; rua=mailto:dmarc@example.com".to_string()),
                policy: Some("reject".to_string()),
                subdomain_policy: None,
                pct: Some(100),
                rua: vec!["mailto:dmarc@example.com".to_string()],
                ruf: vec![],
                adkim: None,
                aspf: None,
                issues: vec![],
            },
            dkim: DkimCheck {
                status: "pass".to_string(),
                summary: "dkim".to_string(),
                checked_selectors: vec![],
                results: vec![],
                issues: vec![],
            },
            dnssec: DnssecCheck {
                status: "pass".to_string(),
                summary: "dnssec".to_string(),
                ds_records: vec![],
                dnskey_records: vec![],
                validated: true,
                validation_error: None,
                issues: vec![],
            },
            mta_sts: MtaStsCheck {
                status: "pass".to_string(),
                summary: "mta-sts ok".to_string(),
                dns_record: None,
                policy_id: None,
                policy_fetched: true,
                mode: Some("enforce".to_string()),
                max_age: Some(604800),
                mx_patterns: vec!["mx.example.com".to_string()],
                raw_policy: None,
                issues: vec![],
            },
            tls_rpt: TlsRptCheck {
                status: "pass".to_string(),
                summary: "tls-rpt ok".to_string(),
                raw_record: None,
                rua: vec!["mailto:tls@example.com".to_string()],
                issues: vec![],
            },
            bimi: BimiCheck {
                status: "missing".to_string(),
                summary: "missing".to_string(),
                raw_record: None,
                logo_url: None,
                authority_url: None,
                issues: vec![],
            },
            dane: DaneCheck {
                status: "missing".to_string(),
                summary: "missing".to_string(),
                mx_checked: vec![],
                records: vec![],
                dnssec_required_met: true,
                issues: vec![],
            },
        }
    }

    fn base_whois() -> WhoisInfo {
        WhoisInfo {
            status: "ok".to_string(),
            queried_domain: "example.com".to_string(),
            servers_queried: vec![],
            latency_ms: 10,
            registrar: Some("Example Registrar".to_string()),
            registrar_url: None,
            registrar_iana_id: None,
            created_date: None,
            updated_date: None,
            expiry_date: Some("2030-01-01T00:00:00Z".to_string()),
            days_until_expiry: Some(365),
            registrant_org: None,
            registrant_country: None,
            abuse_email: None,
            abuse_phone: None,
            dnssec: None,
            statuses: vec!["clientTransferProhibited".to_string()],
            name_servers: vec![],
            raw_text: String::new(),
            error: None,
        }
    }

    fn base_website(with_all_headers: bool) -> WebsiteInfo {
        WebsiteInfo {
            status: "ok".to_string(),
            url: Some("https://example.com".to_string()),
            final_url: Some("https://example.com/".to_string()),
            http_status: Some(200),
            https: true,
            http3_supported: false,
            alt_svc: None,
            latency_ms: 50,
            title: None,
            description: None,
            generator: None,
            server: Some("nginx/1.26.0".to_string()),
            powered_by: None,
            content_type: None,
            technologies: vec![],
            wordpress_plugins: vec![],
            security_headers: vec![
                SecurityHeaderStatus {
                    name: "Strict-Transport-Security".to_string(),
                    present: with_all_headers,
                    value: with_all_headers.then(|| "max-age=31536000".to_string()),
                },
                SecurityHeaderStatus {
                    name: "Content-Security-Policy".to_string(),
                    present: with_all_headers,
                    value: with_all_headers.then(|| "default-src 'self'".to_string()),
                },
                SecurityHeaderStatus {
                    name: "X-Frame-Options".to_string(),
                    present: with_all_headers,
                    value: with_all_headers.then(|| "DENY".to_string()),
                },
                SecurityHeaderStatus {
                    name: "X-Content-Type-Options".to_string(),
                    present: with_all_headers,
                    value: with_all_headers.then(|| "nosniff".to_string()),
                },
                SecurityHeaderStatus {
                    name: "Referrer-Policy".to_string(),
                    present: with_all_headers,
                    value: with_all_headers.then(|| "strict-origin".to_string()),
                },
            ],
            response_headers: vec![],
            script_urls: vec![],
            stylesheet_urls: vec![],
            security_audit: Some(WebSecurityAudit {
                cookies: vec![CookieAuditItem {
                    name: "prefs".to_string(),
                    secure: true,
                    http_only: true,
                    same_site: Some("lax".to_string()),
                    issues: vec![],
                }],
                cors_acao: None,
                cors_acac: false,
                cors_issue: None,
                mixed_content_urls: vec![],
                files: vec![WebFileCheck {
                    path: "/.well-known/security.txt".to_string(),
                    label: "Security Policy".to_string(),
                    category: "security".to_string(),
                    status: "found".to_string(),
                    http_status: Some(200),
                    summary: "ok".to_string(),
                    preview: None,
                }],
                exposed_count: 0,
            }),
            error: None,
        }
    }

    fn base_tls() -> TlsReport {
        TlsReport {
            status: "ok".to_string(),
            host: "example.com".to_string(),
            port: 443,
            starttls: None,
            protocol_version: Some("TLS 1.3".to_string()),
            cipher_suite: None,
            chain_valid: true,
            hostname_match: true,
            verification_error: None,
            days_remaining: Some(80),
            handshake_ms: 25,
            certificates: vec![TlsCertInfo {
                subject: "CN=example.com".to_string(),
                common_name: Some("example.com".to_string()),
                issuer: "O=Let's Encrypt".to_string(),
                issuer_org: Some("Let's Encrypt".to_string()),
                sans: vec!["example.com".to_string()],
                not_before: String::new(),
                not_after: String::new(),
                days_remaining: 80,
                serial_hex: String::new(),
                signature_algorithm: String::new(),
                public_key_algorithm: String::new(),
                public_key_bits: Some(256),
                sha256_fingerprint: String::new(),
                is_ca: false,
                is_self_signed: false,
            }],
            error: None,
        }
    }

    fn base_redirects() -> RedirectReport {
        RedirectReport {
            status: "ok".to_string(),
            canonical_url: Some("https://example.com/".to_string()),
            http_to_https: true,
            canonical_consistent: true,
            hsts_present: true,
            hsts_max_age: Some(31536000),
            hsts_include_subdomains: false,
            hsts_preload: false,
            chains: vec![],
            waterfall: None,
            issues: vec![],
            latency_ms: 40,
            error: None,
        }
    }

    fn base_network() -> NetworkReport {
        NetworkReport {
            status: "ok".to_string(),
            latency_ms: 20,
            ips: vec![IpNetworkInfo {
                ip: "93.184.216.34".to_string(),
                ip_version: "IPv4".to_string(),
                roles: vec!["Web / Apex".to_string(), "Mail (MX)".to_string()],
                hostnames: vec!["example.com".to_string()],
                ptr_records: vec!["mx.example.com".to_string()],
                asn: Some(15133),
                as_org: Some("Edgecast".to_string()),
                cidr: Some("93.184.216.0/24".to_string()),
                country: Some("US".to_string()),
                country_code: Some("US".to_string()),
                region: None,
                city: None,
                isp: None,
                provider_type: "Network".to_string(),
                provider_name: None,
                is_anycast_cdn: false,
                rpki_status: Some("valid".to_string()),
                rpki_detail: None,
            }],
            unique_asns: 1,
            countries: vec!["US".to_string()],
            cdn_detected: None,
            error: None,
        }
    }

    fn base_subdomains() -> SubdomainDiscoveryReport {
        SubdomainDiscoveryReport {
            apex_domain: "example.com".to_string(),
            total_found: 1,
            live_count: 1,
            ct_only_count: 0,
            takeover_count: 0,
            wildcard_detected: false,
            wildcard_ips: vec![],
            ct_status: "ok".to_string(),
            ct_note: None,
            passive_sources: vec![],
            probe_count: 10,
            latency_ms: 30,
            subdomains: vec![],
        }
    }

    fn base_ports() -> PortScanReport {
        PortScanReport {
            target_host: "example.com".to_string(),
            target_ip: Some("93.184.216.34".to_string()),
            available_ips: vec![],
            open_count: 2,
            closed_count: 10,
            filtered_count: 0,
            total_checked: 12,
            latency_ms: 50,
            ports: vec![PortScanItem {
                port: 443,
                service: "HTTPS".to_string(),
                category: "Web".to_string(),
                status: "open".to_string(),
                latency_ms: 5,
                banner: None,
                risk_level: "normal".to_string(),
                note: None,
            }],
            error: None,
        }
    }

    #[test]
    fn test_compute_health_report_100_pts_and_remediation_snippets() {
        let clean_entry = BlacklistEntry {
            list_name: "Spamhaus DBL".to_string(),
            zone: "dbl.spamhaus.org".to_string(),
            target: "example.com".to_string(),
            target_role: "Domain".to_string(),
            status: "clean".to_string(),
            return_codes: vec![],
            detail: None,
            delist_url: Some("https://check.spamhaus.org/".to_string()),
            latency_ms: 12,
        };

        let healthy = compute_health_report(
            "example.com",
            BlacklistScanBundle {
                domain_blacklists: vec![clean_entry.clone()],
                ip_blacklists: vec![clean_entry],
                checked_ips: vec!["93.184.216.34".to_string()],
                ns_count: 2,
                mx_hosts: vec!["aspmx.l.google.com".to_string()],
                caa_records: vec!["0 issue \"letsencrypt.org\"".to_string()],
            },
            &[],
            &base_security("pass", "pass"),
            &base_tls(),
            &base_redirects(),
            &base_network(),
            &base_whois(),
            &base_website(true),
            &base_subdomains(),
            &base_ports(),
        );
        let max_sum: u32 = healthy.checks.iter().map(|c| c.max_points).sum();
        assert_eq!(max_sum, 100);
        assert_eq!(healthy.score, 100);
        assert_eq!(healthy.grade, "A+");
        assert_eq!(healthy.overall_status, "healthy");
        assert_eq!(healthy.spam_status, "clean");

        // Test actionable remediation snippets when headers/CAA/DMARC/takeover fail
        let mut subs = base_subdomains();
        subs.takeover_count = 1;
        subs.subdomains.push(SubdomainItem {
            subdomain: "blog.example.com".to_string(),
            live: true,
            a_records: vec![],
            aaaa_records: vec![],
            cname: Some("oldapp.herokuapp.com".to_string()),
            sources: vec![],
            takeover_risk: Some(TakeoverFinding {
                provider: "Heroku".to_string(),
                cname_target: "oldapp.herokuapp.com".to_string(),
                confidence: "high".to_string(),
                evidence: "No such app".to_string(),
                remediation: "Remove CNAME".to_string(),
            }),
        });

        let risky = compute_health_report(
            "example.com",
            BlacklistScanBundle {
                domain_blacklists: vec![],
                ip_blacklists: vec![],
                checked_ips: vec![],
                ns_count: 2,
                mx_hosts: vec![],
                caa_records: vec![],
            },
            &[],
            &base_security("missing", "missing"),
            &base_tls(),
            &base_redirects(),
            &base_network(),
            &base_whois(),
            &base_website(false),
            &subs,
            &base_ports(),
        );
        assert_eq!(risky.grade, "F");
        assert_eq!(risky.overall_status, "at_risk");
        let hdr_chk = risky.checks.iter().find(|c| c.id == "web_headers").unwrap();
        assert!(hdr_chk
            .suggested_snippet
            .as_deref()
            .unwrap()
            .contains("add_header Strict-Transport-Security"));
        let caa_chk = risky.checks.iter().find(|c| c.id == "dns_caa").unwrap();
        assert!(caa_chk
            .suggested_snippet
            .as_deref()
            .unwrap()
            .contains("letsencrypt.org"));
    }
}
