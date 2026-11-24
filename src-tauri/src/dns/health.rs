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
    BlacklistEntry, DomainHealthReport, HealthCheckItem, PropagationRow, ResolverResult,
    SecurityReport, WebsiteInfo, WhoisInfo,
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
            ("blocked", Some("Blocked/unrecognized Spamhaus DBL response".to_string()))
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
        return ("blocked", Some("Blocked/unrecognized Spamhaus response".to_string()));
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
            latency_ms: start.elapsed().as_millis() as u64,
        },
    }
}

async fn collect_target_ips(
    domain: &str,
    resolvers: &[ResolverResult],
    dnsbl_resolver: &TokioResolver,
) -> (Vec<(Ipv4Addr, String)>, Vec<String>) {
    let mut web_ips: Vec<Ipv4Addr> = Vec::new();
    let mut mx_hosts: Vec<String> = Vec::new();
    let mut ns_records: Vec<String> = Vec::new();

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
                            .or_else(|| rec.value.split_whitespace().nth(1).map(|s| s.to_string()));
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
                    let clean = mx.exchange().to_string().trim_end_matches('.').to_ascii_lowercase();
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

    (targets, ns_records)
}

pub fn compute_health_report(
    domain_blacklists: Vec<BlacklistEntry>,
    ip_blacklists: Vec<BlacklistEntry>,
    checked_ips: Vec<String>,
    ns_count: usize,
    propagation: &[PropagationRow],
    security: &SecurityReport,
    whois: &WhoisInfo,
    website: &WebsiteInfo,
) -> DomainHealthReport {
    let blacklists_checked = domain_blacklists.len() + ip_blacklists.len();
    let domain_listed = domain_blacklists
        .iter()
        .filter(|b| b.status == "listed")
        .count();
    let ip_listed = ip_blacklists.iter().filter(|b| b.status == "listed").count();
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

    // 1. Reputation (35 pts)
    let domain_rep_pts = if domain_listed > 0 {
        0
    } else if domain_blacklists.iter().any(|b| b.status == "policy") {
        12
    } else {
        20
    };
    checks.push(HealthCheckItem {
        id: "domain_rhsbl".to_string(),
        category: "Reputation".to_string(),
        title: "Domain Blacklists (RHSBL)".to_string(),
        status: if domain_listed > 0 {
            "fail"
        } else if domain_rep_pts < 20 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        detail: if domain_listed > 0 {
            format!("Domain listed on {domain_listed} domain reputation list(s).")
        } else if domain_rep_pts < 20 {
            "Domain flagged on fresh/policy list (newly registered caution).".to_string()
        } else {
            format!("Clean across {} domain blacklists.", domain_blacklists.len())
        },
        points: domain_rep_pts,
        max_points: 20,
    });

    let ip_rep_pts = if ip_listed > 0 {
        0
    } else if ip_blacklists.iter().any(|b| b.status == "policy") {
        10
    } else {
        15
    };
    checks.push(HealthCheckItem {
        id: "ip_dnsbl".to_string(),
        category: "Reputation".to_string(),
        title: "Web & Mail IP Blacklists (DNSBL)".to_string(),
        status: if ip_listed > 0 {
            "fail"
        } else if ip_blacklists.is_empty() {
            "info"
        } else if ip_rep_pts < 15 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        detail: if ip_blacklists.is_empty() {
            "No public IPv4 A or MX host IPs found to check.".to_string()
        } else if ip_listed > 0 {
            format!("Active listing detected across {ip_listed} IP blacklist check(s).")
        } else if ip_rep_pts < 15 {
            "IP listed on a dynamic/policy block list (PBL).".to_string()
        } else {
            format!(
                "Clean across {} checks on {} IP(s).",
                ip_blacklists.len(),
                checked_ips.len()
            )
        },
        points: ip_rep_pts,
        max_points: 15,
    });

    // 2. DNS (20 pts)
    let ns_pts = if ns_count >= 2 {
        8
    } else if ns_count == 1 {
        3
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
        detail: if ns_count >= 2 {
            format!("{ns_count} authoritative nameservers configured.")
        } else if ns_count == 1 {
            "Only 1 nameserver found (single point of failure).".to_string()
        } else {
            "No NS records resolved.".to_string()
        },
        points: ns_pts,
        max_points: 8,
    });

    let divergent_count = propagation.iter().filter(|p| p.status == "divergent").count();
    let error_count = propagation
        .iter()
        .filter(|p| p.status == "partial_error")
        .count();
    let prop_pts = if divergent_count == 0 && error_count == 0 {
        7
    } else if divergent_count == 0 {
        5
    } else {
        3
    };
    checks.push(HealthCheckItem {
        id: "dns_propagation".to_string(),
        category: "DNS".to_string(),
        title: "Resolver Consensus".to_string(),
        status: if divergent_count > 0 {
            "warn"
        } else if error_count > 0 {
            "warn"
        } else {
            "pass"
        }
        .to_string(),
        detail: if divergent_count > 0 {
            format!("{divergent_count} record type(s) returned differing answers across resolvers.")
        } else if error_count > 0 {
            "Some resolvers encountered transient errors.".to_string()
        } else {
            "All queried resolvers agree on DNS responses.".to_string()
        },
        points: prop_pts,
        max_points: 7,
    });

    let dnssec_pts = match security.dnssec.status.as_str() {
        "pass" => 5,
        "warn" | "unsigned" => 2,
        _ => 0,
    };
    checks.push(HealthCheckItem {
        id: "dns_dnssec".to_string(),
        category: "DNS".to_string(),
        title: "DNSSEC Validation".to_string(),
        status: match security.dnssec.status.as_str() {
            "pass" => "pass",
            "fail" => "fail",
            _ => "warn",
        }
        .to_string(),
        detail: security.dnssec.summary.clone(),
        points: dnssec_pts,
        max_points: 5,
    });

    // 3. Email (20 pts)
    let spf_pts = match security.spf.status.as_str() {
        "pass" => 8,
        "warn" => 5,
        _ => 0,
    };
    checks.push(HealthCheckItem {
        id: "email_spf".to_string(),
        category: "Email".to_string(),
        title: "SPF Record".to_string(),
        status: if security.spf.status == "missing" {
            "warn"
        } else {
            security.spf.status.as_str()
        }
        .to_string(),
        detail: security.spf.summary.clone(),
        points: spf_pts,
        max_points: 8,
    });

    let dmarc_pts = match security.dmarc.status.as_str() {
        "pass" => 8,
        "warn" => 5,
        _ => 0,
    };
    checks.push(HealthCheckItem {
        id: "email_dmarc".to_string(),
        category: "Email".to_string(),
        title: "DMARC Policy".to_string(),
        status: if security.dmarc.status == "missing" {
            "warn"
        } else {
            security.dmarc.status.as_str()
        }
        .to_string(),
        detail: security.dmarc.summary.clone(),
        points: dmarc_pts,
        max_points: 8,
    });

    let dkim_pts = if security.dkim.status == "pass" { 4 } else { 2 };
    checks.push(HealthCheckItem {
        id: "email_dkim".to_string(),
        category: "Email".to_string(),
        title: "DKIM Signing".to_string(),
        status: if security.dkim.status == "pass" {
            "pass"
        } else {
            "info"
        }
        .to_string(),
        detail: security.dkim.summary.clone(),
        points: dkim_pts,
        max_points: 4,
    });

    // 4. Registration (10 pts)
    let (expiry_pts, expiry_status, expiry_detail) = match whois.days_until_expiry {
        Some(days) if days < 0 => (0, "fail", format!("Domain expired {} day(s) ago.", days.abs())),
        Some(days) if days <= 30 => (2, "warn", format!("Domain expires soon ({days} day(s) left).")),
        Some(days) => (5, "pass", format!("Valid registration ({days} days remaining).")),
        None if whois.status == "not_found" => (0, "fail", "No WHOIS registration record found.".to_string()),
        None => (3, "info", "WHOIS expiry date unavailable from registry.".to_string()),
    };
    checks.push(HealthCheckItem {
        id: "reg_expiry".to_string(),
        category: "Registration".to_string(),
        title: "Domain Expiration".to_string(),
        status: expiry_status.to_string(),
        detail: expiry_detail,
        points: expiry_pts,
        max_points: 5,
    });

    let has_hold = whois.statuses.iter().any(|s| {
        let low = s.to_ascii_lowercase();
        low.contains("clienthold") || low.contains("serverhold")
    });
    let has_transfer_lock = whois
        .statuses
        .iter()
        .any(|s| s.to_ascii_lowercase().contains("transferprohibited"));
    let (epp_pts, epp_status, epp_detail) = if has_hold {
        (0, "fail", "Registry/Registrar HOLD status active — domain may not resolve.".to_string())
    } else if has_transfer_lock {
        (5, "pass", "Transfer lock active; no hold flags present.".to_string())
    } else if whois.status == "ok" {
        (4, "info", "No hold flags; transfer lock not advertised in WHOIS.".to_string())
    } else {
        (3, "info", "EPP status flags unavailable.".to_string())
    };
    checks.push(HealthCheckItem {
        id: "reg_status".to_string(),
        category: "Registration".to_string(),
        title: "EPP Lock & Hold Status".to_string(),
        status: epp_status.to_string(),
        detail: epp_detail,
        points: epp_pts,
        max_points: 5,
    });

    // 5. Web (15 pts)
    if website.status == "ok" {
        let https_pts = if website.https { 8 } else { 0 };
        checks.push(HealthCheckItem {
            id: "web_https".to_string(),
            category: "Web".to_string(),
            title: "HTTPS Encryption".to_string(),
            status: if website.https { "pass" } else { "fail" }.to_string(),
            detail: if website.https {
                "Website serves traffic over HTTPS.".to_string()
            } else {
                "Website responded only over unencrypted HTTP.".to_string()
            },
            points: https_pts,
            max_points: 8,
        });

        let present_headers = website.security_headers.iter().filter(|h| h.present).count();
        let header_pts = match present_headers {
            4..=6 => 7,
            2..=3 => 5,
            1 => 3,
            _ => 1,
        };
        checks.push(HealthCheckItem {
            id: "web_headers".to_string(),
            category: "Web".to_string(),
            title: "HTTP Security Headers".to_string(),
            status: if present_headers >= 3 {
                "pass"
            } else {
                "warn"
            }
            .to_string(),
            detail: format!("{present_headers} of {} recommended security headers present.", website.security_headers.len()),
            points: header_pts,
            max_points: 7,
        });
    } else {
        checks.push(HealthCheckItem {
            id: "web_presence".to_string(),
            category: "Web".to_string(),
            title: "Web Server & HTTPS".to_string(),
            status: "info".to_string(),
            detail: "No public website detected (neutral score applied).".to_string(),
            points: 12,
            max_points: 15,
        });
    }

    let score: u32 = checks.iter().map(|c| c.points).sum();
    let mut grade = match score {
        93..=100 => "A+",
        85..=92 => "A",
        75..=84 => "B",
        65..=74 => "C",
        50..=64 => "D",
        _ => "F",
    };

    if blacklists_listed >= 2 {
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
        format!(
            "Listed on {blacklists_listed} of {blacklists_checked} checked blacklists."
        )
    } else if has_policy_hit {
        format!(
            "No active spam blacklists ({blacklists_checked} checked), but a policy/fresh-domain flag was raised."
        )
    } else if spam_status == "caution" {
        format!(
            "Clean on {blacklists_checked} blacklists, but SPF/DMARC protection is incomplete."
        )
    } else {
        format!(
            "Clean across all {blacklists_checked} domain & IP blacklists with SPF/DMARC protection."
        )
    };

    let overall_status = if blacklists_listed > 0 || score < 55 || has_hold {
        "at_risk"
    } else if score < 80 || spam_status == "caution" {
        "caution"
    } else {
        "healthy"
    };

    let summary = match overall_status {
        "healthy" => format!("Domain is healthy and clean ({score}/100, Grade {grade})."),
        "caution" => format!("Domain has minor hygiene or configuration warnings ({score}/100, Grade {grade})."),
        _ => format!("Domain has active risk or blacklist issues ({score}/100, Grade {grade})."),
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

pub async fn evaluate_domain_health(
    domain: &str,
    resolvers: &[ResolverResult],
    propagation: &[PropagationRow],
    security: &SecurityReport,
    whois: &WhoisInfo,
    website: &WebsiteInfo,
) -> DomainHealthReport {
    let apex_domain = extract_whois_domain(domain);
    let dnsbl_resolver = match build_dnsbl_resolver() {
        Ok(r) => r,
        Err(_) => {
            return compute_health_report(
                vec![],
                vec![],
                vec![],
                0,
                propagation,
                security,
                whois,
                website,
            );
        }
    };

    let (target_ips, ns_records) = collect_target_ips(domain, resolvers, &dnsbl_resolver).await;
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

    compute_health_report(
        domain_blacklists,
        ip_blacklists,
        checked_ips,
        ns_records.len(),
        propagation,
        security,
        whois,
        website,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{
        DkimCheck, DmarcCheck, DnssecCheck, SecurityHeaderStatus, SpfCheck,
    };

    #[test]
    fn test_reverse_ipv4() {
        assert_eq!(
            reverse_ipv4(Ipv4Addr::new(192, 0, 2, 44)),
            "44.2.0.192"
        );
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
                raw_record: None,
                mechanisms: vec![],
                all_qualifier: Some("-all".to_string()),
                dns_lookup_count: 1,
                issues: vec![],
            },
            dmarc: DmarcCheck {
                status: dmarc_status.to_string(),
                summary: "dmarc".to_string(),
                raw_record: None,
                policy: Some("reject".to_string()),
                subdomain_policy: None,
                pct: Some(100),
                rua: vec![],
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

    fn base_website() -> WebsiteInfo {
        WebsiteInfo {
            status: "ok".to_string(),
            url: Some("https://example.com".to_string()),
            final_url: Some("https://example.com/".to_string()),
            http_status: Some(200),
            https: true,
            latency_ms: 50,
            title: None,
            description: None,
            generator: None,
            server: None,
            powered_by: None,
            content_type: None,
            technologies: vec![],
            wordpress_plugins: vec![],
            security_headers: vec![
                SecurityHeaderStatus {
                    name: "Strict-Transport-Security".to_string(),
                    present: true,
                    value: Some("max-age=31536000".to_string()),
                },
                SecurityHeaderStatus {
                    name: "Content-Security-Policy".to_string(),
                    present: true,
                    value: Some("default-src 'self'".to_string()),
                },
                SecurityHeaderStatus {
                    name: "X-Frame-Options".to_string(),
                    present: true,
                    value: Some("DENY".to_string()),
                },
                SecurityHeaderStatus {
                    name: "X-Content-Type-Options".to_string(),
                    present: true,
                    value: Some("nosniff".to_string()),
                },
            ],
            response_headers: vec![],
            script_urls: vec![],
            stylesheet_urls: vec![],
            error: None,
        }
    }

    #[test]
    fn test_compute_health_report_clean_vs_blacklisted() {
        let clean_entry = BlacklistEntry {
            list_name: "Spamhaus DBL".to_string(),
            zone: "dbl.spamhaus.org".to_string(),
            target: "example.com".to_string(),
            target_role: "Domain".to_string(),
            status: "clean".to_string(),
            return_codes: vec![],
            detail: None,
            latency_ms: 12,
        };

        let healthy = compute_health_report(
            vec![clean_entry.clone()],
            vec![clean_entry],
            vec!["93.184.216.34".to_string()],
            2,
            &[],
            &base_security("pass", "pass"),
            &base_whois(),
            &base_website(),
        );
        assert_eq!(healthy.score, 100);
        assert_eq!(healthy.grade, "A+");
        assert_eq!(healthy.overall_status, "healthy");
        assert_eq!(healthy.spam_status, "clean");

        let listed_entry = BlacklistEntry {
            list_name: "Spamhaus DBL".to_string(),
            zone: "dbl.spamhaus.org".to_string(),
            target: "bad.example".to_string(),
            target_role: "Domain".to_string(),
            status: "listed".to_string(),
            return_codes: vec!["127.0.1.2".to_string()],
            detail: Some("Spam domain".to_string()),
            latency_ms: 15,
        };

        let listed = compute_health_report(
            vec![listed_entry],
            vec![],
            vec![],
            2,
            &[],
            &base_security("pass", "pass"),
            &base_whois(),
            &base_website(),
        );
        assert_eq!(listed.spam_status, "listed");
        assert_eq!(listed.overall_status, "at_risk");
        assert_eq!(listed.grade, "D");
    }
}
