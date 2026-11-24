use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use regex::Regex;
use serde::Deserialize;

use crate::dns::whois::extract_whois_domain;
use crate::models::{SubdomainDiscoveryReport, SubdomainItem, SubdomainSourceStatus};

const MAX_PASSIVE_BYTES: usize = 1024 * 1024;
const MAX_CRTSH_BYTES: usize = 2 * 1024 * 1024;
const MAX_CT_LIVE_CHECKS: usize = 80;
const MAX_TOTAL_SUBDOMAINS: usize = 200;
const PROBE_CONCURRENCY: usize = 24;

const COMMON_SUBDOMAINS: &[&str] = &[
    "www",
    "mail",
    "webmail",
    "smtp",
    "imap",
    "pop",
    "ftp",
    "sftp",
    "api",
    "app",
    "portal",
    "admin",
    "login",
    "auth",
    "sso",
    "id",
    "account",
    "accounts",
    "blog",
    "docs",
    "developers",
    "dev",
    "staging",
    "stage",
    "test",
    "beta",
    "demo",
    "sandbox",
    "qa",
    "uat",
    "help",
    "support",
    "status",
    "shop",
    "store",
    "cdn",
    "static",
    "assets",
    "img",
    "images",
    "media",
    "files",
    "download",
    "downloads",
    "ns1",
    "ns2",
    "ns3",
    "ns4",
    "dns",
    "vpn",
    "remote",
    "autodiscover",
    "autoconfig",
    "sip",
    "lyncdiscover",
    "m",
    "mobile",
    "cloud",
    "git",
    "gitlab",
    "ci",
    "grafana",
    "monitor",
    "metrics",
    "analytics",
    "track",
    "email",
    "mx",
    "mx1",
    "mx2",
    "relay",
    "pay",
    "billing",
    "checkout",
    "crm",
    "erp",
    "intranet",
    "owa",
    "exchange",
    "calendar",
    "meet",
    "chat",
    "forum",
    "community",
    "wiki",
    "dash",
    "dashboard",
    "panel",
    "cpanel",
    "whm",
    "server",
    "webdisk",
    "internal",
];

#[derive(Deserialize)]
struct CrtShEntry {
    name_value: String,
}

fn build_fast_resolver() -> TokioResolver {
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    );
    let opts: &mut ResolverOpts = builder.options_mut();
    opts.cache_size = 0;
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    opts.edns0 = true;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.validate = false;
    builder.build()
}

fn is_valid_subdomain_of(host: &str, apex: &str) -> bool {
    let suffix = format!(".{apex}");
    if !host.ends_with(&suffix) || host.len() <= suffix.len() || host.len() > 253 {
        return false;
    }
    if host.contains("..") {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

async fn read_response_capped(mut resp: reqwest::Response, max_bytes: usize) -> (String, bool) {
    let mut bytes = Vec::with_capacity(32 * 1024);
    let mut truncated = false;
    while let Ok(Some(chunk)) = resp.chunk().await {
        let remaining = max_bytes.saturating_sub(bytes.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        let take = chunk.len().min(remaining);
        bytes.extend_from_slice(&chunk[..take]);
        if bytes.len() >= max_bytes {
            truncated = true;
            break;
        }
    }
    (String::from_utf8_lossy(&bytes).into_owned(), truncated)
}

pub fn parse_crtsh_json(raw_json: &str, apex: &str) -> Result<Vec<String>, String> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }

    let entries: Vec<CrtShEntry> = match serde_json::from_str(trimmed) {
        Ok(list) => list,
        Err(orig_err) => {
            if let Some(last_obj_end) = trimmed.rfind("},") {
                let repaired = format!("{}]", &trimmed[..last_obj_end + 1]);
                serde_json::from_str(&repaired)
                    .map_err(|_| format!("Invalid crt.sh JSON: {orig_err}"))?
            } else {
                return Err(format!("Invalid crt.sh JSON: {orig_err}"));
            }
        }
    };

    let apex_lower = apex.to_ascii_lowercase();
    let mut set = BTreeSet::new();

    for entry in entries {
        for raw_line in entry.name_value.split('\n') {
            let mut candidate = raw_line.trim().to_ascii_lowercase();
            while let Some(stripped) = candidate.strip_prefix("*.") {
                candidate = stripped.to_string();
            }
            candidate = candidate.trim_end_matches('.').to_string();
            if is_valid_subdomain_of(&candidate, &apex_lower) {
                set.insert(candidate);
            }
        }
    }

    Ok(set.into_iter().collect())
}

pub fn parse_hackertarget_text(body: &str, apex: &str) -> Result<Vec<String>, String> {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return Ok(vec![]);
    }
    let lower = trimmed.to_ascii_lowercase();
    if lower.contains("api count exceeded") || lower.contains("rate limit") {
        return Err("rate_limited".to_string());
    }
    if lower.starts_with("error ") {
        return Err(trimmed.to_string());
    }

    let apex_lower = apex.to_ascii_lowercase();
    let mut set = BTreeSet::new();
    for line in trimmed.lines() {
        let host = line
            .split(',')
            .next()
            .unwrap_or("")
            .trim()
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if is_valid_subdomain_of(&host, &apex_lower) {
            set.insert(host);
        }
    }
    Ok(set.into_iter().collect())
}

pub fn parse_rapiddns_html(html: &str, apex: &str) -> Vec<String> {
    let apex_lower = apex.to_ascii_lowercase();
    let pattern = format!(r"(?i)\b([a-z0-9_.-]+\.{})", regex::escape(&apex_lower));
    let Ok(re) = Regex::new(&pattern) else {
        return vec![];
    };

    let mut set = BTreeSet::new();
    for cap in re.captures_iter(html) {
        let mut candidate = cap[1].trim().trim_end_matches('.').to_ascii_lowercase();
        while let Some(stripped) = candidate.strip_prefix("*.") {
            candidate = stripped.to_string();
        }
        if is_valid_subdomain_of(&candidate, &apex_lower) {
            set.insert(candidate);
        }
    }
    set.into_iter().collect()
}

async fn fetch_hackertarget_subdomains(
    client: &reqwest::Client,
    apex: &str,
) -> (SubdomainSourceStatus, Vec<String>) {
    let url = format!("https://api.hackertarget.com/hostsearch/?q={apex}");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let status = if e.is_timeout() { "timeout" } else { "error" };
            return (
                SubdomainSourceStatus {
                    name: "HackerTarget".to_string(),
                    status: status.to_string(),
                    count: 0,
                },
                vec![],
            );
        }
    };

    if resp.status().as_u16() == 429 {
        return (
            SubdomainSourceStatus {
                name: "HackerTarget".to_string(),
                status: "rate_limited".to_string(),
                count: 0,
            },
            vec![],
        );
    }
    if !resp.status().is_success() {
        return (
            SubdomainSourceStatus {
                name: "HackerTarget".to_string(),
                status: "error".to_string(),
                count: 0,
            },
            vec![],
        );
    }

    let (text, _) = read_response_capped(resp, MAX_PASSIVE_BYTES).await;
    match parse_hackertarget_text(&text, apex) {
        Ok(names) => (
            SubdomainSourceStatus {
                name: "HackerTarget".to_string(),
                status: "ok".to_string(),
                count: names.len(),
            },
            names,
        ),
        Err(err) if err == "rate_limited" => (
            SubdomainSourceStatus {
                name: "HackerTarget".to_string(),
                status: "rate_limited".to_string(),
                count: 0,
            },
            vec![],
        ),
        Err(_) => (
            SubdomainSourceStatus {
                name: "HackerTarget".to_string(),
                status: "error".to_string(),
                count: 0,
            },
            vec![],
        ),
    }
}

async fn fetch_rapiddns_subdomains(
    client: &reqwest::Client,
    apex: &str,
) -> (SubdomainSourceStatus, Vec<String>) {
    let url = format!("https://rapiddns.io/subdomain/{apex}?full=1");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let status = if e.is_timeout() { "timeout" } else { "error" };
            return (
                SubdomainSourceStatus {
                    name: "RapidDNS".to_string(),
                    status: status.to_string(),
                    count: 0,
                },
                vec![],
            );
        }
    };

    if resp.status().as_u16() == 429 {
        return (
            SubdomainSourceStatus {
                name: "RapidDNS".to_string(),
                status: "rate_limited".to_string(),
                count: 0,
            },
            vec![],
        );
    }
    if !resp.status().is_success() {
        return (
            SubdomainSourceStatus {
                name: "RapidDNS".to_string(),
                status: "error".to_string(),
                count: 0,
            },
            vec![],
        );
    }

    let (html, _) = read_response_capped(resp, MAX_PASSIVE_BYTES).await;
    let names = parse_rapiddns_html(&html, apex);
    (
        SubdomainSourceStatus {
            name: "RapidDNS".to_string(),
            status: "ok".to_string(),
            count: names.len(),
        },
        names,
    )
}

async fn fetch_crtsh_subdomains(
    client: &reqwest::Client,
    apex: &str,
) -> (SubdomainSourceStatus, Option<String>, Vec<String>) {
    let url = format!("https://crt.sh/?q=%25.{apex}&output=json");
    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            let status = if e.is_timeout() { "timeout" } else { "error" };
            return (
                SubdomainSourceStatus {
                    name: "crt.sh".to_string(),
                    status: status.to_string(),
                    count: 0,
                },
                None,
                vec![],
            );
        }
    };

    if resp.status().as_u16() == 429 {
        return (
            SubdomainSourceStatus {
                name: "crt.sh".to_string(),
                status: "rate_limited".to_string(),
                count: 0,
            },
            None,
            vec![],
        );
    }
    if !resp.status().is_success() {
        return (
            SubdomainSourceStatus {
                name: "crt.sh".to_string(),
                status: "error".to_string(),
                count: 0,
            },
            None,
            vec![],
        );
    }

    let (text, truncated) = read_response_capped(resp, MAX_CRTSH_BYTES).await;
    match parse_crtsh_json(&text, apex) {
        Ok(names) => {
            let note = if truncated {
                Some("Large crt.sh response truncated at 2 MB; showing parsed subset.".to_string())
            } else {
                None
            };
            (
                SubdomainSourceStatus {
                    name: "crt.sh".to_string(),
                    status: "ok".to_string(),
                    count: names.len(),
                },
                note,
                names,
            )
        }
        Err(_) => (
            SubdomainSourceStatus {
                name: "crt.sh".to_string(),
                status: "error".to_string(),
                count: 0,
            },
            None,
            vec![],
        ),
    }
}

async fn resolve_subdomain(
    resolver: &TokioResolver,
    subdomain: &str,
) -> (Vec<String>, Vec<String>, Option<String>) {
    let fqdn = format!("{subdomain}.");
    let (a_res, aaaa_res, cname_res) = tokio::join!(
        resolver.lookup(&fqdn, RecordType::A),
        resolver.lookup(&fqdn, RecordType::AAAA),
        resolver.lookup(&fqdn, RecordType::CNAME),
    );

    let mut a_records = Vec::new();
    if let Ok(lookup) = a_res {
        for r in lookup.record_iter() {
            if let RData::A(a) = r.data() {
                let s = a.0.to_string();
                if !a_records.contains(&s) {
                    a_records.push(s);
                }
            }
        }
    }

    let mut aaaa_records = Vec::new();
    if let Ok(lookup) = aaaa_res {
        for r in lookup.record_iter() {
            if let RData::AAAA(aaaa) = r.data() {
                let s = aaaa.0.to_string();
                if !aaaa_records.contains(&s) {
                    aaaa_records.push(s);
                }
            }
        }
    }

    let cname = cname_res.ok().and_then(|lookup| {
        lookup.record_iter().find_map(|r| match r.data() {
            RData::CNAME(c) => Some(c.0.to_string().trim_end_matches('.').to_string()),
            _ => None,
        })
    });

    (a_records, aaaa_records, cname)
}

async fn detect_wildcard(resolver: &TokioResolver, apex: &str) -> BTreeSet<String> {
    let probe = format!("domain-tools-wc-9f3a7b2c.{apex}");
    let (a_res, aaaa_res, _) = resolve_subdomain(resolver, &probe).await;
    let mut set = BTreeSet::new();
    for ip in a_res.into_iter().chain(aaaa_res) {
        set.insert(ip);
    }
    set
}

pub fn is_wildcard_match(
    a_records: &[String],
    aaaa_records: &[String],
    cname: &Option<String>,
    wildcard_ips: &BTreeSet<String>,
) -> bool {
    if wildcard_ips.is_empty() || cname.is_some() {
        return false;
    }
    let total_ips = a_records.len() + aaaa_records.len();
    if total_ips == 0 {
        return false;
    }
    a_records
        .iter()
        .chain(aaaa_records.iter())
        .all(|ip| wildcard_ips.contains(ip))
}

pub async fn discover_subdomains(domain: &str) -> SubdomainDiscoveryReport {
    let start = Instant::now();
    let apex = extract_whois_domain(domain);
    let resolver = build_fast_resolver();

    let http_client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(4))
        .user_agent("DomainTools/0.1 (Passive Subdomain Discovery)")
        .build()
        .ok();

    let ((ht_res, rd_res, ct_res), wildcard_ips) = tokio::join!(
        async {
            if let Some(client) = &http_client {
                tokio::join!(
                    fetch_hackertarget_subdomains(client, &apex),
                    fetch_rapiddns_subdomains(client, &apex),
                    fetch_crtsh_subdomains(client, &apex),
                )
            } else {
                (
                    (
                        SubdomainSourceStatus {
                            name: "HackerTarget".to_string(),
                            status: "error".to_string(),
                            count: 0,
                        },
                        vec![],
                    ),
                    (
                        SubdomainSourceStatus {
                            name: "RapidDNS".to_string(),
                            status: "error".to_string(),
                            count: 0,
                        },
                        vec![],
                    ),
                    (
                        SubdomainSourceStatus {
                            name: "crt.sh".to_string(),
                            status: "error".to_string(),
                            count: 0,
                        },
                        None,
                        vec![],
                    ),
                )
            }
        },
        detect_wildcard(&resolver, &apex),
    );

    let (ht_status, ht_names) = ht_res;
    let (rd_status, rd_names) = rd_res;
    let (crt_status, crt_trunc_note, crt_names) = ct_res;

    let passive_sources = vec![ht_status.clone(), rd_status.clone(), crt_status.clone()];

    let any_passive_ok = passive_sources.iter().any(|s| s.status == "ok");
    let any_timeout = passive_sources.iter().any(|s| s.status == "timeout");

    let ct_status = if any_passive_ok {
        "ok".to_string()
    } else if any_timeout {
        "timeout".to_string()
    } else {
        "error".to_string()
    };

    let ct_note = if !any_passive_ok {
        Some("All passive subdomain sources timed out or errored; showing DNS probe results.".to_string())
    } else {
        crt_trunc_note
    };

    let probe_targets: Vec<String> = COMMON_SUBDOMAINS
        .iter()
        .map(|prefix| format!("{prefix}.{apex}"))
        .collect();
    let probe_count = probe_targets.len();

    let probe_results: Vec<(String, Vec<String>, Vec<String>, Option<String>)> =
        stream::iter(probe_targets)
            .map(|sub| {
                let res_ref = &resolver;
                async move {
                    let (a, aaaa, cname) = resolve_subdomain(res_ref, &sub).await;
                    (sub, a, aaaa, cname)
                }
            })
            .buffer_unordered(PROBE_CONCURRENCY)
            .collect()
            .await;

    let mut map: BTreeMap<String, SubdomainItem> = BTreeMap::new();

    for (sub, a, aaaa, cname) in probe_results {
        let has_data = !a.is_empty() || !aaaa.is_empty() || cname.is_some();
        if !has_data || is_wildcard_match(&a, &aaaa, &cname, &wildcard_ips) {
            continue;
        }
        map.insert(
            sub.clone(),
            SubdomainItem {
                subdomain: sub,
                live: true,
                a_records: a,
                aaaa_records: aaaa,
                cname,
                sources: vec!["DNS Probe".to_string()],
            },
        );
    }

    let mut passive_sources_by_host: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (source_label, list) in [
        ("HackerTarget", ht_names),
        ("RapidDNS", rd_names),
        ("crt.sh", crt_names),
    ] {
        for host in list {
            let entry = passive_sources_by_host.entry(host).or_default();
            if !entry.iter().any(|s| s == source_label) {
                entry.push(source_label.to_string());
            }
        }
    }

    let mut passive_to_resolve: Vec<(String, Vec<String>)> = Vec::new();
    let mut passive_overflow: Vec<(String, Vec<String>)> = Vec::new();

    for (host, srcs) in passive_sources_by_host {
        if let Some(existing) = map.get_mut(&host) {
            for s in srcs {
                if !existing.sources.contains(&s) {
                    existing.sources.push(s);
                }
            }
        } else if passive_to_resolve.len() < MAX_CT_LIVE_CHECKS {
            passive_to_resolve.push((host, srcs));
        } else {
            passive_overflow.push((host, srcs));
        }
    }

    let passive_resolved: Vec<(String, Vec<String>, Vec<String>, Vec<String>, Option<String>)> =
        stream::iter(passive_to_resolve)
            .map(|(sub, srcs)| {
                let res_ref = &resolver;
                async move {
                    let (a, aaaa, cname) = resolve_subdomain(res_ref, &sub).await;
                    (sub, srcs, a, aaaa, cname)
                }
            })
            .buffer_unordered(PROBE_CONCURRENCY)
            .collect()
            .await;

    for (sub, srcs, a, aaaa, cname) in passive_resolved {
        let has_data = !a.is_empty() || !aaaa.is_empty() || cname.is_some();
        let wc_hit = is_wildcard_match(&a, &aaaa, &cname, &wildcard_ips);
        let live = has_data && !wc_hit;
        map.insert(
            sub.clone(),
            SubdomainItem {
                subdomain: sub,
                live,
                a_records: if live { a } else { vec![] },
                aaaa_records: if live { aaaa } else { vec![] },
                cname: if live { cname } else { None },
                sources: srcs,
            },
        );
    }

    for (sub, srcs) in passive_overflow {
        if map.len() >= MAX_TOTAL_SUBDOMAINS {
            break;
        }
        map.entry(sub.clone()).or_insert(SubdomainItem {
            subdomain: sub,
            live: false,
            a_records: vec![],
            aaaa_records: vec![],
            cname: None,
            sources: srcs,
        });
    }

    let mut subdomains: Vec<SubdomainItem> = map.into_values().collect();
    subdomains.sort_by(|a, b| {
        b.live
            .cmp(&a.live)
            .then_with(|| a.subdomain.cmp(&b.subdomain))
    });
    if subdomains.len() > MAX_TOTAL_SUBDOMAINS {
        subdomains.truncate(MAX_TOTAL_SUBDOMAINS);
    }

    let total_found = subdomains.len();
    let live_count = subdomains.iter().filter(|s| s.live).count();
    let ct_only_count = total_found.saturating_sub(live_count);

    SubdomainDiscoveryReport {
        apex_domain: apex,
        total_found,
        live_count,
        ct_only_count,
        wildcard_detected: !wildcard_ips.is_empty(),
        wildcard_ips: wildcard_ips.into_iter().collect(),
        ct_status,
        ct_note,
        passive_sources,
        probe_count,
        latency_ms: start.elapsed().as_millis() as u64,
        subdomains,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_crtsh_json_variants() {
        let json = r#"[
            {"name_value": "api.example.com\n*.dev.example.com\nexample.com"},
            {"name_value": "WWW.EXAMPLE.COM.\notherdomain.org\nbad host.example.com"},
            {"name_value": "*.api.example.com"}
        ]"#;

        let parsed = parse_crtsh_json(json, "example.com").unwrap();
        assert_eq!(
            parsed,
            vec!["api.example.com", "dev.example.com", "www.example.com"]
        );

        let truncated = r#"[{"name_value":"mail.example.com"},{"name_value":"partial"#;
        let repaired = parse_crtsh_json(truncated, "example.com").unwrap();
        assert_eq!(repaired, vec!["mail.example.com"]);
    }

    #[test]
    fn test_parse_hackertarget_text() {
        let body = "\
example.com,1.2.3.4
api.example.com,1.2.3.5
WWW.EXAMPLE.COM.,1.2.3.6
other.org,9.9.9.9
";
        let parsed = parse_hackertarget_text(body, "example.com").unwrap();
        assert_eq!(parsed, vec!["api.example.com", "www.example.com"]);

        let limited = "API count exceeded - Increase Quota with Membership";
        assert_eq!(
            parse_hackertarget_text(limited, "example.com").unwrap_err(),
            "rate_limited"
        );
    }

    #[test]
    fn test_parse_rapiddns_html() {
        let html = r#"
            <table>
              <tr><td>cpanel.example.com</td><td>1.2.3.4</td></tr>
              <tr><td>MAIL.EXAMPLE.COM</td><td>1.2.3.5</td></tr>
              <tr><td>notrelated.com</td><td>9.9.9.9</td></tr>
            </table>
        "#;
        let parsed = parse_rapiddns_html(html, "example.com");
        assert_eq!(parsed, vec!["cpanel.example.com", "mail.example.com"]);
    }

    #[test]
    fn test_is_wildcard_match() {
        let mut wc = BTreeSet::new();
        assert!(!is_wildcard_match(&["1.2.3.4".into()], &[], &None, &wc));

        wc.insert("1.2.3.4".to_string());
        assert!(is_wildcard_match(&["1.2.3.4".into()], &[], &None, &wc));
        assert!(!is_wildcard_match(&["5.6.7.8".into()], &[], &None, &wc));
        assert!(!is_wildcard_match(
            &["1.2.3.4".into()],
            &[],
            &Some("target.example.com".into()),
            &wc
        ));
    }
}
