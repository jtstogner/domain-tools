pub mod bulk;
pub mod ct;
pub mod email_probe;
pub mod health;
pub mod monitor;
pub mod network;
pub mod ports;
pub mod redirects;
pub mod security;
pub mod subdomains;
pub mod tls;
pub mod trace;
pub mod traceroute;
pub mod typosquat;
pub mod website;
pub mod whois;

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::future::join_all;
use hickory_resolver::config::{
    NameServerConfigGroup, ResolveHosts, ResolverConfig, ResolverOpts,
};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, Record, RecordType};
use hickory_resolver::{ResolveError, Resolver, TokioResolver};

use crate::models::{
    DnsOnlyResult, DnsQueryReport, DnsRecordItem, PropagationRow, QueryProgressEvent, QueryRequest,
    RecordTypeResult, ResolverResult,
};

const DEFAULT_RECORD_TYPES: &[&str] = &[
    "A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA", "CAA", "SRV",
];
const DEFAULT_RESOLVERS: &[&str] = &["cloudflare", "google", "quad9", "system"];

pub fn normalize_domain(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_string();
    if s.is_empty() {
        return Err("Please enter a domain name.".to_string());
    }

    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        s = rest.to_string();
    } else if let Some(idx) = s.find("://") {
        let scheme = &s[..idx];
        if scheme.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '-' || c == '.') {
            s = s[idx + 3..].to_string();
        }
    }

    if let Some(idx) = s.find(['/', '?', '#']) {
        s.truncate(idx);
    }

    if let Some(at_idx) = s.rfind('@') {
        s = s[at_idx + 1..].to_string();
    }

    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            s = host.to_string();
        }
    }

    let s = s.trim_end_matches('.').to_ascii_lowercase();
    if s.is_empty() {
        return Err("Domain name cannot be empty.".to_string());
    }
    if s.len() > 253 {
        return Err("Domain name exceeds 253 characters.".to_string());
    }
    if s.contains("..") {
        return Err("Domain name contains empty labels ('..').".to_string());
    }

    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("Invalid domain label '{label}'."));
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(format!("Domain label '{label}' cannot start or end with '-'."));
        }
        if !label
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        {
            return Err(format!(
                "Domain label '{label}' contains invalid characters."
            ));
        }
    }

    Ok(s)
}

pub fn parse_record_type(name: &str) -> Result<RecordType, String> {
    match name.trim().to_ascii_uppercase().as_str() {
        "A" => Ok(RecordType::A),
        "AAAA" => Ok(RecordType::AAAA),
        "CNAME" => Ok(RecordType::CNAME),
        "MX" => Ok(RecordType::MX),
        "TXT" => Ok(RecordType::TXT),
        "NS" => Ok(RecordType::NS),
        "SOA" => Ok(RecordType::SOA),
        "CAA" => Ok(RecordType::CAA),
        "SRV" => Ok(RecordType::SRV),
        other => Err(format!("Unsupported record type '{other}'.")),
    }
}

fn parse_custom_socket_addr(raw: &str) -> Result<SocketAddr, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Custom resolver IP cannot be empty.".to_string());
    }
    if let Ok(sock) = trimmed.parse::<SocketAddr>() {
        return Ok(sock);
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(SocketAddr::new(ip, 53));
    }
    Err(format!(
        "Invalid custom resolver '{trimmed}'. Enter an IPv4/IPv6 address (e.g. 94.140.14.14 or 1.1.1.1:53)."
    ))
}

fn apply_standard_opts(opts: &mut ResolverOpts, validate_dnssec: bool) {
    opts.cache_size = 0;
    opts.timeout = Duration::from_secs(4);
    opts.attempts = 2;
    opts.edns0 = true;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.validate = validate_dnssec;
}

pub fn build_resolver(
    id: &str,
    custom_ip: Option<&str>,
    validate_dnssec: bool,
) -> Result<(String, String, TokioResolver), String> {
    match id.trim().to_ascii_lowercase().as_str() {
        "cloudflare" => {
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::cloudflare(),
                TokioConnectionProvider::default(),
            );
            apply_standard_opts(builder.options_mut(), validate_dnssec);
            Ok((
                "Cloudflare".to_string(),
                "1.1.1.1".to_string(),
                builder.build(),
            ))
        }
        "google" => {
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::google(),
                TokioConnectionProvider::default(),
            );
            apply_standard_opts(builder.options_mut(), validate_dnssec);
            Ok(("Google".to_string(), "8.8.8.8".to_string(), builder.build()))
        }
        "quad9" => {
            let mut builder = Resolver::builder_with_config(
                ResolverConfig::quad9(),
                TokioConnectionProvider::default(),
            );
            apply_standard_opts(builder.options_mut(), validate_dnssec);
            Ok(("Quad9".to_string(), "9.9.9.9".to_string(), builder.build()))
        }
        "system" => {
            let mut builder = Resolver::builder_tokio()
                .map_err(|e| format!("Failed to load system DNS config: {e}"))?;
            apply_standard_opts(builder.options_mut(), validate_dnssec);
            let resolver = builder.build();
            let servers: Vec<String> = resolver
                .config()
                .name_servers()
                .iter()
                .map(|ns| ns.socket_addr.ip().to_string())
                .collect::<BTreeSet<_>>()
                .into_iter()
                .collect();
            let addr = if servers.is_empty() {
                "System resolv.conf".to_string()
            } else {
                servers.join(", ")
            };
            Ok(("System DNS".to_string(), addr, resolver))
        }
        "custom" => {
            let raw = custom_ip.ok_or_else(|| "Custom resolver IP is required.".to_string())?;
            let sock = parse_custom_socket_addr(raw)?;
            let group = NameServerConfigGroup::from_ips_clear(&[sock.ip()], sock.port(), true);
            let config = ResolverConfig::from_parts(None, vec![], group);
            let mut builder =
                Resolver::builder_with_config(config, TokioConnectionProvider::default());
            apply_standard_opts(builder.options_mut(), validate_dnssec);
            Ok(("Custom DNS".to_string(), sock.to_string(), builder.build()))
        }
        other => Err(format!("Unknown resolver '{other}'.")),
    }
}

pub fn txt_to_string(txt: &hickory_resolver::proto::rr::rdata::TXT) -> String {
    txt.txt_data()
        .iter()
        .map(|chunk| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<_>>()
        .join("")
}

pub fn format_record(record: &Record) -> DnsRecordItem {
    let name = record.name().to_string().trim_end_matches('.').to_string();
    let record_type = record.record_type().to_string();
    let ttl = record.ttl();
    let class = record.dns_class().to_string();

    let (value, details) = match record.data() {
        RData::A(a) => (a.0.to_string(), None),
        RData::AAAA(aaaa) => (aaaa.0.to_string(), None),
        RData::CNAME(cname) => (cname.0.to_string(), None),
        RData::NS(ns) => (ns.0.to_string(), None),
        RData::MX(mx) => {
            let exchange = mx.exchange().to_string();
            let preference = mx.preference();
            (
                format!("{preference} {exchange}"),
                Some(serde_json::json!({
                    "priority": preference,
                    "exchange": exchange,
                })),
            )
        }
        RData::TXT(txt) => (txt_to_string(txt), None),
        RData::SOA(soa) => {
            let mname = soa.mname().to_string();
            let rname = soa.rname().to_string();
            let serial = soa.serial();
            let refresh = soa.refresh();
            let retry = soa.retry();
            let expire = soa.expire();
            let minimum = soa.minimum();
            (
                format!("{mname} {rname} {serial} {refresh} {retry} {expire} {minimum}"),
                Some(serde_json::json!({
                    "mname": mname,
                    "rname": rname,
                    "serial": serial,
                    "refresh": refresh,
                    "retry": retry,
                    "expire": expire,
                    "minimum": minimum,
                })),
            )
        }
        RData::CAA(caa) => {
            let flags = caa.flags();
            let issuer_critical = caa.issuer_critical();
            let tag = caa.tag().as_str().to_string();
            let val = String::from_utf8_lossy(caa.raw_value()).into_owned();
            (
                format!("{flags} {tag} \"{val}\""),
                Some(serde_json::json!({
                    "flags": flags,
                    "issuer_critical": issuer_critical,
                    "tag": tag,
                    "value": val,
                })),
            )
        }
        RData::SRV(srv) => {
            let priority = srv.priority();
            let weight = srv.weight();
            let port = srv.port();
            let target = srv.target().to_string();
            (
                format!("{priority} {weight} {port} {target}"),
                Some(serde_json::json!({
                    "priority": priority,
                    "weight": weight,
                    "port": port,
                    "target": target,
                })),
            )
        }
        other => (other.to_string(), None),
    };

    DnsRecordItem {
        name,
        record_type,
        ttl,
        class,
        value,
        details,
    }
}

fn classify_resolve_error(err: &ResolveError) -> (&'static str, Option<String>) {
    if err.is_nx_domain() {
        ("nxdomain", None)
    } else if err.is_no_records_found() {
        ("no_records", None)
    } else {
        ("error", Some(err.to_string()))
    }
}

async fn query_record_type(
    resolver: &TokioResolver,
    fqdn: &str,
    type_name: &str,
    target_type: RecordType,
) -> RecordTypeResult {
    let start = Instant::now();
    match resolver.lookup(fqdn, target_type).await {
        Ok(lookup) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let records: Vec<DnsRecordItem> = lookup
                .record_iter()
                .filter(|r| r.record_type() == target_type)
                .map(format_record)
                .collect();
            let status = if records.is_empty() {
                "no_records".to_string()
            } else {
                "ok".to_string()
            };
            RecordTypeResult {
                record_type: type_name.to_string(),
                status,
                latency_ms,
                records,
                error: None,
            }
        }
        Err(err) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let (status, error) = classify_resolve_error(&err);
            RecordTypeResult {
                record_type: type_name.to_string(),
                status: status.to_string(),
                latency_ms,
                records: vec![],
                error,
            }
        }
    }
}

async fn query_with_resolver(
    id: String,
    fqdn: String,
    record_types: Vec<(String, RecordType)>,
    custom_resolver: Option<String>,
) -> ResolverResult {
    let total_start = Instant::now();
    let built = build_resolver(&id, custom_resolver.as_deref(), false);

    let (label, address, resolver) = match built {
        Ok(v) => v,
        Err(err_msg) => {
            return ResolverResult {
                id,
                label: "Resolver".to_string(),
                address: custom_resolver.unwrap_or_default(),
                total_latency_ms: 0,
                status: "error".to_string(),
                error: Some(err_msg),
                results: vec![],
            };
        }
    };

    let futures = record_types.iter().map(|(name, rtype)| {
        let resolver_ref = &resolver;
        let fqdn_ref = &fqdn;
        async move { query_record_type(resolver_ref, fqdn_ref, name, *rtype).await }
    });

    let results = join_all(futures).await;
    let total_latency_ms = total_start.elapsed().as_millis() as u64;
    let all_failed = !results.is_empty() && results.iter().all(|r| r.status == "error");
    let first_error = if all_failed {
        results.iter().find_map(|r| r.error.clone())
    } else {
        None
    };

    ResolverResult {
        id,
        label,
        address,
        total_latency_ms,
        status: if all_failed {
            "error".to_string()
        } else {
            "ok".to_string()
        },
        error: first_error,
        results,
    }
}

pub fn compute_propagation(
    resolvers: &[ResolverResult],
    record_types: &[String],
) -> Vec<PropagationRow> {
    record_types
        .iter()
        .map(|rtype| {
            let mut answers_by_resolver = BTreeMap::new();
            let mut status_by_resolver = BTreeMap::new();
            let mut latency_by_resolver = BTreeMap::new();
            let mut distinct_sets: BTreeSet<Vec<String>> = BTreeSet::new();
            let mut any_error = false;

            for res in resolvers {
                if res.status == "error" {
                    any_error = true;
                    answers_by_resolver.insert(res.id.clone(), vec![]);
                    status_by_resolver.insert(res.id.clone(), "error".to_string());
                    latency_by_resolver.insert(res.id.clone(), res.total_latency_ms);
                    continue;
                }

                if let Some(tr) = res.results.iter().find(|r| r.record_type == *rtype) {
                    let mut vals: Vec<String> = tr
                        .records
                        .iter()
                        .map(|item| item.value.clone())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                    vals.sort();
                    if tr.status == "error" {
                        any_error = true;
                    } else {
                        distinct_sets.insert(vals.clone());
                    }
                    answers_by_resolver.insert(res.id.clone(), vals);
                    status_by_resolver.insert(res.id.clone(), tr.status.clone());
                    latency_by_resolver.insert(res.id.clone(), tr.latency_ms);
                }
            }

            let status = if any_error {
                "partial_error"
            } else if distinct_sets.len() > 1 {
                "divergent"
            } else if let Some(only) = distinct_sets.iter().next() {
                if only.is_empty() {
                    "empty"
                } else {
                    "consistent"
                }
            } else {
                "empty"
            };

            PropagationRow {
                record_type: rtype.clone(),
                status: status.to_string(),
                answers_by_resolver,
                status_by_resolver,
                latency_by_resolver,
            }
        })
        .collect()
}

fn emit_stage<F>(cb: &F, stage: &str, label: &str, status: &str, elapsed_ms: Option<u64>)
where
    F: Fn(QueryProgressEvent),
{
    cb(QueryProgressEvent {
        stage: stage.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        elapsed_ms,
    });
}

pub async fn execute_query(request: QueryRequest) -> Result<DnsQueryReport, String> {
    execute_query_with_progress(request, |_| {}).await
}

pub async fn execute_query_with_progress<F>(
    request: QueryRequest,
    on_progress: F,
) -> Result<DnsQueryReport, String>
where
    F: Fn(QueryProgressEvent) + Send + Sync,
{
    let domain = normalize_domain(&request.domain)?;
    let fqdn = format!("{domain}.");

    let raw_types: Vec<String> = if request.record_types.is_empty() {
        DEFAULT_RECORD_TYPES.iter().map(|s| s.to_string()).collect()
    } else {
        request.record_types
    };

    let mut parsed_types = Vec::with_capacity(raw_types.len());
    let mut ordered_type_names = Vec::with_capacity(raw_types.len());
    for t in &raw_types {
        let upper = t.trim().to_ascii_uppercase();
        if ordered_type_names.contains(&upper) {
            continue;
        }
        let rtype = parse_record_type(&upper)?;
        ordered_type_names.push(upper.clone());
        parsed_types.push((upper, rtype));
    }

    let raw_resolvers: Vec<String> = if request.resolvers.is_empty() {
        DEFAULT_RESOLVERS.iter().map(|s| s.to_string()).collect()
    } else {
        request.resolvers
    };

    let mut unique_resolvers = Vec::new();
    for r in raw_resolvers {
        let lower = r.trim().to_ascii_lowercase();
        if !lower.is_empty() && !unique_resolvers.contains(&lower) {
            unique_resolvers.push(lower);
        }
    }

    if let Some(custom) = request.custom_resolver.as_deref() {
        if !custom.trim().is_empty() && !unique_resolvers.contains(&"custom".to_string()) {
            unique_resolvers.push("custom".to_string());
        }
    }

    if unique_resolvers.is_empty() {
        return Err("Select at least one DNS resolver.".to_string());
    }

    let resolver_futs = unique_resolvers.into_iter().map(|res_id| {
        query_with_resolver(
            res_id,
            fqdn.clone(),
            parsed_types.clone(),
            request.custom_resolver.clone(),
        )
    });

    let primary_for_sec = build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false))
        .map(|(_, _, r)| r)?;

    let (resolvers, security, tls, redirects, whois, website, subdomains) = tokio::join!(
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "dns", "DNS Records", "running", None);
            let out = join_all(resolver_futs).await;
            emit_stage(
                &on_progress,
                "dns",
                "DNS Records",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "security", "Email & DNSSEC", "running", None);
            let out =
                security::run_security_checks(&domain, &primary_for_sec, &request.dkim_selectors)
                    .await;
            emit_stage(
                &on_progress,
                "security",
                "Email & DNSSEC",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "tls", "SSL / TLS", "running", None);
            let out = tls::inspect_tls(&domain, 443, None).await;
            emit_stage(
                &on_progress,
                "tls",
                "SSL / TLS",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "redirects", "Redirects & TTFB", "running", None);
            let out = redirects::inspect_redirects(&domain).await;
            emit_stage(
                &on_progress,
                "redirects",
                "Redirects & TTFB",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "whois", "WHOIS & RDAP", "running", None);
            let out = whois::lookup_whois(&domain).await;
            emit_stage(
                &on_progress,
                "whois",
                "WHOIS & RDAP",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "website", "Website Stack", "running", None);
            let out = website::inspect_website(&domain).await;
            emit_stage(
                &on_progress,
                "website",
                "Website Stack",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "subdomains", "Subdomains", "running", None);
            let out = subdomains::discover_subdomains(&domain).await;
            emit_stage(
                &on_progress,
                "subdomains",
                "Subdomains",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        }
    );

    let propagation = compute_propagation(&resolvers, &ordered_type_names);
    let (blacklist_bundle, network, ports) = tokio::join!(
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "health", "Domain Health", "running", None);
            let out = health::run_blacklist_checks(&domain, &resolvers).await;
            emit_stage(
                &on_progress,
                "health",
                "Domain Health",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "network", "IP / ASN / PTR", "running", None);
            let out = network::inspect_network(&domain, &resolvers).await;
            emit_stage(
                &on_progress,
                "network",
                "IP / ASN / PTR",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = std::time::Instant::now();
            emit_stage(&on_progress, "ports", "Port Scan", "running", None);
            let out = ports::scan_domain_ports(&domain, &resolvers).await;
            emit_stage(
                &on_progress,
                "ports",
                "Port Scan",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        }
    );

    let health = health::compute_health_report(
        &domain,
        blacklist_bundle,
        &propagation,
        &security,
        &tls,
        &redirects,
        &network,
        &whois,
        &website,
        &subdomains,
        &ports,
    );

    Ok(DnsQueryReport {
        domain,
        queried_at: Utc::now().to_rfc3339(),
        resolvers,
        propagation,
        security,
        tls,
        redirects,
        network,
        whois,
        website,
        health,
        subdomains,
        ports,
    })
}

pub async fn execute_dns_only(
    domain: String,
    record_types: Vec<String>,
    resolver_id: String,
    custom_resolver: Option<String>,
) -> Result<DnsOnlyResult, String> {
    let domain = normalize_domain(&domain)?;
    let fqdn = format!("{domain}.");

    let raw_types: Vec<String> = if record_types.is_empty() {
        DEFAULT_RECORD_TYPES.iter().map(|s| s.to_string()).collect()
    } else {
        record_types
    };

    let mut parsed_types = Vec::with_capacity(raw_types.len());
    let mut seen_types = Vec::with_capacity(raw_types.len());
    for t in &raw_types {
        let upper = t.trim().to_ascii_uppercase();
        if upper.is_empty() || upper == "DMARC" || seen_types.contains(&upper) {
            continue;
        }
        let rtype = parse_record_type(&upper)?;
        seen_types.push(upper);
        parsed_types.push((t.trim().to_ascii_uppercase(), rtype));
    }

    let res_id = {
        let lower = resolver_id.trim().to_ascii_lowercase();
        if lower.is_empty() {
            "cloudflare".to_string()
        } else {
            lower
        }
    };

    let dmarc_fqdn = format!("_dmarc.{domain}.");
    let custom_ref = custom_resolver.as_deref();
    let dmarc_fut = async {
        match build_resolver(&res_id, custom_ref, false) {
            Ok((_, _, r)) => query_record_type(&r, &dmarc_fqdn, "DMARC", RecordType::TXT).await,
            Err(err) => RecordTypeResult {
                record_type: "DMARC".to_string(),
                status: "error".to_string(),
                latency_ms: 0,
                records: vec![],
                error: Some(err),
            },
        }
    };

    let (mut resolver, dmarc_result) = tokio::join!(
        query_with_resolver(
            res_id.clone(),
            fqdn,
            parsed_types,
            custom_resolver.clone(),
        ),
        dmarc_fut
    );

    resolver.results.push(dmarc_result);

    Ok(DnsOnlyResult { domain, resolver })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_domain_cases() {
        assert_eq!(normalize_domain("Example.COM.").unwrap(), "example.com");
        assert_eq!(
            normalize_domain("https://Sub.Example.com:8443/path?x=1").unwrap(),
            "sub.example.com"
        );
        assert_eq!(
            normalize_domain("_dmarc.example.com").unwrap(),
            "_dmarc.example.com"
        );
        assert!(normalize_domain("").is_err());
        assert!(normalize_domain("bad..domain.com").is_err());
        assert!(normalize_domain("-bad.example.com").is_err());
        assert!(normalize_domain("bad host.com").is_err());
    }

    fn make_resolver_result(id: &str, rtype: &str, status: &str, values: &[&str]) -> ResolverResult {
        ResolverResult {
            id: id.to_string(),
            label: id.to_string(),
            address: "1.1.1.1".to_string(),
            total_latency_ms: 15,
            status: "ok".to_string(),
            error: None,
            results: vec![RecordTypeResult {
                record_type: rtype.to_string(),
                status: status.to_string(),
                latency_ms: 15,
                records: values
                    .iter()
                    .map(|v| DnsRecordItem {
                        name: "example.com".to_string(),
                        record_type: rtype.to_string(),
                        ttl: 300,
                        class: "IN".to_string(),
                        value: (*v).to_string(),
                        details: None,
                    })
                    .collect(),
                error: None,
            }],
        }
    }

    #[test]
    fn test_compute_propagation_states() {
        let types = vec!["A".to_string()];

        let consistent = compute_propagation(
            &[
                make_resolver_result("cloudflare", "A", "ok", &["1.1.1.1", "1.0.0.1"]),
                make_resolver_result("google", "A", "ok", &["1.0.0.1", "1.1.1.1"]),
            ],
            &types,
        );
        assert_eq!(consistent[0].status, "consistent");

        let divergent = compute_propagation(
            &[
                make_resolver_result("cloudflare", "A", "ok", &["1.1.1.1"]),
                make_resolver_result("google", "A", "ok", &["2.2.2.2"]),
            ],
            &types,
        );
        assert_eq!(divergent[0].status, "divergent");

        let empty = compute_propagation(
            &[
                make_resolver_result("cloudflare", "A", "no_records", &[]),
                make_resolver_result("google", "A", "no_records", &[]),
            ],
            &types,
        );
        assert_eq!(empty[0].status, "empty");

        let partial = compute_propagation(
            &[
                make_resolver_result("cloudflare", "A", "ok", &["1.1.1.1"]),
                make_resolver_result("google", "A", "error", &[]),
            ],
            &types,
        );
        assert_eq!(partial[0].status, "partial_error");
    }

    #[tokio::test]
    #[ignore = "Requires live network DNS access"]
    async fn test_live_cloudflare_query() {
        let report = execute_query(QueryRequest {
            domain: "cloudflare.com".to_string(),
            record_types: vec!["A".into(), "MX".into(), "NS".into(), "TXT".into()],
            resolvers: vec!["cloudflare".into(), "google".into()],
            custom_resolver: None,
            dkim_selectors: vec![],
        })
        .await
        .expect("live query failed");

        assert_eq!(report.domain, "cloudflare.com");
        assert_eq!(report.resolvers.len(), 2);
        assert!(report
            .resolvers
            .iter()
            .all(|r| r.status == "ok" && !r.results.is_empty()));
        assert_ne!(report.security.spf.status, "missing");
        assert_ne!(report.security.dmarc.status, "missing");
        assert_eq!(report.whois.status, "ok");
        assert!(report.whois.registrar.is_some());
        assert_eq!(report.website.status, "ok");
        assert!(!report.website.technologies.is_empty());
        assert!(report.health.blacklists_checked > 0);
        assert_eq!(report.health.blacklists_listed, 0);
        assert!(report.health.score >= 70);
        assert!(report.subdomains.live_count > 0);
        assert!(report.ports.open_count > 0);
    }

    #[tokio::test]
    async fn test_execute_dns_only_validation() {
        let bad_domain = execute_dns_only(
            "invalid..domain".to_string(),
            vec!["A".to_string()],
            "cloudflare".to_string(),
            None,
        )
        .await;
        assert!(bad_domain.is_err());

        let bad_type = execute_dns_only(
            "example.com".to_string(),
            vec!["NOTATYPE".to_string()],
            "cloudflare".to_string(),
            None,
        )
        .await;
        assert!(bad_type.is_err());
    }
}
