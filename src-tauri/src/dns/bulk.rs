use std::collections::BTreeSet;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, NaiveDateTime, Utc};
use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::dns::{build_resolver, normalize_domain, security, tls, whois};
use crate::models::{BulkDomainResult, BulkProgressEvent};

const MAX_BULK_DOMAINS: usize = 100;
const BULK_CONCURRENCY: usize = 6;
const DNS_TIMEOUT: Duration = Duration::from_secs(4);
const HTTP_TIMEOUT: Duration = Duration::from_secs(5);

pub fn parse_expiry_days_remaining(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some((dt.with_timezone(&Utc) - Utc::now()).num_days());
    }

    let first_token = trimmed.split_whitespace().next().unwrap_or(trimmed);
    for fmt in [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
    ] {
        if let Ok(ndt) = NaiveDateTime::parse_from_str(trimmed, fmt)
            .or_else(|_| NaiveDateTime::parse_from_str(first_token, fmt))
        {
            return Some((ndt.and_utc() - Utc::now()).num_days());
        }
    }

    let date_part = first_token.split('T').next().unwrap_or(first_token);
    for fmt in ["%Y-%m-%d", "%d-%b-%Y", "%Y.%m.%d", "%Y/%m/%d"] {
        if let Ok(nd) = NaiveDate::parse_from_str(date_part, fmt) {
            let today = Utc::now().date_naive();
            return Some((nd - today).num_days());
        }
    }

    None
}

pub fn classify_bulk_status(
    a_records: &[String],
    http_status: Option<u16>,
    ssl_valid: Option<bool>,
    ssl_days: Option<i64>,
    domain_days: Option<i64>,
    spf_status: &str,
    dmarc_status: &str,
) -> String {
    if a_records.is_empty() && http_status.is_none() {
        return "issue".to_string();
    }
    if ssl_valid == Some(false) || ssl_days.map(|d| d <= 0).unwrap_or(false) {
        return "issue".to_string();
    }
    if http_status.map(|s| s >= 500).unwrap_or(false) {
        return "issue".to_string();
    }
    if domain_days.map(|d| d <= 14).unwrap_or(false) {
        return "caution".to_string();
    }
    if ssl_days.map(|d| d <= 30).unwrap_or(false)
        || http_status.map(|s| s >= 400).unwrap_or(false)
        || spf_status == "fail"
        || dmarc_status == "fail"
    {
        return "caution".to_string();
    }
    if spf_status == "warn" || dmarc_status == "warn" || http_status.is_none() {
        return "caution".to_string();
    }
    "healthy".to_string()
}

async fn quick_http_probe(client: &reqwest::Client, domain: &str) -> (Option<u16>, Option<u64>, Option<String>) {
    for url in [format!("https://{domain}"), format!("http://{domain}")] {
        let start = Instant::now();
        if let Ok(resp) = client.get(&url).send().await {
            return (
                Some(resp.status().as_u16()),
                Some(start.elapsed().as_millis() as u64),
                Some(resp.url().to_string()),
            );
        }
    }
    (None, None, None)
}

async fn check_single_domain(
    raw_input: String,
    http_client: reqwest::Client,
) -> BulkDomainResult {
    let started = Instant::now();
    let domain = match normalize_domain(&raw_input) {
        Ok(d) => d,
        Err(err) => {
            return BulkDomainResult {
                domain: raw_input,
                status: "error".to_string(),
                a_records: vec![],
                mx_count: 0,
                ns_count: 0,
                http_status: None,
                http_latency_ms: None,
                final_url: None,
                ssl_valid: None,
                ssl_days_remaining: None,
                ssl_issuer: None,
                spf_status: "missing".to_string(),
                dmarc_status: "missing".to_string(),
                dnssec_status: "missing".to_string(),
                registrar: None,
                domain_expiry_date: None,
                domain_days_remaining: None,
                latency_ms: 0,
                error: Some(err),
            }
        }
    };

    let resolver = match build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false))
    {
        Ok((_, _, r)) => r,
        Err(err) => {
            return BulkDomainResult {
                domain,
                status: "error".to_string(),
                a_records: vec![],
                mx_count: 0,
                ns_count: 0,
                http_status: None,
                http_latency_ms: None,
                final_url: None,
                ssl_valid: None,
                ssl_days_remaining: None,
                ssl_issuer: None,
                spf_status: "missing".to_string(),
                dmarc_status: "missing".to_string(),
                dnssec_status: "missing".to_string(),
                registrar: None,
                domain_expiry_date: None,
                domain_days_remaining: None,
                latency_ms: started.elapsed().as_millis() as u64,
                error: Some(err),
            }
        }
    };

    let fqdn = format!("{domain}.");
    let dns_fut = async {
        let (a_res, mx_res, ns_res) = tokio::join!(
            timeout(DNS_TIMEOUT, resolver.lookup(fqdn.clone(), RecordType::A)),
            timeout(DNS_TIMEOUT, resolver.lookup(fqdn.clone(), RecordType::MX)),
            timeout(DNS_TIMEOUT, resolver.lookup(fqdn.clone(), RecordType::NS))
        );

        let a_records: Vec<String> = match a_res {
            Ok(Ok(l)) => l
                .iter()
                .filter_map(|r| match r {
                    RData::A(v4) => Some(Ipv4Addr::from(*v4).to_string()),
                    _ => None,
                })
                .collect(),
            _ => Vec::new(),
        };
        let mx_count = mx_res
            .ok()
            .and_then(|r| r.ok())
            .map(|l| l.iter().count())
            .unwrap_or(0);
        let ns_count = ns_res
            .ok()
            .and_then(|r| r.ok())
            .map(|l| l.iter().count())
            .unwrap_or(0);
        (a_records, mx_count, ns_count)
    };

    let (
        (a_records, mx_count, ns_count),
        sec,
        tls_rep,
        (http_status, http_latency_ms, final_url),
        whois_info,
    ) = tokio::join!(
        dns_fut,
        security::run_security_checks(&domain, &resolver, &[]),
        tls::inspect_tls(&domain, 443, None),
        quick_http_probe(&http_client, &domain),
        whois::lookup_whois(&domain)
    );

    let ssl_valid = if tls_rep.error.is_some() {
        None
    } else {
        Some(tls_rep.chain_valid && tls_rep.hostname_match && tls_rep.days_remaining.unwrap_or(-1) > 0)
    };
    let ssl_issuer = tls_rep
        .certificates
        .first()
        .and_then(|c| c.issuer_org.clone().or_else(|| Some(c.issuer.clone())));

    let domain_days_remaining = whois_info
        .expiry_date
        .as_deref()
        .and_then(parse_expiry_days_remaining);

    let status = classify_bulk_status(
        &a_records,
        http_status,
        ssl_valid,
        tls_rep.days_remaining,
        domain_days_remaining,
        &sec.spf.status,
        &sec.dmarc.status,
    );

    BulkDomainResult {
        domain,
        status,
        a_records,
        mx_count,
        ns_count,
        http_status,
        http_latency_ms,
        final_url,
        ssl_valid,
        ssl_days_remaining: tls_rep.days_remaining,
        ssl_issuer,
        spf_status: sec.spf.status,
        dmarc_status: sec.dmarc.status,
        dnssec_status: sec.dnssec.status,
        registrar: whois_info.registrar,
        domain_expiry_date: whois_info.expiry_date,
        domain_days_remaining,
        latency_ms: started.elapsed().as_millis() as u64,
        error: None,
    }
}

pub async fn run_bulk_check<F>(domains: Vec<String>, on_progress: F) -> Vec<BulkDomainResult>
where
    F: Fn(BulkProgressEvent) + Send + Sync,
{
    let mut seen = BTreeSet::new();
    let mut cleaned = Vec::new();
    for raw in domains {
        let trimmed = raw.trim().to_string();
        if trimmed.is_empty() {
            continue;
        }
        let key = normalize_domain(&trimmed).unwrap_or_else(|_| trimmed.to_ascii_lowercase());
        if seen.insert(key) {
            cleaned.push(trimmed);
            if cleaned.len() >= MAX_BULK_DOMAINS {
                break;
            }
        }
    }

    let total = cleaned.len();
    if total == 0 {
        return Vec::new();
    }

    let http_client = reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .user_agent("DomainTools/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let sem = Arc::new(Semaphore::new(BULK_CONCURRENCY));
    let completed = Arc::new(AtomicUsize::new(0));
    let on_progress = &on_progress;

    let futs = cleaned.into_iter().map(|dom| {
        let sem = sem.clone();
        let completed = completed.clone();
        let client = http_client.clone();
        async move {
            let _permit = sem.acquire().await;
            let result = check_single_domain(dom, client).await;
            let done_now = completed.fetch_add(1, Ordering::SeqCst) + 1;
            on_progress(BulkProgressEvent {
                completed: done_now,
                total,
                result: result.clone(),
            });
            result
        }
    });

    join_all(futs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_expiry_days_remaining() {
        let future = (Utc::now() + chrono::Duration::days(45)).to_rfc3339();
        let days = parse_expiry_days_remaining(&future).unwrap();
        assert!((44..=45).contains(&days));

        let future_date = (Utc::now().date_naive() + chrono::Duration::days(10))
            .format("%Y-%m-%d")
            .to_string();
        assert_eq!(parse_expiry_days_remaining(&future_date), Some(10));
        assert_eq!(parse_expiry_days_remaining("invalid-date"), None);
    }

    #[test]
    fn test_classify_bulk_status() {
        assert_eq!(
            classify_bulk_status(
                &["1.1.1.1".to_string()],
                Some(200),
                Some(true),
                Some(80),
                Some(200),
                "pass",
                "pass"
            ),
            "healthy"
        );
        assert_eq!(
            classify_bulk_status(
                &["1.1.1.1".to_string()],
                Some(200),
                Some(true),
                Some(12),
                Some(200),
                "pass",
                "pass"
            ),
            "caution"
        );
        assert_eq!(
            classify_bulk_status(
                &["1.1.1.1".to_string()],
                Some(502),
                Some(true),
                Some(80),
                Some(200),
                "pass",
                "pass"
            ),
            "issue"
        );
        assert_eq!(
            classify_bulk_status(
                &["1.1.1.1".to_string()],
                Some(200),
                Some(false),
                Some(-5),
                Some(200),
                "pass",
                "pass"
            ),
            "issue"
        );
    }
}
