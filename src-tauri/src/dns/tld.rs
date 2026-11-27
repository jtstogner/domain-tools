use std::sync::Arc;
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::proto::rr::RecordType;
use hickory_resolver::TokioResolver;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use crate::dns::whois::{extract_whois_domain, lookup_whois};
use crate::dns::{build_resolver, normalize_domain};
use crate::models::{TldAvailabilityItem, TldAvailabilityReport};

pub const DEFAULT_TLDS: &[&str] = &[
    "com", "net", "org", "io", "dev", "ai", "app", "co", "xyz", "me", "gg", "cloud",
];
pub const MAX_TLDS: usize = 24;
const MAX_CONCURRENT_CHECKS: usize = 6;
const DNS_CHECK_TIMEOUT: Duration = Duration::from_millis(2500);
const WHOIS_CHECK_TIMEOUT: Duration = Duration::from_secs(4);

pub fn clean_base_name(input: &str) -> Result<String, String> {
    let mut s = input.trim().to_string();
    if s.is_empty() {
        return Err("Please enter a base domain name (e.g. 'acme').".to_string());
    }

    if let Some(rest) = s
        .strip_prefix("https://")
        .or_else(|| s.strip_prefix("http://"))
    {
        s = rest.to_string();
    } else if let Some(idx) = s.find("://") {
        s = s[idx + 3..].to_string();
    }

    if let Some(idx) = s.find(['/', '?', '#']) {
        s.truncate(idx);
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if !host.contains(':') && port.chars().all(|c| c.is_ascii_digit()) {
            s = host.to_string();
        }
    }

    let lowered = s.trim().trim_matches('.').to_ascii_lowercase();
    let without_www = lowered.strip_prefix("www.").unwrap_or(&lowered);

    let candidate = if without_www.contains('.') {
        let apex = extract_whois_domain(without_www);
        apex.split('.').next().unwrap_or("").to_string()
    } else {
        without_www.to_string()
    };

    let cleaned: String = candidate
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect::<String>()
        .trim_matches('-')
        .to_string();

    if cleaned.is_empty() {
        return Err("Base domain name must contain letters or digits.".to_string());
    }
    if cleaned.len() > 63 {
        return Err("Base domain label exceeds 63 characters.".to_string());
    }

    Ok(cleaned)
}

pub fn normalize_tlds(input: Option<Vec<String>>) -> Vec<String> {
    let raw: Vec<String> = match input {
        Some(list) if !list.is_empty() => list,
        _ => return DEFAULT_TLDS.iter().map(|s| s.to_string()).collect(),
    };

    let mut out = Vec::new();
    for item in raw {
        let cleaned = item
            .trim()
            .trim_start_matches('.')
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if cleaned.is_empty() || cleaned.len() > 63 || cleaned.contains("..") {
            continue;
        }
        let valid = cleaned.split('.').all(|part| {
            !part.is_empty()
                && !part.starts_with('-')
                && !part.ends_with('-')
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        });
        if valid && !out.contains(&cleaned) {
            out.push(cleaned);
            if out.len() >= MAX_TLDS {
                break;
            }
        }
    }

    if out.is_empty() {
        DEFAULT_TLDS.iter().map(|s| s.to_string()).collect()
    } else {
        out
    }
}

async fn has_any_dns(resolver: &TokioResolver, fqdn: &str) -> bool {
    let (ns_res, soa_res, a_res) = tokio::join!(
        timeout(DNS_CHECK_TIMEOUT, resolver.lookup(fqdn, RecordType::NS)),
        timeout(DNS_CHECK_TIMEOUT, resolver.lookup(fqdn, RecordType::SOA)),
        timeout(DNS_CHECK_TIMEOUT, resolver.lookup(fqdn, RecordType::A)),
    );

    let ns_ok = matches!(ns_res, Ok(Ok(ref l)) if l.record_iter().next().is_some());
    let soa_ok = matches!(soa_res, Ok(Ok(ref l)) if l.record_iter().next().is_some());
    let a_ok = matches!(a_res, Ok(Ok(ref l)) if l.record_iter().next().is_some());
    ns_ok || soa_ok || a_ok
}

async fn check_single_tld(
    base_name: &str,
    tld: &str,
    resolver: &TokioResolver,
    sem: Arc<Semaphore>,
) -> TldAvailabilityItem {
    let _permit = sem.acquire_owned().await;
    let started = Instant::now();
    let domain = format!("{base_name}.{tld}");

    if normalize_domain(&domain).is_err() {
        return TldAvailabilityItem {
            domain,
            tld: tld.to_string(),
            status: "unknown".to_string(),
            has_dns: false,
            registrar: None,
            expiry_date: None,
            latency_ms: started.elapsed().as_millis() as u64,
            detail: Some("Invalid domain label/TLD combination.".to_string()),
        };
    }

    let fqdn = format!("{domain}.");
    let (has_dns, whois_res) = tokio::join!(
        has_any_dns(resolver, &fqdn),
        timeout(WHOIS_CHECK_TIMEOUT, lookup_whois(&domain)),
    );

    let latency_ms = started.elapsed().as_millis() as u64;

    match whois_res {
        Ok(whois) => match whois.status.as_str() {
            "ok" => TldAvailabilityItem {
                domain,
                tld: tld.to_string(),
                status: "registered".to_string(),
                has_dns,
                registrar: whois.registrar,
                expiry_date: whois.expiry_date,
                latency_ms,
                detail: if has_dns {
                    Some("Registered (WHOIS/RDAP + active DNS)".to_string())
                } else {
                    Some("Registered (WHOIS/RDAP record found, no active DNS)".to_string())
                },
            },
            "not_found" => {
                if has_dns {
                    TldAvailabilityItem {
                        domain,
                        tld: tld.to_string(),
                        status: "registered".to_string(),
                        has_dns: true,
                        registrar: None,
                        expiry_date: None,
                        latency_ms,
                        detail: Some("Active DNS records detected despite WHOIS not-found".to_string()),
                    }
                } else {
                    TldAvailabilityItem {
                        domain,
                        tld: tld.to_string(),
                        status: "available".to_string(),
                        has_dns: false,
                        registrar: None,
                        expiry_date: None,
                        latency_ms,
                        detail: Some("No WHOIS/RDAP registration or DNS records found".to_string()),
                    }
                }
            }
            _ => {
                if has_dns {
                    TldAvailabilityItem {
                        domain,
                        tld: tld.to_string(),
                        status: "registered".to_string(),
                        has_dns: true,
                        registrar: None,
                        expiry_date: None,
                        latency_ms,
                        detail: Some("Active DNS records found (WHOIS/RDAP unavailable)".to_string()),
                    }
                } else {
                    TldAvailabilityItem {
                        domain,
                        tld: tld.to_string(),
                        status: "unknown".to_string(),
                        has_dns: false,
                        registrar: None,
                        expiry_date: None,
                        latency_ms,
                        detail: whois
                            .error
                            .or_else(|| Some("Registry lookup unavailable".to_string())),
                    }
                }
            }
        },
        Err(_) => {
            if has_dns {
                TldAvailabilityItem {
                    domain,
                    tld: tld.to_string(),
                    status: "registered".to_string(),
                    has_dns: true,
                    registrar: None,
                    expiry_date: None,
                    latency_ms,
                    detail: Some("Active DNS records found (WHOIS/RDAP timed out)".to_string()),
                }
            } else {
                TldAvailabilityItem {
                    domain,
                    tld: tld.to_string(),
                    status: "unknown".to_string(),
                    has_dns: false,
                    registrar: None,
                    expiry_date: None,
                    latency_ms,
                    detail: Some("WHOIS/RDAP lookup timed out".to_string()),
                }
            }
        }
    }
}

pub async fn check_tld_availability(
    base_name_input: &str,
    tlds_input: Option<Vec<String>>,
) -> Result<TldAvailabilityReport, String> {
    let base_name = clean_base_name(base_name_input)?;
    let tlds = normalize_tlds(tlds_input);
    let started = Instant::now();

    let resolver = build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false))
        .map(|(_, _, r)| r)?;

    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_CHECKS));
    let futs = tlds.iter().map(|tld| {
        let sem_clone = Arc::clone(&sem);
        let resolver_ref = &resolver;
        let base_ref = &base_name;
        async move { check_single_tld(base_ref, tld, resolver_ref, sem_clone).await }
    });

    let items = join_all(futs).await;
    let checked_count = items.len();
    let available_count = items.iter().filter(|i| i.status == "available").count();
    let registered_count = items.iter().filter(|i| i.status == "registered").count();

    Ok(TldAvailabilityReport {
        base_name,
        checked_count,
        available_count,
        registered_count,
        latency_ms: started.elapsed().as_millis() as u64,
        items,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clean_base_name() {
        assert_eq!(clean_base_name("Acme").unwrap(), "acme");
        assert_eq!(clean_base_name("https://www.Example.COM/foo").unwrap(), "example");
        assert_eq!(clean_base_name("my-brand.co.uk").unwrap(), "my-brand");
        assert_eq!(clean_base_name("  --Cool-App--  ").unwrap(), "cool-app");
        assert!(clean_base_name("").is_err());
        assert!(clean_base_name("!!!").is_err());
    }

    #[test]
    fn test_normalize_tlds_defaults_and_cap() {
        let defaults = normalize_tlds(None);
        assert_eq!(defaults.len(), 12);
        assert!(defaults.contains(&"com".to_string()));
        assert!(defaults.contains(&"cloud".to_string()));

        let custom = normalize_tlds(Some(vec![
            ".COM".into(),
            "io".into(),
            "com".into(),
            "bad..tld".into(),
            "co.uk".into(),
        ]));
        assert_eq!(custom, vec!["com", "io", "co.uk"]);

        let many: Vec<String> = (0..40).map(|i| format!("t{i}")).collect();
        let capped = normalize_tlds(Some(many));
        assert_eq!(capped.len(), MAX_TLDS);
    }
}
