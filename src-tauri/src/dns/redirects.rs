use std::collections::HashSet;
use std::time::{Duration, Instant};

use futures::future::join_all;
use reqwest::redirect::Policy;
use reqwest::Url;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::dns::normalize_domain;
use crate::dns::tls::build_permissive_tls_connector;
use crate::models::{RedirectChain, RedirectHop, RedirectReport, TimingWaterfall};

const STEP_TIMEOUT: Duration = Duration::from_secs(5);
const WATERFALL_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_HOPS: usize = 10;

pub fn resolve_next_url(base_url: &str, location: &str) -> Option<String> {
    let base = Url::parse(base_url).ok()?;
    base.join(location.trim()).ok().map(|u| u.to_string())
}

pub fn parse_hsts_header(header: &str) -> (Option<u64>, bool, bool) {
    let mut max_age = None;
    let mut include_subdomains = false;
    let mut preload = false;

    for part in header.split(';') {
        let trimmed = part.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(val) = lower.strip_prefix("max-age=") {
            let cleaned = val.trim().trim_matches('"');
            if let Ok(num) = cleaned.parse::<u64>() {
                max_age = Some(num);
            }
        } else if lower == "includesubdomains" {
            include_subdomains = true;
        } else if lower == "preload" {
            preload = true;
        }
    }

    (max_age, include_subdomains, preload)
}

async fn trace_single_chain(
    client: &reqwest::Client,
    label: &str,
    start_url: &str,
) -> RedirectChain {
    let total_start = Instant::now();
    let mut current_url = start_url.to_string();
    let mut visited = HashSet::new();
    let mut hops = Vec::new();
    let mut has_loop = false;
    let mut error = None;

    for idx in 1..=MAX_HOPS {
        if !visited.insert(current_url.clone()) {
            has_loop = true;
            error = Some(format!("Redirect loop detected at {current_url}"));
            break;
        }

        let hop_start = Instant::now();
        let resp = match client.get(&current_url).send().await {
            Ok(r) => r,
            Err(e) => {
                error = Some(format!("Request to {current_url} failed: {e}"));
                break;
            }
        };

        let latency_ms = hop_start.elapsed().as_millis() as u64;
        let status = resp.status();
        let status_code = status.as_u16();
        let status_text = status.canonical_reason().unwrap_or("").to_string();
        let headers = resp.headers();

        let location = headers
            .get(reqwest::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        let server = headers
            .get(reqwest::header::SERVER)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        let hsts = headers
            .get(reqwest::header::STRICT_TRANSPORT_SECURITY)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());
        let cache_control = headers
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.trim().to_string());

        let resolved_next_url = location
            .as_deref()
            .and_then(|loc| resolve_next_url(&current_url, loc));

        hops.push(RedirectHop {
            hop_index: idx,
            url: current_url.clone(),
            status_code,
            status_text,
            location,
            resolved_next_url: resolved_next_url.clone(),
            latency_ms,
            server,
            hsts,
            cache_control,
        });

        if status.is_redirection() {
            if let Some(next_url) = resolved_next_url {
                current_url = next_url;
                continue;
            }
        }
        break;
    }

    let final_hop = hops.last();
    let final_url = final_hop
        .map(|h| h.url.clone())
        .unwrap_or_else(|| current_url);
    let final_status = final_hop.map(|h| h.status_code);
    let hop_count = hops.iter().filter(|h| (300..400).contains(&h.status_code)).count();

    RedirectChain {
        label: label.to_string(),
        start_url: start_url.to_string(),
        final_url,
        final_status,
        hop_count,
        total_ms: total_start.elapsed().as_millis() as u64,
        has_loop,
        hops,
        error,
    }
}

fn parse_http_status_line(buf: &[u8]) -> Option<u16> {
    let text = std::str::from_utf8(buf).ok()?;
    let first_line = text.lines().next()?;
    let code_str = first_line.split_whitespace().nth(1)?;
    code_str.parse::<u16>().ok()
}

pub async fn measure_timing_waterfall(target_url: &str) -> TimingWaterfall {
    let total_start = Instant::now();
    let parsed = match Url::parse(target_url) {
        Ok(u) => u,
        Err(e) => {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms: 0,
                tcp_ms: 0,
                tls_ms: None,
                ttfb_ms: 0,
                total_ms: 0,
                http_status: None,
                error: Some(format!("Invalid URL '{target_url}': {e}")),
            }
        }
    };

    let Some(host) = parsed.host_str().map(|s| s.to_string()) else {
        return TimingWaterfall {
            target_url: target_url.to_string(),
            dns_ms: 0,
            tcp_ms: 0,
            tls_ms: None,
            ttfb_ms: 0,
            total_ms: 0,
            http_status: None,
            error: Some("URL does not contain a host.".to_string()),
        };
    };

    let is_https = parsed.scheme().eq_ignore_ascii_case("https");
    let port = parsed.port_or_known_default().unwrap_or(if is_https { 443 } else { 80 });
    let mut path_and_query = parsed.path().to_string();
    if path_and_query.is_empty() {
        path_and_query.push('/');
    }
    if let Some(q) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    // 1. DNS lookup
    let dns_start = Instant::now();
    let addrs = match timeout(WATERFALL_TIMEOUT, lookup_host((host.as_str(), port))).await {
        Ok(Ok(iter)) => iter.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms: dns_start.elapsed().as_millis() as u64,
                tcp_ms: 0,
                tls_ms: None,
                ttfb_ms: 0,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some(format!("DNS lookup failed: {e}")),
            }
        }
        Err(_) => {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms: dns_start.elapsed().as_millis() as u64,
                tcp_ms: 0,
                tls_ms: None,
                ttfb_ms: 0,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some("DNS lookup timed out.".to_string()),
            }
        }
    };
    let dns_ms = dns_start.elapsed().as_millis() as u64;

    let Some(sock) = addrs.into_iter().next() else {
        return TimingWaterfall {
            target_url: target_url.to_string(),
            dns_ms,
            tcp_ms: 0,
            tls_ms: None,
            ttfb_ms: 0,
            total_ms: total_start.elapsed().as_millis() as u64,
            http_status: None,
            error: Some("No IP address resolved for host.".to_string()),
        };
    };

    // 2. TCP connect
    let tcp_start = Instant::now();
    let mut tcp = match timeout(WATERFALL_TIMEOUT, TcpStream::connect(sock)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms,
                tcp_ms: tcp_start.elapsed().as_millis() as u64,
                tls_ms: None,
                ttfb_ms: 0,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some(format!("TCP connect failed: {e}")),
            }
        }
        Err(_) => {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms,
                tcp_ms: tcp_start.elapsed().as_millis() as u64,
                tls_ms: None,
                ttfb_ms: 0,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some("TCP connect timed out.".to_string()),
            }
        }
    };
    let tcp_ms = tcp_start.elapsed().as_millis() as u64;

    let host_header = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.clone(),
    };
    let request_bytes = format!(
        "GET {path_and_query} HTTP/1.1\r\nHost: {host_header}\r\nUser-Agent: DomainTools/1.0\r\nAccept: text/html,application/xhtml+xml,*/*;q=0.8\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
    );

    if is_https {
        let tls_start = Instant::now();
        let (connector, _) = match build_permissive_tls_connector() {
            Ok(c) => c,
            Err(e) => {
                return TimingWaterfall {
                    target_url: target_url.to_string(),
                    dns_ms,
                    tcp_ms,
                    tls_ms: Some(0),
                    ttfb_ms: 0,
                    total_ms: total_start.elapsed().as_millis() as u64,
                    http_status: None,
                    error: Some(e),
                }
            }
        };

        let server_name = match ServerName::try_from(host.clone()) {
            Ok(sn) => sn,
            Err(e) => {
                return TimingWaterfall {
                    target_url: target_url.to_string(),
                    dns_ms,
                    tcp_ms,
                    tls_ms: Some(0),
                    ttfb_ms: 0,
                    total_ms: total_start.elapsed().as_millis() as u64,
                    http_status: None,
                    error: Some(format!("Invalid TLS host '{host}': {e}")),
                }
            }
        };

        let mut tls_stream = match timeout(WATERFALL_TIMEOUT, connector.connect(server_name, tcp)).await {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => {
                return TimingWaterfall {
                    target_url: target_url.to_string(),
                    dns_ms,
                    tcp_ms,
                    tls_ms: Some(tls_start.elapsed().as_millis() as u64),
                    ttfb_ms: 0,
                    total_ms: total_start.elapsed().as_millis() as u64,
                    http_status: None,
                    error: Some(format!("TLS handshake failed: {e}")),
                }
            }
            Err(_) => {
                return TimingWaterfall {
                    target_url: target_url.to_string(),
                    dns_ms,
                    tcp_ms,
                    tls_ms: Some(tls_start.elapsed().as_millis() as u64),
                    ttfb_ms: 0,
                    total_ms: total_start.elapsed().as_millis() as u64,
                    http_status: None,
                    error: Some("TLS handshake timed out.".to_string()),
                }
            }
        };
        let tls_ms = tls_start.elapsed().as_millis() as u64;

        let ttfb_start = Instant::now();
        if let Err(e) = timeout(WATERFALL_TIMEOUT, tls_stream.write_all(request_bytes.as_bytes())).await {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms,
                tcp_ms,
                tls_ms: Some(tls_ms),
                ttfb_ms: ttfb_start.elapsed().as_millis() as u64,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some(format!("HTTP write failed: {e}")),
            };
        }
        let mut buf = [0u8; 512];
        let (http_status, err) = match timeout(WATERFALL_TIMEOUT, tls_stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => (parse_http_status_line(&buf[..n]), None),
            Ok(Ok(_)) => (None, Some("Server closed connection without response.".to_string())),
            Ok(Err(e)) => (None, Some(format!("HTTP read failed: {e}"))),
            Err(_) => (None, Some("Timed out waiting for first byte (TTFB).".to_string())),
        };
        let ttfb_ms = ttfb_start.elapsed().as_millis() as u64;

        TimingWaterfall {
            target_url: target_url.to_string(),
            dns_ms,
            tcp_ms,
            tls_ms: Some(tls_ms),
            ttfb_ms,
            total_ms: total_start.elapsed().as_millis() as u64,
            http_status,
            error: err,
        }
    } else {
        let ttfb_start = Instant::now();
        if let Err(e) = timeout(WATERFALL_TIMEOUT, tcp.write_all(request_bytes.as_bytes())).await {
            return TimingWaterfall {
                target_url: target_url.to_string(),
                dns_ms,
                tcp_ms,
                tls_ms: None,
                ttfb_ms: ttfb_start.elapsed().as_millis() as u64,
                total_ms: total_start.elapsed().as_millis() as u64,
                http_status: None,
                error: Some(format!("HTTP write failed: {e}")),
            };
        }
        let mut buf = [0u8; 512];
        let (http_status, err) = match timeout(WATERFALL_TIMEOUT, tcp.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => (parse_http_status_line(&buf[..n]), None),
            Ok(Ok(_)) => (None, Some("Server closed connection without response.".to_string())),
            Ok(Err(e)) => (None, Some(format!("HTTP read failed: {e}"))),
            Err(_) => (None, Some("Timed out waiting for first byte (TTFB).".to_string())),
        };
        let ttfb_ms = ttfb_start.elapsed().as_millis() as u64;

        TimingWaterfall {
            target_url: target_url.to_string(),
            dns_ms,
            tcp_ms,
            tls_ms: None,
            ttfb_ms,
            total_ms: total_start.elapsed().as_millis() as u64,
            http_status,
            error: err,
        }
    }
}

fn normalize_url_key(url: &str) -> String {
    url.trim().trim_end_matches('/').to_ascii_lowercase()
}

pub fn evaluate_canonical_chains(chains: &[RedirectChain]) -> (Option<String>, bool, bool, Vec<String>) {
    let mut issues = Vec::new();

    for ch in chains {
        if ch.has_loop {
            issues.push(format!("{} entered a redirect loop.", ch.label));
        }
        if ch.hop_count > 3 {
            issues.push(format!(
                "{} required {} redirects (consider consolidating to 1 hop).",
                ch.label, ch.hop_count
            ));
        }
    }

    let http_apex = chains.iter().find(|c| c.label == "HTTP Apex");
    let http_to_https = http_apex
        .map(|c| c.error.is_none() && c.final_url.starts_with("https://"))
        .unwrap_or(false);

    if let Some(c) = http_apex {
        if c.error.is_none() && !c.final_url.starts_with("https://") {
            issues.push("HTTP apex does not redirect to HTTPS.".to_string());
        }
    }

    let successful_finals: Vec<String> = chains
        .iter()
        .filter(|c| c.error.is_none() && c.final_status.map(|s| s < 400).unwrap_or(false))
        .map(|c| c.final_url.clone())
        .collect();

    let canonical_url = chains
        .iter()
        .find(|c| c.label == "HTTPS Apex" && c.error.is_none())
        .or_else(|| chains.iter().find(|c| c.error.is_none()))
        .map(|c| c.final_url.clone());

    let unique_finals: HashSet<String> = successful_finals.iter().map(|u| normalize_url_key(u)).collect();
    let canonical_consistent = !unique_finals.is_empty() && unique_finals.len() == 1;
    if unique_finals.len() > 1 {
        issues.push(
            "Apex and www endpoints resolve to different final URLs instead of one canonical host."
                .to_string(),
        );
    }

    (canonical_url, http_to_https, canonical_consistent, issues)
}

fn summarize_report(chains: Vec<RedirectChain>, waterfall: Option<TimingWaterfall>, latency_ms: u64) -> RedirectReport {
    let (canonical_url, http_to_https, canonical_consistent, mut issues) =
        evaluate_canonical_chains(&chains);

    let hsts_header = chains
        .iter()
        .flat_map(|c| c.hops.iter().rev())
        .filter(|h| h.url.starts_with("https://"))
        .find_map(|h| h.hsts.clone());

    let (hsts_present, hsts_max_age, hsts_include_subdomains, hsts_preload) = match hsts_header {
        Some(hdr) => {
            let (max_age, sub, preload) = parse_hsts_header(&hdr);
            (true, max_age, sub, preload)
        }
        None => (false, None, false, false),
    };

    if !hsts_present && chains.iter().any(|c| c.final_url.starts_with("https://") && c.error.is_none()) {
        issues.push("Strict-Transport-Security (HSTS) header is not set on HTTPS responses.".to_string());
    }

    let any_ok = chains.iter().any(|c| !c.hops.is_empty());
    let status = if !any_ok {
        "unavailable".to_string()
    } else if chains.iter().any(|c| c.has_loop) {
        "error".to_string()
    } else if !issues.is_empty() {
        "warning".to_string()
    } else {
        "ok".to_string()
    };

    RedirectReport {
        status,
        canonical_url,
        http_to_https,
        canonical_consistent,
        hsts_present,
        hsts_max_age,
        hsts_include_subdomains,
        hsts_preload,
        chains,
        waterfall,
        issues,
        latency_ms,
        error: if any_ok {
            None
        } else {
            Some("Could not reach HTTP or HTTPS endpoints for redirect inspection.".to_string())
        },
    }
}

pub async fn inspect_redirects(domain: &str) -> RedirectReport {
    let started = Instant::now();
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(STEP_TIMEOUT)
        .user_agent("DomainTools/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let targets = [
        ("HTTP Apex", format!("http://{domain}")),
        ("HTTPS Apex", format!("https://{domain}")),
        ("HTTP www", format!("http://www.{domain}")),
        ("HTTPS www", format!("https://www.{domain}")),
    ];

    let chains = join_all(
        targets
            .iter()
            .map(|(label, url)| trace_single_chain(&client, label, url)),
    )
    .await;

    let waterfall_target = chains
        .iter()
        .find(|c| c.error.is_none() && c.final_status.map(|s| s < 400).unwrap_or(false))
        .map(|c| c.final_url.clone())
        .unwrap_or_else(|| format!("https://{domain}"));

    let waterfall = measure_timing_waterfall(&waterfall_target).await;
    summarize_report(chains, Some(waterfall), started.elapsed().as_millis() as u64)
}

pub async fn trace_custom_url(input: &str) -> RedirectReport {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return RedirectReport {
            status: "error".to_string(),
            canonical_url: None,
            http_to_https: false,
            canonical_consistent: false,
            hsts_present: false,
            hsts_max_age: None,
            hsts_include_subdomains: false,
            hsts_preload: false,
            chains: vec![],
            waterfall: None,
            issues: vec![],
            latency_ms: 0,
            error: Some("Enter a URL or domain to trace.".to_string()),
        };
    }

    if !trimmed.contains("://") && !trimmed.contains('/') {
        if let Ok(domain) = normalize_domain(trimmed) {
            return inspect_redirects(&domain).await;
        }
    }

    let started = Instant::now();
    let normalized_url = if trimmed.contains("://") {
        trimmed.to_string()
    } else {
        format!("https://{trimmed}")
    };

    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .timeout(STEP_TIMEOUT)
        .user_agent("DomainTools/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let chain = trace_single_chain(&client, "Custom URL", &normalized_url).await;
    let waterfall_target = if chain.error.is_none() {
        chain.final_url.clone()
    } else {
        normalized_url
    };
    let waterfall = measure_timing_waterfall(&waterfall_target).await;
    summarize_report(vec![chain], Some(waterfall), started.elapsed().as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resolve_next_url() {
        assert_eq!(
            resolve_next_url("https://example.com/old", "/new?a=1").as_deref(),
            Some("https://example.com/new?a=1")
        );
        assert_eq!(
            resolve_next_url("http://example.com/", "https://www.example.com/").as_deref(),
            Some("https://www.example.com/")
        );
    }

    #[test]
    fn test_parse_hsts_header() {
        let (max_age, sub, preload) =
            parse_hsts_header("max-age=31536000; includeSubDomains; preload");
        assert_eq!(max_age, Some(31536000));
        assert!(sub);
        assert!(preload);
    }

    #[test]
    fn test_evaluate_canonical_chains() {
        let chains = vec![
            RedirectChain {
                label: "HTTP Apex".to_string(),
                start_url: "http://example.com".to_string(),
                final_url: "https://www.example.com/".to_string(),
                final_status: Some(200),
                hop_count: 1,
                total_ms: 80,
                has_loop: false,
                hops: vec![],
                error: None,
            },
            RedirectChain {
                label: "HTTPS Apex".to_string(),
                start_url: "https://example.com".to_string(),
                final_url: "https://www.example.com/".to_string(),
                final_status: Some(200),
                hop_count: 1,
                total_ms: 90,
                has_loop: false,
                hops: vec![],
                error: None,
            },
        ];

        let (canon, http_https, consistent, issues) = evaluate_canonical_chains(&chains);
        assert_eq!(canon.as_deref(), Some("https://www.example.com/"));
        assert!(http_https);
        assert!(consistent);
        assert!(issues.is_empty());
    }
}
