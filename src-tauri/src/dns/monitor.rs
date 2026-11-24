use std::net::IpAddr;
use std::time::{Duration, Instant};

use chrono::Utc;
use tokio::net::{lookup_host, TcpStream};
use tokio::time::timeout;

use crate::dns::{build_resolver, format_record, normalize_domain, parse_record_type, redirects};
use crate::models::{MonitorProbeRequest, MonitorProbeResult};

const PROBE_TIMEOUT: Duration = Duration::from_secs(4);

fn extract_host(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Monitor target cannot be empty.".to_string());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    normalize_domain(trimmed)
}

async fn probe_https(target: &str) -> MonitorProbeResult {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return MonitorProbeResult {
            timestamp: Utc::now().to_rfc3339(),
            mode: "https".to_string(),
            target: target.to_string(),
            status: "down".to_string(),
            total_ms: 0,
            dns_ms: None,
            tcp_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            http_status: None,
            resolved_values: vec![],
            summary: "Target cannot be empty".to_string(),
            error: Some("Target cannot be empty.".to_string()),
        };
    }

    let url = if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        trimmed.to_string()
    } else {
        match normalize_domain(trimmed) {
            Ok(d) => format!("https://{d}"),
            Err(e) => {
                return MonitorProbeResult {
                    timestamp: Utc::now().to_rfc3339(),
                    mode: "https".to_string(),
                    target: trimmed.to_string(),
                    status: "down".to_string(),
                    total_ms: 0,
                    dns_ms: None,
                    tcp_ms: None,
                    tls_ms: None,
                    ttfb_ms: None,
                    http_status: None,
                    resolved_values: vec![],
                    summary: e.clone(),
                    error: Some(e),
                }
            }
        }
    };

    let wf = redirects::measure_timing_waterfall(&url).await;
    let (status, summary) = if let Some(ref err) = wf.error {
        ("down".to_string(), err.clone())
    } else {
        match wf.http_status {
            Some(code) if code >= 500 => ("down".to_string(), format!("HTTP {code}")),
            Some(code) if code >= 400 => ("degraded".to_string(), format!("HTTP {code}")),
            Some(code) if wf.total_ms > 1500 => {
                ("degraded".to_string(), format!("HTTP {code} (slow: {}ms)", wf.total_ms))
            }
            Some(code) => ("up".to_string(), format!("HTTP {code} in {}ms", wf.total_ms)),
            None => ("down".to_string(), "No HTTP status received".to_string()),
        }
    };

    MonitorProbeResult {
        timestamp: Utc::now().to_rfc3339(),
        mode: "https".to_string(),
        target: url,
        status,
        total_ms: wf.total_ms,
        dns_ms: Some(wf.dns_ms),
        tcp_ms: Some(wf.tcp_ms),
        tls_ms: wf.tls_ms,
        ttfb_ms: Some(wf.ttfb_ms),
        http_status: wf.http_status,
        resolved_values: vec![],
        summary,
        error: wf.error,
    }
}

async fn probe_tcp(target: &str, port: u16) -> MonitorProbeResult {
    let total_start = Instant::now();
    let host = match extract_host(target) {
        Ok(h) => h,
        Err(e) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "tcp".to_string(),
                target: format!("{}:{port}", target.trim()),
                status: "down".to_string(),
                total_ms: 0,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: e.clone(),
                error: Some(e),
            }
        }
    };

    let dns_start = Instant::now();
    let addrs = match timeout(PROBE_TIMEOUT, lookup_host((host.as_str(), port))).await {
        Ok(Ok(iter)) => iter.collect::<Vec<_>>(),
        Ok(Err(e)) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "tcp".to_string(),
                target: format!("{host}:{port}"),
                status: "down".to_string(),
                total_ms: total_start.elapsed().as_millis() as u64,
                dns_ms: Some(dns_start.elapsed().as_millis() as u64),
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: format!("DNS failed: {e}"),
                error: Some(format!("DNS failed: {e}")),
            }
        }
        Err(_) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "tcp".to_string(),
                target: format!("{host}:{port}"),
                status: "down".to_string(),
                total_ms: total_start.elapsed().as_millis() as u64,
                dns_ms: Some(dns_start.elapsed().as_millis() as u64),
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: "DNS timed out".to_string(),
                error: Some("DNS timed out.".to_string()),
            }
        }
    };
    let dns_ms = dns_start.elapsed().as_millis() as u64;
    let resolved_values: Vec<String> = addrs.iter().map(|a| a.ip().to_string()).collect();

    let Some(sock) = addrs.into_iter().next() else {
        return MonitorProbeResult {
            timestamp: Utc::now().to_rfc3339(),
            mode: "tcp".to_string(),
            target: format!("{host}:{port}"),
            status: "down".to_string(),
            total_ms: total_start.elapsed().as_millis() as u64,
            dns_ms: Some(dns_ms),
            tcp_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            http_status: None,
            resolved_values,
            summary: "No IP resolved".to_string(),
            error: Some("No IP resolved for target.".to_string()),
        };
    };

    let tcp_start = Instant::now();
    match timeout(PROBE_TIMEOUT, TcpStream::connect(sock)).await {
        Ok(Ok(_)) => {
            let tcp_ms = tcp_start.elapsed().as_millis() as u64;
            let total_ms = total_start.elapsed().as_millis() as u64;
            let status = if total_ms > 800 { "degraded" } else { "up" };
            MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "tcp".to_string(),
                target: format!("{host}:{port}"),
                status: status.to_string(),
                total_ms,
                dns_ms: Some(dns_ms),
                tcp_ms: Some(tcp_ms),
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values,
                summary: format!("TCP :{port} connected ({tcp_ms}ms)"),
                error: None,
            }
        }
        Ok(Err(e)) => {
            let tcp_ms = tcp_start.elapsed().as_millis() as u64;
            MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "tcp".to_string(),
                target: format!("{host}:{port}"),
                status: "down".to_string(),
                total_ms: total_start.elapsed().as_millis() as u64,
                dns_ms: Some(dns_ms),
                tcp_ms: Some(tcp_ms),
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values,
                summary: format!("TCP :{port} refused/failed"),
                error: Some(format!("TCP connect failed: {e}")),
            }
        }
        Err(_) => MonitorProbeResult {
            timestamp: Utc::now().to_rfc3339(),
            mode: "tcp".to_string(),
            target: format!("{host}:{port}"),
            status: "down".to_string(),
            total_ms: total_start.elapsed().as_millis() as u64,
            dns_ms: Some(dns_ms),
            tcp_ms: Some(tcp_start.elapsed().as_millis() as u64),
            tls_ms: None,
            ttfb_ms: None,
            http_status: None,
            resolved_values,
            summary: format!("TCP :{port} timed out"),
            error: Some(format!("TCP connection to {host}:{port} timed out.")),
        },
    }
}

async fn probe_dns(target: &str, resolver_id: &str, record_type_name: &str) -> MonitorProbeResult {
    let total_start = Instant::now();
    let domain = match normalize_domain(target) {
        Ok(d) => d,
        Err(e) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "dns".to_string(),
                target: target.to_string(),
                status: "down".to_string(),
                total_ms: 0,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: e.clone(),
                error: Some(e),
            }
        }
    };

    let rtype = match parse_record_type(record_type_name) {
        Ok(t) => t,
        Err(e) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "dns".to_string(),
                target: domain,
                status: "down".to_string(),
                total_ms: 0,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: e.clone(),
                error: Some(e),
            }
        }
    };

    let (res_label, _, resolver) = match build_resolver(resolver_id, None, false) {
        Ok(triple) => triple,
        Err(e) => {
            return MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "dns".to_string(),
                target: domain,
                status: "down".to_string(),
                total_ms: 0,
                dns_ms: None,
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: e.clone(),
                error: Some(e),
            }
        }
    };

    let fqdn = format!("{domain}.");
    let query_start = Instant::now();
    match timeout(PROBE_TIMEOUT, resolver.lookup(fqdn, rtype)).await {
        Ok(Ok(lookup)) => {
            let dns_ms = query_start.elapsed().as_millis() as u64;
            let mut values: Vec<String> = lookup
                .record_iter()
                .map(|r| format_record(r).value)
                .collect();
            values.sort();
            values.dedup();
            let status = if dns_ms > 500 { "degraded" } else { "up" };
            let summary = if values.is_empty() {
                format!("{record_type_name} via {res_label}: 0 records ({dns_ms}ms)")
            } else {
                format!(
                    "{record_type_name} via {res_label}: {} ({dns_ms}ms)",
                    values.join(", ")
                )
            };
            MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "dns".to_string(),
                target: domain,
                status: status.to_string(),
                total_ms: total_start.elapsed().as_millis() as u64,
                dns_ms: Some(dns_ms),
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: values,
                summary,
                error: None,
            }
        }
        Ok(Err(e)) => {
            let dns_ms = query_start.elapsed().as_millis() as u64;
            let err_str = e.to_string();
            let status = if err_str.to_ascii_lowercase().contains("no record") {
                "degraded"
            } else {
                "down"
            };
            MonitorProbeResult {
                timestamp: Utc::now().to_rfc3339(),
                mode: "dns".to_string(),
                target: domain,
                status: status.to_string(),
                total_ms: total_start.elapsed().as_millis() as u64,
                dns_ms: Some(dns_ms),
                tcp_ms: None,
                tls_ms: None,
                ttfb_ms: None,
                http_status: None,
                resolved_values: vec![],
                summary: format!("{record_type_name} via {res_label}: query error"),
                error: Some(err_str),
            }
        }
        Err(_) => MonitorProbeResult {
            timestamp: Utc::now().to_rfc3339(),
            mode: "dns".to_string(),
            target: domain,
            status: "down".to_string(),
            total_ms: total_start.elapsed().as_millis() as u64,
            dns_ms: Some(query_start.elapsed().as_millis() as u64),
            tcp_ms: None,
            tls_ms: None,
            ttfb_ms: None,
            http_status: None,
            resolved_values: vec![],
            summary: format!("{record_type_name} via {res_label}: timed out"),
            error: Some("DNS probe timed out.".to_string()),
        },
    }
}

pub async fn probe_endpoint(req: MonitorProbeRequest) -> MonitorProbeResult {
    match req.mode.trim().to_ascii_lowercase().as_str() {
        "tcp" => probe_tcp(&req.target, req.port.unwrap_or(443)).await,
        "dns" => {
            let res = req.resolver.as_deref().unwrap_or("cloudflare");
            let rtype = req.record_type.as_deref().unwrap_or("A");
            probe_dns(&req.target, res, rtype).await
        }
        _ => probe_https(&req.target).await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_probe_tcp_local_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = probe_endpoint(MonitorProbeRequest {
            target: "127.0.0.1".to_string(),
            mode: "tcp".to_string(),
            port: Some(port),
            resolver: None,
            record_type: None,
        })
        .await;

        assert_eq!(result.status, "up");
        assert!(result.error.is_none());
        assert!(result.tcp_ms.is_some());
        let _ = server.await;
    }
}
