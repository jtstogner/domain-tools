use std::net::IpAddr;
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::dns::tls::{build_permissive_tls_connector, hostname_matches_cert, parse_cert_der};
use crate::dns::{build_resolver, normalize_domain};
use crate::models::{SmtpDeliverabilityReport, SmtpMxProbe};

const SMTP_TCP_TIMEOUT: Duration = Duration::from_millis(3500);
const SMTP_IO_TIMEOUT: Duration = Duration::from_millis(3000);
const MAX_MX_PROBES: usize = 4;

async fn read_smtp_reply(reader: &mut BufReader<&mut TcpStream>) -> Result<(u16, Vec<String>), String> {
    let mut lines = Vec::new();
    let mut last_code = 0u16;
    for _ in 0..48 {
        let mut line = String::new();
        let n = timeout(SMTP_IO_TIMEOUT, reader.read_line(&mut line))
            .await
            .map_err(|_| "SMTP response timed out.".to_string())?
            .map_err(|e| format!("SMTP read error: {e}"))?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
        if trimmed.len() >= 3 {
            if let Ok(code) = trimmed[..3].parse::<u16>() {
                last_code = code;
            }
        }
        let has_more = trimmed.len() >= 4 && trimmed.as_bytes()[3] == b'-';
        lines.push(trimmed);
        if !has_more {
            break;
        }
    }
    Ok((last_code, lines))
}

pub fn parse_ehlo_extensions(lines: &[String]) -> Vec<String> {
    let mut exts = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        // First line is usually "250-hostname greets ..."
        if idx == 0 {
            continue;
        }
        if line.len() > 4 {
            let ext = line[4..].trim();
            if !ext.is_empty() {
                exts.push(ext.to_string());
            }
        }
    }
    exts
}

pub fn banner_matches_any_ptr(banner: &str, ptr_records: &[String]) -> bool {
    if ptr_records.is_empty() {
        return false;
    }
    let rest = banner
        .strip_prefix("220")
        .unwrap_or(banner)
        .trim_start_matches(['-', ' ']);
    let banner_host = rest
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if banner_host.is_empty() {
        return false;
    }
    ptr_records
        .iter()
        .any(|p| p.trim_end_matches('.').eq_ignore_ascii_case(&banner_host))
}

async fn resolve_mx_ip(resolver: &TokioResolver, mx_host: &str) -> Option<IpAddr> {
    let fqdn = format!("{mx_host}.");
    if let Ok(Ok(a_lookup)) = timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::A)).await {
        for rec in a_lookup.record_iter() {
            if let RData::A(v4) = rec.data() {
                return Some(IpAddr::V4(v4.0));
            }
        }
    }
    if let Ok(Ok(aaaa_lookup)) =
        timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::AAAA)).await
    {
        for rec in aaaa_lookup.record_iter() {
            if let RData::AAAA(v6) = rec.data() {
                return Some(IpAddr::V6(v6.0));
            }
        }
    }
    None
}

async fn verify_fcrdns(resolver: &TokioResolver, ip: IpAddr) -> (Vec<String>, bool) {
    let ptrs: Vec<String> = match timeout(Duration::from_secs(2), resolver.reverse_lookup(ip)).await {
        Ok(Ok(resp)) => resp
            .iter()
            .map(|p| p.0.to_string().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => vec![],
    };
    if ptrs.is_empty() {
        return (ptrs, false);
    }

    for ptr in &ptrs {
        let fqdn = format!("{ptr}.");
        let rtype = if ip.is_ipv4() {
            RecordType::A
        } else {
            RecordType::AAAA
        };
        if let Ok(Ok(fwd)) = timeout(Duration::from_secs(2), resolver.lookup(&fqdn, rtype)).await {
            for rec in fwd.record_iter() {
                let matched = match rec.data() {
                    RData::A(a) => IpAddr::V4(a.0) == ip,
                    RData::AAAA(aaaa) => IpAddr::V6(aaaa.0) == ip,
                    _ => false,
                };
                if matched {
                    return (ptrs, true);
                }
            }
        }
    }

    (ptrs, false)
}

async fn probe_single_mx(
    resolver: &TokioResolver,
    mx_host: String,
    priority: u16,
) -> SmtpMxProbe {
    let started = Instant::now();
    let mut issues = Vec::new();

    let ip = resolve_mx_ip(resolver, &mx_host).await;
    let Some(target_ip) = ip else {
        return SmtpMxProbe {
            mx_host,
            priority,
            ip: None,
            ptr_records: vec![],
            fcrdns_valid: false,
            banner_matches_ptr: false,
            reachable: false,
            banner: None,
            ehlo_extensions: vec![],
            supports_starttls: false,
            starttls_negotiated: false,
            tls_version: None,
            tls_cert_valid: None,
            tls_cert_cn: None,
            tls_days_remaining: None,
            latency_ms: started.elapsed().as_millis() as u64,
            issues: vec!["MX hostname failed to resolve to an A or AAAA IP.".to_string()],
            error: Some("DNS resolution for MX host failed".to_string()),
        };
    };

    let (ptr_records, fcrdns_valid) = verify_fcrdns(resolver, target_ip).await;
    if ptr_records.is_empty() {
        issues.push(format!("No PTR reverse DNS record found for {target_ip}."));
    } else if !fcrdns_valid {
        issues.push(format!(
            "Forward-confirmed rDNS (FCrDNS) mismatch for {target_ip}."
        ));
    }

    let addr = std::net::SocketAddr::new(target_ip, 25);
    let mut stream = match timeout(SMTP_TCP_TIMEOUT, TcpStream::connect(addr)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return SmtpMxProbe {
                mx_host,
                priority,
                ip: Some(target_ip.to_string()),
                ptr_records,
                fcrdns_valid,
                banner_matches_ptr: false,
                reachable: false,
                banner: None,
                ehlo_extensions: vec![],
                supports_starttls: false,
                starttls_negotiated: false,
                tls_version: None,
                tls_cert_valid: None,
                tls_cert_cn: None,
                tls_days_remaining: None,
                latency_ms: started.elapsed().as_millis() as u64,
                issues,
                error: Some(format!("TCP/25 connection failed: {e}")),
            };
        }
        Err(_) => {
            return SmtpMxProbe {
                mx_host,
                priority,
                ip: Some(target_ip.to_string()),
                ptr_records,
                fcrdns_valid,
                banner_matches_ptr: false,
                reachable: false,
                banner: None,
                ehlo_extensions: vec![],
                supports_starttls: false,
                starttls_negotiated: false,
                tls_version: None,
                tls_cert_valid: None,
                tls_cert_cn: None,
                tls_days_remaining: None,
                latency_ms: started.elapsed().as_millis() as u64,
                issues,
                error: Some("TCP/25 connection timed out (outbound port 25 may be blocked by ISP/firewall).".to_string()),
            };
        }
    };

    let mut banner_text: Option<String> = None;
    let mut ehlo_extensions = Vec::new();
    let mut supports_starttls = false;
    let mut starttls_negotiated = false;
    let mut tls_version = None;
    let mut tls_cert_valid = None;
    let mut tls_cert_cn = None;
    let mut tls_days_remaining = None;
    let mut error = None;

    let mut reader = BufReader::new(&mut stream);
    match read_smtp_reply(&mut reader).await {
        Ok((code, lines)) => {
            let joined = lines.join(" | ");
            banner_text = Some(joined.clone());
            if code != 220 {
                issues.push(format!("Unexpected SMTP greeting code {code}."));
            }
        }
        Err(e) => {
            error = Some(e);
        }
    }

    let banner_matches_ptr = banner_text
        .as_deref()
        .is_some_and(|b| banner_matches_any_ptr(b, &ptr_records));
    if banner_text.is_some() && !ptr_records.is_empty() && !banner_matches_ptr {
        issues.push("SMTP 220 banner hostname does not match PTR hostname.".to_string());
    }

    if error.is_none() {
        if let Err(e) = reader.get_mut().write_all(b"EHLO domain-tools.local\r\n").await {
            error = Some(format!("Failed sending EHLO: {e}"));
        } else {
            match read_smtp_reply(&mut reader).await {
                Ok((code, lines)) if code == 250 => {
                    ehlo_extensions = parse_ehlo_extensions(&lines);
                    supports_starttls = ehlo_extensions
                        .iter()
                        .any(|e| e.eq_ignore_ascii_case("STARTTLS") || e.to_ascii_uppercase().starts_with("STARTTLS "));
                }
                Ok((code, lines)) => {
                    issues.push(format!("EHLO returned code {code}: {}", lines.join(" ")));
                }
                Err(e) => {
                    error = Some(e);
                }
            }
        }
    }

    if !supports_starttls && error.is_none() {
        issues.push("Server did not advertise STARTTLS in EHLO response.".to_string());
    }

    if supports_starttls && error.is_none() {
        if let Err(e) = reader.get_mut().write_all(b"STARTTLS\r\n").await {
            error = Some(format!("Failed sending STARTTLS: {e}"));
        } else {
            match read_smtp_reply(&mut reader).await {
                Ok((220, _)) => {
                    drop(reader);
                    match build_permissive_tls_connector() {
                        Ok((connector, outcome)) => {
                            if let Ok(server_name) = ServerName::try_from(mx_host.clone()) {
                                match timeout(SMTP_IO_TIMEOUT, connector.connect(server_name, stream))
                                    .await
                                {
                                    Ok(Ok(mut tls_stream)) => {
                                        starttls_negotiated = true;
                                        let (_, conn) = tls_stream.get_ref();
                                        tls_version = conn.protocol_version().map(|v| match v {
                                            rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
                                            rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
                                            other => format!("{other:?}"),
                                        });
                                        let mut host_match = false;
                                        if let Some(certs) = conn.peer_certificates() {
                                            if let Some(leaf_der) = certs.first() {
                                                if let Ok(parsed) = parse_cert_der(leaf_der.as_ref()) {
                                                    host_match = hostname_matches_cert(
                                                        &mx_host,
                                                        parsed.common_name.as_deref(),
                                                        &parsed.sans,
                                                    );
                                                    tls_cert_cn = parsed.common_name;
                                                    tls_days_remaining = Some(parsed.days_remaining);
                                                    if parsed.days_remaining < 0 {
                                                        issues.push("SMTP STARTTLS certificate has expired.".to_string());
                                                    } else if parsed.days_remaining <= 14 {
                                                        issues.push(format!(
                                                            "SMTP STARTTLS certificate expires in {} day(s).",
                                                            parsed.days_remaining
                                                        ));
                                                    }
                                                }
                                            }
                                        }
                                        let chain_ok = outcome
                                            .lock()
                                            .ok()
                                            .and_then(|g| g.clone())
                                            .is_some_and(|r| r.is_ok());
                                        tls_cert_valid = Some(chain_ok && host_match);
                                        if !chain_ok {
                                            issues.push("SMTP STARTTLS certificate chain failed trust verification.".to_string());
                                        }
                                        if !host_match {
                                            issues.push(format!(
                                                "SMTP STARTTLS certificate does not match MX hostname {mx_host}."
                                            ));
                                        }
                                        let _ = tls_stream.write_all(b"QUIT\r\n").await;
                                    }
                                    Ok(Err(e)) => {
                                        issues.push(format!("STARTTLS handshake failed: {e}"));
                                    }
                                    Err(_) => {
                                        issues.push("STARTTLS handshake timed out.".to_string());
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            issues.push(e);
                        }
                    }
                    return SmtpMxProbe {
                        mx_host,
                        priority,
                        ip: Some(target_ip.to_string()),
                        ptr_records,
                        fcrdns_valid,
                        banner_matches_ptr,
                        reachable: true,
                        banner: banner_text,
                        ehlo_extensions,
                        supports_starttls,
                        starttls_negotiated,
                        tls_version,
                        tls_cert_valid,
                        tls_cert_cn,
                        tls_days_remaining,
                        latency_ms: started.elapsed().as_millis() as u64,
                        issues,
                        error,
                    };
                }
                Ok((code, lines)) => {
                    issues.push(format!("STARTTLS rejected ({code}): {}", lines.join(" ")));
                }
                Err(e) => {
                    issues.push(e);
                }
            }
        }
    } else {
        let _ = reader.get_mut().write_all(b"QUIT\r\n").await;
    }

    SmtpMxProbe {
        mx_host,
        priority,
        ip: Some(target_ip.to_string()),
        ptr_records,
        fcrdns_valid,
        banner_matches_ptr,
        reachable: true,
        banner: banner_text,
        ehlo_extensions,
        supports_starttls,
        starttls_negotiated,
        tls_version,
        tls_cert_valid,
        tls_cert_cn,
        tls_days_remaining,
        latency_ms: started.elapsed().as_millis() as u64,
        issues,
        error,
    }
}

pub async fn probe_smtp_deliverability(domain: &str) -> Result<SmtpDeliverabilityReport, String> {
    let clean_domain = normalize_domain(domain)?;
    let started = Instant::now();
    let (_, _, resolver) = build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false))?;

    let fqdn = format!("{clean_domain}.");
    let mut mx_list: Vec<(u16, String)> = Vec::new();
    if let Ok(lookup) = timeout(Duration::from_secs(3), resolver.lookup(&fqdn, RecordType::MX)).await
    {
        if let Ok(res) = lookup {
            for rec in res.record_iter() {
                if let RData::MX(mx) = rec.data() {
                    let host = mx
                        .exchange()
                        .to_string()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    if !host.is_empty() && host != "." {
                        mx_list.push((mx.preference(), host));
                    }
                }
            }
        }
    }

    mx_list.sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    let mx_count = mx_list.len();
    let to_test: Vec<(u16, String)> = mx_list.into_iter().take(MAX_MX_PROBES).collect();
    let tested_count = to_test.len();

    let mut report_issues = Vec::new();
    if mx_count == 0 {
        report_issues.push("No MX records published for this domain.".to_string());
        return Ok(SmtpDeliverabilityReport {
            domain: clean_domain,
            mx_count: 0,
            tested_count: 0,
            port25_blocked_suspected: false,
            latency_ms: started.elapsed().as_millis() as u64,
            servers: vec![],
            issues: report_issues,
        });
    }

    let servers = join_all(
        to_test
            .into_iter()
            .map(|(prio, host)| probe_single_mx(&resolver, host, prio)),
    )
    .await;

    let port25_blocked_suspected = !servers.is_empty() && servers.iter().all(|s| !s.reachable);
    if port25_blocked_suspected {
        report_issues.push(
            "All MX hosts timed out/failed on TCP/25 — outbound port 25 is frequently blocked on residential/corporate/cloud networks."
                .to_string(),
        );
    }

    Ok(SmtpDeliverabilityReport {
        domain: clean_domain,
        mx_count,
        tested_count,
        port25_blocked_suspected,
        latency_ms: started.elapsed().as_millis() as u64,
        servers,
        issues: report_issues,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ehlo_extensions() {
        let lines = vec![
            "250-mx.example.com Hello".to_string(),
            "250-PIPELINING".to_string(),
            "250-SIZE 35882577".to_string(),
            "250-STARTTLS".to_string(),
            "250 SMTPUTF8".to_string(),
        ];
        let exts = parse_ehlo_extensions(&lines);
        assert_eq!(
            exts,
            vec!["PIPELINING", "SIZE 35882577", "STARTTLS", "SMTPUTF8"]
        );
    }

    #[test]
    fn test_banner_matches_any_ptr() {
        let ptrs = vec!["mx1.example.com".to_string()];
        assert!(banner_matches_any_ptr(
            "220 mx1.example.com ESMTP Postfix",
            &ptrs
        ));
        assert!(!banner_matches_any_ptr(
            "220 other.example.net ESMTP",
            &ptrs
        ));
        assert!(!banner_matches_any_ptr("220 mx1.example.com ESMTP", &[]));
    }
}
