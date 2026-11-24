use std::time::{Duration, Instant};

use chrono::{DateTime, NaiveDate, Utc};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::models::WhoisInfo;

const WHOIS_TIMEOUT_SECS: u64 = 4;
const MAX_WHOIS_BYTES: usize = 256 * 1024;

const TWO_LEVEL_PUBLIC_SUFFIXES: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "ne.jp", "or.jp", "com.br", "com.mx", "com.pl", "net.pl", "org.pl", "info.pl", "biz.pl",
    "edu.pl", "gov.pl", "co.in", "com.cn", "com.sg", "co.za", "com.tr", "com.ar", "com.kr",
    "com.tw", "com.hk", "com.ua", "co.il",
];

pub fn extract_whois_domain(domain: &str) -> String {
    let trimmed = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = trimmed
        .split('.')
        .filter(|l| !l.is_empty())
        .collect();

    let clean_labels: Vec<&str> = labels
        .iter()
        .skip_while(|l| l.starts_with('_'))
        .copied()
        .collect();

    let effective = if clean_labels.len() >= 2 {
        clean_labels
    } else {
        labels
    };

    if effective.len() <= 2 {
        return effective.join(".");
    }

    let last_two = format!(
        "{}.{}",
        effective[effective.len() - 2],
        effective[effective.len() - 1]
    );
    if TWO_LEVEL_PUBLIC_SUFFIXES.contains(&last_two.as_str()) && effective.len() >= 3 {
        effective[effective.len() - 3..].join(".")
    } else {
        last_two
    }
}

pub fn whois_server_for_tld(tld: &str) -> Option<&'static str> {
    match tld.to_ascii_lowercase().as_str() {
        "com" | "net" => Some("whois.verisign-grs.com"),
        "org" => Some("whois.pir.org"),
        "io" => Some("whois.nic.io"),
        "dev" | "app" | "page" => Some("whois.nic.google"),
        "ai" => Some("whois.nic.ai"),
        "co" => Some("whois.nic.co"),
        "me" => Some("whois.nic.me"),
        "info" => Some("whois.nic.info"),
        "biz" => Some("whois.nic.biz"),
        "pl" => Some("whois.dns.pl"),
        "uk" => Some("whois.nic.uk"),
        "de" => Some("whois.denic.de"),
        "eu" => Some("whois.eu"),
        "ca" => Some("whois.cira.ca"),
        "fr" => Some("whois.nic.fr"),
        "nl" => Some("whois.domain-registry.nl"),
        "xyz" => Some("whois.nic.xyz"),
        "gg" => Some("whois.gg"),
        "tv" => Some("whois.nic.tv"),
        "us" => Some("whois.nic.us"),
        "edu" => Some("whois.educause.edu"),
        "gov" => Some("whois.dotgov.gov"),
        _ => None,
    }
}

async fn tcp_whois_query(server: &str, query: &str, timeout_secs: u64) -> Result<String, String> {
    let dur = Duration::from_secs(timeout_secs);
    let addr = format!("{server}:43");

    let mut stream = timeout(dur, TcpStream::connect(&addr))
        .await
        .map_err(|_| format!("Timed out connecting to {addr}"))?
        .map_err(|e| format!("Failed to connect to {addr}: {e}"))?;

    let payload = format!("{query}\r\n");
    timeout(dur, stream.write_all(payload.as_bytes()))
        .await
        .map_err(|_| format!("Timed out writing WHOIS query to {server}"))?
        .map_err(|e| format!("Failed writing WHOIS query to {server}: {e}"))?;

    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];

    let read_res = timeout(dur, async {
        loop {
            let n = stream.read(&mut chunk).await?;
            if n == 0 {
                break;
            }
            let remaining = MAX_WHOIS_BYTES.saturating_sub(buf.len());
            if remaining == 0 {
                break;
            }
            let take = n.min(remaining);
            buf.extend_from_slice(&chunk[..take]);
            if buf.len() >= MAX_WHOIS_BYTES {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;

    match read_res {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            if buf.is_empty() {
                return Err(format!("Failed reading WHOIS response from {server}: {e}"));
            }
        }
        Err(_) => {
            if buf.is_empty() {
                return Err(format!("Timed out reading WHOIS response from {server}"));
            }
        }
    }

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

fn format_server_query(server: &str, domain: &str) -> String {
    if server.eq_ignore_ascii_case("whois.verisign-grs.com") {
        format!("domain {domain}")
    } else if server.eq_ignore_ascii_case("whois.denic.de") {
        format!("-T dn,ace {domain}")
    } else {
        domain.to_string()
    }
}

async fn discover_iana_whois_server(tld: &str) -> Result<String, String> {
    let raw = tcp_whois_query("whois.iana.org", tld, WHOIS_TIMEOUT_SECS).await?;
    for line in raw.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if let Some(val) = lower
            .strip_prefix("refer:")
            .or_else(|| lower.strip_prefix("whois:"))
        {
            let host = val.trim().trim_end_matches('.');
            if is_valid_whois_host(host) {
                return Ok(host.to_string());
            }
        }
    }
    Err(format!("No WHOIS server found in IANA response for '.{tld}'"))
}

fn is_valid_whois_host(host: &str) -> bool {
    !host.is_empty()
        && host.contains('.')
        && !host.contains(' ')
        && !host.contains('/')
        && host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-')
}

fn extract_referral_server(text: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some((key, val)) = trimmed.split_once(':') {
            let key_lower = key.trim().to_ascii_lowercase();
            if matches!(
                key_lower.as_str(),
                "registrar whois server" | "whois server" | "referralserver"
            ) {
                let cleaned = val
                    .trim()
                    .trim_start_matches("whois://")
                    .trim_start_matches("rwhois://")
                    .split(['/', ':'])
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_ascii_lowercase();
                if is_valid_whois_host(&cleaned) {
                    return Some(cleaned);
                }
            }
        }
    }
    None
}

pub fn parse_expiry_days(date_str: &str) -> Option<i64> {
    let trimmed = date_str.trim();
    if let Ok(dt) = DateTime::parse_from_rfc3339(trimmed) {
        return Some((dt.with_timezone(&Utc) - Utc::now()).num_days());
    }
    let date_prefix = trimmed.get(..10)?;
    if let Ok(nd) = NaiveDate::parse_from_str(date_prefix, "%Y-%m-%d") {
        let today = Utc::now().date_naive();
        return Some((nd - today).num_days());
    }
    None
}

#[derive(Default)]
struct ParsedWhoisFields {
    registrar: Option<String>,
    registrar_url: Option<String>,
    registrar_iana_id: Option<String>,
    created_date: Option<String>,
    updated_date: Option<String>,
    expiry_date: Option<String>,
    registrant_org: Option<String>,
    registrant_country: Option<String>,
    abuse_email: Option<String>,
    abuse_phone: Option<String>,
    dnssec: Option<String>,
    statuses: Vec<String>,
    name_servers: Vec<String>,
    not_found_marker: bool,
}

fn push_unique(vec: &mut Vec<String>, item: String) {
    if !item.is_empty() && !vec.contains(&item) {
        vec.push(item);
    }
}

fn parse_whois_section(text: &str) -> ParsedWhoisFields {
    let mut out = ParsedWhoisFields::default();
    let lower_full = text.to_ascii_lowercase();

    for marker in [
        "no match for",
        "not found",
        "no entries found",
        "status: free",
        "status: available",
        "domain not found",
    ] {
        if lower_full.contains(marker) {
            out.not_found_marker = true;
            break;
        }
    }

    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
            continue;
        }
        let Some((raw_key, raw_val)) = trimmed.split_once(':') else {
            continue;
        };
        let key = raw_key.trim().to_ascii_lowercase();
        let val = raw_val.trim();
        if val.is_empty() {
            continue;
        }

        match key.as_str() {
            "registrar" | "sponsoring registrar" => {
                if out.registrar.is_none() {
                    out.registrar = Some(val.to_string());
                }
            }
            "registrar url" => {
                if out.registrar_url.is_none() {
                    out.registrar_url = Some(val.to_string());
                }
            }
            "registrar iana id" => {
                if out.registrar_iana_id.is_none() {
                    out.registrar_iana_id = Some(val.to_string());
                }
            }
            "creation date" | "created" | "created on" | "registered on" | "registration time" => {
                if out.created_date.is_none() {
                    out.created_date = Some(val.to_string());
                }
            }
            "updated date" | "last modified" | "last updated" | "changed" => {
                if out.updated_date.is_none() {
                    out.updated_date = Some(val.to_string());
                }
            }
            "registry expiry date"
            | "registrar registration expiration date"
            | "expiration date"
            | "expiry date"
            | "paid-till"
            | "renewal date"
            | "expiration time" => {
                if out.expiry_date.is_none() {
                    out.expiry_date = Some(val.to_string());
                }
            }
            "registrant organization" | "orgname" | "registrant org" => {
                if out.registrant_org.is_none() {
                    out.registrant_org = Some(val.to_string());
                }
            }
            "registrant country" => {
                if out.registrant_country.is_none() {
                    out.registrant_country = Some(val.to_string());
                }
            }
            "registrar abuse contact email" => {
                if out.abuse_email.is_none() {
                    out.abuse_email = Some(val.to_string());
                }
            }
            "registrar abuse contact phone" => {
                if out.abuse_phone.is_none() {
                    out.abuse_phone = Some(val.to_string());
                }
            }
            "dnssec" => {
                if out.dnssec.is_none() {
                    out.dnssec = Some(val.to_string());
                }
            }
            "domain status" | "status" => {
                push_unique(&mut out.statuses, val.to_string());
            }
            "name server" | "nserver" => {
                let ns = val
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                push_unique(&mut out.name_servers, ns);
            }
            _ => {}
        }
    }

    out
}

fn merge_fields(primary: ParsedWhoisFields, fallback: ParsedWhoisFields) -> ParsedWhoisFields {
    let mut statuses = primary.statuses;
    for s in fallback.statuses {
        push_unique(&mut statuses, s);
    }
    let mut name_servers = primary.name_servers;
    for ns in fallback.name_servers {
        push_unique(&mut name_servers, ns);
    }

    ParsedWhoisFields {
        registrar: primary.registrar.or(fallback.registrar),
        registrar_url: primary.registrar_url.or(fallback.registrar_url),
        registrar_iana_id: primary.registrar_iana_id.or(fallback.registrar_iana_id),
        created_date: primary.created_date.or(fallback.created_date),
        updated_date: primary.updated_date.or(fallback.updated_date),
        expiry_date: primary.expiry_date.or(fallback.expiry_date),
        registrant_org: primary.registrant_org.or(fallback.registrant_org),
        registrant_country: primary.registrant_country.or(fallback.registrant_country),
        abuse_email: primary.abuse_email.or(fallback.abuse_email),
        abuse_phone: primary.abuse_phone.or(fallback.abuse_phone),
        dnssec: primary.dnssec.or(fallback.dnssec),
        statuses,
        name_servers,
        not_found_marker: primary.not_found_marker && fallback.not_found_marker,
    }
}

pub fn build_whois_info_from_sections(
    queried_domain: String,
    servers_queried: Vec<String>,
    sections: Vec<(String, String)>,
    latency_ms: u64,
) -> WhoisInfo {
    let raw_text = if sections.len() == 1 {
        sections[0].1.trim().to_string()
    } else {
        sections
            .iter()
            .map(|(srv, txt)| format!("=== {srv} ===\n{}", txt.trim()))
            .collect::<Vec<_>>()
            .join("\n\n")
    };

    let mut parsed = ParsedWhoisFields::default();
    if let Some((_, first_txt)) = sections.first() {
        parsed = parse_whois_section(first_txt);
    }
    if let Some((_, second_txt)) = sections.get(1) {
        let registrar_parsed = parse_whois_section(second_txt);
        parsed = merge_fields(registrar_parsed, parsed);
    }

    let is_not_found = parsed.not_found_marker
        && parsed.created_date.is_none()
        && parsed.registrar.is_none()
        && parsed.name_servers.is_empty();

    let days_until_expiry = parsed.expiry_date.as_deref().and_then(parse_expiry_days);

    WhoisInfo {
        status: if is_not_found {
            "not_found".to_string()
        } else {
            "ok".to_string()
        },
        queried_domain,
        servers_queried,
        latency_ms,
        registrar: parsed.registrar,
        registrar_url: parsed.registrar_url,
        registrar_iana_id: parsed.registrar_iana_id,
        created_date: parsed.created_date,
        updated_date: parsed.updated_date,
        expiry_date: parsed.expiry_date,
        days_until_expiry,
        registrant_org: parsed.registrant_org,
        registrant_country: parsed.registrant_country,
        abuse_email: parsed.abuse_email,
        abuse_phone: parsed.abuse_phone,
        dnssec: parsed.dnssec,
        statuses: parsed.statuses,
        name_servers: parsed.name_servers,
        raw_text,
        error: None,
    }
}

fn error_whois(queried_domain: String, servers_queried: Vec<String>, latency_ms: u64, err: String) -> WhoisInfo {
    WhoisInfo {
        status: "error".to_string(),
        queried_domain,
        servers_queried,
        latency_ms,
        registrar: None,
        registrar_url: None,
        registrar_iana_id: None,
        created_date: None,
        updated_date: None,
        expiry_date: None,
        days_until_expiry: None,
        registrant_org: None,
        registrant_country: None,
        abuse_email: None,
        abuse_phone: None,
        dnssec: None,
        statuses: vec![],
        name_servers: vec![],
        raw_text: String::new(),
        error: Some(err),
    }
}

pub async fn lookup_whois(domain: &str) -> WhoisInfo {
    let start = Instant::now();
    let queried_domain = extract_whois_domain(domain);

    let Some(tld) = queried_domain.rsplit('.').next() else {
        return error_whois(
            queried_domain,
            vec![],
            start.elapsed().as_millis() as u64,
            "Cannot determine TLD for WHOIS lookup.".to_string(),
        );
    };

    let registry_server = match whois_server_for_tld(tld) {
        Some(s) => s.to_string(),
        None => match discover_iana_whois_server(tld).await {
            Ok(s) => s,
            Err(e) => {
                return error_whois(
                    queried_domain,
                    vec!["whois.iana.org".to_string()],
                    start.elapsed().as_millis() as u64,
                    e,
                );
            }
        },
    };

    let mut servers_queried = vec![registry_server.clone()];
    let registry_query = format_server_query(&registry_server, &queried_domain);
    let registry_text = match tcp_whois_query(&registry_server, &registry_query, WHOIS_TIMEOUT_SECS).await {
        Ok(txt) => txt,
        Err(e) => {
            return error_whois(
                queried_domain,
                servers_queried,
                start.elapsed().as_millis() as u64,
                e,
            );
        }
    };

    let mut sections = vec![(registry_server.clone(), registry_text.clone())];

    if let Some(referral) = extract_referral_server(&registry_text) {
        if !referral.eq_ignore_ascii_case(&registry_server) {
            let ref_query = format_server_query(&referral, &queried_domain);
            if let Ok(ref_text) = tcp_whois_query(&referral, &ref_query, WHOIS_TIMEOUT_SECS).await {
                if !ref_text.trim().is_empty() {
                    servers_queried.push(referral.clone());
                    sections.push((referral, ref_text));
                }
            }
        }
    }

    build_whois_info_from_sections(
        queried_domain,
        servers_queried,
        sections,
        start.elapsed().as_millis() as u64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_whois_domain() {
        assert_eq!(extract_whois_domain("example.com"), "example.com");
        assert_eq!(extract_whois_domain("www.sub.example.com."), "example.com");
        assert_eq!(extract_whois_domain("_dmarc.example.com"), "example.com");
        assert_eq!(extract_whois_domain("mail.bbc.co.uk"), "bbc.co.uk");
        assert_eq!(extract_whois_domain("app.firma.com.pl"), "firma.com.pl");
    }

    #[test]
    fn test_parse_whois_text_and_referral() {
        let sample = "\
   Domain Name: CLOUDFLARE.COM
   Registry Domain ID: 1542998887_DOMAIN_COM-VRSN
   Registrar WHOIS Server: whois.cloudflare.com
   Registrar URL: http://www.cloudflare.com
   Updated Date: 2024-01-09T16:45:28Z
   Creation Date: 2009-02-17T22:07:54Z
   Registry Expiry Date: 2033-02-17T22:07:54Z
   Registrar: Cloudflare, Inc.
   Registrar IANA ID: 1910
   Registrar Abuse Contact Email: registrar-abuse@cloudflare.com
   Registrar Abuse Contact Phone: +1.6503198930
   Domain Status: clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited
   Name Server: NS3.CLOUDFLARE.COM
   Name Server: ns4.cloudflare.com.
   DNSSEC: signedDelegation
";
        assert_eq!(
            extract_referral_server(sample).as_deref(),
            Some("whois.cloudflare.com")
        );

        let info = build_whois_info_from_sections(
            "cloudflare.com".to_string(),
            vec!["whois.verisign-grs.com".to_string()],
            vec![("whois.verisign-grs.com".to_string(), sample.to_string())],
            42,
        );
        assert_eq!(info.status, "ok");
        assert_eq!(info.registrar.as_deref(), Some("Cloudflare, Inc."));
        assert_eq!(info.registrar_iana_id.as_deref(), Some("1910"));
        assert_eq!(info.created_date.as_deref(), Some("2009-02-17T22:07:54Z"));
        assert_eq!(info.expiry_date.as_deref(), Some("2033-02-17T22:07:54Z"));
        assert!(info.days_until_expiry.is_some());
        assert_eq!(
            info.name_servers,
            vec!["ns3.cloudflare.com", "ns4.cloudflare.com"]
        );
        assert_eq!(info.dnssec.as_deref(), Some("signedDelegation"));
    }

    #[test]
    fn test_parse_whois_not_found() {
        let missing = "No match for domain \"NONEXISTENT-XYZ-12345.COM\".\n";
        let info = build_whois_info_from_sections(
            "nonexistent-xyz-12345.com".to_string(),
            vec!["whois.verisign-grs.com".to_string()],
            vec![("whois.verisign-grs.com".to_string(), missing.to_string())],
            20,
        );
        assert_eq!(info.status, "not_found");
    }
}
