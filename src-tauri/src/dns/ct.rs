use std::collections::{BTreeMap, BTreeSet};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use hickory_resolver::proto::rr::{RData, RecordType};
use serde::Deserialize;
use tokio::time::timeout;

use crate::dns::whois::extract_whois_domain;
use crate::dns::{build_resolver, normalize_domain};
use crate::models::{CtHistoryReport, CtIssuerSummary, CtLogEntry};

const MAX_CRTSH_BYTES: usize = 2 * 1024 * 1024;
const MAX_CT_ENTRIES: usize = 150;

#[derive(Deserialize)]
struct RawCrtShEntry {
    id: Option<u64>,
    issuer_name: Option<String>,
    common_name: Option<String>,
    name_value: Option<String>,
    not_before: Option<String>,
    not_after: Option<String>,
    serial_number: Option<String>,
}

pub fn extract_issuer_org(issuer_dn: &str) -> String {
    for part in issuer_dn.split(',') {
        let trimmed = part.trim();
        if let Some(val) = trimmed
            .strip_prefix("O=")
            .or_else(|| trimmed.strip_prefix("o="))
        {
            let clean = val.trim().trim_matches('"').trim();
            if !clean.is_empty() {
                return clean.to_string();
            }
        }
    }
    for part in issuer_dn.split(',') {
        let trimmed = part.trim();
        if let Some(val) = trimmed
            .strip_prefix("CN=")
            .or_else(|| trimmed.strip_prefix("cn="))
        {
            let clean = val.trim().trim_matches('"').trim();
            if !clean.is_empty() {
                return clean.to_string();
            }
        }
    }
    issuer_dn.trim().to_string()
}

pub fn ca_org_matches_caa_domain(issuer_org: &str, caa_domain: &str) -> bool {
    let org = issuer_org.to_ascii_lowercase();
    let caa = caa_domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if caa.is_empty() {
        return false;
    }

    let known_pairs: &[(&[&str], &[&str])] = &[
        (&["let's encrypt", "letsencrypt", "isrg"], &["letsencrypt.org"]),
        (&["digicert", "thawte", "rapidssl", "geotrust"], &["digicert.com", "thawte.com", "geotrust.com"]),
        (&["sectigo", "comodo"], &["sectigo.com", "comodoca.com", "comodo.com"]),
        (&["google trust services", "gts"], &["pki.goog"]),
        (&["globalsign"], &["globalsign.com"]),
        (&["amazon", "aws"], &["amazon.com", "amazontrust.com", "awstrust.com", "amazonaws.com"]),
        (&["entrust"], &["entrust.net", "entrust.com"]),
        (&["zerossl"], &["zerossl.com", "sectigo.com"]),
        (&["ssl.com"], &["ssl.com"]),
        (&["cloudflare"], &["digicert.com", "letsencrypt.org", "pki.goog", "ssl.com", "comodoca.com"]),
        (&["microsoft"], &["microsoft.com", "digicert.com"]),
        (&["buypass"], &["buypass.com"]),
        (&["trustcor"], &["trustcor.ca"]),
    ];

    for (org_keys, caa_keys) in known_pairs {
        if org_keys.iter().any(|k| org.contains(k)) && caa_keys.iter().any(|d| caa == *d || caa.ends_with(&format!(".{d}"))) {
            return true;
        }
    }

    // Generic fallback: stem match
    let stem = caa.split('.').next().unwrap_or("");
    stem.len() >= 3 && org.contains(stem)
}

fn parse_not_after_expired(not_after: &str) -> bool {
    let candidate = if not_after.ends_with('Z') || not_after.contains('+') {
        not_after.to_string()
    } else {
        format!("{not_after}Z")
    };
    if let Ok(dt) = DateTime::parse_from_rfc3339(&candidate) {
        return dt.with_timezone(&Utc) < Utc::now();
    }
    if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(not_after, "%Y-%m-%dT%H:%M:%S") {
        return naive.and_utc() < Utc::now();
    }
    false
}

pub fn parse_crtsh_entries(raw_json: &str) -> Result<Vec<CtLogEntry>, String> {
    let trimmed = raw_json.trim();
    if trimmed.is_empty() || trimmed == "[]" {
        return Ok(vec![]);
    }

    let raw_entries: Vec<RawCrtShEntry> = match serde_json::from_str(trimmed) {
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

    let mut seen_keys: BTreeSet<(String, String)> = BTreeSet::new();
    let mut entries = Vec::new();

    for raw in raw_entries {
        let common_name = raw.common_name.unwrap_or_default().trim().to_ascii_lowercase();
        let serial_number = raw.serial_number.unwrap_or_default().trim().to_string();
        if !seen_keys.insert((serial_number.clone(), common_name.clone())) {
            continue;
        }

        let issuer_name = raw.issuer_name.unwrap_or_default();
        let issuer_org = extract_issuer_org(&issuer_name);
        let not_before = raw.not_before.unwrap_or_default();
        let not_after = raw.not_after.unwrap_or_default();
        let is_expired = parse_not_after_expired(&not_after);

        let mut sans_set = BTreeSet::new();
        for line in raw.name_value.unwrap_or_default().split('\n') {
            let clean = line.trim().to_ascii_lowercase();
            if !clean.is_empty() {
                sans_set.insert(clean);
            }
        }
        let sans: Vec<String> = sans_set.into_iter().collect();
        let is_wildcard =
            common_name.starts_with("*.") || sans.iter().any(|s| s.starts_with("*."));

        entries.push(CtLogEntry {
            id: raw.id.unwrap_or(0),
            issuer_name,
            issuer_org,
            common_name,
            sans,
            not_before,
            not_after,
            is_expired,
            is_wildcard,
            serial_number,
        });
    }

    entries.sort_by(|a, b| b.not_before.cmp(&a.not_before));
    if entries.len() > MAX_CT_ENTRIES {
        entries.truncate(MAX_CT_ENTRIES);
    }

    Ok(entries)
}

pub async fn fetch_ct_history(domain: &str) -> Result<CtHistoryReport, String> {
    let clean_domain = normalize_domain(domain)?;
    let apex = extract_whois_domain(&clean_domain);
    let started = Instant::now();

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(10))
        .user_agent("DomainTools/0.2 (CT Audit)")
        .build()
        .map_err(|e| format!("HTTP client error: {e}"))?;

    let url = format!("https://crt.sh/?q=%25.{apex}&output=json");

    let caa_fut = async {
        let mut caa_vals = Vec::new();
        let mut issue_domains = Vec::new();
        if let Ok((_, _, resolver)) = build_resolver("cloudflare", None, false) {
            for target in [clean_domain.as_str(), apex.as_str()] {
                let fqdn = format!("{target}.");
                if let Ok(Ok(lookup)) =
                    timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::CAA)).await
                {
                    for r in lookup.record_iter() {
                        if let RData::CAA(caa) = r.data() {
                            let tag = caa.tag().as_str().to_string();
                            let val = String::from_utf8_lossy(caa.raw_value()).into_owned();
                            let formatted = format!("{} {} \"{}\"", caa.flags(), tag, val);
                            if !caa_vals.contains(&formatted) {
                                caa_vals.push(formatted);
                            }
                            if tag.eq_ignore_ascii_case("issue") || tag.eq_ignore_ascii_case("issuewild") {
                                let ca_host = val.split(';').next().unwrap_or("").trim().to_string();
                                if !ca_host.is_empty() && ca_host != ";" && !issue_domains.contains(&ca_host) {
                                    issue_domains.push(ca_host);
                                }
                            }
                        }
                    }
                }
                if !caa_vals.is_empty() {
                    break;
                }
            }
        }
        (caa_vals, issue_domains)
    };

    let ct_fut = async {
        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("crt.sh request failed: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("crt.sh returned HTTP {}", resp.status().as_u16()));
        }
        let mut bytes = Vec::with_capacity(64 * 1024);
        let mut r = resp;
        while let Ok(Some(chunk)) = r.chunk().await {
            let rem = MAX_CRTSH_BYTES.saturating_sub(bytes.len());
            if rem == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..chunk.len().min(rem)]);
            if bytes.len() >= MAX_CRTSH_BYTES {
                break;
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        parse_crtsh_entries(&text)
    };

    let ((caa_records, issue_domains), ct_res) = tokio::join!(caa_fut, ct_fut);

    let entries = match ct_res {
        Ok(list) => list,
        Err(err) => {
            return Ok(CtHistoryReport {
                domain: apex,
                total_certs: 0,
                active_certs: 0,
                expired_certs: 0,
                wildcard_certs: 0,
                caa_records,
                unauthorized_issuers: vec![],
                issuers: vec![],
                entries: vec![],
                latency_ms: started.elapsed().as_millis() as u64,
                error: Some(err),
            });
        }
    };

    let total_certs = entries.len();
    let active_certs = entries.iter().filter(|e| !e.is_expired).count();
    let expired_certs = total_certs.saturating_sub(active_certs);
    let wildcard_certs = entries.iter().filter(|e| e.is_wildcard).count();

    let mut by_issuer: BTreeMap<String, (usize, usize)> = BTreeMap::new();
    for entry in &entries {
        let counts = by_issuer.entry(entry.issuer_org.clone()).or_insert((0, 0));
        counts.0 += 1;
        if !entry.is_expired {
            counts.1 += 1;
        }
    }

    let has_caa = !issue_domains.is_empty();
    let mut unauthorized_issuers = Vec::new();
    let mut issuers: Vec<CtIssuerSummary> = by_issuer
        .into_iter()
        .map(|(issuer_org, (total, active))| {
            let caa_authorized = if has_caa {
                let auth = issue_domains
                    .iter()
                    .any(|caa| ca_org_matches_caa_domain(&issuer_org, caa));
                if !auth && active > 0 {
                    unauthorized_issuers.push(issuer_org.clone());
                }
                Some(auth)
            } else {
                None
            };
            CtIssuerSummary {
                issuer_org,
                total_certs: total,
                active_certs: active,
                caa_authorized,
            }
        })
        .collect();

    issuers.sort_by(|a, b| b.total_certs.cmp(&a.total_certs));

    Ok(CtHistoryReport {
        domain: apex,
        total_certs,
        active_certs,
        expired_certs,
        wildcard_certs,
        caa_records,
        unauthorized_issuers,
        issuers,
        entries,
        latency_ms: started.elapsed().as_millis() as u64,
        error: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_issuer_org_and_caa_match() {
        assert_eq!(
            extract_issuer_org("C=US, O=Let's Encrypt, CN=R10"),
            "Let's Encrypt"
        );
        assert_eq!(
            extract_issuer_org("C=US, O=\"Google Trust Services LLC\", CN=WE1"),
            "Google Trust Services LLC"
        );
        assert!(ca_org_matches_caa_domain("Let's Encrypt", "letsencrypt.org"));
        assert!(ca_org_matches_caa_domain("Google Trust Services LLC", "pki.goog"));
        assert!(!ca_org_matches_caa_domain("DigiCert Inc", "letsencrypt.org"));
    }

    #[test]
    fn test_parse_crtsh_entries_dedup_and_repair() {
        let json = r#"[
            {"id":1,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"*.example.com","name_value":"*.example.com\nexample.com","not_before":"2026-01-01T00:00:00","not_after":"2099-01-01T00:00:00","serial_number":"aa11"},
            {"id":2,"issuer_name":"C=US, O=Let's Encrypt, CN=R3","common_name":"*.example.com","name_value":"*.example.com","not_before":"2026-01-01T00:00:00","not_after":"2099-01-01T00:00:00","serial_number":"aa11"},
            {"id":3,"issuer_name":"partial"#;
        let parsed = parse_crtsh_entries(json).unwrap();
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_wildcard);
        assert!(!parsed[0].is_expired);
        assert_eq!(parsed[0].issuer_org, "Let's Encrypt");
    }
}
