use futures::future::join_all;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::dnssec::PublicKey;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;

use crate::dns::{build_resolver, txt_to_string};
use crate::models::{
    DkimCheck, DkimSelectorResult, DmarcCheck, DnssecCheck, SecurityReport, SpfCheck,
};

const DEFAULT_DKIM_SELECTORS: &[&str] = &[
    "default",
    "google",
    "selector1",
    "selector2",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2",
    "mx",
];

async fn fetch_txt_strings(resolver: &TokioResolver, fqdn: &str) -> Result<Vec<String>, String> {
    match resolver.lookup(fqdn, RecordType::TXT).await {
        Ok(lookup) => Ok(lookup
            .record_iter()
            .filter_map(|r| match r.data() {
                RData::TXT(txt) => Some(txt_to_string(txt)),
                _ => None,
            })
            .collect()),
        Err(err) if err.is_nx_domain() || err.is_no_records_found() => Ok(vec![]),
        Err(err) => Err(err.to_string()),
    }
}

pub fn analyze_spf(txt_records: &[String]) -> SpfCheck {
    let spf_records: Vec<&String> = txt_records
        .iter()
        .filter(|s| {
            let trimmed = s.trim_start();
            let lower = trimmed.to_ascii_lowercase();
            lower == "v=spf1" || lower.starts_with("v=spf1 ")
        })
        .collect();

    if spf_records.is_empty() {
        return SpfCheck {
            status: "missing".to_string(),
            summary: "No SPF record found at apex TXT.".to_string(),
            raw_record: None,
            mechanisms: vec![],
            all_qualifier: None,
            dns_lookup_count: 0,
            issues: vec!["Add a v=spf1 TXT record to authorize mail senders.".to_string()],
        };
    }

    if spf_records.len() > 1 {
        return SpfCheck {
            status: "fail".to_string(),
            summary: format!("Multiple SPF records detected ({}).", spf_records.len()),
            raw_record: Some(spf_records.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" | ")),
            mechanisms: vec![],
            all_qualifier: None,
            dns_lookup_count: 0,
            issues: vec![
                "RFC 7208 permits only one v=spf1 TXT record; multiple records cause a PermError."
                    .to_string(),
            ],
        };
    }

    let raw = spf_records[0].trim().to_string();
    let tokens: Vec<&str> = raw.split_whitespace().collect();
    let mut mechanisms = Vec::new();
    let mut all_qualifier = None;
    let mut dns_lookup_count: u32 = 0;
    let mut issues = Vec::new();

    for token in tokens.iter().skip(1) {
        mechanisms.push((*token).to_string());
        let lower = token.to_ascii_lowercase();
        let stripped = lower.trim_start_matches(['+', '-', '~', '?']);

        if stripped == "all" {
            let qual = if lower.starts_with('-') {
                "-all"
            } else if lower.starts_with('~') {
                "~all"
            } else if lower.starts_with('?') {
                "?all"
            } else {
                "+all"
            };
            all_qualifier = Some(qual.to_string());
        } else if stripped.starts_with("include:")
            || stripped == "a"
            || stripped.starts_with("a:")
            || stripped.starts_with("a/")
            || stripped == "mx"
            || stripped.starts_with("mx:")
            || stripped.starts_with("mx/")
            || stripped == "ptr"
            || stripped.starts_with("ptr:")
            || stripped.starts_with("exists:")
            || lower.starts_with("redirect=")
        {
            dns_lookup_count += 1;
            if stripped == "ptr" || stripped.starts_with("ptr:") {
                issues.push("Mechanism 'ptr' is deprecated and discouraged by RFC 7208.".to_string());
            }
        }
    }

    if dns_lookup_count > 10 {
        issues.push(format!(
            "SPF requires {dns_lookup_count} DNS lookups (RFC 7208 limit is 10)."
        ));
    }

    let mut status = "pass";
    match all_qualifier.as_deref() {
        Some("+all") => {
            status = "fail";
            issues.push("'+all' permits any server on the internet to spoof this domain.".to_string());
        }
        Some("?all") => {
            status = "warn";
            issues.push("'?all' (neutral) provides minimal spoofing protection.".to_string());
        }
        Some("~all") => {
            if dns_lookup_count > 10 || !issues.is_empty() {
                status = "warn";
            }
        }
        Some("-all") => {
            if dns_lookup_count > 10 {
                status = "warn";
            }
        }
        None => {
            if !mechanisms.iter().any(|m| m.to_ascii_lowercase().starts_with("redirect=")) {
                status = "warn";
                issues.push("Missing terminal 'all' mechanism (e.g. -all or ~all).".to_string());
            }
        }
        _ => {}
    }

    if dns_lookup_count > 10 && status == "pass" {
        status = "warn";
    }

    let summary = match status {
        "pass" => format!(
            "Valid SPF ({}, {dns_lookup_count}/10 DNS lookups).",
            all_qualifier.as_deref().unwrap_or("redirect")
        ),
        "warn" => format!(
            "SPF present with warnings ({}, {dns_lookup_count}/10 lookups).",
            all_qualifier.as_deref().unwrap_or("no all")
        ),
        _ => "SPF configuration is unsafe or invalid.".to_string(),
    };

    SpfCheck {
        status: status.to_string(),
        summary,
        raw_record: Some(raw),
        mechanisms,
        all_qualifier,
        dns_lookup_count,
        issues,
    }
}

pub fn analyze_dmarc(txt_records: &[String]) -> DmarcCheck {
    let dmarc_records: Vec<&String> = txt_records
        .iter()
        .filter(|s| s.trim_start().to_ascii_lowercase().starts_with("v=dmarc1"))
        .collect();

    if dmarc_records.is_empty() {
        return DmarcCheck {
            status: "missing".to_string(),
            summary: "No DMARC record found at _dmarc.".to_string(),
            raw_record: None,
            policy: None,
            subdomain_policy: None,
            pct: None,
            rua: vec![],
            ruf: vec![],
            adkim: None,
            aspf: None,
            issues: vec!["Publish a v=DMARC1 TXT record at _dmarc to enforce alignment.".to_string()],
        };
    }

    if dmarc_records.len() > 1 {
        return DmarcCheck {
            status: "fail".to_string(),
            summary: format!("Multiple DMARC records found ({}).", dmarc_records.len()),
            raw_record: Some(dmarc_records.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" | ")),
            policy: None,
            subdomain_policy: None,
            pct: None,
            rua: vec![],
            ruf: vec![],
            adkim: None,
            aspf: None,
            issues: vec!["Multiple DMARC TXT records cause receivers to ignore DMARC.".to_string()],
        };
    }

    let raw = dmarc_records[0].trim().to_string();
    let mut policy = None;
    let mut subdomain_policy = None;
    let mut pct: Option<u8> = None;
    let mut rua = Vec::new();
    let mut ruf = Vec::new();
    let mut adkim = None;
    let mut aspf = None;
    let mut issues = Vec::new();

    for part in raw.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match key.as_str() {
                "p" => policy = Some(val.to_ascii_lowercase()),
                "sp" => subdomain_policy = Some(val.to_ascii_lowercase()),
                "pct" => {
                    if let Ok(parsed) = val.parse::<u8>() {
                        pct = Some(parsed);
                    } else {
                        issues.push(format!("Invalid pct value '{val}'."));
                    }
                }
                "rua" => {
                    rua.extend(
                        val.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
                "ruf" => {
                    ruf.extend(
                        val.split(',')
                            .map(|s| s.trim().to_string())
                            .filter(|s| !s.is_empty()),
                    );
                }
                "adkim" => adkim = Some(val.to_ascii_lowercase()),
                "aspf" => aspf = Some(val.to_ascii_lowercase()),
                _ => {}
            }
        }
    }

    if rua.is_empty() {
        issues.push("No aggregate reporting address (rua) configured.".to_string());
    }
    if let Some(p_pct) = pct {
        if p_pct < 100 {
            issues.push(format!("Policy applies to only {p_pct}% of messages (pct={p_pct})."));
        }
    }

    let status = match policy.as_deref() {
        Some("reject") | Some("quarantine") => {
            if pct.is_some_and(|p| p < 100) {
                "warn"
            } else {
                "pass"
            }
        }
        Some("none") => {
            issues.push("Policy is set to 'none' (monitoring only; does not block spoofing).".to_string());
            "warn"
        }
        Some(other) => {
            issues.push(format!("Unknown DMARC policy 'p={other}'."));
            "fail"
        }
        None => {
            issues.push("Missing required 'p=' policy tag.".to_string());
            "fail"
        }
    };

    let summary = match policy.as_deref() {
        Some(p) => format!("DMARC policy p={p}{}.", if rua.is_empty() { " (no rua)" } else { "" }),
        None => "Invalid DMARC record (missing p= tag).".to_string(),
    };

    DmarcCheck {
        status: status.to_string(),
        summary,
        raw_record: Some(raw),
        policy,
        subdomain_policy,
        pct,
        rua,
        ruf,
        adkim,
        aspf,
        issues,
    }
}

pub fn parse_dkim_txt(selector: &str, raw: &str, cname_target: Option<String>) -> DkimSelectorResult {
    let mut key_type = Some("rsa".to_string());
    let mut p_value: Option<String> = None;
    let mut has_v_dkim = false;

    for part in raw.split(';') {
        let trimmed = part.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim().to_string();
            match key.as_str() {
                "v" if val.eq_ignore_ascii_case("DKIM1") => has_v_dkim = true,
                "k" => key_type = Some(val.to_ascii_lowercase()),
                "p" => p_value = Some(val),
                _ => {}
            }
        }
    }

    let mut notes = Vec::new();
    let public_key_present = p_value.as_deref().is_some_and(|p| !p.is_empty());

    let status = match p_value.as_deref() {
        Some("") => {
            notes.push("Empty 'p=' tag indicates a revoked DKIM key.".to_string());
            "warn"
        }
        Some(_) => {
            if !has_v_dkim && !raw.to_ascii_lowercase().contains("p=") {
                notes.push("Missing v=DKIM1 version tag.".to_string());
                "warn"
            } else {
                "pass"
            }
        }
        None => {
            notes.push("Missing 'p=' public key tag.".to_string());
            "warn"
        }
    };

    DkimSelectorResult {
        selector: selector.to_string(),
        found: true,
        cname_target,
        raw_record: Some(raw.to_string()),
        key_type,
        public_key_present,
        status: status.to_string(),
        notes,
    }
}

async fn probe_dkim_selector(
    resolver: &TokioResolver,
    domain: &str,
    selector: &str,
) -> DkimSelectorResult {
    let fqdn = format!("{selector}._domainkey.{domain}.");

    let cname_target = match resolver.lookup(&fqdn, RecordType::CNAME).await {
        Ok(lookup) => lookup.record_iter().find_map(|r| match r.data() {
            RData::CNAME(c) => Some(c.0.to_string()),
            _ => None,
        }),
        Err(_) => None,
    };

    match fetch_txt_strings(resolver, &fqdn).await {
        Ok(txts) => {
            if let Some(dkim_txt) = txts
                .iter()
                .find(|t| {
                    let l = t.to_ascii_lowercase();
                    l.contains("v=dkim1") || l.contains("p=")
                })
                .or_else(|| txts.first())
            {
                parse_dkim_txt(selector, dkim_txt, cname_target)
            } else if let Some(target) = cname_target {
                DkimSelectorResult {
                    selector: selector.to_string(),
                    found: true,
                    cname_target: Some(target),
                    raw_record: None,
                    key_type: None,
                    public_key_present: false,
                    status: "warn".to_string(),
                    notes: vec!["CNAME exists but target returned no DKIM TXT record.".to_string()],
                }
            } else {
                DkimSelectorResult {
                    selector: selector.to_string(),
                    found: false,
                    cname_target: None,
                    raw_record: None,
                    key_type: None,
                    public_key_present: false,
                    status: "missing".to_string(),
                    notes: vec![],
                }
            }
        }
        Err(err) => DkimSelectorResult {
            selector: selector.to_string(),
            found: false,
            cname_target,
            raw_record: None,
            key_type: None,
            public_key_present: false,
            status: "missing".to_string(),
            notes: vec![format!("Lookup error: {err}")],
        },
    }
}

async fn check_dkim(
    resolver: &TokioResolver,
    domain: &str,
    custom_selectors: &[String],
) -> DkimCheck {
    let cleaned: Vec<String> = custom_selectors
        .iter()
        .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let using_custom = !cleaned.is_empty();
    let selectors: Vec<String> = if using_custom {
        cleaned
    } else {
        DEFAULT_DKIM_SELECTORS.iter().map(|s| s.to_string()).collect()
    };

    let results = join_all(
        selectors
            .iter()
            .map(|sel| probe_dkim_selector(resolver, domain, sel)),
    )
    .await;

    let active_count = results
        .iter()
        .filter(|r| r.found && r.status == "pass")
        .count();
    let found_count = results.iter().filter(|r| r.found).count();
    let mut issues = Vec::new();

    let (status, summary) = if active_count > 0 {
        (
            "pass".to_string(),
            format!("Found {active_count} active DKIM selector(s)."),
        )
    } else if found_count > 0 {
        issues.push("Found DKIM selector(s), but none contain an active public key.".to_string());
        (
            "warn".to_string(),
            "DKIM selector found without active public key.".to_string(),
        )
    } else {
        if using_custom {
            issues.push("None of the specified DKIM selectors resolved.".to_string());
        } else {
            issues.push(
                "No common DKIM selectors matched. Enter your mail provider's exact selector to verify."
                    .to_string(),
            );
        }
        (
            "warn".to_string(),
            "No DKIM records matched checked selectors.".to_string(),
        )
    };

    DkimCheck {
        status,
        summary,
        checked_selectors: selectors,
        results,
        issues,
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

async fn check_dnssec(resolver: &TokioResolver, domain: &str) -> DnssecCheck {
    let fqdn = format!("{domain}.");

    let (ds_res, dnskey_res) = tokio::join!(
        resolver.lookup(&fqdn, RecordType::DS),
        resolver.lookup(&fqdn, RecordType::DNSKEY),
    );

    let mut ds_records = Vec::new();
    let mut dnskey_records = Vec::new();
    let mut issues = Vec::new();

    if let Ok(lookup) = ds_res {
        for rec in lookup.record_iter() {
            if let RData::DNSSEC(DNSSECRData::DS(ds)) = rec.data() {
                let digest_hex = hex_encode(ds.digest());
                let preview = if digest_hex.len() > 20 {
                    format!("{}...", &digest_hex[..20])
                } else {
                    digest_hex
                };
                ds_records.push(format!(
                    "tag={} alg={} digest={:?} ({preview})",
                    ds.key_tag(),
                    ds.algorithm(),
                    ds.digest_type()
                ));
            }
        }
    }

    if let Ok(lookup) = dnskey_res {
        for rec in lookup.record_iter() {
            if let RData::DNSSEC(DNSSECRData::DNSKEY(key)) = rec.data() {
                let role = if key.is_key_signing_key() {
                    "KSK"
                } else if key.zone_key() {
                    "ZSK"
                } else {
                    "Key"
                };
                let revoked = if key.revoke() { " [REVOKED]" } else { "" };
                dnskey_records.push(format!(
                    "flags={} ({role}{revoked}) alg={}",
                    key.flags(),
                    key.public_key().algorithm()
                ));
            }
        }
    }

    let has_ds = !ds_records.is_empty();
    let has_dnskey = !dnskey_records.is_empty();

    if !has_ds && !has_dnskey {
        return DnssecCheck {
            status: "unsigned".to_string(),
            summary: "DNSSEC is not enabled (no DS or DNSKEY records).".to_string(),
            ds_records,
            dnskey_records,
            validated: false,
            validation_error: None,
            issues: vec!["Zone is unsigned; consider enabling DNSSEC at your DNS host and registrar.".to_string()],
        };
    }

    let mut validated = false;
    let mut validation_error = None;

    if let Ok((_, _, val_resolver)) = build_resolver("cloudflare", None, true) {
        match val_resolver.lookup(&fqdn, RecordType::SOA).await {
            Ok(_) => validated = true,
            Err(err) => {
                validation_error = Some(err.to_string());
            }
        }
    }

    let status = if has_ds && has_dnskey && validated {
        "pass"
    } else if !has_ds || !has_dnskey {
        if !has_ds {
            issues.push("DNSKEY exists, but no DS record found at parent zone.".to_string());
        }
        if !has_dnskey {
            issues.push("DS record exists, but no DNSKEY record was returned.".to_string());
        }
        if validation_error.is_some() {
            "fail"
        } else {
            "warn"
        }
    } else if !validated {
        issues.push("DNSSEC cryptographic validation failed.".to_string());
        "fail"
    } else {
        "pass"
    };

    let summary = match status {
        "pass" => format!(
            "DNSSEC signed & validated ({} DS, {} DNSKEY).",
            ds_records.len(),
            dnskey_records.len()
        ),
        "warn" => "Partial DNSSEC configuration (incomplete chain of trust).".to_string(),
        _ => "DNSSEC validation failed.".to_string(),
    };

    DnssecCheck {
        status: status.to_string(),
        summary,
        ds_records,
        dnskey_records,
        validated,
        validation_error,
        issues,
    }
}

pub async fn run_security_checks(
    domain: &str,
    resolver: &TokioResolver,
    custom_dkim_selectors: &[String],
) -> SecurityReport {
    let apex_fqdn = format!("{domain}.");
    let dmarc_fqdn = format!("_dmarc.{domain}.");

    let (apex_txts, dmarc_txts, dkim, dnssec) = tokio::join!(
        fetch_txt_strings(resolver, &apex_fqdn),
        fetch_txt_strings(resolver, &dmarc_fqdn),
        check_dkim(resolver, domain, custom_dkim_selectors),
        check_dnssec(resolver, domain),
    );

    let spf = match apex_txts {
        Ok(txts) => analyze_spf(&txts),
        Err(err) => SpfCheck {
            status: "missing".to_string(),
            summary: "Failed to query apex TXT for SPF.".to_string(),
            raw_record: None,
            mechanisms: vec![],
            all_qualifier: None,
            dns_lookup_count: 0,
            issues: vec![err],
        },
    };

    let dmarc = match dmarc_txts {
        Ok(txts) => analyze_dmarc(&txts),
        Err(err) => DmarcCheck {
            status: "missing".to_string(),
            summary: "Failed to query _dmarc TXT.".to_string(),
            raw_record: None,
            policy: None,
            subdomain_policy: None,
            pct: None,
            rua: vec![],
            ruf: vec![],
            adkim: None,
            aspf: None,
            issues: vec![err],
        },
    };

    SecurityReport {
        spf,
        dmarc,
        dkim,
        dnssec,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_analyze_spf_variants() {
        let valid = analyze_spf(&["v=spf1 include:_spf.google.com ~all".to_string()]);
        assert_eq!(valid.status, "pass");
        assert_eq!(valid.all_qualifier.as_deref(), Some("~all"));
        assert_eq!(valid.dns_lookup_count, 1);

        let dangerous = analyze_spf(&["v=spf1 +all".to_string()]);
        assert_eq!(dangerous.status, "fail");
        assert_eq!(dangerous.all_qualifier.as_deref(), Some("+all"));

        let too_many = analyze_spf(&[
            "v=spf1 a mx include:1 include:2 include:3 include:4 include:5 include:6 include:7 include:8 include:9 -all"
                .to_string(),
        ]);
        assert_eq!(too_many.status, "warn");
        assert_eq!(too_many.dns_lookup_count, 11);

        let multiple = analyze_spf(&["v=spf1 -all".to_string(), "v=spf1 ~all".to_string()]);
        assert_eq!(multiple.status, "fail");

        let missing = analyze_spf(&["google-site-verification=abc".to_string()]);
        assert_eq!(missing.status, "missing");
    }

    #[test]
    fn test_analyze_dmarc_variants() {
        let strict = analyze_dmarc(&[
            "v=DMARC1; p=reject; sp=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@example.com"
                .to_string(),
        ]);
        assert_eq!(strict.status, "pass");
        assert_eq!(strict.policy.as_deref(), Some("reject"));
        assert_eq!(strict.subdomain_policy.as_deref(), Some("quarantine"));
        assert_eq!(strict.pct, Some(100));
        assert_eq!(strict.rua, vec!["mailto:dmarc@example.com"]);

        let monitor = analyze_dmarc(&["v=DMARC1; p=none; rua=mailto:a@b.com".to_string()]);
        assert_eq!(monitor.status, "warn");

        let missing = analyze_dmarc(&[]);
        assert_eq!(missing.status, "missing");
    }

    #[test]
    fn test_parse_dkim_txt() {
        let active = parse_dkim_txt("google", "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A", None);
        assert_eq!(active.status, "pass");
        assert!(active.public_key_present);
        assert_eq!(active.key_type.as_deref(), Some("rsa"));

        let revoked = parse_dkim_txt("old", "v=DKIM1; k=rsa; p=", None);
        assert_eq!(revoked.status, "warn");
        assert!(!revoked.public_key_present);
    }
}
