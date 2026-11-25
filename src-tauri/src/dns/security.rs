use std::collections::HashSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use futures::future::join_all;
use hickory_resolver::proto::dnssec::rdata::DNSSECRData;
use hickory_resolver::proto::dnssec::PublicKey;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use tokio::time::timeout;

use crate::dns::{build_resolver, txt_to_string};
use crate::models::{
    BimiCheck, DkimCheck, DkimSelectorResult, DmarcCheck, DnssecCheck, MtaStsCheck, SecurityReport,
    SpfCheck, SpfLookupNode, TlsRptCheck,
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

const SPF_LOOKUP_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_SPF_DEPTH: u8 = 5;
const MAX_SPF_NODES: usize = 25;

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
            recursive_lookup_count: 0,
            lookup_tree: vec![],
            issues: vec!["Add a v=spf1 TXT record to authorize mail senders.".to_string()],
        };
    }

    if spf_records.len() > 1 {
        return SpfCheck {
            status: "fail".to_string(),
            summary: format!("Multiple SPF records detected ({}).", spf_records.len()),
            raw_record: Some(
                spf_records
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            mechanisms: vec![],
            all_qualifier: None,
            dns_lookup_count: 0,
            recursive_lookup_count: 0,
            lookup_tree: vec![],
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
                issues.push(
                    "Mechanism 'ptr' is deprecated and discouraged by RFC 7208.".to_string(),
                );
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
            issues
                .push("'+all' permits any server on the internet to spoof this domain.".to_string());
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
            if !mechanisms
                .iter()
                .any(|m| m.to_ascii_lowercase().starts_with("redirect="))
            {
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
        recursive_lookup_count: dns_lookup_count,
        lookup_tree: vec![],
        issues,
    }
}

fn is_spf_lookup_mechanism(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    let stripped = lower.trim_start_matches(['+', '-', '~', '?']);
    stripped.starts_with("include:")
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
}

fn extract_spf_target(token: &str, root_domain: &str) -> (String, String, bool) {
    let lower = token.to_ascii_lowercase();
    let stripped = lower.trim_start_matches(['+', '-', '~', '?']);
    if let Some(target) = stripped.strip_prefix("include:") {
        let clean = target.trim().trim_end_matches('.').to_string();
        return ("include".to_string(), clean, true);
    }
    if let Some(target) = lower.strip_prefix("redirect=") {
        let clean = target.trim().trim_end_matches('.').to_string();
        return ("redirect".to_string(), clean, true);
    }
    let mech_kind = stripped.split([':', '/']).next().unwrap_or(stripped).to_string();
    let target = stripped
        .split_once(':')
        .map(|(_, rest)| rest.split('/').next().unwrap_or(rest).to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| root_domain.to_string());
    (mech_kind, target, false)
}

fn resolve_spf_nodes_rec<'a>(
    resolver: &'a TokioResolver,
    current_domain: &'a str,
    mechanisms: &'a [String],
    depth: u8,
    visited: &'a mut HashSet<String>,
    node_count: &'a mut usize,
) -> Pin<Box<dyn Future<Output = (Vec<SpfLookupNode>, u32)> + Send + 'a>> {
    Box::pin(async move {
        let mut nodes = Vec::new();
        let mut total_lookups: u32 = 0;

        for token in mechanisms {
            if !is_spf_lookup_mechanism(token) {
                continue;
            }
            if *node_count >= MAX_SPF_NODES {
                break;
            }
            *node_count += 1;
            total_lookups += 1;

            let (kind, target, is_recursive) = extract_spf_target(token, current_domain);

            if !is_recursive {
                nodes.push(SpfLookupNode {
                    mechanism: token.clone(),
                    target,
                    lookups_added: 1,
                    depth,
                    raw_record: None,
                    error: None,
                    children: vec![],
                });
                continue;
            }

            if depth >= MAX_SPF_DEPTH {
                nodes.push(SpfLookupNode {
                    mechanism: token.clone(),
                    target,
                    lookups_added: 1,
                    depth,
                    raw_record: None,
                    error: Some("Max SPF recursion depth (5) reached".to_string()),
                    children: vec![],
                });
                continue;
            }

            if target.is_empty() || target.contains('%') {
                let err_msg = if target.contains('%') {
                    Some("Macro expansion target not statically resolved".to_string())
                } else {
                    Some(format!("Empty {kind} target"))
                };
                nodes.push(SpfLookupNode {
                    mechanism: token.clone(),
                    target,
                    lookups_added: 1,
                    depth,
                    raw_record: None,
                    error: err_msg,
                    children: vec![],
                });
                continue;
            }

            if !visited.insert(target.clone()) {
                nodes.push(SpfLookupNode {
                    mechanism: token.clone(),
                    target,
                    lookups_added: 1,
                    depth,
                    raw_record: None,
                    error: Some("Circular SPF include/redirect loop detected".to_string()),
                    children: vec![],
                });
                continue;
            }

            let fqdn = format!("{target}.");
            let mut raw_record = None;
            let mut err_msg = None;
            let mut children = Vec::new();
            let mut subtree_lookups = 0u32;

            match timeout(SPF_LOOKUP_TIMEOUT, fetch_txt_strings(resolver, &fqdn)).await {
                Ok(Ok(txts)) => {
                    let spf_txts: Vec<&String> = txts
                        .iter()
                        .filter(|s| {
                            let l = s.trim_start().to_ascii_lowercase();
                            l == "v=spf1" || l.starts_with("v=spf1 ")
                        })
                        .collect();

                    if spf_txts.is_empty() {
                        err_msg = Some("No v=spf1 TXT record found at target".to_string());
                    } else if spf_txts.len() > 1 {
                        raw_record = Some(spf_txts[0].trim().to_string());
                        err_msg = Some("Target publishes multiple SPF records".to_string());
                    } else {
                        let raw = spf_txts[0].trim().to_string();
                        let sub_mechs: Vec<String> = raw
                            .split_whitespace()
                            .skip(1)
                            .map(|s| s.to_string())
                            .collect();
                        raw_record = Some(raw);
                        let (sub_nodes, sub_count) = resolve_spf_nodes_rec(
                            resolver,
                            &target,
                            &sub_mechs,
                            depth + 1,
                            visited,
                            node_count,
                        )
                        .await;
                        children = sub_nodes;
                        subtree_lookups = sub_count;
                    }
                }
                Ok(Err(e)) => {
                    err_msg = Some(e);
                }
                Err(_) => {
                    err_msg = Some("TXT lookup timed out".to_string());
                }
            }

            total_lookups += subtree_lookups;
            nodes.push(SpfLookupNode {
                mechanism: token.clone(),
                target,
                lookups_added: 1 + subtree_lookups,
                depth,
                raw_record,
                error: err_msg,
                children,
            });
        }

        (nodes, total_lookups)
    })
}

async fn resolve_spf_tree(resolver: &TokioResolver, domain: &str, spf: &mut SpfCheck) {
    if spf.mechanisms.is_empty() {
        return;
    }
    let mut visited = HashSet::new();
    visited.insert(domain.to_ascii_lowercase());
    let mut node_count = 0usize;

    let (tree, recursive_count) =
        resolve_spf_nodes_rec(resolver, domain, &spf.mechanisms, 1, &mut visited, &mut node_count)
            .await;

    spf.lookup_tree = tree;
    spf.recursive_lookup_count = recursive_count.max(spf.dns_lookup_count);

    if spf.recursive_lookup_count > 10 {
        let already_flagged = spf.issues.iter().any(|i| i.contains("limit is 10"));
        if !already_flagged {
            spf.issues.push(format!(
                "Recursive SPF evaluation requires {} DNS lookups (RFC 7208 max is 10 — causes PermError).",
                spf.recursive_lookup_count
            ));
        }
        if spf.status == "pass" {
            spf.status = "warn".to_string();
        }
        spf.summary = format!(
            "SPF exceeds 10-lookup limit ({} recursive lookups).",
            spf.recursive_lookup_count
        );
    } else if spf.status == "pass" {
        spf.summary = format!(
            "Valid SPF ({}, {}/10 recursive lookups).",
            spf.all_qualifier.as_deref().unwrap_or("redirect"),
            spf.recursive_lookup_count
        );
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
            issues: vec![
                "Publish a v=DMARC1 TXT record at _dmarc to enforce alignment.".to_string(),
            ],
        };
    }

    if dmarc_records.len() > 1 {
        return DmarcCheck {
            status: "fail".to_string(),
            summary: format!("Multiple DMARC records found ({}).", dmarc_records.len()),
            raw_record: Some(
                dmarc_records
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(" | "),
            ),
            policy: None,
            subdomain_policy: None,
            pct: None,
            rua: vec![],
            ruf: vec![],
            adkim: None,
            aspf: None,
            issues: vec![
                "Multiple DMARC TXT records cause receivers to ignore DMARC.".to_string(),
            ],
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
            issues.push(format!(
                "Policy applies to only {p_pct}% of messages (pct={p_pct})."
            ));
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
            issues.push(
                "Policy is set to 'none' (monitoring only; does not block spoofing).".to_string(),
            );
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
        Some(p) => format!(
            "DMARC policy p={p}{}.",
            if rua.is_empty() { " (no rua)" } else { "" }
        ),
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
            issues: vec![
                "Zone is unsigned; consider enabling DNSSEC at your DNS host and registrar."
                    .to_string(),
            ],
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

pub fn parse_mta_sts_policy(raw: &str) -> (Option<String>, Option<u64>, Vec<String>) {
    let mut mode = None;
    let mut max_age = None;
    let mut mx_patterns = Vec::new();

    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            match key.as_str() {
                "mode" => mode = Some(val.to_ascii_lowercase()),
                "max_age" => {
                    if let Ok(n) = val.parse::<u64>() {
                        max_age = Some(n);
                    }
                }
                "mx" => {
                    if !val.is_empty() {
                        mx_patterns.push(val.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    (mode, max_age, mx_patterns)
}

async fn check_mta_sts(resolver: &TokioResolver, domain: &str) -> MtaStsCheck {
    let fqdn = format!("_mta-sts.{domain}.");
    let txts = match fetch_txt_strings(resolver, &fqdn).await {
        Ok(list) => list,
        Err(_) => vec![],
    };

    let sts_record = txts
        .into_iter()
        .find(|s| s.trim_start().to_ascii_lowercase().starts_with("v=stsv1"));

    let Some(dns_record) = sts_record else {
        return MtaStsCheck {
            status: "missing".to_string(),
            summary: "No _mta-sts TXT record found.".to_string(),
            dns_record: None,
            policy_id: None,
            policy_fetched: false,
            mode: None,
            max_age: None,
            mx_patterns: vec![],
            raw_policy: None,
            issues: vec![
                "Publish _mta-sts TXT and /.well-known/mta-sts.txt to enforce TLS for inbound mail."
                    .to_string(),
            ],
        };
    };

    let mut policy_id = None;
    for part in dns_record.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k.trim().eq_ignore_ascii_case("id") {
                policy_id = Some(v.trim().to_string());
            }
        }
    }

    let mut issues = Vec::new();
    let policy_url = format!("https://mta-sts.{domain}/.well-known/mta-sts.txt");
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_secs(3))
        .user_agent("DomainTools/0.2")
        .build();

    let mut policy_fetched = false;
    let mut mode = None;
    let mut max_age = None;
    let mut mx_patterns = Vec::new();
    let mut raw_policy = None;

    if let Ok(c) = client {
        match c.get(&policy_url).send().await {
            Ok(resp) if resp.status().is_success() => {
                if let Ok(bytes) = resp.bytes().await {
                    let capped = &bytes[..bytes.len().min(16 * 1024)];
                    let text = String::from_utf8_lossy(capped).into_owned();
                    let (m, age, mxs) = parse_mta_sts_policy(&text);
                    policy_fetched = true;
                    mode = m;
                    max_age = age;
                    mx_patterns = mxs;
                    raw_policy = Some(text);
                }
            }
            Ok(resp) => {
                issues.push(format!(
                    "Policy file {policy_url} returned HTTP {}.",
                    resp.status().as_u16()
                ));
            }
            Err(e) => {
                issues.push(format!("Failed to fetch {policy_url}: {e}"));
            }
        }
    }

    let status = if !policy_fetched {
        "fail"
    } else {
        match mode.as_deref() {
            Some("enforce") => {
                if mx_patterns.is_empty() {
                    issues.push("MTA-STS policy contains no 'mx:' host patterns.".to_string());
                    "warn"
                } else {
                    "pass"
                }
            }
            Some("testing") => {
                issues.push("MTA-STS mode is 'testing' (reports only; switch to 'enforce').".to_string());
                "warn"
            }
            Some("none") => {
                issues.push("MTA-STS mode is 'none' (disabled).".to_string());
                "warn"
            }
            _ => {
                issues.push("MTA-STS policy file missing valid 'mode:' directive.".to_string());
                "warn"
            }
        }
    };

    let summary = match (policy_fetched, mode.as_deref()) {
        (true, Some(m)) => format!("MTA-STS active (mode={m}, {} MX patterns).", mx_patterns.len()),
        (true, None) => "MTA-STS policy fetched, but mode is invalid.".to_string(),
        (false, _) => "DNS _mta-sts record found, but HTTPS policy file failed.".to_string(),
    };

    MtaStsCheck {
        status: status.to_string(),
        summary,
        dns_record: Some(dns_record),
        policy_id,
        policy_fetched,
        mode,
        max_age,
        mx_patterns,
        raw_policy,
        issues,
    }
}

pub fn analyze_tls_rpt(txt_records: &[String]) -> TlsRptCheck {
    let matching: Vec<&String> = txt_records
        .iter()
        .filter(|s| s.trim_start().to_ascii_lowercase().starts_with("v=tlsrptv1"))
        .collect();

    if matching.is_empty() {
        return TlsRptCheck {
            status: "missing".to_string(),
            summary: "No _smtp._tls TXT record found.".to_string(),
            raw_record: None,
            rua: vec![],
            issues: vec![
                "Publish a v=TLSRPTv1 record at _smtp._tls to receive SMTP TLS failure reports."
                    .to_string(),
            ],
        };
    }

    let raw = matching[0].trim().to_string();
    let mut rua = Vec::new();
    let mut issues = Vec::new();

    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            if k.trim().eq_ignore_ascii_case("rua") {
                rua.extend(
                    v.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty()),
                );
            }
        }
    }

    let status = if rua.is_empty() {
        issues.push("TLS-RPT record is missing a 'rua=' reporting URI.".to_string());
        "warn"
    } else {
        "pass"
    };

    TlsRptCheck {
        status: status.to_string(),
        summary: if rua.is_empty() {
            "TLS-RPT record missing rua= destination.".to_string()
        } else {
            format!("TLS-RPT active ({} reporting target(s)).", rua.len())
        },
        raw_record: Some(raw),
        rua,
        issues,
    }
}

async fn check_tls_rpt(resolver: &TokioResolver, domain: &str) -> TlsRptCheck {
    let fqdn = format!("_smtp._tls.{domain}.");
    match fetch_txt_strings(resolver, &fqdn).await {
        Ok(txts) => analyze_tls_rpt(&txts),
        Err(err) => TlsRptCheck {
            status: "missing".to_string(),
            summary: "Failed to query _smtp._tls TXT.".to_string(),
            raw_record: None,
            rua: vec![],
            issues: vec![err],
        },
    }
}

pub fn analyze_bimi(txt_records: &[String]) -> BimiCheck {
    let matching: Vec<&String> = txt_records
        .iter()
        .filter(|s| s.trim_start().to_ascii_lowercase().starts_with("v=bimi1"))
        .collect();

    if matching.is_empty() {
        return BimiCheck {
            status: "missing".to_string(),
            summary: "No BIMI record found at default._bimi.".to_string(),
            raw_record: None,
            logo_url: None,
            authority_url: None,
            issues: vec![],
        };
    }

    let raw = matching[0].trim().to_string();
    let mut logo_url = None;
    let mut authority_url = None;
    let mut issues = Vec::new();

    for part in raw.split(';') {
        if let Some((k, v)) = part.trim().split_once('=') {
            let key = k.trim().to_ascii_lowercase();
            let val = v.trim();
            if key == "l" && !val.is_empty() {
                logo_url = Some(val.to_string());
            } else if key == "a" && !val.is_empty() {
                authority_url = Some(val.to_string());
            }
        }
    }

    let status = if logo_url
        .as_deref()
        .is_some_and(|u| u.starts_with("https://"))
    {
        if authority_url.is_none() {
            issues.push("No VMC/CMC certificate URL (a=) set; some inbox providers require VMC.".to_string());
        }
        "pass"
    } else {
        issues.push("BIMI record missing valid HTTPS SVG logo URL (l=).".to_string());
        "warn"
    };

    BimiCheck {
        status: status.to_string(),
        summary: if status == "pass" {
            if authority_url.is_some() {
                "BIMI configured with HTTPS logo and VMC authority certificate.".to_string()
            } else {
                "BIMI configured with HTTPS SVG logo.".to_string()
            }
        } else {
            "BIMI record incomplete.".to_string()
        },
        raw_record: Some(raw),
        logo_url,
        authority_url,
        issues,
    }
}

async fn check_bimi(resolver: &TokioResolver, domain: &str) -> BimiCheck {
    let fqdn = format!("default._bimi.{domain}.");
    match fetch_txt_strings(resolver, &fqdn).await {
        Ok(txts) => analyze_bimi(&txts),
        Err(_) => BimiCheck {
            status: "missing".to_string(),
            summary: "No BIMI record found at default._bimi.".to_string(),
            raw_record: None,
            logo_url: None,
            authority_url: None,
            issues: vec![],
        },
    }
}

pub async fn run_security_checks(
    domain: &str,
    resolver: &TokioResolver,
    custom_dkim_selectors: &[String],
) -> SecurityReport {
    let apex_fqdn = format!("{domain}.");
    let dmarc_fqdn = format!("_dmarc.{domain}.");

    let (apex_txts, dmarc_txts, dkim, dnssec, mta_sts, tls_rpt, bimi) = tokio::join!(
        fetch_txt_strings(resolver, &apex_fqdn),
        fetch_txt_strings(resolver, &dmarc_fqdn),
        check_dkim(resolver, domain, custom_dkim_selectors),
        check_dnssec(resolver, domain),
        check_mta_sts(resolver, domain),
        check_tls_rpt(resolver, domain),
        check_bimi(resolver, domain),
    );

    let mut spf = match apex_txts {
        Ok(txts) => analyze_spf(&txts),
        Err(err) => SpfCheck {
            status: "missing".to_string(),
            summary: "Failed to query apex TXT for SPF.".to_string(),
            raw_record: None,
            mechanisms: vec![],
            all_qualifier: None,
            dns_lookup_count: 0,
            recursive_lookup_count: 0,
            lookup_tree: vec![],
            issues: vec![err],
        },
    };

    if spf.status != "missing" && spf.raw_record.is_some() {
        resolve_spf_tree(resolver, domain, &mut spf).await;
    }

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
        mta_sts,
        tls_rpt,
        bimi,
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
        let active = parse_dkim_txt(
            "google",
            "v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
            None,
        );
        assert_eq!(active.status, "pass");
        assert!(active.public_key_present);
        assert_eq!(active.key_type.as_deref(), Some("rsa"));

        let revoked = parse_dkim_txt("old", "v=DKIM1; k=rsa; p=", None);
        assert_eq!(revoked.status, "warn");
        assert!(!revoked.public_key_present);
    }

    #[test]
    fn test_parse_mta_sts_policy() {
        let policy = "version: STSv1\nmode: enforce\nmx: *.mail.protection.outlook.com\nmx: mail.example.com\nmax_age: 604800\n";
        let (mode, max_age, mxs) = parse_mta_sts_policy(policy);
        assert_eq!(mode.as_deref(), Some("enforce"));
        assert_eq!(max_age, Some(604800));
        assert_eq!(mxs, vec!["*.mail.protection.outlook.com", "mail.example.com"]);
    }

    #[test]
    fn test_analyze_tls_rpt_and_bimi() {
        let rpt = analyze_tls_rpt(&["v=TLSRPTv1; rua=mailto:tlsrpt@example.com".to_string()]);
        assert_eq!(rpt.status, "pass");
        assert_eq!(rpt.rua, vec!["mailto:tlsrpt@example.com"]);

        let bimi = analyze_bimi(&[
            "v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem".to_string(),
        ]);
        assert_eq!(bimi.status, "pass");
        assert_eq!(bimi.logo_url.as_deref(), Some("https://example.com/logo.svg"));
        assert_eq!(
            bimi.authority_url.as_deref(),
            Some("https://example.com/vmc.pem")
        );
    }
}
