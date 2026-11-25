use std::collections::{BTreeSet, HashSet};
use std::time::{Duration, Instant};

use futures::stream::{self, StreamExt};
use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Resolver, TokioResolver};
use tokio::time::timeout;

use crate::dns::normalize_domain;
use crate::dns::whois::extract_whois_domain;
use crate::models::{TyposquatCandidate, TyposquatReport};

const MAX_TYPOSQUAT_CANDIDATES: usize = 96;
const PROBE_CONCURRENCY: usize = 24;

const SWAP_TLDS: &[&str] = &[
    "com", "net", "org", "io", "co", "app", "dev", "ai", "info", "biz", "xyz", "online", "site",
    "us", "uk", "ca", "de", "gg",
];

fn build_fast_resolver() -> TokioResolver {
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::cloudflare(),
        TokioConnectionProvider::default(),
    );
    let opts: &mut ResolverOpts = builder.options_mut();
    opts.cache_size = 0;
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    opts.edns0 = true;
    opts.use_hosts_file = ResolveHosts::Never;
    opts.validate = false;
    builder.build()
}

fn qwerty_neighbors(c: char) -> &'static [char] {
    match c {
        'a' => &['q', 'w', 's', 'z'],
        'b' => &['v', 'g', 'h', 'n'],
        'c' => &['x', 'd', 'f', 'v'],
        'd' => &['s', 'e', 'r', 'f', 'c', 'x'],
        'e' => &['w', 's', 'd', 'r'],
        'f' => &['d', 'r', 't', 'g', 'v', 'c'],
        'g' => &['f', 't', 'y', 'h', 'b', 'v'],
        'h' => &['g', 'y', 'u', 'j', 'n', 'b'],
        'i' => &['u', 'j', 'k', 'o'],
        'j' => &['h', 'u', 'i', 'k', 'm', 'n'],
        'k' => &['j', 'i', 'o', 'l', 'm'],
        'l' => &['k', 'o', 'p'],
        'm' => &['n', 'j', 'k'],
        'n' => &['b', 'h', 'j', 'm'],
        'o' => &['i', 'k', 'l', 'p'],
        'p' => &['o', 'l'],
        'q' => &['w', 'a'],
        'r' => &['e', 'd', 'f', 't'],
        's' => &['a', 'w', 'e', 'd', 'x', 'z'],
        't' => &['r', 'f', 'g', 'y'],
        'u' => &['y', 'h', 'j', 'i'],
        'v' => &['c', 'f', 'g', 'b'],
        'w' => &['q', 'a', 's', 'e'],
        'x' => &['z', 's', 'd', 'c'],
        'y' => &['t', 'g', 'h', 'u'],
        'z' => &['a', 's', 'x'],
        _ => &[],
    }
}

fn is_valid_sld(sld: &str) -> bool {
    !sld.is_empty()
        && sld.len() <= 63
        && !sld.starts_with('-')
        && !sld.ends_with('-')
        && !sld.contains("--")
        && sld
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
}

pub fn generate_typosquat_variants(domain: &str) -> Vec<(String, String)> {
    let apex = extract_whois_domain(domain);
    let Some((sld, tld)) = apex.split_once('.') else {
        return vec![];
    };

    let mut seen: HashSet<String> = HashSet::new();
    seen.insert(apex.clone());
    let mut out: Vec<(String, String)> = Vec::new();

    let mut push_cand = |new_sld: String, new_tld: &str, fuzzer: &str| {
        if !is_valid_sld(&new_sld) {
            return;
        }
        let fq = format!("{new_sld}.{new_tld}");
        if seen.insert(fq.clone()) {
            out.push((fq, fuzzer.to_string()));
        }
    };

    // 1. TLD Swaps (highest signal)
    for alt_tld in SWAP_TLDS {
        if *alt_tld != tld {
            push_cand(sld.to_string(), alt_tld, "TLD Swap");
        }
    }

    // 2. Combo / Phishing lures
    for lure in [
        format!("login-{sld}"),
        format!("{sld}-login"),
        format!("{sld}-secure"),
        format!("{sld}-support"),
        format!("my{sld}"),
        format!("{sld}app"),
        format!("{sld}mail"),
        format!("{sld}portal"),
    ] {
        push_cand(lure, tld, "Combo / Phishing");
    }

    // 3. Homoglyphs
    let homoglyph_pairs = [
        ("o", "0"),
        ("0", "o"),
        ("l", "1"),
        ("1", "l"),
        ("i", "l"),
        ("l", "i"),
        ("m", "rn"),
        ("rn", "m"),
        ("w", "vv"),
        ("vv", "w"),
        ("d", "cl"),
        ("cl", "d"),
    ];
    for (from, to) in homoglyph_pairs {
        for (idx, _) in sld.match_indices(from) {
            let replaced = format!("{}{}{}", &sld[..idx], to, &sld[idx + from.len()..]);
            push_cand(replaced, tld, "Homoglyph");
        }
    }

    let chars: Vec<char> = sld.chars().collect();

    // 4. Omission (drop 1 char)
    if chars.len() > 2 {
        for i in 0..chars.len() {
            let mut s = String::with_capacity(chars.len());
            for (j, ch) in chars.iter().enumerate() {
                if i != j {
                    s.push(*ch);
                }
            }
            push_cand(s, tld, "Omission");
        }
    }

    // 5. Transposition (swap adjacent)
    if chars.len() >= 2 {
        for i in 0..(chars.len() - 1) {
            if chars[i] != chars[i + 1] {
                let mut cloned = chars.clone();
                cloned.swap(i, i + 1);
                push_cand(cloned.into_iter().collect(), tld, "Transposition");
            }
        }
    }

    // 6. Repetition (duplicate char)
    for i in 0..chars.len() {
        let mut s = String::with_capacity(chars.len() + 1);
        for (j, ch) in chars.iter().enumerate() {
            s.push(*ch);
            if i == j {
                s.push(*ch);
            }
        }
        push_cand(s, tld, "Repetition");
    }

    // 7. Hyphenation
    if chars.len() >= 3 {
        for i in 1..chars.len() {
            if chars[i - 1] != '-' && chars[i] != '-' {
                let left: String = chars[..i].iter().collect();
                let right: String = chars[i..].iter().collect();
                push_cand(format!("{left}-{right}"), tld, "Hyphenation");
            }
        }
    }

    // 8. QWERTY adjacent typos (bounded)
    for (i, ch) in chars.iter().enumerate().take(16) {
        for &rep in qwerty_neighbors(*ch) {
            let mut cloned = chars.clone();
            cloned[i] = rep;
            push_cand(cloned.into_iter().collect(), tld, "QWERTY Typo");
        }
    }

    out
}

pub fn classify_typosquat_risk(
    a_records: &[String],
    aaaa_records: &[String],
    mx_records: &[String],
    ns_records: &[String],
) -> (bool, String, String) {
    let has_ip = !a_records.is_empty() || !aaaa_records.is_empty();
    let has_mx = !mx_records.is_empty();
    let has_ns = !ns_records.is_empty();
    let registered = has_ip || has_mx || has_ns;

    if has_mx {
        (
            true,
            "high".to_string(),
            "Active MX mail records — high phishing/BEC impersonation risk".to_string(),
        )
    } else if has_ip {
        (
            true,
            "medium".to_string(),
            "Resolves to active web/host IP address".to_string(),
        )
    } else if has_ns {
        (
            true,
            "low".to_string(),
            "Registered/delegated nameservers (no A/MX records)".to_string(),
        )
    } else {
        (
            registered,
            "none".to_string(),
            "Unregistered / NXDOMAIN".to_string(),
        )
    }
}

async fn probe_candidate(resolver: &TokioResolver, domain: String, fuzzer: String) -> TyposquatCandidate {
    let fqdn = format!("{domain}.");
    let (a_res, aaaa_res, mx_res, ns_res) = tokio::join!(
        timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::A)),
        timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::AAAA)),
        timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::MX)),
        timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::NS)),
    );

    let mut a_records = Vec::new();
    if let Ok(Ok(lookup)) = a_res {
        for r in lookup.record_iter() {
            if let RData::A(a) = r.data() {
                a_records.push(a.0.to_string());
            }
        }
    }

    let mut aaaa_records = Vec::new();
    if let Ok(Ok(lookup)) = aaaa_res {
        for r in lookup.record_iter() {
            if let RData::AAAA(aaaa) = r.data() {
                aaaa_records.push(aaaa.0.to_string());
            }
        }
    }

    let mut mx_records = Vec::new();
    if let Ok(Ok(lookup)) = mx_res {
        for r in lookup.record_iter() {
            if let RData::MX(mx) = r.data() {
                mx_records.push(format!(
                    "{} {}",
                    mx.preference(),
                    mx.exchange().to_string().trim_end_matches('.')
                ));
            }
        }
    }

    let mut ns_set = BTreeSet::new();
    if let Ok(Ok(lookup)) = ns_res {
        for r in lookup.record_iter() {
            if let RData::NS(ns) = r.data() {
                ns_set.insert(ns.0.to_string().trim_end_matches('.').to_ascii_lowercase());
            }
        }
    }
    let ns_records: Vec<String> = ns_set.into_iter().collect();

    let (registered, risk_level, risk_reason) =
        classify_typosquat_risk(&a_records, &aaaa_records, &mx_records, &ns_records);

    TyposquatCandidate {
        domain,
        fuzzer,
        registered,
        a_records,
        aaaa_records,
        mx_records,
        ns_records,
        risk_level,
        risk_reason,
    }
}

pub async fn scan_typosquats(domain: &str) -> Result<TyposquatReport, String> {
    let clean = normalize_domain(domain)?;
    let apex = extract_whois_domain(&clean);
    let started = Instant::now();

    let all_variants = generate_typosquat_variants(&apex);
    let total_generated = all_variants.len();
    let to_check: Vec<(String, String)> = all_variants
        .into_iter()
        .take(MAX_TYPOSQUAT_CANDIDATES)
        .collect();
    let total_checked = to_check.len();

    let resolver = build_fast_resolver();
    let mut candidates: Vec<TyposquatCandidate> = stream::iter(to_check)
        .map(|(dom, fuzzer)| {
            let r = &resolver;
            async move { probe_candidate(r, dom, fuzzer).await }
        })
        .buffer_unordered(PROBE_CONCURRENCY)
        .collect()
        .await;

    let risk_rank = |level: &str| match level {
        "high" => 0u8,
        "medium" => 1,
        "low" => 2,
        _ => 3,
    };

    candidates.sort_by(|a, b| {
        risk_rank(&a.risk_level)
            .cmp(&risk_rank(&b.risk_level))
            .then_with(|| a.domain.cmp(&b.domain))
    });

    let registered_count = candidates.iter().filter(|c| c.registered).count();
    let high_risk_count = candidates.iter().filter(|c| c.risk_level == "high").count();
    let active_web_count = candidates
        .iter()
        .filter(|c| !c.a_records.is_empty() || !c.aaaa_records.is_empty())
        .count();

    Ok(TyposquatReport {
        source_domain: apex,
        total_generated,
        total_checked,
        registered_count,
        high_risk_count,
        active_web_count,
        latency_ms: started.elapsed().as_millis() as u64,
        candidates,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_typosquat_variants() {
        let vars = generate_typosquat_variants("portal.example.com");
        assert!(!vars.is_empty());
        assert!(vars.iter().any(|(d, f)| d == "example.net" && f == "TLD Swap"));
        assert!(vars.iter().any(|(d, f)| d == "exampel.com" && f == "Transposition"));
        assert!(vars.iter().any(|(d, f)| d == "exmple.com" && f == "Omission"));
        assert!(vars.iter().any(|(d, f)| d == "login-example.com" && f == "Combo / Phishing"));
        assert!(!vars.iter().any(|(d, _)| d == "example.com"));
    }

    #[test]
    fn test_classify_typosquat_risk() {
        let (reg1, lvl1, _) = classify_typosquat_risk(
            &["1.2.3.4".into()],
            &[],
            &["10 mail.bad.com".into()],
            &["ns1.bad.com".into()],
        );
        assert!(reg1);
        assert_eq!(lvl1, "high");

        let (reg2, lvl2, _) = classify_typosquat_risk(&["1.2.3.4".into()], &[], &[], &[]);
        assert!(reg2);
        assert_eq!(lvl2, "medium");

        let (reg3, lvl3, _) = classify_typosquat_risk(&[], &[], &[], &[]);
        assert!(!reg3);
        assert_eq!(lvl3, "none");
    }
}
