use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use tokio::time::timeout;

use crate::dns::{build_resolver, txt_to_string};
use crate::models::{IpNetworkInfo, NetworkReport, ResolverResult};

const DNS_ENRICH_TIMEOUT: Duration = Duration::from_millis(2500);
const GEO_HTTP_TIMEOUT: Duration = Duration::from_millis(3000);
const MAX_NETWORK_IPS: usize = 12;

#[derive(Debug, Clone)]
struct CollectedIp {
    ip: IpAddr,
    roles: BTreeSet<String>,
    hostnames: BTreeSet<String>,
}

pub fn reverse_ipv6_nibbles(ip: Ipv6Addr) -> String {
    let octets = ip.octets();
    let mut parts = Vec::with_capacity(32);
    for byte in octets.iter().rev() {
        parts.push(format!("{:x}", byte & 0x0f));
        parts.push(format!("{:x}", (byte >> 4) & 0x0f));
    }
    parts.join(".")
}

pub fn parse_cymru_origin_txt(raw: &str) -> Option<(u32, Option<String>, Option<String>)> {
    // Format: "13335 | 104.16.0.0/14 | US | arin | 2014-03-28"
    let cols: Vec<&str> = raw.split('|').map(|s| s.trim()).collect();
    if cols.is_empty() {
        return None;
    }
    let asn = cols[0].split_whitespace().next()?.parse::<u32>().ok()?;
    let cidr = cols.get(1).and_then(|s| (!s.is_empty()).then(|| s.to_string()));
    let cc = cols.get(2).and_then(|s| (!s.is_empty()).then(|| s.to_string()));
    Some((asn, cidr, cc))
}

pub fn parse_cymru_asn_txt(raw: &str) -> Option<String> {
    // Format: "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US"
    let cols: Vec<&str> = raw.split('|').map(|s| s.trim()).collect();
    let org = cols.last().copied().unwrap_or("").trim();
    if org.is_empty() {
        None
    } else {
        Some(org.to_string())
    }
}

pub fn classify_network_provider(
    as_org: Option<&str>,
    ptrs: &[String],
    asn: Option<u32>,
) -> (String, Option<String>, bool) {
    let hay = format!(
        "{} {}",
        as_org.unwrap_or(""),
        ptrs.join(" ")
    )
    .to_ascii_lowercase();

    let cdn_match: Option<&str> = if asn == Some(13335) || hay.contains("cloudflare") {
        Some("Cloudflare")
    } else if asn == Some(54113) || hay.contains("fastly") {
        Some("Fastly")
    } else if hay.contains("akamai") || hay.contains("deploy.static.akamaitechnologies") {
        Some("Akamai")
    } else if hay.contains("cloudfront") {
        Some("AWS CloudFront")
    } else if hay.contains("vercel") {
        Some("Vercel")
    } else if hay.contains("netlify") {
        Some("Netlify")
    } else if hay.contains("bunnycdn") || hay.contains("bunny.net") || hay.contains("dataplug") {
        Some("Bunny.net")
    } else if hay.contains("sucuri") {
        Some("Sucuri WAF")
    } else if hay.contains("imperva") || hay.contains("incapsula") {
        Some("Imperva")
    } else if hay.contains("shopify") {
        Some("Shopify")
    } else if hay.contains("squarespace") {
        Some("Squarespace")
    } else if hay.contains("edgecast") || hay.contains("verizon digital media") {
        Some("Edgio / Edgecast")
    } else if asn == Some(15169) && hay.contains("1e100.net") {
        Some("Google Edge")
    } else {
        None
    };

    if let Some(name) = cdn_match {
        return ("CDN / Anycast".to_string(), Some(name.to_string()), true);
    }

    let mail_match: Option<&str> = if hay.contains("mimecast") {
        Some("Mimecast")
    } else if hay.contains("proofpoint") || hay.contains("pphosted") {
        Some("Proofpoint")
    } else if hay.contains("sendgrid") {
        Some("SendGrid")
    } else if hay.contains("mailgun") {
        Some("Mailgun")
    } else if hay.contains("fastmail") {
        Some("Fastmail")
    } else if hay.contains("proton") {
        Some("Proton Mail")
    } else if hay.contains("zoho") {
        Some("Zoho")
    } else if hay.contains("protection.outlook.com") || hay.contains("mail.eo.outlook") {
        Some("Microsoft 365 Mail")
    } else if hay.contains("google.com") && hay.contains("smtp") {
        Some("Google Workspace Mail")
    } else {
        None
    };

    if let Some(name) = mail_match {
        return ("Mail Provider".to_string(), Some(name.to_string()), false);
    }

    let cloud_match: Option<&str> = if hay.contains("amazon") || hay.contains("amazonaws") || asn == Some(16509) || asn == Some(14618) {
        Some("Amazon AWS")
    } else if hay.contains("google") || asn == Some(15169) || asn == Some(396982) {
        Some("Google Cloud")
    } else if hay.contains("microsoft") || hay.contains("azure") || asn == Some(8075) {
        Some("Microsoft Azure")
    } else if hay.contains("digitalocean") || asn == Some(14061) {
        Some("DigitalOcean")
    } else if hay.contains("hetzner") || asn == Some(24940) {
        Some("Hetzner")
    } else if hay.contains("ovh") || asn == Some(16276) {
        Some("OVHcloud")
    } else if hay.contains("linode") || hay.contains("akamai connected cloud") || asn == Some(63949) {
        Some("Akamai / Linode")
    } else if hay.contains("vultr") || hay.contains("choopa") || asn == Some(20473) {
        Some("Vultr")
    } else if hay.contains("oracle") || asn == Some(31898) {
        Some("Oracle Cloud")
    } else if hay.contains("fly.io") {
        Some("Fly.io")
    } else if hay.contains("wpengine") {
        Some("WP Engine")
    } else {
        None
    };

    if let Some(name) = cloud_match {
        return ("Cloud / Hosting".to_string(), Some(name.to_string()), false);
    }

    ("Network".to_string(), None, false)
}

pub(crate) async fn lookup_ptr(resolver: &TokioResolver, ip: IpAddr) -> Vec<String> {
    match timeout(DNS_ENRICH_TIMEOUT, resolver.reverse_lookup(ip)).await {
        Ok(Ok(resp)) => resp
            .iter()
            .map(|ptr| ptr.0.to_string().trim_end_matches('.').to_string())
            .filter(|s| !s.is_empty())
            .collect(),
        _ => Vec::new(),
    }
}

pub(crate) async fn lookup_cymru_asn(
    resolver: &TokioResolver,
    ip: IpAddr,
) -> (Option<u32>, Option<String>, Option<String>, Option<String>) {
    let origin_fqdn = match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com.")
        }
        IpAddr::V6(v6) => format!("{}.origin6.asn.cymru.com.", reverse_ipv6_nibbles(v6)),
    };

    let Ok(Ok(lookup)) = timeout(DNS_ENRICH_TIMEOUT, resolver.lookup(origin_fqdn, RecordType::TXT)).await else {
        return (None, None, None, None);
    };

    let mut parsed = None;
    for r in lookup.iter() {
        if let RData::TXT(txt) = r {
            let line = txt_to_string(txt);
            if let Some(val) = parse_cymru_origin_txt(&line) {
                parsed = Some(val);
                break;
            }
        }
    }

    let Some((asn, cidr, cc)) = parsed else {
        return (None, None, None, None);
    };

    let asn_fqdn = format!("AS{asn}.asn.cymru.com.");
    let as_org = match timeout(DNS_ENRICH_TIMEOUT, resolver.lookup(asn_fqdn, RecordType::TXT)).await {
        Ok(Ok(resp)) => resp.iter().find_map(|r| match r {
            RData::TXT(txt) => parse_cymru_asn_txt(&txt_to_string(txt)),
            _ => None,
        }),
        _ => None,
    };

    (Some(asn), as_org, cidr, cc)
}

#[derive(Default)]
struct GeoLookupData {
    asn: Option<u32>,
    as_org: Option<String>,
    country: Option<String>,
    country_code: Option<String>,
    region: Option<String>,
    city: Option<String>,
    isp: Option<String>,
}

async fn lookup_geo_ipwho(client: &reqwest::Client, ip: IpAddr) -> GeoLookupData {
    let url = format!("https://ipwho.is/{ip}");
    let Ok(resp) = client.get(&url).send().await else {
        return GeoLookupData::default();
    };
    if !resp.status().is_success() {
        return GeoLookupData::default();
    }
    let Ok(bytes) = resp.bytes().await else {
        return GeoLookupData::default();
    };
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return GeoLookupData::default();
    };
    if val.get("success").and_then(|v| v.as_bool()) != Some(true) {
        return GeoLookupData::default();
    }

    let conn = val.get("connection");
    let asn = conn
        .and_then(|c| c.get("asn"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let as_org = conn
        .and_then(|c| c.get("org").or_else(|| c.get("isp")))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let isp = conn
        .and_then(|c| c.get("isp"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    GeoLookupData {
        asn,
        as_org,
        country: val
            .get("country")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        country_code: val
            .get("country_code")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        region: val
            .get("region")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        city: val
            .get("city")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty()),
        isp,
    }
}

pub fn parse_cloudflare_rpki_json(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let val: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let state = val
        .get("validated_route")
        .and_then(|vr| vr.get("validity"))
        .and_then(|v| v.get("state"))
        .or_else(|| val.get("state"))
        .and_then(|s| s.as_str())?
        .to_ascii_lowercase();
    let desc = val
        .get("validated_route")
        .and_then(|vr| vr.get("validity"))
        .and_then(|v| v.get("description"))
        .or_else(|| val.get("description"))
        .and_then(|s| s.as_str())
        .map(|s| s.to_string());

    let normalized = match state.as_str() {
        "valid" => "valid",
        "invalid" | "invalid_asn" | "invalid_length" => "invalid",
        "unknown" | "not_found" => "not_found",
        _ => "unknown",
    };
    Some((normalized.to_string(), desc))
}

pub fn parse_ripestat_rpki_json(bytes: &[u8]) -> Option<(String, Option<String>)> {
    let val: serde_json::Value = serde_json::from_slice(bytes).ok()?;
    let status = val
        .get("data")
        .and_then(|d| d.get("status"))
        .and_then(|s| s.as_str())?
        .to_ascii_lowercase();
    let normalized = match status.as_str() {
        "valid" => "valid",
        "invalid" | "invalid_asn" | "invalid_length" => "invalid",
        "unknown" => "not_found",
        _ => "unknown",
    };
    let detail = match normalized {
        "valid" => Some("BGP origin ASN matches a valid RPKI ROA".to_string()),
        "invalid" => Some("RPKI ROA mismatch (invalid origin ASN or prefix length)".to_string()),
        "not_found" => Some("No RPKI ROA published for this ASN/prefix".to_string()),
        _ => None,
    };
    Some((normalized.to_string(), detail))
}

pub(crate) async fn lookup_rpki(
    client: &reqwest::Client,
    asn: Option<u32>,
    cidr: Option<&str>,
) -> (Option<String>, Option<String>) {
    let (Some(asn_num), Some(prefix)) = (asn, cidr) else {
        return (None, None);
    };

    let cf_url = format!("https://rpki.cloudflare.com/api/v1/validity/{asn_num}/{prefix}");
    if let Ok(Ok(resp)) = timeout(GEO_HTTP_TIMEOUT, client.get(&cf_url).send()).await {
        if resp.status().is_success() {
            if let Ok(bytes) = resp.bytes().await {
                if let Some((st, desc)) = parse_cloudflare_rpki_json(&bytes) {
                    return (Some(st), desc);
                }
            }
        }
    }

    let ripe_url = format!(
        "https://stat.ripe.net/data/rpki-validation/data.json?resource={asn_num}&prefix={prefix}"
    );
    if let Ok(Ok(resp)) = timeout(GEO_HTTP_TIMEOUT, client.get(&ripe_url).send()).await {
        if resp.status().is_success() {
            if let Ok(bytes) = resp.bytes().await {
                if let Some((st, desc)) = parse_ripestat_rpki_json(&bytes) {
                    return (Some(st), desc);
                }
            }
        }
    }

    (Some("unknown".to_string()), Some("RPKI validator unavailable".to_string()))
}

fn mx_target_from_value(val: &str) -> Option<String> {
    let mut parts = val.split_whitespace();
    let first = parts.next()?;
    let host = if first.chars().all(|c| c.is_ascii_digit()) {
        parts.next()?
    } else {
        first
    };
    let clean = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() || clean == "." {
        None
    } else {
        Some(clean)
    }
}

pub async fn inspect_network(domain: &str, resolvers: &[ResolverResult]) -> NetworkReport {
    let started = Instant::now();
    let mut collected: BTreeMap<IpAddr, CollectedIp> = BTreeMap::new();
    let mut mx_hosts: BTreeSet<String> = BTreeSet::new();

    for res in resolvers {
        if res.status != "ok" {
            continue;
        }
        for tr in &res.results {
            if tr.record_type == "A" || tr.record_type == "AAAA" {
                for rec in &tr.records {
                    if let Ok(ip) = rec.value.trim().parse::<IpAddr>() {
                        let entry = collected.entry(ip).or_insert_with(|| CollectedIp {
                            ip,
                            roles: BTreeSet::new(),
                            hostnames: BTreeSet::new(),
                        });
                        entry.roles.insert("Web / Apex".to_string());
                        entry.hostnames.insert(domain.to_string());
                    }
                }
            } else if tr.record_type == "MX" {
                for rec in &tr.records {
                    if let Some(mx) = mx_target_from_value(&rec.value) {
                        mx_hosts.insert(mx);
                    }
                }
            }
        }
    }

    let resolver_res = build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false));

    let Ok((_, _, dns_resolver)) = resolver_res else {
        return NetworkReport {
            status: "error".to_string(),
            latency_ms: started.elapsed().as_millis() as u64,
            ips: vec![],
            unique_asns: 0,
            countries: vec![],
            cdn_detected: None,
            error: Some("Unable to construct DNS resolver for reverse lookups.".to_string()),
        };
    };

    // Resolve up to 3 MX hostnames to include mail server IPs as well.
    let mx_futs = mx_hosts.into_iter().take(3).map(|mx| {
        let r = dns_resolver.clone();
        async move {
            let fqdn = format!("{mx}.");
            let mut ips = Vec::new();
            if let Ok(Ok(a)) = timeout(DNS_ENRICH_TIMEOUT, r.lookup(fqdn.clone(), RecordType::A)).await {
                for rec in a.iter() {
                    if let RData::A(v4) = rec {
                        ips.push(IpAddr::V4(Ipv4Addr::from(*v4)));
                    }
                }
            }
            if let Ok(Ok(aaaa)) = timeout(DNS_ENRICH_TIMEOUT, r.lookup(fqdn, RecordType::AAAA)).await {
                for rec in aaaa.iter() {
                    if let RData::AAAA(v6) = rec {
                        ips.push(IpAddr::V6(Ipv6Addr::from(*v6)));
                    }
                }
            }
            (mx, ips)
        }
    });

    for (mx, ips) in join_all(mx_futs).await {
        for ip in ips {
            let entry = collected.entry(ip).or_insert_with(|| CollectedIp {
                ip,
                roles: BTreeSet::new(),
                hostnames: BTreeSet::new(),
            });
            entry.roles.insert("Mail (MX)".to_string());
            entry.hostnames.insert(mx.clone());
        }
    }

    if collected.is_empty() {
        return NetworkReport {
            status: "unavailable".to_string(),
            latency_ms: started.elapsed().as_millis() as u64,
            ips: vec![],
            unique_asns: 0,
            countries: vec![],
            cdn_detected: None,
            error: Some("No A, AAAA, or MX IP addresses found for this domain.".to_string()),
        };
    }

    let client = reqwest::Client::builder()
        .timeout(GEO_HTTP_TIMEOUT)
        .user_agent("DomainTools/1.0")
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());

    let ip_list: Vec<CollectedIp> = collected.into_values().take(MAX_NETWORK_IPS).collect();
    let enrich_futs = ip_list.into_iter().map(|item| {
        let dns_r = dns_resolver.clone();
        let http = client.clone();
        async move {
            let (ptr_records, (cymru_asn, cymru_org, cidr, cymru_cc), geo) = tokio::join!(
                lookup_ptr(&dns_r, item.ip),
                lookup_cymru_asn(&dns_r, item.ip),
                lookup_geo_ipwho(&http, item.ip)
            );

            let asn = geo.asn.or(cymru_asn);
            let as_org = geo.as_org.or(cymru_org);
            let country_code = geo.country_code.or(cymru_cc);
            let (provider_type, provider_name, is_anycast_cdn) =
                classify_network_provider(as_org.as_deref(), &ptr_records, asn);
            let (rpki_status, rpki_detail) = lookup_rpki(&http, asn, cidr.as_deref()).await;

            IpNetworkInfo {
                ip: item.ip.to_string(),
                ip_version: if item.ip.is_ipv4() {
                    "IPv4".to_string()
                } else {
                    "IPv6".to_string()
                },
                roles: item.roles.into_iter().collect(),
                hostnames: item.hostnames.into_iter().collect(),
                ptr_records,
                asn,
                as_org,
                cidr,
                country: geo.country,
                country_code,
                region: geo.region,
                city: geo.city,
                isp: geo.isp,
                provider_type,
                provider_name,
                is_anycast_cdn,
                rpki_status,
                rpki_detail,
            }
        }
    });

    let ips = join_all(enrich_futs).await;

    let unique_asns: BTreeSet<u32> = ips.iter().filter_map(|i| i.asn).collect();
    let countries: Vec<String> = ips
        .iter()
        .filter_map(|i| i.country.clone().or_else(|| i.country_code.clone()))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let cdn_detected = ips
        .iter()
        .find(|i| i.roles.iter().any(|r| r.contains("Web")) && i.is_anycast_cdn)
        .and_then(|i| i.provider_name.clone());

    NetworkReport {
        status: "ok".to_string(),
        latency_ms: started.elapsed().as_millis() as u64,
        ips,
        unique_asns: unique_asns.len(),
        countries,
        cdn_detected,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_ipv6_nibbles() {
        let ip: Ipv6Addr = "2001:4860:4860::8888".parse().unwrap();
        let rev = reverse_ipv6_nibbles(ip);
        assert!(rev.starts_with("8.8.8.8.0.0.0.0."));
        assert!(rev.ends_with(".0.6.8.4.0.6.8.4.1.0.0.2"));
    }

    #[test]
    fn test_parse_cymru_txts() {
        let origin = "13335 | 104.16.0.0/14 | US | arin | 2014-03-28";
        let (asn, cidr, cc) = parse_cymru_origin_txt(origin).unwrap();
        assert_eq!(asn, 13335);
        assert_eq!(cidr.as_deref(), Some("104.16.0.0/14"));
        assert_eq!(cc.as_deref(), Some("US"));

        let asn_line = "13335 | US | arin | 2010-07-14 | CLOUDFLARENET, US";
        assert_eq!(
            parse_cymru_asn_txt(asn_line).as_deref(),
            Some("CLOUDFLARENET, US")
        );
    }

    #[test]
    fn test_classify_network_provider() {
        let (kind, name, cdn) =
            classify_network_provider(Some("CLOUDFLARENET"), &[], Some(13335));
        assert_eq!(kind, "CDN / Anycast");
        assert_eq!(name.as_deref(), Some("Cloudflare"));
        assert!(cdn);

        let (kind2, name2, cdn2) =
            classify_network_provider(Some("Amazon.com, Inc."), &[], Some(16509));
        assert_eq!(kind2, "Cloud / Hosting");
        assert_eq!(name2.as_deref(), Some("Amazon AWS"));
        assert!(!cdn2);
    }

    #[test]
    fn test_parse_rpki_responses() {
        let cf = br#"{"validated_route":{"validity":{"state":"valid","description":"Matches ROA"}}}"#;
        let (st, desc) = parse_cloudflare_rpki_json(cf).unwrap();
        assert_eq!(st, "valid");
        assert_eq!(desc.as_deref(), Some("Matches ROA"));

        let ripe = br#"{"data":{"status":"unknown"}}"#;
        let (st2, _) = parse_ripestat_rpki_json(ripe).unwrap();
        assert_eq!(st2, "not_found");
    }
}
