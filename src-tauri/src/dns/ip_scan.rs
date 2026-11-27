use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use chrono::Utc;
use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use serde_json::Value;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::dns::health::{build_dnsbl_resolver, query_dnsbl_entry, reverse_ipv4, IP_BLACKLISTS};
use crate::dns::network::{
    classify_network_provider, lookup_cymru_asn, lookup_ptr, lookup_rpki, reverse_ipv6_nibbles,
};
use crate::dns::ports::scan_ip_with_ports;
use crate::dns::tls::inspect_ip_tls;
use crate::dns::{build_resolver, txt_to_string};
use crate::models::{
    HttpHeaderItem, IpAddressMeta, IpAssociatedHost, IpBgpInfo, IpDeepScanReport, IpGeoInfo,
    IpHttpProbe, IpInternetDbInfo, IpPtrEntry, IpRdapInfo, IpReachabilityInfo, IpReputationInfo,
    IpRiskFinding, PortScanReport, QueryProgressEvent, SecurityHeaderStatus,
};

const HTTP_PROBE_TIMEOUT: Duration = Duration::from_secs(4);
const META_HTTP_TIMEOUT: Duration = Duration::from_millis(3500);
const RDAP_HTTP_TIMEOUT: Duration = Duration::from_secs(4);
const DNS_PROBE_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_HTTP_BODY_BYTES: usize = 64 * 1024;
const MAX_REVERSE_IP_HOSTS: usize = 50;

const EXTRA_IP_BLACKLISTS: &[(&str, &str)] = &[
    ("Barracuda BRBL", "b.barracudacentral.org"),
    ("Mailspike BL", "bl.mailspike.net"),
    ("SORBS DNSBL", "dnsbl.sorbs.net"),
    ("S5H All", "all.s5h.net"),
];

const DEEP_SCAN_PORTS: &[u16] = &[
    21, 22, 23, 25, 53, 80, 110, 139, 143, 389, 443, 445, 465, 587, 636, 993, 995, 1433, 2082,
    2083, 2086, 2087, 2222, 2375, 2376, 3306, 3389, 5432, 5900, 5985, 5986, 6379, 6443, 8000,
    8080, 8443, 8888, 9090, 9200, 11211, 27017,
];

fn emit_stage<F>(cb: &F, stage: &str, label: &str, status: &str, elapsed_ms: Option<u64>)
where
    F: Fn(QueryProgressEvent),
{
    cb(QueryProgressEvent {
        stage: stage.to_string(),
        label: label.to_string(),
        status: status.to_string(),
        elapsed_ms,
    });
}

pub fn parse_ip_target(raw: &str) -> Result<IpAddr, String> {
    let mut s = raw.trim().to_string();
    if s.is_empty() {
        return Err("Please enter an IPv4 or IPv6 address.".to_string());
    }

    if let Some(rest) = s.strip_prefix("https://").or_else(|| s.strip_prefix("http://")) {
        s = rest.to_string();
    }
    if let Some(idx) = s.find(['/', '?', '#']) {
        s.truncate(idx);
    }
    if let Some(at_idx) = s.rfind('@') {
        s = s[at_idx + 1..].to_string();
    }

    // Handle bracketed IPv6 e.g. [::1] or [::1]:443
    if s.starts_with('[') {
        if let Some(end_bracket) = s.find(']') {
            let inner = &s[1..end_bracket];
            if let Ok(ip) = inner.parse::<IpAddr>() {
                return Ok(ip);
            }
        }
    }

    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok(ip);
    }

    // Handle IPv4:port or SocketAddr
    if let Ok(sock) = s.parse::<SocketAddr>() {
        return Ok(sock.ip());
    }

    Err(format!(
        "Invalid IP address '{raw}'. Enter a valid IPv4 or IPv6 address (e.g. 1.1.1.1 or 2606:4700:4700::1111)."
    ))
}

fn expand_ipv6(ip: Ipv6Addr) -> String {
    ip.segments()
        .iter()
        .map(|seg| format!("{seg:04x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn classify_ip_meta(ip: IpAddr) -> IpAddressMeta {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            let int_val = u32::from_be_bytes(octets);
            let is_loopback = v4.is_loopback();
            let is_multicast = v4.is_multicast();
            let is_private_rfc1918 = v4.is_private();
            let is_cgnat = octets[0] == 100 && (64..=127).contains(&octets[1]);
            let is_link_local = v4.is_link_local();
            let is_doc = (octets[0] == 192 && octets[1] == 0 && octets[2] == 2)
                || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100)
                || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113);
            let is_unspecified = v4.is_unspecified();
            let is_broadcast = v4.is_broadcast();
            let is_benchmark = octets[0] == 198 && (octets[1] == 18 || octets[1] == 19);
            let is_reserved = is_unspecified
                || is_broadcast
                || is_benchmark
                || octets[0] >= 240
                || octets[0] == 0;

            let scope = if is_loopback {
                "Loopback (127.0.0.0/8)"
            } else if is_private_rfc1918 {
                "Private (RFC 1918)"
            } else if is_cgnat {
                "Shared / CGNAT (RFC 6598)"
            } else if is_link_local {
                "Link-Local (169.254.0.0/16)"
            } else if is_doc {
                "Documentation (TEST-NET)"
            } else if is_multicast {
                "Multicast (224.0.0.0/4)"
            } else if is_benchmark {
                "Benchmarking (RFC 2544)"
            } else if is_reserved {
                "Reserved / Special"
            } else {
                "Public Unicast"
            };

            let is_public = scope == "Public Unicast";
            let is_private = is_private_rfc1918 || is_cgnat || is_link_local;

            IpAddressMeta {
                ip: v4.to_string(),
                ip_version: "IPv4".to_string(),
                normalized: v4.to_string(),
                expanded: None,
                hex: format!("0x{int_val:08x}"),
                integer: int_val.to_string(),
                binary: Some(
                    octets
                        .iter()
                        .map(|b| format!("{b:08b}"))
                        .collect::<Vec<_>>()
                        .join("."),
                ),
                scope: scope.to_string(),
                is_public,
                is_private,
                is_loopback,
                is_multicast,
                reverse_ptr_zone: format!("{}.in-addr.arpa", reverse_ipv4(v4)),
            }
        }
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let int_val = u128::from_be_bytes(octets);
            let segs = v6.segments();
            let is_loopback = v6.is_loopback();
            let is_multicast = v6.is_multicast();
            let is_ula = (segs[0] & 0xfe00) == 0xfc00;
            let is_link_local = (segs[0] & 0xffc0) == 0xfe80;
            let is_doc = segs[0] == 0x2001 && segs[1] == 0x0db8;
            let is_unspecified = v6.is_unspecified();
            let is_v4_mapped = v6.to_ipv4_mapped().is_some();
            let is_global_unicast = (segs[0] & 0xe000) == 0x2000 && !is_doc;

            let scope = if is_loopback {
                "Loopback (::1)"
            } else if is_unspecified {
                "Unspecified (::)"
            } else if is_ula {
                "Unique Local (RFC 4193)"
            } else if is_link_local {
                "Link-Local (fe80::/10)"
            } else if is_doc {
                "Documentation (2001:db8::/32)"
            } else if is_multicast {
                "Multicast (ff00::/8)"
            } else if is_v4_mapped {
                "IPv4-Mapped IPv6"
            } else if is_global_unicast {
                "Public Unicast"
            } else {
                "Reserved / Special"
            };

            let is_public = scope == "Public Unicast";
            let is_private = is_ula || is_link_local;

            IpAddressMeta {
                ip: v6.to_string(),
                ip_version: "IPv6".to_string(),
                normalized: v6.to_string(),
                expanded: Some(expand_ipv6(v6)),
                hex: format!("0x{int_val:032x}"),
                integer: int_val.to_string(),
                binary: None,
                scope: scope.to_string(),
                is_public,
                is_private,
                is_loopback,
                is_multicast,
                reverse_ptr_zone: format!("{}.ip6.arpa", reverse_ipv6_nibbles(v6)),
            }
        }
    }
}

fn classify_ptr_pattern(ptr: &str) -> Option<String> {
    let low = ptr.to_ascii_lowercase();
    if low.contains("1e100.net")
        || low.contains("cloudflare")
        || low.contains("fastly")
        || low.contains("akamaitechnologies")
        || low.contains("cloudfront.net")
    {
        Some("CDN / Edge".to_string())
    } else if low.contains("amazonaws.com")
        || low.contains("googleusercontent.com")
        || low.contains("azure")
        || low.contains("digitalocean")
        || low.contains("linode")
        || low.contains("hetzner")
        || low.contains("ovh")
        || low.contains("vultr")
    {
        Some("Cloud / Compute".to_string())
    } else if low.contains("dynamic")
        || low.contains("dhcp")
        || low.contains("pool")
        || low.contains("cpe.")
        || low.contains("dsl")
        || low.contains("cable")
        || low.contains("res.")
        || low.contains("residential")
    {
        Some("Residential / Dynamic ISP".to_string())
    } else {
        None
    }
}

async fn resolve_ptr_entries(resolver: &TokioResolver, ip: IpAddr) -> Vec<IpPtrEntry> {
    let ptrs = lookup_ptr(resolver, ip).await;
    if ptrs.is_empty() {
        return vec![];
    }

    let rtype = if ip.is_ipv4() {
        RecordType::A
    } else {
        RecordType::AAAA
    };

    let futs = ptrs.into_iter().map(|hostname| {
        let r = resolver.clone();
        async move {
            let fqdn = format!("{hostname}.");
            let mut forward_ips = Vec::new();
            let mut matched = false;
            if let Ok(Ok(lookup)) = timeout(DNS_PROBE_TIMEOUT, r.lookup(fqdn, rtype)).await {
                for rec in lookup.record_iter() {
                    match rec.data() {
                        RData::A(a) => {
                            let cand = IpAddr::V4(a.0);
                            if cand == ip {
                                matched = true;
                            }
                            forward_ips.push(cand.to_string());
                        }
                        RData::AAAA(aaaa) => {
                            let cand = IpAddr::V6(aaaa.0);
                            if cand == ip {
                                matched = true;
                            }
                            forward_ips.push(cand.to_string());
                        }
                        _ => {}
                    }
                }
            }
            let generic_pattern = classify_ptr_pattern(&hostname);
            IpPtrEntry {
                hostname,
                forward_ips,
                fcrdns_valid: matched,
                generic_pattern,
            }
        }
    });

    join_all(futs).await
}

fn parse_cymru_full_origin(raw: &str) -> (Option<String>, Option<String>) {
    // "13335 | 104.16.0.0/14 | US | arin | 2014-03-28"
    let cols: Vec<&str> = raw.split('|').map(|s| s.trim()).collect();
    let rir = cols
        .get(3)
        .map(|s| s.to_ascii_uppercase())
        .filter(|s| !s.is_empty());
    let allocated = cols
        .get(4)
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    (rir, allocated)
}

pub fn parse_ripestat_prefix_overview(bytes: &[u8]) -> (Option<String>, Option<bool>, Option<u32>, Option<String>) {
    let Ok(val) = serde_json::from_slice::<Value>(bytes) else {
        return (None, None, None, None);
    };
    let Some(data) = val.get("data") else {
        return (None, None, None, None);
    };
    let resource = data
        .get("resource")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let announced = data.get("announced").and_then(|v| v.as_bool());
    let first_asn = data
        .get("asns")
        .and_then(|a| a.as_array())
        .and_then(|arr| arr.first());
    let asn = first_asn
        .and_then(|a| a.get("asn"))
        .and_then(|v| v.as_u64())
        .map(|n| n as u32);
    let holder = first_asn
        .and_then(|a| a.get("holder"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    (resource, announced, asn, holder)
}

pub fn parse_ripestat_asn_neighbours(bytes: &[u8]) -> (Option<usize>, Option<usize>, Option<usize>) {
    let Ok(val) = serde_json::from_slice::<Value>(bytes) else {
        return (None, None, None);
    };
    let Some(counts) = val.get("data").and_then(|d| d.get("neighbour_counts")) else {
        return (None, None, None);
    };
    let left = counts.get("left").and_then(|v| v.as_u64()).map(|n| n as usize);
    let right = counts.get("right").and_then(|v| v.as_u64()).map(|n| n as usize);
    let uncertain = counts
        .get("uncertain")
        .and_then(|v| v.as_u64())
        .map(|n| n as usize);
    (left, right, uncertain)
}

async fn fetch_bgp_info(
    dns_resolver: &TokioResolver,
    http: &reqwest::Client,
    ip: IpAddr,
    ptrs: &[String],
    is_public: bool,
) -> IpBgpInfo {
    if !is_public {
        return IpBgpInfo {
            asn: None,
            as_org: None,
            as_holder: None,
            prefix: None,
            rir: None,
            allocated_date: None,
            country_code: None,
            provider_type: "Private / Special".to_string(),
            provider_name: None,
            is_anycast_cdn: false,
            rpki_status: None,
            rpki_detail: None,
            announced: Some(false),
            neighbors_left: None,
            neighbors_right: None,
            neighbors_uncertain: None,
            related_prefixes: vec![],
        };
    }

    let origin_fqdn = match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            format!("{d}.{c}.{b}.{a}.origin.asn.cymru.com.")
        }
        IpAddr::V6(v6) => format!("{}.origin6.asn.cymru.com.", reverse_ipv6_nibbles(v6)),
    };

    let cymru_origin_raw_fut = async {
        if let Ok(Ok(lookup)) =
            timeout(DNS_PROBE_TIMEOUT, dns_resolver.lookup(origin_fqdn, RecordType::TXT)).await
        {
            for r in lookup.iter() {
                if let RData::TXT(txt) = r {
                    let s = txt_to_string(txt);
                    if !s.trim().is_empty() {
                        return Some(s);
                    }
                }
            }
        }
        None
    };

    let ripe_prefix_url = format!(
        "https://stat.ripe.net/data/prefix-overview/data.json?resource={ip}"
    );
    let ripe_prefix_fut = async {
        if let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&ripe_prefix_url).send()).await {
            if resp.status().is_success() {
                if let Ok(bytes) = resp.bytes().await {
                    return parse_ripestat_prefix_overview(&bytes);
                }
            }
        }
        (None, None, None, None)
    };

    let ((cymru_asn, cymru_org, cymru_cidr, cymru_cc), cymru_raw, (ripe_prefix, announced, ripe_asn, as_holder)) =
        tokio::join!(
            lookup_cymru_asn(dns_resolver, ip),
            cymru_origin_raw_fut,
            ripe_prefix_fut
        );

    let (rir, allocated_date) = cymru_raw
        .as_deref()
        .map(parse_cymru_full_origin)
        .unwrap_or((None, None));

    let asn = cymru_asn.or(ripe_asn);
    let prefix = cymru_cidr.or(ripe_prefix);
    let as_org = cymru_org.or_else(|| as_holder.clone());

    let ((rpki_status, rpki_detail), (neighbors_left, neighbors_right, neighbors_uncertain), related_prefixes) =
        if let Some(asn_num) = asn {
            let neigh_url = format!(
                "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS{asn_num}"
            );
            let prefixes_url = format!(
                "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS{asn_num}"
            );
            let neigh_fut = async {
                if let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&neigh_url).send()).await {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            return parse_ripestat_asn_neighbours(&bytes);
                        }
                    }
                }
                (None, None, None)
            };
            let prefixes_fut = async {
                let mut out = Vec::new();
                if let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&prefixes_url).send()).await {
                    if resp.status().is_success() {
                        if let Ok(bytes) = resp.bytes().await {
                            if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                                if let Some(arr) = val
                                    .get("data")
                                    .and_then(|d| d.get("prefixes"))
                                    .and_then(|p| p.as_array())
                                {
                                    for item in arr.iter().take(12) {
                                        if let Some(pfx) = item.get("prefix").and_then(|v| v.as_str()) {
                                            out.push(pfx.to_string());
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                out
            };
            tokio::join!(
                lookup_rpki(http, Some(asn_num), prefix.as_deref()),
                neigh_fut,
                prefixes_fut
            )
        } else {
            ((None, None), (None, None, None), vec![])
        };

    let (provider_type, provider_name, is_anycast_cdn) =
        classify_network_provider(as_org.as_deref(), ptrs, asn);

    IpBgpInfo {
        asn,
        as_org,
        as_holder,
        prefix,
        rir,
        allocated_date,
        country_code: cymru_cc,
        provider_type,
        provider_name,
        is_anycast_cdn,
        rpki_status,
        rpki_detail,
        announced,
        neighbors_left,
        neighbors_right,
        neighbors_uncertain,
        related_prefixes,
    }
}

fn extract_vcard_contacts(
    entities: &[Value],
    org_name: &mut Option<String>,
    abuse_email: &mut Option<String>,
    abuse_phone: &mut Option<String>,
    tech_email: &mut Option<String>,
) {
    for ent in entities {
        let roles: Vec<String> = ent
            .get("roles")
            .and_then(|r| r.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_ascii_lowercase())
                    .collect()
            })
            .unwrap_or_default();

        let is_abuse = roles.iter().any(|r| r == "abuse");
        let is_tech = roles.iter().any(|r| r == "technical" || r == "noc" || r == "administrative");
        let is_registrant = roles.iter().any(|r| r == "registrant");

        if let Some(vcard_items) = ent
            .get("vcardArray")
            .and_then(|v| v.as_array())
            .and_then(|a| a.get(1))
            .and_then(|b| b.as_array())
        {
            for prop in vcard_items {
                let Some(arr) = prop.as_array() else {
                    continue;
                };
                let prop_name = arr
                    .first()
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                let val = arr.get(3).and_then(|v| v.as_str()).map(str::trim).unwrap_or("");
                if val.is_empty() {
                    continue;
                }
                match prop_name.as_str() {
                    "fn" if org_name.is_none() || is_registrant => {
                        *org_name = Some(val.to_string());
                    }
                    "email" => {
                        if is_abuse && abuse_email.is_none() {
                            *abuse_email = Some(val.to_string());
                        } else if is_tech && tech_email.is_none() {
                            *tech_email = Some(val.to_string());
                        }
                    }
                    "tel" => {
                        let cleaned = val.strip_prefix("tel:").unwrap_or(val).trim();
                        if is_abuse && abuse_phone.is_none() && !cleaned.is_empty() {
                            *abuse_phone = Some(cleaned.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        if let Some(nested) = ent.get("entities").and_then(|e| e.as_array()) {
            extract_vcard_contacts(nested, org_name, abuse_email, abuse_phone, tech_email);
        }
    }
}

pub fn parse_rdap_ip_json(bytes: &[u8], server: Option<String>) -> Result<IpRdapInfo, String> {
    let val: Value = serde_json::from_slice(bytes).map_err(|e| format!("Invalid RDAP JSON: {e}"))?;

    let handle = val
        .get("handle")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let net_name = val
        .get("name")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let net_type = val
        .get("type")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let parent_handle = val
        .get("parentHandle")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let start_address = val
        .get("startAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let end_address = val
        .get("endAddress")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());
    let country = val
        .get("country")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty());

    let mut cidrs = Vec::new();
    if let Some(arr) = val.get("cidr0_cidrs").and_then(|v| v.as_array()) {
        for item in arr {
            if let (Some(pfx), Some(len)) = (
                item.get("v4prefix")
                    .or_else(|| item.get("v6prefix"))
                    .and_then(|v| v.as_str()),
                item.get("length").and_then(|v| v.as_u64()),
            ) {
                cidrs.push(format!("{pfx}/{len}"));
            }
        }
    }

    let statuses: Vec<String> = val
        .get("status")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|s| s.as_str())
                .map(|s| s.to_string())
                .collect()
        })
        .unwrap_or_default();

    let mut registered_date = None;
    let mut last_changed_date = None;
    if let Some(events) = val.get("events").and_then(|v| v.as_array()) {
        for ev in events {
            let action = ev
                .get("eventAction")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_ascii_lowercase();
            let date = ev
                .get("eventDate")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            if action == "registration" && registered_date.is_none() {
                registered_date = date;
            } else if action == "last changed" && last_changed_date.is_none() {
                last_changed_date = date;
            }
        }
    }

    let mut remarks = Vec::new();
    if let Some(arr) = val.get("remarks").and_then(|v| v.as_array()) {
        for r in arr.iter().take(4) {
            if let Some(desc_arr) = r.get("description").and_then(|v| v.as_array()) {
                let joined: Vec<&str> = desc_arr.iter().filter_map(|v| v.as_str()).collect();
                if !joined.is_empty() {
                    remarks.push(joined.join(" "));
                }
            }
        }
    }

    let mut org_name = None;
    let mut abuse_email = None;
    let mut abuse_phone = None;
    let mut tech_email = None;
    if let Some(entities) = val.get("entities").and_then(|v| v.as_array()) {
        extract_vcard_contacts(
            entities,
            &mut org_name,
            &mut abuse_email,
            &mut abuse_phone,
            &mut tech_email,
        );
    }

    Ok(IpRdapInfo {
        status: "ok".to_string(),
        rdap_server: server,
        handle,
        net_name,
        net_type,
        parent_handle,
        start_address,
        end_address,
        cidrs,
        country,
        org_name,
        abuse_email,
        abuse_phone,
        tech_email,
        registered_date,
        last_changed_date,
        statuses,
        remarks,
        error: None,
    })
}

async fn fetch_rdap_info(http: &reqwest::Client, ip: IpAddr, is_public: bool) -> IpRdapInfo {
    if !is_public {
        return IpRdapInfo {
            status: "skipped".to_string(),
            rdap_server: None,
            handle: None,
            net_name: None,
            net_type: None,
            parent_handle: None,
            start_address: None,
            end_address: None,
            cidrs: vec![],
            country: None,
            org_name: None,
            abuse_email: None,
            abuse_phone: None,
            tech_email: None,
            registered_date: None,
            last_changed_date: None,
            statuses: vec![],
            remarks: vec![],
            error: Some("Skipped RDAP lookup for non-public IP address.".to_string()),
        };
    }

    let candidates = [
        format!("https://rdap.arin.net/registry/ip/{ip}"),
        format!("https://rdap.apnic.net/ip/{ip}"),
    ];

    let mut last_err = None;
    for url in candidates {
        match timeout(RDAP_HTTP_TIMEOUT, http.get(&url).send()).await {
            Ok(Ok(resp)) => {
                let final_host = resp.url().host_str().map(|s| s.to_string());
                let code = resp.status();
                if code.as_u16() == 404 {
                    last_err = Some("IP allocation not found in RDAP".to_string());
                    continue;
                }
                if !code.is_success() {
                    last_err = Some(format!("RDAP returned HTTP {}", code.as_u16()));
                    continue;
                }
                if let Ok(bytes) = resp.bytes().await {
                    match parse_rdap_ip_json(&bytes, final_host) {
                        Ok(info) => return info,
                        Err(e) => last_err = Some(e),
                    }
                }
            }
            Ok(Err(e)) => last_err = Some(e.to_string()),
            Err(_) => last_err = Some("RDAP request timed out".to_string()),
        }
    }

    IpRdapInfo {
        status: if last_err
            .as_deref()
            .is_some_and(|e| e.to_ascii_lowercase().contains("not found"))
        {
            "not_found".to_string()
        } else {
            "error".to_string()
        },
        rdap_server: None,
        handle: None,
        net_name: None,
        net_type: None,
        parent_handle: None,
        start_address: None,
        end_address: None,
        cidrs: vec![],
        country: None,
        org_name: None,
        abuse_email: None,
        abuse_phone: None,
        tech_email: None,
        registered_date: None,
        last_changed_date: None,
        statuses: vec![],
        remarks: vec![],
        error: last_err,
    }
}

async fn fetch_geo_info(http: &reqwest::Client, ip: IpAddr, is_public: bool) -> IpGeoInfo {
    if !is_public {
        return IpGeoInfo {
            country: None,
            country_code: None,
            continent: None,
            region: None,
            city: None,
            postal: None,
            latitude: None,
            longitude: None,
            timezone: None,
            utc_offset: None,
            isp: None,
            org: None,
            domain: None,
            is_mobile: None,
            is_proxy_or_vpn: None,
            is_hosting: None,
            source: None,
        };
    }

    let url = format!("https://ipwho.is/{ip}");
    if let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&url).send()).await {
        if resp.status().is_success() {
            if let Ok(bytes) = resp.bytes().await {
                if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                    if val.get("success").and_then(|v| v.as_bool()) == Some(true) {
                        let conn = val.get("connection");
                        let tz = val.get("timezone");
                        let str_at = |obj: Option<&Value>, key: &str| -> Option<String> {
                            obj.and_then(|o| o.get(key))
                                .and_then(|v| v.as_str())
                                .map(|s| s.trim().to_string())
                                .filter(|s| !s.is_empty())
                        };
                        return IpGeoInfo {
                            country: str_at(Some(&val), "country"),
                            country_code: str_at(Some(&val), "country_code"),
                            continent: str_at(Some(&val), "continent"),
                            region: str_at(Some(&val), "region"),
                            city: str_at(Some(&val), "city"),
                            postal: str_at(Some(&val), "postal"),
                            latitude: val.get("latitude").and_then(|v| v.as_f64()),
                            longitude: val.get("longitude").and_then(|v| v.as_f64()),
                            timezone: str_at(tz, "id"),
                            utc_offset: str_at(tz, "utc"),
                            isp: str_at(conn, "isp"),
                            org: str_at(conn, "org"),
                            domain: str_at(conn, "domain"),
                            is_mobile: None,
                            is_proxy_or_vpn: None,
                            is_hosting: None,
                            source: Some("ipwho.is".to_string()),
                        };
                    }
                }
            }
        }
    }

    // Fallback to ipapi.co
    let fallback_url = format!("https://ipapi.co/{ip}/json/");
    if let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&fallback_url).send()).await {
        if resp.status().is_success() {
            if let Ok(bytes) = resp.bytes().await {
                if let Ok(val) = serde_json::from_slice::<Value>(&bytes) {
                    if val.get("error").and_then(|v| v.as_bool()) != Some(true) {
                        let s = |k: &str| -> Option<String> {
                            val.get(k)
                                .and_then(|v| v.as_str())
                                .map(|x| x.trim().to_string())
                                .filter(|x| !x.is_empty())
                        };
                        return IpGeoInfo {
                            country: s("country_name"),
                            country_code: s("country_code"),
                            continent: s("continent_code"),
                            region: s("region"),
                            city: s("city"),
                            postal: s("postal"),
                            latitude: val.get("latitude").and_then(|v| v.as_f64()),
                            longitude: val.get("longitude").and_then(|v| v.as_f64()),
                            timezone: s("timezone"),
                            utc_offset: s("utc_offset"),
                            isp: s("org"),
                            org: s("org"),
                            domain: None,
                            is_mobile: None,
                            is_proxy_or_vpn: None,
                            is_hosting: None,
                            source: Some("ipapi.co".to_string()),
                        };
                    }
                }
            }
        }
    }

    IpGeoInfo {
        country: None,
        country_code: None,
        continent: None,
        region: None,
        city: None,
        postal: None,
        latitude: None,
        longitude: None,
        timezone: None,
        utc_offset: None,
        isp: None,
        org: None,
        domain: None,
        is_mobile: None,
        is_proxy_or_vpn: None,
        is_hosting: None,
        source: None,
    }
}

pub fn parse_internetdb_json(bytes: &[u8]) -> Result<IpInternetDbInfo, String> {
    let val: Value =
        serde_json::from_slice(bytes).map_err(|e| format!("Invalid InternetDB JSON: {e}"))?;
    if let Some(detail) = val.get("detail").and_then(|v| v.as_str()) {
        if detail.to_ascii_lowercase().contains("no information") {
            return Ok(IpInternetDbInfo {
                indexed: false,
                ports: vec![],
                hostnames: vec![],
                cpes: vec![],
                tags: vec![],
                vulns: vec![],
                error: None,
            });
        }
    }

    let str_vec = |k: &str| -> Vec<String> {
        val.get(k)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str())
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect()
            })
            .unwrap_or_default()
    };

    let ports: Vec<u16> = val
        .get("ports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_u64())
                .filter_map(|p| u16::try_from(p).ok())
                .collect()
        })
        .unwrap_or_default();

    Ok(IpInternetDbInfo {
        indexed: true,
        ports,
        hostnames: str_vec("hostnames"),
        cpes: str_vec("cpes"),
        tags: str_vec("tags"),
        vulns: str_vec("vulns"),
        error: None,
    })
}

async fn fetch_internetdb(http: &reqwest::Client, ip: IpAddr) -> IpInternetDbInfo {
    let url = format!("https://internetdb.shodan.io/{ip}");
    match timeout(META_HTTP_TIMEOUT, http.get(&url).send()).await {
        Ok(Ok(resp)) => {
            if resp.status().as_u16() == 404 {
                return IpInternetDbInfo {
                    indexed: false,
                    ports: vec![],
                    hostnames: vec![],
                    cpes: vec![],
                    tags: vec![],
                    vulns: vec![],
                    error: None,
                };
            }
            if !resp.status().is_success() {
                return IpInternetDbInfo {
                    indexed: false,
                    ports: vec![],
                    hostnames: vec![],
                    cpes: vec![],
                    tags: vec![],
                    vulns: vec![],
                    error: Some(format!("InternetDB HTTP {}", resp.status().as_u16())),
                };
            }
            match resp.bytes().await {
                Ok(bytes) => parse_internetdb_json(&bytes).unwrap_or_else(|e| IpInternetDbInfo {
                    indexed: false,
                    ports: vec![],
                    hostnames: vec![],
                    cpes: vec![],
                    tags: vec![],
                    vulns: vec![],
                    error: Some(e),
                }),
                Err(e) => IpInternetDbInfo {
                    indexed: false,
                    ports: vec![],
                    hostnames: vec![],
                    cpes: vec![],
                    tags: vec![],
                    vulns: vec![],
                    error: Some(e.to_string()),
                },
            }
        }
        Ok(Err(e)) => IpInternetDbInfo {
            indexed: false,
            ports: vec![],
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
            error: Some(e.to_string()),
        },
        Err(_) => IpInternetDbInfo {
            indexed: false,
            ports: vec![],
            hostnames: vec![],
            cpes: vec![],
            tags: vec![],
            vulns: vec![],
            error: Some("InternetDB request timed out".to_string()),
        },
    }
}

async fn check_tor_exit(resolver: &TokioResolver, ip: Ipv4Addr) -> bool {
    let q = format!("{}.dnsel.torproject.org.", reverse_ipv4(ip));
    if let Ok(Ok(lookup)) = timeout(DNS_PROBE_TIMEOUT, resolver.lookup(&q, RecordType::A)).await {
        return lookup.record_iter().any(|r| {
            matches!(r.data(), RData::A(a) if a.0 == Ipv4Addr::new(127, 0, 0, 2))
        });
    }
    false
}

async fn fetch_reverse_ip_hosts(http: &reqwest::Client, ip: IpAddr) -> Vec<String> {
    let url = format!("https://api.hackertarget.com/reverseiplookup/?q={ip}");
    let Ok(Ok(resp)) = timeout(META_HTTP_TIMEOUT, http.get(&url).send()).await else {
        return vec![];
    };
    if !resp.status().is_success() {
        return vec![];
    }
    let Ok(bytes) = resp.bytes().await else {
        return vec![];
    };
    let slice = &bytes[..bytes.len().min(64 * 1024)];
    let text = String::from_utf8_lossy(slice);
    let mut hosts = BTreeSet::new();
    for line in text.lines() {
        let trimmed = line.trim().trim_end_matches('.').to_ascii_lowercase();
        if trimmed.is_empty()
            || trimmed.contains(' ')
            || trimmed.starts_with("error")
            || trimmed.starts_with("api count")
            || trimmed.starts_with("no dns")
            || !trimmed.contains('.')
        {
            continue;
        }
        if trimmed.parse::<IpAddr>().is_ok() {
            continue;
        }
        hosts.insert(trimmed);
        if hosts.len() >= MAX_REVERSE_IP_HOSTS {
            break;
        }
    }
    hosts.into_iter().collect()
}

async fn fetch_reputation(
    dns_resolver: &TokioResolver,
    http: &reqwest::Client,
    ip: IpAddr,
    is_public: bool,
) -> (IpReputationInfo, Vec<String>) {
    if !is_public {
        return (
            IpReputationInfo {
                status: "skipped".to_string(),
                is_tor_exit: false,
                blacklists_checked: 0,
                blacklists_listed: 0,
                blacklists_blocked: 0,
                blacklists: vec![],
                internetdb: None,
                signals: vec!["Reputation checks skipped for non-public IP.".to_string()],
            },
            vec![],
        );
    }

    let internetdb_fut = fetch_internetdb(http, ip);
    let reverse_ip_fut = fetch_reverse_ip_hosts(http, ip);

    let (blacklists, is_tor_exit, internetdb, reverse_hosts) = match ip {
        IpAddr::V4(v4) => {
            let rev = reverse_ipv4(v4);
            let ip_str = v4.to_string();
            let dnsbl_res = build_dnsbl_resolver().ok();
            let dnsbl_fut = async {
                let Some(resolver) = dnsbl_res else {
                    return Vec::new();
                };
                let futs = IP_BLACKLISTS
                    .iter()
                    .chain(EXTRA_IP_BLACKLISTS.iter())
                    .map(|(name, zone)| {
                        let q = format!("{rev}.{zone}.");
                        query_dnsbl_entry(
                            &resolver,
                            name,
                            zone,
                            ip_str.clone(),
                            "IP".to_string(),
                            q,
                        )
                    });
                join_all(futs).await
            };
            let tor_fut = check_tor_exit(dns_resolver, v4);
            tokio::join!(dnsbl_fut, tor_fut, internetdb_fut, reverse_ip_fut)
        }
        IpAddr::V6(_) => {
            let (idb, rev_hosts) = tokio::join!(internetdb_fut, reverse_ip_fut);
            (vec![], false, idb, rev_hosts)
        }
    };

    let blacklists_checked = blacklists.len();
    let blacklists_listed = blacklists.iter().filter(|b| b.status == "listed").count();
    let blacklists_blocked = blacklists.iter().filter(|b| b.status == "blocked").count();
    let has_policy = blacklists.iter().any(|b| b.status == "policy");

    let mut signals = Vec::new();
    if is_tor_exit {
        signals.push("Listed in Tor Project DNSEL as an active Tor exit node.".to_string());
    }
    if blacklists_listed > 0 {
        let names: Vec<&str> = blacklists
            .iter()
            .filter(|b| b.status == "listed")
            .map(|b| b.list_name.as_str())
            .collect();
        signals.push(format!("Listed on DNSBLs: {}", names.join(", ")));
    }
    if !internetdb.vulns.is_empty() {
        signals.push(format!(
            "Shodan InternetDB reports {} known CVE(s).",
            internetdb.vulns.len()
        ));
    }
    if !internetdb.tags.is_empty() {
        signals.push(format!("InternetDB tags: {}", internetdb.tags.join(", ")));
    }

    let status = if blacklists_listed > 0 || !internetdb.vulns.is_empty() {
        "listed".to_string()
    } else if is_tor_exit || has_policy {
        "caution".to_string()
    } else {
        "clean".to_string()
    };

    (
        IpReputationInfo {
            status,
            is_tor_exit,
            blacklists_checked,
            blacklists_listed,
            blacklists_blocked,
            blacklists,
            internetdb: Some(internetdb),
            signals,
        },
        reverse_hosts,
    )
}

fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start_tag = lower.find("<title")?;
    let after_gt = lower[start_tag..].find('>')? + start_tag + 1;
    let end_tag = lower[after_gt..].find("</title>")? + after_gt;
    let raw = html[after_gt..end_tag].split_whitespace().collect::<Vec<_>>().join(" ");
    let cleaned = raw
        .replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'");
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn build_ip_security_headers(headers: &[(String, String)]) -> Vec<SecurityHeaderStatus> {
    const CHECKS: &[&str] = &[
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "X-Frame-Options",
        "Referrer-Policy",
        "Permissions-Policy",
    ];
    CHECKS
        .iter()
        .map(|name| {
            let found = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.clone());
            SecurityHeaderStatus {
                name: (*name).to_string(),
                present: found.is_some(),
                value: found,
            }
        })
        .collect()
}

fn extract_waf_cdn_headers(headers: &[(String, String)]) -> Vec<String> {
    const MARKERS: &[(&str, &str)] = &[
        ("cf-ray", "Cloudflare (cf-ray)"),
        ("cf-cache-status", "Cloudflare Cache"),
        ("x-amz-cf-id", "AWS CloudFront"),
        ("x-amz-cf-pop", "AWS CloudFront POP"),
        ("x-fastly-request-id", "Fastly"),
        ("x-served-by", "CDN x-served-by"),
        ("x-vercel-id", "Vercel"),
        ("x-nf-request-id", "Netlify"),
        ("fly-request-id", "Fly.io"),
        ("x-sucuri-id", "Sucuri WAF"),
        ("x-iinfo", "Imperva / Incapsula"),
        ("x-azure-ref", "Azure Front Door"),
        ("x-cache", "Proxy / Cache"),
        ("via", "Proxy Via"),
    ];
    let mut found = Vec::new();
    for (hdr, label) in MARKERS {
        if let Some((_, val)) = headers.iter().find(|(k, _)| k.eq_ignore_ascii_case(hdr)) {
            let short_val: String = val.chars().take(48).collect();
            found.push(format!("{label}: {short_val}"));
        }
    }
    found
}

async fn probe_single_http(ip: IpAddr, scheme: &str) -> IpHttpProbe {
    let host_fmt = match ip {
        IpAddr::V4(v4) => v4.to_string(),
        IpAddr::V6(v6) => format!("[{v6}]"),
    };
    let url = format!("{scheme}://{host_fmt}/");
    let started = Instant::now();

    let client = match reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .danger_accept_invalid_certs(true)
        .timeout(HTTP_PROBE_TIMEOUT)
        .user_agent("DomainTools/0.4 (IP Deep Scan)")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return IpHttpProbe {
                scheme: scheme.to_string(),
                url,
                reachable: false,
                http_status: None,
                latency_ms: 0,
                server: None,
                powered_by: None,
                location: None,
                title: None,
                content_type: None,
                alt_svc: None,
                http3_supported: false,
                waf_or_cdn_headers: vec![],
                security_headers: vec![],
                headers: vec![],
                error: Some(e.to_string()),
            };
        }
    };

    match client.get(&url).send().await {
        Ok(mut resp) => {
            let latency_ms = started.elapsed().as_millis() as u64;
            let status_code = resp.status().as_u16();
            let mut raw_headers: Vec<(String, String)> = Vec::new();
            for (k, v) in resp.headers() {
                if let Ok(val) = v.to_str() {
                    raw_headers.push((k.as_str().to_string(), val.to_string()));
                }
            }
            let get_hdr = |name: &str| -> Option<String> {
                raw_headers
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
                    .map(|(_, v)| v.clone())
            };

            let server = get_hdr("server");
            let powered_by = get_hdr("x-powered-by");
            let location = get_hdr("location");
            let content_type = get_hdr("content-type");
            let alt_svc = get_hdr("alt-svc");
            let http3_supported = alt_svc
                .as_deref()
                .map(|a| a.to_ascii_lowercase().contains("h3"))
                .unwrap_or(false);

            let mut body_bytes = Vec::new();
            let is_text = content_type
                .as_deref()
                .map(|ct| {
                    let l = ct.to_ascii_lowercase();
                    l.contains("text/html") || l.contains("application/xhtml")
                })
                .unwrap_or(true);
            if is_text {
                while let Ok(Some(chunk)) = resp.chunk().await {
                    let rem = MAX_HTTP_BODY_BYTES.saturating_sub(body_bytes.len());
                    if rem == 0 {
                        break;
                    }
                    let take = chunk.len().min(rem);
                    body_bytes.extend_from_slice(&chunk[..take]);
                    if body_bytes.len() >= MAX_HTTP_BODY_BYTES {
                        break;
                    }
                }
            }
            let html = String::from_utf8_lossy(&body_bytes);
            let title = extract_html_title(&html);
            let security_headers = build_ip_security_headers(&raw_headers);
            let waf_or_cdn_headers = extract_waf_cdn_headers(&raw_headers);
            let headers = raw_headers
                .into_iter()
                .take(40)
                .map(|(name, value)| HttpHeaderItem { name, value })
                .collect();

            IpHttpProbe {
                scheme: scheme.to_string(),
                url,
                reachable: true,
                http_status: Some(status_code),
                latency_ms,
                server,
                powered_by,
                location,
                title,
                content_type,
                alt_svc,
                http3_supported,
                waf_or_cdn_headers,
                security_headers,
                headers,
                error: None,
            }
        }
        Err(e) => IpHttpProbe {
            scheme: scheme.to_string(),
            url,
            reachable: false,
            http_status: None,
            latency_ms: started.elapsed().as_millis() as u64,
            server: None,
            powered_by: None,
            location: None,
            title: None,
            content_type: None,
            alt_svc: None,
            http3_supported: false,
            waf_or_cdn_headers: vec![],
            security_headers: vec![],
            headers: vec![],
            error: Some(e.to_string()),
        },
    }
}

async fn measure_tcp_reachability(ip: IpAddr, ports: &PortScanReport) -> IpReachabilityInfo {
    let open_ports: Vec<u16> = ports
        .ports
        .iter()
        .filter(|p| p.status == "open")
        .map(|p| p.port)
        .collect();

    let preferred = [443u16, 80, 22, 53, 8443, 25, 587]
        .into_iter()
        .find(|p| open_ports.contains(p))
        .or_else(|| open_ports.first().copied());

    let Some(port) = preferred else {
        return IpReachabilityInfo {
            reachable: false,
            probe_port: None,
            samples_ms: vec![],
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            packet_loss_pct: 100,
        };
    };

    let sock = SocketAddr::new(ip, port);
    let mut samples_ms = Vec::new();
    let mut failed = 0u8;
    for _ in 0..3 {
        let t0 = Instant::now();
        match timeout(Duration::from_millis(1500), TcpStream::connect(sock)).await {
            Ok(Ok(_)) => {
                samples_ms.push(t0.elapsed().as_millis() as u64);
            }
            _ => {
                failed += 1;
            }
        }
    }

    let min_ms = samples_ms.iter().copied().min();
    let max_ms = samples_ms.iter().copied().max();
    let avg_ms = if samples_ms.is_empty() {
        None
    } else {
        Some(samples_ms.iter().sum::<u64>() / samples_ms.len() as u64)
    };
    let packet_loss_pct = ((failed as u16 * 100) / 3) as u8;

    IpReachabilityInfo {
        reachable: !samples_ms.is_empty(),
        probe_port: Some(port),
        samples_ms,
        min_ms,
        avg_ms,
        max_ms,
        packet_loss_pct,
    }
}

fn add_associated_host(
    map: &mut BTreeMap<String, BTreeSet<String>>,
    raw_host: &str,
    source: &str,
) {
    let clean = raw_host
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase();
    if clean.is_empty() || !clean.contains('.') || clean.parse::<IpAddr>().is_ok() {
        return;
    }
    map.entry(clean).or_default().insert(source.to_string());
}

fn extract_host_from_url(raw_url: &str) -> Option<String> {
    let rest = raw_url
        .trim()
        .strip_prefix("https://")
        .or_else(|| raw_url.trim().strip_prefix("http://"))?;
    let host_port = rest.split(['/', '?', '#']).next()?;
    let host = if host_port.starts_with('[') {
        return None;
    } else {
        host_port.split(':').next().unwrap_or("")
    };
    if host.is_empty() || host.parse::<IpAddr>().is_ok() {
        None
    } else {
        Some(host.to_string())
    }
}

pub fn synthesize_findings_and_posture(
    meta: &IpAddressMeta,
    bgp: &IpBgpInfo,
    reputation: &IpReputationInfo,
    ports: &PortScanReport,
    ptr_records: &[IpPtrEntry],
    fcrdns_overall: Option<bool>,
) -> (String, String, String, Vec<IpRiskFinding>) {
    let mut findings = Vec::new();

    if reputation.blacklists_listed > 0 {
        let zones: Vec<&str> = reputation
            .blacklists
            .iter()
            .filter(|b| b.status == "listed")
            .map(|b| b.list_name.as_str())
            .collect();
        findings.push(IpRiskFinding {
            severity: "high".to_string(),
            category: "Reputation".to_string(),
            title: format!("Listed on {} DNS blacklist(s)", reputation.blacklists_listed),
            detail: format!("Active listings: {}.", zones.join(", ")),
        });
    }

    if reputation.is_tor_exit {
        findings.push(IpRiskFinding {
            severity: "medium".to_string(),
            category: "Reputation".to_string(),
            title: "Active Tor Exit Node".to_string(),
            detail: "This IP is listed in the Tor Project DNSEL exit node directory.".to_string(),
        });
    }

    if let Some(idb) = &reputation.internetdb {
        if !idb.vulns.is_empty() {
            let preview: Vec<&str> = idb.vulns.iter().take(6).map(|s| s.as_str()).collect();
            findings.push(IpRiskFinding {
                severity: "high".to_string(),
                category: "Vulnerabilities".to_string(),
                title: format!("{} CVE(s) associated in InternetDB", idb.vulns.len()),
                detail: format!("Reported CVEs: {}.", preview.join(", ")),
            });
        }
    }

    if bgp.rpki_status.as_deref() == Some("invalid") {
        findings.push(IpRiskFinding {
            severity: "high".to_string(),
            category: "Routing".to_string(),
            title: "RPKI Route Origin Validation Invalid".to_string(),
            detail: bgp
                .rpki_detail
                .clone()
                .unwrap_or_else(|| "BGP origin ASN conflicts with published RPKI ROA.".to_string()),
        });
    }

    let high_risk_ports: Vec<&crate::models::PortScanItem> = ports
        .ports
        .iter()
        .filter(|p| p.status == "open" && p.risk_level == "high")
        .collect();
    if !high_risk_ports.is_empty() {
        let list: Vec<String> = high_risk_ports
            .iter()
            .map(|p| format!("{} ({})", p.port, p.service))
            .collect();
        findings.push(IpRiskFinding {
            severity: "critical".to_string(),
            category: "Exposure".to_string(),
            title: format!("{} high-risk service port(s) exposed", high_risk_ports.len()),
            detail: format!("Open high-risk ports: {}.", list.join(", ")),
        });
    }

    let caution_ports: Vec<&crate::models::PortScanItem> = ports
        .ports
        .iter()
        .filter(|p| p.status == "open" && p.risk_level == "caution")
        .collect();
    if !caution_ports.is_empty() {
        let list: Vec<String> = caution_ports
            .iter()
            .map(|p| format!("{} ({})", p.port, p.service))
            .collect();
        findings.push(IpRiskFinding {
            severity: "medium".to_string(),
            category: "Exposure".to_string(),
            title: format!("{} administrative / remote-access port(s) open", caution_ports.len()),
            detail: format!("Open management ports: {}.", list.join(", ")),
        });
    }

    let smtp_open = ports
        .ports
        .iter()
        .any(|p| p.status == "open" && matches!(p.port, 25 | 465 | 587));
    if smtp_open && fcrdns_overall == Some(false) {
        findings.push(IpRiskFinding {
            severity: "medium".to_string(),
            category: "DNS / Mail".to_string(),
            title: "SMTP open without valid FCrDNS".to_string(),
            detail: "Mail servers without matching forward-confirmed reverse DNS face spam filtering or rejection.".to_string(),
        });
    } else if meta.is_public && ptr_records.is_empty() {
        findings.push(IpRiskFinding {
            severity: "info".to_string(),
            category: "DNS".to_string(),
            title: "No PTR reverse DNS record".to_string(),
            detail: "This IP has no reverse PTR hostname configured.".to_string(),
        });
    }

    let has_critical_or_high = findings
        .iter()
        .any(|f| f.severity == "critical" || f.severity == "high");
    let has_medium = findings.iter().any(|f| f.severity == "medium");

    let posture = if has_critical_or_high {
        "elevated_risk"
    } else if has_medium {
        "caution"
    } else {
        "clean"
    };

    let exposure_risk = if !high_risk_ports.is_empty()
        || reputation.blacklists_listed > 0
        || reputation
            .internetdb
            .as_ref()
            .is_some_and(|i| !i.vulns.is_empty())
    {
        "high"
    } else if !caution_ports.is_empty() || reputation.is_tor_exit {
        "medium"
    } else {
        "low"
    };

    let summary = match posture {
        "elevated_risk" => format!(
            "Elevated risk detected for {} ({} open port(s), {} finding(s)).",
            meta.normalized,
            ports.open_count,
            findings.len()
        ),
        "caution" => format!(
            "{} scanned with caution signals ({} open port(s), {} finding(s)).",
            meta.normalized,
            ports.open_count,
            findings.len()
        ),
        _ => format!(
            "{} looks clean ({} open port(s), {} DNSBLs clean).",
            meta.normalized, ports.open_count, reputation.blacklists_checked
        ),
    };

    (
        posture.to_string(),
        exposure_risk.to_string(),
        summary,
        findings,
    )
}

pub async fn deep_scan_ip_with_progress<F>(
    raw_target: &str,
    custom_ports: Option<Vec<u16>>,
    on_progress: F,
) -> Result<IpDeepScanReport, String>
where
    F: Fn(QueryProgressEvent) + Send + Sync,
{
    let started = Instant::now();
    let ip = parse_ip_target(raw_target)?;
    let meta = classify_ip_meta(ip);

    let (_, _, dns_resolver) = build_resolver("cloudflare", None, false)
        .or_else(|_| build_resolver("google", None, false))?;
    let http = reqwest::Client::builder()
        .timeout(RDAP_HTTP_TIMEOUT)
        .user_agent("DomainTools/0.4 (IP Deep Scan)")
        .build()
        .map_err(|e| format!("Failed to create HTTP client: {e}"))?;

    // Stage 1: Meta & PTR + FCrDNS
    emit_stage(&on_progress, "meta", "Classification & PTR", "running", None);
    let t_meta = Instant::now();
    let ptr_records = resolve_ptr_entries(&dns_resolver, ip).await;
    let ptr_hostnames: Vec<String> = ptr_records.iter().map(|p| p.hostname.clone()).collect();
    let fcrdns_overall = if ptr_records.is_empty() {
        None
    } else {
        Some(ptr_records.iter().any(|p| p.fcrdns_valid))
    };
    emit_stage(
        &on_progress,
        "meta",
        "Classification & PTR",
        "done",
        Some(t_meta.elapsed().as_millis() as u64),
    );

    // Phase 1: Parallel BGP, RDAP, Geo, Reputation, Ports
    let (bgp, rdap, mut geo, (reputation, reverse_hosts), ports) = tokio::join!(
        async {
            let t0 = Instant::now();
            emit_stage(&on_progress, "bgp", "BGP / ASN / RPKI", "running", None);
            let out = fetch_bgp_info(&dns_resolver, &http, ip, &ptr_hostnames, meta.is_public).await;
            emit_stage(
                &on_progress,
                "bgp",
                "BGP / ASN / RPKI",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = Instant::now();
            emit_stage(&on_progress, "rdap", "RDAP / Registry", "running", None);
            let out = fetch_rdap_info(&http, ip, meta.is_public).await;
            emit_stage(
                &on_progress,
                "rdap",
                "RDAP / Registry",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = Instant::now();
            emit_stage(&on_progress, "geo", "Geolocation", "running", None);
            let out = fetch_geo_info(&http, ip, meta.is_public).await;
            emit_stage(
                &on_progress,
                "geo",
                "Geolocation",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = Instant::now();
            emit_stage(
                &on_progress,
                "reputation",
                "Reputation & Threat Intel",
                "running",
                None,
            );
            let out = fetch_reputation(&dns_resolver, &http, ip, meta.is_public).await;
            emit_stage(
                &on_progress,
                "reputation",
                "Reputation & Threat Intel",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        },
        async {
            let t0 = Instant::now();
            emit_stage(&on_progress, "ports", "Deep Port Scan", "running", None);
            let out = scan_ip_with_ports(
                meta.normalized.clone(),
                ip,
                vec![meta.normalized.clone()],
                DEEP_SCAN_PORTS,
                custom_ports,
            )
            .await;
            emit_stage(
                &on_progress,
                "ports",
                "Deep Port Scan",
                "done",
                Some(t0.elapsed().as_millis() as u64),
            );
            out
        }
    );

    // Enrich geo trait flags from BGP + InternetDB + Tor
    let idb_tags_lower: Vec<String> = reputation
        .internetdb
        .as_ref()
        .map(|i| i.tags.iter().map(|t| t.to_ascii_lowercase()).collect())
        .unwrap_or_default();
    geo.is_hosting = Some(
        bgp.is_anycast_cdn
            || bgp.provider_type == "Cloud / Hosting"
            || idb_tags_lower.iter().any(|t| t == "cloud" || t == "cdn"),
    );
    geo.is_proxy_or_vpn = Some(
        reputation.is_tor_exit
            || idb_tags_lower
                .iter()
                .any(|t| t == "vpn" || t == "proxy" || t == "tor"),
    );

    let port_status = |p: u16| -> Option<&str> {
        ports
            .ports
            .iter()
            .find(|item| item.port == p)
            .map(|item| item.status.as_str())
    };
    let is_open = |p: u16| port_status(p) == Some("open");

    // Phase 2: TLS & HTTP / Reachability probes based on discovered ports
    let ptr_sni = ptr_hostnames.first().map(|s| s.as_str());

    let tls_fut = async {
        let t0 = Instant::now();
        emit_stage(&on_progress, "tls", "TLS Certificates", "running", None);

        let mut tls_targets: Vec<(u16, Option<&'static str>)> = Vec::new();
        let candidates: &[(u16, Option<&'static str>)] = &[
            (443, None),
            (8443, None),
            (465, None),
            (993, None),
            (995, None),
            (636, None),
            (2083, None),
            (2087, None),
            (587, Some("smtp")),
            (25, Some("smtp")),
        ];
        for (p, mode) in candidates {
            if is_open(*p) {
                tls_targets.push((*p, *mode));
                if tls_targets.len() >= 3 {
                    break;
                }
            }
        }
        if tls_targets.is_empty() && !matches!(port_status(443), Some("closed" | "filtered")) {
            tls_targets.push((443, None));
        }

        let probe_futs = tls_targets.into_iter().map(|(port, stls)| async move {
            let first = inspect_ip_tls(ip, port, None, stls).await;
            if first.certificates.is_empty() {
                if let Some(sni) = ptr_sni {
                    let retry = inspect_ip_tls(ip, port, Some(sni), stls).await;
                    if !retry.certificates.is_empty() {
                        return retry;
                    }
                }
            }
            first
        });
        let out = join_all(probe_futs).await;

        emit_stage(
            &on_progress,
            "tls",
            "TLS Certificates",
            "done",
            Some(t0.elapsed().as_millis() as u64),
        );
        out
    };

    let http_reach_fut = async {
        let t0 = Instant::now();
        emit_stage(
            &on_progress,
            "http",
            "HTTP / Web Probe & Latency",
            "running",
            None,
        );

        let mut schemes = Vec::new();
        if is_open(443) || !matches!(port_status(443), Some("closed" | "filtered")) {
            schemes.push("https");
        }
        if is_open(80) || !matches!(port_status(80), Some("closed" | "filtered")) {
            schemes.push("http");
        }

        let http_futs = schemes.into_iter().map(|s| probe_single_http(ip, s));
        let (http_probes, reachability) =
            tokio::join!(join_all(http_futs), measure_tcp_reachability(ip, &ports));

        emit_stage(
            &on_progress,
            "http",
            "HTTP / Web Probe & Latency",
            "done",
            Some(t0.elapsed().as_millis() as u64),
        );
        (http_probes, reachability)
    };

    let (tls_reports, (http_probes, reachability)) = tokio::join!(tls_fut, http_reach_fut);

    // Synthesize associated hostnames across all intelligence sources
    let mut host_sources: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for p in &ptr_records {
        add_associated_host(&mut host_sources, &p.hostname, "PTR");
    }
    for tls in &tls_reports {
        for cert in tls.certificates.iter().take(1) {
            if let Some(cn) = &cert.common_name {
                add_associated_host(&mut host_sources, cn, "TLS CN");
            }
            for san in &cert.sans {
                add_associated_host(&mut host_sources, san, "TLS SAN");
            }
        }
    }
    for probe in &http_probes {
        if let Some(loc) = &probe.location {
            if let Some(h) = extract_host_from_url(loc) {
                add_associated_host(&mut host_sources, &h, "HTTP Redirect");
            }
        }
    }
    if let Some(idb) = &reputation.internetdb {
        for h in &idb.hostnames {
            add_associated_host(&mut host_sources, h, "InternetDB");
        }
    }
    for h in reverse_hosts {
        add_associated_host(&mut host_sources, &h, "Reverse IP");
    }

    let associated_hosts: Vec<IpAssociatedHost> = host_sources
        .into_iter()
        .map(|(hostname, sources)| IpAssociatedHost {
            hostname,
            sources: sources.into_iter().collect(),
        })
        .collect();

    let (posture, exposure_risk, summary, findings) = synthesize_findings_and_posture(
        &meta,
        &bgp,
        &reputation,
        &ports,
        &ptr_records,
        fcrdns_overall,
    );

    let mut warnings = Vec::new();
    if !meta.is_public {
        warnings.push(format!(
            "Address {} has scope '{}'; external BGP, RDAP, geolocation, and blacklist lookups were skipped.",
            meta.normalized, meta.scope
        ));
    }
    if reputation.blacklists_blocked > 0 {
        warnings.push(format!(
            "{} DNSBL(s) rate-limited or blocked queries via your current DNS resolver.",
            reputation.blacklists_blocked
        ));
    }

    Ok(IpDeepScanReport {
        ip: meta.normalized.clone(),
        queried_at: Utc::now().to_rfc3339(),
        latency_ms: started.elapsed().as_millis() as u64,
        posture,
        exposure_risk,
        summary,
        findings,
        meta,
        ptr_records,
        fcrdns_overall,
        bgp,
        rdap,
        geo,
        reputation,
        ports,
        reachability,
        tls_reports,
        http_probes,
        associated_hosts,
        warnings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{BlacklistEntry, PortScanItem};

    #[test]
    fn test_parse_ip_target_variants() {
        assert_eq!(parse_ip_target("1.1.1.1").unwrap(), IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            parse_ip_target("https://8.8.8.8/dns-query").unwrap(),
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        );
        assert_eq!(
            parse_ip_target("9.9.9.9:853").unwrap(),
            IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9))
        );
        assert_eq!(
            parse_ip_target("[2606:4700:4700::1111]:443").unwrap(),
            "2606:4700:4700::1111".parse::<IpAddr>().unwrap()
        );
        assert!(parse_ip_target("cloudflare.com").is_err());
        assert!(parse_ip_target("   ").is_err());
    }

    #[test]
    fn test_classify_ip_meta_scopes_and_representations() {
        let pub_v4 = classify_ip_meta("1.1.1.1".parse().unwrap());
        assert_eq!(pub_v4.ip_version, "IPv4");
        assert_eq!(pub_v4.scope, "Public Unicast");
        assert!(pub_v4.is_public);
        assert!(!pub_v4.is_private);
        assert_eq!(pub_v4.hex, "0x01010101");
        assert_eq!(pub_v4.integer, "16843009");
        assert_eq!(
            pub_v4.binary.as_deref(),
            Some("00000001.00000001.00000001.00000001")
        );
        assert_eq!(pub_v4.reverse_ptr_zone, "1.1.1.1.in-addr.arpa");

        let rfc1918 = classify_ip_meta("192.168.1.10".parse().unwrap());
        assert_eq!(rfc1918.scope, "Private (RFC 1918)");
        assert!(!rfc1918.is_public);
        assert!(rfc1918.is_private);

        let cgnat = classify_ip_meta("100.64.5.1".parse().unwrap());
        assert_eq!(cgnat.scope, "Shared / CGNAT (RFC 6598)");
        assert!(!cgnat.is_public);
        assert!(cgnat.is_private);

        let loop_v4 = classify_ip_meta("127.0.0.1".parse().unwrap());
        assert_eq!(loop_v4.scope, "Loopback (127.0.0.0/8)");
        assert!(loop_v4.is_loopback);
        assert!(!loop_v4.is_public);

        let pub_v6 = classify_ip_meta("2606:4700:4700::1111".parse().unwrap());
        assert_eq!(pub_v6.ip_version, "IPv6");
        assert_eq!(pub_v6.scope, "Public Unicast");
        assert!(pub_v6.is_public);
        assert_eq!(
            pub_v6.expanded.as_deref(),
            Some("2606:4700:4700:0000:0000:0000:0000:1111")
        );
        assert!(pub_v6.reverse_ptr_zone.ends_with(".ip6.arpa"));

        let ula = classify_ip_meta("fd12:3456:789a::1".parse().unwrap());
        assert_eq!(ula.scope, "Unique Local (RFC 4193)");
        assert!(ula.is_private);
        assert!(!ula.is_public);

        let link_local = classify_ip_meta("fe80::1".parse().unwrap());
        assert_eq!(link_local.scope, "Link-Local (fe80::/10)");
        assert!(link_local.is_private);
    }

    #[test]
    fn test_parse_rdap_ip_json() {
        let sample = br#"{
          "handle": "NET-1-1-1-0-1",
          "name": "APNIC-LABS",
          "type": "DIRECT ASSIGNMENT",
          "parentHandle": "NET-1-0-0-0-0",
          "startAddress": "1.1.1.0",
          "endAddress": "1.1.1.255",
          "country": "AU",
          "status": ["active"],
          "cidr0_cidrs": [{"v4prefix": "1.1.1.0", "length": 24}],
          "events": [
            {"eventAction": "registration", "eventDate": "2011-08-11T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2020-07-15T12:00:00Z"}
          ],
          "entities": [
            {
              "roles": ["registrant"],
              "vcardArray": ["vcard", [["fn", {}, "text", "APNIC Research and Development"]]],
              "entities": [
                {
                  "roles": ["abuse"],
                  "vcardArray": ["vcard", [
                    ["email", {}, "text", "helpdesk@apnic.net"],
                    ["tel", {}, "uri", "tel:+61-7-3858-3188"]
                  ]]
                }
              ]
            }
          ]
        }"#;

        let rdap = parse_rdap_ip_json(sample, Some("rdap.apnic.net".to_string())).unwrap();
        assert_eq!(rdap.status, "ok");
        assert_eq!(rdap.net_name.as_deref(), Some("APNIC-LABS"));
        assert_eq!(rdap.cidrs, vec!["1.1.1.0/24".to_string()]);
        assert_eq!(rdap.org_name.as_deref(), Some("APNIC Research and Development"));
        assert_eq!(rdap.abuse_email.as_deref(), Some("helpdesk@apnic.net"));
        assert_eq!(rdap.abuse_phone.as_deref(), Some("+61-7-3858-3188"));
        assert_eq!(rdap.registered_date.as_deref(), Some("2011-08-11T00:00:00Z"));
    }

    #[test]
    fn test_parse_internetdb_and_ripestat() {
        let idb = br#"{
          "ip": "1.1.1.1",
          "ports": [53, 80, 443],
          "hostnames": ["one.one.one.one"],
          "cpes": ["cpe:/a:cloudflare:nginx"],
          "tags": ["cdn"],
          "vulns": ["CVE-2024-0001"]
        }"#;
        let parsed = parse_internetdb_json(idb).unwrap();
        assert!(parsed.indexed);
        assert_eq!(parsed.ports, vec![53, 80, 443]);
        assert_eq!(parsed.vulns, vec!["CVE-2024-0001"]);

        let ripe_pfx = br#"{"data":{"resource":"1.1.1.0/24","announced":true,"asns":[{"asn":13335,"holder":"CLOUDFLARENET"}]}}"#;
        let (pfx, ann, asn, holder) = parse_ripestat_prefix_overview(ripe_pfx);
        assert_eq!(pfx.as_deref(), Some("1.1.1.0/24"));
        assert_eq!(ann, Some(true));
        assert_eq!(asn, Some(13335));
        assert_eq!(holder.as_deref(), Some("CLOUDFLARENET"));

        let ripe_neigh = br#"{"data":{"neighbour_counts":{"left":12,"right":34,"uncertain":2}}}"#;
        assert_eq!(parse_ripestat_asn_neighbours(ripe_neigh), (Some(12), Some(34), Some(2)));
    }

    #[test]
    fn test_synthesize_findings_and_posture() {
        let meta = classify_ip_meta("203.0.113.5".parse().unwrap());
        let bgp = IpBgpInfo {
            asn: Some(64500),
            as_org: Some("Example Net".to_string()),
            as_holder: None,
            prefix: Some("203.0.113.0/24".to_string()),
            rir: Some("ARIN".to_string()),
            allocated_date: None,
            country_code: Some("US".to_string()),
            provider_type: "Network".to_string(),
            provider_name: None,
            is_anycast_cdn: false,
            rpki_status: Some("invalid".to_string()),
            rpki_detail: Some("Origin mismatch".to_string()),
            announced: Some(true),
            neighbors_left: None,
            neighbors_right: None,
            neighbors_uncertain: None,
            related_prefixes: vec![],
        };
        let rep = IpReputationInfo {
            status: "listed".to_string(),
            is_tor_exit: true,
            blacklists_checked: 10,
            blacklists_listed: 1,
            blacklists_blocked: 0,
            blacklists: vec![BlacklistEntry {
                list_name: "Spamhaus ZEN".to_string(),
                zone: "zen.spamhaus.org".to_string(),
                target: "203.0.113.5".to_string(),
                target_role: "IP".to_string(),
                status: "listed".to_string(),
                return_codes: vec!["127.0.0.2".to_string()],
                detail: None,
                delist_url: None,
                latency_ms: 10,
            }],
            internetdb: None,
            signals: vec![],
        };
        let ports = PortScanReport {
            target_host: "203.0.113.5".to_string(),
            target_ip: Some("203.0.113.5".to_string()),
            available_ips: vec!["203.0.113.5".to_string()],
            open_count: 1,
            closed_count: 0,
            filtered_count: 0,
            total_checked: 1,
            latency_ms: 5,
            ports: vec![PortScanItem {
                port: 3306,
                service: "MySQL / MariaDB".to_string(),
                category: "Database".to_string(),
                status: "open".to_string(),
                latency_ms: 5,
                banner: None,
                risk_level: "high".to_string(),
                note: None,
            }],
            error: None,
        };

        let (posture, risk, _summary, findings) =
            synthesize_findings_and_posture(&meta, &bgp, &rep, &ports, &[], None);
        assert_eq!(posture, "elevated_risk");
        assert_eq!(risk, "high");
        assert!(findings.iter().any(|f| f.category == "Exposure"));
        assert!(findings.iter().any(|f| f.category == "Routing"));
        assert!(findings.iter().any(|f| f.category == "Reputation"));
    }
}
