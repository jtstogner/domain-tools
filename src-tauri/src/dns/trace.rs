use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::timeout;

use crate::dns::{build_resolver, normalize_domain};
use crate::models::{AuthoritativeNsCheck, DnsTraceHop, DnsTraceReport};

const TRACE_QUERY_TIMEOUT: Duration = Duration::from_millis(2500);
const MAX_TRACE_HOPS: usize = 12;

const ROOT_HINTS: &[(&str, &str)] = &[
    ("a.root-servers.net", "198.41.0.4"),
    ("b.root-servers.net", "199.9.14.201"),
    ("c.root-servers.net", "192.33.4.12"),
    ("d.root-servers.net", "199.7.91.13"),
];

pub fn qtype_code(record_type: &str) -> Result<(u16, &'static str), String> {
    match record_type.trim().to_ascii_uppercase().as_str() {
        "A" => Ok((1, "A")),
        "NS" => Ok((2, "NS")),
        "CNAME" => Ok((5, "CNAME")),
        "SOA" => Ok((6, "SOA")),
        "PTR" => Ok((12, "PTR")),
        "MX" => Ok((15, "MX")),
        "TXT" => Ok((16, "TXT")),
        "AAAA" => Ok((28, "AAAA")),
        "SRV" => Ok((33, "SRV")),
        "DS" => Ok((43, "DS")),
        "RRSIG" => Ok((46, "RRSIG")),
        "DNSKEY" => Ok((48, "DNSKEY")),
        "CAA" => Ok((257, "CAA")),
        other => Err(format!("Unsupported DNS trace record type '{other}'.")),
    }
}

pub fn encode_dns_name(domain: &str) -> Result<Vec<u8>, String> {
    let trimmed = domain.trim().trim_end_matches('.');
    if trimmed.is_empty() {
        return Ok(vec![0]);
    }
    let mut out = Vec::with_capacity(trimmed.len() + 2);
    for label in trimmed.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return Err(format!("Invalid DNS label '{label}'."));
        }
        out.push(bytes.len() as u8);
        out.extend_from_slice(bytes);
    }
    out.push(0);
    Ok(out)
}

pub fn build_dns_query_packet(tx_id: u16, domain: &str, qtype: u16, dnssec_ok: bool) -> Result<Vec<u8>, String> {
    let qname = encode_dns_name(domain)?;
    let mut pkt = Vec::with_capacity(64);
    // Header: ID, Flags (RD=0), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0/1
    pkt.extend_from_slice(&tx_id.to_be_bytes());
    pkt.extend_from_slice(&0x0000u16.to_be_bytes()); // RD=0 iterative
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&(if dnssec_ok { 1u16 } else { 0u16 }).to_be_bytes());

    // Question
    pkt.extend_from_slice(&qname);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // IN class

    if dnssec_ok {
        // EDNS0 OPT RR: root(0), type=41(OPT), payload=1232, ext_rcode=0, ver=0, DO=0x8000, rdlen=0
        pkt.push(0);
        pkt.extend_from_slice(&41u16.to_be_bytes());
        pkt.extend_from_slice(&1232u16.to_be_bytes());
        pkt.push(0);
        pkt.push(0);
        pkt.extend_from_slice(&0x8000u16.to_be_bytes());
        pkt.extend_from_slice(&0u16.to_be_bytes());
    }

    Ok(pkt)
}

pub fn decode_dns_name(pkt: &[u8], mut offset: usize) -> Result<(String, usize), String> {
    let mut labels = Vec::new();
    let mut jumped = false;
    let mut end_offset = offset;
    let mut jumps = 0usize;

    loop {
        if offset >= pkt.len() {
            return Err("Truncated DNS name".to_string());
        }
        let len = pkt[offset];
        if (len & 0xC0) == 0xC0 {
            if offset + 1 >= pkt.len() {
                return Err("Truncated DNS pointer".to_string());
            }
            let ptr = (((len & 0x3F) as usize) << 8) | (pkt[offset + 1] as usize);
            if !jumped {
                end_offset = offset + 2;
                jumped = true;
            }
            offset = ptr;
            jumps += 1;
            if jumps > 32 {
                return Err("DNS name compression pointer loop".to_string());
            }
        } else if len == 0 {
            if !jumped {
                end_offset = offset + 1;
            }
            break;
        } else {
            let l = len as usize;
            if offset + 1 + l > pkt.len() {
                return Err("DNS label exceeds packet bounds".to_string());
            }
            labels.push(String::from_utf8_lossy(&pkt[offset + 1..offset + 1 + l]).into_owned());
            offset += 1 + l;
        }
    }

    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".").to_ascii_lowercase()
    };
    Ok((name, end_offset))
}

#[derive(Debug, Clone)]
pub struct WireRr {
    pub name: String,
    pub rtype: u16,
    pub ttl: u32,
    pub display: String,
    pub a_ip: Option<Ipv4Addr>,
    pub ns_target: Option<String>,
    pub cname_target: Option<String>,
    pub soa_serial: Option<u32>,
}

#[derive(Debug, Clone)]
pub struct WireResponse {
    pub rcode: u8,
    pub authoritative: bool,
    pub truncated: bool,
    pub answers: Vec<WireRr>,
    pub authorities: Vec<WireRr>,
    pub additionals: Vec<WireRr>,
}

fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        _ => "OTHER",
    }
}

fn read_u16(pkt: &[u8], off: usize) -> Result<u16, String> {
    if off + 2 > pkt.len() {
        return Err("Truncated u16".to_string());
    }
    Ok(u16::from_be_bytes([pkt[off], pkt[off + 1]]))
}

fn read_u32(pkt: &[u8], off: usize) -> Result<u32, String> {
    if off + 4 > pkt.len() {
        return Err("Truncated u32".to_string());
    }
    Ok(u32::from_be_bytes([
        pkt[off],
        pkt[off + 1],
        pkt[off + 2],
        pkt[off + 3],
    ]))
}

fn parse_rr_list(pkt: &[u8], mut offset: usize, count: u16) -> Result<(Vec<WireRr>, usize), String> {
    let mut list = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let (name, next) = decode_dns_name(pkt, offset)?;
        offset = next;
        let rtype = read_u16(pkt, offset)?;
        let _rclass = read_u16(pkt, offset + 2)?;
        let ttl = read_u32(pkt, offset + 4)?;
        let rdlen = read_u16(pkt, offset + 8)? as usize;
        offset += 10;
        if offset + rdlen > pkt.len() {
            return Err("Truncated DNS RDATA".to_string());
        }
        let rdata_start = offset;
        let rdata_end = offset + rdlen;

        let mut a_ip = None;
        let mut ns_target = None;
        let mut cname_target = None;
        let mut soa_serial = None;

        let display = match rtype {
            1 if rdlen == 4 => {
                let ip = Ipv4Addr::new(
                    pkt[rdata_start],
                    pkt[rdata_start + 1],
                    pkt[rdata_start + 2],
                    pkt[rdata_start + 3],
                );
                a_ip = Some(ip);
                format!("{name} {ttl} IN A {ip}")
            }
            28 if rdlen == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&pkt[rdata_start..rdata_end]);
                let ip = std::net::Ipv6Addr::from(octets);
                format!("{name} {ttl} IN AAAA {ip}")
            }
            2 => {
                let (target, _) = decode_dns_name(pkt, rdata_start)?;
                ns_target = Some(target.clone());
                format!("{name} {ttl} IN NS {target}")
            }
            5 => {
                let (target, _) = decode_dns_name(pkt, rdata_start)?;
                cname_target = Some(target.clone());
                format!("{name} {ttl} IN CNAME {target}")
            }
            6 => {
                let (mname, p1) = decode_dns_name(pkt, rdata_start)?;
                let (rname, p2) = decode_dns_name(pkt, p1)?;
                let serial = read_u32(pkt, p2)?;
                soa_serial = Some(serial);
                format!("{name} {ttl} IN SOA {mname} {rname} {serial}")
            }
            15 if rdlen >= 3 => {
                let pref = read_u16(pkt, rdata_start)?;
                let (exch, _) = decode_dns_name(pkt, rdata_start + 2)?;
                format!("{name} {ttl} IN MX {pref} {exch}")
            }
            16 => {
                let mut pos = rdata_start;
                let mut text = String::new();
                while pos < rdata_end {
                    let slen = pkt[pos] as usize;
                    pos += 1;
                    let take = slen.min(rdata_end - pos);
                    text.push_str(&String::from_utf8_lossy(&pkt[pos..pos + take]));
                    pos += take;
                }
                format!("{name} {ttl} IN TXT \"{text}\"")
            }
            43 if rdlen >= 4 => {
                let key_tag = read_u16(pkt, rdata_start)?;
                let alg = pkt[rdata_start + 2];
                let digest_type = pkt[rdata_start + 3];
                format!("{name} {ttl} IN DS tag={key_tag} alg={alg} digest={digest_type}")
            }
            46 if rdlen >= 18 => {
                let covered = read_u16(pkt, rdata_start)?;
                format!("{name} {ttl} IN RRSIG covers={covered}")
            }
            41 => {
                // OPT pseudo-record; skip displaying as normal RR
                offset = rdata_end;
                continue;
            }
            257 if rdlen >= 2 => {
                let flags = pkt[rdata_start];
                let tlen = pkt[rdata_start + 1] as usize;
                let tag_end = (rdata_start + 2 + tlen).min(rdata_end);
                let tag = String::from_utf8_lossy(&pkt[rdata_start + 2..tag_end]);
                let val = String::from_utf8_lossy(&pkt[tag_end..rdata_end]);
                format!("{name} {ttl} IN CAA {flags} {tag} \"{val}\"")
            }
            _ => format!("{name} {ttl} IN TYPE{rtype} ({rdlen} bytes)"),
        };

        list.push(WireRr {
            name,
            rtype,
            ttl,
            display,
            a_ip,
            ns_target,
            cname_target,
            soa_serial,
        });
        offset = rdata_end;
    }
    Ok((list, offset))
}

pub fn parse_dns_response(pkt: &[u8]) -> Result<WireResponse, String> {
    if pkt.len() < 12 {
        return Err("DNS packet shorter than 12-byte header".to_string());
    }
    let flags = read_u16(pkt, 2)?;
    let authoritative = (flags & 0x0400) != 0;
    let truncated = (flags & 0x0200) != 0;
    let rcode = (flags & 0x000F) as u8;

    let qdcount = read_u16(pkt, 4)?;
    let ancount = read_u16(pkt, 6)?;
    let nscount = read_u16(pkt, 8)?;
    let arcount = read_u16(pkt, 10)?;

    let mut offset = 12usize;
    for _ in 0..qdcount {
        let (_, next) = decode_dns_name(pkt, offset)?;
        offset = next + 4;
        if offset > pkt.len() {
            return Err("Truncated DNS question section".to_string());
        }
    }

    let (answers, off_an) = parse_rr_list(pkt, offset, ancount)?;
    let (authorities, off_ns) = parse_rr_list(pkt, off_an, nscount)?;
    let (additionals, _) = parse_rr_list(pkt, off_ns, arcount)?;

    Ok(WireResponse {
        rcode,
        authoritative,
        truncated,
        answers,
        authorities,
        additionals,
    })
}

async fn send_udp_or_tcp_query(server_ip: IpAddr, domain: &str, qtype: u16) -> Result<(WireResponse, u64), String> {
    let started = Instant::now();
    let tx_id: u16 = ((started.elapsed().subsec_nanos() ^ 0x5A3C) & 0xFFFF) as u16;
    let pkt = build_dns_query_packet(tx_id, domain, qtype, true)?;
    let target = SocketAddr::new(server_ip, 53);

    let bind_addr = if server_ip.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let sock = UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| format!("UDP bind error: {e}"))?;

    sock.send_to(&pkt, target)
        .await
        .map_err(|e| format!("UDP send error to {target}: {e}"))?;

    let mut buf = vec![0u8; 4096];
    let n = timeout(TRACE_QUERY_TIMEOUT, sock.recv(&mut buf))
        .await
        .map_err(|_| format!("DNS query to {server_ip} timed out"))?
        .map_err(|e| format!("UDP recv error from {server_ip}: {e}"))?;

    let parsed = parse_dns_response(&buf[..n])?;
    if !parsed.truncated {
        return Ok((parsed, started.elapsed().as_millis() as u64));
    }

    // Retry over TCP if truncated (TC=1)
    let mut tcp = timeout(TRACE_QUERY_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| format!("TCP fallback to {server_ip} timed out"))?
        .map_err(|e| format!("TCP fallback connect error: {e}"))?;
    let mut framed = Vec::with_capacity(2 + pkt.len());
    framed.extend_from_slice(&(pkt.len() as u16).to_be_bytes());
    framed.extend_from_slice(&pkt);
    tcp.write_all(&framed)
        .await
        .map_err(|e| format!("TCP write error: {e}"))?;

    let mut len_buf = [0u8; 2];
    timeout(TRACE_QUERY_TIMEOUT, tcp.read_exact(&mut len_buf))
        .await
        .map_err(|_| "TCP DNS length read timed out".to_string())?
        .map_err(|e| format!("TCP DNS length read error: {e}"))?;
    let msg_len = u16::from_be_bytes(len_buf) as usize;
    let mut tcp_buf = vec![0u8; msg_len.min(65535)];
    timeout(TRACE_QUERY_TIMEOUT, tcp.read_exact(&mut tcp_buf))
        .await
        .map_err(|_| "TCP DNS payload read timed out".to_string())?
        .map_err(|e| format!("TCP DNS payload read error: {e}"))?;

    let parsed_tcp = parse_dns_response(&tcp_buf)?;
    Ok((parsed_tcp, started.elapsed().as_millis() as u64))
}

async fn resolve_ns_ip_fallback(ns_name: &str) -> Option<IpAddr> {
    let Ok((_, _, resolver)) = build_resolver("cloudflare", None, false) else {
        return None;
    };
    let fqdn = format!("{}.", ns_name.trim_end_matches('.'));
    if let Ok(Ok(lookup)) = timeout(Duration::from_secs(2), resolver.lookup(&fqdn, RecordType::A)).await {
        for r in lookup.record_iter() {
            if let RData::A(a) = r.data() {
                return Some(IpAddr::V4(a.0));
            }
        }
    }
    None
}

pub async fn run_dns_trace(domain: &str, record_type: Option<&str>) -> Result<DnsTraceReport, String> {
    let clean_domain = normalize_domain(domain)?;
    let (qtype, rtype_label) = qtype_code(record_type.unwrap_or("A"))?;
    let started = Instant::now();

    let mut hops = Vec::new();
    let mut issues = Vec::new();
    let mut trace_error = None;

    let mut current_server_name = ROOT_HINTS[0].0.to_string();
    let mut current_server_ip: IpAddr = ROOT_HINTS[0].1.parse().unwrap();
    let mut current_level = "Root".to_string();
    let mut current_zone = ".".to_string();
    let mut visited_servers: BTreeSet<String> = BTreeSet::new();
    let mut final_ns_candidates: Vec<(String, Option<IpAddr>)> = Vec::new();

    for step in 1..=MAX_TRACE_HOPS {
        visited_servers.insert(format!("{current_zone}@{current_server_ip}"));

        let query_res = if step == 1 {
            // Try root hints in order on first step if one times out
            let mut last_err = None;
            let mut ok_res = None;
            for (rname, rip) in ROOT_HINTS {
                let ip: IpAddr = rip.parse().unwrap();
                match send_udp_or_tcp_query(ip, &clean_domain, qtype).await {
                    Ok(v) => {
                        current_server_name = (*rname).to_string();
                        current_server_ip = ip;
                        ok_res = Some(v);
                        break;
                    }
                    Err(e) => last_err = Some(e),
                }
            }
            ok_res.ok_or_else(|| last_err.unwrap_or_else(|| "Root servers unreachable".to_string()))
        } else {
            send_udp_or_tcp_query(current_server_ip, &clean_domain, qtype).await
        };

        let (resp, latency_ms) = match query_res {
            Ok(v) => v,
            Err(e) => {
                trace_error = Some(e.clone());
                issues.push(format!("Trace stopped at {current_server_name} ({current_server_ip}): {e}"));
                break;
            }
        };

        let answers: Vec<String> = resp.answers.iter().map(|r| r.display.clone()).collect();
        let ns_referrals: Vec<(String, String)> = resp
            .authorities
            .iter()
            .filter_map(|r| r.ns_target.as_ref().map(|ns| (r.name.clone(), ns.clone())))
            .collect();
        let referrals: Vec<String> = ns_referrals.iter().map(|(_, ns)| ns.clone()).collect();

        let mut glue_map: BTreeMap<String, IpAddr> = BTreeMap::new();
        let mut glue_ips = Vec::new();
        for add in &resp.additionals {
            if let Some(ip) = add.a_ip {
                glue_map.entry(add.name.clone()).or_insert(IpAddr::V4(ip));
                glue_ips.push(format!("{} -> {}", add.name, ip));
            }
        }

        let has_ds = resp.authorities.iter().any(|r| r.rtype == 43);
        let has_rrsig = resp
            .answers
            .iter()
            .chain(resp.authorities.iter())
            .any(|r| r.rtype == 46);

        let mut note = None;
        if resp.rcode == 3 {
            note = Some("Authoritative NXDOMAIN — domain does not exist.".to_string());
        } else if !answers.is_empty() && resp.authoritative {
            note = Some("Authoritative answer received.".to_string());
        } else if !answers.is_empty() && !resp.authoritative {
            note = Some("Non-authoritative answer returned (unexpected from iterative server).".to_string());
        } else if referrals.is_empty() && resp.authorities.iter().any(|r| r.rtype == 6) {
            note = Some("NODATA: domain exists, but no records of requested type.".to_string());
        } else if !referrals.is_empty() && glue_map.is_empty() {
            note = Some("Glueless referral — resolved next nameserver IP via fallback DNS.".to_string());
        }

        hops.push(DnsTraceHop {
            step,
            level: current_level.clone(),
            zone: current_zone.clone(),
            server_name: current_server_name.clone(),
            server_ip: current_server_ip.to_string(),
            rcode: rcode_name(resp.rcode).to_string(),
            authoritative: resp.authoritative,
            latency_ms,
            answers: answers.clone(),
            referrals: referrals.clone(),
            glue_ips,
            has_ds,
            has_rrsig,
            note,
        });

        // Stop if we got an answer or terminal NXDOMAIN / SOA NODATA
        if !answers.is_empty()
            || resp.rcode != 0
            || (referrals.is_empty() && resp.authorities.iter().any(|r| r.rtype == 6))
        {
            if !resp.authoritative && !answers.is_empty() {
                issues.push(format!(
                    "Server {} ({}) returned non-authoritative answer.",
                    current_server_name, current_server_ip
                ));
            }
            break;
        }

        if ns_referrals.is_empty() {
            issues.push(format!(
                "Delegation ended without answer or NS referral at {} ({}).",
                current_server_name, current_server_ip
            ));
            break;
        }

        let next_zone = ns_referrals[0].0.clone();
        let next_level = if next_zone.contains('.') {
            "Authoritative".to_string()
        } else {
            "TLD".to_string()
        };

        // Pick next nameserver & IP
        let mut chosen: Option<(String, IpAddr)> = None;
        let mut candidates_for_auth = Vec::new();

        for (_, ns) in &ns_referrals {
            let ip_opt = glue_map.get(ns).copied();
            candidates_for_auth.push((ns.clone(), ip_opt));
            if chosen.is_none() {
                if let Some(ip) = ip_opt {
                    let key = format!("{next_zone}@{ip}");
                    if !visited_servers.contains(&key) {
                        chosen = Some((ns.clone(), ip));
                    }
                }
            }
        }

        if chosen.is_none() {
            for (_, ns) in &ns_referrals {
                if let Some(ip) = resolve_ns_ip_fallback(ns).await {
                    let key = format!("{next_zone}@{ip}");
                    if !visited_servers.contains(&key) {
                        chosen = Some((ns.clone(), ip));
                        break;
                    }
                }
            }
        }

        final_ns_candidates = candidates_for_auth;

        let Some((next_name, next_ip)) = chosen else {
            issues.push(format!(
                "Could not resolve IP address for referred nameserver '{}'.",
                ns_referrals[0].1
            ));
            break;
        };

        current_zone = next_zone;
        current_level = next_level;
        current_server_name = next_name;
        current_server_ip = next_ip;
    }

    // Authoritative NS Consistency Audit across all referred authoritative nameservers
    if final_ns_candidates.is_empty() {
        if let Ok((_, _, res)) = build_resolver("cloudflare", None, false) {
            let fqdn = format!("{clean_domain}.");
            if let Ok(Ok(ns_lookup)) = timeout(Duration::from_secs(2), res.lookup(&fqdn, RecordType::NS)).await {
                for r in ns_lookup.record_iter() {
                    if let RData::NS(ns) = r.data() {
                        final_ns_candidates.push((
                            ns.0.to_string().trim_end_matches('.').to_ascii_lowercase(),
                            None,
                        ));
                    }
                }
            }
        }
    }

    let auth_futs = final_ns_candidates.into_iter().take(6).map(|(ns_name, maybe_ip)| {
        let dom = clean_domain.clone();
        async move {
            let ip = match maybe_ip {
                Some(v) => Some(v),
                None => resolve_ns_ip_fallback(&ns_name).await,
            };
            let Some(server_ip) = ip else {
                return AuthoritativeNsCheck {
                    nameserver: ns_name,
                    ip: None,
                    reachable: false,
                    authoritative: false,
                    soa_serial: None,
                    ns_records: vec![],
                    latency_ms: 0,
                    error: Some("Could not resolve NS IP".to_string()),
                };
            };

            let (soa_res, ns_res) = tokio::join!(
                send_udp_or_tcp_query(server_ip, &dom, 6),
                send_udp_or_tcp_query(server_ip, &dom, 2)
            );

            match soa_res {
                Ok((soa_resp, latency_ms)) => {
                    let soa_serial = soa_resp
                        .answers
                        .iter()
                        .chain(soa_resp.authorities.iter())
                        .find_map(|r| r.soa_serial);
                    let ns_records = ns_res
                        .map(|(r, _)| {
                            r.answers
                                .into_iter()
                                .filter_map(|a| a.ns_target)
                                .collect::<Vec<_>>()
                        })
                        .unwrap_or_default();
                    AuthoritativeNsCheck {
                        nameserver: ns_name,
                        ip: Some(server_ip.to_string()),
                        reachable: true,
                        authoritative: soa_resp.authoritative,
                        soa_serial,
                        ns_records,
                        latency_ms,
                        error: if !soa_resp.authoritative {
                            Some("Lame delegation (AA flag not set)".to_string())
                        } else {
                            None
                        },
                    }
                }
                Err(e) => AuthoritativeNsCheck {
                    nameserver: ns_name,
                    ip: Some(server_ip.to_string()),
                    reachable: false,
                    authoritative: false,
                    soa_serial: None,
                    ns_records: vec![],
                    latency_ms: 0,
                    error: Some(e),
                },
            }
        }
    });

    let authoritative_checks = join_all(auth_futs).await;

    let lame_count = authoritative_checks
        .iter()
        .filter(|c| c.reachable && !c.authoritative)
        .count();
    if lame_count > 0 {
        issues.push(format!(
            "{lame_count} authoritative nameserver(s) responded without the AA (Authoritative Answer) flag (lame delegation)."
        ));
    }

    let unreach_count = authoritative_checks.iter().filter(|c| !c.reachable).count();
    if unreach_count > 0 {
        issues.push(format!(
            "{unreach_count} authoritative nameserver(s) were unreachable or timed out."
        ));
    }

    let serials: BTreeSet<u32> = authoritative_checks
        .iter()
        .filter_map(|c| c.soa_serial)
        .collect();
    if serials.len() > 1 {
        issues.push(format!(
            "SOA serial mismatch detected across authoritative nameservers ({:?}).",
            serials
        ));
    }

    Ok(DnsTraceReport {
        domain: clean_domain,
        record_type: rtype_label.to_string(),
        total_ms: started.elapsed().as_millis() as u64,
        hops,
        authoritative_checks,
        issues,
        error: trace_error,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_and_build_query_packet() {
        let encoded = encode_dns_name("example.com").unwrap();
        assert_eq!(encoded, b"\x07example\x03com\x00");

        let pkt = build_dns_query_packet(0x1234, "example.com", 1, true).unwrap();
        assert_eq!(&pkt[0..2], &[0x12, 0x34]);
        assert_eq!(&pkt[2..4], &[0x00, 0x00]); // RD=0
        assert_eq!(&pkt[10..12], &[0x00, 0x01]); // ARCOUNT=1 (OPT)
    }

    #[test]
    fn test_parse_dns_response_with_compression_pointer() {
        // Minimal DNS response: 1 question (example.com A), 1 answer (pointer 0xC00C -> 93.184.216.34)
        let mut pkt = vec![
            0x12, 0x34, // ID
            0x84, 0x00, // QR=1, AA=1, RCODE=0
            0x00, 0x01, // QD=1
            0x00, 0x01, // AN=1
            0x00, 0x00, // NS=0
            0x00, 0x00, // AR=0
        ];
        pkt.extend_from_slice(b"\x07example\x03com\x00");
        pkt.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // QTYPE=A, QCLASS=IN
        // Answer: pointer to offset 12 (0xC00C), TYPE=A, CLASS=IN, TTL=300, RDLEN=4, IP=93.184.216.34
        pkt.extend_from_slice(&[0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2C, 0x00, 0x04]);
        pkt.extend_from_slice(&[93, 184, 216, 34]);

        let parsed = parse_dns_response(&pkt).unwrap();
        assert!(parsed.authoritative);
        assert_eq!(parsed.rcode, 0);
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].a_ip, Some(Ipv4Addr::new(93, 184, 216, 34)));
    }
}
