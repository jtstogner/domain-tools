use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use futures::future::join_all;
use hickory_resolver::proto::rr::{RData, RecordType};
use tokio::io::AsyncReadExt;
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::dns::{build_resolver, normalize_domain};
use crate::models::{PortScanItem, PortScanReport, ResolverResult};

const PORT_CONNECT_TIMEOUT_MS: u64 = 1500;
const BANNER_READ_TIMEOUT_MS: u64 = 400;
const MAX_TOTAL_PORTS: usize = 64;

const COMMON_PORTS: &[(u16, &str, &str)] = &[
    (80, "HTTP", "Web"),
    (443, "HTTPS", "Web"),
    (8080, "HTTP Alt", "Web"),
    (8443, "HTTPS Alt", "Web"),
    (21, "FTP", "File Transfer"),
    (22, "SSH", "Remote Access"),
    (23, "Telnet", "Remote Access"),
    (3389, "RDP", "Remote Access"),
    (5900, "VNC", "Remote Access"),
    (25, "SMTP", "Mail"),
    (465, "SMTPS", "Mail"),
    (587, "SMTP Submission", "Mail"),
    (110, "POP3", "Mail"),
    (995, "POP3S", "Mail"),
    (143, "IMAP", "Mail"),
    (993, "IMAPS", "Mail"),
    (53, "DNS TCP", "Infrastructure"),
    (2082, "cPanel HTTP", "Hosting"),
    (2083, "cPanel HTTPS", "Hosting"),
    (2086, "WHM HTTP", "Hosting"),
    (2087, "WHM HTTPS", "Hosting"),
    (3306, "MySQL / MariaDB", "Database"),
    (5432, "PostgreSQL", "Database"),
    (6379, "Redis", "Database"),
    (27017, "MongoDB", "Database"),
    (1433, "MS SQL", "Database"),
];

fn lookup_port_meta(port: u16) -> (&'static str, &'static str) {
    if let Some((_, svc, cat)) = COMMON_PORTS.iter().find(|(p, _, _)| *p == port) {
        return (*svc, *cat);
    }
    match port {
        139 => ("NetBIOS", "File Sharing"),
        445 => ("SMB", "File Sharing"),
        389 => ("LDAP", "Directory"),
        636 => ("LDAPS", "Directory"),
        2222 => ("SSH Alt", "Remote Access"),
        2375 => ("Docker API (Unencrypted)", "Container"),
        2376 => ("Docker API (TLS)", "Container"),
        5985 => ("WinRM HTTP", "Remote Access"),
        5986 => ("WinRM HTTPS", "Remote Access"),
        6443 => ("Kubernetes API", "Container"),
        8000 => ("HTTP Alt", "Web"),
        8888 => ("HTTP Alt", "Web"),
        9090 => ("Admin / Prometheus", "Infrastructure"),
        9200 => ("Elasticsearch", "Database"),
        11211 => ("Memcached", "Database"),
        _ => ("Custom", "Custom"),
    }
}

pub fn classify_port_risk(port: u16) -> (&'static str, Option<&'static str>) {
    match port {
        23 => ("high", Some("Unencrypted Telnet exposed publicly.")),
        445 | 139 => ("high", Some("SMB / NetBIOS file sharing port exposed publicly.")),
        2375 => ("high", Some("Unencrypted Docker daemon API exposed publicly.")),
        3306 | 5432 | 6379 | 27017 | 1433 | 9200 | 11211 => (
            "high",
            Some("Database / cache port reachable from the public internet."),
        ),
        21 => ("caution", Some("Plaintext FTP control port exposed.")),
        22 | 2222 => ("caution", Some("Public SSH access enabled.")),
        389 => ("caution", Some("Unencrypted LDAP directory port exposed.")),
        3389 => ("caution", Some("Public Windows RDP port exposed.")),
        5900 => ("caution", Some("Public VNC remote desktop port exposed.")),
        5985 | 5986 => ("caution", Some("Public WinRM remote management port exposed.")),
        2376 | 6443 | 9090 => ("caution", Some("Cluster / management control plane port exposed.")),
        2082 | 2086 => ("caution", Some("Unencrypted cPanel/WHM port exposed.")),
        _ => ("normal", None),
    }
}

pub fn sanitize_banner(bytes: &[u8]) -> Option<String> {
    let raw = String::from_utf8_lossy(bytes);
    let first_line = raw.lines().next().unwrap_or("");
    let cleaned: String = first_line
        .chars()
        .filter(|c| c.is_ascii_graphic() || *c == ' ')
        .take(160)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn supports_passive_banner(port: u16) -> bool {
    matches!(port, 21 | 22 | 25 | 110 | 143 | 587)
}

pub async fn probe_port(ip: IpAddr, port: u16) -> PortScanItem {
    probe_port_with_timeout(ip, port, Duration::from_millis(PORT_CONNECT_TIMEOUT_MS)).await
}

pub async fn probe_port_with_timeout(
    ip: IpAddr,
    port: u16,
    connect_timeout: Duration,
) -> PortScanItem {
    let (service, category) = lookup_port_meta(port);
    let start = Instant::now();
    let addr = SocketAddr::new(ip, port);

    match timeout(connect_timeout, TcpStream::connect(addr)).await {
        Ok(Ok(mut stream)) => {
            let latency_ms = start.elapsed().as_millis() as u64;
            let banner = if supports_passive_banner(port) {
                let mut buf = [0u8; 256];
                match timeout(
                    Duration::from_millis(BANNER_READ_TIMEOUT_MS),
                    stream.read(&mut buf),
                )
                .await
                {
                    Ok(Ok(n)) if n > 0 => sanitize_banner(&buf[..n]),
                    _ => None,
                }
            } else {
                None
            };

            let (risk_level, note) = classify_port_risk(port);
            PortScanItem {
                port,
                service: service.to_string(),
                category: category.to_string(),
                status: "open".to_string(),
                latency_ms,
                banner,
                risk_level: risk_level.to_string(),
                note: note.map(|s| s.to_string()),
            }
        }
        Ok(Err(err)) if err.kind() == ErrorKind::ConnectionRefused => PortScanItem {
            port,
            service: service.to_string(),
            category: category.to_string(),
            status: "closed".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            banner: None,
            risk_level: "normal".to_string(),
            note: None,
        },
        Ok(Err(err)) => PortScanItem {
            port,
            service: service.to_string(),
            category: category.to_string(),
            status: "error".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            banner: None,
            risk_level: "normal".to_string(),
            note: Some(err.to_string()),
        },
        Err(_) => PortScanItem {
            port,
            service: service.to_string(),
            category: category.to_string(),
            status: "filtered".to_string(),
            latency_ms: start.elapsed().as_millis() as u64,
            banner: None,
            risk_level: "normal".to_string(),
            note: Some("Connection timed out (firewalled or dropped)".to_string()),
        },
    }
}

fn status_rank(status: &str) -> u8 {
    match status {
        "open" => 0,
        "closed" => 1,
        "filtered" => 2,
        _ => 3,
    }
}

pub async fn scan_ip_with_ports(
    target_host: String,
    ip: IpAddr,
    available_ips: Vec<String>,
    base_ports: &[u16],
    custom_ports: Option<Vec<u16>>,
) -> PortScanReport {
    let start = Instant::now();
    let mut port_list: Vec<u16> = base_ports.to_vec();

    if let Some(extras) = custom_ports {
        for p in extras {
            if p > 0 && !port_list.contains(&p) {
                port_list.push(p);
                if port_list.len() >= MAX_TOTAL_PORTS {
                    break;
                }
            }
        }
    }

    let mut ports = join_all(port_list.into_iter().map(|p| probe_port(ip, p))).await;
    ports.sort_by(|a, b| {
        status_rank(&a.status)
            .cmp(&status_rank(&b.status))
            .then_with(|| a.port.cmp(&b.port))
    });

    let open_count = ports.iter().filter(|p| p.status == "open").count();
    let closed_count = ports.iter().filter(|p| p.status == "closed").count();
    let filtered_count = ports.iter().filter(|p| p.status == "filtered").count();
    let total_checked = ports.len();

    PortScanReport {
        target_host,
        target_ip: Some(ip.to_string()),
        available_ips,
        open_count,
        closed_count,
        filtered_count,
        total_checked,
        latency_ms: start.elapsed().as_millis() as u64,
        ports,
        error: None,
    }
}

pub async fn scan_ip_ports(
    target_host: String,
    ip: IpAddr,
    available_ips: Vec<String>,
    custom_ports: Option<Vec<u16>>,
) -> PortScanReport {
    let base: Vec<u16> = COMMON_PORTS.iter().map(|(p, _, _)| *p).collect();
    scan_ip_with_ports(target_host, ip, available_ips, &base, custom_ports).await
}

pub async fn scan_domain_ports(domain: &str, resolvers: &[ResolverResult]) -> PortScanReport {
    let mut ips: Vec<IpAddr> = Vec::new();

    if let Some(primary) = resolvers.iter().find(|r| r.status == "ok") {
        for rtype in ["A", "AAAA"] {
            for tr in &primary.results {
                if tr.record_type == rtype {
                    for rec in &tr.records {
                        if let Ok(ip) = rec.value.trim().parse::<IpAddr>() {
                            if !ips.contains(&ip) {
                                ips.push(ip);
                            }
                        }
                    }
                }
            }
        }
    }

    if ips.is_empty() {
        if let Ok((_, _, fallback)) = build_resolver("cloudflare", None, false) {
            let fqdn = format!("{domain}.");
            let (a_res, aaaa_res) = tokio::join!(
                fallback.lookup(&fqdn, RecordType::A),
                fallback.lookup(&fqdn, RecordType::AAAA),
            );
            if let Ok(lookup) = a_res {
                for r in lookup.record_iter() {
                    if let RData::A(a) = r.data() {
                        let ip = IpAddr::V4(a.0);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
            if let Ok(lookup) = aaaa_res {
                for r in lookup.record_iter() {
                    if let RData::AAAA(aaaa) = r.data() {
                        let ip = IpAddr::V6(aaaa.0);
                        if !ips.contains(&ip) {
                            ips.push(ip);
                        }
                    }
                }
            }
        }
    }

    let Some(primary_ip) = ips.first().copied() else {
        return PortScanReport {
            target_host: domain.to_string(),
            target_ip: None,
            available_ips: vec![],
            open_count: 0,
            closed_count: 0,
            filtered_count: 0,
            total_checked: 0,
            latency_ms: 0,
            ports: vec![],
            error: Some("No A/AAAA IP address resolved for port scanning.".to_string()),
        };
    };

    let available_ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();
    scan_ip_ports(domain.to_string(), primary_ip, available_ips, None).await
}

pub async fn scan_custom_target(
    target: String,
    custom_ports: Option<Vec<u16>>,
) -> Result<PortScanReport, String> {
    let trimmed = target.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok(scan_ip_ports(trimmed.to_string(), ip, vec![ip.to_string()], custom_ports).await);
    }

    let domain = normalize_domain(trimmed)?;
    let (_, _, resolver) = build_resolver("cloudflare", None, false)?;
    let fqdn = format!("{domain}.");

    let mut ips: Vec<IpAddr> = Vec::new();
    let (a_res, aaaa_res) = tokio::join!(
        resolver.lookup(&fqdn, RecordType::A),
        resolver.lookup(&fqdn, RecordType::AAAA),
    );
    if let Ok(lookup) = a_res {
        for r in lookup.record_iter() {
            if let RData::A(a) = r.data() {
                let ip = IpAddr::V4(a.0);
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }
    if let Ok(lookup) = aaaa_res {
        for r in lookup.record_iter() {
            if let RData::AAAA(aaaa) = r.data() {
                let ip = IpAddr::V6(aaaa.0);
                if !ips.contains(&ip) {
                    ips.push(ip);
                }
            }
        }
    }

    let primary_ip = ips
        .first()
        .copied()
        .ok_or_else(|| format!("No A/AAAA IP address resolved for '{domain}'."))?;
    let available_ips: Vec<String> = ips.iter().map(|ip| ip.to_string()).collect();

    Ok(scan_ip_ports(domain, primary_ip, available_ips, custom_ports).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpListener;

    #[test]
    fn test_sanitize_banner_and_risk() {
        let b = sanitize_banner(b"SSH-2.0-OpenSSH_9.6\r\nExtra line\x00\x07");
        assert_eq!(b.as_deref(), Some("SSH-2.0-OpenSSH_9.6"));
        assert_eq!(sanitize_banner(b"\r\n\x00"), None);

        assert_eq!(classify_port_risk(23).0, "high");
        assert_eq!(classify_port_risk(3306).0, "high");
        assert_eq!(classify_port_risk(22).0, "caution");
        assert_eq!(classify_port_risk(443).0, "normal");
    }

    #[tokio::test]
    async fn test_probe_port_open_banner_and_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let server_task = tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let _ = socket.write_all(b"SSH-2.0-TestServer\r\n").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });

        let open_item = probe_port(IpAddr::V4(Ipv4Addr::LOCALHOST), port).await;
        assert_eq!(open_item.status, "open");
        let _ = server_task.await;

        let closed_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_port = closed_listener.local_addr().unwrap().port();
        drop(closed_listener);

        let closed_item = probe_port_with_timeout(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            closed_port,
            Duration::from_millis(3500),
        )
        .await;
        assert_eq!(closed_item.status, "closed");
    }

    #[tokio::test]
    async fn test_probe_port_22_banner_extraction() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            if let Ok((mut sock, _)) = listener.accept().await {
                let _ = sock.write_all(b"220 mail.example.com ESMTP Postfix\r\n").await;
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        });
        let mut stream = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(
            sanitize_banner(&buf[..n]).as_deref(),
            Some("220 mail.example.com ESMTP Postfix")
        );
        let _ = handle.await;
    }
}
