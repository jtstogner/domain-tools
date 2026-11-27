use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;
use x509_parser::extensions::GeneralName;
use x509_parser::public_key::PublicKey;

use crate::dns::normalize_domain;
use crate::models::{TlsCertInfo, TlsReport};

const TCP_TIMEOUT: Duration = Duration::from_secs(4);
const TLS_TIMEOUT: Duration = Duration::from_secs(4);

static ROOT_STORE: OnceLock<Arc<RootCertStore>> = OnceLock::new();

fn native_root_store() -> Arc<RootCertStore> {
    ROOT_STORE
        .get_or_init(|| {
            let mut store = RootCertStore::empty();
            let loaded = rustls_native_certs::load_native_certs();
            for cert in loaded.certs {
                let _ = store.add(cert);
            }
            Arc::new(store)
        })
        .clone()
}

#[derive(Debug)]
struct InspectingVerifier {
    inner: Arc<rustls::client::WebPkiServerVerifier>,
    outcome: Arc<Mutex<Option<Result<(), String>>>>,
}

impl ServerCertVerifier for InspectingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let res = self.inner.verify_server_cert(
            end_entity,
            intermediates,
            server_name,
            ocsp_response,
            now,
        );
        let mapped = res.as_ref().map(|_| ()).map_err(|e| e.to_string());
        if let Ok(mut guard) = self.outcome.lock() {
            *guard = Some(mapped);
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

pub(crate) fn build_permissive_tls_connector(
) -> Result<(TlsConnector, Arc<Mutex<Option<Result<(), String>>>>), String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let roots = native_root_store();
    let webpki = rustls::client::WebPkiServerVerifier::builder_with_provider(roots, provider.clone())
        .build()
        .map_err(|e| format!("Failed to initialize TLS root verifier: {e}"))?;

    let outcome = Arc::new(Mutex::new(None));
    let verifier = Arc::new(InspectingVerifier {
        inner: webpki,
        outcome: outcome.clone(),
    });

    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS protocol configuration failed: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();

    Ok((TlsConnector::from(Arc::new(config)), outcome))
}

async fn read_smtp_multiline(reader: &mut BufReader<&mut TcpStream>) -> Result<(u16, String), String> {
    let mut all = String::new();
    let mut last_code = 0u16;
    for _ in 0..32 {
        let mut line = String::new();
        let n = timeout(Duration::from_secs(3), reader.read_line(&mut line))
            .await
            .map_err(|_| "SMTP STARTTLS banner/response timed out.".to_string())?
            .map_err(|e| format!("SMTP read error: {e}"))?;
        if n == 0 {
            break;
        }
        all.push_str(&line);
        if line.len() >= 3 {
            if let Ok(code) = line[..3].parse::<u16>() {
                last_code = code;
            }
        }
        if line.len() < 4 || line.as_bytes()[3] != b'-' {
            break;
        }
    }
    Ok((last_code, all))
}

async fn negotiate_starttls(stream: &mut TcpStream, protocol: &str) -> Result<(), String> {
    match protocol {
        "smtp" => {
            let mut reader = BufReader::new(stream);
            let (code, msg) = read_smtp_multiline(&mut reader).await?;
            if code != 220 {
                return Err(format!(
                    "Expected SMTP 220 greeting before STARTTLS, got {code}: {}",
                    msg.trim()
                ));
            }
            reader
                .get_mut()
                .write_all(b"EHLO domain-tools.local\r\n")
                .await
                .map_err(|e| format!("Failed sending EHLO: {e}"))?;
            let (ehlo_code, ehlo_msg) = read_smtp_multiline(&mut reader).await?;
            if ehlo_code != 250 {
                return Err(format!(
                    "SMTP EHLO rejected ({ehlo_code}): {}",
                    ehlo_msg.trim()
                ));
            }
            reader
                .get_mut()
                .write_all(b"STARTTLS\r\n")
                .await
                .map_err(|e| format!("Failed sending STARTTLS: {e}"))?;
            let (tls_code, tls_msg) = read_smtp_multiline(&mut reader).await?;
            if tls_code != 220 {
                return Err(format!(
                    "SMTP STARTTLS rejected ({tls_code}): {}",
                    tls_msg.trim()
                ));
            }
            Ok(())
        }
        "imap" => {
            let mut reader = BufReader::new(stream);
            let mut banner = String::new();
            let n = timeout(Duration::from_secs(3), reader.read_line(&mut banner))
                .await
                .map_err(|_| "IMAP greeting timed out.".to_string())?
                .map_err(|e| format!("IMAP read error: {e}"))?;
            if n == 0 || !banner.trim_start().starts_with("* ") {
                return Err(format!("Unexpected IMAP greeting: {}", banner.trim()));
            }
            reader
                .get_mut()
                .write_all(b"a001 STARTTLS\r\n")
                .await
                .map_err(|e| format!("Failed sending IMAP STARTTLS: {e}"))?;
            let mut resp = String::new();
            timeout(Duration::from_secs(3), reader.read_line(&mut resp))
                .await
                .map_err(|_| "IMAP STARTTLS response timed out.".to_string())?
                .map_err(|e| format!("IMAP read error: {e}"))?;
            if !resp.to_ascii_uppercase().contains("OK") {
                return Err(format!("IMAP STARTTLS rejected: {}", resp.trim()));
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

pub fn format_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn friendly_sig_alg(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.11" => "SHA256 with RSA".to_string(),
        "1.2.840.113549.1.1.12" => "SHA384 with RSA".to_string(),
        "1.2.840.113549.1.1.13" => "SHA512 with RSA".to_string(),
        "1.2.840.113549.1.1.10" => "RSA-PSS".to_string(),
        "1.2.840.10045.4.3.2" => "ECDSA with SHA256".to_string(),
        "1.2.840.10045.4.3.3" => "ECDSA with SHA384".to_string(),
        "1.2.840.10045.4.3.4" => "ECDSA with SHA512".to_string(),
        "1.3.101.112" => "Ed25519".to_string(),
        "1.3.101.113" => "Ed448".to_string(),
        other => other.to_string(),
    }
}

pub fn hostname_matches_cert(host: &str, common_name: Option<&str>, sans: &[String]) -> bool {
    let target = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }

    let mut patterns: Vec<String> = sans.to_vec();
    if patterns.is_empty() {
        if let Some(cn) = common_name {
            patterns.push(cn.to_string());
        }
    }

    for pat in patterns {
        let p = pat.trim().trim_end_matches('.').to_ascii_lowercase();
        if p == target {
            return true;
        }
        if let Some(suffix) = p.strip_prefix("*.") {
            // RFC 6125 single-label wildcard check
            if let Some((left, right)) = target.split_once('.') {
                if !left.is_empty() && right == suffix {
                    return true;
                }
            }
        }
    }
    false
}

pub(crate) fn parse_cert_der(der: &[u8]) -> Result<TlsCertInfo, String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("X.509 parse error: {e}"))?;

    let subject = cert.subject().to_string();
    let issuer = cert.issuer().to_string();
    let common_name = cert
        .subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());
    let issuer_org = cert
        .issuer()
        .iter_organization()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());

    let mut sans = Vec::new();
    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for gn in &san_ext.value.general_names {
            match gn {
                GeneralName::DNSName(dns) => sans.push((*dns).to_string()),
                GeneralName::IPAddress(bytes) => {
                    if bytes.len() == 4 {
                        sans.push(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string());
                    } else if bytes.len() == 16 {
                        let mut octets = [0u8; 16];
                        octets.copy_from_slice(bytes);
                        sans.push(Ipv6Addr::from(octets).to_string());
                    }
                }
                _ => {}
            }
        }
    }

    let nb_ts = cert.validity().not_before.timestamp();
    let na_ts = cert.validity().not_after.timestamp();
    let not_before = DateTime::from_timestamp(nb_ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| cert.validity().not_before.to_string());
    let not_after = DateTime::from_timestamp(na_ts, 0)
        .map(|d| d.to_rfc3339())
        .unwrap_or_else(|| cert.validity().not_after.to_string());
    let days_remaining = (na_ts - Utc::now().timestamp()) / 86_400;

    let serial_hex = cert.raw_serial_as_string();
    let signature_algorithm = friendly_sig_alg(&cert.signature_algorithm.algorithm.to_id_string());

    let (public_key_algorithm, public_key_bits) = match cert.public_key().parsed() {
        Ok(PublicKey::RSA(rsa)) => {
            let sig_bytes = rsa.modulus.iter().skip_while(|&&b| b == 0).count();
            ("RSA".to_string(), Some((sig_bytes * 8) as u32))
        }
        Ok(PublicKey::EC(ec)) => {
            let bits = match ec.data().len() {
                65 => Some(256),
                97 => Some(384),
                133 => Some(521),
                n if n > 1 => Some(((n - 1) / 2 * 8) as u32),
                _ => None,
            };
            ("ECDSA".to_string(), bits)
        }
        Ok(PublicKey::DSA(_)) => ("DSA".to_string(), None),
        _ => {
            let oid = cert.public_key().algorithm.algorithm.to_id_string();
            if oid == "1.3.101.112" {
                ("Ed25519".to_string(), Some(256))
            } else if oid == "1.3.101.113" {
                ("Ed448".to_string(), Some(448))
            } else {
                (oid, None)
            }
        }
    };

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    let is_self_signed = cert.subject() == cert.issuer();

    Ok(TlsCertInfo {
        subject,
        common_name,
        issuer,
        issuer_org,
        sans,
        not_before,
        not_after,
        days_remaining,
        serial_hex,
        signature_algorithm,
        public_key_algorithm,
        public_key_bits,
        sha256_fingerprint: format_fingerprint(der),
        is_ca,
        is_self_signed,
    })
}

fn empty_tls_report(host: String, port: u16, starttls: Option<String>, handshake_ms: u64, error: String) -> TlsReport {
    TlsReport {
        status: "unavailable".to_string(),
        host,
        port,
        starttls,
        protocol_version: None,
        cipher_suite: None,
        chain_valid: false,
        hostname_match: false,
        verification_error: None,
        days_remaining: None,
        handshake_ms,
        certificates: vec![],
        error: Some(error),
    }
}

fn resolve_effective_starttls(port: u16, starttls: Option<&str>) -> Result<Option<String>, String> {
    match starttls.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("none") | Some("") => Ok(None),
        Some("smtp") => Ok(Some("smtp".to_string())),
        Some("imap") => Ok(Some("imap".to_string())),
        Some("auto") | None => match port {
            25 | 587 => Ok(Some("smtp".to_string())),
            143 => Ok(Some("imap".to_string())),
            _ => Ok(None),
        },
        Some(other) => Err(format!("Unsupported STARTTLS mode '{other}'.")),
    }
}

async fn inspect_tls_with_connector(
    display_host: String,
    addr_target: String,
    server_name: ServerName<'static>,
    port: u16,
    effective_starttls: Option<String>,
    started: Instant,
) -> TlsReport {
    let mut tcp = match timeout(TCP_TIMEOUT, TcpStream::connect(&addr_target)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                format!("TCP connection to {addr_target} failed: {e}"),
            )
        }
        Err(_) => {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                format!("TCP connection to {addr_target} timed out."),
            )
        }
    };

    if let Some(proto) = effective_starttls.as_deref() {
        if let Err(e) = negotiate_starttls(&mut tcp, proto).await {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                e,
            );
        }
    }

    let (connector, outcome) = match build_permissive_tls_connector() {
        Ok(pair) => pair,
        Err(e) => {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                e,
            )
        }
    };

    let tls_stream = match timeout(TLS_TIMEOUT, connector.connect(server_name, tcp)).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                format!("TLS handshake with {addr_target} failed: {e}"),
            )
        }
        Err(_) => {
            return empty_tls_report(
                display_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                format!("TLS handshake with {addr_target} timed out."),
            )
        }
    };

    let handshake_ms = started.elapsed().as_millis() as u64;
    let (_, conn) = tls_stream.get_ref();

    let protocol_version = conn.protocol_version().map(|v| match v {
        rustls::ProtocolVersion::TLSv1_3 => "TLS 1.3".to_string(),
        rustls::ProtocolVersion::TLSv1_2 => "TLS 1.2".to_string(),
        other => format!("{other:?}"),
    });

    let cipher_suite = conn
        .negotiated_cipher_suite()
        .map(|cs| format!("{:?}", cs.suite()));

    let mut certificates = Vec::new();
    if let Some(peer_certs) = conn.peer_certificates() {
        for der in peer_certs {
            if let Ok(parsed) = parse_cert_der(der.as_ref()) {
                certificates.push(parsed);
            }
        }
    }

    let verify_result = outcome.lock().ok().and_then(|g| g.clone());
    let (chain_valid, verification_error) = match verify_result {
        Some(Ok(())) => (true, None),
        Some(Err(err)) => (false, Some(err)),
        None => (false, Some("No server certificate verification outcome recorded.".to_string())),
    };

    let leaf = certificates.first();
    let days_remaining = leaf.map(|c| c.days_remaining);
    let hostname_match = leaf
        .map(|c| hostname_matches_cert(&display_host, c.common_name.as_deref(), &c.sans))
        .unwrap_or(false);

    let status = if certificates.is_empty() {
        "error".to_string()
    } else if !chain_valid || !hostname_match || days_remaining.unwrap_or(-1) <= 0 {
        "error".to_string()
    } else if days_remaining.unwrap_or(999) <= 30 {
        "warning".to_string()
    } else {
        "ok".to_string()
    };

    TlsReport {
        status,
        host: display_host,
        port,
        starttls: effective_starttls,
        protocol_version,
        cipher_suite,
        chain_valid,
        hostname_match,
        verification_error,
        days_remaining,
        handshake_ms,
        certificates,
        error: None,
    }
}

pub async fn inspect_tls(host: &str, port: u16, starttls: Option<&str>) -> TlsReport {
    let started = Instant::now();
    let trimmed = host.trim();
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return inspect_ip_tls(ip, port, None, starttls).await;
    }

    let normalized_host = match normalize_domain(trimmed) {
        Ok(d) => d,
        Err(e) => {
            return empty_tls_report(
                trimmed.to_string(),
                port,
                starttls.map(|s| s.to_string()),
                0,
                e,
            )
        }
    };

    let effective_starttls = match resolve_effective_starttls(port, starttls) {
        Ok(mode) => mode,
        Err(e) => {
            return empty_tls_report(
                normalized_host,
                port,
                starttls.map(|s| s.to_string()),
                0,
                e,
            )
        }
    };

    let server_name = match ServerName::try_from(normalized_host.clone()) {
        Ok(sn) => sn,
        Err(e) => {
            return empty_tls_report(
                normalized_host,
                port,
                effective_starttls,
                started.elapsed().as_millis() as u64,
                format!("Invalid TLS server name: {e}"),
            )
        }
    };

    let addr_target = format!("{normalized_host}:{port}");
    inspect_tls_with_connector(
        normalized_host,
        addr_target,
        server_name,
        port,
        effective_starttls,
        started,
    )
    .await
}

pub async fn inspect_ip_tls(
    ip: IpAddr,
    port: u16,
    sni_override: Option<&str>,
    starttls: Option<&str>,
) -> TlsReport {
    let started = Instant::now();
    let effective_starttls = match resolve_effective_starttls(port, starttls) {
        Ok(mode) => mode,
        Err(e) => {
            return empty_tls_report(
                ip.to_string(),
                port,
                starttls.map(|s| s.to_string()),
                0,
                e,
            )
        }
    };

    let display_host = sni_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| ip.to_string());

    let server_name = match sni_override.map(str::trim).filter(|s| !s.is_empty()) {
        Some(sni) => match ServerName::try_from(sni.to_string()) {
            Ok(sn) => sn,
            Err(_) => ServerName::IpAddress(ip.into()),
        },
        None => ServerName::IpAddress(ip.into()),
    };

    let sock = std::net::SocketAddr::new(ip, port);
    inspect_tls_with_connector(
        display_host,
        sock.to_string(),
        server_name,
        port,
        effective_starttls,
        started,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hostname_matches_cert_variants() {
        let sans = vec!["example.com".to_string(), "*.example.com".to_string()];
        assert!(hostname_matches_cert("example.com", None, &sans));
        assert!(hostname_matches_cert("WWW.Example.COM", None, &sans));
        assert!(hostname_matches_cert("api.example.com", None, &sans));
        assert!(!hostname_matches_cert("deep.api.example.com", None, &sans));
        assert!(!hostname_matches_cert("evil-example.com", None, &sans));

        // Fallback to CN when SAN list is empty
        assert!(hostname_matches_cert("mail.test.org", Some("mail.test.org"), &[]));
    }

    #[test]
    fn test_format_fingerprint() {
        let fp = format_fingerprint(b"hello");
        assert!(fp.contains(':'));
        assert_eq!(fp.split(':').count(), 32);
    }
}
