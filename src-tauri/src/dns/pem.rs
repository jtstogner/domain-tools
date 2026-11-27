use std::net::{Ipv4Addr, Ipv6Addr};

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use x509_parser::certification_request::X509CertificationRequest;
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::pem::Pem;
use x509_parser::prelude::FromDer;
use x509_parser::public_key::PublicKey;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::models::{PemDecodeReport, PemDecodedItem};

fn sha256_hex_lower(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn sha256_colon_upper(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest
        .iter()
        .map(|b| format!("{b:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

fn friendly_sig_alg(oid: &str) -> String {
    match oid {
        "1.2.840.113549.1.1.5" => "SHA1 with RSA".to_string(),
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

fn extract_public_key_info(spki: &SubjectPublicKeyInfo<'_>) -> (String, Option<u32>) {
    match spki.parsed() {
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
            let oid = spki.algorithm.algorithm.to_id_string();
            if oid == "1.3.101.112" {
                ("Ed25519".to_string(), Some(256))
            } else if oid == "1.3.101.113" {
                ("Ed448".to_string(), Some(448))
            } else {
                (oid, None)
            }
        }
    }
}

fn format_general_name(gn: &GeneralName<'_>) -> Option<String> {
    match gn {
        GeneralName::DNSName(dns) => Some((*dns).to_string()),
        GeneralName::IPAddress(bytes) => {
            if bytes.len() == 4 {
                Some(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string())
            } else if bytes.len() == 16 {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(bytes);
                Some(Ipv6Addr::from(octets).to_string())
            } else {
                None
            }
        }
        GeneralName::RFC822Name(email) => Some(format!("email:{email}")),
        GeneralName::URI(uri) => Some(format!("uri:{uri}")),
        _ => None,
    }
}

fn decode_certificate_der(der: &[u8], warnings: &mut Vec<String>) -> Result<PemDecodedItem, String> {
    let (_, cert) =
        x509_parser::parse_x509_certificate(der).map_err(|e| format!("X.509 certificate parse error: {e}"))?;

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
            if let Some(val) = format_general_name(gn) {
                sans.push(val);
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
    let sig_oid = cert.signature_algorithm.algorithm.to_id_string();
    let signature_algorithm = friendly_sig_alg(&sig_oid);
    let (public_key_algorithm, public_key_bits) = extract_public_key_info(cert.public_key());

    let is_ca = cert
        .basic_constraints()
        .ok()
        .flatten()
        .map(|bc| bc.value.ca)
        .unwrap_or(false);
    let is_self_signed = cert.subject() == cert.issuer();

    let sha256_fingerprint = sha256_colon_upper(der);
    let cert_sha256_lower = sha256_hex_lower(der);
    let spki_sha256 = sha256_hex_lower(cert.public_key().raw);
    let tlsa_3_1_1 = format!("3 1 1 {spki_sha256}");
    let tlsa_3_0_1 = format!("3 0 1 {cert_sha256_lower}");

    let label = common_name.as_deref().unwrap_or(&subject);
    if days_remaining < 0 {
        warnings.push(format!(
            "Certificate '{label}' expired {} day(s) ago.",
            days_remaining.abs()
        ));
    } else if days_remaining <= 14 {
        warnings.push(format!(
            "Certificate '{label}' expires in {days_remaining} day(s)."
        ));
    }
    if sig_oid == "1.2.840.113549.1.1.5" {
        warnings.push(format!(
            "Certificate '{label}' uses deprecated SHA-1 signature algorithm."
        ));
    }
    if public_key_algorithm == "RSA" {
        if let Some(bits) = public_key_bits {
            if bits < 2048 {
                warnings.push(format!(
                    "Certificate '{label}' uses weak {bits}-bit RSA key (< 2048 bits)."
                ));
            }
        }
    }

    Ok(PemDecodedItem {
        kind: "CERTIFICATE".to_string(),
        subject,
        common_name,
        issuer: Some(issuer),
        issuer_org,
        sans,
        not_before: Some(not_before),
        not_after: Some(not_after),
        days_remaining: Some(days_remaining),
        serial_hex: Some(serial_hex),
        signature_algorithm,
        public_key_algorithm,
        public_key_bits,
        sha256_fingerprint,
        spki_sha256: Some(spki_sha256),
        is_ca,
        is_self_signed,
        tlsa_3_1_1: Some(tlsa_3_1_1),
        tlsa_3_0_1: Some(tlsa_3_0_1),
    })
}

fn decode_csr_der(der: &[u8], warnings: &mut Vec<String>) -> Result<PemDecodedItem, String> {
    let (_, csr) = X509CertificationRequest::from_der(der)
        .map_err(|e| format!("PKCS#10 CSR parse error: {e}"))?;

    let info = &csr.certification_request_info;
    let subject = info.subject.to_string();
    let common_name = info
        .subject
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(|s| s.to_string());

    let mut sans = Vec::new();
    if let Some(exts) = csr.requested_extensions() {
        for ext in exts {
            if let ParsedExtension::SubjectAlternativeName(san) = ext {
                for gn in &san.general_names {
                    if let Some(val) = format_general_name(gn) {
                        sans.push(val);
                    }
                }
            }
        }
    }

    let sig_oid = csr.signature_algorithm.algorithm.to_id_string();
    let signature_algorithm = friendly_sig_alg(&sig_oid);
    let (public_key_algorithm, public_key_bits) = extract_public_key_info(&info.subject_pki);

    let sha256_fingerprint = sha256_colon_upper(der);
    let spki_sha256 = sha256_hex_lower(info.subject_pki.raw);
    let tlsa_3_1_1 = format!("3 1 1 {spki_sha256}");

    let label = common_name.as_deref().unwrap_or(&subject);
    if public_key_algorithm == "RSA" {
        if let Some(bits) = public_key_bits {
            if bits < 2048 {
                warnings.push(format!(
                    "CSR '{label}' uses weak {bits}-bit RSA key (< 2048 bits)."
                ));
            }
        }
    }

    Ok(PemDecodedItem {
        kind: "CSR".to_string(),
        subject,
        common_name,
        issuer: None,
        issuer_org: None,
        sans,
        not_before: None,
        not_after: None,
        days_remaining: None,
        serial_hex: None,
        signature_algorithm,
        public_key_algorithm,
        public_key_bits,
        sha256_fingerprint,
        spki_sha256: Some(spki_sha256),
        is_ca: false,
        is_self_signed: false,
        tlsa_3_1_1: Some(tlsa_3_1_1),
        tlsa_3_0_1: None,
    })
}

fn normalize_pem_lines(pem_text: &str) -> String {
    pem_text
        .lines()
        .map(|line| line.trim())
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn decode_pem_blocks(pem_text: &str) -> PemDecodeReport {
    let trimmed = pem_text.trim();
    if trimmed.is_empty() {
        return PemDecodeReport {
            items: vec![],
            chain_order_valid: None,
            warnings: vec![],
            error: Some("Please paste a PEM-encoded certificate, certificate chain, or CSR.".to_string()),
        };
    }

    let normalized = normalize_pem_lines(trimmed);
    let mut items = Vec::new();
    let mut warnings = Vec::new();
    let mut parse_errors = Vec::new();
    let mut block_count = 0usize;

    for pem_res in Pem::iter_from_buffer(normalized.as_bytes()) {
        block_count += 1;
        let pem = match pem_res {
            Ok(p) => p,
            Err(e) => {
                parse_errors.push(format!("PEM block #{block_count} decode error: {e}"));
                continue;
            }
        };

        let label = pem.label.trim().to_ascii_uppercase();
        match label.as_str() {
            "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE" => {
                match decode_certificate_der(&pem.contents, &mut warnings) {
                    Ok(item) => items.push(item),
                    Err(e) => parse_errors.push(format!("Block #{block_count} ({label}): {e}")),
                }
            }
            "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => {
                match decode_csr_der(&pem.contents, &mut warnings) {
                    Ok(item) => items.push(item),
                    Err(e) => parse_errors.push(format!("Block #{block_count} ({label}): {e}")),
                }
            }
            l if l.contains("PRIVATE KEY") => {
                warnings.push(format!(
                    "Private key block ('{label}') detected and skipped for safety. Never share private keys."
                ));
            }
            _ => {
                warnings.push(format!("Skipped unsupported PEM block '{label}'."));
            }
        }
    }

    if block_count == 0 {
        return PemDecodeReport {
            items: vec![],
            chain_order_valid: None,
            warnings,
            error: Some(
                "No PEM blocks found. Expected -----BEGIN CERTIFICATE----- or -----BEGIN CERTIFICATE REQUEST-----."
                    .to_string(),
            ),
        };
    }

    let certs: Vec<&PemDecodedItem> = items
        .iter()
        .filter(|i| i.kind == "CERTIFICATE")
        .collect();

    let chain_order_valid = if certs.len() >= 2 {
        let mut all_linked = true;
        for idx in 0..certs.len() - 1 {
            let child = certs[idx];
            let parent = certs[idx + 1];
            if child.issuer.as_deref() != Some(parent.subject.as_str()) {
                all_linked = false;
                warnings.push(format!(
                    "Chain order mismatch between cert #{} (issuer: {}) and cert #{} (subject: {}).",
                    idx + 1,
                    child.issuer.as_deref().unwrap_or("<none>"),
                    idx + 2,
                    parent.subject
                ));
            }
        }
        Some(all_linked)
    } else {
        None
    };

    let error = if items.is_empty() && !parse_errors.is_empty() {
        Some(parse_errors.join("; "))
    } else {
        for err in parse_errors {
            warnings.push(err);
        }
        None
    };

    PemDecodeReport {
        items,
        chain_order_valid,
        warnings,
        error,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_pem_empty_and_invalid() {
        let empty = decode_pem_blocks("   ");
        assert!(empty.items.is_empty());
        assert!(empty.error.is_some());

        let no_blocks = decode_pem_blocks("just plain text without pem headers");
        assert!(no_blocks.items.is_empty());
        assert!(no_blocks.error.is_some());

        let bad_b64 = decode_pem_blocks(
            "-----BEGIN CERTIFICATE-----\n!!!not-base64!!!\n-----END CERTIFICATE-----",
        );
        assert!(bad_b64.items.is_empty());
        assert!(bad_b64.error.is_some());
    }

    #[test]
    fn test_decode_pem_skips_private_key_with_warning() {
        let key_pem = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----";
        let report = decode_pem_blocks(key_pem);
        assert!(report.items.is_empty());
        assert!(report.warnings.iter().any(|w| w.contains("Private key")));
    }

    #[test]
    fn test_decode_pem_valid_x509_certificate_and_tlsa() {
        // Minimal self-signed X.509 v3 cert (DER encoded) using x509-parser test vector / real cert
        // Generate DER via a well-known valid ASN.1 X.509 certificate (CN=example.com)
        let cert_pem = "\
-----BEGIN CERTIFICATE-----
MIIBfzCCASWgAwIBAgIJAJ1p7m8yQ9nFMAoGCCqGSM49BAMCMBYxFDASBgNVBAMM
C2V4YW1wbGUuY29tMB4XDTI1MDEwMTAwMDAwMFoXDTM1MDEwMTAwMDAwMFowFjEU
MBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS1
sJ7+8X9gS0v8F0M1Y2Y3Y4Y5Y6Y7Y8Y9Z0Z1Z2Z3Z4Z5Z6Z7Z8Z9a0a1a2a3a4a5
a6a7a8a9b0b1b2b3b4b5b6b7o1MwUTAdBgNVHQ4EFgQUAAAAAAAAAAAAAAAAAAAA
AAAAAAAAMAwGA1UdEwEB/wQCMAAwIgYDVR0RBBswGYILZXhhbXBsZS5jb22CCnd3
dy5leC5jb20wCgYIKoZIzj0EAwIDSQAwRgIhAMAAAAAAAAAAAAAAAAAAAAAAAAAA
AAAAAAAAAAAAAAIhANAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
-----END CERTIFICATE-----";
        // Note: if base64 has invalid length, we verify via a properly constructed DER cert below.
        let _ = cert_pem;

        // Build a valid minimal DER X.509 v3 certificate in code so test is 100% deterministic & self-contained!
        fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 128 {
                out.push(content.len() as u8);
            } else if content.len() < 256 {
                out.push(0x81);
                out.push(content.len() as u8);
            } else {
                out.push(0x82);
                out.push((content.len() >> 8) as u8);
                out.push((content.len() & 0xff) as u8);
            }
            out.extend_from_slice(content);
            out
        }
        fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
            let mut body = Vec::new();
            for p in parts {
                body.extend_from_slice(p);
            }
            der_tlv(0x30, &body)
        }
        fn der_oid(bytes: &[u8]) -> Vec<u8> {
            der_tlv(0x06, bytes)
        }
        fn der_name_cn(cn: &str) -> Vec<u8> {
            // OID 2.5.4.3 = 55 04 03
            let atv = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0c, cn.as_bytes())]);
            let rdn = der_tlv(0x31, &atv);
            der_seq(&[rdn])
        }
        fn build_test_cert_der(subject_cn: &str, issuer_cn: &str, san_dns: Option<&str>) -> Vec<u8> {
            // Version v3: [0] EXPLICIT INTEGER 2
            let version = der_tlv(0xa0, &der_tlv(0x02, &[2]));
            let serial = der_tlv(0x02, &[0x01, 0x23, 0x45]);
            // ecdsa-with-SHA256: 1.2.840.10045.4.3.2 -> 2a 86 48 ce 3d 04 03 02
            let sig_alg = der_seq(&[der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
            let issuer = der_name_cn(issuer_cn);
            // Validity: 2025-01-01 to 2035-01-01 (UTCTime)
            let validity = der_seq(&[
                der_tlv(0x17, b"250101000000Z"),
                der_tlv(0x17, b"350101000000Z"),
            ]);
            let subject = der_name_cn(subject_cn);
            // SPKI: id-ecPublicKey (1.2.840.10045.2.1) + prime256v1 (1.2.840.10045.3.1.7)
            let spki_alg = der_seq(&[
                der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
                der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
            ]);
            let mut ec_point = vec![0x00, 0x04]; // 0 unused bits + uncompressed EC point (65 bytes)
            ec_point.extend_from_slice(&[0x11u8; 64]);
            let spki = der_seq(&[spki_alg, der_tlv(0x03, &ec_point)]);

            let mut tbs_parts = vec![version, serial, sig_alg.clone(), issuer, validity, subject, spki];
            if let Some(dns) = san_dns {
                // SAN OID 2.5.29.17 -> 55 1d 11
                let general_names = der_seq(&[der_tlv(0x82, dns.as_bytes())]);
                let san_ext = der_seq(&[
                    der_oid(&[0x55, 0x1d, 0x11]),
                    der_tlv(0x04, &general_names),
                ]);
                let exts = der_tlv(0xa3, &der_seq(&[san_ext]));
                tbs_parts.push(exts);
            }
            let tbs = der_seq(&tbs_parts);
            let sig_val = der_tlv(0x03, &[0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
            der_seq(&[tbs, sig_alg, sig_val])
        }
        fn to_pem(label: &str, der: &[u8]) -> String {
            const TABLE: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut b64 = String::new();
            for chunk in der.chunks(3) {
                let b0 = chunk[0] as u32;
                let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
                let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
                let n = (b0 << 16) | (b1 << 8) | b2;
                b64.push(TABLE[((n >> 18) & 63) as usize] as char);
                b64.push(TABLE[((n >> 12) & 63) as usize] as char);
                b64.push(if chunk.len() > 1 {
                    TABLE[((n >> 6) & 63) as usize] as char
                } else {
                    '='
                });
                b64.push(if chunk.len() > 2 {
                    TABLE[(n & 63) as usize] as char
                } else {
                    '='
                });
            }
            format!("-----BEGIN {label}-----\n{b64}\n-----END {label}-----")
        }

        let leaf_der = build_test_cert_der("example.com", "Test Intermediate CA", Some("www.example.com"));
        let ca_der = build_test_cert_der("Test Intermediate CA", "Test Intermediate CA", None);

        let chain_pem = format!(
            "{}\n{}\n",
            to_pem("CERTIFICATE", &leaf_der),
            to_pem("CERTIFICATE", &ca_der)
        );
        let report = decode_pem_blocks(&chain_pem);
        assert!(report.error.is_none(), "unexpected error: {:?}", report.error);
        assert_eq!(report.items.len(), 2);
        assert_eq!(report.chain_order_valid, Some(true));

        let leaf = &report.items[0];
        assert_eq!(leaf.kind, "CERTIFICATE");
        assert_eq!(leaf.common_name.as_deref(), Some("example.com"));
        assert_eq!(leaf.sans, vec!["www.example.com"]);
        assert_eq!(leaf.public_key_algorithm, "ECDSA");
        assert_eq!(leaf.public_key_bits, Some(256));
        assert_eq!(leaf.signature_algorithm, "ECDSA with SHA256");
        assert!(leaf.tlsa_3_1_1.as_deref().unwrap().starts_with("3 1 1 "));
        assert!(leaf.tlsa_3_0_1.as_deref().unwrap().starts_with("3 0 1 "));
        assert!(!leaf.is_self_signed);
        assert!(report.items[1].is_self_signed);

        // Reversed chain should report chain_order_valid = Some(false)
        let reversed_pem = format!(
            "{}\n{}\n",
            to_pem("CERTIFICATE", &ca_der),
            to_pem("CERTIFICATE", &leaf_der)
        );
        let rev_report = decode_pem_blocks(&reversed_pem);
        assert_eq!(rev_report.chain_order_valid, Some(false));
        assert!(rev_report.warnings.iter().any(|w| w.contains("Chain order mismatch")));
    }

    #[test]
    fn test_decode_pem_csr() {
        fn der_tlv(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            if content.len() < 128 {
                out.push(content.len() as u8);
            } else {
                out.push(0x81);
                out.push(content.len() as u8);
            }
            out.extend_from_slice(content);
            out
        }
        fn der_seq(parts: &[Vec<u8>]) -> Vec<u8> {
            let mut body = Vec::new();
            for p in parts {
                body.extend_from_slice(p);
            }
            der_tlv(0x30, &body)
        }
        fn der_oid(bytes: &[u8]) -> Vec<u8> {
            der_tlv(0x06, bytes)
        }
        // Build minimal valid PKCS#10 CSR for CN=csr.example.org
        let version = der_tlv(0x02, &[0]);
        let atv = der_seq(&[der_oid(&[0x55, 0x04, 0x03]), der_tlv(0x0c, b"csr.example.org")]);
        let subject = der_seq(&[der_tlv(0x31, &atv)]);
        let spki_alg = der_seq(&[
            der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]),
            der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]),
        ]);
        let mut ec_point = vec![0x00, 0x04];
        ec_point.extend_from_slice(&[0x22u8; 64]);
        let spki = der_seq(&[spki_alg, der_tlv(0x03, &ec_point)]);
        let attrs = der_tlv(0xa0, &[]);
        let cri = der_seq(&[version, subject, spki, attrs]);
        let sig_alg = der_seq(&[der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02])]);
        let sig_val = der_tlv(0x03, &[0x00, 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01]);
        let csr_der = der_seq(&[cri, sig_alg, sig_val]);

        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut b64 = String::new();
        for chunk in csr_der.chunks(3) {
            let b0 = chunk[0] as u32;
            let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
            let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
            let n = (b0 << 16) | (b1 << 8) | b2;
            b64.push(TABLE[((n >> 18) & 63) as usize] as char);
            b64.push(TABLE[((n >> 12) & 63) as usize] as char);
            b64.push(if chunk.len() > 1 { TABLE[((n >> 6) & 63) as usize] as char } else { '=' });
            b64.push(if chunk.len() > 2 { TABLE[(n & 63) as usize] as char } else { '=' });
        }
        let csr_pem = format!(
            "-----BEGIN CERTIFICATE REQUEST-----\n{b64}\n-----END CERTIFICATE REQUEST-----"
        );
        let report = decode_pem_blocks(&csr_pem);
        assert!(report.error.is_none(), "unexpected error: {:?}", report.error);
        assert_eq!(report.items.len(), 1);
        assert_eq!(report.chain_order_valid, None);
        let item = &report.items[0];
        assert_eq!(item.kind, "CSR");
        assert_eq!(item.common_name.as_deref(), Some("csr.example.org"));
        assert!(item.issuer.is_none());
        assert!(item.tlsa_3_1_1.is_some());
        assert!(item.tlsa_3_0_1.is_none());
    }
}
