use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Deserialize)]
pub struct QueryRequest {
    pub domain: String,
    pub record_types: Vec<String>,
    pub resolvers: Vec<String>,
    pub custom_resolver: Option<String>,
    pub dkim_selectors: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DnsRecordItem {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub class: String,
    pub value: String,
    pub details: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordTypeResult {
    pub record_type: String,
    /// "ok" | "no_records" | "nxdomain" | "error"
    pub status: String,
    pub latency_ms: u64,
    pub records: Vec<DnsRecordItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolverResult {
    pub id: String,
    pub label: String,
    pub address: String,
    pub total_latency_ms: u64,
    /// "ok" | "error"
    pub status: String,
    pub error: Option<String>,
    pub results: Vec<RecordTypeResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PropagationRow {
    pub record_type: String,
    /// "consistent" | "divergent" | "empty" | "partial_error"
    pub status: String,
    pub answers_by_resolver: BTreeMap<String, Vec<String>>,
    pub status_by_resolver: BTreeMap<String, String>,
    pub latency_by_resolver: BTreeMap<String, u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpfCheck {
    /// "pass" | "warn" | "fail" | "missing"
    pub status: String,
    pub summary: String,
    pub raw_record: Option<String>,
    pub mechanisms: Vec<String>,
    pub all_qualifier: Option<String>,
    pub dns_lookup_count: u32,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DmarcCheck {
    /// "pass" | "warn" | "fail" | "missing"
    pub status: String,
    pub summary: String,
    pub raw_record: Option<String>,
    pub policy: Option<String>,
    pub subdomain_policy: Option<String>,
    pub pct: Option<u8>,
    pub rua: Vec<String>,
    pub ruf: Vec<String>,
    pub adkim: Option<String>,
    pub aspf: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimSelectorResult {
    pub selector: String,
    pub found: bool,
    pub cname_target: Option<String>,
    pub raw_record: Option<String>,
    pub key_type: Option<String>,
    pub public_key_present: bool,
    /// "pass" | "warn" | "missing"
    pub status: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkimCheck {
    /// "pass" | "warn" | "fail" | "missing"
    pub status: String,
    pub summary: String,
    pub checked_selectors: Vec<String>,
    pub results: Vec<DkimSelectorResult>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnssecCheck {
    /// "pass" | "warn" | "fail" | "unsigned"
    pub status: String,
    pub summary: String,
    pub ds_records: Vec<String>,
    pub dnskey_records: Vec<String>,
    pub validated: bool,
    pub validation_error: Option<String>,
    pub issues: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityReport {
    pub spf: SpfCheck,
    pub dmarc: DmarcCheck,
    pub dkim: DkimCheck,
    pub dnssec: DnssecCheck,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    /// "ok" | "not_found" | "error"
    pub status: String,
    pub queried_domain: String,
    pub servers_queried: Vec<String>,
    pub latency_ms: u64,
    pub registrar: Option<String>,
    pub registrar_url: Option<String>,
    pub registrar_iana_id: Option<String>,
    pub created_date: Option<String>,
    pub updated_date: Option<String>,
    pub expiry_date: Option<String>,
    pub days_until_expiry: Option<i64>,
    pub registrant_org: Option<String>,
    pub registrant_country: Option<String>,
    pub abuse_email: Option<String>,
    pub abuse_phone: Option<String>,
    pub dnssec: Option<String>,
    pub statuses: Vec<String>,
    pub name_servers: Vec<String>,
    pub raw_text: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTech {
    pub name: String,
    pub category: String,
    pub version: Option<String>,
    /// "high" | "medium"
    pub confidence: String,
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpHeaderItem {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityHeaderStatus {
    pub name: String,
    pub present: bool,
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebsiteInfo {
    /// "ok" | "no_website" | "error"
    pub status: String,
    pub url: Option<String>,
    pub final_url: Option<String>,
    pub http_status: Option<u16>,
    pub https: bool,
    pub latency_ms: u64,
    pub title: Option<String>,
    pub description: Option<String>,
    pub generator: Option<String>,
    pub server: Option<String>,
    pub powered_by: Option<String>,
    pub content_type: Option<String>,
    pub technologies: Vec<DetectedTech>,
    pub wordpress_plugins: Vec<String>,
    pub security_headers: Vec<SecurityHeaderStatus>,
    pub response_headers: Vec<HttpHeaderItem>,
    pub script_urls: Vec<String>,
    pub stylesheet_urls: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlacklistEntry {
    pub list_name: String,
    pub zone: String,
    pub target: String,
    /// "Domain" | "Web IP (A)" | "Mail IP (MX)"
    pub target_role: String,
    /// "clean" | "listed" | "policy" | "blocked" | "error"
    pub status: String,
    pub return_codes: Vec<String>,
    pub detail: Option<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckItem {
    pub id: String,
    /// "Reputation" | "DNS" | "Email" | "Registration" | "Web"
    pub category: String,
    pub title: String,
    /// "pass" | "warn" | "fail" | "info"
    pub status: String,
    pub detail: String,
    pub points: u32,
    pub max_points: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainHealthReport {
    pub score: u32,
    /// "A+" | "A" | "B" | "C" | "D" | "F"
    pub grade: String,
    /// "healthy" | "caution" | "at_risk"
    pub overall_status: String,
    pub summary: String,
    /// "clean" | "caution" | "listed"
    pub spam_status: String,
    pub spam_summary: String,
    pub blacklists_checked: usize,
    pub blacklists_listed: usize,
    pub blacklists_blocked: usize,
    pub checked_ips: Vec<String>,
    pub domain_blacklists: Vec<BlacklistEntry>,
    pub ip_blacklists: Vec<BlacklistEntry>,
    pub checks: Vec<HealthCheckItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainItem {
    pub subdomain: String,
    pub live: bool,
    pub a_records: Vec<String>,
    pub aaaa_records: Vec<String>,
    pub cname: Option<String>,
    pub sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainSourceStatus {
    pub name: String,
    /// "ok" | "timeout" | "rate_limited" | "error"
    pub status: String,
    pub count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainDiscoveryReport {
    pub apex_domain: String,
    pub total_found: usize,
    pub live_count: usize,
    pub ct_only_count: usize,
    pub wildcard_detected: bool,
    pub wildcard_ips: Vec<String>,
    /// "ok" | "timeout" | "error"
    pub ct_status: String,
    pub ct_note: Option<String>,
    pub passive_sources: Vec<SubdomainSourceStatus>,
    pub probe_count: usize,
    pub latency_ms: u64,
    pub subdomains: Vec<SubdomainItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanItem {
    pub port: u16,
    pub service: String,
    pub category: String,
    /// "open" | "closed" | "filtered" | "error"
    pub status: String,
    pub latency_ms: u64,
    pub banner: Option<String>,
    /// "normal" | "caution" | "high"
    pub risk_level: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortScanReport {
    pub target_host: String,
    pub target_ip: Option<String>,
    pub available_ips: Vec<String>,
    pub open_count: usize,
    pub closed_count: usize,
    pub filtered_count: usize,
    pub total_checked: usize,
    pub latency_ms: u64,
    pub ports: Vec<PortScanItem>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsCertInfo {
    pub subject: String,
    pub common_name: Option<String>,
    pub issuer: String,
    pub issuer_org: Option<String>,
    pub sans: Vec<String>,
    pub not_before: String,
    pub not_after: String,
    pub days_remaining: i64,
    pub serial_hex: String,
    pub signature_algorithm: String,
    pub public_key_algorithm: String,
    pub public_key_bits: Option<u32>,
    pub sha256_fingerprint: String,
    pub is_ca: bool,
    pub is_self_signed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsReport {
    pub status: String,
    pub host: String,
    pub port: u16,
    pub starttls: Option<String>,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub chain_valid: bool,
    pub hostname_match: bool,
    pub verification_error: Option<String>,
    pub days_remaining: Option<i64>,
    pub handshake_ms: u64,
    pub certificates: Vec<TlsCertInfo>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpNetworkInfo {
    pub ip: String,
    pub ip_version: String,
    pub roles: Vec<String>,
    pub hostnames: Vec<String>,
    pub ptr_records: Vec<String>,
    pub asn: Option<u32>,
    pub as_org: Option<String>,
    pub cidr: Option<String>,
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub region: Option<String>,
    pub city: Option<String>,
    pub isp: Option<String>,
    pub provider_type: String,
    pub provider_name: Option<String>,
    pub is_anycast_cdn: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkReport {
    pub status: String,
    pub latency_ms: u64,
    pub ips: Vec<IpNetworkInfo>,
    pub unique_asns: usize,
    pub countries: Vec<String>,
    pub cdn_detected: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectHop {
    pub hop_index: usize,
    pub url: String,
    pub status_code: u16,
    pub status_text: String,
    pub location: Option<String>,
    pub resolved_next_url: Option<String>,
    pub latency_ms: u64,
    pub server: Option<String>,
    pub hsts: Option<String>,
    pub cache_control: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimingWaterfall {
    pub target_url: String,
    pub dns_ms: u64,
    pub tcp_ms: u64,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: u64,
    pub total_ms: u64,
    pub http_status: Option<u16>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectChain {
    pub label: String,
    pub start_url: String,
    pub final_url: String,
    pub final_status: Option<u16>,
    pub hop_count: usize,
    pub total_ms: u64,
    pub has_loop: bool,
    pub hops: Vec<RedirectHop>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedirectReport {
    pub status: String,
    pub canonical_url: Option<String>,
    pub http_to_https: bool,
    pub canonical_consistent: bool,
    pub hsts_present: bool,
    pub hsts_max_age: Option<u64>,
    pub hsts_include_subdomains: bool,
    pub hsts_preload: bool,
    pub chains: Vec<RedirectChain>,
    pub waterfall: Option<TimingWaterfall>,
    pub issues: Vec<String>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkDomainResult {
    pub domain: String,
    pub status: String,
    pub a_records: Vec<String>,
    pub mx_count: usize,
    pub ns_count: usize,
    pub http_status: Option<u16>,
    pub http_latency_ms: Option<u64>,
    pub final_url: Option<String>,
    pub ssl_valid: Option<bool>,
    pub ssl_days_remaining: Option<i64>,
    pub ssl_issuer: Option<String>,
    pub spf_status: String,
    pub dmarc_status: String,
    pub dnssec_status: String,
    pub registrar: Option<String>,
    pub domain_expiry_date: Option<String>,
    pub domain_days_remaining: Option<i64>,
    pub latency_ms: u64,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkProgressEvent {
    pub completed: usize,
    pub total: usize,
    pub result: BulkDomainResult,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorProbeRequest {
    pub target: String,
    pub mode: String,
    pub port: Option<u16>,
    pub resolver: Option<String>,
    pub record_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorProbeResult {
    pub timestamp: String,
    pub mode: String,
    pub target: String,
    pub status: String,
    pub total_ms: u64,
    pub dns_ms: Option<u64>,
    pub tcp_ms: Option<u64>,
    pub tls_ms: Option<u64>,
    pub ttfb_ms: Option<u64>,
    pub http_status: Option<u16>,
    pub resolved_values: Vec<String>,
    pub summary: String,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryProgressEvent {
    pub stage: String,
    pub label: String,
    pub status: String,
    pub elapsed_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQueryReport {
    pub domain: String,
    pub queried_at: String,
    pub resolvers: Vec<ResolverResult>,
    pub propagation: Vec<PropagationRow>,
    pub security: SecurityReport,
    pub tls: TlsReport,
    pub redirects: RedirectReport,
    pub network: NetworkReport,
    pub whois: WhoisInfo,
    pub website: WebsiteInfo,
    pub health: DomainHealthReport,
    pub subdomains: SubdomainDiscoveryReport,
    pub ports: PortScanReport,
}
