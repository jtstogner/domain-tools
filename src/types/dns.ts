export type RecordTypeName =
  | "A"
  | "AAAA"
  | "CNAME"
  | "MX"
  | "TXT"
  | "NS"
  | "SOA"
  | "CAA"
  | "SRV"
  | "HTTPS"
  | "SVCB"
  | "PTR"
  | "TLSA"
  | "SSHFP"
  | "NAPTR"
  | "DNSKEY"
  | "DS";

export type ResolverId =
  | "cloudflare"
  | "google"
  | "quad9"
  | "system"
  | "cloudflare_doh"
  | "google_doh"
  | "quad9_dot"
  | "custom";

export interface QueryRequest {
  domain: string;
  record_types: string[];
  resolvers: string[];
  custom_resolver: string | null;
  dkim_selectors: string[];
}

export interface DnsRecordItem {
  name: string;
  record_type: string;
  ttl: number;
  class: string;
  value: string;
  details: Record<string, unknown> | null;
}

export interface RecordTypeResult {
  record_type: string;
  status: "ok" | "no_records" | "nxdomain" | "error";
  latency_ms: number;
  records: DnsRecordItem[];
  error: string | null;
}

export interface ResolverResult {
  id: string;
  label: string;
  address: string;
  total_latency_ms: number;
  status: "ok" | "error";
  error: string | null;
  results: RecordTypeResult[];
}

export interface PropagationRow {
  record_type: string;
  status: "consistent" | "divergent" | "empty" | "partial_error";
  answers_by_resolver: Record<string, string[]>;
  status_by_resolver: Record<string, string>;
  latency_by_resolver: Record<string, number>;
}

export interface SpfLookupNode {
  mechanism: string;
  target: string;
  lookups_added: number;
  depth: number;
  raw_record: string | null;
  error: string | null;
  children: SpfLookupNode[];
}

export interface SpfCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  raw_record: string | null;
  mechanisms: string[];
  all_qualifier: string | null;
  dns_lookup_count: number;
  recursive_lookup_count: number;
  lookup_tree: SpfLookupNode[];
  flattened_ips?: string[];
  flattened_record?: string | null;
  duplicate_includes?: string[];
  issues: string[];
}

export interface DmarcCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  raw_record: string | null;
  policy: string | null;
  subdomain_policy: string | null;
  pct: number | null;
  rua: string[];
  ruf: string[];
  adkim: string | null;
  aspf: string | null;
  issues: string[];
}

export interface DkimSelectorResult {
  selector: string;
  found: boolean;
  cname_target: string | null;
  raw_record: string | null;
  key_type: string | null;
  public_key_present: boolean;
  status: "pass" | "warn" | "missing";
  notes: string[];
}

export interface DkimCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  checked_selectors: string[];
  results: DkimSelectorResult[];
  issues: string[];
}

export interface DnssecCheck {
  status: "pass" | "warn" | "fail" | "unsigned";
  summary: string;
  ds_records: string[];
  dnskey_records: string[];
  validated: boolean;
  validation_error: string | null;
  issues: string[];
}

export interface MtaStsCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  dns_record: string | null;
  policy_id: string | null;
  policy_fetched: boolean;
  mode: string | null;
  max_age: number | null;
  mx_patterns: string[];
  raw_policy: string | null;
  issues: string[];
}

export interface TlsRptCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  raw_record: string | null;
  rua: string[];
  issues: string[];
}

export interface BimiCheck {
  status: "pass" | "warn" | "missing";
  summary: string;
  raw_record: string | null;
  logo_url: string | null;
  authority_url: string | null;
  issues: string[];
}

export interface DaneTlsaRecord {
  mx_host: string;
  port: number;
  usage: number;
  usage_label: string;
  selector: number;
  selector_label: string;
  matching_type: number;
  matching_type_label: string;
  certificate_data: string;
  raw: string;
}

export interface DaneCheck {
  status: "pass" | "warn" | "missing";
  summary: string;
  mx_checked: string[];
  records: DaneTlsaRecord[];
  dnssec_required_met: boolean;
  issues: string[];
}

export interface SecurityReport {
  spf: SpfCheck;
  dmarc: DmarcCheck;
  dkim: DkimCheck;
  dnssec: DnssecCheck;
  mta_sts: MtaStsCheck;
  tls_rpt: TlsRptCheck;
  bimi: BimiCheck;
  dane?: DaneCheck;
}

export interface SmtpMxProbe {
  mx_host: string;
  priority: number;
  ip: string | null;
  ptr_records: string[];
  fcrdns_valid: boolean;
  banner_matches_ptr: boolean;
  reachable: boolean;
  banner: string | null;
  ehlo_extensions: string[];
  supports_starttls: boolean;
  starttls_negotiated: boolean;
  tls_version: string | null;
  tls_cert_valid: boolean | null;
  tls_cert_cn: string | null;
  tls_days_remaining: number | null;
  latency_ms: number;
  issues: string[];
  error: string | null;
}

export interface SmtpDeliverabilityReport {
  domain: string;
  mx_count: number;
  tested_count: number;
  port25_blocked_suspected: boolean;
  latency_ms: number;
  servers: SmtpMxProbe[];
  issues: string[];
}

export interface WhoisInfo {
  status: "ok" | "not_found" | "error";
  queried_domain: string;
  servers_queried: string[];
  latency_ms: number;
  registrar: string | null;
  registrar_url: string | null;
  registrar_iana_id: string | null;
  created_date: string | null;
  updated_date: string | null;
  expiry_date: string | null;
  days_until_expiry: number | null;
  registrant_org: string | null;
  registrant_country: string | null;
  abuse_email: string | null;
  abuse_phone: string | null;
  dnssec: string | null;
  statuses: string[];
  name_servers: string[];
  raw_text: string;
  error: string | null;
}

export interface DetectedTech {
  name: string;
  category: string;
  version: string | null;
  confidence: "high" | "medium";
  evidence: string;
}

export interface HttpHeaderItem {
  name: string;
  value: string;
}

export interface SecurityHeaderStatus {
  name: string;
  present: boolean;
  value: string | null;
}

export interface CookieAuditItem {
  name: string;
  secure: boolean;
  http_only: boolean;
  same_site: string | null;
  issues: string[];
}

export interface WebFileCheck {
  path: string;
  label: string;
  category: "hygiene" | "security" | "exposure";
  status: "found" | "missing" | "warn" | "exposed" | "error";
  http_status: number | null;
  summary: string;
  preview: string | null;
}

export interface WebSecurityAudit {
  cookies: CookieAuditItem[];
  cors_acao: string | null;
  cors_acac: boolean;
  cors_issue: string | null;
  mixed_content_urls: string[];
  files: WebFileCheck[];
  exposed_count: number;
}

export interface WebsiteInfo {
  status: "ok" | "no_website" | "error";
  url: string | null;
  final_url: string | null;
  http_status: number | null;
  https: boolean;
  http3_supported?: boolean;
  alt_svc?: string | null;
  latency_ms: number;
  title: string | null;
  description: string | null;
  generator: string | null;
  server: string | null;
  powered_by: string | null;
  content_type: string | null;
  technologies: DetectedTech[];
  wordpress_plugins: string[];
  security_headers: SecurityHeaderStatus[];
  response_headers: HttpHeaderItem[];
  script_urls: string[];
  stylesheet_urls: string[];
  security_audit: WebSecurityAudit | null;
  error: string | null;
}

export interface BlacklistEntry {
  list_name: string;
  zone: string;
  target: string;
  target_role: string;
  status: "clean" | "listed" | "policy" | "blocked" | "error";
  return_codes: string[];
  detail: string | null;
  delist_url: string | null;
  latency_ms: number;
}

export interface HealthCheckItem {
  id: string;
  category: string;
  title: string;
  status: "pass" | "warn" | "fail" | "info";
  severity: "critical" | "high" | "medium" | "low" | "info";
  detail: string;
  why_it_matters: string | null;
  remediation_steps: string[];
  suggested_snippet: string | null;
  snippet_label: string | null;
  reference_url: string | null;
  points: number;
  max_points: number;
}

export interface DomainHealthReport {
  score: number;
  grade: string;
  overall_status: "healthy" | "caution" | "at_risk";
  summary: string;
  spam_status: "clean" | "caution" | "listed";
  spam_summary: string;
  blacklists_checked: number;
  blacklists_listed: number;
  blacklists_blocked: number;
  checked_ips: string[];
  domain_blacklists: BlacklistEntry[];
  ip_blacklists: BlacklistEntry[];
  checks: HealthCheckItem[];
}

export interface TakeoverFinding {
  provider: string;
  cname_target: string;
  confidence: "high" | "medium";
  evidence: string;
  remediation: string;
}

export interface SubdomainItem {
  subdomain: string;
  live: boolean;
  a_records: string[];
  aaaa_records: string[];
  cname: string | null;
  sources: string[];
  takeover_risk: TakeoverFinding | null;
}

export interface SubdomainSourceStatus {
  name: string;
  status: "ok" | "timeout" | "rate_limited" | "error";
  count: number;
}

export interface SubdomainDiscoveryReport {
  apex_domain: string;
  total_found: number;
  live_count: number;
  ct_only_count: number;
  takeover_count: number;
  wildcard_detected: boolean;
  wildcard_ips: string[];
  ct_status: "ok" | "timeout" | "error";
  ct_note: string | null;
  passive_sources: SubdomainSourceStatus[];
  probe_count: number;
  latency_ms: number;
  subdomains: SubdomainItem[];
}

export interface PortScanItem {
  port: number;
  service: string;
  category: string;
  status: "open" | "closed" | "filtered" | "error";
  latency_ms: number;
  banner: string | null;
  risk_level: "normal" | "caution" | "high";
  note: string | null;
}

export interface PortScanReport {
  target_host: string;
  target_ip: string | null;
  available_ips: string[];
  open_count: number;
  closed_count: number;
  filtered_count: number;
  total_checked: number;
  latency_ms: number;
  ports: PortScanItem[];
  error: string | null;
}

export interface TlsCertInfo {
  subject: string;
  common_name: string | null;
  issuer: string;
  issuer_org: string | null;
  sans: string[];
  not_before: string;
  not_after: string;
  days_remaining: number;
  serial_hex: string;
  signature_algorithm: string;
  public_key_algorithm: string;
  public_key_bits: number | null;
  sha256_fingerprint: string;
  is_ca: boolean;
  is_self_signed: boolean;
}

export interface TlsReport {
  status: "ok" | "warning" | "error" | "unavailable";
  host: string;
  port: number;
  starttls: string | null;
  protocol_version: string | null;
  cipher_suite: string | null;
  chain_valid: boolean;
  hostname_match: boolean;
  verification_error: string | null;
  days_remaining: number | null;
  handshake_ms: number;
  certificates: TlsCertInfo[];
  error: string | null;
}

export interface IpNetworkInfo {
  ip: string;
  ip_version: "IPv4" | "IPv6";
  roles: string[];
  hostnames: string[];
  ptr_records: string[];
  asn: number | null;
  as_org: string | null;
  cidr: string | null;
  country: string | null;
  country_code: string | null;
  region: string | null;
  city: string | null;
  isp: string | null;
  provider_type: "CDN / Anycast" | "Cloud / Hosting" | "Mail Provider" | "Network";
  provider_name: string | null;
  is_anycast_cdn: boolean;
  rpki_status: "valid" | "invalid" | "not_found" | "unknown" | null;
  rpki_detail: string | null;
}

export interface NetworkReport {
  status: string;
  latency_ms: number;
  ips: IpNetworkInfo[];
  unique_asns: number;
  countries: string[];
  cdn_detected: string | null;
  error: string | null;
}

export interface TracerouteHop {
  hop: number;
  ip: string | null;
  hostname: string | null;
  rtt_ms: number[];
  avg_ms: number | null;
  timed_out: boolean;
}

export interface TracerouteReport {
  target: string;
  resolved_ip: string | null;
  tool_used: string;
  completed: boolean;
  latency_ms: number;
  hops: TracerouteHop[];
  error: string | null;
}

export interface CtLogEntry {
  id: number;
  issuer_name: string;
  issuer_org: string;
  common_name: string;
  sans: string[];
  not_before: string;
  not_after: string;
  is_expired: boolean;
  is_wildcard: boolean;
  serial_number: string;
}

export interface CtIssuerSummary {
  issuer_org: string;
  total_certs: number;
  active_certs: number;
  caa_authorized: boolean | null;
}

export interface CtHistoryReport {
  domain: string;
  total_certs: number;
  active_certs: number;
  expired_certs: number;
  wildcard_certs: number;
  caa_records: string[];
  unauthorized_issuers: string[];
  issuers: CtIssuerSummary[];
  entries: CtLogEntry[];
  latency_ms: number;
  error: string | null;
}

export interface DnsTraceHop {
  step: number;
  level: "Root" | "TLD" | "Authoritative" | "CNAME";
  zone: string;
  server_name: string;
  server_ip: string;
  rcode: string;
  authoritative: boolean;
  latency_ms: number;
  answers: string[];
  referrals: string[];
  glue_ips: string[];
  has_ds: boolean;
  has_rrsig: boolean;
  note: string | null;
}

export interface AuthoritativeNsCheck {
  nameserver: string;
  ip: string | null;
  reachable: boolean;
  authoritative: boolean;
  soa_serial: number | null;
  ns_records: string[];
  latency_ms: number;
  error: string | null;
}

export interface DnsTraceReport {
  domain: string;
  record_type: string;
  total_ms: number;
  hops: DnsTraceHop[];
  authoritative_checks: AuthoritativeNsCheck[];
  issues: string[];
  error: string | null;
}

export interface TyposquatCandidate {
  domain: string;
  fuzzer: string;
  registered: boolean;
  a_records: string[];
  aaaa_records: string[];
  mx_records: string[];
  ns_records: string[];
  risk_level: "high" | "medium" | "low" | "none";
  risk_reason: string;
}

export interface TyposquatReport {
  source_domain: string;
  total_generated: number;
  total_checked: number;
  registered_count: number;
  high_risk_count: number;
  active_web_count: number;
  latency_ms: number;
  candidates: TyposquatCandidate[];
}

export interface RedirectHop {
  hop_index: number;
  url: string;
  status_code: number;
  status_text: string;
  location: string | null;
  resolved_next_url: string | null;
  latency_ms: number;
  server: string | null;
  hsts: string | null;
  cache_control: string | null;
}

export interface TimingWaterfall {
  target_url: string;
  dns_ms: number;
  tcp_ms: number;
  tls_ms: number | null;
  ttfb_ms: number;
  total_ms: number;
  http_status: number | null;
  error: string | null;
}

export interface RedirectChain {
  label: string;
  start_url: string;
  final_url: string;
  final_status: number | null;
  hop_count: number;
  total_ms: number;
  has_loop: boolean;
  hops: RedirectHop[];
  error: string | null;
}

export interface RedirectReport {
  status: "ok" | "warning" | "error" | "unavailable";
  canonical_url: string | null;
  http_to_https: boolean;
  canonical_consistent: boolean;
  hsts_present: boolean;
  hsts_max_age: number | null;
  hsts_include_subdomains: boolean;
  hsts_preload: boolean;
  chains: RedirectChain[];
  waterfall: TimingWaterfall | null;
  issues: string[];
  latency_ms: number;
  error: string | null;
}

export interface BulkDomainResult {
  domain: string;
  status: "healthy" | "caution" | "issue" | "error";
  a_records: string[];
  aaaa_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  mx_count: number;
  ns_count: number;
  http_status: number | null;
  http_latency_ms: number | null;
  final_url: string | null;
  ssl_valid: boolean | null;
  ssl_days_remaining: number | null;
  ssl_issuer: string | null;
  spf_status: string;
  spf_record?: string | null;
  dmarc_status: string;
  dmarc_record?: string | null;
  dnssec_status: string;
  registrar: string | null;
  domain_expiry_date: string | null;
  domain_days_remaining: number | null;
  latency_ms: number;
  error: string | null;
}

export interface BulkProgressEvent {
  completed: number;
  total: number;
  result: BulkDomainResult;
}

export interface MonitorProbeRequest {
  target: string;
  mode: "https" | "tcp" | "dns";
  port?: number | null;
  resolver?: string | null;
  record_type?: string | null;
}

export interface MonitorProbeResult {
  timestamp: string;
  mode: "https" | "tcp" | "dns";
  target: string;
  status: "up" | "degraded" | "down";
  total_ms: number;
  dns_ms: number | null;
  tcp_ms: number | null;
  tls_ms: number | null;
  ttfb_ms: number | null;
  http_status: number | null;
  resolved_values: string[];
  summary: string;
  error: string | null;
}

export interface QueryProgressEvent {
  stage: string;
  label: string;
  status: "running" | "done";
  elapsed_ms: number | null;
}

export interface DnsOnlyResult {
  domain: string;
  resolver: ResolverResult;
}

export interface DnsQueryReport {
  domain: string;
  queried_at: string;
  resolvers: ResolverResult[];
  propagation: PropagationRow[];
  security: SecurityReport;
  tls: TlsReport;
  redirects: RedirectReport;
  network: NetworkReport;
  whois: WhoisInfo;
  website: WebsiteInfo;
  health: DomainHealthReport;
  subdomains: SubdomainDiscoveryReport;
  ports: PortScanReport;
}

export interface HistoryEntry {
  domain: string;
  queried_at: string;
  spfStatus: SpfCheck["status"];
  dmarcStatus: DmarcCheck["status"];
  dkimStatus: DkimCheck["status"];
  dnssecStatus: DnssecCheck["status"];
  totalRecords: number;
}

export interface StandaloneDnsblReport {
  target: string;
  target_kind: string;
  resolved_ips: string[];
  checked_count: number;
  listed_count: number;
  blocked_count: number;
  latency_ms: number;
  entries: BlacklistEntry[];
  error: string | null;
}

export interface TldAvailabilityItem {
  domain: string;
  tld: string;
  status: string;
  has_dns: boolean;
  registrar: string | null;
  expiry_date: string | null;
  latency_ms: number;
  detail: string | null;
}

export interface TldAvailabilityReport {
  base_name: string;
  checked_count: number;
  available_count: number;
  registered_count: number;
  latency_ms: number;
  items: TldAvailabilityItem[];
}

export interface RobotsFetchResult {
  domain: string;
  url: string;
  http_status: number | null;
  found: boolean;
  content: string;
  sitemaps: string[];
  latency_ms: number;
  error: string | null;
}

export interface PemDecodedItem {
  kind: string;
  subject: string;
  common_name: string | null;
  issuer: string | null;
  issuer_org: string | null;
  sans: string[];
  not_before: string | null;
  not_after: string | null;
  days_remaining: number | null;
  serial_hex: string | null;
  signature_algorithm: string;
  public_key_algorithm: string;
  public_key_bits: number | null;
  sha256_fingerprint: string;
  spki_sha256: string | null;
  is_ca: boolean;
  is_self_signed: boolean;
  tlsa_3_1_1: string | null;
  tlsa_3_0_1: string | null;
}

export interface PemDecodeReport {
  items: PemDecodedItem[];
  chain_order_valid: boolean | null;
  warnings: string[];
  error: string | null;
}

export interface IpAddressMeta {
  ip: string;
  ip_version: "IPv4" | "IPv6" | string;
  normalized: string;
  expanded: string | null;
  hex: string;
  integer: string;
  binary: string | null;
  scope: string;
  is_public: boolean;
  is_private: boolean;
  is_loopback: boolean;
  is_multicast: boolean;
  reverse_ptr_zone: string;
}

export interface IpPtrEntry {
  hostname: string;
  forward_ips: string[];
  fcrdns_valid: boolean;
  generic_pattern: string | null;
}

export interface IpBgpInfo {
  asn: number | null;
  as_org: string | null;
  as_holder: string | null;
  prefix: string | null;
  rir: string | null;
  allocated_date: string | null;
  country_code: string | null;
  provider_type: string;
  provider_name: string | null;
  is_anycast_cdn: boolean;
  rpki_status: "valid" | "invalid" | "not_found" | "unknown" | string | null;
  rpki_detail: string | null;
  announced: boolean | null;
  neighbors_left: number | null;
  neighbors_right: number | null;
  neighbors_uncertain: number | null;
  related_prefixes: string[];
}

export interface IpRdapInfo {
  status: "ok" | "not_found" | "skipped" | "error" | string;
  rdap_server: string | null;
  handle: string | null;
  net_name: string | null;
  net_type: string | null;
  parent_handle: string | null;
  start_address: string | null;
  end_address: string | null;
  cidrs: string[];
  country: string | null;
  org_name: string | null;
  abuse_email: string | null;
  abuse_phone: string | null;
  tech_email: string | null;
  registered_date: string | null;
  last_changed_date: string | null;
  statuses: string[];
  remarks: string[];
  error: string | null;
}

export interface IpGeoInfo {
  country: string | null;
  country_code: string | null;
  continent: string | null;
  region: string | null;
  city: string | null;
  postal: string | null;
  latitude: number | null;
  longitude: number | null;
  timezone: string | null;
  utc_offset: string | null;
  isp: string | null;
  org: string | null;
  domain: string | null;
  is_mobile: boolean | null;
  is_proxy_or_vpn: boolean | null;
  is_hosting: boolean | null;
  source: string | null;
}

export interface IpInternetDbInfo {
  indexed: boolean;
  ports: number[];
  hostnames: string[];
  cpes: string[];
  tags: string[];
  vulns: string[];
  error: string | null;
}

export interface IpReputationInfo {
  status: "clean" | "caution" | "listed" | "skipped" | string;
  is_tor_exit: boolean;
  blacklists_checked: number;
  blacklists_listed: number;
  blacklists_blocked: number;
  blacklists: BlacklistEntry[];
  internetdb: IpInternetDbInfo | null;
  signals: string[];
}

export interface IpHttpProbe {
  scheme: "https" | "http" | string;
  url: string;
  reachable: boolean;
  http_status: number | null;
  latency_ms: number;
  server: string | null;
  powered_by: string | null;
  location: string | null;
  title: string | null;
  content_type: string | null;
  alt_svc: string | null;
  http3_supported: boolean;
  waf_or_cdn_headers: string[];
  security_headers: SecurityHeaderStatus[];
  headers: HttpHeaderItem[];
  error: string | null;
}

export interface IpReachabilityInfo {
  reachable: boolean;
  probe_port: number | null;
  samples_ms: number[];
  min_ms: number | null;
  avg_ms: number | null;
  max_ms: number | null;
  packet_loss_pct: number;
}

export interface IpAssociatedHost {
  hostname: string;
  sources: string[];
}

export interface IpRiskFinding {
  severity: "critical" | "high" | "medium" | "low" | "info" | string;
  category: string;
  title: string;
  detail: string;
}

export interface IpDeepScanReport {
  ip: string;
  queried_at: string;
  latency_ms: number;
  posture: "clean" | "caution" | "elevated_risk" | string;
  exposure_risk: "low" | "medium" | "high" | string;
  summary: string;
  findings: IpRiskFinding[];
  meta: IpAddressMeta;
  ptr_records: IpPtrEntry[];
  fcrdns_overall: boolean | null;
  bgp: IpBgpInfo;
  rdap: IpRdapInfo;
  geo: IpGeoInfo;
  reputation: IpReputationInfo;
  ports: PortScanReport;
  reachability: IpReachabilityInfo;
  tls_reports: TlsReport[];
  http_probes: IpHttpProbe[];
  associated_hosts: IpAssociatedHost[];
  warnings: string[];
}
