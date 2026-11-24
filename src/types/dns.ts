export type RecordTypeName =
  | "A"
  | "AAAA"
  | "CNAME"
  | "MX"
  | "TXT"
  | "NS"
  | "SOA"
  | "CAA"
  | "SRV";

export type ResolverId =
  | "cloudflare"
  | "google"
  | "quad9"
  | "system"
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

export interface SpfCheck {
  status: "pass" | "warn" | "fail" | "missing";
  summary: string;
  raw_record: string | null;
  mechanisms: string[];
  all_qualifier: string | null;
  dns_lookup_count: number;
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

export interface SecurityReport {
  spf: SpfCheck;
  dmarc: DmarcCheck;
  dkim: DkimCheck;
  dnssec: DnssecCheck;
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

export interface WebsiteInfo {
  status: "ok" | "no_website" | "error";
  url: string | null;
  final_url: string | null;
  http_status: number | null;
  https: boolean;
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
  latency_ms: number;
}

export interface HealthCheckItem {
  id: string;
  category: string;
  title: string;
  status: "pass" | "warn" | "fail" | "info";
  detail: string;
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

export interface SubdomainItem {
  subdomain: string;
  live: boolean;
  a_records: string[];
  aaaa_records: string[];
  cname: string | null;
  sources: string[];
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
  wildcard_detected: boolean;
  wildcard_ips: string[];
  ct_status: "ok" | "timeout" | "error";
  ct_note: string | null;
  passive_sources: SubdomainSourceStatus[];
  probe_count: number;
  latency_ms: number;
  subdomains: SubdomainItem[];
}

export interface DnsQueryReport {
  domain: string;
  queried_at: string;
  resolvers: ResolverResult[];
  propagation: PropagationRow[];
  security: SecurityReport;
  whois: WhoisInfo;
  website: WebsiteInfo;
  health: DomainHealthReport;
  subdomains: SubdomainDiscoveryReport;
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
