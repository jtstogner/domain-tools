import {
  ChevronDown,
  ChevronUp,
  Globe,
  Loader2,
  Lock,
  RefreshCw,
  Search,
  SlidersHorizontal,
} from "lucide-react";
import { useState, type FormEvent, type KeyboardEvent, type RefObject } from "react";
import type { RecordTypeName, ResolverId } from "../types/dns";

export const STANDARD_RECORD_TYPES: RecordTypeName[] = [
  "A",
  "AAAA",
  "CNAME",
  "MX",
  "TXT",
  "NS",
  "SOA",
  "CAA",
  "SRV",
];

export const EXTENDED_RECORD_TYPES: RecordTypeName[] = [
  "HTTPS",
  "SVCB",
  "PTR",
  "TLSA",
  "SSHFP",
  "NAPTR",
  "DNSKEY",
  "DS",
];

export const ALL_RECORD_TYPES: RecordTypeName[] = [
  ...STANDARD_RECORD_TYPES,
  ...EXTENDED_RECORD_TYPES,
];

export const BUILTIN_RESOLVERS: {
  id: ResolverId;
  label: string;
  ip: string;
  encrypted?: "DoH" | "DoT";
}[] = [
  { id: "cloudflare", label: "Cloudflare", ip: "1.1.1.1" },
  { id: "google", label: "Google", ip: "8.8.8.8" },
  { id: "quad9", label: "Quad9", ip: "9.9.9.9" },
  { id: "system", label: "System DNS", ip: "Local OS" },
  {
    id: "cloudflare_doh",
    label: "Cloudflare DoH",
    ip: "https://1.1.1.1/dns-query",
    encrypted: "DoH",
  },
  {
    id: "google_doh",
    label: "Google DoH",
    ip: "https://dns.google/dns-query",
    encrypted: "DoH",
  },
  {
    id: "quad9_dot",
    label: "Quad9 DoT",
    ip: "tls://9.9.9.9:853",
    encrypted: "DoT",
  },
];

const SAMPLE_DOMAINS = ["cloudflare.com", "google.com", "github.com"];

interface QueryBarProps {
  domain: string;
  onDomainChange: (v: string) => void;
  recordTypes: RecordTypeName[];
  onRecordTypesChange: (types: RecordTypeName[]) => void;
  resolvers: ResolverId[];
  onResolversChange: (resolvers: ResolverId[]) => void;
  customResolver: string;
  onCustomResolverChange: (v: string) => void;
  dkimSelectorsInput: string;
  onDkimSelectorsInputChange: (v: string) => void;
  loading: boolean;
  activeDomain?: string;
  onSubmit: (overrideDomain?: string, options?: { forceRefresh?: boolean }) => void;
  inputRef: RefObject<HTMLInputElement | null>;
}

export function QueryBar({
  domain,
  onDomainChange,
  recordTypes,
  onRecordTypesChange,
  resolvers,
  onResolversChange,
  customResolver,
  onCustomResolverChange,
  dkimSelectorsInput,
  onDkimSelectorsInputChange,
  loading,
  activeDomain,
  onSubmit,
  inputRef,
}: QueryBarProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [showExtendedTypes, setShowExtendedTypes] = useState(false);

  const activeExtendedCount = EXTENDED_RECORD_TYPES.filter((t) =>
    recordTypes.includes(t),
  ).length;

  const toggleRecordType = (type: RecordTypeName) => {
    if (recordTypes.includes(type)) {
      if (recordTypes.length > 1) {
        onRecordTypesChange(recordTypes.filter((t) => t !== type));
      }
    } else {
      onRecordTypesChange([...recordTypes, type]);
    }
  };

  const toggleResolver = (id: ResolverId) => {
    if (resolvers.includes(id)) {
      if (resolvers.length > 1 || customResolver.trim().length > 0) {
        onResolversChange(resolvers.filter((r) => r !== id));
      }
    } else {
      onResolversChange([...resolvers, id]);
    }
  };

  const handleFormSubmit = (e: FormEvent) => {
    e.preventDefault();
    onSubmit();
  };

  const handleInputKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter" && e.shiftKey) {
      e.preventDefault();
      if (!loading && domain.trim()) {
        onSubmit(undefined, { forceRefresh: true });
      }
    }
  };

  const normalizedInput = domain
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .replace(/\.$/, "");
  const isSameAsActive = Boolean(
    activeDomain && normalizedInput && activeDomain.toLowerCase() === normalizedInput,
  );

  return (
    <form
      onSubmit={handleFormSubmit}
      className="rounded-xl border border-line bg-surface p-4 shadow-sm shadow-slate-900/5 dark:shadow-lg dark:shadow-black/30"
    >
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
        <div className="relative flex-1">
          <Globe className="pointer-events-none absolute left-3.5 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-muted" />
          <input
            ref={inputRef}
            type="text"
            value={domain}
            onChange={(e) => onDomainChange(e.target.value)}
            onKeyDown={handleInputKeyDown}
            placeholder="Enter domain name (e.g. cloudflare.com) — Ctrl+K · Shift+Enter to force refresh"
            spellCheck={false}
            autoCapitalize="none"
            autoComplete="off"
            className="w-full rounded-lg border border-line-strong bg-canvas py-2.5 pl-10 pr-4 font-mono text-sm text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none focus:ring-2 focus:ring-sky-500/20"
          />
        </div>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowAdvanced((v) => !v)}
            className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-2.5 text-xs font-medium transition ${
              showAdvanced
                ? "border-sky-500/60 bg-sky-500/10 text-sky-700 dark:text-sky-300"
                : "border-line-strong bg-surface-alt text-ink-secondary hover:border-slate-400 hover:text-ink dark:hover:border-slate-600"
            }`}
          >
            <SlidersHorizontal className="h-3.5 w-3.5" />
            Options
          </button>

          {activeDomain && domain.trim() && (
            <button
              type="button"
              disabled={loading}
              onClick={() => onSubmit(undefined, { forceRefresh: true })}
              title="Force fresh live query bypassing cache (Shift+Enter)"
              className="inline-flex items-center gap-1.5 rounded-lg border border-line-strong bg-surface-alt px-3 py-2.5 text-xs font-medium text-ink-secondary transition hover:border-sky-500/50 hover:text-sky-600 disabled:cursor-not-allowed disabled:opacity-50 dark:hover:text-sky-300"
            >
              <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
              <span className="hidden sm:inline">Force Refresh</span>
            </button>
          )}

          <button
            type="submit"
            disabled={loading || !domain.trim()}
            title={
              isSameAsActive
                ? "Re-query live DNS for the active domain"
                : "Lookup DNS (Shift+Enter to bypass cache)"
            }
            className="inline-flex items-center gap-2 rounded-lg bg-sky-600 px-5 py-2.5 text-sm font-semibold text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50 dark:bg-sky-500 dark:text-slate-950 dark:hover:bg-sky-400"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                Querying...
              </>
            ) : (
              <>
                <Search className="h-4 w-4" />
                {isSameAsActive ? "Refresh Live" : "Lookup DNS"}
              </>
            )}
          </button>
        </div>
      </div>

      <div className="mt-3 flex flex-col gap-2.5 border-t border-line pt-3">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
              Types:
            </span>
            {STANDARD_RECORD_TYPES.map((type) => {
              const active = recordTypes.includes(type);
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => toggleRecordType(type)}
                  className={`rounded-md border px-2 py-1 font-mono text-xs font-medium transition ${
                    active
                      ? "border-sky-500/60 bg-sky-500/15 text-sky-700 dark:text-sky-300"
                      : "border-line bg-canvas text-ink-muted hover:border-line-strong hover:text-ink"
                  }`}
                >
                  {type}
                </button>
              );
            })}
            <button
              type="button"
              onClick={() => setShowExtendedTypes((v) => !v)}
              className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium transition ${
                showExtendedTypes || activeExtendedCount > 0
                  ? "border-violet-500/50 bg-violet-500/10 text-violet-700 dark:text-violet-300"
                  : "border-line bg-surface-alt text-ink-muted hover:border-line-strong hover:text-ink"
              }`}
            >
              <span>
                + Extended{activeExtendedCount > 0 ? ` (${activeExtendedCount})` : ""}
              </span>
              {showExtendedTypes ? (
                <ChevronUp className="h-3 w-3" />
              ) : (
                <ChevronDown className="h-3 w-3" />
              )}
            </button>
            <span className="mx-0.5 text-line-strong">|</span>
            <button
              type="button"
              onClick={() => onRecordTypesChange(STANDARD_RECORD_TYPES)}
              className="text-xs text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
            >
              Standard
            </button>
            <button
              type="button"
              onClick={() => {
                onRecordTypesChange(ALL_RECORD_TYPES);
                setShowExtendedTypes(true);
              }}
              className="text-xs text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
            >
              All
            </button>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
              Resolvers:
            </span>
            {BUILTIN_RESOLVERS.map((res) => {
              const active = resolvers.includes(res.id);
              const title = res.encrypted
                ? `Encrypted ${res.encrypted} (${res.ip})`
                : res.ip;
              return (
                <button
                  key={res.id}
                  type="button"
                  onClick={() => toggleResolver(res.id)}
                  title={title}
                  className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 text-xs font-medium transition ${
                    active
                      ? res.encrypted
                        ? "border-teal-500/50 bg-teal-500/15 text-teal-700 dark:text-teal-300"
                        : "border-emerald-500/50 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                      : "border-line bg-canvas text-ink-muted hover:border-line-strong hover:text-ink"
                  }`}
                >
                  {res.encrypted && <Lock className="h-3 w-3 opacity-80" />}
                  {res.label}
                </button>
              );
            })}
          </div>
        </div>

        {showExtendedTypes && (
          <div className="flex flex-wrap items-center gap-1.5 rounded-lg border border-line bg-surface-alt/60 px-2.5 py-2">
            <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
              Extended:
            </span>
            {EXTENDED_RECORD_TYPES.map((type) => {
              const active = recordTypes.includes(type);
              return (
                <button
                  key={type}
                  type="button"
                  onClick={() => toggleRecordType(type)}
                  className={`rounded-md border px-2 py-0.5 font-mono text-xs font-medium transition ${
                    active
                      ? "border-violet-500/60 bg-violet-500/15 text-violet-700 dark:text-violet-300"
                      : "border-line bg-canvas text-ink-muted hover:border-line-strong hover:text-ink"
                  }`}
                >
                  {type}
                </button>
              );
            })}
          </div>
        )}
      </div>

      {showAdvanced && (
        <div className="mt-3 grid grid-cols-1 gap-3 border-t border-line pt-3 md:grid-cols-2">
          <div>
            <label className="mb-1 block text-xs font-medium text-ink-secondary">
              Custom DNS Resolver IP (optional)
            </label>
            <input
              type="text"
              value={customResolver}
              onChange={(e) => onCustomResolverChange(e.target.value)}
              placeholder="e.g. 94.140.14.14 or 1.1.1.1:53"
              className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-xs font-medium text-ink-secondary">
              DKIM Selectors (comma-separated, optional)
            </label>
            <input
              type="text"
              value={dkimSelectorsInput}
              onChange={(e) => onDkimSelectorsInputChange(e.target.value)}
              placeholder="Leave blank for auto-probe (google, selector1, k1, default...)"
              className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-2 font-mono text-xs text-ink placeholder:text-ink-muted/70 focus:border-sky-500 focus:outline-none"
            />
          </div>
        </div>
      )}

      <div className="mt-2.5 flex flex-wrap items-center gap-2 text-xs text-ink-muted">
        <span>Quick examples:</span>
        {SAMPLE_DOMAINS.map((sample) => (
          <button
            key={sample}
            type="button"
            onClick={() => {
              onDomainChange(sample);
              onSubmit(sample);
            }}
            className="rounded border border-line bg-canvas px-2 py-0.5 font-mono text-[11px] text-ink-muted transition hover:border-line-strong hover:text-sky-600 dark:hover:text-sky-300"
          >
            {sample}
          </button>
        ))}
      </div>
    </form>
  );
}
