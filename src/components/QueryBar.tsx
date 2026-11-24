import { Search, Loader2, SlidersHorizontal, Globe } from "lucide-react";
import { useState, type FormEvent, type RefObject } from "react";
import type { RecordTypeName, ResolverId } from "../types/dns";

export const ALL_RECORD_TYPES: RecordTypeName[] = [
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

export const BUILTIN_RESOLVERS: { id: ResolverId; label: string; ip: string }[] = [
  { id: "cloudflare", label: "Cloudflare", ip: "1.1.1.1" },
  { id: "google", label: "Google", ip: "8.8.8.8" },
  { id: "quad9", label: "Quad9", ip: "9.9.9.9" },
  { id: "system", label: "System DNS", ip: "Local OS" },
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
  onSubmit: (overrideDomain?: string) => void;
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
  onSubmit,
  inputRef,
}: QueryBarProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);

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
            placeholder="Enter domain name (e.g. cloudflare.com) — Ctrl+K"
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

          <button
            type="submit"
            disabled={loading || !domain.trim()}
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
                Lookup DNS
              </>
            )}
          </button>
        </div>
      </div>

      <div className="mt-3 flex flex-wrap items-center justify-between gap-3 border-t border-line pt-3">
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-ink-muted">
            Types:
          </span>
          {ALL_RECORD_TYPES.map((type) => {
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
            onClick={() => onRecordTypesChange(ALL_RECORD_TYPES)}
            className="ml-1 text-xs text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
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
            return (
              <button
                key={res.id}
                type="button"
                onClick={() => toggleResolver(res.id)}
                title={res.ip}
                className={`rounded-md border px-2.5 py-1 text-xs font-medium transition ${
                  active
                    ? "border-emerald-500/50 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                    : "border-line bg-canvas text-ink-muted hover:border-line-strong hover:text-ink"
                }`}
              >
                {res.label}
              </button>
            );
          })}
        </div>
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
