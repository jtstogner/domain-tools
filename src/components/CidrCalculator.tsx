import { Copy } from "lucide-react";
import { useEffect, useMemo, useState } from "react";
import { copyToClipboard } from "../lib/api";
import { calculateCidr, cidrToSpfToken, ipToReversePtr, isIpInCidr } from "../lib/cidr";

export interface CidrCalculatorProps {
  initialCidr?: string;
  initialTestIp?: string;
  onNotify: (msg: string) => void;
}

const CIDR_PRESETS: Array<{ label: string; cidr: string; ip: string }> = [
  { label: "RFC 5737 /24", cidr: "192.0.2.0/24", ip: "192.0.2.44" },
  { label: "RFC 1918 /16", cidr: "10.10.0.0/16", ip: "10.10.42.15" },
  { label: "Cloudflare /14", cidr: "104.16.0.0/14", ip: "104.16.132.229" },
  { label: "IPv6 /48", cidr: "2001:db8::/48", ip: "2001:db8::1" },
];

export function CidrCalculator({
  initialCidr,
  initialTestIp,
  onNotify,
}: CidrCalculatorProps) {
  const [cidrInput, setCidrInput] = useState(initialCidr?.trim() || "192.0.2.0/24");
  const [testIpInput, setTestIpInput] = useState(
    initialTestIp !== undefined ? initialTestIp : initialCidr ? "" : "192.0.2.44",
  );

  useEffect(() => {
    if (initialCidr && initialCidr.trim()) {
      setCidrInput(initialCidr.trim());
    }
  }, [initialCidr]);

  useEffect(() => {
    if (initialTestIp !== undefined) {
      setTestIpInput(initialTestIp);
    }
  }, [initialTestIp]);

  const cidrResult = useMemo(() => calculateCidr(cidrInput), [cidrInput]);
  const ipMatch = useMemo(() => {
    if (!testIpInput.trim()) return null;
    return isIpInCidr(cidrInput, testIpInput);
  }, [cidrInput, testIpInput]);
  const reversePtr = useMemo(
    () => ipToReversePtr(testIpInput.trim() || cidrInput),
    [testIpInput, cidrInput],
  );
  const spfToken = useMemo(() => cidrToSpfToken(cidrInput), [cidrInput]);

  const copyText = async (text: string, label: string) => {
    await copyToClipboard(text);
    onNotify(`Copied ${label}`);
  };

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-line bg-surface p-4 space-y-3">
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
          <div>
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              IPv4 or IPv6 CIDR Block
            </label>
            <input
              type="text"
              value={cidrInput}
              onChange={(e) => setCidrInput(e.target.value)}
              placeholder="e.g. 192.0.2.0/24 or 2001:db8::/48"
              className="w-full rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
            />
          </div>
          <div>
            <label className="mb-1 block text-[11px] font-medium text-ink-muted">
              Single IP for Reverse PTR &amp; Membership Test
            </label>
            <div className="flex items-center gap-2">
              <input
                type="text"
                value={testIpInput}
                onChange={(e) => setTestIpInput(e.target.value)}
                placeholder="e.g. 192.0.2.44"
                className="flex-1 rounded-lg border border-line-strong bg-canvas px-3 py-1.5 font-mono text-xs text-ink focus:border-sky-500 focus:outline-none"
              />
              {ipMatch !== null && (
                <span
                  className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold ${
                    ipMatch
                      ? "border-emerald-500/40 bg-emerald-500/15 text-emerald-700 dark:text-emerald-300"
                      : "border-rose-500/40 bg-rose-500/15 text-rose-700 dark:text-rose-300"
                  }`}
                >
                  {ipMatch ? "In Subnet" : "Outside"}
                </span>
              )}
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
          <span className="text-ink-muted">Presets:</span>
          {CIDR_PRESETS.map((p) => (
            <button
              key={p.cidr}
              type="button"
              onClick={() => {
                setCidrInput(p.cidr);
                setTestIpInput(p.ip);
              }}
              className="rounded-md border border-line bg-surface-alt px-2 py-0.5 font-mono text-ink-secondary transition hover:border-sky-500/40 hover:text-ink"
            >
              {p.label}
            </button>
          ))}
        </div>
      </div>

      {"error" in cidrResult ? (
        <div className="rounded-xl border border-rose-500/30 bg-rose-500/10 p-4 text-xs text-rose-800 dark:text-rose-200">
          {cidrResult.error}
        </div>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              ["Network Address", `${cidrResult.networkAddress}/${cidrResult.prefix}`],
              [
                cidrResult.version === 4 ? "Broadcast Address" : "Last Address",
                cidrResult.broadcastOrLastAddress,
              ],
              ["Usable Range", `${cidrResult.firstUsable} – ${cidrResult.lastUsable}`],
              ["Usable Hosts", `${cidrResult.usableHosts} (${cidrResult.totalAddresses} total)`],
              ["Netmask", cidrResult.netmask],
              ["Wildcard Mask", cidrResult.wildcardMask ?? "N/A (IPv6)"],
              ["Address Scope", cidrResult.scope],
              ["IP Version", `IPv${cidrResult.version}`],
            ].map(([label, val]) => (
              <div key={label} className="rounded-xl border border-line bg-surface p-3.5">
                <div className="text-[11px] text-ink-muted">{label}</div>
                <div className="mt-1 break-all font-mono text-xs font-semibold text-ink">
                  {val}
                </div>
              </div>
            ))}
          </div>

          {cidrResult.binaryMask && (
            <div className="rounded-xl border border-line bg-surface p-3.5 text-xs">
              <span className="text-ink-muted">Binary Netmask: </span>
              <span className="font-mono text-ink-secondary">{cidrResult.binaryMask}</span>
            </div>
          )}

          {(reversePtr || spfToken) && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              {reversePtr && (
                <div className="rounded-xl border border-line bg-surface p-4 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-ink">Reverse DNS (PTR Name)</span>
                    <button
                      type="button"
                      onClick={() => void copyText(reversePtr.ptrName, "Reverse PTR name")}
                      className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                    >
                      <Copy className="h-3 w-3" />
                      Copy
                    </button>
                  </div>
                  <div className="mt-1.5 break-all rounded border border-line bg-canvas p-2.5 font-mono text-xs text-ink">
                    {reversePtr.ptrName}
                  </div>
                  <div className="mt-1.5 text-[11px] text-ink-muted">
                    Zones: <span className="font-mono">{reversePtr.delegatedZone}</span>
                    {reversePtr.secondaryZone ? ` · ${reversePtr.secondaryZone}` : ""}
                  </div>
                </div>
              )}
              {spfToken && (
                <div className="rounded-xl border border-line bg-surface p-4 text-xs">
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-semibold text-ink">SPF Notation Token</span>
                    <button
                      type="button"
                      onClick={() => void copyText(spfToken, spfToken)}
                      className="inline-flex items-center gap-1 text-[11px] text-ink-muted hover:text-sky-600 dark:hover:text-sky-300"
                    >
                      <Copy className="h-3 w-3" />
                      Copy
                    </button>
                  </div>
                  <div className="mt-1.5 break-all rounded border border-line bg-canvas p-2.5 font-mono text-xs text-sky-700 dark:text-sky-300">
                    {spfToken}
                  </div>
                </div>
              )}
            </div>
          )}

          {cidrResult.childSubnets.length > 0 && (
            <div className="overflow-hidden rounded-xl border border-line bg-surface">
              <div className="border-b border-line bg-surface-alt px-4 py-2.5 text-xs font-semibold text-ink">
                Subnets Split ({cidrResult.childSubnets.length} blocks — click CIDR to drill down)
              </div>
              <div className="overflow-x-auto">
                <table className="w-full border-collapse text-left text-xs">
                  <thead>
                    <tr className="border-b border-line bg-canvas text-[11px] font-semibold uppercase tracking-wider text-ink-muted">
                      <th className="px-4 py-2">CIDR</th>
                      <th className="px-4 py-2">Address Range</th>
                      <th className="px-4 py-2 text-right">Usable Hosts</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-line font-mono">
                    {cidrResult.childSubnets.map((sub) => (
                      <tr key={sub.cidr} className="hover:bg-surface-alt/70">
                        <td className="px-4 py-2 font-semibold text-sky-700 dark:text-sky-300">
                          <button
                            type="button"
                            onClick={() => setCidrInput(sub.cidr)}
                            className="hover:underline"
                          >
                            {sub.cidr}
                          </button>
                        </td>
                        <td className="px-4 py-2 text-ink-secondary">{sub.range}</td>
                        <td className="px-4 py-2 text-right text-ink">{sub.hosts}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
