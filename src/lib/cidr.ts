export interface CidrSubnetInfo {
  version: 4 | 6;
  input: string;
  ip: string;
  prefix: number;
  networkAddress: string;
  broadcastOrLastAddress: string;
  firstUsable: string;
  lastUsable: string;
  netmask: string;
  wildcardMask: string | null;
  totalAddresses: string;
  usableHosts: string;
  scope: string;
  binaryMask: string | null;
  childSubnets: { cidr: string; range: string; hosts: string }[];
}

function parseIpv4ToBigInt(ip: string): bigint | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  let val = 0n;
  for (const part of parts) {
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n < 0 || n > 255) return null;
    val = (val << 8n) | BigInt(n);
  }
  return val;
}

function bigIntToIpv4(val: bigint): string {
  const a = Number((val >> 24n) & 0xffn);
  const b = Number((val >> 16n) & 0xffn);
  const c = Number((val >> 8n) & 0xffn);
  const d = Number(val & 0xffn);
  return `${a}.${b}.${c}.${d}`;
}

function formatIpv4Binary(val: bigint): string {
  const octets: string[] = [];
  for (let shift = 24n; shift >= 0n; shift -= 8n) {
    const byte = Number((val >> shift) & 0xffn);
    octets.push(byte.toString(2).padStart(8, "0"));
  }
  return octets.join(".");
}

function parseIpv6ToBigInt(ip: string): bigint | null {
  let clean = ip.trim();
  const zoneIdx = clean.indexOf("%");
  if (zoneIdx !== -1) clean = clean.slice(0, zoneIdx);
  if (!clean.includes(":")) return null;

  const halves = clean.split("::");
  if (halves.length > 2) return null;

  const parseSide = (side: string): number[] | null => {
    if (!side) return [];
    const tokens = side.split(":");
    const groups: number[] = [];
    for (let i = 0; i < tokens.length; i++) {
      const tok = tokens[i];
      if (tok.includes(".")) {
        if (i !== tokens.length - 1) return null;
        const v4 = parseIpv4ToBigInt(tok);
        if (v4 === null) return null;
        groups.push(Number((v4 >> 16n) & 0xffffn));
        groups.push(Number(v4 & 0xffffn));
      } else {
        if (!/^[0-9a-fA-F]{1,4}$/.test(tok)) return null;
        groups.push(Number.parseInt(tok, 16));
      }
    }
    return groups;
  };

  const left = parseSide(halves[0]);
  if (!left) return null;

  let groups: number[];
  if (halves.length === 2) {
    const right = parseSide(halves[1]);
    if (!right) return null;
    const missing = 8 - (left.length + right.length);
    if (missing < 1) return null;
    groups = [...left, ...new Array<number>(missing).fill(0), ...right];
  } else {
    if (left.length !== 8) return null;
    groups = left;
  }

  let val = 0n;
  for (const g of groups) {
    val = (val << 16n) | BigInt(g);
  }
  return val;
}

function bigIntToIpv6(val: bigint): string {
  const groups: number[] = [];
  for (let i = 7; i >= 0; i--) {
    groups.push(Number((val >> BigInt(i * 16)) & 0xffffn));
  }

  // Compress longest run of zeros
  let bestStart = -1;
  let bestLen = 0;
  let curStart = -1;
  let curLen = 0;
  for (let i = 0; i < 8; i++) {
    if (groups[i] === 0) {
      if (curStart === -1) curStart = i;
      curLen++;
      if (curLen > bestLen) {
        bestStart = curStart;
        bestLen = curLen;
      }
    } else {
      curStart = -1;
      curLen = 0;
    }
  }
  if (bestLen < 2) {
    return groups.map((g) => g.toString(16)).join(":");
  }

  const left = groups
    .slice(0, bestStart)
    .map((g) => g.toString(16))
    .join(":");
  const right = groups
    .slice(bestStart + bestLen)
    .map((g) => g.toString(16))
    .join(":");
  return `${left}::${right}`;
}

function classifyIpv4Scope(net: bigint): string {
  const a = Number((net >> 24n) & 0xffn);
  const b = Number((net >> 16n) & 0xffn);
  const c = Number((net >> 8n) & 0xffn);
  if (a === 10) return "Private (RFC 1918)";
  if (a === 172 && b >= 16 && b <= 31) return "Private (RFC 1918)";
  if (a === 192 && b === 168) return "Private (RFC 1918)";
  if (a === 100 && b >= 64 && b <= 127) return "Shared / CGNAT (RFC 6598)";
  if (a === 127) return "Loopback (RFC 1122)";
  if (a === 169 && b === 254) return "Link-Local (RFC 3927)";
  if (
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113)
  ) {
    return "Documentation (RFC 5737)";
  }
  if (a >= 224 && a <= 239) return "Multicast";
  if (a >= 240) return "Reserved";
  return "Public Internet Routable";
}

function classifyIpv6Scope(net: bigint): string {
  const top16 = Number((net >> 112n) & 0xffffn);
  if (net === 1n) return "Loopback (::1)";
  if ((top16 & 0xfe00) === 0xfc00) return "Unique Local (ULA RFC 4193)";
  if ((top16 & 0xffc0) === 0xfe80) return "Link-Local (fe80::/10)";
  if ((top16 & 0xff00) === 0xff00) return "Multicast (ff00::/8)";
  if (top16 === 0x2001 && Number((net >> 96n) & 0xffffn) === 0x0db8) {
    return "Documentation (2001:db8::/32)";
  }
  if ((top16 & 0xe000) === 0x2000) return "Global Unicast (2000::/3)";
  return "Special / Reserved";
}

function formatBigCount(n: bigint): string {
  return n.toLocaleString("en-US");
}

export function calculateCidr(input: string): CidrSubnetInfo | { error: string } {
  const trimmed = input.trim();
  if (!trimmed) {
    return { error: "Enter an IPv4 or IPv6 address/CIDR (e.g. 192.168.1.0/24 or 104.16.0.0/14)." };
  }

  const slashIdx = trimmed.indexOf("/");
  const ipPart = slashIdx === -1 ? trimmed : trimmed.slice(0, slashIdx).trim();
  const prefixPart = slashIdx === -1 ? null : trimmed.slice(slashIdx + 1).trim();

  const v4Val = parseIpv4ToBigInt(ipPart);
  if (v4Val !== null) {
    const prefix =
      prefixPart === null ? 32 : Number.parseInt(prefixPart, 10);
    if (
      prefixPart !== null &&
      (!/^\d+$/.test(prefixPart) || Number.isNaN(prefix) || prefix < 0 || prefix > 32)
    ) {
      return { error: "IPv4 CIDR prefix must be between /0 and /32." };
    }

    const allOnes = 0xffffffffn;
    const hostBits = BigInt(32 - prefix);
    const mask = prefix === 0 ? 0n : (allOnes << hostBits) & allOnes;
    const wildcard = allOnes ^ mask;
    const network = v4Val & mask;
    const broadcast = network | wildcard;
    const total = 1n << hostBits;

    let firstUsable: bigint;
    let lastUsable: bigint;
    let usable: bigint;
    if (prefix === 32) {
      firstUsable = network;
      lastUsable = network;
      usable = 1n;
    } else if (prefix === 31) {
      firstUsable = network;
      lastUsable = broadcast;
      usable = 2n;
    } else {
      firstUsable = network + 1n;
      lastUsable = broadcast - 1n;
      usable = total - 2n;
    }

    const childSubnets: { cidr: string; range: string; hosts: string }[] = [];
    if (prefix < 31) {
      const splitStep = prefix + 2 <= 32 ? 2 : 1;
      const childPrefix = prefix + splitStep;
      const count = 1 << splitStep;
      const childSize = 1n << BigInt(32 - childPrefix);
      const childUsable = childPrefix === 31 ? 2n : childPrefix === 32 ? 1n : childSize - 2n;
      for (let i = 0; i < count; i++) {
        const cNet = network + BigInt(i) * childSize;
        const cBroad = cNet + childSize - 1n;
        childSubnets.push({
          cidr: `${bigIntToIpv4(cNet)}/${childPrefix}`,
          range: `${bigIntToIpv4(cNet)} – ${bigIntToIpv4(cBroad)}`,
          hosts: formatBigCount(childUsable),
        });
      }
    }

    return {
      version: 4,
      input: trimmed,
      ip: bigIntToIpv4(v4Val),
      prefix,
      networkAddress: bigIntToIpv4(network),
      broadcastOrLastAddress: bigIntToIpv4(broadcast),
      firstUsable: bigIntToIpv4(firstUsable),
      lastUsable: bigIntToIpv4(lastUsable),
      netmask: bigIntToIpv4(mask),
      wildcardMask: bigIntToIpv4(wildcard),
      totalAddresses: formatBigCount(total),
      usableHosts: formatBigCount(usable),
      scope: classifyIpv4Scope(network),
      binaryMask: formatIpv4Binary(mask),
      childSubnets,
    };
  }

  const v6Val = parseIpv6ToBigInt(ipPart);
  if (v6Val !== null) {
    const prefix =
      prefixPart === null ? 128 : Number.parseInt(prefixPart, 10);
    if (
      prefixPart !== null &&
      (!/^\d+$/.test(prefixPart) || Number.isNaN(prefix) || prefix < 0 || prefix > 128)
    ) {
      return { error: "IPv6 CIDR prefix must be between /0 and /128." };
    }

    const allOnes = (1n << 128n) - 1n;
    const hostBits = BigInt(128 - prefix);
    const mask = prefix === 0 ? 0n : (allOnes << hostBits) & allOnes;
    const wildcard = allOnes ^ mask;
    const network = v6Val & mask;
    const last = network | wildcard;
    const total = 1n << hostBits;

    const childSubnets: { cidr: string; range: string; hosts: string }[] = [];
    if (prefix <= 124) {
      const childPrefix = prefix + 2;
      const childSize = 1n << BigInt(128 - childPrefix);
      for (let i = 0; i < 4; i++) {
        const cNet = network + BigInt(i) * childSize;
        const cEnd = cNet + childSize - 1n;
        childSubnets.push({
          cidr: `${bigIntToIpv6(cNet)}/${childPrefix}`,
          range: `${bigIntToIpv6(cNet)} – ${bigIntToIpv6(cEnd)}`,
          hosts: childSize <= 1_000_000_000n ? formatBigCount(childSize) : `2^${128 - childPrefix}`,
        });
      }
    }

    return {
      version: 6,
      input: trimmed,
      ip: bigIntToIpv6(v6Val),
      prefix,
      networkAddress: bigIntToIpv6(network),
      broadcastOrLastAddress: bigIntToIpv6(last),
      firstUsable: bigIntToIpv6(network),
      lastUsable: bigIntToIpv6(last),
      netmask: `/${prefix}`,
      wildcardMask: null,
      totalAddresses: total <= 1_000_000_000_000n ? formatBigCount(total) : `2^${128 - prefix}`,
      usableHosts: total <= 1_000_000_000_000n ? formatBigCount(total) : `2^${128 - prefix}`,
      scope: classifyIpv6Scope(network),
      binaryMask: null,
      childSubnets,
    };
  }

  return { error: `Invalid IP address or CIDR notation: "${trimmed}"` };
}

export function isIpInCidr(cidrInput: string, ipInput: string): boolean | null {
  const parsed = calculateCidr(cidrInput);
  if ("error" in parsed) return null;
  const targetTrim = ipInput.trim();
  if (parsed.version === 4) {
    const net = parseIpv4ToBigInt(parsed.networkAddress);
    const end = parseIpv4ToBigInt(parsed.broadcastOrLastAddress);
    const val = parseIpv4ToBigInt(targetTrim);
    if (net === null || end === null || val === null) return null;
    return val >= net && val <= end;
  }
  const net = parseIpv6ToBigInt(parsed.networkAddress);
  const end = parseIpv6ToBigInt(parsed.broadcastOrLastAddress);
  const val = parseIpv6ToBigInt(targetTrim);
  if (net === null || end === null || val === null) return null;
  return val >= net && val <= end;
}
