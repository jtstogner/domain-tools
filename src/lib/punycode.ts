// Pure TypeScript RFC 3492 Punycode encoder/decoder + homoglyph inspector

const BASE = 36;
const TMIN = 1;
const TMAX = 26;
const SKEW = 38;
const DAMP = 700;
const INITIAL_BIAS = 72;
const INITIAL_N = 128;
const DELIMITER = "-";

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - TMIN) * TMAX) >> 1) {
    d = Math.floor(d / (BASE - TMIN));
    k += BASE;
  }
  return Math.floor(k + ((BASE - TMIN + 1) * d) / (d + SKEW));
}

function digitToBasic(digit: number): number {
  return digit + 22 + 75 * (digit < 26 ? 1 : 0);
}

function basicToDigit(codePoint: number): number {
  if (codePoint - 48 < 10) return codePoint - 22;
  if (codePoint - 65 < 26) return codePoint - 65;
  if (codePoint - 97 < 26) return codePoint - 97;
  return BASE;
}

export function encodePunycode(input: string): string {
  const codePoints = Array.from(input, (ch) => ch.codePointAt(0)!);
  const output: string[] = [];

  for (const cp of codePoints) {
    if (cp < 0x80) output.push(String.fromCodePoint(cp));
  }

  const basicLength = output.length;
  let handled = basicLength;
  if (basicLength > 0) output.push(DELIMITER);

  let n = INITIAL_N;
  let delta = 0;
  let bias = INITIAL_BIAS;

  while (handled < codePoints.length) {
    let minCp = Number.MAX_SAFE_INTEGER;
    for (const cp of codePoints) {
      if (cp >= n && cp < minCp) minCp = cp;
    }

    delta += (minCp - n) * (handled + 1);
    n = minCp;

    for (const cp of codePoints) {
      if (cp < n) {
        delta += 1;
      } else if (cp === n) {
        let q = delta;
        for (let k = BASE; ; k += BASE) {
          const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
          if (q < t) break;
          const qMinusT = q - t;
          const baseMinusT = BASE - t;
          output.push(String.fromCodePoint(digitToBasic(t + (qMinusT % baseMinusT))));
          q = Math.floor(qMinusT / baseMinusT);
        }
        output.push(String.fromCodePoint(digitToBasic(q)));
        bias = adapt(delta, handled + 1, handled === basicLength);
        delta = 0;
        handled += 1;
      }
    }
    delta += 1;
    n += 1;
  }

  return output.join("");
}

export function decodePunycode(input: string): string {
  const output: number[] = [];
  const basicEnd = input.lastIndexOf(DELIMITER);
  let i = 0;
  let idx = 0;

  if (basicEnd > 0) {
    for (let j = 0; j < basicEnd; j += 1) {
      const cp = input.charCodeAt(j);
      if (cp >= 0x80) throw new Error("Invalid basic code point in Punycode label.");
      output.push(cp);
    }
    idx = basicEnd + 1;
  }

  let n = INITIAL_N;
  let bias = INITIAL_BIAS;

  while (idx < input.length) {
    const oldI = i;
    let w = 1;
    for (let k = BASE; ; k += BASE) {
      if (idx >= input.length) throw new Error("Truncated Punycode sequence.");
      const digit = basicToDigit(input.charCodeAt(idx));
      idx += 1;
      if (digit >= BASE) throw new Error("Invalid Punycode character.");
      i += digit * w;
      const t = k <= bias ? TMIN : k >= bias + TMAX ? TMAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }

    const outLen = output.length + 1;
    bias = adapt(i - oldI, outLen, oldI === 0);
    n += Math.floor(i / outLen);
    i %= outLen;
    output.splice(i, 0, n);
    i += 1;
  }

  return String.fromCodePoint(...output);
}

export function toAsciiDomain(domain: string): {
  ascii: string;
  changed: boolean;
  error: string | null;
} {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0] ?? "";
  if (!clean) return { ascii: "", changed: false, error: null };
  try {
    const labels = clean.split(".").map((label) => {
      if (/^[\x00-\x7f]*$/.test(label)) return label;
      return `xn--${encodePunycode(label)}`;
    });
    const ascii = labels.join(".");
    return { ascii, changed: ascii !== clean, error: null };
  } catch (err) {
    return { ascii: clean, changed: false, error: String(err) };
  }
}

export function toUnicodeDomain(domain: string): {
  unicode: string;
  changed: boolean;
  error: string | null;
} {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").split(/[/?#]/)[0] ?? "";
  if (!clean) return { unicode: "", changed: false, error: null };
  try {
    const labels = clean.split(".").map((label) => {
      if (label.startsWith("xn--")) {
        return decodePunycode(label.slice(4));
      }
      return label;
    });
    const unicode = labels.join(".");
    return { unicode, changed: unicode !== clean, error: null };
  } catch (err) {
    return { unicode: clean, changed: false, error: String(err) };
  }
}

export interface ConfusableCharFinding {
  char: string;
  codePoint: string;
  script: string;
  lookalikeLatin?: string;
}

const KNOWN_CONFUSABLES: Record<string, { script: string; latin: string }> = {
  "\u0430": { script: "Cyrillic", latin: "a" },
  "\u0435": { script: "Cyrillic", latin: "e" },
  "\u043E": { script: "Cyrillic", latin: "o" },
  "\u0440": { script: "Cyrillic", latin: "p" },
  "\u0441": { script: "Cyrillic", latin: "c" },
  "\u0443": { script: "Cyrillic", latin: "y" },
  "\u0445": { script: "Cyrillic", latin: "x" },
  "\u0456": { script: "Cyrillic", latin: "i" },
  "\u0455": { script: "Cyrillic", latin: "s" },
  "\u0458": { script: "Cyrillic", latin: "j" },
  "\u04CF": { script: "Cyrillic", latin: "l" },
  "\u03B1": { script: "Greek", latin: "a" },
  "\u03BF": { script: "Greek", latin: "o" },
  "\u03BD": { script: "Greek", latin: "v" },
};

function detectScript(cp: number): string {
  if (cp >= 0x41 && cp <= 0x5a) return "Latin";
  if (cp >= 0x61 && cp <= 0x7a) return "Latin";
  if (cp >= 0xc0 && cp <= 0x024f) return "Latin Extended";
  if (cp >= 0x0400 && cp <= 0x04ff) return "Cyrillic";
  if (cp >= 0x0370 && cp <= 0x03ff) return "Greek";
  if (cp >= 0x0590 && cp <= 0x05ff) return "Hebrew";
  if (cp >= 0x0600 && cp <= 0x06ff) return "Arabic";
  if (cp >= 0x3040 && cp <= 0x30ff) return "Japanese";
  if (cp >= 0x4e00 && cp <= 0x9fff) return "CJK";
  return "Other";
}

export function inspectDomainScripts(unicodeDomain: string): {
  scripts: string[];
  mixedScript: boolean;
  confusables: ConfusableCharFinding[];
} {
  const scripts = new Set<string>();
  const confusables: ConfusableCharFinding[] = [];
  const seenPos = new Set<string>();

  for (const ch of unicodeDomain) {
    const cp = ch.codePointAt(0)!;
    if (ch === "." || ch === "-" || (cp >= 0x30 && cp <= 0x39)) continue;

    const known = KNOWN_CONFUSABLES[ch];
    const script = known?.script ?? detectScript(cp);
    scripts.add(script);

    if (cp >= 0x80) {
      const hex = `U+${cp.toString(16).toUpperCase().padStart(4, "0")}`;
      if (!seenPos.has(`${ch}:${hex}`)) {
        seenPos.add(`${ch}:${hex}`);
        confusables.push({
          char: ch,
          codePoint: hex,
          script,
          lookalikeLatin: known?.latin,
        });
      }
    }
  }

  return {
    scripts: Array.from(scripts),
    mixedScript: scripts.size > 1,
    confusables,
  };
}
