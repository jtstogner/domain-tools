export type CspPresetId = "strict-spa" | "marketing" | "api" | "wordpress";
export type ServerConfigFormat = "nginx" | "apache" | "caddy" | "cloudflare" | "iis";

export type CspDirectives = Record<string, string[]>;

export interface CspPreset {
  id: CspPresetId;
  label: string;
  description: string;
  directives: CspDirectives;
}

export const CSP_DIRECTIVE_NAMES: string[] = [
  "default-src",
  "script-src",
  "style-src",
  "img-src",
  "font-src",
  "connect-src",
  "media-src",
  "object-src",
  "frame-src",
  "frame-ancestors",
  "base-uri",
  "form-action",
  "upgrade-insecure-requests",
];

export const CSP_PRESETS: Record<CspPresetId, CspPreset> = {
  "strict-spa": {
    id: "strict-spa",
    label: "Strict SPA",
    description: "Locked-down policy for modern React/Vue/Svelte SPAs with zero inline scripts.",
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'"],
      "style-src": ["'self'"],
      "img-src": ["'self'", "data:", "https:"],
      "font-src": ["'self'"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "upgrade-insecure-requests": [],
    },
  },
  marketing: {
    id: "marketing",
    label: "Marketing / Docs Site",
    description: "Balanced CSP permitting Google Fonts & analytics while blocking objects and framing.",
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "https://www.googletagmanager.com"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "img-src": ["'self'", "data:", "https:"],
      "font-src": ["'self'", "https://fonts.gstatic.com"],
      "connect-src": ["'self'", "https://www.google-analytics.com"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'self'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "upgrade-insecure-requests": [],
    },
  },
  api: {
    id: "api",
    label: "JSON / REST API",
    description: "Minimal deny-all CSP for pure API endpoints that never serve HTML.",
    directives: {
      "default-src": ["'none'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'none'"],
      "base-uri": ["'none'"],
    },
  },
  wordpress: {
    id: "wordpress",
    label: "WordPress",
    description: "Practical starter policy accommodating common themes/plugins while restricting embeds.",
    directives: {
      "default-src": ["'self'"],
      "script-src": ["'self'", "'unsafe-inline'"],
      "style-src": ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      "img-src": ["'self'", "data:", "https:", "https://secure.gravatar.com"],
      "font-src": ["'self'", "data:", "https://fonts.gstatic.com"],
      "connect-src": ["'self'"],
      "object-src": ["'none'"],
      "frame-ancestors": ["'self'"],
      "base-uri": ["'self'"],
      "form-action": ["'self'"],
      "upgrade-insecure-requests": [],
    },
  },
};

export interface CspIssue {
  level: "fail" | "warn" | "pass";
  directive: string;
  message: string;
}

export interface CspEvaluation {
  score: number;
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  headerValue: string;
  issues: CspIssue[];
}

export function serializeCsp(directives: CspDirectives): string {
  const parts: string[] = [];
  for (const [key, rawValues] of Object.entries(directives)) {
    const name = key.trim().toLowerCase();
    if (!name) continue;
    const values = rawValues.map((v) => v.trim()).filter(Boolean);
    if (name === "upgrade-insecure-requests" || name === "block-all-mixed-content") {
      parts.push(name);
    } else if (values.length > 0) {
      parts.push(`${name} ${values.join(" ")}`);
    }
  }
  return parts.join("; ");
}

export function parseCsp(headerValue: string): CspDirectives {
  const directives: CspDirectives = {};
  const segments = headerValue
    .split(";")
    .map((s) => s.trim())
    .filter(Boolean);

  for (const seg of segments) {
    const tokens = seg.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) continue;
    const name = tokens[0].toLowerCase();
    const values = tokens.slice(1);
    directives[name] = values;
  }
  return directives;
}

export function evaluateCsp(input: string | CspDirectives): CspEvaluation {
  const directives = typeof input === "string" ? parseCsp(input) : input;
  const headerValue = typeof input === "string" ? input.trim() : serializeCsp(input);
  const issues: CspIssue[] = [];

  if (!headerValue) {
    return {
      score: 0,
      grade: "F",
      headerValue: "",
      issues: [
        {
          level: "fail",
          directive: "Content-Security-Policy",
          message: "Empty CSP provides no protection against XSS or clickjacking.",
        },
      ],
    };
  }

  let score = 100;
  const lowerMap = new Map<string, string[]>();
  for (const [k, vals] of Object.entries(directives)) {
    lowerMap.set(
      k.toLowerCase(),
      vals.map((v) => v.trim()),
    );
  }

  const defaultSrc = lowerMap.get("default-src");
  const scriptSrc = lowerMap.get("script-src") ?? defaultSrc ?? [];
  const styleSrc = lowerMap.get("style-src") ?? defaultSrc ?? [];
  const objectSrc = lowerMap.get("object-src");
  const frameAncestors = lowerMap.get("frame-ancestors");
  const baseUri = lowerMap.get("base-uri");

  if (!defaultSrc || defaultSrc.length === 0) {
    score -= 15;
    issues.push({
      level: "warn",
      directive: "default-src",
      message: "Missing fallback 'default-src' directive; unspecified resource types are unrestricted.",
    });
  } else {
    issues.push({
      level: "pass",
      directive: "default-src",
      message: `Fallback policy set: default-src ${defaultSrc.join(" ")}.`,
    });
  }

  // Script-src checks
  const scriptLower = scriptSrc.map((v) => v.toLowerCase());
  const hasNonceOrHash = scriptLower.some(
    (v) => v.startsWith("'nonce-") || v.startsWith("'sha256-") || v.startsWith("'sha384-") || v.startsWith("'sha512-"),
  );
  const hasStrictDynamic = scriptLower.includes("'strict-dynamic'");

  if (scriptLower.includes("'unsafe-inline'") && !hasNonceOrHash && !hasStrictDynamic) {
    score -= 25;
    issues.push({
      level: "fail",
      directive: "script-src",
      message: "'unsafe-inline' in script-src allows arbitrary inline XSS execution; replace with nonces/hashes.",
    });
  }
  if (scriptLower.includes("'unsafe-eval'")) {
    score -= 20;
    issues.push({
      level: "fail",
      directive: "script-src",
      message: "'unsafe-eval' permits eval()/Function() code execution from strings.",
    });
  }
  if (scriptLower.includes("*")) {
    score -= 25;
    issues.push({
      level: "fail",
      directive: "script-src",
      message: "Wildcard '*' in script-src allows loading scripts from any host on the internet.",
    });
  }
  if (scriptLower.includes("data:")) {
    score -= 15;
    issues.push({
      level: "fail",
      directive: "script-src",
      message: "'data:' URI scheme in script-src allows injecting arbitrary script payloads.",
    });
  }

  // Style-src unsafe-inline (lighter penalty than script-src)
  const styleLower = styleSrc.map((v) => v.toLowerCase());
  if (styleLower.includes("'unsafe-inline'")) {
    score -= 5;
    issues.push({
      level: "warn",
      directive: "style-src",
      message: "'unsafe-inline' in style-src weakens CSS injection defense (consider nonces if feasible).",
    });
  }

  // Wildcards and insecure http: across all directives
  for (const [dir, vals] of lowerMap.entries()) {
    const valsLower = vals.map((v) => v.toLowerCase());
    if (valsLower.some((v) => v === "http:" || v.startsWith("http://"))) {
      score -= 15;
      issues.push({
        level: "fail",
        directive: dir,
        message: `Plaintext 'http:' source in ${dir} permits active MITM downgrades.`,
      });
    }
    if (
      dir !== "script-src" &&
      valsLower.includes("*") &&
      (dir === "default-src" || dir === "object-src" || dir === "frame-ancestors" || dir === "connect-src")
    ) {
      score -= 15;
      issues.push({
        level: "warn",
        directive: dir,
        message: `Broad wildcard '*' in ${dir} should be narrowed to explicit trusted origins.`,
      });
    }
  }

  // object-src 'none'
  const effectiveObjectSrc = objectSrc ?? defaultSrc ?? [];
  if (!effectiveObjectSrc.map((v) => v.toLowerCase()).includes("'none'")) {
    score -= 15;
    issues.push({
      level: "warn",
      directive: "object-src",
      message: "Missing \"object-src 'none'\" — legacy Flash/plugin objects should be explicitly blocked.",
    });
  } else {
    issues.push({
      level: "pass",
      directive: "object-src",
      message: "Plugins/objects blocked with object-src 'none'.",
    });
  }

  // frame-ancestors
  if (!frameAncestors || frameAncestors.length === 0) {
    score -= 10;
    issues.push({
      level: "warn",
      directive: "frame-ancestors",
      message: "Missing 'frame-ancestors' directive (modern clickjacking protection superseding X-Frame-Options).",
    });
  } else {
    issues.push({
      level: "pass",
      directive: "frame-ancestors",
      message: `Clickjacking restricted via frame-ancestors ${frameAncestors.join(" ")}.`,
    });
  }

  // base-uri
  if (!baseUri || baseUri.length === 0) {
    score -= 10;
    issues.push({
      level: "warn",
      directive: "base-uri",
      message: "Missing 'base-uri' directive (prevents <base> tag injection hijacking relative script URLs).",
    });
  } else {
    issues.push({
      level: "pass",
      directive: "base-uri",
      message: `Base URL restricted via base-uri ${baseUri.join(" ")}.`,
    });
  }

  if (lowerMap.has("upgrade-insecure-requests")) {
    issues.push({
      level: "pass",
      directive: "upgrade-insecure-requests",
      message: "Automatic HTTPS upgrade enabled for subresources.",
    });
  }

  const clamped = Math.max(0, Math.min(100, score));
  let grade: CspEvaluation["grade"];
  if (clamped >= 95) grade = "A+";
  else if (clamped >= 85) grade = "A";
  else if (clamped >= 70) grade = "B";
  else if (clamped >= 55) grade = "C";
  else if (clamped >= 40) grade = "D";
  else grade = "F";

  return {
    score: clamped,
    grade,
    headerValue,
    issues,
  };
}

export interface HstsConfig {
  maxAge: number;
  includeSubDomains: boolean;
  preload: boolean;
}

export interface HstsEvaluation {
  headerValue: string;
  preloadEligible: boolean;
  checks: { label: string; pass: boolean; detail: string }[];
}

const ONE_YEAR_SEC = 31536000;

export function buildHsts(config: HstsConfig): HstsEvaluation {
  const maxAge = Math.max(0, Math.round(config.maxAge));
  const parts = [`max-age=${maxAge}`];
  if (config.includeSubDomains) parts.push("includeSubDomains");
  if (config.preload) parts.push("preload");
  const headerValue = parts.join("; ");

  const minAgeOk = maxAge >= ONE_YEAR_SEC;
  const checks = [
    {
      label: "max-age >= 1 year (31536000s)",
      pass: minAgeOk,
      detail: minAgeOk
        ? `max-age=${maxAge} meets hstspreload.org minimum (1 year).`
        : `max-age=${maxAge} is below 31536000s (1 year) required for HSTS preload.`,
    },
    {
      label: "includeSubDomains directive",
      pass: config.includeSubDomains,
      detail: config.includeSubDomains
        ? "All subdomains are covered by HTTPS enforcement."
        : "Required for HSTS preload (ensure every subdomain supports HTTPS before enabling!).",
    },
    {
      label: "preload token",
      pass: config.preload,
      detail: config.preload
        ? "Signals browser preload list eligibility."
        : "Add 'preload' when ready to submit to hstspreload.org.",
    },
  ];

  return {
    headerValue,
    preloadEligible: minAgeOk && config.includeSubDomains && config.preload,
    checks,
  };
}

export interface PermissionsFeatureDef {
  id: string;
  label: string;
  defaultValue: "()" | "self" | "*";
}

export const PERMISSIONS_FEATURES: PermissionsFeatureDef[] = [
  { id: "camera", label: "Camera", defaultValue: "()" },
  { id: "microphone", label: "Microphone", defaultValue: "()" },
  { id: "geolocation", label: "Geolocation", defaultValue: "()" },
  { id: "payment", label: "Payment Request", defaultValue: "()" },
  { id: "usb", label: "WebUSB", defaultValue: "()" },
  { id: "accelerometer", label: "Accelerometer", defaultValue: "()" },
  { id: "gyroscope", label: "Gyroscope", defaultValue: "()" },
  { id: "fullscreen", label: "Fullscreen", defaultValue: "self" },
  { id: "interest-cohort", label: "FLoC / Interest Cohort", defaultValue: "()" },
];

export type PermissionsPolicyConfig = Record<string, "()" | "self" | "*" | string>;

export function buildPermissionsPolicy(config: PermissionsPolicyConfig): string {
  const entries: string[] = [];
  for (const [feature, rawMode] of Object.entries(config)) {
    const f = feature.trim().toLowerCase();
    const mode = rawMode.trim();
    if (!f || !mode) continue;
    if (mode === "()" || mode === "none") {
      entries.push(`${f}=()`);
    } else if (mode === "self" || mode === "(self)") {
      entries.push(`${f}=(self)`);
    } else if (mode === "*") {
      entries.push(`${f}=*`);
    } else if (mode.startsWith("(") && mode.endsWith(")")) {
      entries.push(`${f}=${mode}`);
    } else {
      entries.push(`${f}=(${mode})`);
    }
  }
  return entries.join(", ");
}

export interface SecurityHeadersBundle {
  csp: string;
  hsts: string;
  permissionsPolicy: string;
  xContentTypeOptions: string;
  xFrameOptions: string;
  referrerPolicy: string;
  coop: string;
  corp: string;
}

export const DEFAULT_SECURITY_HEADERS: SecurityHeadersBundle = {
  csp: serializeCsp(CSP_PRESETS["strict-spa"].directives),
  hsts: "max-age=63072000; includeSubDomains; preload",
  permissionsPolicy: buildPermissionsPolicy({
    camera: "()",
    microphone: "()",
    geolocation: "()",
    payment: "()",
    usb: "()",
    fullscreen: "self",
  }),
  xContentTypeOptions: "nosniff",
  xFrameOptions: "DENY",
  referrerPolicy: "strict-origin-when-cross-origin",
  coop: "same-origin",
  corp: "same-origin",
};

export function buildSecurityHeadersMap(
  bundle: Partial<SecurityHeadersBundle>,
): Record<string, string> {
  const out: Record<string, string> = {};
  const pairs: [string, string | undefined][] = [
    ["Strict-Transport-Security", bundle.hsts],
    ["Content-Security-Policy", bundle.csp],
    ["X-Content-Type-Options", bundle.xContentTypeOptions],
    ["X-Frame-Options", bundle.xFrameOptions],
    ["Referrer-Policy", bundle.referrerPolicy],
    ["Permissions-Policy", bundle.permissionsPolicy],
    ["Cross-Origin-Opener-Policy", bundle.coop],
    ["Cross-Origin-Resource-Policy", bundle.corp],
  ];
  for (const [name, val] of pairs) {
    const clean = val?.trim();
    if (clean) out[name] = clean;
  }
  return out;
}

function escapeXmlAttr(val: string): string {
  return val
    .replace(/&/g, "&amp;")
    .replace(/"/g, "&quot;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function escapeDoubleQuotes(val: string): string {
  return val.replace(/\\/g, "\\\\").replace(/"/g, '\\"');
}

export function generateServerConfig(
  format: ServerConfigFormat,
  headers: Record<string, string>,
): string {
  const entries = Object.entries(headers).filter(([, v]) => Boolean(v.trim()));
  if (entries.length === 0) {
    return "# Enable at least one security header to generate server configuration.";
  }

  switch (format) {
    case "nginx": {
      const lines = entries.map(
        ([k, v]) => `    add_header ${k} "${escapeDoubleQuotes(v)}" always;`,
      );
      return [
        "# Nginx (place inside server { ... } block)",
        "server {",
        ...lines,
        "}",
      ].join("\n");
    }

    case "apache": {
      const lines = entries.map(
        ([k, v]) => `    Header always set ${k} "${escapeDoubleQuotes(v)}"`,
      );
      return [
        "# Apache (.htaccess or VirtualHost — requires mod_headers)",
        "<IfModule mod_headers.c>",
        ...lines,
        "</IfModule>",
      ].join("\n");
    }

    case "caddy": {
      const lines = entries.map(
        ([k, v]) => `        ${k} "${escapeDoubleQuotes(v)}"`,
      );
      return [
        "# Caddyfile",
        "example.com {",
        "    header {",
        ...lines,
        "    }",
        "}",
      ].join("\n");
    }

    case "cloudflare": {
      const lines = entries.map(([k, v]) => `  ${k}: ${v}`);
      return [
        "# Cloudflare Pages (_headers file in build output root)",
        "/*",
        ...lines,
      ].join("\n");
    }

    case "iis": {
      const lines = entries.map(
        ([k, v]) => `        <add name="${escapeXmlAttr(k)}" value="${escapeXmlAttr(v)}" />`,
      );
      return [
        "<!-- IIS web.config -->",
        "<configuration>",
        "  <system.webServer>",
        "    <httpProtocol>",
        "      <customHeaders>",
        ...lines,
        "      </customHeaders>",
        "    </httpProtocol>",
        "  </system.webServer>",
        "</configuration>",
      ].join("\n");
    }
  }
}
