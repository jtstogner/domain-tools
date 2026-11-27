export interface RobotsRule {
  type: "allow" | "disallow";
  path: string;
  lineNumber: number;
}

export interface RobotsGroup {
  userAgents: string[];
  rules: RobotsRule[];
  crawlDelay?: number;
}

export interface ParsedRobotsTxt {
  groups: RobotsGroup[];
  sitemaps: string[];
  host: string | null;
  warnings: string[];
}

export interface RobotsTestResult {
  allowed: boolean;
  matchedGroup: string | null;
  matchedRule: { type: "allow" | "disallow"; path: string } | null;
  reason: string;
  crawlDelay?: number;
}

export interface BotPreset {
  id: string;
  name: string;
  category: "search" | "ai" | "archive" | "wildcard";
  description: string;
}

export const COMMON_BOT_PRESETS: BotPreset[] = [
  { id: "googlebot", name: "Googlebot", category: "search", description: "Google Search web crawler" },
  { id: "bingbot", name: "Bingbot", category: "search", description: "Microsoft Bing search crawler" },
  { id: "gptbot", name: "GPTBot", category: "ai", description: "OpenAI training & search crawler" },
  { id: "claudebot", name: "ClaudeBot", category: "ai", description: "Anthropic web crawler" },
  { id: "perplexitybot", name: "PerplexityBot", category: "ai", description: "Perplexity AI search crawler" },
  { id: "applebot", name: "Applebot", category: "search", description: "Apple Siri / Spotlight / Apple Intelligence" },
  { id: "ccbot", name: "CCBot", category: "archive", description: "Common Crawl dataset archive bot" },
  { id: "wildcard", name: "*", category: "wildcard", description: "Default fallback rule for all crawlers" },
];

export function parseRobotsTxt(content: string): ParsedRobotsTxt {
  const cleaned = content.replace(/^\uFEFF/, "");
  const lines = cleaned.split(/\r?\n/);

  const groups: RobotsGroup[] = [];
  const sitemaps: string[] = [];
  const warnings: string[] = [];
  let host: string | null = null;

  let currentGroup: RobotsGroup | null = null;
  let seenRuleInGroup = false;

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNumber = idx + 1;
    // Strip comments starting with '#'
    const withoutComment = lines[idx].replace(/#.*$/, "").trim();
    if (!withoutComment) continue;

    const colonIdx = withoutComment.indexOf(":");
    if (colonIdx === -1) {
      warnings.push(`Line ${lineNumber}: ignored malformed line without ':' ("${withoutComment}").`);
      continue;
    }

    const field = withoutComment.slice(0, colonIdx).trim().toLowerCase();
    const value = withoutComment.slice(colonIdx + 1).trim();

    if (field === "user-agent") {
      if (!value) {
        warnings.push(`Line ${lineNumber}: empty User-agent directive ignored.`);
        continue;
      }
      if (!currentGroup || seenRuleInGroup) {
        currentGroup = { userAgents: [value], rules: [] };
        groups.push(currentGroup);
        seenRuleInGroup = false;
      } else {
        currentGroup.userAgents.push(value);
      }
    } else if (field === "allow" || field === "disallow") {
      if (!currentGroup) {
        warnings.push(
          `Line ${lineNumber}: '${field}' rule appeared before any User-agent directive and was ignored.`,
        );
        continue;
      }
      seenRuleInGroup = true;
      currentGroup.rules.push({
        type: field,
        path: value,
        lineNumber,
      });
    } else if (field === "crawl-delay") {
      if (!currentGroup) {
        warnings.push(`Line ${lineNumber}: 'Crawl-delay' appeared before any User-agent directive.`);
        continue;
      }
      seenRuleInGroup = true;
      const delay = Number(value);
      if (Number.isFinite(delay) && delay >= 0) {
        currentGroup.crawlDelay = delay;
      } else {
        warnings.push(`Line ${lineNumber}: invalid Crawl-delay value '${value}'.`);
      }
    } else if (field === "sitemap") {
      if (!value) {
        warnings.push(`Line ${lineNumber}: empty Sitemap directive.`);
      } else {
        if (!/^https?:\/\//i.test(value)) {
          warnings.push(`Line ${lineNumber}: Sitemap URL '${value}' should be an absolute http(s):// URL.`);
        }
        if (!sitemaps.includes(value)) {
          sitemaps.push(value);
        }
      }
    } else if (field === "host") {
      if (value) host = value;
    }
  }

  return { groups, sitemaps, host, warnings };
}

function normalizeTestPath(rawPath: string): string {
  const trimmed = rawPath.trim();
  if (!trimmed) return "/";

  if (/^https?:\/\//i.test(trimmed)) {
    try {
      const parsed = new URL(trimmed);
      return `${parsed.pathname || "/"}${parsed.search}`;
    } catch {
      // Fall through to path normalization
    }
  }

  return trimmed.startsWith("/") ? trimmed : `/${trimmed}`;
}

/**
 * Compiles an RFC 9309 robots.txt path pattern supporting '*' wildcards and '$' end anchor.
 */
function matchesRobotsPattern(pattern: string, path: string): boolean {
  if (pattern === "") return false;

  const hasEndAnchor = pattern.endsWith("$");
  const core = hasEndAnchor ? pattern.slice(0, -1) : pattern;

  // Escape regex metacharacters except '*', then convert '*' to '.*'
  const escaped = core
    .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
    .replace(/\*/g, ".*");

  const regexStr = `^${escaped}${hasEndAnchor ? "$" : ""}`;
  try {
    return new RegExp(regexStr).test(path);
  } catch {
    return path.startsWith(core);
  }
}

/**
 * Extracts the RFC 9309 product token from a User-Agent string (e.g. "Googlebot/2.1" -> "googlebot").
 */
function extractProductToken(ua: string): string {
  const trimmed = ua.trim().toLowerCase();
  if (trimmed === "*") return "*";
  const slashIdx = trimmed.indexOf("/");
  return slashIdx === -1 ? trimmed : trimmed.slice(0, slashIdx).trim();
}

export function testRobotsPath(
  content: string,
  userAgent: string,
  rawPath: string,
): RobotsTestResult {
  const parsed = parseRobotsTxt(content);
  const path = normalizeTestPath(rawPath);
  const targetUa = (userAgent || "*").trim();
  const targetToken = extractProductToken(targetUa);

  // RFC 9309 §2.2.1: Match the most specific (longest) User-agent product token.
  // If multiple groups specify the same winning token, combine their rules.
  let bestSpecificity = -1;
  let matchedAgentLabel: string | null = null;
  const matchedRules: RobotsRule[] = [];
  let crawlDelay: number | undefined;

  if (targetToken !== "*") {
    for (const group of parsed.groups) {
      for (const ua of group.userAgents) {
        const groupToken = extractProductToken(ua);
        if (groupToken === "*") continue;

        // Per RFC 9309, product token is matched case-insensitively (exact or prefix match)
        const matches =
          targetToken === groupToken ||
          targetToken.startsWith(groupToken) ||
          targetUa.toLowerCase().includes(groupToken);

        if (matches) {
          if (groupToken.length > bestSpecificity) {
            bestSpecificity = groupToken.length;
            matchedAgentLabel = ua;
            matchedRules.length = 0;
            matchedRules.push(...group.rules);
            crawlDelay = group.crawlDelay;
          } else if (groupToken.length === bestSpecificity) {
            matchedRules.push(...group.rules);
            if (crawlDelay === undefined && group.crawlDelay !== undefined) {
              crawlDelay = group.crawlDelay;
            }
          }
        }
      }
    }
  }

  // Fallback to wildcard '*' groups if no specific user-agent matched
  if (bestSpecificity === -1) {
    for (const group of parsed.groups) {
      if (group.userAgents.some((ua) => ua.trim() === "*")) {
        matchedAgentLabel = "*";
        matchedRules.push(...group.rules);
        if (crawlDelay === undefined && group.crawlDelay !== undefined) {
          crawlDelay = group.crawlDelay;
        }
      }
    }
  }

  if (matchedAgentLabel === null) {
    return {
      allowed: true,
      matchedGroup: null,
      matchedRule: null,
      reason: `No User-agent group matched "${targetUa}" — crawling is allowed by default (RFC 9309).`,
    };
  }

  // Evaluate all rules in the winning group(s): longest pattern wins; Allow wins ties (RFC 9309 §2.2.2)
  let winningRule: RobotsRule | null = null;
  let winningLen = -1;

  for (const rule of matchedRules) {
    // Empty Disallow: means allow everything (no disallow match)
    if (rule.path === "") continue;

    if (matchesRobotsPattern(rule.path, path)) {
      const ruleLen = rule.path.length;
      if (
        ruleLen > winningLen ||
        (ruleLen === winningLen && rule.type === "allow" && winningRule?.type === "disallow")
      ) {
        winningLen = ruleLen;
        winningRule = rule;
      }
    }
  }

  if (!winningRule) {
    return {
      allowed: true,
      matchedGroup: matchedAgentLabel,
      matchedRule: null,
      reason: `Matched group "User-agent: ${matchedAgentLabel}", but no Disallow rule blocked "${path}" — allowed by default.`,
      crawlDelay,
    };
  }

  const allowed = winningRule.type === "allow";
  return {
    allowed,
    matchedGroup: matchedAgentLabel,
    matchedRule: { type: winningRule.type, path: winningRule.path },
    reason: allowed
      ? `Explicitly allowed by "${winningRule.type === "allow" ? "Allow" : "Disallow"}: ${winningRule.path}" in User-agent: ${matchedAgentLabel} (line ${winningRule.lineNumber}).`
      : `Blocked by "Disallow: ${winningRule.path}" in User-agent: ${matchedAgentLabel} (line ${winningRule.lineNumber}).`,
    crawlDelay,
  };
}
