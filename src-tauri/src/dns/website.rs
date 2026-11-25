use std::collections::{BTreeSet, HashMap};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use futures::future::join_all;
use regex::Regex;
use reqwest::redirect::Policy;

use crate::models::{
    CookieAuditItem, DetectedTech, HttpHeaderItem, SecurityHeaderStatus, WebFileCheck,
    WebSecurityAudit, WebsiteInfo,
};

const MAX_BODY_BYTES: usize = 512 * 1024;
const MAX_SCRIPT_URLS: usize = 40;
const MAX_STYLESHEET_URLS: usize = 30;

fn re(cell: &'static OnceLock<Regex>, pattern: &str) -> &'static Regex {
    cell.get_or_init(|| Regex::new(pattern).expect("valid static regex"))
}

fn empty_website(status: &str, latency_ms: u64, error: Option<String>) -> WebsiteInfo {
    WebsiteInfo {
        status: status.to_string(),
        url: None,
        final_url: None,
        http_status: None,
        https: false,
        latency_ms,
        title: None,
        description: None,
        generator: None,
        server: None,
        powered_by: None,
        content_type: None,
        technologies: vec![],
        wordpress_plugins: vec![],
        security_headers: vec![],
        response_headers: vec![],
        script_urls: vec![],
        stylesheet_urls: vec![],
        security_audit: None,
        error,
    }
}

fn decode_basic_entities(s: &str) -> String {
    s.replace("&amp;", "&")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&quot;", "\"")
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&nbsp;", " ")
}

fn collapse_whitespace(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_title(html: &str) -> Option<String> {
    static RE_TITLE: OnceLock<Regex> = OnceLock::new();
    let cap = re(&RE_TITLE, r"(?is)<title[^>]*>(.*?)</title>").captures(html)?;
    let cleaned = collapse_whitespace(&decode_basic_entities(&cap[1]));
    if cleaned.is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

fn extract_meta_content(html: &str, meta_name: &str) -> Option<String> {
    static RE_META_TAG: OnceLock<Regex> = OnceLock::new();
    static RE_NAME_ATTR: OnceLock<Regex> = OnceLock::new();
    static RE_CONTENT_ATTR: OnceLock<Regex> = OnceLock::new();

    let tag_re = re(&RE_META_TAG, r"(?is)<meta\b[^>]*>");
    let name_re = re(
        &RE_NAME_ATTR,
        r#"(?is)\b(?:name|property)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#,
    );
    let content_re = re(
        &RE_CONTENT_ATTR,
        r#"(?is)\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#,
    );

    for m in tag_re.find_iter(html) {
        let tag = m.as_str();
        let Some(ncap) = name_re.captures(tag) else {
            continue;
        };
        let found_name = ncap
            .get(1)
            .or_else(|| ncap.get(2))
            .or_else(|| ncap.get(3))
            .map(|x| x.as_str())
            .unwrap_or("");
        if !found_name.eq_ignore_ascii_case(meta_name) {
            continue;
        }
        if let Some(ccap) = content_re.captures(tag) {
            let val = ccap
                .get(1)
                .or_else(|| ccap.get(2))
                .or_else(|| ccap.get(3))
                .map(|x| x.as_str())
                .unwrap_or("");
            let cleaned = collapse_whitespace(&decode_basic_entities(val));
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    None
}

fn extract_script_urls(html: &str) -> Vec<String> {
    static RE_SCRIPT: OnceLock<Regex> = OnceLock::new();
    let script_re = re(
        &RE_SCRIPT,
        r#"(?is)<script\b[^>]*\bsrc\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))"#,
    );
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for cap in script_re.captures_iter(html) {
        let url = cap
            .get(1)
            .or_else(|| cap.get(2))
            .or_else(|| cap.get(3))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if !url.is_empty() && seen.insert(url.to_string()) {
            out.push(url.to_string());
            if out.len() >= MAX_SCRIPT_URLS {
                break;
            }
        }
    }
    out
}

fn extract_stylesheet_urls(html: &str) -> Vec<String> {
    static RE_LINK: OnceLock<Regex> = OnceLock::new();
    static RE_REL: OnceLock<Regex> = OnceLock::new();
    static RE_HREF: OnceLock<Regex> = OnceLock::new();

    let link_re = re(&RE_LINK, r"(?is)<link\b[^>]*>");
    let rel_re = re(
        &RE_REL,
        r#"(?is)\brel\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'>]+))"#,
    );
    let href_re = re(
        &RE_HREF,
        r#"(?is)\bhref\s*=\s*(?:"([^"]+)"|'([^']+)'|([^\s"'>]+))"#,
    );

    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for m in link_re.find_iter(html) {
        let tag = m.as_str();
        let Some(rcap) = rel_re.captures(tag) else {
            continue;
        };
        let rel = rcap
            .get(1)
            .or_else(|| rcap.get(2))
            .or_else(|| rcap.get(3))
            .map(|x| x.as_str())
            .unwrap_or("");
        if !rel
            .split_whitespace()
            .any(|tok| tok.eq_ignore_ascii_case("stylesheet"))
        {
            continue;
        }
        if let Some(hcap) = href_re.captures(tag) {
            let href = hcap
                .get(1)
                .or_else(|| hcap.get(2))
                .or_else(|| hcap.get(3))
                .map(|x| x.as_str().trim())
                .unwrap_or("");
            if !href.is_empty() && seen.insert(href.to_string()) {
                out.push(href.to_string());
                if out.len() >= MAX_STYLESHEET_URLS {
                    break;
                }
            }
        }
    }
    out
}

fn extract_wp_plugins(html: &str) -> Vec<String> {
    static RE_WP_PLUGIN: OnceLock<Regex> = OnceLock::new();
    let plugin_re = re(&RE_WP_PLUGIN, r"(?i)/wp-content/plugins/([a-z0-9_-]+)/");
    let mut set = BTreeSet::new();
    for cap in plugin_re.captures_iter(html) {
        set.insert(cap[1].to_ascii_lowercase());
    }
    set.into_iter().collect()
}

fn add_tech(
    techs: &mut Vec<DetectedTech>,
    name: &str,
    category: &str,
    version: Option<String>,
    confidence: &str,
    evidence: impl Into<String>,
) {
    if let Some(existing) = techs.iter_mut().find(|t| t.name == name) {
        if existing.version.is_none() && version.is_some() {
            existing.version = version;
        }
        if existing.confidence != "high" && confidence == "high" {
            existing.confidence = "high".to_string();
        }
        return;
    }
    techs.push(DetectedTech {
        name: name.to_string(),
        category: category.to_string(),
        version: version.filter(|v| !v.is_empty()),
        confidence: confidence.to_string(),
        evidence: evidence.into(),
    });
}

fn capture_version(pattern: &Regex, text: &str) -> Option<String> {
    pattern
        .captures(text)
        .and_then(|c| c.get(1))
        .map(|m| m.as_str().to_string())
}

fn detect_technologies(
    headers: &[(String, String)],
    html: &str,
    script_urls: &[String],
    stylesheet_urls: &[String],
    generator: Option<&str>,
    wp_plugins: &[String],
) -> Vec<DetectedTech> {
    let mut techs = Vec::new();
    let mut header_map: HashMap<String, String> = HashMap::new();
    let mut cookies = Vec::new();

    for (k, v) in headers {
        let lower_k = k.to_ascii_lowercase();
        if lower_k == "set-cookie" {
            cookies.push(v.to_ascii_lowercase());
        } else {
            header_map
                .entry(lower_k)
                .and_modify(|existing| {
                    existing.push_str(", ");
                    existing.push_str(v);
                })
                .or_insert_with(|| v.clone());
        }
    }

    let cookie_blob = cookies.join("; ");
    let scripts_blob = script_urls.join("\n").to_ascii_lowercase();
    let styles_blob = stylesheet_urls.join("\n").to_ascii_lowercase();
    let assets_blob = format!("{scripts_blob}\n{styles_blob}");
    let html_lower = html.to_ascii_lowercase();
    let gen_lower = generator.unwrap_or("").to_ascii_lowercase();

    // --- JS Frameworks ---
    if html_lower.contains("__next_data__")
        || html_lower.contains("/_next/static/")
        || header_map
            .get("x-powered-by")
            .is_some_and(|v| v.to_ascii_lowercase().contains("next.js"))
    {
        add_tech(
            &mut techs,
            "Next.js",
            "JS Framework",
            None,
            "high",
            "__NEXT_DATA__ / /_next/static/ assets",
        );
        add_tech(
            &mut techs,
            "React",
            "JS Framework",
            None,
            "high",
            "Inferred via Next.js",
        );
    }

    static RE_REACT_VER: OnceLock<Regex> = OnceLock::new();
    let react_ver_re = re(&RE_REACT_VER, r"(?i)react(?:-dom)?[@/-](\d+\.\d+(?:\.\d+)?)");
    if html_lower.contains("data-reactroot")
        || html_lower.contains("data-reactid")
        || html_lower.contains("_reactlistening")
        || scripts_blob.contains("react-dom")
        || scripts_blob.contains("react.production")
        || scripts_blob.contains("react.development")
    {
        let ver = capture_version(react_ver_re, &scripts_blob)
            .or_else(|| capture_version(react_ver_re, html));
        add_tech(
            &mut techs,
            "React",
            "JS Framework",
            ver,
            "high",
            "React DOM markers / react script bundle",
        );
    }

    if html_lower.contains("__remixcontext") || html_lower.contains("__remixmanifest") {
        add_tech(
            &mut techs,
            "Remix",
            "JS Framework",
            None,
            "high",
            "__remixContext runtime marker",
        );
    }

    if html_lower.contains("___gatsby") || gen_lower.contains("gatsby") {
        add_tech(
            &mut techs,
            "Gatsby",
            "JS Framework",
            None,
            "high",
            "___gatsby container / generator",
        );
    }

    if html_lower.contains("/_nuxt/") || html_lower.contains("__nuxt__") || html_lower.contains("window.__nuxt") {
        add_tech(
            &mut techs,
            "Nuxt",
            "JS Framework",
            None,
            "high",
            "/_nuxt/ assets / __NUXT__ state",
        );
        add_tech(
            &mut techs,
            "Vue.js",
            "JS Framework",
            None,
            "high",
            "Inferred via Nuxt",
        );
    }

    static RE_VUE_SCOPED: OnceLock<Regex> = OnceLock::new();
    static RE_VUE_VER: OnceLock<Regex> = OnceLock::new();
    let vue_scoped_re = re(&RE_VUE_SCOPED, r"\bdata-v-[0-9a-f]{6,}\b");
    let vue_ver_re = re(&RE_VUE_VER, r"(?i)vue(?:@|-)(\d+\.\d+(?:\.\d+)?)");
    if vue_scoped_re.is_match(&html_lower)
        || html_lower.contains("__vue__")
        || scripts_blob.contains("/vue.")
        || scripts_blob.contains("vue.global")
        || scripts_blob.contains("vue.runtime")
        || scripts_blob.contains("vue.min.js")
    {
        let ver = capture_version(vue_ver_re, &scripts_blob);
        add_tech(
            &mut techs,
            "Vue.js",
            "JS Framework",
            ver,
            "high",
            "data-v-* scoped attributes / Vue runtime",
        );
    }

    static RE_NG_VER: OnceLock<Regex> = OnceLock::new();
    let ng_ver_re = re(&RE_NG_VER, r#"(?i)ng-version\s*=\s*["'](\d+[\d.]*)["']"#);
    if let Some(ver) = capture_version(ng_ver_re, html) {
        add_tech(
            &mut techs,
            "Angular",
            "JS Framework",
            Some(ver),
            "high",
            "ng-version attribute",
        );
    } else if html_lower.contains("_ngcontent-")
        || html_lower.contains("_nghost-")
        || scripts_blob.contains("angular.min.js")
        || scripts_blob.contains("angular.js")
        || html_lower.contains("ng-app")
    {
        add_tech(
            &mut techs,
            "Angular",
            "JS Framework",
            None,
            "high",
            "_ngcontent / ng-app / angular script",
        );
    }

    if html_lower.contains("__sveltekit_") || html_lower.contains("data-sveltekit") || html_lower.contains("svelte-") {
        add_tech(
            &mut techs,
            "Svelte / SvelteKit",
            "JS Framework",
            None,
            "high",
            "SvelteKit hydration markers",
        );
    }

    static RE_KO_SCRIPT: OnceLock<Regex> = OnceLock::new();
    static RE_KO_BIND: OnceLock<Regex> = OnceLock::new();
    static RE_KO_COMMENT: OnceLock<Regex> = OnceLock::new();
    let ko_script_re = re(&RE_KO_SCRIPT, r"(?i)knockout(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.debug|\.min)?\.js");
    let ko_bind_re = re(
        &RE_KO_BIND,
        r#"(?is)\bdata-bind\s*=\s*["']\s*(?:text|html|visible|hidden|foreach|value|textinput|click|event|css|style|attr|with|if|ifnot|template|component|options|checked|enable|disable)\s*:"#,
    );
    let ko_comment_re = re(&RE_KO_COMMENT, r"(?is)<!--\s*ko\s+");
    if ko_script_re.is_match(&scripts_blob)
        || html_lower.contains("ko.applybindings")
        || ko_bind_re.is_match(html)
        || ko_comment_re.is_match(html)
    {
        let ver = capture_version(ko_script_re, &scripts_blob)
            .or_else(|| capture_version(ko_script_re, html));
        add_tech(
            &mut techs,
            "Knockout.js",
            "JS Framework",
            ver,
            "high",
            "knockout.js / data-bind / ko.applyBindings",
        );
    }

    if scripts_blob.contains("alpine") || html_lower.contains("x-data=") {
        add_tech(
            &mut techs,
            "Alpine.js",
            "JS Framework",
            None,
            "high",
            "x-data attributes / alpinejs script",
        );
    }

    if scripts_blob.contains("htmx") || html_lower.contains("hx-get=") || html_lower.contains("hx-post=") {
        add_tech(
            &mut techs,
            "HTMX",
            "JS Framework",
            None,
            "high",
            "hx-* attributes / htmx script",
        );
    }

    if html_lower.contains("<astro-island")
        || html_lower.contains("data-astro-cid")
        || gen_lower.contains("astro")
    {
        add_tech(
            &mut techs,
            "Astro",
            "JS Framework",
            None,
            "high",
            "astro-island / data-astro-cid",
        );
    }

    if html_lower.contains("_$hy") || html_lower.contains("data-hk=") {
        add_tech(
            &mut techs,
            "SolidJS",
            "JS Framework",
            None,
            "medium",
            "Solid hydration markers",
        );
    }

    if html_lower.contains("ember-application") || html_lower.contains("ember-view") {
        add_tech(
            &mut techs,
            "Ember.js",
            "JS Framework",
            None,
            "high",
            "ember-application / ember-view class",
        );
    }

    if scripts_blob.contains("backbone") {
        add_tech(
            &mut techs,
            "Backbone.js",
            "JS Framework",
            None,
            "high",
            "backbone.js script reference",
        );
    }

    static RE_JQ_VER: OnceLock<Regex> = OnceLock::new();
    let jq_ver_re = re(&RE_JQ_VER, r"(?i)jquery(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.slim)?(?:\.min)?\.js");
    if jq_ver_re.is_match(&scripts_blob) || html_lower.contains("jquery(") || html_lower.contains("jquery.min.js") {
        let ver = capture_version(jq_ver_re, &scripts_blob)
            .or_else(|| capture_version(jq_ver_re, html));
        add_tech(
            &mut techs,
            "jQuery",
            "JS Framework",
            ver,
            "high",
            "jquery script / jQuery() usage",
        );
    }

    if assets_blob.contains("jquery-ui") || html_lower.contains("ui-widget") {
        add_tech(
            &mut techs,
            "jQuery UI",
            "UI & Plugins",
            None,
            "medium",
            "jquery-ui asset / ui-widget class",
        );
    }

    if scripts_blob.contains("lit-html") || scripts_blob.contains("lit-element") {
        add_tech(&mut techs, "Lit", "JS Framework", None, "medium", "lit-html / lit-element");
    }

    // --- CSS Frameworks ---
    static RE_TW_UTILITY: OnceLock<Regex> = OnceLock::new();
    let tw_util_re = re(
        &RE_TW_UTILITY,
        r#"(?i)\b(?:sm|md|lg|xl|2xl|hover|focus|dark):(?:flex|grid|hidden|block|text-|bg-|px-|py-|p-|m-|mt-|mb-|rounded|border)\b"#,
    );
    if assets_blob.contains("tailwind")
        || html_lower.contains("cdn.tailwindcss.com")
        || html_lower.contains("--tw-")
        || tw_util_re.find_iter(&html_lower).count() >= 3
    {
        add_tech(
            &mut techs,
            "Tailwind CSS",
            "CSS Framework",
            None,
            "high",
            "tailwindcss asset / --tw- vars / responsive utility classes",
        );
    }

    static RE_BS_VER: OnceLock<Regex> = OnceLock::new();
    let bs_ver_re = re(
        &RE_BS_VER,
        r"(?i)bootstrap(?:-(\d+\.\d+(?:\.\d+)?))?(?:\.bundle)?(?:\.min)?\.(?:css|js)",
    );
    if bs_ver_re.is_match(&assets_blob)
        || html_lower.contains("data-bs-toggle")
        || html_lower.contains("data-bs-target")
        || (html_lower.contains("navbar-expand-") && html_lower.contains("container-fluid"))
    {
        let ver = capture_version(bs_ver_re, &assets_blob)
            .or_else(|| capture_version(bs_ver_re, html));
        add_tech(
            &mut techs,
            "Bootstrap",
            "CSS Framework",
            ver,
            "high",
            "bootstrap CSS/JS / data-bs-* attributes",
        );
    }

    if styles_blob.contains("bulma") || (html_lower.contains("is-primary") && html_lower.contains("columns")) {
        add_tech(&mut techs, "Bulma", "CSS Framework", None, "medium", "bulma.css / Bulma classes");
    }

    if assets_blob.contains("foundation.") {
        add_tech(&mut techs, "Foundation", "CSS Framework", None, "high", "foundation asset");
    }

    if html_lower.contains("muibox-root") || html_lower.contains("muitypography-") || html_lower.contains("mui-style") {
        add_tech(&mut techs, "Material UI (MUI)", "CSS Framework", None, "high", "MuiBox-root / MuiTypography-*");
    }

    if html_lower.contains("chakra-ui") || html_lower.contains("data-chakra-") {
        add_tech(&mut techs, "Chakra UI", "CSS Framework", None, "high", "chakra-ui / data-chakra-*");
    }

    if html_lower.contains("ant-btn") && html_lower.contains("ant-layout") || assets_blob.contains("antd") {
        add_tech(&mut techs, "Ant Design", "CSS Framework", None, "high", "ant-btn / ant-layout / antd");
    }

    if assets_blob.contains("semantic.min.") || assets_blob.contains("fomantic") {
        add_tech(&mut techs, "Semantic / Fomantic UI", "CSS Framework", None, "high", "semantic/fomantic asset");
    }

    if assets_blob.contains("uikit") || html_lower.contains("uk-container") {
        add_tech(&mut techs, "UIkit", "CSS Framework", None, "medium", "uikit asset / uk-container");
    }

    if assets_blob.contains("daisyui") {
        add_tech(&mut techs, "DaisyUI", "CSS Framework", None, "high", "daisyui stylesheet");
    }

    if styles_blob.contains("animate.min.css") || styles_blob.contains("animate.css") {
        add_tech(&mut techs, "Animate.css", "CSS Framework", None, "high", "animate.css stylesheet");
    }

    // --- UI & Frontend Plugins ---
    if assets_blob.contains("font-awesome")
        || assets_blob.contains("fontawesome")
        || html_lower.contains("fa-solid")
        || html_lower.contains("fas fa-")
        || html_lower.contains("far fa-")
    {
        add_tech(&mut techs, "Font Awesome", "UI & Plugins", None, "high", "Font Awesome CSS/JS or fa-* classes");
    }

    if styles_blob.contains("fonts.googleapis.com") || html_lower.contains("fonts.gstatic.com") {
        add_tech(&mut techs, "Google Fonts", "UI & Plugins", None, "high", "fonts.googleapis.com / gstatic");
    }

    if assets_blob.contains("bootstrap-icons") {
        add_tech(&mut techs, "Bootstrap Icons", "UI & Plugins", None, "high", "bootstrap-icons asset");
    }

    if assets_blob.contains("swiper") {
        add_tech(&mut techs, "Swiper", "UI & Plugins", None, "high", "swiper script/stylesheet");
    }

    if assets_blob.contains("slick.") || assets_blob.contains("slick-carousel") {
        add_tech(&mut techs, "Slick Carousel", "UI & Plugins", None, "high", "slick asset");
    }

    if assets_blob.contains("datatables") {
        add_tech(&mut techs, "DataTables", "UI & Plugins", None, "high", "datatables asset");
    }

    if assets_blob.contains("select2") {
        add_tech(&mut techs, "Select2", "UI & Plugins", None, "high", "select2 asset");
    }

    if scripts_blob.contains("chart.min.js") || scripts_blob.contains("chart.js") || scripts_blob.contains("chart.umd") {
        add_tech(&mut techs, "Chart.js", "UI & Plugins", None, "high", "chart.js script");
    }

    if scripts_blob.contains("d3.min.js") || scripts_blob.contains("d3.v") {
        add_tech(&mut techs, "D3.js", "UI & Plugins", None, "high", "d3.js script");
    }

    if scripts_blob.contains("three.min.js") || scripts_blob.contains("three.module.js") {
        add_tech(&mut techs, "Three.js", "UI & Plugins", None, "high", "three.js script");
    }

    if scripts_blob.contains("gsap") {
        add_tech(&mut techs, "GSAP", "UI & Plugins", None, "high", "gsap animation script");
    }

    if scripts_blob.contains("lodash") {
        add_tech(&mut techs, "Lodash", "UI & Plugins", None, "high", "lodash script");
    }

    if scripts_blob.contains("axios") {
        add_tech(&mut techs, "Axios", "UI & Plugins", None, "high", "axios script");
    }

    if assets_blob.contains("/aos.") || assets_blob.contains("aos.min") {
        add_tech(&mut techs, "AOS (Animate On Scroll)", "UI & Plugins", None, "high", "aos asset");
    }

    if scripts_blob.contains("tinymce") {
        add_tech(&mut techs, "TinyMCE", "UI & Plugins", None, "high", "tinymce script");
    }

    if scripts_blob.contains("ckeditor") {
        add_tech(&mut techs, "CKEditor", "UI & Plugins", None, "high", "ckeditor script");
    }

    if wp_plugins.iter().any(|p| p == "elementor") || html_lower.contains("elementor-") {
        add_tech(&mut techs, "Elementor", "UI & Plugins", None, "high", "WordPress Elementor plugin / classes");
    }

    if wp_plugins.iter().any(|p| p == "woocommerce") || html_lower.contains("woocommerce") {
        add_tech(&mut techs, "WooCommerce", "UI & Plugins", None, "high", "WooCommerce plugin / markup");
    }

    if wp_plugins.iter().any(|p| p.contains("yoast")) || html_lower.contains("yoast seo") {
        add_tech(&mut techs, "Yoast SEO", "UI & Plugins", None, "high", "Yoast SEO plugin / meta comment");
    }

    if wp_plugins.iter().any(|p| p == "contact-form-7") || html_lower.contains("wpcf7") {
        add_tech(&mut techs, "Contact Form 7", "UI & Plugins", None, "high", "contact-form-7 / wpcf7");
    }

    if scripts_blob.contains("js.stripe.com") {
        add_tech(&mut techs, "Stripe", "UI & Plugins", None, "high", "js.stripe.com");
    }

    if scripts_blob.contains("google.com/recaptcha") || html_lower.contains("g-recaptcha") {
        add_tech(&mut techs, "Google reCAPTCHA", "UI & Plugins", None, "high", "recaptcha script / g-recaptcha");
    }

    if scripts_blob.contains("challenges.cloudflare.com/turnstile") || html_lower.contains("cf-turnstile") {
        add_tech(&mut techs, "Cloudflare Turnstile", "UI & Plugins", None, "high", "turnstile script / cf-turnstile");
    }

    if scripts_blob.contains("hcaptcha.com") || html_lower.contains("h-captcha") {
        add_tech(&mut techs, "hCaptcha", "UI & Plugins", None, "high", "hcaptcha.com / h-captcha");
    }

    // --- CMS & Platform ---
    static RE_WP_VER: OnceLock<Regex> = OnceLock::new();
    let wp_ver_re = re(&RE_WP_VER, r"(?i)wordpress\s+(\d+\.\d+(?:\.\d+)?)");
    if html_lower.contains("/wp-content/")
        || html_lower.contains("/wp-includes/")
        || gen_lower.contains("wordpress")
    {
        let ver = capture_version(wp_ver_re, generator.unwrap_or(""));
        add_tech(
            &mut techs,
            "WordPress",
            "CMS & Platform",
            ver,
            "high",
            "/wp-content/ /wp-includes/ or meta generator",
        );
    }

    if html_lower.contains("cdn.shopify.com")
        || html_lower.contains("shopify.theme")
        || header_map.contains_key("x-shopid")
    {
        add_tech(&mut techs, "Shopify", "CMS & Platform", None, "high", "cdn.shopify.com / Shopify.theme");
    }

    if html_lower.contains("data-wf-site")
        || scripts_blob.contains("webflow")
        || assets_blob.contains("website-files.com")
    {
        add_tech(&mut techs, "Webflow", "CMS & Platform", None, "high", "data-wf-site / webflow assets");
    }

    if html_lower.contains("static.wixstatic.com")
        || header_map.contains_key("x-wix-request-id")
        || gen_lower.contains("wix.com")
    {
        add_tech(&mut techs, "Wix", "CMS & Platform", None, "high", "wixstatic.com / x-wix-request-id");
    }

    if html_lower.contains("static1.squarespace.com") || html_lower.contains("squarespace.constants") {
        add_tech(&mut techs, "Squarespace", "CMS & Platform", None, "high", "squarespace.com assets");
    }

    if html_lower.contains("drupal.settings")
        || html_lower.contains("/sites/default/files/")
        || header_map.contains_key("x-drupal-cache")
        || gen_lower.contains("drupal")
    {
        add_tech(&mut techs, "Drupal", "CMS & Platform", None, "high", "Drupal.settings / x-drupal-cache");
    }

    if gen_lower.contains("joomla") || html_lower.contains("/media/jui/") {
        add_tech(&mut techs, "Joomla", "CMS & Platform", None, "high", "Joomla generator / /media/jui/");
    }

    if header_map.keys().any(|k| k.starts_with("x-magento-"))
        || html_lower.contains("text/x-magento-init")
        || html_lower.contains("mage.cookies")
    {
        add_tech(&mut techs, "Magento", "CMS & Platform", None, "high", "x-magento-* / x-magento-init");
    }

    if gen_lower.contains("ghost") {
        add_tech(&mut techs, "Ghost", "CMS & Platform", None, "high", "Ghost meta generator");
    }

    for (gen_key, label) in [
        ("hugo", "Hugo"),
        ("jekyll", "Jekyll"),
        ("docusaurus", "Docusaurus"),
        ("eleventy", "Eleventy"),
        ("vitepress", "VitePress"),
    ] {
        if gen_lower.contains(gen_key) {
            add_tech(&mut techs, label, "CMS & Platform", None, "high", format!("Meta generator: {}", generator.unwrap_or(label)));
        }
    }

    if html_lower.contains("framerusercontent.com") || gen_lower.contains("framer") {
        add_tech(&mut techs, "Framer", "CMS & Platform", None, "high", "framerusercontent.com");
    }

    if scripts_blob.contains("js.hs-scripts.com") || html_lower.contains("hs-script-loader") {
        add_tech(&mut techs, "HubSpot", "CMS & Platform", None, "high", "hs-scripts.com");
    }

    if html_lower.contains("prestashop") {
        add_tech(&mut techs, "PrestaShop", "CMS & Platform", None, "medium", "PrestaShop marker");
    }

    // --- Server & Backend ---
    if let Some(srv) = header_map.get("server") {
        let s_low = srv.to_ascii_lowercase();
        for (needle, label) in [
            ("nginx", "Nginx"),
            ("apache", "Apache HTTP Server"),
            ("litespeed", "LiteSpeed"),
            ("microsoft-iis", "Microsoft IIS"),
            ("caddy", "Caddy"),
            ("openresty", "OpenResty"),
            ("envoy", "Envoy"),
            ("gunicorn", "Gunicorn"),
            ("kestrel", "Kestrel"),
        ] {
            if s_low.contains(needle) {
                add_tech(&mut techs, label, "Server & Backend", None, "high", format!("Server: {srv}"));
            }
        }
    }

    if let Some(xpb) = header_map.get("x-powered-by") {
        let p_low = xpb.to_ascii_lowercase();
        if p_low.contains("php") {
            add_tech(&mut techs, "PHP", "Server & Backend", None, "high", format!("X-Powered-By: {xpb}"));
        }
        if p_low.contains("asp.net") {
            add_tech(&mut techs, "ASP.NET", "Server & Backend", None, "high", format!("X-Powered-By: {xpb}"));
        }
        if p_low.contains("express") {
            add_tech(&mut techs, "Express", "Server & Backend", None, "high", format!("X-Powered-By: {xpb}"));
        }
    }

    if cookie_blob.contains("phpsessid") {
        add_tech(&mut techs, "PHP", "Server & Backend", None, "high", "PHPSESSID cookie");
    }
    if cookie_blob.contains("asp.net_sessionid")
        || header_map.contains_key("x-aspnet-version")
        || html_lower.contains("__viewstate")
    {
        add_tech(&mut techs, "ASP.NET", "Server & Backend", None, "high", "ASP.NET header / __VIEWSTATE / cookie");
    }
    if cookie_blob.contains("laravel_session") {
        add_tech(&mut techs, "Laravel", "Server & Backend", None, "high", "laravel_session cookie");
    }
    if cookie_blob.contains("csrftoken") && html_lower.contains("csrfmiddlewaretoken") {
        add_tech(&mut techs, "Django", "Server & Backend", None, "high", "Django csrftoken & csrfmiddlewaretoken");
    }
    if cookie_blob.contains("jsessionid") {
        add_tech(&mut techs, "Java / Servlet", "Server & Backend", None, "high", "JSESSIONID cookie");
    }

    // --- CDN & Hosting ---
    if header_map.contains_key("cf-ray")
        || header_map
            .get("server")
            .is_some_and(|v| v.eq_ignore_ascii_case("cloudflare"))
    {
        add_tech(&mut techs, "Cloudflare", "CDN & Hosting", None, "high", "cf-ray / Server: cloudflare");
    }
    if header_map.contains_key("x-vercel-id")
        || header_map
            .get("server")
            .is_some_and(|v| v.eq_ignore_ascii_case("vercel"))
    {
        add_tech(&mut techs, "Vercel", "CDN & Hosting", None, "high", "x-vercel-id / Server: Vercel");
    }
    if header_map.contains_key("x-nf-request-id")
        || header_map
            .get("server")
            .is_some_and(|v| v.eq_ignore_ascii_case("netlify"))
    {
        add_tech(&mut techs, "Netlify", "CDN & Hosting", None, "high", "x-nf-request-id / Server: Netlify");
    }
    if header_map.contains_key("x-fastly-request-id")
        || header_map
            .get("x-served-by")
            .is_some_and(|v| v.to_ascii_lowercase().contains("cache-"))
    {
        add_tech(&mut techs, "Fastly", "CDN & Hosting", None, "high", "x-fastly-request-id / x-served-by cache-*");
    }
    if header_map.contains_key("x-amz-cf-id") || header_map.contains_key("x-amz-cf-pop") {
        add_tech(&mut techs, "AWS CloudFront", "CDN & Hosting", None, "high", "x-amz-cf-id / x-amz-cf-pop");
    }
    if header_map.keys().any(|k| k.starts_with("x-akamai-")) {
        add_tech(&mut techs, "Akamai", "CDN & Hosting", None, "high", "x-akamai-* header");
    }
    if header_map
        .get("server")
        .is_some_and(|v| v.eq_ignore_ascii_case("github.com"))
    {
        add_tech(&mut techs, "GitHub Pages", "CDN & Hosting", None, "high", "Server: GitHub.com");
    }
    if header_map.contains_key("fly-request-id") {
        add_tech(&mut techs, "Fly.io", "CDN & Hosting", None, "high", "fly-request-id header");
    }

    // --- Analytics & Services ---
    if scripts_blob.contains("googletagmanager.com/gtm.js") || html_lower.contains("gtm-") {
        add_tech(&mut techs, "Google Tag Manager", "Analytics & Services", None, "high", "googletagmanager.com/gtm.js");
    }
    if scripts_blob.contains("googletagmanager.com/gtag/js")
        || scripts_blob.contains("google-analytics.com/analytics.js")
        || html_lower.contains("gtag(")
    {
        add_tech(&mut techs, "Google Analytics", "Analytics & Services", None, "high", "gtag.js / analytics.js");
    }
    if scripts_blob.contains("static.cloudflareinsights.com") {
        add_tech(&mut techs, "Cloudflare Web Analytics", "Analytics & Services", None, "high", "cloudflareinsights.com");
    }
    if scripts_blob.contains("plausible.io/js/") {
        add_tech(&mut techs, "Plausible Analytics", "Analytics & Services", None, "high", "plausible.io/js/");
    }
    if scripts_blob.contains("matomo.js") || scripts_blob.contains("piwik.js") {
        add_tech(&mut techs, "Matomo", "Analytics & Services", None, "high", "matomo.js / piwik.js");
    }
    if scripts_blob.contains("static.hotjar.com") {
        add_tech(&mut techs, "Hotjar", "Analytics & Services", None, "high", "static.hotjar.com");
    }
    if scripts_blob.contains("clarity.ms/tag/") {
        add_tech(&mut techs, "Microsoft Clarity", "Analytics & Services", None, "high", "clarity.ms");
    }
    if scripts_blob.contains("connect.facebook.net") || html_lower.contains("fbq(") {
        add_tech(&mut techs, "Meta Pixel", "Analytics & Services", None, "high", "connect.facebook.net / fbq()");
    }
    if scripts_blob.contains("sentry-cdn.com") || html_lower.contains("sentry.io") {
        add_tech(&mut techs, "Sentry", "Analytics & Services", None, "high", "sentry-cdn.com");
    }
    if scripts_blob.contains("widget.intercom.io") {
        add_tech(&mut techs, "Intercom", "Analytics & Services", None, "high", "widget.intercom.io");
    }
    if scripts_blob.contains("static.zdassets.com") {
        add_tech(&mut techs, "Zendesk", "Analytics & Services", None, "high", "static.zdassets.com");
    }
    if scripts_blob.contains("client.crisp.chat") {
        add_tech(&mut techs, "Crisp", "Analytics & Services", None, "high", "client.crisp.chat");
    }

    techs
}

fn build_security_headers(headers: &[(String, String)]) -> Vec<SecurityHeaderStatus> {
    let check_names = [
        ("strict-transport-security", "Strict-Transport-Security"),
        ("content-security-policy", "Content-Security-Policy"),
        ("x-frame-options", "X-Frame-Options"),
        ("x-content-type-options", "X-Content-Type-Options"),
        ("referrer-policy", "Referrer-Policy"),
        ("permissions-policy", "Permissions-Policy"),
    ];

    check_names
        .into_iter()
        .map(|(lower_name, display_name)| {
            let value = headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(lower_name))
                .map(|(_, v)| v.clone());
            SecurityHeaderStatus {
                name: display_name.to_string(),
                present: value.is_some(),
                value,
            }
        })
        .collect()
}

pub fn parse_set_cookie_audit(raw_cookies: &[String], is_https: bool) -> Vec<CookieAuditItem> {
    let mut items = Vec::new();
    for raw in raw_cookies {
        let mut parts = raw.split(';');
        let first = parts.next().unwrap_or("").trim();
        let name = first
            .split_once('=')
            .map(|(k, _)| k.trim())
            .unwrap_or(first)
            .to_string();
        if name.is_empty() {
            continue;
        }

        let mut secure = false;
        let mut http_only = false;
        let mut same_site: Option<String> = None;

        for attr in parts {
            let trimmed = attr.trim();
            let lower = trimmed.to_ascii_lowercase();
            if lower == "secure" {
                secure = true;
            } else if lower == "httponly" {
                http_only = true;
            } else if let Some(val) = lower.strip_prefix("samesite=") {
                same_site = Some(val.trim().to_string());
            }
        }

        let mut issues = Vec::new();
        if is_https && !secure {
            issues.push("Missing 'Secure' flag on HTTPS site.".to_string());
        }
        if !http_only {
            let low_name = name.to_ascii_lowercase();
            if low_name.contains("sess")
                || low_name.contains("auth")
                || low_name.contains("token")
                || low_name.contains("jwt")
                || low_name.contains("sid")
            {
                issues.push("Session/auth cookie is missing 'HttpOnly' flag.".to_string());
            } else {
                issues.push("Missing 'HttpOnly' flag.".to_string());
            }
        }
        match same_site.as_deref() {
            None => issues.push("Missing 'SameSite' attribute.".to_string()),
            Some("none") if !secure => {
                issues.push("'SameSite=None' requires the 'Secure' attribute.".to_string());
            }
            _ => {}
        }

        items.push(CookieAuditItem {
            name,
            secure,
            http_only,
            same_site,
            issues,
        });
    }
    items
}

pub fn evaluate_web_file_body(
    path: &str,
    label: &str,
    category: &str,
    status_code: Option<u16>,
    content_type: Option<&str>,
    body: &str,
) -> WebFileCheck {
    let Some(code) = status_code else {
        return WebFileCheck {
            path: path.to_string(),
            label: label.to_string(),
            category: category.to_string(),
            status: "error".to_string(),
            http_status: None,
            summary: "Request failed or timed out.".to_string(),
            preview: None,
        };
    };

    if code != 200 {
        return WebFileCheck {
            path: path.to_string(),
            label: label.to_string(),
            category: category.to_string(),
            status: "missing".to_string(),
            http_status: Some(code),
            summary: if category == "exposure" {
                format!("Not exposed (HTTP {code}).")
            } else {
                format!("Not published (HTTP {code}).")
            },
            preview: None,
        };
    }

    let trimmed = body.trim();
    let lower = trimmed.to_ascii_lowercase();
    let is_html_page = content_type
        .map(|ct| ct.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
        || lower.starts_with("<!doctype html")
        || lower.starts_with("<html");

    let preview_str: String = trimmed.lines().take(5).collect::<Vec<_>>().join("\n");
    let preview = (!preview_str.is_empty()).then(|| {
        if preview_str.len() > 280 {
            format!("{}...", &preview_str[..280])
        } else {
            preview_str
        }
    });

    match path {
        "/.git/HEAD" => {
            if !is_html_page && (trimmed.starts_with("ref: refs/") || (trimmed.len() == 40 && trimmed.chars().all(|c| c.is_ascii_hexdigit()))) {
                return WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: "exposure".to_string(),
                    status: "exposed".to_string(),
                    http_status: Some(code),
                    summary: "CRITICAL: Public .git/HEAD repository metadata is exposed!".to_string(),
                    preview,
                };
            }
            WebFileCheck {
                path: path.to_string(),
                label: label.to_string(),
                category: "exposure".to_string(),
                status: "missing".to_string(),
                http_status: Some(code),
                summary: "Not exposed (soft-404/non-git response).".to_string(),
                preview: None,
            }
        }
        "/.env" => {
            let env_lines = trimmed
                .lines()
                .filter(|l| {
                    let t = l.trim();
                    !t.is_empty()
                        && !t.starts_with('#')
                        && t.split_once('=')
                            .is_some_and(|(k, _)| {
                                k.len() >= 3 && k.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
                            })
                })
                .count();
            if !is_html_page && env_lines >= 2 {
                return WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: "exposure".to_string(),
                    status: "exposed".to_string(),
                    http_status: Some(code),
                    summary: format!("CRITICAL: .env secrets file exposed ({env_lines} key=value lines)!"),
                    preview: Some("[Redacted — .env key/value signatures detected]".to_string()),
                };
            }
            WebFileCheck {
                path: path.to_string(),
                label: label.to_string(),
                category: "exposure".to_string(),
                status: "missing".to_string(),
                http_status: Some(code),
                summary: "Not exposed (soft-404/non-env response).".to_string(),
                preview: None,
            }
        }
        "/phpinfo.php" => {
            if lower.contains("phpinfo()") && lower.contains("php version") {
                return WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: "exposure".to_string(),
                    status: "exposed".to_string(),
                    http_status: Some(code),
                    summary: "HIGH: phpinfo() diagnostics page is publicly exposed!".to_string(),
                    preview: None,
                };
            }
            WebFileCheck {
                path: path.to_string(),
                label: label.to_string(),
                category: "exposure".to_string(),
                status: "missing".to_string(),
                http_status: Some(code),
                summary: "Not exposed (soft-404 response).".to_string(),
                preview: None,
            }
        }
        "/robots.txt" => {
            if !is_html_page && (lower.contains("user-agent") || lower.contains("disallow") || lower.contains("sitemap")) {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "found".to_string(),
                    http_status: Some(code),
                    summary: "Published valid robots.txt.".to_string(),
                    preview,
                }
            } else {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "missing".to_string(),
                    http_status: Some(code),
                    summary: "Returned HTML instead of robots.txt directives.".to_string(),
                    preview: None,
                }
            }
        }
        "/sitemap.xml" => {
            if lower.contains("<urlset") || lower.contains("<sitemapindex") {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "found".to_string(),
                    http_status: Some(code),
                    summary: "Valid XML sitemap detected.".to_string(),
                    preview,
                }
            } else {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "missing".to_string(),
                    http_status: Some(code),
                    summary: "No valid XML <urlset>/<sitemapindex> found.".to_string(),
                    preview: None,
                }
            }
        }
        "/.well-known/security.txt" => {
            if !is_html_page && lower.contains("contact:") {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "found".to_string(),
                    http_status: Some(code),
                    summary: "RFC 9116 security.txt published with Contact directive.".to_string(),
                    preview,
                }
            } else {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "missing".to_string(),
                    http_status: Some(code),
                    summary: "Missing RFC 9116 security.txt.".to_string(),
                    preview: None,
                }
            }
        }
        _ => {
            // /ads.txt
            if !is_html_page && trimmed.lines().any(|l| l.contains(',') && !l.trim().starts_with('#')) {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "found".to_string(),
                    http_status: Some(code),
                    summary: "Valid ads.txt entries detected.".to_string(),
                    preview,
                }
            } else {
                WebFileCheck {
                    path: path.to_string(),
                    label: label.to_string(),
                    category: category.to_string(),
                    status: "missing".to_string(),
                    http_status: Some(code),
                    summary: "No ads.txt published.".to_string(),
                    preview: None,
                }
            }
        }
    }
}

async fn audit_web_files(base_origin: &str) -> Vec<WebFileCheck> {
    let Ok(probe_client) = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(2))
        .timeout(Duration::from_millis(2500))
        .redirect(Policy::limited(2))
        .user_agent("DomainTools/1.0 (Security Hygiene Check)")
        .build()
    else {
        return vec![];
    };

    let targets = [
        ("/.well-known/security.txt", "Security Policy (security.txt)", "security"),
        ("/robots.txt", "Crawler Policy (robots.txt)", "hygiene"),
        ("/sitemap.xml", "XML Sitemap", "hygiene"),
        ("/ads.txt", "Authorized Sellers (ads.txt)", "hygiene"),
        ("/.git/HEAD", "Exposed .git Repository", "exposure"),
        ("/.env", "Exposed .env Secrets", "exposure"),
        ("/phpinfo.php", "Exposed phpinfo.php", "exposure"),
    ];

    let futs = targets.into_iter().map(|(path, label, category)| {
        let client = probe_client.clone();
        let full_url = format!("{base_origin}{path}");
        async move {
            match client.get(&full_url).send().await {
                Ok(mut resp) => {
                    let code = resp.status().as_u16();
                    let ct = resp
                        .headers()
                        .get(reqwest::header::CONTENT_TYPE)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    let mut bytes = Vec::with_capacity(4096);
                    if code == 200 {
                        while let Ok(Some(chunk)) = resp.chunk().await {
                            let rem = 8192usize.saturating_sub(bytes.len());
                            if rem == 0 {
                                break;
                            }
                            bytes.extend_from_slice(&chunk[..chunk.len().min(rem)]);
                            if bytes.len() >= 8192 {
                                break;
                            }
                        }
                    }
                    let body = String::from_utf8_lossy(&bytes);
                    evaluate_web_file_body(path, label, category, Some(code), ct.as_deref(), &body)
                }
                Err(_) => evaluate_web_file_body(path, label, category, None, None, ""),
            }
        }
    });

    join_all(futs).await
}

pub fn analyze_website_response(
    url: String,
    final_url: String,
    http_status: u16,
    latency_ms: u64,
    headers: Vec<(String, String)>,
    body_html: &str,
) -> WebsiteInfo {
    let https = final_url.starts_with("https://");
    let find_header = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.clone())
    };

    let server = find_header("server");
    let powered_by = find_header("x-powered-by");
    let content_type = find_header("content-type");

    let is_html = content_type
        .as_deref()
        .map(|ct| {
            let l = ct.to_ascii_lowercase();
            l.contains("text/html") || l.contains("application/xhtml+xml")
        })
        .unwrap_or(true);

    let (title, description, generator, script_urls, stylesheet_urls, wp_plugins) = if is_html {
        (
            extract_title(body_html),
            extract_meta_content(body_html, "description"),
            extract_meta_content(body_html, "generator"),
            extract_script_urls(body_html),
            extract_stylesheet_urls(body_html),
            extract_wp_plugins(body_html),
        )
    } else {
        (None, None, None, vec![], vec![], vec![])
    };

    let technologies = detect_technologies(
        &headers,
        if is_html { body_html } else { "" },
        &script_urls,
        &stylesheet_urls,
        generator.as_deref(),
        &wp_plugins,
    );

    let security_headers = build_security_headers(&headers);

    let raw_cookies: Vec<String> = headers
        .iter()
        .filter(|(k, _)| k.eq_ignore_ascii_case("set-cookie"))
        .map(|(_, v)| v.clone())
        .collect();
    let cookies = parse_set_cookie_audit(&raw_cookies, https);
    let cors_acao = find_header("access-control-allow-origin");
    let cors_acac = find_header("access-control-allow-credentials")
        .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
    let cors_issue = if cors_acao.as_deref() == Some("*") && cors_acac {
        Some("CORS allows wildcard origin '*' with Allow-Credentials: true.".to_string())
    } else {
        None
    };

    let mixed_content_urls: Vec<String> = if https {
        script_urls
            .iter()
            .chain(stylesheet_urls.iter())
            .filter(|u| u.to_ascii_lowercase().starts_with("http://"))
            .cloned()
            .collect()
    } else {
        vec![]
    };

    let security_audit = Some(WebSecurityAudit {
        cookies,
        cors_acao,
        cors_acac,
        cors_issue,
        mixed_content_urls,
        files: vec![],
        exposed_count: 0,
    });

    let response_headers = headers
        .into_iter()
        .filter(|(k, _)| !k.eq_ignore_ascii_case("set-cookie"))
        .map(|(name, value)| HttpHeaderItem { name, value })
        .collect();

    WebsiteInfo {
        status: "ok".to_string(),
        url: Some(url),
        final_url: Some(final_url),
        http_status: Some(http_status),
        https,
        latency_ms,
        title,
        description,
        generator,
        server,
        powered_by,
        content_type,
        technologies,
        wordpress_plugins: wp_plugins,
        security_headers,
        response_headers,
        script_urls,
        stylesheet_urls,
        security_audit,
        error: None,
    }
}

pub async fn inspect_website(domain: &str) -> WebsiteInfo {
    if domain.starts_with('_') {
        return empty_website("no_website", 0, None);
    }

    let start = Instant::now();
    let client = match reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(3))
        .timeout(Duration::from_secs(6))
        .redirect(Policy::limited(6))
        .user_agent("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) DomainTools/0.1 Chrome/131.0.0.0 Safari/537.36")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            return empty_website(
                "error",
                start.elapsed().as_millis() as u64,
                Some(format!("Failed to initialize HTTP client: {e}")),
            );
        }
    };

    let https_url = format!("https://{domain}");
    let http_url = format!("http://{domain}");

    let (attempted_url, response) = match client.get(&https_url).send().await {
        Ok(resp) => (https_url, resp),
        Err(https_err) => match client.get(&http_url).send().await {
            Ok(resp) => (http_url, resp),
            Err(http_err) => {
                let latency_ms = start.elapsed().as_millis() as u64;
                if https_err.is_connect() || http_err.is_connect() || https_err.is_timeout() {
                    return empty_website(
                        "no_website",
                        latency_ms,
                        Some(format!("No HTTP/HTTPS server reachable on {domain}")),
                    );
                }
                return empty_website(
                    "error",
                    latency_ms,
                    Some(format!("HTTPS: {https_err}; HTTP: {http_err}")),
                );
            }
        },
    };

    let final_url = response.url().to_string();
    let origin_base = reqwest::Url::parse(&final_url)
        .ok()
        .map(|u| format!("{}://{}", u.scheme(), u.host_str().unwrap_or(domain)))
        .unwrap_or_else(|| attempted_url.clone());
    let http_status = response.status().as_u16();
    let headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let mut body_bytes = Vec::with_capacity(32 * 1024);
    let mut resp = response;
    while let Ok(Some(chunk)) = resp.chunk().await {
        let remaining = MAX_BODY_BYTES.saturating_sub(body_bytes.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        body_bytes.extend_from_slice(&chunk[..take]);
        if body_bytes.len() >= MAX_BODY_BYTES {
            break;
        }
    }

    let body_html = String::from_utf8_lossy(&body_bytes);
    let files = audit_web_files(&origin_base).await;
    let exposed_count = files.iter().filter(|f| f.status == "exposed").count();

    let latency_ms = start.elapsed().as_millis() as u64;
    let mut info = analyze_website_response(
        attempted_url,
        final_url,
        http_status,
        latency_ms,
        headers,
        &body_html,
    );
    if let Some(audit) = info.security_audit.as_mut() {
        audit.files = files;
        audit.exposed_count = exposed_count;
    }
    info
}

#[cfg(test)]
mod tests {
    use super::*;

    fn has_tech(info: &WebsiteInfo, name: &str) -> bool {
        info.technologies.iter().any(|t| t.name == name)
    }

    #[test]
    fn test_detect_react_nextjs_tailwind_vercel() {
        let html = r#"
            <!doctype html>
            <html>
              <head>
                <title>Next App &amp; Docs</title>
                <meta name="description" content="Modern React storefront" />
                <script src="/_next/static/chunks/main-123.js"></script>
                <link rel="stylesheet" href="/_next/static/css/app.css" />
              </head>
              <body class="bg-slate-950 md:flex lg:grid hover:text-sky-400">
                <div id="__next"></div>
                <script id="__NEXT_DATA__" type="application/json">{}</script>
              </body>
            </html>
        "#;
        let headers = vec![
            ("server".into(), "Vercel".into()),
            ("x-vercel-id".into(), "iad1::abc".into()),
            ("content-type".into(), "text/html; charset=utf-8".into()),
            ("strict-transport-security".into(), "max-age=63072000".into()),
        ];

        let info = analyze_website_response(
            "https://example.com".into(),
            "https://example.com/".into(),
            200,
            45,
            headers,
            html,
        );

        assert_eq!(info.title.as_deref(), Some("Next App & Docs"));
        assert_eq!(info.description.as_deref(), Some("Modern React storefront"));
        assert!(has_tech(&info, "Next.js"));
        assert!(has_tech(&info, "React"));
        assert!(has_tech(&info, "Tailwind CSS"));
        assert!(has_tech(&info, "Vercel"));
        assert!(info
            .security_headers
            .iter()
            .any(|h| h.name == "Strict-Transport-Security" && h.present));
    }

    #[test]
    fn test_detect_knockout_bootstrap_jquery_aspnet() {
        let html = r#"
            <html>
              <head>
                <title>Legacy Portal</title>
                <link href="/assets/bootstrap-5.3.3.min.css" rel="stylesheet" />
                <script src="/scripts/jquery-3.7.1.min.js"></script>
                <script src="/scripts/knockout-3.5.1.js"></script>
              </head>
              <body>
                <input type="hidden" name="__VIEWSTATE" value="xyz" />
                <div data-bind="foreach: items">
                  <span data-bind="text: title"></span>
                </div>
                <script>ko.applyBindings(vm);</script>
              </body>
            </html>
        "#;
        let headers = vec![
            ("server".into(), "Microsoft-IIS/10.0".into()),
            ("x-powered-by".into(), "ASP.NET".into()),
        ];

        let info = analyze_website_response(
            "https://portal.example.com".into(),
            "https://portal.example.com/".into(),
            200,
            80,
            headers,
            html,
        );

        let ko = info
            .technologies
            .iter()
            .find(|t| t.name == "Knockout.js")
            .expect("Knockout.js not detected");
        assert_eq!(ko.version.as_deref(), Some("3.5.1"));

        let bs = info
            .technologies
            .iter()
            .find(|t| t.name == "Bootstrap")
            .expect("Bootstrap not detected");
        assert_eq!(bs.version.as_deref(), Some("5.3.3"));

        let jq = info
            .technologies
            .iter()
            .find(|t| t.name == "jQuery")
            .expect("jQuery not detected");
        assert_eq!(jq.version.as_deref(), Some("3.7.1"));

        assert!(has_tech(&info, "ASP.NET"));
        assert!(has_tech(&info, "Microsoft IIS"));
    }

    #[test]
    fn test_detect_wordpress_plugins_and_cloudflare() {
        let html = r#"
            <html>
              <head>
                <meta content="WordPress 6.6.2" name="generator" />
                <link rel="stylesheet" href="https://site.com/wp-content/plugins/elementor/assets/css/frontend.min.css" />
                <script src="https://site.com/wp-content/plugins/woocommerce/assets/js/frontend.min.js"></script>
                <script src="https://site.com/wp-content/plugins/wordpress-seo/js/dist/yoast.js"></script>
              </head>
              <body class="elementor-page"></body>
            </html>
        "#;
        let headers = vec![
            ("server".into(), "cloudflare".into()),
            ("cf-ray".into(), "8f123abc-ORD".into()),
            ("x-powered-by".into(), "PHP/8.3".into()),
        ];

        let info = analyze_website_response(
            "https://wp.example.com".into(),
            "https://wp.example.com/".into(),
            200,
            110,
            headers,
            html,
        );

        let wp = info
            .technologies
            .iter()
            .find(|t| t.name == "WordPress")
            .expect("WordPress not detected");
        assert_eq!(wp.version.as_deref(), Some("6.6.2"));
        assert_eq!(
            info.wordpress_plugins,
            vec!["elementor", "woocommerce", "wordpress-seo"]
        );
        assert!(has_tech(&info, "Elementor"));
        assert!(has_tech(&info, "WooCommerce"));
        assert!(has_tech(&info, "Cloudflare"));
        assert!(has_tech(&info, "PHP"));
    }

    #[test]
    fn test_detect_vue_nuxt_fontawesome_analytics() {
        let html = r#"
            <html>
              <head>
                <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css" />
                <script src="https://www.googletagmanager.com/gtag/js?id=G-12345"></script>
                <script src="/_nuxt/entry.js"></script>
              </head>
              <body>
                <div id="__nuxt" data-v-7ba5bd90><i class="fa-solid fa-check"></i></div>
              </body>
            </html>
        "#;

        let info = analyze_website_response(
            "https://vue.example.com".into(),
            "https://vue.example.com/".into(),
            200,
            60,
            vec![],
            html,
        );

        assert!(has_tech(&info, "Nuxt"));
        assert!(has_tech(&info, "Vue.js"));
        assert!(has_tech(&info, "Font Awesome"));
        assert!(has_tech(&info, "Google Analytics"));
    }

    #[test]
    fn test_cookie_and_exposure_audit() {
        let cookies = parse_set_cookie_audit(
            &[
                "session_id=abc123; Path=/".to_string(),
                "prefs=dark; Secure; HttpOnly; SameSite=Lax".to_string(),
            ],
            true,
        );
        assert_eq!(cookies.len(), 2);
        assert!(!cookies[0].secure);
        assert!(!cookies[0].http_only);
        assert!(cookies[0].issues.len() >= 2);
        assert!(cookies[1].issues.is_empty());

        let git_exposed = evaluate_web_file_body(
            "/.git/HEAD",
            "Exposed .git Repository",
            "exposure",
            Some(200),
            Some("text/plain"),
            "ref: refs/heads/main\n",
        );
        assert_eq!(git_exposed.status, "exposed");

        let soft_404 = evaluate_web_file_body(
            "/.git/HEAD",
            "Exposed .git Repository",
            "exposure",
            Some(200),
            Some("text/html"),
            "<!doctype html><html><body>Not found</body></html>",
        );
        assert_eq!(soft_404.status, "missing");

        let env_exposed = evaluate_web_file_body(
            "/.env",
            "Exposed .env Secrets",
            "exposure",
            Some(200),
            Some("text/plain"),
            "DB_HOST=localhost\nAPP_KEY=secret123\n",
        );
        assert_eq!(env_exposed.status, "exposed");
    }
}
