use std::time::{Duration, Instant};

use reqwest::redirect::Policy;

use crate::dns::normalize_domain;
use crate::models::RobotsFetchResult;

const MAX_ROBOTS_BYTES: usize = 256 * 1024;
const ROBOTS_TIMEOUT_SECS: u64 = 6;

pub fn extract_sitemaps(content: &str) -> Vec<String> {
    let mut sitemaps = Vec::new();
    for line in content.lines() {
        let without_comment = line.split('#').next().unwrap_or("").trim();
        if without_comment.is_empty() {
            continue;
        }
        if let Some((key, val)) = without_comment.split_once(':') {
            if key.trim().eq_ignore_ascii_case("sitemap") {
                let url = val.trim();
                if !url.is_empty() && !sitemaps.iter().any(|existing| existing == url) {
                    sitemaps.push(url.to_string());
                }
            }
        }
    }
    sitemaps
}

async fn try_fetch_url(
    client: &reqwest::Client,
    url: &str,
) -> Result<(String, u16, String), String> {
    let mut resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| format!("Request to {url} failed: {e}"))?;

    let final_url = resp.url().to_string();
    let status = resp.status().as_u16();

    let mut body = Vec::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| format!("Failed reading response body from {final_url}: {e}"))?
    {
        let remaining = MAX_ROBOTS_BYTES.saturating_sub(body.len());
        if remaining == 0 {
            break;
        }
        let take = chunk.len().min(remaining);
        body.extend_from_slice(&chunk[..take]);
        if body.len() >= MAX_ROBOTS_BYTES {
            break;
        }
    }

    Ok((final_url, status, String::from_utf8_lossy(&body).into_owned()))
}

pub async fn fetch_robots_txt(domain_input: &str) -> Result<RobotsFetchResult, String> {
    let domain = normalize_domain(domain_input)?;
    let started = Instant::now();

    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(4))
        .timeout(Duration::from_secs(ROBOTS_TIMEOUT_SECS))
        .redirect(Policy::limited(5))
        .user_agent("DomainTools/0.3 (Robots.txt Inspector)")
        .build()
        .map_err(|e| format!("Failed to initialize HTTP client: {e}"))?;

    let https_url = format!("https://{domain}/robots.txt");
    let http_url = format!("http://{domain}/robots.txt");

    let fetch_res = match try_fetch_url(&client, &https_url).await {
        Ok(ok) => Ok(ok),
        Err(https_err) => match try_fetch_url(&client, &http_url).await {
            Ok(ok) => Ok(ok),
            Err(http_err) => Err(format!("{https_err}; HTTP fallback failed: {http_err}")),
        },
    };

    let latency_ms = started.elapsed().as_millis() as u64;

    match fetch_res {
        Ok((final_url, status, content)) => {
            let found = (200..300).contains(&status);
            let sitemaps = if found {
                extract_sitemaps(&content)
            } else {
                vec![]
            };
            let error = if found {
                None
            } else {
                Some(format!("Server returned HTTP {status} for robots.txt."))
            };
            Ok(RobotsFetchResult {
                domain,
                url: final_url,
                http_status: Some(status),
                found,
                content: if found { content } else { String::new() },
                sitemaps,
                latency_ms,
                error,
            })
        }
        Err(err) => Ok(RobotsFetchResult {
            domain,
            url: https_url,
            http_status: None,
            found: false,
            content: String::new(),
            sitemaps: vec![],
            latency_ms,
            error: Some(err),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_sitemaps() {
        let sample = "\
# Robots file
User-agent: *
Disallow: /admin/
Sitemap: https://example.com/sitemap.xml
sitemap:   https://example.com/sitemap-news.xml  # inline comment
Sitemap: https://example.com/sitemap.xml
# Sitemap: https://example.com/commented-out.xml
";
        let sitemaps = extract_sitemaps(sample);
        assert_eq!(
            sitemaps,
            vec![
                "https://example.com/sitemap.xml",
                "https://example.com/sitemap-news.xml",
            ]
        );
    }

    #[test]
    fn test_extract_sitemaps_empty() {
        let sample = "User-agent: *\nAllow: /\n";
        assert!(extract_sitemaps(sample).is_empty());
    }
}
