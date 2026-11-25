use std::net::IpAddr;
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::time::timeout;

use crate::dns::{build_resolver, normalize_domain};
use crate::models::{TracerouteHop, TracerouteReport};

const TRACEROUTE_TIMEOUT: Duration = Duration::from_secs(20);

fn validate_traceroute_target(raw: &str) -> Result<(String, Option<String>), String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("Traceroute target cannot be empty.".to_string());
    }
    if trimmed.starts_with('-') {
        return Err("Invalid traceroute target.".to_string());
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok((ip.to_string(), Some(ip.to_string())));
    }
    let clean = normalize_domain(trimmed)?;
    Ok((clean, None))
}

fn is_ip_token(tok: &str) -> bool {
    let clean = tok.trim_matches(['(', ')', '[', ']', ',']);
    clean.parse::<IpAddr>().is_ok()
}

pub fn parse_traceroute_output(stdout: &str) -> Vec<TracerouteHop> {
    let mut hops = Vec::new();
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let tokens: Vec<&str> = trimmed.split_whitespace().collect();
        if tokens.is_empty() {
            continue;
        }
        // Skip tracepath PMTU header lines like "1?: [LOCALHOST] pmtu 1500"
        if tokens[0].ends_with("?:") || trimmed.contains("[LOCALHOST]") {
            continue;
        }
        // Linux tracepath lines start with "1:"
        let hop_str = tokens[0].trim_end_matches(':');
        let Ok(hop_num) = hop_str.parse::<u8>() else {
            continue;
        };
        if hop_num == 0 {
            continue;
        }

        let mut ip: Option<String> = None;
        let mut rtt_ms: Vec<f64> = Vec::new();
        let mut all_stars = true;

        let mut i = 1usize;
        while i < tokens.len() {
            let tok = tokens[i];
            if tok != "*" && tok != "no" && tok != "reply" {
                all_stars = false;
            }

            if ip.is_none() && is_ip_token(tok) {
                ip = Some(tok.trim_matches(['(', ')', '[', ']', ',']).to_string());
            }

            // Windows tracert outputs "<1 ms" or "12 ms"; Linux outputs "12.345 ms" or "12.345ms"
            if tok == "ms" && i > 0 {
                let prev = tokens[i - 1].trim_start_matches('<');
                if let Ok(val) = prev.parse::<f64>() {
                    rtt_ms.push(val);
                }
            } else if let Some(num_part) = tok.strip_suffix("ms") {
                let prev = num_part.trim_start_matches('<');
                if let Ok(val) = prev.parse::<f64>() {
                    rtt_ms.push(val);
                }
            }

            i += 1;
        }

        let timed_out = ip.is_none() && (all_stars || trimmed.contains("Request timed out") || trimmed.contains("no reply"));
        let avg_ms = if rtt_ms.is_empty() {
            None
        } else {
            let sum: f64 = rtt_ms.iter().sum();
            Some(((sum / rtt_ms.len() as f64) * 100.0).round() / 100.0)
        };

        hops.push(TracerouteHop {
            hop: hop_num,
            ip,
            hostname: None,
            rtt_ms,
            avg_ms,
            timed_out,
        });
    }
    hops
}

pub async fn run_traceroute(target: &str) -> Result<TracerouteReport, String> {
    let (clean_target, mut resolved_ip) = validate_traceroute_target(target)?;
    let started = Instant::now();

    if resolved_ip.is_none() {
        if let Ok((_, _, resolver)) = build_resolver("cloudflare", None, false) {
            let fqdn = format!("{clean_target}.");
            if let Ok(Ok(lookup)) = timeout(
                Duration::from_secs(2),
                resolver.lookup(&fqdn, hickory_resolver::proto::rr::RecordType::A),
            )
            .await
            {
                for r in lookup.record_iter() {
                    if let hickory_resolver::proto::rr::RData::A(a) = r.data() {
                        resolved_ip = Some(a.0.to_string());
                        break;
                    }
                }
            }
        }
    }

    let exec_target = resolved_ip.clone().unwrap_or_else(|| clean_target.clone());

    #[cfg(target_os = "windows")]
    let candidates: &[(&str, &[&str])] = &[("tracert", &["-d", "-h", "20", "-w", "1500"])];

    #[cfg(not(target_os = "windows"))]
    let candidates: &[(&str, &[&str])] = &[
        ("traceroute", &["-n", "-q", "2", "-w", "2", "-m", "20"]),
        ("tracepath", &["-n", "-m", "20"]),
    ];

    let mut tool_used = String::new();
    let mut stdout_text = String::new();
    let mut stderr_text = String::new();
    let mut ran_ok = false;
    let mut spawn_errors = Vec::new();

    for (bin, base_args) in candidates {
        let mut cmd = Command::new(bin);
        for arg in *base_args {
            cmd.arg(arg);
        }
        cmd.arg(&exec_target);

        match timeout(TRACEROUTE_TIMEOUT, cmd.output()).await {
            Ok(Ok(output)) => {
                tool_used = (*bin).to_string();
                stdout_text = String::from_utf8_lossy(&output.stdout).into_owned();
                stderr_text = String::from_utf8_lossy(&output.stderr).into_owned();
                ran_ok = true;
                break;
            }
            Ok(Err(e)) => {
                spawn_errors.push(format!("{bin}: {e}"));
            }
            Err(_) => {
                return Ok(TracerouteReport {
                    target: clean_target,
                    resolved_ip,
                    tool_used: (*bin).to_string(),
                    completed: false,
                    latency_ms: started.elapsed().as_millis() as u64,
                    hops: vec![],
                    error: Some("Traceroute timed out after 20s.".to_string()),
                });
            }
        }
    }

    if !ran_ok {
        return Ok(TracerouteReport {
            target: clean_target,
            resolved_ip,
            tool_used: "none".to_string(),
            completed: false,
            latency_ms: started.elapsed().as_millis() as u64,
            hops: vec![],
            error: Some(format!(
                "No traceroute utility available ({}).",
                spawn_errors.join("; ")
            )),
        });
    }

    let hops = parse_traceroute_output(&stdout_text);
    let completed = resolved_ip
        .as_ref()
        .is_some_and(|rip| hops.iter().any(|h| h.ip.as_deref() == Some(rip.as_str())));

    let err = if hops.is_empty() && !stderr_text.trim().is_empty() {
        Some(stderr_text.trim().to_string())
    } else {
        None
    };

    Ok(TracerouteReport {
        target: clean_target,
        resolved_ip,
        tool_used,
        completed,
        latency_ms: started.elapsed().as_millis() as u64,
        hops,
        error: err,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_linux_traceroute_and_tracepath() {
        let linux_out = "\
traceroute to 1.1.1.1 (1.1.1.1), 20 hops max, 60 byte packets
 1  192.168.1.1  1.234 ms  1.456 ms
 2  * *
 3  1.1.1.1  10.500 ms  11.000 ms
";
        let hops = parse_traceroute_output(linux_out);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].hop, 1);
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].avg_ms, Some(1.35));
        assert!(hops[1].timed_out);
        assert_eq!(hops[2].ip.as_deref(), Some("1.1.1.1"));

        let tracepath_out = "\
 1?: [LOCALHOST]                      pmtu 1500
 1:  10.0.0.1                                              0.812ms
 2:  no reply
 3:  1.1.1.1                                               9.420ms reached
";
        let tp_hops = parse_traceroute_output(tracepath_out);
        assert_eq!(tp_hops.len(), 3);
        assert_eq!(tp_hops[0].ip.as_deref(), Some("10.0.0.1"));
        assert!(tp_hops[1].timed_out);
        assert_eq!(tp_hops[2].avg_ms, Some(9.42));
    }

    #[test]
    fn test_parse_windows_tracert() {
        let win_out = "\
  1    <1 ms     1 ms     1 ms  192.168.1.1
  2     *        *        *     Request timed out.
  3    12 ms    13 ms    11 ms  1.1.1.1
";
        let hops = parse_traceroute_output(win_out);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].avg_ms, Some(1.0));
        assert!(hops[1].timed_out);
        assert_eq!(hops[2].avg_ms, Some(12.0));
    }
}
