//! DNS infrastructure monitor.
//!
//! Uses the `dig` command via subprocess to query DNS records across
//! multiple resolvers and detect changes.

use crate::alerts::{Alert, AlertManager, AlertType, Severity};
use crate::config::MonitoredHost;
use crate::database::{Database, DnsSnapshot};
use chrono::Utc;
use std::process::Command;
use tracing::{error, info};

pub struct DnsMonitor<'a> {
    db: &'a Database,
    alerts: &'a AlertManager,
    resolvers: Vec<String>,
}

impl<'a> DnsMonitor<'a> {
    pub fn new(db: &'a Database, alerts: &'a AlertManager, resolvers: &[&str]) -> Self {
        Self {
            db,
            alerts,
            resolvers: resolvers.iter().map(|s| s.to_string()).collect(),
        }
    }

    /// Run standard record queries for all hosts.
    pub fn check_all(&self, hosts: &[MonitoredHost]) {
        for host in hosts {
            for rtype in host.record_types {
                for resolver in &self.resolvers {
                    if let Err(e) = self.check_record(host.hostname, rtype, resolver) {
                        error!(
                            host = host.hostname, record_type = rtype,
                            resolver = resolver.as_str(), error = %e,
                            "DNS check failed"
                        );
                    }
                }
            }
        }
    }

    /// Run trace queries for hosts that have trace enabled (once per hour).
    pub fn check_traces(&self, hosts: &[MonitoredHost]) {
        for host in hosts {
            if !host.trace {
                continue;
            }
            if let Err(e) = self.check_trace(host.hostname) {
                error!(host = host.hostname, error = %e, "DNS trace failed");
            }
        }
    }

    fn check_record(&self, host: &str, rtype: &str, resolver: &str) -> Result<(), Box<dyn std::error::Error>> {
        let output = run_dig(host, rtype, resolver)?;
        let parsed = parse_dig_output(&output);

        let now = Utc::now().to_rfc3339();
        let resolver_label = if resolver.is_empty() {
            "default"
        } else {
            resolver
        };

        let snap = DnsSnapshot {
            id: None,
            host: host.to_string(),
            resolver: resolver_label.to_string(),
            record_type: rtype.to_string(),
            timestamp: now,
            ttl: parsed.ttl,
            answers: parsed.answers.clone(),
            authority: parsed.authority.clone(),
            additional: parsed.additional.clone(),
        };

        let previous = self.db.latest_dns_snapshot(host, resolver_label, rtype)?;
        self.db.insert_dns_snapshot(&snap)?;

        let Some(prev) = previous else {
            info!(host, record_type = rtype, resolver = resolver_label, "first DNS snapshot recorded");
            return Ok(());
        };

        // Compare answers — normalize out TTL so a TTL-only change doesn't
        // fire DNS_ANSWER_CHANGE (that's what DNS_TTL_CHANGE is for).
        let mut old_answers: Vec<String> = prev.answers.iter().map(|a| strip_ttl(a)).collect();
        let mut new_answers: Vec<String> = parsed.answers.iter().map(|a| strip_ttl(a)).collect();
        old_answers.sort();
        new_answers.sort();

        if old_answers != new_answers {
            let alert_type = if rtype == "NS" {
                AlertType::DnsDelegationChange
            } else {
                AlertType::DnsAnswerChange
            };
            let severity = if rtype == "NS" {
                Severity::High
            } else {
                Severity::Medium
            };

            let old_str = old_answers.join(", ");
            let new_str = new_answers.join(", ");

            self.alerts.emit(&Alert {
                alert_type,
                severity,
                title: format!(
                    "Possible infrastructure change: {} {} via {}",
                    host, rtype, resolver_label
                ),
                details: format!("Old answers: {old_str}\nNew answers: {new_str}"),
                source: host.to_string(),
            });

            self.db.insert_dns_event(
                host,
                &alert_type.to_string(),
                Some(&old_str),
                Some(&new_str),
                severity.as_str(),
            )?;
        }

        // Compare TTL
        if let (Some(old_ttl), Some(new_ttl)) = (prev.ttl, parsed.ttl) {
            if old_ttl != new_ttl {
                self.alerts.emit(&Alert {
                    alert_type: AlertType::DnsTtlChange,
                    severity: Severity::Low,
                    title: format!(
                        "TTL change for {} {} via {}",
                        host, rtype, resolver_label
                    ),
                    details: format!("Old TTL: {old_ttl}\nNew TTL: {new_ttl}"),
                    source: host.to_string(),
                });

                self.db.insert_dns_event(
                    host,
                    "DNS_TTL_CHANGE",
                    Some(&old_ttl.to_string()),
                    Some(&new_ttl.to_string()),
                    Severity::Low.as_str(),
                )?;
            }
        }

        Ok(())
    }

    fn check_trace(&self, host: &str) -> Result<(), Box<dyn std::error::Error>> {
        info!(host, "running dig +trace");

        let output = Command::new("dig")
            .args(["+trace", host])
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();

        let now = Utc::now().to_rfc3339();
        let snap = DnsSnapshot {
            id: None,
            host: host.to_string(),
            resolver: "trace".to_string(),
            record_type: "TRACE".to_string(),
            timestamp: now,
            ttl: None,
            answers: vec![stdout.clone()],
            authority: None,
            additional: None,
        };

        let previous = self.db.latest_dns_snapshot(host, "trace", "TRACE")?;
        self.db.insert_dns_snapshot(&snap)?;

        if let Some(prev) = previous {
            if prev.answers != vec![stdout.clone()] {
                // Trace output varies naturally (TTL decay, different Anycast nodes per run).
                // Log the difference for reference but do NOT emit an alert — real IP
                // changes are already caught by the A/AAAA record checks via 3 resolvers.
                tracing::info!(
                    host,
                    "dig +trace output changed (stored in DB for reference)"
                );
            }
        }

        Ok(())
    }
}

// ── dig subprocess ──

fn run_dig(host: &str, rtype: &str, resolver: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut args = vec![host.to_string(), rtype.to_string()];
    if !resolver.is_empty() {
        args.push(format!("@{resolver}"));
    }

    let output = Command::new("dig").args(&args).output()?;
    Ok(String::from_utf8_lossy(&output.stdout).to_string())
}

// ── dig output parser ──

struct ParsedDig {
    answers: Vec<String>,
    ttl: Option<i64>,
    authority: Option<String>,
    additional: Option<String>,
}

/// Strip the TTL field from a DNS record string so answer comparison
/// ignores natural TTL decay. Format: "name TTL class type data..."
fn strip_ttl(record: &str) -> String {
    let parts: Vec<&str> = record.split_whitespace().collect();
    if parts.len() >= 2 {
        // Reconstruct as "name class type data..." (drop index 1 = TTL)
        let mut out = vec![parts[0]];
        out.extend_from_slice(&parts[2..]);
        out.join(" ")
    } else {
        record.to_string()
    }
}

fn parse_dig_output(raw: &str) -> ParsedDig {
    let mut answers = Vec::new();
    let mut authority_lines = Vec::new();
    let mut additional_lines = Vec::new();
    let mut section = "";
    let mut first_ttl: Option<i64> = None;

    for line in raw.lines() {
        let trimmed = line.trim();

        if trimmed.starts_with(";; ANSWER SECTION:") {
            section = "answer";
            continue;
        } else if trimmed.starts_with(";; AUTHORITY SECTION:") {
            section = "authority";
            continue;
        } else if trimmed.starts_with(";; ADDITIONAL SECTION:") {
            section = "additional";
            continue;
        } else if trimmed.starts_with(";;") || trimmed.is_empty() {
            if !trimmed.starts_with(";; ANSWER")
                && !trimmed.starts_with(";; AUTHORITY")
                && !trimmed.starts_with(";; ADDITIONAL")
            {
                section = "";
            }
            continue;
        }

        match section {
            "answer" => {
                answers.push(trimmed.to_string());
                if first_ttl.is_none() {
                    // Parse TTL from second field: "host. TTL IN TYPE data"
                    let parts: Vec<&str> = trimmed.split_whitespace().collect();
                    if parts.len() >= 2 {
                        first_ttl = parts[1].parse().ok();
                    }
                }
            }
            "authority" => {
                authority_lines.push(trimmed.to_string());
            }
            "additional" => {
                additional_lines.push(trimmed.to_string());
            }
            _ => {}
        }
    }

    ParsedDig {
        answers,
        ttl: first_ttl,
        authority: if authority_lines.is_empty() {
            None
        } else {
            Some(authority_lines.join("\n"))
        },
        additional: if additional_lines.is_empty() {
            None
        } else {
            Some(additional_lines.join("\n"))
        },
    }
}
