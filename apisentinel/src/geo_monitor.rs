//! Infrastructure / hosting monitor for the Kalshi API server.
//!
//! Resolves api.elections.kalshi.com, then cross-references each IP against
//! the official AWS IP ranges (ip-ranges.amazonaws.com/ip-ranges.json) to
//! determine:
//!   - Which cloud provider hosts it (AWS, Cloudflare, GCP, etc.)
//!   - Which AWS service/region (e.g. CLOUDFRONT/GLOBAL, EC2/us-east-1, ...)
//!
//! This is location-independent — unlike a geo lookup, the same IP always
//! maps to the same AWS region regardless of where the query runs.
//!
//! Currently api.elections.kalshi.com is fronted by CloudFront (GLOBAL).
//! Alert fires if the provider or AWS region changes.

use crate::alerts::{Alert, AlertManager, AlertType, Severity};
use crate::database::Database;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, ToSocketAddrs};
use std::str::FromStr;
use std::time::Duration;
use tracing::{error, info, warn};

const API_HOST: &str = "api.elections.kalshi.com";
const AWS_IP_RANGES_URL: &str = "https://ip-ranges.amazonaws.com/ip-ranges.json";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct HostingInfo {
    ip: String,
    provider: String, // "AWS", "GCP", "Cloudflare", "Unknown", …
    service: String,  // "CLOUDFRONT", "EC2", "ELB", … or "unknown"
    region: String,   // "GLOBAL", "us-east-1", "us-west-2", … or "unknown"
}

impl HostingInfo {
    fn label(&self) -> String {
        format!("{} / {} / {}", self.provider, self.service, self.region)
    }
}

pub struct GeoMonitor<'a> {
    db: &'a Database,
    alerts: &'a AlertManager,
    client: Client,
}

impl<'a> GeoMonitor<'a> {
    pub fn new(db: &'a Database, alerts: &'a AlertManager) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(20))
            .user_agent("API-Sentinel/0.1")
            .build()
            .expect("failed to build geo HTTP client");
        Self { db, alerts, client }
    }

    pub fn check(&self) {
        if let Err(e) = self.check_inner() {
            error!(error = %e, "infrastructure check failed");
        }
    }

    fn check_inner(&self) -> anyhow::Result<()> {
        let ips = resolve_ips(API_HOST)?;
        if ips.is_empty() {
            warn!(host = API_HOST, "could not resolve any IPs");
            return Ok(());
        }

        let ip = &ips[0];
        let info = self.lookup_hosting(ip)?;

        info!(
            host = API_HOST,
            ip,
            provider = %info.provider,
            service = %info.service,
            region = %info.region,
            "infrastructure check complete"
        );

        let previous = self.db.get_geo_baseline(API_HOST)?;
        self.db.set_geo_baseline(API_HOST, &serde_json::to_string(&info)?)?;

        let Some(prev_json) = previous else {
            info!(host = API_HOST, hosting = %info.label(), "infrastructure baseline recorded");
            return Ok(());
        };

        // Gracefully handle baseline format changes — treat parse error as no baseline.
        let prev: HostingInfo = match serde_json::from_str(&prev_json) {
            Ok(v) => v,
            Err(_) => {
                info!(host = API_HOST, "baseline format changed — resetting");
                return Ok(());
            }
        };

        if prev.label() != info.label() {
            warn!(
                host = API_HOST,
                old = %prev.label(),
                new = %info.label(),
                "API server infrastructure changed — consider relocating VPS"
            );

            self.alerts.emit(&Alert {
                alert_type: AlertType::ApiGeoRelocation,
                severity: Severity::High,
                title: format!("API server infrastructure changed: {API_HOST}"),
                details: format!(
                    "Previous: {}\nCurrent:  {}\nNew IP: {ip}\n\nAction: Review whether VPS should be relocated.",
                    prev.label(),
                    info.label(),
                ),
                source: API_HOST.to_string(),
            });
        }

        Ok(())
    }

    fn lookup_hosting(&self, ip: &str) -> anyhow::Result<HostingInfo> {
        // Try AWS IP ranges first.
        if let Some(aws) = self.lookup_aws(ip)? {
            return Ok(HostingInfo {
                ip: ip.to_string(),
                provider: "AWS".to_string(),
                service: aws.0,
                region: aws.1,
            });
        }

        // Fall back to ip-api.com for non-AWS IPs.
        let fallback = self.lookup_ipapi(ip)?;
        Ok(HostingInfo {
            ip: ip.to_string(),
            provider: fallback.0,
            service: "unknown".to_string(),
            region: fallback.1,
        })
    }

    /// Returns (service, region) if the IP is in AWS ranges, else None.
    fn lookup_aws(&self, ip_str: &str) -> anyhow::Result<Option<(String, String)>> {
        #[derive(Deserialize)]
        struct Prefix {
            ip_prefix: Option<String>,
            ipv6_prefix: Option<String>,
            region: String,
            service: String,
        }
        #[derive(Deserialize)]
        struct AwsRanges {
            prefixes: Vec<Prefix>,
            ipv6_prefixes: Vec<Prefix>,
        }

        let ranges: AwsRanges = self.client.get(AWS_IP_RANGES_URL).send()?.json()?;
        let ip: IpAddr = IpAddr::from_str(ip_str)?;

        // Use longest-prefix-match: the most specific (highest prefix length) wins.
        // This ensures "CLOUDFRONT/52.84.0.0/15" beats "AMAZON/52.0.0.0/8".
        let mut best: Option<(u32, String, String)> = None; // (prefix_len, service, region)
        for prefix in ranges.prefixes.iter().chain(ranges.ipv6_prefixes.iter()) {
            let cidr = prefix.ip_prefix.as_deref()
                .or(prefix.ipv6_prefix.as_deref())
                .unwrap_or("");
            if cidr_contains(cidr, ip) {
                let prefix_len: u32 = cidr.split_once('/')
                    .and_then(|(_, b)| b.parse().ok())
                    .unwrap_or(0);
                if best.as_ref().map_or(true, |(best_len, _, _)| prefix_len > *best_len) {
                    best = Some((prefix_len, prefix.service.clone(), prefix.region.clone()));
                }
            }
        }
        Ok(best.map(|(_, svc, region)| (svc, region)))
    }

    /// Returns (org, city) via ip-api.com for non-AWS IPs.
    fn lookup_ipapi(&self, ip: &str) -> anyhow::Result<(String, String)> {
        #[derive(Deserialize)]
        struct Resp {
            org: Option<String>,
            city: Option<String>,
        }
        let url = format!("http://ip-api.com/json/{ip}?fields=org,city");
        let resp: Resp = self.client.get(&url).send()?.json()?;
        Ok((
            resp.org.unwrap_or_else(|| "Unknown".to_string()),
            resp.city.unwrap_or_else(|| "unknown".to_string()),
        ))
    }
}

fn resolve_ips(host: &str) -> anyhow::Result<Vec<String>> {
    let addrs: Vec<String> = format!("{host}:443")
        .to_socket_addrs()?
        .map(|a| a.ip().to_string())
        .collect();
    Ok(addrs)
}

/// Check if a CIDR string (e.g. "52.84.0.0/15") contains the given IP.
fn cidr_contains(cidr: &str, ip: IpAddr) -> bool {
    let Some((prefix_str, bits_str)) = cidr.split_once('/') else { return false };
    let Ok(bits) = bits_str.parse::<u32>() else { return false };
    match (IpAddr::from_str(prefix_str), ip) {
        (Ok(IpAddr::V4(network)), IpAddr::V4(addr)) => {
            let mask = if bits == 0 { 0u32 } else { !0u32 << (32 - bits) };
            (u32::from(network) & mask) == (u32::from(addr) & mask)
        }
        (Ok(IpAddr::V6(network)), IpAddr::V6(addr)) => {
            let n = u128::from(network);
            let a = u128::from(addr);
            let mask = if bits == 0 { 0u128 } else { !0u128 << (128 - bits) };
            (n & mask) == (a & mask)
        }
        _ => false,
    }
}
