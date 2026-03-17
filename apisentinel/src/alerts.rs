use crate::bot_stop;
use std::fmt;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertType {
    DocRawChange,
    DocSemanticChange,
    DocStableChange,
    DnsAnswerChange,
    DnsTtlChange,
    DnsDelegationChange,
    ApiGeoRelocation,
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocRawChange => write!(f, "DOC_RAW_CHANGE"),
            Self::DocSemanticChange => write!(f, "DOC_SEMANTIC_CHANGE"),
            Self::DocStableChange => write!(f, "DOC_STABLE_CHANGE"),
            Self::DnsAnswerChange => write!(f, "DNS_ANSWER_CHANGE"),
            Self::DnsTtlChange => write!(f, "DNS_TTL_CHANGE"),
            Self::DnsDelegationChange => write!(f, "DNS_DELEGATION_CHANGE"),
            Self::ApiGeoRelocation => write!(f, "API_GEO_RELOCATION"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "LOW"),
            Self::Medium => write!(f, "MEDIUM"),
            Self::High => write!(f, "HIGH"),
        }
    }
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "LOW",
            Self::Medium => "MEDIUM",
            Self::High => "HIGH",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Alert {
    pub alert_type: AlertType,
    pub severity: Severity,
    pub title: String,
    pub details: String,
    pub source: String,
}

impl Alert {
    /// Whether this alert warrants stopping the trading bot immediately.
    ///
    /// Triggers:
    ///  - ApiGeoRelocation — the API server moved datacenters; VPS must follow.
    ///  - DnsDelegationChange — NS records changed for the core domain (not docs CDN).
    ///  - DocSemanticChange on AsyncAPI — WebSocket layer the bot depends on.
    ///  - DocSemanticChange on OpenAPI at Medium/High — endpoint removal, auth, schema.
    ///
    /// Not triggers:
    ///  - DnsAnswerChange — IP rotation is normal (CDN, load balancing); geo check handles this.
    ///  - DnsTtlChange — informational only.
    ///  - DocRawChange — whitespace/formatting, no semantic impact.
    pub fn should_stop_bot(&self) -> bool {
        match self.alert_type {
            // Confirmed stable doc change: same new hash for 5 consecutive cycles.
            // DocSemanticChange is informational only — the hash check is the real gate.
            // Only stop on a confirmed-stable HIGH-severity structural change.
            // Medium/Low (e.g. new endpoint added, param tweak) — alert only, no stop.
            AlertType::DocStableChange => self.severity == Severity::High,
            // Server relocation signals.
            AlertType::ApiGeoRelocation => true,
            AlertType::DnsDelegationChange => self.source != "docs.kalshi.com",
            _ => false,
        }
    }

    /// Human-readable reason passed into the stop notification.
    pub fn stop_reason(&self) -> &str {
        match self.alert_type {
            AlertType::DocStableChange => "API docs changed (confirmed stable over 5 cycles)",
            AlertType::ApiGeoRelocation => "Server relocation (datacenter change)",
            AlertType::DnsDelegationChange => "Server relocation (DNS delegation change)",
            _ => "Unknown",
        }
    }
}

pub struct AlertManager {
    slack_url: Option<String>,
    client: reqwest::blocking::Client,
}

impl AlertManager {
    pub fn new(slack_url: Option<String>) -> Self {
        Self {
            slack_url,
            client: reqwest::blocking::Client::new(),
        }
    }

    pub fn emit(&self, alert: &Alert) {
        self.console_alert(alert);
        if self.slack_url.is_some() {
            self.slack_alert(alert);
        }
        if alert.should_stop_bot() {
            bot_stop::stop_kalshi_bot(alert.stop_reason());
        }
    }

    fn console_alert(&self, alert: &Alert) {
        let sep = "=".repeat(60);
        println!("\n{sep}");
        println!("  ALERT: {}", alert.alert_type);
        println!("  Severity: {}", alert.severity);
        println!("  Source: {}", alert.source);
        println!("  {}", alert.title);
        println!("{sep}");
        println!("{}", alert.details);
        println!("{sep}");

        warn!(
            alert_type = %alert.alert_type,
            severity = %alert.severity,
            source = %alert.source,
            title = %alert.title,
            "alert emitted"
        );
    }

    fn slack_alert(&self, alert: &Alert) {
        let Some(url) = &self.slack_url else { return };
        let payload = serde_json::json!({
            "text": format!(
                "*{}* [{}]\n*{}*\nSource: `{}`\n```{}```",
                alert.alert_type, alert.severity,
                alert.title, alert.source, alert.details
            )
        });

        let result: Result<reqwest::blocking::Response, reqwest::Error> =
            self.client.post(url).json(&payload).send();
        match result {
            Ok(resp) if resp.status().is_success() => {
                tracing::info!("slack alert sent");
            }
            Ok(resp) => {
                tracing::error!(status = %resp.status(), "slack alert failed");
            }
            Err(e) => {
                tracing::error!(error = %e, "slack alert request failed");
            }
        }
    }
}
