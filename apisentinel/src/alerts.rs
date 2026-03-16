use std::fmt;
use tracing::warn;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertType {
    DocRawChange,
    DocSemanticChange,
    DnsAnswerChange,
    DnsTtlChange,
    DnsDelegationChange,
}

impl fmt::Display for AlertType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DocRawChange => write!(f, "DOC_RAW_CHANGE"),
            Self::DocSemanticChange => write!(f, "DOC_SEMANTIC_CHANGE"),
            Self::DnsAnswerChange => write!(f, "DNS_ANSWER_CHANGE"),
            Self::DnsTtlChange => write!(f, "DNS_TTL_CHANGE"),
            Self::DnsDelegationChange => write!(f, "DNS_DELEGATION_CHANGE"),
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
