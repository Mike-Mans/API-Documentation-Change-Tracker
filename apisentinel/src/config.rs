use std::path::PathBuf;

/// A documentation source to monitor.
#[derive(Debug, Clone)]
pub struct MonitoredDoc {
    pub url: &'static str,
    pub name: &'static str,
    pub doc_type: DocType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DocType {
    OpenApi,
    AsyncApi,
    Changelog,
}

/// A DNS host to monitor.
#[derive(Debug, Clone)]
pub struct MonitoredHost {
    pub hostname: &'static str,
    pub record_types: &'static [&'static str],
    pub trace: bool,
}

pub const RESOLVERS: &[&str] = &["", "1.1.1.1", "8.8.8.8"];

pub const DOCS: &[MonitoredDoc] = &[
    MonitoredDoc {
        url: "https://docs.kalshi.com/openapi.yaml",
        name: "Kalshi OpenAPI",
        doc_type: DocType::OpenApi,
    },
    MonitoredDoc {
        url: "https://docs.kalshi.com/asyncapi.yaml",
        name: "Kalshi AsyncAPI",
        doc_type: DocType::AsyncApi,
    },
    MonitoredDoc {
        url: "https://docs.kalshi.com/changelog",
        name: "Kalshi Changelog",
        doc_type: DocType::Changelog,
    },
];

pub const HOSTS: &[MonitoredHost] = &[
    MonitoredHost {
        hostname: "docs.kalshi.com",
        record_types: &["A", "AAAA", "CNAME"],
        trace: true,
    },
    MonitoredHost {
        hostname: "api.elections.kalshi.com",
        record_types: &["A", "AAAA", "CNAME"],
        trace: true,
    },
    MonitoredHost {
        hostname: "kalshi.com",
        record_types: &["NS"],
        trace: false,
    },
];

pub struct Config {
    pub db_path: PathBuf,
    pub poll_interval_secs: u64,
    pub trace_interval_secs: u64,
    pub request_timeout_secs: u64,
    pub slack_webhook_url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        let base = std::env::current_exe()
            .unwrap_or_else(|_| PathBuf::from("."))
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf();

        Self {
            db_path: base.join("data").join("sentinel.db"),
            poll_interval_secs: 10 * 60,
            trace_interval_secs: 60 * 60,
            request_timeout_secs: 30,
            slack_webhook_url: std::env::var("SENTINEL_SLACK_WEBHOOK").ok(),
        }
    }
}

impl Config {
    /// Build config using the project data/ directory relative to CWD.
    pub fn with_cwd_data() -> Self {
        let data_dir = PathBuf::from("data");
        std::fs::create_dir_all(&data_dir).ok();
        Self {
            db_path: data_dir.join("sentinel.db"),
            ..Self::default()
        }
    }
}
