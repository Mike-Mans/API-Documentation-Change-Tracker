//! Documentation change monitor.
//!
//! Fetches each monitored doc URL, hashes the content, stores snapshots,
//! compares with previous, and runs semantic diff for API specs.

use crate::alerts::{Alert, AlertManager, AlertType, Severity};
use crate::config::{DocType, MonitoredDoc};
use crate::database::{Database, DocSnapshot};
use crate::openapi_diff;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{error, info};

pub struct DocsMonitor<'a> {
    db: &'a Database,
    alerts: &'a AlertManager,
    client: reqwest::blocking::Client,
}

impl<'a> DocsMonitor<'a> {
    pub fn new(db: &'a Database, alerts: &'a AlertManager, timeout_secs: u64) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(timeout_secs))
            .user_agent("API-Sentinel/0.1")
            .build()
            .expect("failed to build HTTP client");
        Self { db, alerts, client }
    }

    pub fn check_all(&self, docs: &[MonitoredDoc]) {
        for doc in docs {
            if let Err(e) = self.check_one(doc) {
                error!(url = doc.url, error = %e, "failed to check doc");
            }
        }
    }

    fn check_one(&self, doc: &MonitoredDoc) -> anyhow::Result<()> {
        info!(url = doc.url, name = doc.name, "fetching doc");

        let resp = self.client.get(doc.url).send()?;

        let etag = resp
            .headers()
            .get("etag")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let last_modified = resp
            .headers()
            .get("last-modified")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = resp.text()?;
        let hash = format!("{:x}", Sha256::digest(body.as_bytes()));

        let semantic = match doc.doc_type {
            DocType::OpenApi | DocType::AsyncApi => openapi_diff::semantic_hash(&body),
            DocType::Changelog => None,
        };

        let now = Utc::now().to_rfc3339();
        let snap = DocSnapshot {
            id: None,
            url: doc.url.to_string(),
            fetched_at: now,
            etag,
            last_modified,
            sha256: hash.clone(),
            semantic_hash: semantic.clone(),
            content: body.clone(),
        };

        let previous = self.db.latest_doc_snapshot(doc.url)?;

        let snap_id = self.db.insert_doc_snapshot(&snap)?;

        let Some(prev) = previous else {
            info!(url = doc.url, "first snapshot recorded");
            return Ok(());
        };

        // Check raw change
        if prev.sha256 == hash {
            info!(url = doc.url, "no change detected");
            return Ok(());
        }

        // Raw change detected
        info!(url = doc.url, "raw change detected");

        self.alerts.emit(&Alert {
            alert_type: AlertType::DocRawChange,
            severity: Severity::Medium,
            title: format!("{} content changed", doc.name),
            details: format!(
                "SHA256 changed:\n  old: {}\n  new: {}\nURL: {}",
                prev.sha256, hash, doc.url
            ),
            source: doc.url.to_string(),
        });

        self.db.insert_doc_diff(
            doc.url,
            prev.id.unwrap_or(0),
            snap_id,
            "DOC_RAW_CHANGE",
            &format!("SHA256 {} -> {}", prev.sha256, hash),
            Severity::Medium.as_str(),
        )?;

        // Semantic diff for API specs
        if doc.doc_type == DocType::OpenApi || doc.doc_type == DocType::AsyncApi {
            let changes = openapi_diff::diff_specs(&prev.content, &body);
            if !changes.is_empty() {
                let summary_lines: Vec<String> = changes
                    .iter()
                    .map(|c| format!("  [{}] {}: {}", c.category, c.path, c.description))
                    .collect();
                let summary = summary_lines.join("\n");

                let severity = if changes.iter().any(|c| {
                    matches!(
                        c.category,
                        openapi_diff::ChangeCategory::EndpointRemoved
                            | openapi_diff::ChangeCategory::AuthChanged
                    )
                }) {
                    Severity::High
                } else if changes.iter().any(|c| {
                    matches!(
                        c.category,
                        openapi_diff::ChangeCategory::EndpointAdded
                            | openapi_diff::ChangeCategory::ParameterChanged
                            | openapi_diff::ChangeCategory::RequestSchemaChanged
                            | openapi_diff::ChangeCategory::ResponseSchemaChanged
                    )
                }) {
                    Severity::Medium
                } else {
                    Severity::Low
                };

                self.alerts.emit(&Alert {
                    alert_type: AlertType::DocSemanticChange,
                    severity,
                    title: format!("{} API semantic changes detected", doc.name),
                    details: format!("{} change(s):\n{}", changes.len(), summary),
                    source: doc.url.to_string(),
                });

                self.db.insert_doc_diff(
                    doc.url,
                    prev.id.unwrap_or(0),
                    snap_id,
                    "DOC_SEMANTIC_CHANGE",
                    &summary,
                    severity.as_str(),
                )?;
            }
        }

        Ok(())
    }
}

