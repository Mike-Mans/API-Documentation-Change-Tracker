//! Documentation change monitor.
//!
//! Fetches each monitored doc URL, hashes the content, stores snapshots,
//! compares with previous, and runs semantic diff for API specs.
//!
//! ## Conservative stop policy
//!
//! Raw SHA256 changes are logged but never stop the bot — responses may include
//! dynamic fields (timestamps, cache keys) that make the raw hash unstable.
//!
//! For API specs (OpenAPI / AsyncAPI), we track the *semantic hash* — a hash of
//! the parsed YAML structure only (paths, channels, schemas).  A DocStableChange
//! alert is emitted after STABLE_CYCLES consecutive snapshots all share the same
//! new semantic hash that differs from the one preceding them.  Only HIGH-severity
//! stable changes (endpoint removed, auth changed) stop the bot; lower severity
//! ones alert only.

use crate::alerts::{Alert, AlertManager, AlertType, Severity};
use crate::config::{DocType, MonitoredDoc};
use crate::database::{Database, DocSnapshot};
use crate::openapi_diff;
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tracing::{error, info, warn};

/// Number of consecutive cycles the new semantic hash must be stable before
/// we consider the change confirmed and emit DocStableChange.
const STABLE_CYCLES: usize = 5;

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

        // Always insert — every cycle needs a row so the semantic hash history
        // is complete for the STABLE_CYCLES look-back below.
        let snap_id = self.db.insert_doc_snapshot(&snap)?;

        let Some(prev) = previous else {
            info!(url = doc.url, "first snapshot recorded");
            return Ok(());
        };

        let raw_changed = prev.sha256 != hash;

        // ── Raw change (informational only) ──────────────────────────────────
        if raw_changed {
            info!(url = doc.url, "raw change detected");

            self.alerts.emit(&Alert {
                alert_type: AlertType::DocRawChange,
                severity: Severity::Low,
                title: format!("{} raw content changed", doc.name),
                details: format!(
                    "SHA256 changed:\n  old: {}\n  new: {}\nURL: {}\n\
                     (May be formatting, timestamps, or whitespace — semantic check below.)",
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
                Severity::Low.as_str(),
            )?;
        } else {
            info!(url = doc.url, "no raw change detected");
        }

        // ── Semantic checks — API specs only ─────────────────────────────────
        if doc.doc_type != DocType::OpenApi && doc.doc_type != DocType::AsyncApi {
            return Ok(());
        }

        let Some(ref sem_hash) = semantic else {
            warn!(url = doc.url, "semantic hash computation failed — skipping semantic check");
            return Ok(());
        };

        // Only run the expensive diff when the raw body actually changed.
        if raw_changed {
            let prev_sem = prev.semantic_hash.as_deref();
            if prev_sem != Some(sem_hash.as_str()) {
                // Structure changed — run diff and emit informational alert.
                self.emit_semantic_change(doc, &prev, &body, snap_id, sem_hash)?;
            } else {
                info!(
                    url = doc.url,
                    "raw changed but semantic hash unchanged (formatting / whitespace / timestamps only)"
                );
            }
        }

        // ── Stable-change detection ───────────────────────────────────────────
        // Check whether the semantic hash has been the same new value for
        // STABLE_CYCLES consecutive snapshots (including this one).
        //
        // We query STABLE_CYCLES + 1 rows: the first STABLE_CYCLES must all
        // equal `sem_hash`, and the row just before must differ (confirming
        // this is a new stable value, not the longstanding baseline).
        let recent = self.db.recent_semantic_hashes(doc.url, STABLE_CYCLES + 1)?;

        if recent.len() >= STABLE_CYCLES + 1 {
            let all_stable = recent[..STABLE_CYCLES]
                .iter()
                .all(|h| h.as_deref() == Some(sem_hash.as_str()));

            let before_different = recent[STABLE_CYCLES].as_deref() != Some(sem_hash.as_str());

            if all_stable && before_different {
                self.emit_stable_change(doc, sem_hash)?;
            }
        }

        Ok(())
    }

    /// Emit an informational DocSemanticChange alert + insert a diff record.
    fn emit_semantic_change(
        &self,
        doc: &MonitoredDoc,
        prev: &DocSnapshot,
        new_body: &str,
        snap_id: i64,
        _sem_hash: &str,
    ) -> anyhow::Result<()> {
        let changes = openapi_diff::diff_specs(&prev.content, new_body);
        if changes.is_empty() {
            info!(url = doc.url, "semantic hash changed but diff found no actionable changes");
            return Ok(());
        }

        let summary_lines: Vec<String> = changes
            .iter()
            .map(|c| format!("  [{}] {}: {}", c.category, c.path, c.description))
            .collect();
        let summary = summary_lines.join("\n");

        let severity = classify_severity(&changes);

        self.alerts.emit(&Alert {
            alert_type: AlertType::DocSemanticChange,
            severity,
            title: format!("{} API structural changes detected (informational)", doc.name),
            details: format!(
                "{} change(s):\n{}\n\nNo action taken — waiting for {} stable cycles.",
                changes.len(),
                summary,
                STABLE_CYCLES
            ),
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

        Ok(())
    }

    /// Emit a DocStableChange alert after STABLE_CYCLES confirmed the new semantic hash.
    fn emit_stable_change(&self, doc: &MonitoredDoc, sem_hash: &str) -> anyhow::Result<()> {
        // Use the severity stored from when the change was first detected.
        // AsyncAPI is always High — the WebSocket layer is essential for the bot.
        let severity = if doc.doc_type == DocType::AsyncApi {
            Severity::High
        } else {
            match self.db.latest_semantic_diff_severity(doc.url)? {
                Some(s) if s == "HIGH"   => Severity::High,
                Some(s) if s == "MEDIUM" => Severity::Medium,
                _                        => Severity::Low,
            }
        };

        warn!(
            url = doc.url,
            sem_hash,
            cycles = STABLE_CYCLES,
            severity = %severity,
            "DocStableChange: confirmed stable structural change"
        );

        self.alerts.emit(&Alert {
            alert_type: AlertType::DocStableChange,
            severity,
            title: format!(
                "{} API structure changed — confirmed stable for {} cycles",
                doc.name, STABLE_CYCLES
            ),
            details: format!(
                "The semantic hash has been stable at a new value for {} consecutive \
                 monitoring cycles (~{} min).\n\
                 New semantic hash: {}\nURL: {}\n\n\
                 Action: review API diff, verify bot behaviour, then restart tracker manually.",
                STABLE_CYCLES,
                STABLE_CYCLES * 10,
                sem_hash,
                doc.url
            ),
            source: doc.url.to_string(),
        });

        Ok(())
    }
}

fn classify_severity(changes: &[openapi_diff::SemanticChange]) -> Severity {
    if changes.iter().any(|c| {
        matches!(
            c.category,
            openapi_diff::ChangeCategory::EndpointRemoved | openapi_diff::ChangeCategory::AuthChanged
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
    }
}
