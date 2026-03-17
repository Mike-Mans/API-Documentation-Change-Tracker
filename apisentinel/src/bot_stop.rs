//! Remote bot-stop logic.
//!
//! Triggered only by significant API doc changes or server relocation.
//! Flow: SSH stop trading bot → iMessage alerts → tracker process exits.
//! Since the tracker exits, no further SSH commands can run until it is
//! manually restarted after review.

use chrono::Utc;
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::{error, info, warn};

// Guards against a second call in the same cycle if multiple alerts fire at once.
static STOP_IN_PROGRESS: AtomicBool = AtomicBool::new(false);

const ALERT_RECIPIENTS: &[&str] = &["+18183989876", "+18188235726"];

/// Stop the Kalshi trading bot, notify via iMessage, then exit the tracker.
pub fn stop_kalshi_bot(reason: &str) {
    if STOP_IN_PROGRESS.swap(true, Ordering::SeqCst) {
        return; // another alert in the same cycle already triggered this
    }

    warn!(reason, "significant change detected — stopping Kalshi trading bot");

    // 1. SSH stop
    let result = Command::new("ssh")
        .args(["kalshi", "systemctl stop kalshi-data kalshi-control"])
        .output();

    match result {
        Ok(out) if out.status.success() => {
            info!("trading bot stopped successfully via SSH");
        }
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            error!(
                exit_code = out.status.code().unwrap_or(-1),
                stderr = %stderr,
                "ssh stop command failed"
            );
        }
        Err(e) => {
            error!(error = %e, "failed to spawn ssh process");
        }
    }

    // 2. iMessage alerts
    send_imessage_alerts(reason);

    // 3. Exit — no further SSH commands will run until tracker is manually restarted.
    warn!("tracker exiting — restart manually after reviewing the change");
    std::process::exit(0);
}

// ── iMessage via BlueBubbles ──────────────────────────────────────────────────

fn send_imessage_alerts(reason: &str) {
    let (Some(bb_url), Some(bb_password)) = (
        std::env::var("SENTINEL_BB_URL").ok(),
        std::env::var("SENTINEL_BB_PASSWORD").ok(),
    ) else {
        warn!("SENTINEL_BB_URL or SENTINEL_BB_PASSWORD not set — skipping iMessage alerts");
        return;
    };

    let message = format!(
        "## [Action Needed]\n\
        The Kalshi trading bot is stopped due to {reason}, You will need to update.\n\n\
        You will also need to manually start the tracker bot after reviewing."
    );

    let client = match reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(15))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "failed to build HTTP client for iMessage");
            return;
        }
    };

    for phone in ALERT_RECIPIENTS {
        let url = format!("{bb_url}/api/v1/message/text?password={bb_password}");
        let temp_guid = format!(
            "sentinel-{}-{}",
            Utc::now().timestamp_millis(),
            phone.trim_start_matches('+')
        );
        let body = serde_json::json!({
            "chatGuid": format!("iMessage;-;{phone}"),
            "message": message,
            "method": "private-api",
            "tempGuid": temp_guid
        });

        match client.post(&url).json(&body).send() {
            Ok(resp) if resp.status().is_success() => {
                info!(recipient = phone, "iMessage alert sent via BlueBubbles");
            }
            Ok(resp) => {
                error!(
                    recipient = phone,
                    status = %resp.status(),
                    "BlueBubbles iMessage failed"
                );
            }
            Err(e) => {
                error!(recipient = phone, error = %e, "BlueBubbles request failed");
            }
        }
    }
}
