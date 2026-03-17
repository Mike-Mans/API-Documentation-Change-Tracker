//! Remote bot-stop logic.
//!
//! Invoked automatically when apisentinel detects API documentation changes
//! or DNS infrastructure relocation. Runs:
//!   ssh kalshi 'systemctl stop kalshi-data kalshi-control'

use std::process::Command;
use tracing::{error, info, warn};

/// Stop the Kalshi trading bot on the remote VPS via SSH.
/// The SSH host `kalshi` must be configured in ~/.ssh/config.
pub fn stop_kalshi_bot(reason: &str) {
    warn!(reason, "stopping Kalshi trading bot on VPS");

    let result = Command::new("ssh")
        .args(["kalshi", "systemctl stop kalshi-data kalshi-control"])
        .output();

    match result {
        Ok(out) if out.status.success() => {
            info!("bot stopped successfully via SSH");
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
}
