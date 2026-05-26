// TEE Attestation Service Agent — systemd ask-password watcher
//
// Copyright 2025-2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Implements the systemd ask-password protocol to automatically supply
// LUKS decryption keys fetched from the TEE Attestation Service.
//
// Protocol reference: systemd ask-password-api(7)
//   - Scans /run/systemd/ask-password/ask.* files
//   - Parses [Ask] section for Socket=, Id=, PID=, NotAfter=
//   - Sends reply: '+' byte + passphrase via UnixDatagram to Socket path
//
// Runs in a loop (like clevis-luks-askpass -l) until all pending
// cryptsetup requests are answered, with SIGTERM handling for
// clean shutdown.
//
// Systemd dependencies (askpass mode):
//   Runtime:
//     - systemd >= 248 (ask-password protocol, .path units)
//     - systemd-cryptsetup-generator (creates ask files for LUKS volumes)
//     - /run/systemd/ask-password/ directory (tmpfiles.d or systemd itself)
//   Boot ordering:
//     - tas-agent-askpass.path: WantedBy=cryptsetup.target
//     - tas-agent-askpass.service: After=network-online.target
//     - crypttab must include `_netdev` so cryptsetup waits for network
//   Kernel cmdline (dracut/Fedora):
//     - rd.neednet=1 ip=dhcp (or ip=<static>)
//   No unsafe code. Uses safe Rust plus rustix for exact CLOCK_MONOTONIC handling.

use anyhow::{Context, Result};
use log::{debug, info, warn};
use rustix::time::{clock_gettime, ClockId};
use std::collections::HashSet;
use std::fs;
use std::os::unix::net::UnixDatagram;
use std::path::{Path, PathBuf};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, Duration, Instant};

const ASK_PASSWORD_DIR: &str = "/run/systemd/ask-password";

/// How long to wait (with no pending ask files) after answering at least
/// one request before exiting. Gives time for additional volumes to appear.
const IDLE_EXIT_SECS: u64 = 10;

/// Parsed fields from a systemd ask-password `.ask` file.
#[derive(Debug)]
#[allow(dead_code)]
pub struct AskRequest {
    /// Path to the reply socket (from Socket= field)
    pub socket_path: PathBuf,
    /// Id field (e.g. "cryptsetup:/dev/disk/by-uuid/...")
    pub id: String,
    /// Device path extracted from Id (part after "cryptsetup:")
    pub device: String,
    /// PID of the asking process
    pub pid: Option<u32>,
    /// NotAfter timestamp (CLOCK_MONOTONIC usec)
    pub not_after: Option<u64>,
}

fn current_monotonic_usec() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    let secs = u64::try_from(now.tv_sec).unwrap_or_default();
    let nanos = u64::try_from(now.tv_nsec).unwrap_or_default();

    secs.saturating_mul(1_000_000).saturating_add(nanos / 1_000)
}

fn is_request_expired(not_after: u64, now_mono_usec: u64) -> bool {
    not_after > 0 && now_mono_usec > not_after
}

/// Scan the ask-password directory for pending cryptsetup requests.
///
/// Reads all `ask.*` files in `dir`, parses them as INI-like \[Ask\] sections,
/// and returns entries whose `Id` starts with `cryptsetup:`.
pub fn scan_ask_dir(dir: &Path) -> Vec<AskRequest> {
    let mut requests = Vec::new();

    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(err) => {
            debug!("Cannot read ask-password dir {:?}: {}", dir, err);
            return requests;
        }
    };

    for entry in entries.flatten() {
        let path = entry.path();
        let name = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        if !name.starts_with("ask.") {
            continue;
        }

        match parse_ask_file(&path) {
            Ok(Some(req)) => {
                debug!(
                    "Found cryptsetup ask request: id={}, socket={:?}",
                    req.id, req.socket_path
                );
                requests.push(req);
            }
            Ok(None) => {
                debug!("Skipping non-cryptsetup ask file: {:?}", path);
            }
            Err(err) => {
                warn!("Failed to parse ask file {:?}: {}", path, err);
            }
        }
    }

    requests
}

/// Parse a single `.ask` file. Returns `Some(AskRequest)` if it is a
/// cryptsetup request, `None` if it should be skipped.
fn parse_ask_file(path: &Path) -> Result<Option<AskRequest>> {
    let content = fs::read_to_string(path).with_context(|| format!("reading {:?}", path))?;

    let mut socket_path: Option<PathBuf> = None;
    let mut id: Option<String> = None;
    let mut pid: Option<u32> = None;
    let mut not_after: Option<u64> = None;

    for line in content.lines() {
        let line = line.trim();
        if line.starts_with('[') || line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            match key.trim() {
                "Socket" => socket_path = Some(PathBuf::from(value.trim())),
                "Id" => id = Some(value.trim().to_string()),
                "PID" => pid = value.trim().parse().ok(),
                "NotAfter" => not_after = value.trim().parse().ok(),
                _ => {}
            }
        }
    }

    let id = match id {
        Some(id) => id,
        None => return Ok(None),
    };

    // Only handle cryptsetup requests
    if !id.starts_with("cryptsetup:") {
        return Ok(None);
    }

    let socket_path = match socket_path {
        Some(p) => p,
        None => {
            warn!("Ask file {:?} has no Socket= field", path);
            return Ok(None);
        }
    };

    // Validate that the socket file actually exists and is a socket
    if !socket_path.exists() {
        warn!("Socket {:?} does not exist, skipping", socket_path);
        return Ok(None);
    }

    // Skip expired requests: NotAfter is an absolute CLOCK_MONOTONIC
    // timestamp in microseconds. A value of 0 means "no timeout".
    if let Some(na) = not_after {
        let now_mono_usec = current_monotonic_usec();
        if is_request_expired(na, now_mono_usec) {
            debug!(
                "Ask file {:?} expired (NotAfter={}, now_mono={}), skipping",
                path, na, now_mono_usec
            );
            return Ok(None);
        }
    }

    // Extract device path from Id (e.g. "cryptsetup:/dev/sda1" -> "/dev/sda1")
    let device = id.strip_prefix("cryptsetup:").unwrap_or("").to_string();

    Ok(Some(AskRequest {
        socket_path,
        id,
        device,
        pid,
        not_after,
    }))
}

/// Send a passphrase reply to the systemd ask-password socket.
///
/// Protocol: connect a UnixDatagram to the `Socket=` path, then send
/// a `+` byte followed by the passphrase bytes. The `+` signals success
/// (a `-` byte would signal failure/cancellation).
pub fn send_reply(socket_path: &Path, key: &[u8]) -> Result<()> {
    let sock = UnixDatagram::unbound().context("creating UnixDatagram")?;

    // Build the reply: '+' prefix + passphrase
    let mut reply = Vec::with_capacity(1 + key.len());
    reply.push(b'+');
    reply.extend_from_slice(key);

    sock.send_to(&reply, socket_path)
        .with_context(|| format!("sending reply to {:?}", socket_path))?;

    info!("Sent passphrase reply to {:?}", socket_path);
    Ok(())
}

/// Main entry point for askpass mode.
///
/// Runs in a loop (like clevis-luks-askpass -l):
///   1. Scan for pending cryptsetup ask-password requests
///   2. Skip requests already answered (tracked in a HashSet by Id)
///   3. Fetch key from TAS once and reply to all pending requests
///   4. Sleep 0.5s and repeat
///
/// Exits cleanly on:
///   - SIGTERM signal
///   - Idle timeout: after answering at least one request, if no ask
///     files remain for IDLE_EXIT_SECS (10s), exits gracefully. This
///     allows the systemd service to stop after all volumes are unlocked.
///
/// The answered-set prevents redundant TAS fetches during the brief
/// window between sending a reply and cryptsetup deleting the ask file.
pub async fn run_askpass(config_path: Option<PathBuf>) -> Result<()> {
    let ask_dir = Path::new(ASK_PASSWORD_DIR);

    // Set up SIGTERM handler for clean shutdown
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;

    info!(
        "TAS Agent: askpass watcher started, monitoring {:?}",
        ask_dir
    );

    let mut answered: HashSet<String> = HashSet::new();
    let idle_timeout = Duration::from_secs(IDLE_EXIT_SECS);
    let mut idle_since: Option<Instant> = None;

    loop {
        // Check for SIGTERM before each scan
        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, exiting cleanly");
                return Ok(());
            }
            _ = async {
                let all_requests = scan_ask_dir(ask_dir);
                let requests: Vec<_> = all_requests
                    .into_iter()
                    .filter(|r| !answered.contains(&r.id))
                    .collect();

                if requests.is_empty() {
                    debug!("No pending cryptsetup ask-password requests");
                } else {
                    // New work arrived — reset idle timer
                    idle_since = None;
                    info!("Found {} cryptsetup ask-password request(s)", requests.len());

                    // Fetch key once for all requests (same TAS key for all volumes)
                    match crate::fetch_key(config_path.clone(), None).await {
                        Ok(mut key) => {
                            for req in &requests {
                                info!("Replying to ask request: id={}", req.id);
                                if let Err(e) = send_reply(&req.socket_path, &key) {
                                    warn!("Failed to send reply for {}: {}", req.id, e);
                                } else {
                                    info!("TAS Agent: unlocked {}", req.device);
                                    answered.insert(req.id.clone());
                                }
                            }
                            // Zeroize key material after all replies sent
                            zeroize::Zeroize::zeroize(&mut key);
                        }
                        Err(e) => {
                            warn!("TAS Agent: fetch failed: {:#}", e);
                        }
                    }
                }

                // Idle-exit: once we've answered at least one request and no
                // ask files remain for IDLE_EXIT_SECS, exit cleanly.
                if !answered.is_empty() && scan_ask_dir(ask_dir).is_empty() {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= idle_timeout {
                        info!(
                            "All volumes unlocked, no new requests for {}s — exiting",
                            IDLE_EXIT_SECS
                        );
                        return;
                    }
                } else if !requests.is_empty() {
                    idle_since = None;
                }

                // Wait before next scan (same interval as clevis)
                sleep(Duration::from_millis(500)).await;
            } => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_parse_ask_file_cryptsetup() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.xxxx");
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "PID=1234").unwrap();
        // Use a socket path that we create so validation passes
        let sock_path = dir.path().join("sck.xxxx");
        // Create a real Unix socket for validation
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        writeln!(f, "NotAfter=0").unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        let req = result.expect("should parse as cryptsetup request");
        assert_eq!(req.id, "cryptsetup:/dev/sda1");
        assert_eq!(req.device, "/dev/sda1");
        assert_eq!(req.socket_path, sock_path);
        assert_eq!(req.pid, Some(1234));
        assert_eq!(req.not_after, Some(0));
    }

    #[test]
    fn test_parse_ask_file_non_cryptsetup() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.yyyy");
        let sock_path = dir.path().join("sck.yyyy");
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=plymouth:/dev/tty1").unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(result.is_none(), "non-cryptsetup request should be skipped");
    }

    #[test]
    fn test_scan_ask_dir_filters_cryptsetup() {
        let dir = tempfile::tempdir().unwrap();

        // Create sockets for validation
        let sock_a = dir.path().join("sck.aaa");
        let _sock_a = UnixDatagram::bind(&sock_a).unwrap();
        let sock_b = dir.path().join("sck.bbb");
        let _sock_b = UnixDatagram::bind(&sock_b).unwrap();

        // cryptsetup request
        let mut f = fs::File::create(dir.path().join("ask.aaa")).unwrap();
        writeln!(
            f,
            "[Ask]\nSocket={}\nId=cryptsetup:/dev/sda1",
            sock_a.display()
        )
        .unwrap();
        drop(f);

        // non-cryptsetup request
        let mut f = fs::File::create(dir.path().join("ask.bbb")).unwrap();
        writeln!(
            f,
            "[Ask]\nSocket={}\nId=plymouth:/dev/tty1",
            sock_b.display()
        )
        .unwrap();
        drop(f);

        // not an ask file
        let mut f = fs::File::create(dir.path().join("something.else")).unwrap();
        writeln!(f, "random content").unwrap();
        drop(f);

        let requests = scan_ask_dir(dir.path());
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].id, "cryptsetup:/dev/sda1");
        assert_eq!(requests[0].device, "/dev/sda1");
    }

    #[test]
    fn test_parse_ask_file_missing_socket_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.zzzz");
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket=/nonexistent/sck.zzzz").unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(
            result.is_none(),
            "request with nonexistent socket should be skipped"
        );
    }

    #[test]
    fn test_parse_ask_file_expired_not_after() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.expired");
        let sock_path = dir.path().join("sck.expired");
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        // Set NotAfter to 1 microsecond after boot (long expired on any running system)
        writeln!(f, "NotAfter=1").unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(result.is_none(), "expired request should be skipped");
    }

    #[test]
    fn test_parse_ask_file_future_monotonic_not_after_is_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.future");
        let sock_path = dir.path().join("sck.future");
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        writeln!(f, "NotAfter={}", current_monotonic_usec() + 5_000_000).unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(
            result.is_some(),
            "future CLOCK_MONOTONIC deadline should be accepted"
        );
    }

    #[test]
    fn test_parse_ask_file_past_monotonic_not_after_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.past");
        let sock_path = dir.path().join("sck.past");
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        writeln!(
            f,
            "NotAfter={}",
            current_monotonic_usec().checked_sub(1_000_000).unwrap_or(1)
        )
        .unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(
            result.is_none(),
            "past CLOCK_MONOTONIC deadline should be rejected"
        );
    }

    #[test]
    fn test_parse_ask_file_not_after_zero_means_no_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let ask_file = dir.path().join("ask.notimeout");
        let sock_path = dir.path().join("sck.notimeout");
        let _sock = UnixDatagram::bind(&sock_path).unwrap();
        let mut f = fs::File::create(&ask_file).unwrap();
        writeln!(f, "[Ask]").unwrap();
        writeln!(f, "Socket={}", sock_path.display()).unwrap();
        writeln!(f, "Id=cryptsetup:/dev/sda1").unwrap();
        // NotAfter=0 means no timeout (wait forever)
        writeln!(f, "NotAfter=0").unwrap();
        drop(f);

        let result = parse_ask_file(&ask_file).unwrap();
        assert!(result.is_some(), "NotAfter=0 should not expire");
    }
    #[test]
    fn test_send_reply_protocol() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");
        let sock = UnixDatagram::bind(&sock_path).unwrap();

        // Send a reply
        let key = b"test-passphrase";
        send_reply(&sock_path, key).unwrap();

        // Read back and verify protocol
        let mut buf = [0u8; 256];
        let n = sock.recv(&mut buf).unwrap();
        assert_eq!(buf[0], b'+');
        assert_eq!(&buf[1..n], key);
    }
}
