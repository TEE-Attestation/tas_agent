// TEE Attestation Service Agent — initramfs-tools passfifo watcher
//
// Copyright 2026 Hewlett Packard Enterprise Development LP.
// SPDX-License-Identifier: MIT
//
// Implements the initramfs-tools passfifo protocol to automatically supply
// LUKS decryption keys fetched from the TEE Attestation Service.
//
//
// Protocol reference: initramfs-tools cryptsetup integration
//   - cryptsetup spawns /lib/cryptsetup/askpass which opens a named pipe
//     (passfifo) at /lib/cryptsetup/passfifo (or under /run/cryptsetup/)
//   - Any process can write the passphrase bytes into the FIFO
//   - The askpass process reads the passphrase and passes it to cryptsetup
//
// Runs in a loop scanning /proc for the askpass process, extracts the
// CRYPTTAB_SOURCE from its environment, fetches the key from TAS, and
// writes it to the passfifo. Exits cleanly on SIGTERM or after an idle
// timeout once at least one volume has been unlocked.
//
// This replaces the shell-based polling loop in the initramfs local-top
// script with a single Rust binary, avoiding passphrase exposure in shell
// variables and eliminating fragile `ps` output parsing.
//
// No unsafe code. No libc dependency. Pure safe Rust + std.

use anyhow::{Context, Result};
use log::{debug, info, trace, warn};
use std::collections::HashSet;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use tokio::signal::unix::{signal, SignalKind};
use tokio::time::{sleep, Duration, Instant};

/// How long to wait (with no pending askpass processes) after answering at
/// least one request before exiting. Gives time for additional volumes.
const IDLE_EXIT_SECS: u64 = 30;

/// Information about a running cryptsetup askpass process.
#[derive(Debug)]
#[allow(dead_code)]
pub struct PassfifoRequest {
    /// PID of the askpass process
    pub pid: u32,
    /// Path to the passfifo (named pipe)
    pub fifo_path: PathBuf,
    /// CRYPTTAB_SOURCE block device (e.g. /dev/sda2)
    pub device: String,
}

/// Well-known path where the cryptsetup askpass binary creates its FIFO.
const PASSFIFO_PATH: &str = "/lib/cryptsetup/passfifo";

/// Check if the passfifo FIFO exists and a cryptsetup process is waiting
/// for a passphrase. Returns a PassfifoRequest if both conditions are met.
///
/// Instead of scanning for the short-lived askpass process (which runs in
/// a pipe subshell and exits too quickly to catch), we watch for the FIFO
/// file that askpass creates at /lib/cryptsetup/passfifo. When the FIFO
/// exists, we find the CRYPTTAB_SOURCE from the running cryptsetup process
/// (which has the device path in its cmdline).
pub fn scan_passfifo_requests() -> Vec<PassfifoRequest> {
    let mut requests = Vec::new();

    let fifo = Path::new(PASSFIFO_PATH);
    if !fifo.exists() {
        return requests;
    }
    trace!("passfifo exists at {}", PASSFIFO_PATH);

    // Find the device from a running cryptsetup process cmdline.
    // cryptsetup cmdline looks like:
    //   /sbin/cryptsetup -T1 --allow-discards --type=luks --key-file=- open -- /dev/sda2 tasroot
    // We parse out the device path (the arg before the dm name at the end).
    let proc_entries = match fs::read_dir("/proc") {
        Ok(e) => e,
        Err(err) => {
            debug!("Cannot read /proc: {}", err);
            return requests;
        }
    };

    for entry in proc_entries.flatten() {
        let name = match entry.file_name().into_string() {
            Ok(n) => n,
            Err(_) => continue,
        };
        let pid: u32 = match name.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let cmdline_raw = match fs::read(&cmdline_path) {
            Ok(data) => data,
            Err(_) => continue,
        };

        let args: Vec<&str> = cmdline_raw
            .split(|&b| b == 0)
            .filter_map(|a| std::str::from_utf8(a).ok())
            .filter(|a| !a.is_empty())
            .collect();

        if args.is_empty() {
            continue;
        }

        // Match cryptsetup open/luksOpen commands
        let is_cryptsetup = args[0].ends_with("cryptsetup")
            && args.iter().any(|a| *a == "open" || *a == "luksOpen");

        if !is_cryptsetup {
            continue;
        }

        // Extract device path: find "open" or "luksOpen", then the device
        // is the next non-flag argument (doesn't start with -)
        // Also try CRYPTTAB_SOURCE from the process environment first
        let device =
            read_crypttab_source(pid).or_else(|| extract_device_from_cryptsetup_args(&args));

        let device = match device {
            Some(d) => d,
            None => {
                debug!("PID {} is cryptsetup but cannot determine device", pid);
                continue;
            }
        };

        debug!(
            "Found passfifo request: fifo={}, device={}, cryptsetup_pid={}",
            PASSFIFO_PATH, device, pid
        );
        requests.push(PassfifoRequest {
            pid,
            fifo_path: PathBuf::from(PASSFIFO_PATH),
            device,
        });
    }

    requests
}

/// Extract the source device path from cryptsetup command-line arguments.
///
/// Handles cmdlines like:
///   cryptsetup open --type luks --key-file=- -- /dev/sda2 tasroot
///   cryptsetup luksOpen /dev/sda2 tasroot
fn extract_device_from_cryptsetup_args(args: &[&str]) -> Option<String> {
    // Find the position of "open" or "luksOpen"
    let open_pos = args.iter().position(|a| *a == "open" || *a == "luksOpen")?;

    // Skip past "--" if present, then find the first arg starting with /dev/
    for arg in &args[open_pos + 1..] {
        if *arg == "--" {
            continue;
        }
        if arg.starts_with('-') {
            continue;
        }
        if arg.starts_with("/dev/") || arg.starts_with("UUID=") {
            return Some(arg.to_string());
        }
    }

    None
}

/// Read the CRYPTTAB_SOURCE environment variable from /proc/PID/environ.
fn read_crypttab_source(pid: u32) -> Option<String> {
    let environ_path = format!("/proc/{}/environ", pid);
    let data = fs::read(&environ_path).ok()?;

    // Environment variables are null-separated
    for var in data.split(|&b| b == 0) {
        let var_str = String::from_utf8_lossy(var);
        if let Some(value) = var_str.strip_prefix("CRYPTTAB_SOURCE=") {
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }

    None
}

/// Write a passphrase to a named pipe (FIFO).
///
/// Opens the FIFO for writing, writes the passphrase bytes, and flushes.
/// The passphrase is not newline-terminated (matching cryptsetup's
/// expectation for binary key material).
pub fn send_passphrase(fifo_path: &Path, key: &[u8]) -> Result<()> {
    let mut fifo = fs::OpenOptions::new()
        .write(true)
        .open(fifo_path)
        .with_context(|| format!("opening passfifo {:?}", fifo_path))?;

    fifo.write_all(key)
        .with_context(|| format!("writing to passfifo {:?}", fifo_path))?;

    fifo.flush()
        .with_context(|| format!("flushing passfifo {:?}", fifo_path))?;

    info!("Sent passphrase to passfifo {:?}", fifo_path);
    Ok(())
}

/// Write a message directly to /dev/kmsg (kernel log buffer) and a log file.
/// This bypasses the log crate and any pipe wrapper, ensuring messages
/// appear in the serial console regardless of log level or pipe buffering.
/// Follows the clevis pattern of writing directly to console devices.
fn write_console(msg: &str) {
    // Always append to the log file
    if let Ok(mut f) = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/tas_agent.log")
    {
        let _ = writeln!(f, "{}", msg);
    }
    // Write to kernel log buffer (appears on serial console)
    for path in &["/dev/kmsg", "/dev/console"] {
        if let Ok(mut f) = fs::OpenOptions::new().write(true).open(path) {
            let _ = writeln!(f, "tas_agent: {}", msg);
            return;
        }
    }
}

/// Main entry point for passfifo mode.
///
/// Runs in a loop (similar to the askpass mode and clevis-luks-askpass -l):
///   1. Scan /proc for cryptsetup askpass processes
///   2. Skip devices already answered (tracked in a HashSet)
///   3. Fetch key from TAS once and write to each passfifo
///   4. Sleep 500ms and repeat
///
/// Exits cleanly on:
///   - SIGTERM signal
///   - Idle timeout: after answering at least one request, if no askpass
///     processes remain for IDLE_EXIT_SECS, exits gracefully.
pub async fn run_passfifo(config_path: Option<PathBuf>) -> Result<()> {
    // Set up SIGTERM handler for clean shutdown
    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to register SIGTERM handler")?;

    let start_msg = "TAS Agent: passfifo watcher started, scanning /proc for askpass processes";
    info!("{}", start_msg);
    write_console(start_msg);

    // Load kernel modules for TEE attestation
    load_tee_modules();

    let mut answered: HashSet<String> = HashSet::new();
    let idle_timeout = Duration::from_secs(IDLE_EXIT_SECS);
    let mut idle_since: Option<Instant> = None;

    loop {
        // Check for SIGTERM before each scan
        tokio::select! {
            _ = sigterm.recv() => {
                write_console("Received SIGTERM, exiting cleanly");
                return Ok(());
            }
            _ = async {
                let all_requests = scan_passfifo_requests();
                let requests: Vec<_> = all_requests
                    .into_iter()
                    .filter(|r| !answered.contains(&r.device))
                    .collect();
                if requests.is_empty() {
                    trace!("No passfifo found, waiting");
                } else {
                    // New work arrived — reset idle timer
                    idle_since = None;
                    let found_msg = format!("Found {} passfifo request(s)", requests.len());
                    info!("{}", found_msg);
                    write_console(&found_msg);

                    // Fetch key once for all requests (same TAS key for all volumes)
                    match crate::fetch_key(config_path.clone(), None).await {
                        Ok(key) => {
                            for req in &requests {
                                write_console(&format!("Writing passphrase for device {}", req.device));
                                if let Err(e) = send_passphrase(&req.fifo_path, &key) {
                                    let fail_msg = format!("Failed to write passfifo for {}: {}", req.device, e);
                                    warn!("{}", fail_msg);
                                    write_console(&fail_msg);
                                } else {
                                    let msg = format!("TAS Agent: unlocked {}", req.device);
                                    info!("{}", msg);
                                    write_console(&msg);
                                    answered.insert(req.device.clone());
                                }
                            }
                        }
                        Err(e) => {
                            let fail_msg = format!("TAS Agent: fetch failed: {:#}", e);
                            warn!("{}", fail_msg);
                            write_console(&fail_msg);
                        }
                    }
                }

                // Idle-exit: once we've answered at least one request and no
                // askpass processes remain for IDLE_EXIT_SECS, exit cleanly.
                if !answered.is_empty() && scan_passfifo_requests().is_empty() {
                    let since = *idle_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= idle_timeout {
                        write_console(&format!(
                            "All volumes unlocked, no new requests for {}s - exiting",
                            IDLE_EXIT_SECS
                        ));
                        return;
                    }
                } else if !requests.is_empty() {
                    idle_since = None;
                }

                // Wait before next scan (same 500ms interval as askpass mode)
                sleep(Duration::from_millis(500)).await;
            } => {}
        }
    }
}

/// Attempt to load kernel modules needed for TEE attestation.
/// Failures are non-fatal — modules may already be loaded or built-in.
fn load_tee_modules() {
    for module in &["configfs", "tsm", "sev-guest", "tdx-guest"] {
        let status = std::process::Command::new("modprobe").arg(module).status();
        match status {
            Ok(s) if s.success() => debug!("Loaded kernel module: {}", module),
            Ok(s) => debug!("modprobe {} exited with {}", module, s),
            Err(e) => debug!("modprobe {} failed: {}", module, e),
        }
    }

    // Mount configfs if not already mounted
    let status = std::process::Command::new("mount")
        .args(["-t", "configfs", "none", "/sys/kernel/config"])
        .status();
    match status {
        Ok(s) if s.success() => debug!("Mounted configfs"),
        _ => debug!("configfs mount skipped (may already be mounted)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_send_passphrase_to_fifo() {
        // Create a named pipe in a temp directory
        let dir = tempfile::tempdir().unwrap();
        let fifo_path = dir.path().join("test.fifo");

        // Create the FIFO using mkfifo
        let status = std::process::Command::new("mkfifo")
            .arg(&fifo_path)
            .status()
            .unwrap();
        assert!(status.success(), "mkfifo failed");

        let key = b"test-passphrase-1234";
        let fifo_clone = fifo_path.clone();

        // Read from the FIFO in a background thread (FIFO blocks until
        // both reader and writer are connected)
        let reader = std::thread::spawn(move || fs::read(&fifo_clone).unwrap());

        // Write the passphrase
        send_passphrase(&fifo_path, key).unwrap();

        // Verify the reader got the correct data
        let received = reader.join().unwrap();
        assert_eq!(received, key);
    }

    #[test]
    fn test_send_passphrase_nonexistent_fifo() {
        let result = send_passphrase(Path::new("/nonexistent/fifo"), b"key");
        assert!(result.is_err());
    }

    #[test]
    fn test_read_crypttab_source_no_match() {
        // PID 1 should not have CRYPTTAB_SOURCE
        assert!(read_crypttab_source(1).is_none());
    }

    #[test]
    fn test_scan_passfifo_requests_returns_vec() {
        // Should return empty on a normal system (no passfifo file)
        let requests = scan_passfifo_requests();
        assert!(requests.is_empty());
    }

    #[test]
    fn test_extract_device_from_cryptsetup_args() {
        let args = vec![
            "/sbin/cryptsetup",
            "-T1",
            "--allow-discards",
            "--type=luks",
            "--key-file=-",
            "open",
            "--",
            "/dev/sda2",
            "tasroot",
        ];
        assert_eq!(
            extract_device_from_cryptsetup_args(&args),
            Some("/dev/sda2".to_string())
        );

        let args2 = vec!["cryptsetup", "luksOpen", "/dev/nvme0n1p3", "myroot"];
        assert_eq!(
            extract_device_from_cryptsetup_args(&args2),
            Some("/dev/nvme0n1p3".to_string())
        );

        let args3 = vec!["cryptsetup", "status", "tasroot"];
        assert_eq!(extract_device_from_cryptsetup_args(&args3), None);
    }
}
