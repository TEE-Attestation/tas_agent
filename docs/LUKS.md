# LUKS Volume Unlocking

TAS Agent can automatically unlock LUKS-encrypted volumes using TEE
attestation. Once a LUKS volume is bound using `tas-luks-bind`, it can be
unlocked automatically at boot — no password required.

Supported unlock methods:

- **dracut** — Unlocks automatically during early boot (Fedora/RHEL/Ubuntu with dracut)
- **initramfs-tools** — Unlocks automatically during early boot (Ubuntu/Debian)
- **systemd** — Unlocks automatically during late boot (non-root volumes)
- **manual** — Unlocks manually using the command line

## Quick Start

```bash
# 1. Install the packages (see per-distro sections below)
# 2. Configure the TAS server
sudo vi /etc/tas_agent/config.toml    # Set server_uri and key_id
sudo chmod 0600 /etc/tas_agent/api-key && sudo vi /etc/tas_agent/api-key

# 3. Bind a LUKS device (adds a TAS-managed key slot)
sudo tas-luks-bind -d /dev/sda2

# Or supply your own passphrase:
sudo tas-luks-bind -d /dev/sda2 -p 'my-secret-passphrase'

# 4. Follow the printed instructions (crypttab, kernel cmdline, rebuild initrd)
# 5. Reboot — TAS agent unlocks LUKS automatically
```

## Early Boot Unlocking — Dracut (Fedora/RHEL)

### Install

```bash
dnf install tas-agent-*.rpm tas-agent-dracut-*.rpm
```

### Configure

```bash
vi /etc/tas_agent/config.toml      # Set server_uri, key_id
chmod 0600 /etc/tas_agent/api-key
vi /etc/tas_agent/api-key           # Paste your TAS API key
```

### Bind

```bash
sudo tas-luks-bind -d /dev/sda2

# Or supply your own passphrase:
sudo tas-luks-bind -d /dev/sda2 -p 'my-secret-passphrase'
```

### Network

Dracut will not bring up your network by default. The TAS Agent dracut
module automatically injects `rd.neednet=1` (like Clevis), but you must
separately configure how the network is brought up.

**DHCP** (most common):

```bash
grubby --update-kernel=ALL --args="ip=dhcp"
```

**Static IP**:

```bash
grubby --update-kernel=ALL --args="ip=192.168.1.10::192.168.1.1:255.255.255.0::eth0:none"
```

For VLAN, bond, or other advanced configurations, see `dracut.cmdline(7)`.

### Crypttab

Add `_netdev` and `keyfile-timeout` to your LUKS entry in `/etc/crypttab`:

```
tasroot  UUID=<uuid>  none  luks,discard,_netdev,keyfile-timeout=30s
```

- `_netdev` — signals that the device requires network, preventing early
  timeout before the network-based unlock completes
- `keyfile-timeout=30s` — if TAS is unreachable, a manual TTY password
  prompt appears after 30 seconds instead of hanging indefinitely

### Rebuild and Reboot

```bash
dracut --force    # RPM %post rebuilds automatically, but verify
reboot
```

## Early Boot Unlocking — Dracut (Ubuntu)

On Ubuntu systems using dracut, the TAS Agent dracut module falls back to
its own `tas-agent-network.service` with `dhcpcd` for early-boot DHCP,
since dracut's native network module backends are unavailable.

### Install

```bash
dpkg -i tas-agent_*.deb tas-agent-dracut_*.deb
apt-get install -f    # resolve dependencies
```

### Configure, Bind, Crypttab

Same as the Fedora section above.

### Network

```bash
vi /etc/default/grub
# Add to GRUB_CMDLINE_LINUX: ip=dhcp
update-grub
```

### Rebuild and Reboot

```bash
dracut --force
reboot
```

## Early Boot Unlocking — initramfs-tools (Ubuntu/Debian)

For Ubuntu/Debian systems using initramfs-tools, the TAS Agent runs in
`--passfifo` mode, which handles the full passfifo protocol natively in
Rust. The passphrase never passes through shell variables.

### Install

```bash
dpkg -i tas-agent_*.deb tas-agent-initramfs_*.deb
apt-get install -f    # resolve dependencies
```

### Configure

```bash
vi /etc/tas_agent/config.toml      # Set server_uri, key_id
chmod 0600 /etc/tas_agent/api-key
vi /etc/tas_agent/api-key
```

### Bind

```bash
sudo tas-luks-bind -d /dev/sda2

# Or supply your own passphrase:
sudo tas-luks-bind -d /dev/sda2 -p 'my-secret-passphrase'
```

### Network

```bash
vi /etc/default/grub
# Add to GRUB_CMDLINE_LINUX: ip=dhcp
update-grub
```

### Crypttab

```
tasroot  UUID=<uuid>  none  luks,discard,_netdev,keyfile-timeout=30s
```

### Rebuild and Reboot

```bash
update-initramfs -u
reboot
```

## Late Boot Unlocking (systemd)

For non-root LUKS volumes that can wait until the system is fully booted:

```bash
systemctl enable tas-agent-askpass.path
```

After a reboot, TAS Agent will attempt to unlock all LUKS devices listed
in `/etc/crypttab` that have TAS bindings when systemd prompts for their
passwords.

## Manual Unlocking

You can unlock a LUKS volume manually:

```bash
sudo tas_agent -c /etc/tas_agent/config.toml | sudo cryptsetup open /dev/sda2 tasroot -
```

Or verify TAS connectivity without unlocking:

```bash
sudo tas_agent --debug -c /etc/tas_agent/config.toml
```

## Binding and Unbinding

### Bind a LUKS device

```bash
# Random passphrase (default)
sudo tas-luks-bind -d /dev/sda2

# Read passphrase from a file
sudo tas-luks-bind -d /dev/sda2 -P /path/to/secret-file

# Read passphrase from stdin
echo -n 'my-secret-passphrase' | sudo tas-luks-bind -d /dev/sda2 -p -
```

This adds a TAS-managed key to LUKS slot 1 and prints remaining setup
steps. The passphrase (generated or user-supplied) must be uploaded to your TAS server
using the `key_id` from your config.


### Manual Setup (without tas-luks-bind)

If you prefer not to use the `tas-luks-bind` helper, you can perform the
same steps manually:

```bash
# 1. Generate a random passphrase
PASSPHRASE=$(head -c 32 /dev/urandom | base64)

# 2. Add it as a LUKS key (you will be prompted for an existing passphrase)
echo -n "$PASSPHRASE" | sudo cryptsetup luksAddKey /dev/sda2 --key-slot 1 -

# 3. Upload the passphrase to your TAS server using its API or web UI,
#    associated with the key_id in /etc/tas_agent/config.toml

# 4. Configure /etc/crypttab
#    tasroot  UUID=<uuid>  none  luks,discard,_netdev,keyfile-timeout=30s

# 5. Add network boot parameters
#    Fedora/RHEL:
grubby --update-kernel=ALL --args="ip=dhcp"
#    Ubuntu/Debian: edit /etc/default/grub, add ip=dhcp to GRUB_CMDLINE_LINUX
#    then run: sudo update-grub

# 6. Enable the systemd ask-password watcher
sudo systemctl enable tas-agent-askpass.path

# 7. Rebuild the initramfs
sudo dracut --force            # Fedora/RHEL
# or: sudo update-initramfs -u  # Ubuntu/Debian

# 8. Verify TAS connectivity
sudo tas_agent --debug -c /etc/tas_agent/config.toml

# 9. Reboot
```

To unbind manually, remove the key slot:

```bash
sudo cryptsetup luksKillSlot /dev/sda2 1
```

### List binding status

```bash
sudo tas-luks-bind -l -d /dev/sda2
```

### Unbind (remove TAS key slot)

```bash
sudo tas-luks-bind -u -d /dev/sda2
```

## Network Configuration Reference

TAS Agent requires network access during early boot to reach the attestation
service. The dracut module automatically injects `rd.neednet=1` into the
initrd command line (same mechanism as Clevis). You must separately configure
the IP method.

| Method | Kernel Parameter |
|---|---|
| DHCP | `ip=dhcp` |
| Static IP | `ip=<client-ip>::<gw>:<netmask>::<iface>:none` |
| DHCP on specific NIC | `ip=eth0:dhcp` |

### Fedora/RHEL

```bash
grubby --update-kernel=ALL --args="ip=dhcp"
```

### Ubuntu/Debian

```bash
# Edit /etc/default/grub, add to GRUB_CMDLINE_LINUX:
GRUB_CMDLINE_LINUX="ip=dhcp"
update-grub
```

### Verifying Network in initrd

After rebuilding the initrd and rebooting, check the journal:

```bash
journalctl -b -u tas-agent-askpass.service
journalctl -b | grep tas
```

For dracut's self-contained network fallback (Ubuntu):

```bash
journalctl -b | grep tas-net-setup
```

## How It Works

The TAS agent follows the same design as
[Clevis](https://github.com/latchset/clevis) — a policy-based framework
for automated LUKS unlocking. Two modes are supported, each matching its
init system's unlock protocol:

| | Askpass (dracut / systemd) | Passfifo (initramfs-tools) |
|---|---|---|
| **Init system** | systemd (with `systemd-cryptsetup`) | busybox `/init` shell scripts |
| **Trigger** | `.path` unit watches `/run/systemd/ask-password/` via inotify | `local-top` script starts agent in background |
| **Discovery** | Scans ask-password directory for `.ask` files | Scans `/proc` for `cryptsetup` askpass processes |
| **Reply transport** | `UnixDatagram` socket (specified in `.ask` file) | Named pipe at `/lib/cryptsetup/passfifo` |
| **Polling interval** | 500 ms (same as Clevis) | 500 ms (same as Clevis) |
| **Idle exit** | 10 s with no pending requests | 30 s with no pending requests |
| **TTY fallback** | `keyfile-timeout=30s` in crypttab | `keyfile-timeout=30s` in crypttab |
| **Key in shell vars?** | No (Rust only) | No (Rust only) |

### Common to Both Modes

1. **LUKS binding** — `tas-luks-bind` writes a TAS-wrapped key into
   **LUKS slot 1** (label `tas-agent`), analogous to `clevis luks bind`.
   The original passphrase remains in slot 0 as a manual fallback.

2. **Key fetch** — The agent generates a temporary RSA-2048 wrapping key,
   obtains a nonce from TAS (`GET /kb/v0/get_nonce`), gathers a TEE
   attestation report (SEV-SNP or TDX) via `configfs-tsm`, and binds the
   nonce and public key via `SHA-512(nonce || pubkey_der)`. It then
   requests the wrapped secret (`POST /kb/v0/get_secret`). The server
   validates the attestation report and returns an AES-256-GCM–wrapped key
   that the agent unwraps with RSA-OAEP.

3. **HTTP retries** — `reqwest_retry` middleware retries transient failures
   (408, 429, 5xx) up to 3 times with exponential backoff and full jitter.
   Worst-case additional delay is ~7 s. Status codes 400, 401, 404 are not
   retried.

4. **TTY fallback** — The kernel command line includes
   `keyfile-timeout=30s`. If the agent cannot reach the TAS server within
   that window, `systemd-cryptsetup` (or initramfs-tools' `askpass`) falls
   back to a console passphrase prompt.

### Askpass Mode (dracut / systemd)

1. systemd's `cryptsetup` creates ask-password request files in
   `/run/systemd/ask-password/` when it needs a LUKS passphrase.
2. `tas-agent-askpass.path` detects the new file via inotify and starts
   `tas-agent-askpass.service`.
3. `tas_agent --askpass` scans the directory every 500 ms, finds
   cryptsetup requests, fetches the key from TAS, and sends the
   passphrase to cryptsetup via the Unix datagram socket specified in the
   `.ask` file.
4. cryptsetup opens the LUKS volume and boot continues.
5. After 10 seconds with no pending requests the agent exits.

### Passfifo Mode (initramfs-tools)

initramfs-tools does **not** use systemd during early boot. Instead, a
set of shell scripts under `/scripts/` drive the boot sequence:

```
/init (busybox)
  └─ /scripts/local-top/tas_agent      ← starts tas_agent --passfifo &
  └─ /scripts/local-top/cryptroot      ← cryptsetup runs /lib/cryptsetup/askpass
  └─ /scripts/local-bottom/tas_agent   ← kills the agent after root is mounted
```

**Boot flow:**

1. **Network** — The `local-top/tas_agent` script calls
   `configure_networking` (initramfs-tools' built-in DHCP helper, driven
   by the `ip=` kernel parameter) to bring up the network before the
   agent starts.

2. **Agent start** — The script launches `tas_agent --passfifo` in the
   background and saves its PID to `/run/tas_agent.pid`.

3. **Cryptsetup** — Shortly after, `local-top/cryptroot` runs
   `cryptsetup open` which spawns `/lib/cryptsetup/askpass`. That helper
   creates a named pipe (the *passfifo*) at `/lib/cryptsetup/passfifo`
   and blocks reading from it.

4. **Passfifo discovery** — The agent's polling loop (every 500 ms) scans
   `/proc` for running `askpass` processes, then follows
   `/proc/<PID>/fd/*` symlinks to find the open FIFO path.

5. **Key fetch & reply** — The agent fetches the LUKS key from TAS
   (same protocol as askpass mode) and writes the passphrase directly to
   the FIFO. The passphrase never passes through shell variables.

6. **Unlock** — `cryptsetup` reads the passphrase from the FIFO and
   opens the LUKS volume. Boot continues to `local-bottom`.

7. **Cleanup** — `local-bottom/tas_agent` kills the background agent
   via the saved PID and removes the log file.

8. **Idle exit** — If no `askpass` processes appear for 30 seconds after
   the last unlock, the agent exits on its own (the `local-bottom` kill
   is a safety net).

Because initramfs-tools uses busybox `/init` rather than systemd, there
are no `.path` or `.service` units involved — the `local-top` shell
script is the sole trigger.

### Systemd Units

| Unit | Purpose |
|---|---|
| `tas-agent-askpass.path` | Watches `/run/systemd/ask-password/` (inotify), triggers service |
| `tas-agent-askpass.service` | Runs `tas_agent --askpass`, After=network-online.target |
| `tas-agent-network.service` | Fallback DHCP via dhcpcd (Ubuntu dracut only) |

## Troubleshooting

### TAS agent starts but can't reach the server

```bash
# Check network came up in initrd
journalctl -b | grep tas-net-setup

# Verify DNS — use IP address in config.toml if hostname won't resolve in initrd
# Check firewall — TAS server port must be reachable from the CVM
```

### Boot hangs waiting for LUKS passphrase

- Verify `keyfile-timeout=30s` is in `/etc/crypttab`
- After timeout, a TTY prompt appears for manual entry
- Check logs: `journalctl -b -u tas-agent-askpass.service`

### "unable to read API key" error

```bash
ls -la /etc/tas_agent/api-key           # must exist, mode 0600
sudo update-initramfs -u                # rebuild after modifying
# or: sudo dracut --force
```

### TEE attestation fails

```bash
modprobe sev-guest    # or: modprobe tdx-guest
ls /sys/kernel/config/tsm/report/       # must exist

# Ubuntu: install linux-modules-extra for TEE modules
apt install linux-modules-extra-$(uname -r)
```

### "server URI must start with http:// or https://"

Check `server_uri` in `/etc/tas_agent/config.toml` for typos.

### Debug mode

> **Warning:** `--debug` prints sensitive material to the terminal,
> including wrapping keys, nonces, TEE evidence, and decrypted secrets.
> Use only for local troubleshooting and never in production or shared
> terminals.

```bash
sudo tas_agent --debug -c /etc/tas_agent/config.toml
```


## Known Limitations

- **Single key for all volumes**: The agent fetches one key from TAS and
  uses it for all pending LUKS volumes. Multiple volumes with different
  TAS keys are not yet supported.
