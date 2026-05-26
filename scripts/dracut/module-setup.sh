#!/bin/bash
# TAS Agent dracut module for Fedora/RHEL/Ubuntu
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
#
# Installs tas_agent binary, config, systemd askpass units, and
# kernel modules required for configfs-tsm TEE attestation.
#
# Network strategy (following Clevis pattern):
#   - If dracut's "network" module is available (Fedora: systemd-networkd works),
#     declare it as a dependency and let dracut handle networking via rd.neednet=1.
#   - If not (Ubuntu: network backends broken), install our own
#     tas-agent-network.service + tas-net-setup.sh fallback.

check() {
    [ -x /usr/sbin/tas_agent ] && return 0 || return 1
}

depends() {
    local __depends="crypt systemd"
    # Dracut v103+ has a separate systemd-cryptsetup module
    if dracut_module_included "systemd"; then
        local systemd_cryptsetup_dir
        systemd_cryptsetup_dir=$(dracut_module_path "systemd-cryptsetup" 2>/dev/null)
        if [ -d "$systemd_cryptsetup_dir" ]; then
            __depends="$__depends systemd-cryptsetup"
        fi
    fi
    # If dracut's network module exists (Fedora/RHEL), depend on it
    # like Clevis-tang does. This lets dracut handle rd.neednet=1 natively.
    local network_dir
    network_dir=$(dracut_module_path "network" 2>/dev/null)
    if [ -d "$network_dir" ]; then
        __depends="$__depends network"
    fi
    echo "$__depends"
    return 0
}

cmdline() {
    # Auto-inject rd.neednet=1 into the initrd cmdline (Clevis-tang pattern).
    # Dracut writes this to /etc/cmdline.d/ inside the initrd, so the
    # network module activates without manual kernel cmdline edits.
    echo "rd.neednet=1"
}

installkernel() {
    instmods configfs
    instmods tsm tsm_report
    instmods sev-guest tdx-guest
    instmods ccp  # implicit dep of sev-guest, explicit is safer
    instmods virtio_scsi virtio_pci virtio_net sd_mod  # QEMU virtio disk/net
}

install() {
    inst_binary /usr/sbin/tas_agent

    # Config files
    inst_simple /etc/tas_agent/config.toml
    inst_simple /etc/tas_agent/api-key 2>/dev/null || true
    # Restrict api-key permissions in initrd
    if [ -f "${initdir}/etc/tas_agent/api-key" ]; then
        chmod 0600 "${initdir}/etc/tas_agent/api-key"
    fi
    inst_simple /etc/tas_agent/root_cert.pem 2>/dev/null || true
    # System CA bundle (needed when config references /etc/ssl/certs/ca-certificates.crt)
    inst_simple /etc/ssl/certs/ca-certificates.crt 2>/dev/null || true

    # systemd units — both .path (trigger) and .service (handler)
    inst_simple /usr/lib/systemd/system/tas-agent-askpass.path
    inst_simple /usr/lib/systemd/system/tas-agent-askpass.service

    # modules-load.d config
    inst_simple /etc/modules-load.d/tas-agent.conf

    # ---- Networking ----
    # Check if dracut's native network module is handling networking
    local network_dir
    network_dir=$(dracut_module_path "network" 2>/dev/null)

    if [ -d "$network_dir" ]; then
        # Dracut's network module is available (Fedora/RHEL).
        # Following the Clevis pattern: rd.neednet=1 on the kernel cmdline
        # triggers dracut's network module (systemd-networkd or network-legacy).
        # We just need to order cryptsetup after network-online.target.
        mkdir -p "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d"
        cat > "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d/tas-network.conf" << 'DROPIN'
[Unit]
After=network-online.target
Wants=network-online.target
DROPIN
    else
        # Dracut's network module is NOT available or broken (Ubuntu).
        # Use our own tas-agent-network.service + tas-net-setup.sh fallback.
        # dhcpcd for DHCP
        if command -v dhcpcd >/dev/null 2>&1; then
            inst_binary dhcpcd
            inst_multiple -o /etc/dhcpcd.conf
            # dhcpcd expects a run-hooks script; provide a no-op stub if missing
            if [ ! -f "${initdir}/usr/libexec/dhcpcd-run-hooks" ]; then
                mkdir -p "${initdir}/usr/libexec"
                echo '#!/bin/sh' > "${initdir}/usr/libexec/dhcpcd-run-hooks"
                chmod 755 "${initdir}/usr/libexec/dhcpcd-run-hooks"
            fi
        fi

        # Network utilities needed by the setup script
        inst_multiple ip

        inst_simple "$moddir/tas-net-setup.sh" /usr/libexec/tas-net-setup.sh
        inst_simple /usr/lib/systemd/system/tas-agent-network.service

        mkdir -p "$initdir/etc/systemd/system/sysinit.target.wants"
        ln -sf /usr/lib/systemd/system/tas-agent-network.service \
            "$initdir/etc/systemd/system/sysinit.target.wants/tas-agent-network.service"

        # Ordering: cryptsetup must wait for our network service
        mkdir -p "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d"
        cat > "$initdir/etc/systemd/system/systemd-cryptsetup@.service.d/tas-network.conf" << 'DROPIN'
[Unit]
After=tas-agent-network.service
Wants=tas-agent-network.service
DROPIN
    fi

    # Enable the .path unit — use sysinit.target.wants so it starts early
    # (matching systemd-ask-password-console.path behaviour)
    mkdir -p "$initdir/etc/systemd/system/sysinit.target.wants"
    ln -sf /usr/lib/systemd/system/tas-agent-askpass.path \
        "$initdir/etc/systemd/system/sysinit.target.wants/tas-agent-askpass.path"

    dracut_need_initqueue
}
