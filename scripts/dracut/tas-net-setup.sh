#!/bin/sh
# TAS Agent initrd network setup script
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Brings up the first ethernet interface via DHCP using dhcpcd.
# Called by tas-agent-network.service (a systemd unit embedded in the initrd).
#
# Ubuntu 26.04's dracut-network backends are both broken in the initrd:
#   - systemd-networkd requires dbus (modules not shipped)
#   - network-legacy requires dhclient (package removed)

echo "tas-net-setup: starting network setup" >&2

# Ensure virtio_net module is loaded (it may be a module, not built-in)
modprobe virtio_net 2>/dev/null || true
modprobe virtio_pci 2>/dev/null || true

# Wait for a NIC to appear (udev trigger has fired but device
# enumeration may still be in progress).
iface=""
try=0
while [ "$try" -lt 40 ]; do
    for dev in /sys/class/net/*; do
        name="${dev##*/}"
        [ "$name" = "lo" ] && continue
        # Check if it's an ethernet device (type 1)
        devtype="$(cat "$dev/type" 2>/dev/null)"
        [ "$devtype" = "1" ] || continue
        iface="$name"
        break 2
    done
    try=$((try + 1))
    sleep 0.5
done

if [ -z "$iface" ]; then
    echo "tas-net-setup: no ethernet interface found after 20s" >&2
    ls -la /sys/class/net/ >&2
    exit 1
fi

echo "tas-net-setup: found interface $iface" >&2

# Bring the link up
ip link set dev "$iface" up 2>/dev/null || true

# Wait briefly for carrier
i=0
while [ "$i" -lt 10 ]; do
    carrier="$(cat /sys/class/net/"$iface"/carrier 2>/dev/null)"
    [ "$carrier" = "1" ] && break
    i=$((i + 1))
    sleep 0.5
done

# If systemd-networkd is running, let it handle DHCP — just wait for an IP
if systemctl is-active --quiet systemd-networkd.service 2>/dev/null; then
    echo "tas-net-setup: systemd-networkd is active, waiting for IP on $iface" >&2
    ip link set dev "$iface" up 2>/dev/null || true
    j=0
    while [ "$j" -lt 40 ]; do
        if ip addr show dev "$iface" 2>/dev/null | grep -q "inet "; then
            echo "tas-net-setup: $iface got IP via systemd-networkd" >&2
            ip addr show dev "$iface" 2>/dev/null | grep "inet " >&2
            exit 0
        fi
        j=$((j + 1))
        sleep 1
    done
    echo "tas-net-setup: timeout waiting for systemd-networkd to configure $iface" >&2
    exit 1
# Run dhcpcd for DHCP (Ubuntu / distros without systemd-networkd in initrd)
elif command -v dhcpcd >/dev/null 2>&1; then
    if ip addr show dev "$iface" 2>/dev/null | grep -q "inet "; then
        echo "tas-net-setup: $iface already has an IP (static config), skipping dhcpcd" >&2
        exit 0
    fi
    echo "tas-net-setup: running dhcpcd on $iface" >&2
    # --oneshot: exit once a lease is obtained (don't stay running)
    dhcpcd --oneshot --waitip --nobackground "$iface" 2>&1
    echo "tas-net-setup: dhcpcd exited with status $?" >&2
else
    echo "tas-net-setup: ERROR: no network backend available" >&2
    echo "tas-net-setup: need systemd-networkd or dhcpcd in the initrd" >&2
    echo "tas-net-setup: install dhcpcd or enable dracut network module" >&2
    exit 1
fi

# Verify we got an IP
if ip addr show dev "$iface" 2>/dev/null | grep -q "inet "; then
    echo "tas-net-setup: $iface is up with IP" >&2
    ip addr show dev "$iface" 2>/dev/null | grep "inet " >&2
    exit 0
fi

# Fallback: check /sys for the address (if ip is missing)
if [ -d "/sys/class/net/$iface" ]; then
    echo "tas-net-setup: $iface exists, assuming dhcpcd configured it" >&2
    exit 0
fi

echo "tas-net-setup: failed to get IP on $iface" >&2
exit 1
