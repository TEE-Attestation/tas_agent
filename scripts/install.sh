#!/bin/bash
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
# Script to install tas_agent package, with options to update initramfs and remove the package.
#

show_help() {
    echo "Usage: $0 [-d DESTDIR]"
    echo "       $0 [-h]"
    echo "       $0 [-r]"
    echo "       $0 [-u]"
    echo
    echo "Options:"
    echo "  -d DESTDIR   Set the destination directory (default: /)"
    echo "  -r           Remove the tas_agent package from the system"
    echo "  -u           Update-initramfs of the running kernel after the installation"
    echo "               Can combine with -r option to remove package and update initramfs"
    echo "  -h           Show this help message and exit"
}

DESTDIR="/"
UPDATE_INITRAMFS="0"
REMOVE="0"

# Parse command line options
while getopts "d:hur" opt; do
    case "$opt" in
        d) DESTDIR="$OPTARG" ;;
        u) UPDATE_INITRAMFS="1" ;;
        r) REMOVE="1" ;;
        h)
            show_help
            exit 0
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

install() {
    # Check if DESTDIR exists, if not create it
    if [ ! -d "$DESTDIR" ]; then
        mkdir -p "$DESTDIR"
        if [ $? -ne 0 ]; then
            echo "Failed to create directory $DESTDIR. Please check permissions."
            exit 1
        fi
        mkdir -p "$DESTDIR/sbin"
        mkdir -p "$DESTDIR/etc"
    fi

    # Check if the package is good
    if [ ! -e ./sbin/tas_agent ]; then
        echo "Package invalid, sbin/tas_agent not found. Please check the build process."
        exit 1
    fi

    if [ ! -e ./etc/tas_agent ]; then
        echo "Package invalid, etc/tas_agent not found. Please check the build process."
        exit 1
    fi

    if [ ! -e ./ubuntu/hooks/tas_agent ]; then
        echo "Package invalid, ubuntu/hooks/tas_agent not found. Please check the build process."
        exit 1
    fi

    if [ ! -e ./ubuntu/init-premount/tas_agent ]; then
        echo "Package invalid, ubuntu/init-premount/tas_agent not found. Please check the build process."
        exit 1
    fi

    if [ ! -e ./ubuntu/modules ]; then
        echo "Package invalid, ubuntu/modules not found. Please check the build process."
        exit 1
    fi

    echo "Installing tas_agent to $DESTDIR"

    chmod +x ./sbin/tas_agent
    cp ./sbin/tas_agent "$DESTDIR/sbin"
    if [ $? -ne 0 ]; then
        echo "Failed to copy tas_agent to $DESTDIR/sbin. Please check permissions."
        exit 1
    fi

    cp -R ./etc/tas_agent "$DESTDIR/etc"
    if [ $? -ne 0 ]; then
        echo "Failed to copy tas_agent config to $DESTDIR/etc. Please check permissions."
        exit 1
    fi

    # Copy initramfs scripts to the appropriate directories
    chmod +x ./ubuntu/hooks/tas_agent
    cp ./ubuntu/hooks/tas_agent "$DESTDIR/usr/share/initramfs-tools/hooks"
    if [ $? -ne 0 ]; then
        echo "Failed to copy initramfs hook to $DESTDIR/usr/share/initramfs-tools/hooks. Please check permissions."
        exit 1
    fi
    chmod +x ./ubuntu/init-premount/tas_agent
    cp ./ubuntu/init-premount/tas_agent "$DESTDIR/usr/share/initramfs-tools/scripts/init-premount"
    if [ $? -ne 0 ]; then
        echo "Failed to copy initramfs script to $DESTDIR/usr/share/initramfs-tools/scripts/init-premount. Please check permissions."
        exit 1
    fi
    cp ./ubuntu/modules "$DESTDIR/etc/initramfs-tools/modules"
    if [ $? -ne 0 ]; then
        echo "Failed to copy initramfs modules file to $DESTDIR/etc/initramfs-tools/modules. Please check permissions."
        exit 1
    fi
}

if [ $REMOVE -eq 1 ]; then
    INITRD_ARTIFACTS="0"
    echo "Removing tas_agent from $DESTDIR"
    rm -rf "$DESTDIR/sbin/tas_agent"
    rm -rf "$DESTDIR/etc/tas_agent"
    if [ -e "$DESTDIR/usr/share/initramfs-tools/hooks/tas_kbm_ctl" ]; then
        rm -rf "$DESTDIR/usr/share/initramfs-tools/hooks/tas_kbm_ctl"
        INITRD_ARTIFACTS=1
    fi
    if [ -e "$DESTDIR/usr/share/initramfs-tools/scripts/init-premount/tas_kbm_ctl" ]; then
        rm -rf "$DESTDIR/usr/share/initramfs-tools/scripts/init-premount/tas_kbm_ctl"
        INITRD_ARTIFACTS=1
    fi
    if [ -e "$DESTDIR/etc/initramfs-tools/modules" ]; then
        rm -rf "$DESTDIR/etc/initramfs-tools/modules"
        INITRD_ARTIFACTS=1
    fi
    echo "Package removed successfully from $DESTDIR"
    if [ $INITRD_ARTIFACTS -eq 1 ]; then
        if [ $UPDATE_INITRAMFS -eq 0 ]; then
            echo "NO -u option specified and initramfs artifacts found on system, recommend checking initrd image."
        fi
    fi
else
    # Install the package
    install
    echo "Package installed successfully at $DESTDIR"
fi

# Update initramfs of running kernel
if [ $UPDATE_INITRAMFS -eq 1 ]; then

    if [ -x "$(command -v update-initramfs)" ]; then
        echo "Updating iniramfs..."
        KERNEL_VER="$(uname -r)"
        update-initramfs -u -k "$KERNEL_VER"
        if [ $? -ne 0 ]; then
            echo "Failed to update initramfs. Please check the output for errors."
            exit 1
        fi
    else
        echo "update-initramfs command not found. Skipping initramfs update."
    fi

fi



