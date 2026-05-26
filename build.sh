#!/bin/bash
set -euo pipefail
# Copyright 2026 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
#
# Usage: ./build.sh [--tarball [-d DESTDIR] [-r ROOTCERT] [-e CONFIG] [-a APIKEY]] [--deb] [--rpm] [--clean]
#        ./build.sh [-h]
#
# Options:
#   -d DESTDIR   Tarball build only: set the destination directory (default: ./target/package)
#   -r ROOTCERT  Tarball build only: set the TAS root cert
#   -e CONFIG    Tarball build only: set the TAS config file
#   -a APIKEY    Tarball build only: set the TAS API key file
#   --tarball    Build a tarball package
#   --deb        Build a .deb package (requires dpkg-buildpackage)
#   --rpm        Build an .rpm package (requires rpmbuild)
#   -h           Show this help message and exit

show_help() {
    echo "Usage: $0 [--tarball [-d DESTDIR] [-r ROOTCERT] [-e CONFIG] [-a APIKEY]] [--deb] [--rpm]"
    echo "       $0 [-h]"
    echo
    echo "Options:"
    echo "  -d DESTDIR    Tarball build only: set the destination directory (default: ./target/package)"
    echo "  -r ROOTCERT   Tarball build only: set the TAS root cert"
    echo "  -e CONFIG     Tarball build only: set the TAS config file"
    echo "  -a APIKEY     Tarball build only: set the TAS API key file"
    echo "  --tarball     Build a tarball package"
    echo "  --deb         Build a .deb package"
    echo "  --rpm         Build an .rpm package"
    echo "  --clean       Remove packaging build artifacts"
    echo "  -h            Show this help message and exit"
}

DESTDIR="./target/package"
ROOTCERT="./config/root_cert.pem"
CONFIG="./config/config.toml.sample"
APIKEY="./config/api-key.sample"
BUILD_TARBALL=false
BUILD_DEB=false
BUILD_RPM=false
BUILD_CLEAN=false

# Parse command line options
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d) DESTDIR="$2"; shift 2 ;;
        -r) ROOTCERT="$2"; shift 2 ;;
        -e) CONFIG="$2"; shift 2 ;;
        -a) APIKEY="$2"; shift 2 ;;
        --tarball) BUILD_TARBALL=true; shift ;;
        --deb) BUILD_DEB=true; shift ;;
        --rpm) BUILD_RPM=true; shift ;;
        --clean) BUILD_CLEAN=true; shift ;;
        -h)
            show_help
            exit 0
            ;;
        *)
            show_help
            exit 1
            ;;
    esac
done

# Handle --clean (exit early, no build needed)
if [ "$BUILD_CLEAN" = true ]; then
    echo "Cleaning packaging build artifacts..."
    rm -f debian                       # build-time symlink
    rm -rf packaging/debian/.debhelper
    rm -rf packaging/debian/tas-agent/ packaging/debian/tas-agent-dracut/ packaging/debian/tas-agent-initramfs/
    rm -f packaging/debian/debhelper-build-stamp packaging/debian/files
    rm -f packaging/debian/*.substvars packaging/debian/*.postrm.debhelper
    rm -f ../tas-agent*.deb ../tas-agent*.changes ../tas-agent*.buildinfo
    echo "Clean complete."
    exit 0
fi

MODE_COUNT=0
[ "$BUILD_TARBALL" = true ] && MODE_COUNT=$((MODE_COUNT + 1))
[ "$BUILD_DEB" = true ] && MODE_COUNT=$((MODE_COUNT + 1))
[ "$BUILD_RPM" = true ] && MODE_COUNT=$((MODE_COUNT + 1))

if [ "$MODE_COUNT" -eq 0 ]; then
    echo "No build mode specified. Choose one of --tarball, --deb, or --rpm."
    show_help
    exit 1
fi

if [ "$MODE_COUNT" -gt 1 ]; then
    echo "Choose only one build mode: --tarball, --deb, or --rpm."
    exit 1
fi

# Handle --deb packaging (dpkg-buildpackage does its own build via debian/rules)
if [ "$BUILD_DEB" = true ]; then
    echo "Building .deb package..."
    if ! command -v dpkg-buildpackage &> /dev/null; then
        echo "dpkg-buildpackage not found. Install dpkg-dev."
        exit 1
    fi
    # Copy debian dir to project root for dpkg-buildpackage
    cp -r packaging/debian .
    dpkg-buildpackage -us -uc -b -d
    rm -rf debian
    echo "Deb package built. Check parent directory for .deb file."
    exit 0
fi

# Handle --rpm packaging (rpmbuild does its own build via spec file)
if [ "$BUILD_RPM" = true ]; then
    echo "Building .rpm package..."
    if ! command -v rpmbuild &> /dev/null; then
        echo "rpmbuild not found. Install rpm-build."
        exit 1
    fi
    VERSION=$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
    echo "Version: $VERSION"
    mkdir -p ~/rpmbuild/{SPECS,SOURCES}
    cp packaging/rpm/tas-agent.spec ~/rpmbuild/SPECS/
    git archive --format=tar.gz --prefix="tas-agent-${VERSION}/" -o ~/rpmbuild/SOURCES/"tas-agent-${VERSION}.tar.gz" HEAD
    rpmbuild -bb --nodeps ~/rpmbuild/SPECS/tas-agent.spec
    echo "RPM package built. Check ~/rpmbuild/RPMS/ for .rpm files."
    exit 0
fi

if [ -z "$DESTDIR" ]; then
    echo "DESTDIR is not set. Please set it to the desired installation directory."
    exit 1
fi

# Check if DESTDIR exists, if not create it
if [ ! -d "$DESTDIR" ]; then
    mkdir -p "$DESTDIR"
    if [ $? -ne 0 ]; then
        echo "Failed to create directory $DESTDIR. Please check permissions."
        exit 1
    fi
else
    rm -rf "$DESTDIR"/*
    if [ $? -ne 0 ]; then
        echo "Failed to clear directory $DESTDIR. Please check permissions."
        exit 1
    fi
fi

# Check cargo installation
CARGO_CMD=""
if command -v cargo &> /dev/null; then
    CARGO_CMD="cargo"
elif [ -n "$SUDO_USER" ] && [ -f "/home/$SUDO_USER/.cargo/bin/cargo" ]; then
    CARGO_CMD="/home/$SUDO_USER/.cargo/bin/cargo"
    echo "Using cargo: $CARGO_CMD"
elif [ -f "$HOME/.cargo/bin/cargo" ]; then
    CARGO_CMD="$HOME/.cargo/bin/cargo"
    echo "Using cargo: $CARGO_CMD"
else
    echo "Cargo could not be found. Please install Rust and Cargo."
    exit 1
fi

echo "Building tarball package..."

FINAL_DIR="$DESTDIR/tas_agent"

# Build the executable (with askpass and passfifo features enabled)
$CARGO_CMD clean 2>/dev/null || true

$CARGO_CMD build --release --features askpass,passfifo
if [ $? -ne 0 ]; then
    echo "Build failed. Please check the output for errors."
    exit 1
fi
if [ ! -e ./target/release/tas_agent ]; then
    echo "Build output not found. Please check the build process."
    exit 1
fi

# Default tarball packaging
mkdir -p "$FINAL_DIR/sbin"

# Copy the executable to the final directory
cp ./target/release/tas_agent "$FINAL_DIR/sbin"
if [ $? -ne 0 ]; then
    echo "Failed to copy executable to $FINAL_DIR/sbin. Please check the build process."
    exit 1
fi

# Copy the config files to the final directory
mkdir -p "$FINAL_DIR/etc/tas_agent"
cp "$CONFIG" "$FINAL_DIR/etc/tas_agent/config.toml"
if [ $? -ne 0 ]; then
    echo "Failed to copy config file $CONFIG to $FINAL_DIR/etc/tas_agent/config.toml. Please check the build process."
    exit 1
fi

cp "$APIKEY" "$FINAL_DIR/etc/tas_agent/api-key"
if [ $? -ne 0 ]; then
    echo "Failed to copy API key $APIKEY to $FINAL_DIR/etc/tas_agent/api-key. Please check the build process."
    exit 1
fi

# Copy the root certificate to the final directory
if [ -f "$ROOTCERT" ]; then
    cp "$ROOTCERT" "$FINAL_DIR/etc/tas_agent/root_cert.pem"
fi

# Copy systemd units used by askpass and the dracut network fallback
mkdir -p "$FINAL_DIR/usr/lib/systemd/system"
cp scripts/systemd/tas-agent-askpass.path "$FINAL_DIR/usr/lib/systemd/system/"
cp scripts/systemd/tas-agent-askpass.service "$FINAL_DIR/usr/lib/systemd/system/"
cp scripts/systemd/tas-agent-network.service "$FINAL_DIR/usr/lib/systemd/system/"

# Copy modules-load.d config
mkdir -p "$FINAL_DIR/etc/modules-load.d"
cp scripts/systemd/modules-load.d/tas-agent.conf "$FINAL_DIR/etc/modules-load.d/"

# Copy dracut module and fallback helper
mkdir -p "$FINAL_DIR/usr/lib/dracut/modules.d/50tas-agent"
cp scripts/dracut/module-setup.sh "$FINAL_DIR/usr/lib/dracut/modules.d/50tas-agent/"
cp scripts/dracut/tas-net-setup.sh "$FINAL_DIR/usr/lib/dracut/modules.d/50tas-agent/"

# Copy the initramfs scripts to the final directory
cp -R scripts/initramfs/ubuntu "$FINAL_DIR/ubuntu"
if [ ! -d "$FINAL_DIR/ubuntu" ]; then
    echo "initramfs directory not found. Please check the build process."
    exit 1
fi

# Copy the install script to the final directory
# Copy tas-luks-bind helper script
cp scripts/tas-luks-bind "$FINAL_DIR/sbin/tas-luks-bind"
chmod +x "$FINAL_DIR/sbin/tas-luks-bind"

cp scripts/install.sh "$FINAL_DIR/install.sh"
if [ ! -e "$FINAL_DIR/install.sh" ]; then
    echo "install.sh not found. Please check the build process."
    exit 1
fi
chmod +x "$FINAL_DIR/install.sh"

echo "Success - package created in $FINAL_DIR"
find "$FINAL_DIR" -type f

echo "Creating tar file..."
tar -czf "$DESTDIR/tas_agent.tar.gz" -C "$DESTDIR" tas_agent
if [ $? -ne 0 ]; then
    echo "Failed to create tar file. Please check the output for errors."
    exit 1
fi
echo "Package created successfully at $DESTDIR/tas_agent.tar.gz"
echo "Build and packaging completed successfully."

exit 0
