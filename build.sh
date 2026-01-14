#!/bin/bash
#
# Copyright 2025 Hewlett Packard Enterprise Development LP.
# SPDX-License-Identifier: MIT
# Usage: ./build.sh [-d DESTDIR] [-r ROOTCERT]
#        ./build.sh [-h]
#
# Options:
#   -d DESTDIR   Set the destination directory for the package (default: ./target/package)
#   -r ROOTCERT  Set the TAS root cert
#   -h           Show this help message and exit

show_help() {
    echo "Usage: $0 [-d DESTDIR]"
    echo "       $0 [-h]"
    echo
    echo "Options:"
    echo "  -d DESTDIR    Set the destination directory for the package (default: ./target/package)"
    echo "  -r ROOTCERT   Set the TAS root cert"
    echo "  -e CONFIG     Set the TAS config file"
    echo "  -h            Show this help message and exit"
}

DESTDIR="./target/package"
ROOTCERT="./config/root_cert.pem"
CONFIG=".env"

# Parse command line options
while getopts "d:r:h" opt; do
    case "$opt" in
        d) DESTDIR="$OPTARG" ;;
        r) ROOTCERT="$OPTARG" ;;
        e) CONFIG="$OPTARG" ;;
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
    # Check if cargo is in sudo user's home directory
    CARGO_CMD="/home/$SUDO_USER/.cargo/bin/cargo"
    echo "Using cargo: $CARGO_CMD"
elif [ -f "$HOME/.cargo/bin/cargo" ]; then
    # Check if cargo is in root
    CARGO_CMD="$HOME/.cargo/bin/cargo"
    echo "Using cargo: $CARGO_CMD"
else
    echo "Cargo could not be found. Please install Rust and Cargo."
    exit 1
fi

FINAL_DIR="$DESTDIR/tas_agent"

# Build the executable
$CARGO_CMD clean

$CARGO_CMD build --release
if [ $? -ne 0 ]; then
    echo "Build failed. Please check the output for errors."
    exit 1
fi
if [ ! -e ./target/release/tas_agent ]; then
    echo "Build output not found. Please check the build process."
    exit 1
fi

mkdir -p "$FINAL_DIR/sbin"

# Copy the executable to the final directory
cp ./target/release/tas_agent "$FINAL_DIR/sbin"
if [ $? -ne 0 ]; then
    echo "Failed to copy executable to $FINAL_DIR/sbin. Please check the build process."
    exit 1
fi

# Copy the config files to the final directory
mkdir -p "$FINAL_DIR/etc/tas_agent"
cp $CONFIG "$FINAL_DIR/etc/tas_agent/config"
if [ $? -ne 0 ]; then
    echo "Failed to copy config file $CONFIG to $FINAL_DIR/etc/tas_agent/config. Please check the build process."
    exit 1
fi

# Copy the root certificate to the final directory
if [ ! -f "$ROOTCERT" ]; then
    echo "Root certificate not found: $ROOTCERT"
    exit 1
fi
cp "$ROOTCERT" "$FINAL_DIR/etc/tas_agent/root_cert.pem"
if [ $? -ne 0 ]; then
    echo "Failed to copy root_cert.pem to $FINAL_DIR/etc/tas_agent/root_cert.pem. Please check the build process."
    exit 1
fi

# Copy the initramfs scripts to the final directory
cp -R scripts/initramfs/ubuntu "$FINAL_DIR/ubuntu"
if [ ! -d "$FINAL_DIR/ubuntu" ]; then
    echo "initramfs directory not found. Please check the build process."
    exit 1
fi

# Copy the install script to the final directory
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
