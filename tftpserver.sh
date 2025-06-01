#!/bin/bash
# Simple script to setup and start a TFTP server for payload hosting
set -e

# Ensure tftpd-hpa is installed
if ! command -v in.tftpd >/dev/null 2>&1; then
    echo "tftpd-hpa not found. Installing..."
    apt-get update -y && apt-get install tftpd-hpa -y
fi

# Default tftp directory
TFTP_DIR="/var/lib/tftpboot"

# Create directory if it does not exist
mkdir -p "$TFTP_DIR"

# Copy binaries from apache directory if they exist
APACHE_DIR="/var/www/html"
if [ -d "$APACHE_DIR" ]; then
    cp -f "$APACHE_DIR"/* "$TFTP_DIR" 2>/dev/null || true
fi

# Ensure correct permissions
chmod -R 755 "$TFTP_DIR"

# Start tftpd-hpa service
service tftpd-hpa restart

echo "TFTP server is running and serving files from $TFTP_DIR"
