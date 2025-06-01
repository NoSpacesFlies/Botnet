#!/bin/bash
set -e

if ! command -v in.tftpd >/dev/null 2>&1; then
    echo "tftpd-hpa not found. Installing..."
    apt-get update -y && apt-get install tftpd-hpa -y
fi

TFTP_DIR="/var/lib/tftpboot"

mkdir -p "$TFTP_DIR"

APACHE_DIR="/var/www/html"
if [ -d "$APACHE_DIR" ]; then
    cp -f "$APACHE_DIR"/* "$TFTP_DIR" 2>/dev/null || true
fi

chmod -R 755 "$TFTP_DIR"
service tftpd-hpa restart

echo "TFTP server is running and serving files from $TFTP_DIR"
