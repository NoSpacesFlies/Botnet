#!/bin/bash
set -e

if ! command -v vsftpd >/dev/null 2>&1; then
    echo "vsftpd not found. Installing..."
    apt-get update -y && apt-get install vsftpd -y
fi

FTP_DIR="/srv/ftp"

mkdir -p "$FTP_DIR"

APACHE_DIR="/var/www/html"
if [ -d "$APACHE_DIR" ]; then
    cp -f "$APACHE_DIR"/* "$FTP_DIR" 2>/dev/null || true
fi

service vsftpd restart

echo "[FTP-Server]: DONE"
