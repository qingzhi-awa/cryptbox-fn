#!/bin/bash
# Reset the super admin password (run after SSH login to fnOS, no SMTP required)
# Usage: /var/apps/cryptbox/target/reset-password.sh

set -e

# Script is under the target directory; derive the app root and data directory from it
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
APP_ROOT="$(dirname "$SCRIPT_DIR")"
DB_FILE="${APP_ROOT}/var/app.db"

# Select binary based on system architecture
ARCH=$(uname -m)
BIN="${SCRIPT_DIR}/cryptbox-server"
if [ "$ARCH" = "aarch64" ] || [ "$ARCH" = "arm64" ]; then
    BIN="${SCRIPT_DIR}/cryptbox-server-arm64"
fi

if [ ! -x "$BIN" ]; then
    echo "Error: executable not found: $BIN" >&2
    exit 1
fi

if [ ! -f "$DB_FILE" ]; then
    echo "Error: database file not found: $DB_FILE (app may not be initialized)" >&2
    exit 1
fi

# Enter a new password (no echo) and confirm
read -s -p "Enter new super admin password: " NEW_PASSWORD
echo
read -s -p "Confirm password: " CONFIRM
echo

if [ -z "$NEW_PASSWORD" ]; then
    echo "Error: password cannot be empty" >&2
    exit 1
fi

if [ "$NEW_PASSWORD" != "$CONFIRM" ]; then
    echo "Error: passwords do not match" >&2
    exit 1
fi

# Pass the password via stdin to the reset command (avoid the password appearing in the command line)
printf '%s\n' "$NEW_PASSWORD" | DB_DSN="$DB_FILE" "$BIN" -reset-admin
