#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$SCRIPT_DIR"

# Function to print error messages
error() {
    echo "Error: $1"
    exit 1
}

# Check if VERSION file exists
if [ ! -f VERSION ]; then
    error "VERSION file not found."
fi

# Read version from VERSION file
CENTRAL_VERSION=$(tr -d '\n' < VERSION)
echo "Central VERSION: $CENTRAL_VERSION"

# Check if dkms.conf exists
if [ ! -f dkms.conf ]; then
    error "dkms.conf file not found."
fi

# Read only the declarative version; sourcing the whole file would require
# variables that DKMS normally supplies (for example kernel_source_dir).
DKMS_VERSION=$(sed -n 's/^PACKAGE_VERSION="\([^"]*\)"$/\1/p' dkms.conf)
if [ -z "$DKMS_VERSION" ]; then
    error "Could not read PACKAGE_VERSION from dkms.conf"
fi
echo "dkms.conf PACKAGE_VERSION: $DKMS_VERSION"

# Check if bootstrap.sh exists
if [ ! -f bootstrap.sh ]; then
    error "bootstrap.sh file not found."
fi

if ! grep -Fq 'PROJECT_DIR/VERSION' bootstrap.sh; then
    error "bootstrap.sh does not read the kernel component VERSION file"
fi

# Compare versions
if [ "$CENTRAL_VERSION" != "$DKMS_VERSION" ]; then
    error "Version mismatch: VERSION=$CENTRAL_VERSION vs dkms.conf PACKAGE_VERSION=$DKMS_VERSION"
fi

echo "Version consistency check passed."
exit 0
