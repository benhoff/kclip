#!/bin/bash

# Exit immediately if a command exits with a non-zero status
set -e

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

# Read version from dkms.conf (evaluates command substitution if present)
DKMS_VERSION=$( ( source dkms.conf >/dev/null 2>&1; printf '%s' "$PACKAGE_VERSION" ) )
echo "dkms.conf PACKAGE_VERSION: $DKMS_VERSION"

# Check if bootstrap.sh exists
if [ ! -f bootstrap.sh ]; then
    error "bootstrap.sh file not found."
fi

# Extract dynamic MODULE_VERSION assignment from bootstrap.sh
BOOTSTRAP_ASSIGN=$(grep -E '^[[:space:]]*MODULE_VERSION=\$\(' bootstrap.sh | head -n1)
if [ -z "$BOOTSTRAP_ASSIGN" ]; then
    error "Could not locate MODULE_VERSION assignment in bootstrap.sh"
fi

# Strip identifier prefix
BOOTSTRAP_ASSIGN=${BOOTSTRAP_ASSIGN#*=}

# Evaluate assignment in the current tree (expects checkout_dir to point at repo root)
BOOTSTRAP_VERSION=$(bash -c "checkout_dir='.'; echo $BOOTSTRAP_ASSIGN" | tr -d '\n')
echo "bootstrap.sh VERSION: $BOOTSTRAP_VERSION"

# Compare versions
if [ "$CENTRAL_VERSION" != "$DKMS_VERSION" ]; then
    error "Version mismatch: VERSION=$CENTRAL_VERSION vs dkms.conf PACKAGE_VERSION=$DKMS_VERSION"
fi

if [ "$CENTRAL_VERSION" != "$BOOTSTRAP_VERSION" ]; then
    error "Version mismatch: VERSION=$CENTRAL_VERSION vs bootstrap.sh VERSION=$BOOTSTRAP_VERSION"
fi

echo "Version consistency check passed."
exit 0
