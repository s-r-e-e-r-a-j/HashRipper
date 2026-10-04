#!/usr/bin/env bash

# Developer: Sreeraj
# GitHub: https://github.com/s-r-e-e-r-a-j

if [[ -n "${TERMUX_VERSION:-}" || "${PREFIX:-}" == *"/com.termux/"* || -d "/data/data/com.termux" ]]; then
    BINARY="${PREFIX}/bin/hashripper"
else
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
       echo "This script must be run as root or with sudo" 
       exit 1
    fi
    BINARY="/usr/local/bin/hashripper"
fi

if [ -f "$BINARY" ]; then
    echo "Removing $BINARY..."
    rm -f "$BINARY"
    echo "HashRipper has been uninstalled successfully."
else
    echo "HashRipper is not installed in $BINARY."
fi
