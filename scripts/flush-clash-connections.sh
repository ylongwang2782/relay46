#!/bin/bash
# Flush all Clash connections when network changes.
# Usage: manually run, or auto-trigger via LaunchAgent on Wi-Fi change.

SOCKET="/tmp/verge/verge-mihomo.sock"

if [ ! -S "$SOCKET" ]; then
    echo "Clash socket not found: $SOCKET"
    exit 1
fi

curl -s -X DELETE --unix-socket "$SOCKET" http://localhost/connections > /dev/null 2>&1
echo "$(date '+%Y-%m-%d %H:%M:%S') Flushed all Clash connections"
