#!/bin/bash
# Monitor Wi-Fi SSID changes and flush Clash connections automatically.
# Install as LaunchAgent to run at login.

SOCKET="/tmp/verge/verge-mihomo.sock"
LAST_SSID=""

flush_connections() {
    if [ -S "$SOCKET" ]; then
        curl -s -X DELETE --unix-socket "$SOCKET" http://localhost/connections > /dev/null 2>&1
        echo "$(date '+%Y-%m-%d %H:%M:%S') Network changed to '$1', flushed Clash connections"
    fi
}

while true; do
    CURRENT_SSID=$(/System/Library/PrivateFrameworks/Apple80211.framework/Resources/airport -I 2>/dev/null | awk -F': ' '/ SSID/{print $2}')

    if [ -z "$CURRENT_SSID" ]; then
        CURRENT_SSID="disconnected"
    fi

    if [ -n "$LAST_SSID" ] && [ "$CURRENT_SSID" != "$LAST_SSID" ]; then
        flush_connections "$CURRENT_SSID"
    fi

    LAST_SSID="$CURRENT_SSID"
    sleep 5
done
