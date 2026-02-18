#!/usr/bin/env bash
# lib/classify_ext.sh — labels for extended detection modes (ADB Scan, Proxy, Staging)
# Used in Telegram alert lines; does not use flow thresholds like classify.sh

# classify_adb_scan — emoji + label for ADB Scan (Propagation)
classify_adb_scan() {
    echo "🔴 ADB SCAN"
}

# classify_proxy — emoji + label for Proxy microflows
classify_proxy() {
    echo "🟠 PROXY MICROFLOWS"
}

# classify_staging — emoji + label for UDP Staging
classify_staging() {
    echo "🔥 UDP STAGING"
}
