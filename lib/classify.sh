#!/usr/bin/env bash
# lib/classify.sh — flood level classification

# classify_flow FLOWS
# Prints level label (with emoji) for the given flow count.
classify_flow() {
    local flows="$1"

    if   (( flows > THRESHOLD_CRITICAL    )); then echo "🔥 CRITICAL FLOOD"
    elif (( flows > THRESHOLD_HEAVY       )); then echo "🔴 HEAVY FLOOD"
    elif (( flows > THRESHOLD_FLOOD       )); then echo "🟠 FLOOD"
    elif (( flows > THRESHOLD_SUSPICIOUS  )); then echo "🟡 Suspicious"
    else echo "ℹ️  Normal"
    fi
}
