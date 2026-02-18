#!/usr/bin/env bash
# lib/classify.sh — flood level classification

# classify_flow FLOWS
# Prints level label (with emoji) for the given flow count.
classify_flow() {
    local f="$1"
    (( f > THRESHOLD_CRITICAL    )) && { echo "🔥 CRITICAL FLOOD"; return; }
    (( f > THRESHOLD_HEAVY       )) && { echo "🔴 HEAVY FLOOD"; return; }
    (( f > THRESHOLD_FLOOD       )) && { echo "🟠 FLOOD"; return; }
    (( f > THRESHOLD_SUSPICIOUS  )) && { echo "🟡 Suspicious"; return; }
    echo "ℹ️  Normal"
}

# classify_order FLOWS
# Prints numeric order for sorting: 4=CRIT, 3=HEAVY, 2=FLOOD, 1=SUSP, 0=normal.
classify_order() {
    local f="$1"
    (( f > THRESHOLD_CRITICAL    )) && { echo 4; return; }
    (( f > THRESHOLD_HEAVY       )) && { echo 3; return; }
    (( f > THRESHOLD_FLOOD       )) && { echo 2; return; }
    (( f > THRESHOLD_SUSPICIOUS  )) && { echo 1; return; }
    echo 0
}

# classify_level_name FLOWS
# Prints short level for TSV: CRIT | HEAVY | FLOOD | SUSP (PROP/RPROXY use HEAVY for high).
classify_level_name() {
    local f="$1"
    (( f > THRESHOLD_CRITICAL    )) && { echo "CRIT"; return; }
    (( f > THRESHOLD_HEAVY       )) && { echo "HEAVY"; return; }
    (( f > THRESHOLD_FLOOD       )) && { echo "FLOOD"; return; }
    (( f > THRESHOLD_SUSPICIOUS  )) && { echo "SUSP"; return; }
    echo "Normal"
}
