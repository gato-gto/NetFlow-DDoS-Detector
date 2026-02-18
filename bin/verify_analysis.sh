#!/usr/bin/env bash
# Диагностика: проверка цепочки nfdump → awk (то, что выполняет detector.sh)
# Запуск: ./bin/verify_analysis.sh [nfcapd-файл]
# Использует etc/detector.conf (тот же конфиг, что и detector.sh)

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/etc/detector.conf"

[[ ! -f "$CONFIG_FILE" ]] && { echo "ERROR: config not found: $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"
source "${SCRIPT_DIR}/lib/nfdump_analysis.sh"

traffic_scope=$(build_traffic_scope)

# Resolve file (same logic as detector)
file="${1:-}"
if [[ -z "$file" ]]; then
    if [[ "${WAIT_FOR_PREVIOUS_INTERVAL:-0}" == "1" ]]; then
        prev_ts=$(nfdump_expected_previous_minute)
        file=$(nfdump_find_file_for_interval "$NFSEN_BASE" "$prev_ts")
    fi
    [[ -z "$file" ]] && file=$(nfdump_find_last_file "$NFSEN_BASE")
fi
[[ -z "$file" || ! -f "$file" ]] && { echo "ERROR: no nfcapd file found" >&2; exit 1; }

# Single nfdump run, pipe to multiple consumers via temp
raw=$(nfdump -r "$file" "${NFDUMP_FILTER} and (${traffic_scope})" \
    -A srcip,dstip -s "${NFDUMP_TOP_SORT:-record/flows}" -n "$NFDUMP_TOP_N" 2>/dev/null)
thr="$THRESHOLD_SUSPICIOUS"

echo "=== NFDD verify_analysis ==="
echo "Config: $CONFIG_FILE | File: $file"
echo "Scope: $traffic_scope | Threshold: $thr"
echo ""

echo "--- Step 1: Raw nfdump (first 5 data lines) ---"
echo "$raw" | awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {print; if (++n>=5) exit}'
echo ""

echo "--- Step 2: Column check ---"
echo "$raw" | awk '/^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {print "NF=" NF ", src=$4=" $4 ", dst=$5=" $5 ", flows=$NF=" $NF; exit}'
echo ""

echo "--- Step 3: Pairs above threshold ---"
results=$(echo "$raw" | awk -v thr="$thr" '
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
        src=$4; dst=$5; flows=$NF
        if ($(NF-2) ~ /^[GMK]$/) { bytes=$(NF-3) $(NF-2); packets=$(NF-5) $(NF-4) }
        else { bytes=$(NF-2); packets=$(NF-3) }
        if (flows+0 > thr+0) print src "\t" dst "\t" flows "\t" packets "\t" bytes
    }
')
count=$([[ -n "$results" ]] && wc -l <<< "$results" || echo 0)
echo "Count: $count"
echo "$results"
echo ""

[[ $count -gt 0 ]] && echo "OK: $count pairs above threshold — detector SHOULD have alerted." \
    || echo "No pairs above threshold. If raw shows flows > $thr, check awk column mapping."
