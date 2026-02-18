#!/usr/bin/env bash
# verify_analysis.sh — self-test цепочки детекторов
# Запуск: ./bin/verify_analysis.sh [nfcapd-файл]
#         ./bin/verify_analysis.sh --json [nfcapd-файл]  — диагностика по FLOW_NDJSON_V1 (top src→dst, top src по uniq nat_src_port, microflows).
# При VERIFY_LOW_THRESHOLDS=1 использует заниженные пороги для ADB/STAGING.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/etc/detector.conf"

[[ ! -f "$CONFIG_FILE" ]] && { echo "ERROR: config not found: $CONFIG_FILE" >&2; exit 1; }
# shellcheck source=/dev/null
source "$CONFIG_FILE"
source "${SCRIPT_DIR}/lib/log.sh"
source "${SCRIPT_DIR}/lib/nfdump_analysis.sh"
source "${SCRIPT_DIR}/lib/json_flow.sh"
[[ -f "${SCRIPT_DIR}/lib/detectors/nat_burst.sh" ]] && source "${SCRIPT_DIR}/lib/detectors/nat_burst.sh"

# Режим --json: диагностика по нормализованному NDJSON (без legacy-детекторов).
JSON_MODE=0
if [[ "${1:-}" == "--json" ]]; then
    JSON_MODE=1
    shift
fi

# Lowered thresholds for self-test (when VERIFY_LOW_THRESHOLDS=1)
[[ "${VERIFY_LOW_THRESHOLDS:-0}" == "1" ]] && {
    export ADB_SCAN_UNIQUE_DST_PER_MIN=2
    export STAGING_MIN_UNIQUE_SRC=2
    export STAGING_MIN_TOTAL_FLOWS=10
}

traffic_scope=$(build_traffic_scope)
file="${1:-}"
if [[ -z "$file" ]]; then
    [[ "${WAIT_FOR_PREVIOUS_INTERVAL:-0}" == "1" ]] && { prev_ts=$(nfdump_expected_previous_minute); file=$(nfdump_find_file_for_interval "$NFSEN_BASE" "$prev_ts"); }
    [[ -z "$file" ]] && file=$(nfdump_find_last_file "$NFSEN_BASE")
fi
[[ -z "$file" || ! -f "$file" ]] && { echo "ERROR: no nfcapd file found" >&2; exit 1; }

# ----- Режим --json: три диагностических блока по FLOW_NDJSON_V1 -----
if (( JSON_MODE == 1 )); then
    export INTERNAL_CIDR="${INTERNAL_CIDR:-10.0.0.0/8}"
    ndjson_tmp=$(mktemp)
    trap 'rm -f "$ndjson_tmp"' EXIT
    nf_stream_norm "$file" > "$ndjson_tmp" || { echo "ERROR: nf_stream_norm failed" >&2; exit 1; }
    line_count=$(wc -l < "$ndjson_tmp")
    echo "=== NFDD verify_analysis --json (FLOW_NDJSON_V1) ==="
    echo "File: $file | NDJSON lines: $line_count"
    echo ""

    # 1) Top src→dst по количеству flow'ов (строк)
    echo "--- Top src→dst (by flow count) ---"
    jq -r 'select(.src_ip != "" and .dst_ip != "") | "\(.src_ip)\t\(.dst_ip)"' "$ndjson_tmp" 2>/dev/null \
        | sort | uniq -c | sort -rn | head -15 \
        | awk -v OFS='\t' '{ print $1, $2, $3 }'
    echo ""

    # 2) Top src по количеству уникальных nat_src_port (диагностика NAT burst)
    echo "--- Top src by uniq nat_src_port (NAT burst diagnostic) ---"
    jq -r 'select(.nat_src_port != null and .nat_src_port != 0) | "\(.src_ip)\t\(.nat_src_port)"' "$ndjson_tmp" 2>/dev/null \
        | sort -u | cut -f1 | sort | uniq -c | sort -rn | head -15 \
        | awk -v OFS='\t' '{ print $1, $2 }'
    echo ""

    # 3) Top microflows: dur_ms <= X, bytes <= Y (по умолчанию 2000 ms, 500 bytes)
    VERIFY_MICRO_DUR_MS="${VERIFY_MICRO_DUR_MS:-2000}"
    VERIFY_MICRO_BYTES="${VERIFY_MICRO_BYTES:-500}"
    echo "--- Microflows (dur_ms <= ${VERIFY_MICRO_DUR_MS}, bytes <= ${VERIFY_MICRO_BYTES}) ---"
    jq -r --argjson dur "${VERIFY_MICRO_DUR_MS}" --argjson bytes "${VERIFY_MICRO_BYTES}" \
        'select(.dur_ms <= $dur and .bytes <= $bytes) | "\(.src_ip)\t\(.dst_ip)\t\(.dur_ms)\t\(.bytes)\t\(.pkts)"' "$ndjson_tmp" 2>/dev/null \
        | head -20
    echo ""
    echo "========== END (--json) =========="
    exit 0
fi

status_fp="" status_adb="" status_stg="" status_nat=""
raw=$(nfdump -r "$file" "${NFDUMP_FILTER} and (${traffic_scope})" \
    -A srcip,dstip -s "${NFDUMP_TOP_SORT:-record/flows}" -n "$NFDUMP_TOP_N" 2>/dev/null) || raw=""
thr="$THRESHOLD_SUSPICIOUS"

echo "=== NFDD verify_analysis (self-test) ==="
echo "File: $file | Scope: $traffic_scope"
echo ""

# --- FLOODPAIRS ---
echo "--- FLOODPAIRS ---"
results_fp=$(echo "$raw" | awk -v thr="$thr" '
    /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
        src=$4; dst=$5; flows=$NF
        if ($(NF-2) ~ /^[GMK]$/) { bytes=$(NF-3) $(NF-2); packets=$(NF-5) $(NF-4) }
        else { bytes=$(NF-2); packets=$(NF-3) }
        if (flows+0 > thr+0) print src "\t" dst "\t" flows "\t" packets "\t" bytes
    }
' 2>/dev/null) || results_fp=""
count_fp=$([[ -n "$results_fp" ]] && wc -l <<< "$results_fp" || echo 0)
if [[ -z "$raw" ]]; then status_fp="FAIL (no nfdump data)"; elif (( count_fp > 0 )); then status_fp="OK ($count_fp above thr=$thr)"; echo "$results_fp" | head -5; else status_fp="WARN (0 above thr — normal if traffic low)"; fi
echo "FLOODPAIRS: $status_fp"
echo ""

# --- ADBSCAN ---
echo "--- ADBSCAN ---"
results_adb=$(nfdump_detect_adb_scan "$file" "$traffic_scope" 2>/dev/null) || results_adb=""
count_adb=$([[ -n "$results_adb" ]] && wc -l <<< "$results_adb" || echo 0)
if (( count_adb > 0 )); then status_adb="OK ($count_adb triggers)"; echo "$results_adb" | head -3; else status_adb="WARN (0 — normal if no ADB traffic)"; fi
echo "ADBSCAN: $status_adb"
echo ""

# --- STAGING ---
echo "--- STAGING ---"
results_stg=$(nfdump_detect_udp_staging "$file" "$traffic_scope" 2>/dev/null) || results_stg=""
count_stg=$([[ -n "$results_stg" ]] && wc -l <<< "$results_stg" || echo 0)
if (( count_stg > 0 )); then status_stg="OK ($count_stg triggers)"; echo "$results_stg" | head -3; else status_stg="WARN (0 — normal if no staging pattern)"; fi
echo "STAGING: $status_stg"
echo ""

# --- NATBURST ---
echo "--- NATBURST ---"
raw_nat=$(nfdump -r "$file" -o raw "(${traffic_scope})" 2>/dev/null) || raw_nat=""
nat_create=$(echo "${raw_nat:-}" | grep -ci 'nat event[^0-9]*1' 2>/dev/null || echo 0)
nat_delete=$(echo "${raw_nat:-}" | grep -ci 'nat event[^0-9]*2' 2>/dev/null || echo 0)
nat_total=$(( nat_create + nat_delete ))
if (( nat_total > 0 )); then
    results_nat=$(nat_burst_run "$file" "$traffic_scope" 2>/dev/null) || results_nat=""
    count_nat=$([[ -n "$results_nat" ]] && wc -l <<< "$results_nat" || echo 0)
    status_nat="OK (nat events: create=$nat_create delete=$nat_delete, bursts=$count_nat)"
    [[ -n "$results_nat" ]] && echo "$results_nat" | head -3
else
    status_nat="WARN (no nat events in raw — NAT BURST will not trigger)"
fi
echo "NATBURST: $status_nat"
echo ""

# --- Summary ---
echo "========== SUMMARY =========="
echo "FLOODPAIRS: $status_fp"
echo "ADBSCAN:    $status_adb"
echo "STAGING:    $status_stg"
echo "NATBURST:   $status_nat"
echo ""
if [[ "$status_fp" == FAIL* ]] || [[ "$status_adb" == FAIL* ]] || [[ "$status_stg" == FAIL* ]] || [[ "$status_nat" == FAIL* ]]; then
    echo "OVERALL: FAIL — fix errors above"
    exit 1
else
    echo "OVERALL: OK — all modules ran (WARN = no triggers, expected in low traffic)"
    exit 0
fi
