#!/usr/bin/env bash
# lib/json_stream.sh — единая точка входа: nfdump -o json → canonical TSV поток
# Все детекторы (FLOOD/PROP/RPROXY/STAGE/NAT_BURST) работают только с этим потоком.
# Использование: json_stream <nfcapd_file> [nfdump_filter]
# Или: json_stream "$last_file" | detect_flood_pairs

# Зависит от normalize.sh (normalize_flows).
SCRIPT_JSON_STREAM_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ -f "${SCRIPT_JSON_STREAM_DIR}/normalize.sh" ]] && source "${SCRIPT_JSON_STREAM_DIR}/normalize.sh"

# json_stream <nfcapd_file> [filter]
# Печатает в stdout canonical TSV: одна строка на flow.
# Колонки: FIRST_TS DURATION_MS PROTO SRC_IP DST_IP SRC_PORT DST_PORT PACKETS BYTES TCP_FLAGS XLAT_IP XLAT_PORT
# filter — опциональный фильтр nfdump (например "proto udp"). Если не задан, без фильтра (все flow'ы).
json_stream() {
    local file="${1:?}"
    local filter="${2:-}"
    if [[ -n "$filter" ]]; then
        nfdump -r "$file" "$filter" -o json 2>/dev/null | normalize_flows
    else
        nfdump -r "$file" -o json 2>/dev/null | normalize_flows
    fi
}
