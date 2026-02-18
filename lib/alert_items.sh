#!/usr/bin/env bash
# lib/alert_items.sh — canonical TSV format ITEMS_V1 for alert items
# Columns: TYPE, SEV, LEVEL, DEDUP_KEY, SRC, DST, PREFIX, PROTO, DPORT, FLOWS, PKTS, BYTES,
#          DUR_MS, UNIQ_DST, UNIQ_SRC, MICRO, FLAGS_NOTE, MODE_NOTE, AS_NUM, AS_NAME, EXTRA

# normalize_bytes RAW
# Converts "1.2 M", "300 K", "123", "" to integer bytes. Output to stdout.
normalize_bytes() {
    local raw="${1:-}"
    [[ -z "$raw" ]] && echo "0" && return
    echo "$raw" | awk '
        /[Gg]/ { gsub(/[^0-9.]/,""); v=$0*1024*1024*1024; printf "%.0f\n", v; exit }
        /[Mm]/ { gsub(/[^0-9.]/,""); v=$0*1024*1024; printf "%.0f\n", v; exit }
        /[Kk]/ { gsub(/[^0-9.]/,""); v=$0*1024; printf "%.0f\n", v; exit }
        { gsub(/[^0-9]/,""); print ($0=="" ? 0 : $0); exit }
    '
}

# _sev_emoji SEV — map 1..4 to display prefix (emoji + level)
_sev_emoji() {
    case "${1:-0}" in
        4) echo "🔥 CRITICAL" ;;
        3) echo "🔴 HEAVY" ;;
        2) echo "🟠 FLOOD" ;;
        1) echo "🟡 Suspicious" ;;
        *) echo "ℹ️ Normal" ;;
    esac
}

# emit_item_tsv TYPE SEV LEVEL DEDUP_KEY SRC DST PREFIX PROTO DPORT FLOWS PKTS BYTES
#               DUR_MS UNIQ_DST UNIQ_SRC MICRO FLAGS_NOTE MODE_NOTE AS_NUM AS_NAME EXTRA
# Empty = pass empty string. Prints one TSV line to stdout.
emit_item_tsv() {
    printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
        "${1:-}" "${2:-}" "${3:-}" "${4:-}" "${5:-}" "${6:-}" "${7:-}" "${8:-}" "${9:-}" \
        "${10:-}" "${11:-}" "${12:-}" "${13:-}" "${14:-}" "${15:-}" "${16:-}" "${17:-}" "${18:-}" \
        "${19:-}" "${20:-}" "${21:-}"
}

# render_item_html LINE
# LINE = one TSV row (21 columns). Outputs one HTML line for Telegram body.
# Depends: html_escape (from telegram.sh). AS_NAME must be safe (we re-escape if needed).
render_item_html() {
    local line="$1"
    local type sev level dedup_key src dst prefix proto dport flows pkts bytes
    local dur_ms uniq_dst uniq_src micro flags_note mode_note as_num as_name extra
    IFS=$'\t' read -r type sev level dedup_key src dst prefix proto dport flows pkts bytes \
        dur_ms uniq_dst uniq_src micro flags_note mode_note as_num as_name extra <<< "$line"
    local emoji
    emoji=$(_sev_emoji "$sev")
    as_name=$(html_escape "${as_name}")

    case "$type" in
        FLOOD)
            echo "${emoji} <b>${src}</b> → <b>${dst}</b>  flows=<b>${flows}</b>  pkts=${pkts}  bytes=${bytes}  ${as_num} ${as_name}"
            ;;
        PROP)
            local flags_display="${flags_note:+ <i>${flags_note}</i>}"
            [[ -z "$flags_note" ]] && flags_display=" <i>no-SYN (degraded)</i>"
            echo "${emoji} <b>${src}</b>  uniq_dst=<b>${uniq_dst}</b>  flows=${flows}  pkts=${pkts}${flags_display}"
            ;;
        RPROXY)
            local max_pkts="${extra#*max_pkts=}"; max_pkts="${max_pkts%%;*}"
            [[ -z "$max_pkts" ]] && max_pkts="10"
            local max_dur="${extra#*max_dur=}"; max_dur="${max_dur%%;*}"
            [[ -z "$max_dur" ]] && max_dur="2"
            echo "${emoji} <b>${src}</b>  micro_flows=<b>${micro}</b>  uniq_dst=${uniq_dst:-"-"}  dur≤${max_dur}s pkts≤${max_pkts}  <i>${mode_note:-no-dur} (degraded)</i>"
            ;;
        STAGE)
            local key_display="$dst"
            [[ -n "$prefix" ]] && key_display="$prefix"
            if [[ -n "$as_num" && "$as_num" != "0" ]]; then
                echo "${emoji} <b>${key_display}</b>  uniq_src=<b>${uniq_src}</b>  pkts=${pkts}  bytes=${bytes}  ${as_num} ${as_name}"
            else
                echo "${emoji} <b>${key_display}</b>  uniq_src=<b>${uniq_src}</b>  pkts=${pkts}  bytes=${bytes}"
            fi
            ;;
        *)
            echo "${emoji} ${type} <b>${src:-$dst}</b> flows=${flows} pkts=${pkts} bytes=${bytes}"
            ;;
    esac
}

# item_sort_keys TYPE — print sort options for sort -t$'\t' (SEV desc, then primary metric per TYPE)
# Columns: 2=SEV, 10=FLOWS, 11=PKTS, 12=BYTES, 14=UNIQ_DST, 15=UNIQ_SRC, 16=MICRO
item_sort_keys() {
    case "$1" in
        FLOOD)  echo "-k2,2nr -k10,10nr -k12,12nr -k11,11nr" ;;
        PROP)   echo "-k2,2nr -k14,14nr -k10,10nr -k11,11nr" ;;
        RPROXY) echo "-k2,2nr -k16,16nr -k14,14nr" ;;
        STAGE)  echo "-k2,2nr -k15,15nr -k11,11nr -k12,12nr" ;;
        *)      echo "-k2,2nr -k10,10nr" ;;
    esac
}
