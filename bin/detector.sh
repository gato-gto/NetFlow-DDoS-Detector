#!/usr/bin/env bash
# bin/detector.sh — NetFlow DDoS Detector (NFDD)
# Usage: ./bin/detector.sh [--config /path/to/detector.conf] [--dry-run]
#
# Architecture:
#   bin/detector.sh          — orchestrator (this file)
#   lib/log.sh               — structured logging
#   lib/telegram.sh          — Telegram delivery
#   lib/as_lookup.sh         — AS info with TTL cache
#   lib/dedup.sh             — alert deduplication
#   lib/nfdump_analysis.sh   — nfdump invocation & parsing
#   lib/classify.sh          — flow severity classification
#   etc/detector.conf        — configuration (never commit secrets)

set -euo pipefail

# ── Resolve script directory ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Parse CLI arguments ───────────────────────────────────────────────────────
CONFIG_FILE="${SCRIPT_DIR}/etc/detector.conf"
DRY_RUN=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --config)  CONFIG_FILE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1;         shift   ;;
        --debug)   export DEBUG=1;    shift   ;;
        -h|--help)
            echo "Usage: $0 [--config FILE] [--dry-run] [--debug]"
            exit 0
            ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
    esac
done

# ── Load config ───────────────────────────────────────────────────────────────
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "ERROR: config not found: $CONFIG_FILE" >&2
    exit 1
fi
# shellcheck source=/dev/null
source "$CONFIG_FILE"

# Defaults for vNext: only flood pairs enabled if not set (backward compatible)
ENABLE_DETECT_FLOOD_PAIRS="${ENABLE_DETECT_FLOOD_PAIRS:-1}"
ENABLE_DETECT_ADB_SCAN="${ENABLE_DETECT_ADB_SCAN:-0}"
ENABLE_DETECT_PROXY_MICROFLOWS="${ENABLE_DETECT_PROXY_MICROFLOWS:-0}"
ENABLE_DETECT_UDP_STAGING="${ENABLE_DETECT_UDP_STAGING:-0}"
ENABLE_DETECT_NAT_BURST="${ENABLE_DETECT_NAT_BURST:-0}"

# ── Load libraries ────────────────────────────────────────────────────────────
source "${SCRIPT_DIR}/lib/log.sh"
source "${SCRIPT_DIR}/lib/telegram.sh"
source "${SCRIPT_DIR}/lib/as_lookup.sh"
source "${SCRIPT_DIR}/lib/dedup.sh"
source "${SCRIPT_DIR}/lib/nfdump_analysis.sh"
source "${SCRIPT_DIR}/lib/classify.sh"
source "${SCRIPT_DIR}/lib/classify_ext.sh"
source "${SCRIPT_DIR}/lib/alert_items.sh"
[[ -f "${SCRIPT_DIR}/lib/detectors/nat_burst.sh" ]] && source "${SCRIPT_DIR}/lib/detectors/nat_burst.sh"

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in nfdump curl jq whois; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    (( ${#missing[@]} > 0 )) && { log_error "Missing required tools: ${missing[*]}"; exit 1; }
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log_init
    log_info "=== NetFlow DDoS Detector (NFDD) started (dry_run=${DRY_RUN}) ==="
    check_deps

    local traffic_scope
    traffic_scope=$(build_traffic_scope)
    [[ -n "${THREAT_SRC_NETS:-}" ]] && log_debug "Config: BIDIRECTIONAL mode (outbound + inbound from threat IPs)"
    log_debug "Config: NFSEN_BASE=$NFSEN_BASE"
    log_debug "Config: NFDUMP_FILTER=$NFDUMP_FILTER"
    log_debug "Config: TRAFFIC_SCOPE=$traffic_scope"
    log_debug "Config: NFDUMP_TOP_N=$NFDUMP_TOP_N NFDUMP_TOP_SORT=${NFDUMP_TOP_SORT:-record/flows} THRESHOLD_SUSPICIOUS=$THRESHOLD_SUSPICIOUS"

    # 1. Find capture file
    local last_file
    if [[ "${WAIT_FOR_PREVIOUS_INTERVAL:-0}" == "1" ]]; then
        local prev_ts expected_file
        prev_ts=$(nfdump_expected_previous_minute)
        expected_file="nfcapd.${prev_ts}"
        log_info "Waiting for previous interval file: $expected_file (retry every ${WAIT_RETRY_SEC:-10}s, up to ${WAIT_RETRY_COUNT:-6} times)"
        local retries=0
        local max_retries="${WAIT_RETRY_COUNT:-6}"
        local retry_sec="${WAIT_RETRY_SEC:-10}"
        while true; do
            last_file=$(nfdump_find_file_for_interval "$NFSEN_BASE" "$prev_ts")
            if [[ -n "$last_file" ]]; then
                log_info "Found file for previous minute: $last_file"
                break
            fi
            (( retries++ )) || true
            if (( retries >= max_retries )); then
                log_error "File for previous interval ($expected_file) not found after ${max_retries} retries"
                send_telegram "⚠️ NFDD — ERROR" "Файл за предыдущую минуту (${expected_file}) не найден в ${NFSEN_BASE}"
                exit 1
            fi
            log_info "  Retry $retries/$max_retries: waiting ${retry_sec}s..."
            sleep "$retry_sec"
        done
    else
        last_file=$(nfdump_find_last_file "$NFSEN_BASE")
    fi

    if [[ "${DEBUG:-0}" == "1" ]]; then
        local list count
        list=$(find "$NFSEN_BASE" -mindepth 1 -maxdepth 4 -type f -name 'nfcapd.20*' 2>/dev/null | sort -u)
        count=$([[ -n "$list" ]] && wc -l <<< "$list" || echo 0)
        log_debug "Candidate nfcapd files: $count"
        while IFS= read -r line; do [[ -n "$line" ]] && log_debug "  $line"; done <<< "$list"
    fi

    if [[ -z "$last_file" ]]; then
        log_error "No nfcapd files found under $NFSEN_BASE"
        send_telegram "⚠️ NFDD — ERROR" "Нет nfcapd файлов в ${NFSEN_BASE}"
        exit 1
    fi
    log_info "Using file: $last_file"

    local file_size
    file_size=$(stat -c '%s' "$last_file" 2>/dev/null || stat -f '%z' "$last_file" 2>/dev/null || echo "?")
    log_debug "File size: $file_size bytes ($(numfmt --to=iec "$file_size" 2>/dev/null || echo "${file_size} B"))"

    # 2. Parse interval metadata
    read -r interval_date interval_hour interval_min \
        <<< "$(nfdump_parse_interval "$last_file")"
    log_info "Interval: ${interval_date} ${interval_hour}:${interval_min}"

    # 3. Cleanup stale dedup state (once per run)
    dedup_cleanup

    # Delivery: canonical TSV ITEMS_V1 (21 cols). Phase 1: collect items; Phase 2: dedup; Phase 3: render.
    local flood_items="" prop_items="" rproxy_items="" stage_items="" nat_items=""
    local flood_found=0 prop_found=0 rproxy_found=0 stage_found=0 nat_found=0
    local ttl_pair="${ALERT_DEDUP_TTL_PAIR:-${ALERT_DEDUP_TTL:-300}}"
    local ttl_prop="${ALERT_DEDUP_TTL_ADBSCAN:-1800}"
    local ttl_rproxy="${ALERT_DEDUP_TTL_PROXY:-${ALERT_DEDUP_TTL:-300}}"
    local ttl_stage="${ALERT_DEDUP_TTL_STAGING:-300}"
    local ttl_nat="${ALERT_DEDUP_TTL_NATBURST:-600}"
    local stderr_tmp
    [[ "${DEBUG:-0}" == "1" ]] && { stderr_tmp=$(mktemp); export NFDUMP_DEBUG_STDERR="$stderr_tmp"; }

    # ─── Phase 1: emit canonical TSV items (no dedup yet) ─────────────────────

    # FLOOD
    if [[ "${ENABLE_DETECT_FLOOD_PAIRS}" == "1" ]]; then
        log_info "Running nfdump analysis (flood pairs)..."
        local results
        results=$(nfdump_run_analysis "$last_file" "$NFDUMP_FILTER" "$traffic_scope" \
            "$NFDUMP_TOP_N" "$THRESHOLD_SUSPICIOUS" "${NFDUMP_TOP_SORT:-record/flows}") || {
            [[ -n "${stderr_tmp:-}" && -f "${stderr_tmp:-}" ]] && log_debug "nfdump stderr: $(cat "$stderr_tmp")"
            rm -f "${stderr_tmp:-}"; log_error "nfdump exited with error"; exit 1
        }
        while IFS=$'\t' read -r src dst flows pkts bytes; do
            [[ -z "$src" ]] && continue
            local bytes_num level_name sev as_info as_num as_name
            bytes_num=$(normalize_bytes "$bytes")
            level_name=$(classify_level_name "$flows")
            sev=$(classify_order "$flows")
            as_info=$(as_lookup "$dst" 2>/dev/null || true)
            as_num="${as_info%% *}"
            as_name="${as_info#* }"
            flood_items+="$(emit_item_tsv "FLOOD" "$sev" "$level_name" "FLOOD__${src}__${dst}" "$src" "$dst" "" "UDP" "" "$flows" "$pkts" "$bytes_num" "" "" "" "" "" "" "$as_num" "$as_name" "")"$'\n'
            (( flood_found++ )) || true
        done <<< "$results"
        log_info "FLOOD: found=$flood_found"
    fi

    # PROP (ADB)
    if [[ "${ENABLE_DETECT_ADB_SCAN:-0}" == "1" ]]; then
        log_info "ADB scan: port=${ADB_SCAN_PORT:-5555} uniq_dst_thr=${ADB_SCAN_UNIQUE_DST_PER_MIN:-50}"
        local results_adb
        results_adb=$(nfdump_detect_adb_scan "$last_file" "$traffic_scope") || { log_warn "ADB scan failed"; results_adb=""; }
        while IFS=$'\t' read -r src unique_dst total_flows pkts bytes; do
            [[ -z "$src" ]] && continue
            local level_name sev
            level_name=$(classify_level_name "${total_flows:-0}")
            sev=$(classify_order "${total_flows:-0}")
            prop_items+="$(emit_item_tsv "PROP" "$sev" "$level_name" "PROP__${src}" "$src" "" "" "TCP" "5555" "$total_flows" "$pkts" "$(normalize_bytes "$bytes")" "" "$unique_dst" "" "" "no-SYN" "" "" "" "adb_port=5555")"$'\n'
            (( prop_found++ )) || true
        done <<< "$results_adb"
        log_info "PROP: found=$prop_found"
    fi

    # RPROXY
    if [[ "${ENABLE_DETECT_PROXY_MICROFLOWS}" == "1" ]]; then
        log_info "RPROXY: ports ${PROXY_PORTS:-80 443 8080}"
        local results_proxy
        results_proxy=$(run_proxy_analysis "$last_file" "$traffic_scope") || { log_warn "Proxy analysis failed"; results_proxy=""; }
        local max_dur="${PROXY_MAX_DURATION_SEC:-2}" max_pkts="${PROXY_MAX_PKTS_PER_FLOW:-10}"
        while IFS=$'\t' read -r src short_flows total_flows short_ratio pkts bytes; do
            [[ -z "$src" ]] && continue
            local level_name sev
            level_name=$(classify_level_name "${total_flows:-0}")
            sev=$(classify_order "${total_flows:-0}")
            rproxy_items+="$(emit_item_tsv "RPROXY" "$sev" "$level_name" "RPROXY__${src}" "$src" "" "" "TCP" "" "$total_flows" "$pkts" "$(normalize_bytes "$bytes")" "" "" "" "$short_flows" "" "no-dur" "" "" "max_dur=${max_dur};max_pkts=${max_pkts}")"$'\n'
            (( rproxy_found++ )) || true
        done <<< "$results_proxy"
        log_info "RPROXY: found=$rproxy_found"
    fi

    # STAGE (dstip)
    if [[ "${ENABLE_DETECT_UDP_STAGING:-0}" == "1" ]]; then
        log_info "STAGE: min_src=${STAGING_MIN_UNIQUE_SRC:-30} min_flows=${STAGING_MIN_TOTAL_FLOWS:-50000}"
        local results_staging
        results_staging=$(nfdump_detect_udp_staging "$last_file" "$traffic_scope") || { log_warn "Staging failed"; results_staging=""; }
        while IFS=$'\t' read -r dst unique_src total_flows pkts bytes avg_pkt; do
            [[ -z "$dst" ]] && continue
            local level_name sev as_info as_num as_name
            level_name=$(classify_level_name "${total_flows:-0}")
            sev=$(classify_order "${total_flows:-0}")
            as_info=$(as_lookup "$dst" 2>/dev/null || true)
            as_num="${as_info%% *}"
            as_name="${as_info#* }"
            stage_items+="$(emit_item_tsv "STAGE" "$sev" "$level_name" "STAGE__${dst}" "" "$dst" "" "UDP" "" "$total_flows" "$pkts" "$(normalize_bytes "$bytes")" "" "" "$unique_src" "" "" "dstip" "$as_num" "$as_name" "")"$'\n'
            (( stage_found++ )) || true
        done <<< "$results_staging"
        log_info "STAGE: found=$stage_found"
    fi

    # NAT BURST (legacy format, not ITEMS_V1)
    local nat_sent=0 nat_supp=0
    local nat_found=0
    if [[ "${ENABLE_DETECT_NAT_BURST:-0}" == "1" ]] && [[ -f "${SCRIPT_DIR}/lib/detectors/nat_burst.sh" ]]; then
        log_info "NAT BURST: thr_create=${NAT_BURST_CREATE_THR:-2000} thr_total=${NAT_BURST_TOTAL_THR:-3000}"
        local results_nat
        results_nat=$(nat_burst_run "$last_file" "$traffic_scope") || { log_warn "NAT BURST failed"; results_nat=""; }
        while IFS=$'\t' read -r src create del total imb; do
            [[ -z "$src" ]] && continue
            local level order
            level=$(classify_flow "${total:-0}")
            order=$(classify_order "${total:-0}")
            if dedup_check_key "NATBURST__${src}" "$ttl_nat"; then
                dedup_record_key "NATBURST__${src}"
                nat_items+="${order}\t${total}\t${level} NATBURST <b>${src}</b> create=${create} delete=${del} total=${total} ratio=${imb}"$'\n'
                (( nat_sent++ )) || true
            else
                (( nat_supp++ )) || true
            fi
        done <<< "$results_nat"
        (( nat_found = nat_sent + nat_supp )) || true
        log_info "NAT: found=$nat_found sent=$nat_sent suppressed=$nat_supp"
    fi

    # ─── Phase 2: dedup by DEDUP_KEY, build sent_*_items ─────────────────────
    local flood_sent=0 flood_supp=0 flood_sent_items=""
    local prop_sent=0 prop_supp=0 prop_sent_items=""
    local rproxy_sent=0 rproxy_supp=0 rproxy_sent_items=""
    local stage_sent=0 stage_supp=0 stage_sent_items=""
    local line dedup_key

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        dedup_key=$(echo "$line" | cut -f4)
        if dedup_check_key "$dedup_key" "$ttl_pair"; then
            dedup_record_key "$dedup_key"
            flood_sent_items+="${line}"$'\n'
            (( flood_sent++ )) || true
        else
            (( flood_supp++ )) || true
        fi
    done <<< "$flood_items"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        dedup_key=$(echo "$line" | cut -f4)
        if dedup_check_key "$dedup_key" "$ttl_prop"; then
            dedup_record_key "$dedup_key"
            prop_sent_items+="${line}"$'\n'
            (( prop_sent++ )) || true
        else
            (( prop_supp++ )) || true
        fi
    done <<< "$prop_items"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        dedup_key=$(echo "$line" | cut -f4)
        if dedup_check_key "$dedup_key" "$ttl_rproxy"; then
            dedup_record_key "$dedup_key"
            rproxy_sent_items+="${line}"$'\n'
            (( rproxy_sent++ )) || true
        else
            (( rproxy_supp++ )) || true
        fi
    done <<< "$rproxy_items"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        dedup_key=$(echo "$line" | cut -f4)
        if dedup_check_key "$dedup_key" "$ttl_stage"; then
            dedup_record_key "$dedup_key"
            stage_sent_items+="${line}"$'\n'
            (( stage_sent++ )) || true
        else
            (( stage_supp++ )) || true
        fi
    done <<< "$stage_items"

    log_info "FLOOD: sent=$flood_sent suppressed=$flood_supp"
    log_info "PROP: sent=$prop_sent suppressed=$prop_supp"
    log_info "RPROXY: sent=$rproxy_sent suppressed=$rproxy_supp"
    log_info "STAGE: sent=$stage_sent suppressed=$stage_supp"

    if [[ -n "${stderr_tmp:-}" && -f "$stderr_tmp" ]]; then
        [[ -s "$stderr_tmp" ]] && while IFS= read -r line; do log_debug "nfdump stderr: $line"; done < "$stderr_tmp"
        rm -f "$stderr_tmp"
    fi
    unset -v NFDUMP_DEBUG_STDERR 2>/dev/null || true

    local total_sent=$(( flood_sent + prop_sent + rproxy_sent + stage_sent + nat_sent ))
    local total_supp=$(( flood_supp + prop_supp + rproxy_supp + stage_supp + nat_supp ))
    [[ "${DEBUG:-0}" == "1" ]] && log_debug "counts: F found=$flood_found sent=$flood_sent supp=$flood_supp | P found=$prop_found sent=$prop_sent supp=$prop_supp | R found=$rproxy_found sent=$rproxy_sent supp=$rproxy_supp | S found=$stage_found sent=$stage_sent supp=$stage_supp"

    if (( total_sent == 0 )); then
        log_info "All clear (no alerts)"
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "suppressed total=$total_supp (F:$flood_supp P:$prop_supp R:$rproxy_supp S:$stage_supp)"
        exit 0
    fi

    # ─── Build vNext message: subject + body (max items per block, truncation) ─
    local max_flood="${ALERT_MAX_ITEMS_FLOOD:-20}" max_prop="${ALERT_MAX_ITEMS_PROP:-10}"
    local max_rproxy="${ALERT_MAX_ITEMS_RPROXY:-10}" max_stage="${ALERT_MAX_ITEMS_STAGE:-10}"
    local max_chars="${ALERT_MAX_CHARS:-3500}"
    local interval_ts="${interval_date} ${interval_hour}:${interval_min}"
    local nfcapd_name="${last_file##*/}"
    # Subject: sent after dedup and limits (what actually goes in the message)
    local f_disp=$(( flood_sent < max_flood ? flood_sent : max_flood ))
    local p_disp=$(( prop_sent < max_prop ? prop_sent : max_prop ))
    local r_disp=$(( rproxy_sent < max_rproxy ? rproxy_sent : max_rproxy ))
    local s_disp=$(( stage_sent < max_stage ? stage_sent : max_stage ))
    local subject="🚨 NFDD vNext — ${interval_ts} (F:${f_disp} P:${p_disp} R:${r_disp} S:${s_disp})"
    [[ "${nat_sent:-0}" -gt 0 ]] && subject="🚨 NFDD vNext — ${interval_ts} (F:${f_disp} P:${p_disp} R:${r_disp} S:${s_disp} N:${nat_sent})"

    # 0) Шапка сводки
    local body=""
    body+="<b>NFDD vNext</b>"$'\n'
    body+="🕒 Interval: <b>${interval_ts}</b>"$'\n'
    body+="📦 File: <code>${nfcapd_name}</code>"$'\n'$'\n'
    body+="📊 Sent: <b>${total_sent}</b> | Suppressed: <b>${total_supp}</b>"$'\n'
    body+="• FLOOD: ${flood_sent}/${flood_supp}"$'\n'
    body+="• PROP: ${prop_sent}/${prop_supp}"$'\n'
    body+="• RPROXY: ${rproxy_sent}/${rproxy_supp}"$'\n'
    body+="• STAGE: ${stage_sent}/${stage_supp}"
    [[ "${nat_sent:-0}" -gt 0 ]] && body+=$'\n'"• NAT: ${nat_sent}/${nat_supp}"
    body+=$'\n\n'

    local truncated_by_limits=0

    # 1) FLOOD — sort by SEV, FLOWS, PKTS; render from canonical TSV
    if [[ -n "$flood_sent_items" ]] && (( flood_sent > 0 )); then
        local flood_sorted flood_more
        flood_sorted=$(echo -n "$flood_sent_items" | sort -t $'\t' $(item_sort_keys "FLOOD"))
        flood_more=$(( flood_sent - max_flood ))
        body+="<b>🟠 FLOOD (SRC→DST)</b>"$'\n'
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            body+="$(render_item_html "$line")"$'\n'
        done <<< "$(echo -n "$flood_sorted" | head -n "$max_flood")"
        (( flood_more > 0 )) && { body+="<i>… +${flood_more} more</i>"$'\n'; truncated_by_limits=1; }
        body+=$'\n'
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "FLOOD: shown=$(( flood_sent < max_flood ? flood_sent : max_flood )) trimmed=$(( flood_more > 0 ? flood_more : 0 ))"
    fi

    # 2) PROP
    if [[ -n "$prop_sent_items" ]] && (( prop_sent > 0 )); then
        local prop_sorted prop_more
        prop_sorted=$(echo -n "$prop_sent_items" | sort -t $'\t' $(item_sort_keys "PROP"))
        prop_more=$(( prop_sent - max_prop ))
        body+="<b>🛰️ PROPAGATION (ADB TCP/5555)</b>"$'\n'
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            body+="$(render_item_html "$line")"$'\n'
        done <<< "$(echo -n "$prop_sorted" | head -n "$max_prop")"
        (( prop_more > 0 )) && { body+="<i>… +${prop_more} more</i>"$'\n'; truncated_by_limits=1; }
        body+=$'\n'
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "PROP: shown=$(( prop_sent < max_prop ? prop_sent : max_prop )) trimmed=$(( prop_more > 0 ? prop_more : 0 ))"
    fi

    # 3) RPROXY
    if [[ -n "$rproxy_sent_items" ]] && (( rproxy_sent > 0 )); then
        local rproxy_sorted rproxy_more
        rproxy_sorted=$(echo -n "$rproxy_sent_items" | sort -t $'\t' $(item_sort_keys "RPROXY"))
        rproxy_more=$(( rproxy_sent - max_rproxy ))
        body+="<b>🧩 RPROXY (micro-HTTPS)</b>"$'\n'
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            body+="$(render_item_html "$line")"$'\n'
        done <<< "$(echo -n "$rproxy_sorted" | head -n "$max_rproxy")"
        (( rproxy_more > 0 )) && { body+="<i>… +${rproxy_more} more</i>"$'\n'; truncated_by_limits=1; }
        body+=$'\n'
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "RPROXY: shown=$(( rproxy_sent < max_rproxy ? rproxy_sent : max_rproxy )) trimmed=$(( rproxy_more > 0 ? rproxy_more : 0 ))"
    fi

    # 4) STAGE
    if [[ -n "$stage_sent_items" ]] && (( stage_sent > 0 )); then
        local stage_sorted stage_more
        stage_sorted=$(echo -n "$stage_sent_items" | sort -t $'\t' $(item_sort_keys "STAGE"))
        stage_more=$(( stage_sent - max_stage ))
        body+="<b>🧨 STAGING (many→one UDP)</b>"$'\n'
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            body+="$(render_item_html "$line")"$'\n'
        done <<< "$(echo -n "$stage_sorted" | head -n "$max_stage")"
        (( stage_more > 0 )) && { body+="<i>… +${stage_more} more</i>"$'\n'; truncated_by_limits=1; }
        body+=$'\n'
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "STAGE: shown=$(( stage_sent < max_stage ? stage_sent : max_stage )) trimmed=$(( stage_more > 0 ? stage_more : 0 ))"
    fi

    if [[ -n "$nat_items" ]] && (( nat_sent > 0 )); then
        local nat_sorted nat_show
        nat_sorted=$(echo -n "$nat_items" | sort -t $'\t' -k1 -nr -k2 -nr)
        nat_show=$(echo -n "$nat_sorted" | cut -f3-)
        body+="<b>[NAT BURST]</b>"$'\n'"${nat_show}"$'\n\n'
    fi

    # Truncate body if over limit; 5) футер при урезании
    local body_len=${#body}
    if (( body_len > max_chars )); then
        body="${body:0:$(( max_chars - 50 ))}"$'\n'"<i>…(truncated)</i>"$'\n'
        truncated_by_limits=1
        [[ "${DEBUG:-0}" == "1" ]] && log_debug "Body truncated from ${body_len} to ${max_chars} chars"
    fi
    if (( truncated_by_limits )); then
        body+="<i>Note: output truncated by limits (max-items / max-chars).</i>"
    fi
    [[ "${DEBUG:-0}" == "1" ]] && log_debug "final body length=${#body} chars | truncated_by_limits=$truncated_by_limits"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "[DRY-RUN] Would send Telegram:"
        log_info "  Subject: ${subject}"
        log_info "  Body:"
        echo "$body"
        log_info "=== Detector finished (dry-run) ==="
        exit 0
    fi

    log_info "Sending Telegram alert (sent=${total_sent} suppressed=${total_supp})..."
    if ! send_telegram "$subject" "$body"; then
        log_error "Telegram delivery failed — exit 2"
        exit 2
    fi
    log_info "=== Detector finished ==="
}

main "$@"
