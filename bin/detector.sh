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

# ── Load libraries ────────────────────────────────────────────────────────────
source "${SCRIPT_DIR}/lib/log.sh"
source "${SCRIPT_DIR}/lib/telegram.sh"
source "${SCRIPT_DIR}/lib/as_lookup.sh"
source "${SCRIPT_DIR}/lib/dedup.sh"
source "${SCRIPT_DIR}/lib/nfdump_analysis.sh"
source "${SCRIPT_DIR}/lib/classify.sh"

# ── Dependency check ──────────────────────────────────────────────────────────
check_deps() {
    local missing=()
    for cmd in nfdump curl jq whois; do
        command -v "$cmd" &>/dev/null || missing+=("$cmd")
    done
    if (( ${#missing[@]} > 0 )); then
        log_error "Missing required tools: ${missing[*]}"
        exit 1
    fi
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    log_init
    log_info "=== NetFlow DDoS Detector (NFDD) started (dry_run=${DRY_RUN}) ==="
    check_deps

    # 1. Find capture file
    local last_file
    last_file=$(nfdump_find_last_file "$NFSEN_BASE")
    if [[ -z "$last_file" ]]; then
        log_error "No nfcapd files found under $NFSEN_BASE"
        send_telegram "⚠️ NFDD — ERROR" "Нет nfcapd файлов в ${NFSEN_BASE}"
        exit 1
    fi
    log_info "Using file: $last_file"

    # 2. Parse interval metadata
    read -r interval_date interval_hour interval_min \
        <<< "$(nfdump_parse_interval "$last_file")"
    log_info "Interval: ${interval_date} ${interval_hour}:${interval_min}"

    # 3. Run nfdump analysis
    log_info "Running nfdump analysis..."
    local results
    results=$(nfdump_run_analysis \
        "$last_file" \
        "$NFDUMP_FILTER" \
        "$INTERNAL_NETS" \
        "$NFDUMP_TOP_N" \
        "$THRESHOLD_SUSPICIOUS") || {
        log_error "nfdump exited with error"
        exit 1
    }

    if [[ -z "$results" ]]; then
        log_info "No suspicious flows found — all clear."
        exit 0
    fi

    log_info "Suspicious flows detected — building alerts..."

    # 4. Cleanup stale dedup state
    dedup_cleanup

    # 5. Process each flow record
    local alert_lines=""
    local alert_count=0

    while IFS=$'\t' read -r src dst flows pkts bytes; do
        local level
        level=$(classify_flow "$flows")

        log_info "${level}  ${src} -> ${dst}  flows=${flows}  pkts=${pkts}  bytes=${bytes}"

        # Deduplication check
        if dedup_check "$src" "$dst"; then
            log_info "  ↳ Suppressed (dedup TTL=${ALERT_DEDUP_TTL}s)"
            continue
        fi

        # AS lookup
        local as_info asn asname
        as_info=$(as_lookup "$dst")
        asn=$(echo "$as_info"   | awk '{print $1}')
        asname=$(echo "$as_info" | cut -d' ' -f2-)

        # Record dedup timestamp
        dedup_record "$src" "$dst"

        # Accumulate message lines (HTML for Telegram)
        alert_lines+="${level}  <b>${src}</b> → <b>${dst}</b>"$'\n'
        alert_lines+="flows=${flows}  pkts=${pkts}  bytes=${bytes}"$'\n'
        alert_lines+="AS: ${asn}  ${asname}"$'\n'$'\n'

        (( alert_count++ )) || true

    done <<< "$results"

    if (( alert_count == 0 )); then
        log_info "All flows suppressed by dedup — no Telegram message sent."
        exit 0
    fi

    # 6. Send Telegram
    local subject="🚨 NFDD — ${interval_date} ${interval_hour}:${interval_min} (${alert_count} alerts)"

    if [[ "$DRY_RUN" == "1" ]]; then
        log_info "[DRY-RUN] Would send Telegram:"
        log_info "  Subject: ${subject}"
        log_info "  Body:"
        echo "$alert_lines"
    else
        log_info "Sending Telegram alert (${alert_count} flows)..."
        send_telegram "$subject" "$alert_lines"
    fi

    log_info "=== Detector finished ==="
}

main "$@"
