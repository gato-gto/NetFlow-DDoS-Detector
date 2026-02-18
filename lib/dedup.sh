#!/usr/bin/env bash
# lib/dedup.sh — alert deduplication using state directory
# Prevents the same SRC->DST pair from firing alerts repeatedly.
# State files: $STATE_DIR/<src>_<dst>.last

# dedup_check SRC DST
# Returns 0 (suppress) or 1 (allow alert).
dedup_check() {
    local key="${1}__${2}"
    key="${key//[.:]/_}"
    local state_file="${STATE_DIR}/${key}.last" now=$(date +%s)

    if [[ -f "$state_file" ]]; then
        local last_ts age
        last_ts=$(cat "$state_file")
        age=$(( now - last_ts ))
        if (( age < ALERT_DEDUP_TTL )); then
            log_debug "Suppressing duplicate alert $1->$2 (age=${age}s)"
            return 0  # suppress
        fi
    fi
    return 1  # allow
}

# dedup_record SRC DST
dedup_record() {
    local key="${1}__${2}"
    key="${key//[.:]/_}"
    [[ -d "$STATE_DIR" ]] || mkdir -p "$STATE_DIR"
    date +%s > "${STATE_DIR}/${key}.last"
}

# dedup_cleanup — remove state files older than ALERT_DEDUP_TTL * 10 (max 525600 min)
dedup_cleanup() {
    [[ -d "${STATE_DIR:-}" ]] || return 0
    local mmin=$(( (ALERT_DEDUP_TTL * 10) / 60 ))
    [[ $mmin -lt 1 ]] && mmin=1
    find "$STATE_DIR" -name '*.last' -mmin "+$mmin" -delete 2>/dev/null || true
}
