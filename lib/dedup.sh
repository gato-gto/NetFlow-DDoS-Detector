#!/usr/bin/env bash
# lib/dedup.sh — alert deduplication using state directory
# Prevents the same SRC->DST pair from firing alerts repeatedly.
# State files: $STATE_DIR/<src>_<dst>.last

# dedup_check SRC DST
# Returns 0 (suppress) or 1 (allow alert).
dedup_check() {
    local src="$1" dst="$2"
    local key
    key="${src}__${dst}"
    # Replace dots/colons to make safe filenames
    key="${key//[.:]/_}"
    local state_file="${STATE_DIR}/${key}.last"

    local now
    now=$(date +%s)

    if [[ -f "$state_file" ]]; then
        local last_ts
        last_ts=$(cat "$state_file")
        local age=$(( now - last_ts ))
        if (( age < ALERT_DEDUP_TTL )); then
            log_debug "Suppressing duplicate alert ${src}->${dst} (age=${age}s)"
            return 0  # suppress
        fi
    fi
    return 1  # allow
}

# dedup_record SRC DST
dedup_record() {
    local src="$1" dst="$2"
    local key
    key="${src}__${dst}"
    key="${key//[.:]/_}"
    [[ -d "$STATE_DIR" ]] || mkdir -p "$STATE_DIR"
    date +%s > "${STATE_DIR}/${key}.last"
}

# dedup_cleanup — remove state files older than ALERT_DEDUP_TTL * 10
dedup_cleanup() {
    [[ -d "$STATE_DIR" ]] || return 0
    find "$STATE_DIR" -name '*.last' -mmin "+$(( ALERT_DEDUP_TTL * 10 / 60 ))" -delete 2>/dev/null || true
}
