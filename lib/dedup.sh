#!/usr/bin/env bash
# lib/dedup.sh — alert deduplication using state directory
#
# Old behavior: dedup by SRC->DST pair within ALERT_DEDUP_TTL.
# New behavior: generic dedup by arbitrary KEY with per-signal TTL.
# State files: $STATE_DIR/<key>.last

# dedup_key KEY
# Makes a filesystem-safe key.
dedup_key() {
    local key="${1:?}"
    # Replace separators and characters common in IPs/ports/prefixes.
    key="${key//[\/:. -]/_}"
    key="${key//[^a-zA-Z0-9_]/_}"
    echo "$key"
}

# dedup_check_key KEY TTL
# Returns 0 = можно слать (allow), 1 = подавить (suppress).
# TTL in seconds; per-type TTL from config (ALERT_DEDUP_TTL_*).
dedup_check_key() {
    local raw_key="${1:?}" ttl="${2:?}"
    local key; key=$(dedup_key "$raw_key")
    local state_file="${STATE_DIR}/${key}.last" now
    now=$(date +%s)

    if [[ -f "$state_file" ]]; then
        local last_ts age
        last_ts=$(cat "$state_file" 2>/dev/null || echo 0)
        age=$(( now - last_ts ))
        if (( age < ttl )); then
            log_debug "Suppressing duplicate alert key=${raw_key} (age=${age}s ttl=${ttl}s)"
            return 1
        fi
    fi
    return 0
}

# dedup_record_key KEY
dedup_record_key() {
    local raw_key="${1:?}"
    local key; key=$(dedup_key "$raw_key")
    [[ -d "$STATE_DIR" ]] || mkdir -p "$STATE_DIR"
    date +%s > "${STATE_DIR}/${key}.last"
}

# Backward-compatible helpers (SRC->DST pair)

# dedup_check SRC DST — backward compat: return 0 = allow, 1 = suppress (same as dedup_check_key)
dedup_check() {
    local ttl="${ALERT_DEDUP_TTL_PAIR:-${ALERT_DEDUP_TTL:-300}}"
    dedup_check_key "PAIR:${1:?}->${2:?}" "$ttl"
}

# dedup_record SRC DST
dedup_record() {
    dedup_record_key "PAIR:${1:?}->${2:?}"
}

# dedup_cleanup — remove state files older than max_dedup_ttl * 10 (minutes)
dedup_cleanup() {
    [[ -d "${STATE_DIR:-}" ]] || return 0

    # Pick the largest TTL among known settings to avoid premature cleanup.
    local max_ttl="${ALERT_DEDUP_TTL:-300}"
    [[ -n "${ALERT_DEDUP_TTL_PAIR:-}" ]] && [[ "${ALERT_DEDUP_TTL_PAIR}" -gt "$max_ttl" ]] && max_ttl="$ALERT_DEDUP_TTL_PAIR"
    [[ -n "${ALERT_DEDUP_TTL_ADBSCAN:-}" ]] && [[ "${ALERT_DEDUP_TTL_ADBSCAN}" -gt "$max_ttl" ]] && max_ttl="$ALERT_DEDUP_TTL_ADBSCAN"
    [[ -n "${ALERT_DEDUP_TTL_PROXY:-}" ]] && [[ "${ALERT_DEDUP_TTL_PROXY}" -gt "$max_ttl" ]] && max_ttl="$ALERT_DEDUP_TTL_PROXY"
    [[ -n "${ALERT_DEDUP_TTL_STAGING:-}" ]] && [[ "${ALERT_DEDUP_TTL_STAGING}" -gt "$max_ttl" ]] && max_ttl="$ALERT_DEDUP_TTL_STAGING"
    [[ -n "${ALERT_DEDUP_TTL_NATBURST:-}" ]] && [[ "${ALERT_DEDUP_TTL_NATBURST}" -gt "$max_ttl" ]] && max_ttl="$ALERT_DEDUP_TTL_NATBURST"

    local mmin=$(( (max_ttl * 10) / 60 ))
    [[ $mmin -lt 1 ]] && mmin=1
    find "$STATE_DIR" -name '*.last' -mmin "+$mmin" -delete 2>/dev/null || true
}
