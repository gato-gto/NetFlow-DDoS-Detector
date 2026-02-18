#!/usr/bin/env bash
# lib/log.sh — structured logging helpers
# Usage: source lib/log.sh

# Call log_init before using other log functions.
# LOG_FILE must be set (from config).
log_init() {
    local log_dir
    log_dir="$(dirname "${LOG_FILE}")"
    if [[ ! -d "$log_dir" ]]; then
        mkdir -p "$log_dir" || { echo "ERROR: cannot create log dir $log_dir" >&2; exit 1; }
    fi
}

_log() {
    local level="$1" ts; shift
    ts=$(date '+%Y-%m-%d %H:%M:%S')
    local msg="[${ts}] [${level}] $*"
    echo "$msg"
    [[ -n "${LOG_FILE:-}" ]] && echo "$msg" >> "$LOG_FILE"
}

log_info()  { _log "INFO " "$@"; }
log_warn()  { _log "WARN " "$@"; }
log_error() { _log "ERROR" "$@"; }
log_debug() { [[ "${DEBUG:-0}" == "1" ]] && _log "DEBUG" "$@" || true; }
