#!/usr/bin/env bash
# lib/telegram.sh — Telegram Bot API helper
# Depends on: log.sh, jq, curl

# html_escape STRING
# Escapes < > & for safe insertion into Telegram HTML (parse_mode=HTML).
# Use for AS names and any user-supplied text; IPs/numbers can be passed as-is.
html_escape() {
    local s="$1"
    s="${s//&/&amp;}"
    s="${s//</&lt;}"
    s="${s//>/&gt;}"
    echo "$s"
}

# send_telegram SUBJECT BODY
# Returns 0 on success, 1 on failure. Caller should exit 2 on failure if needed.
send_telegram() {
    local subject="$1"
    local body="$2"

    # Combine subject + body; Telegram text is plain UTF-8
    local text="${subject}"$'\n'"${body}"

    # Build JSON safely with jq — avoids injection through special characters
    # message_thread_id — optional, for topics in supergroups
    local payload
    payload=$(jq -cn \
        --arg chat_id "${TELEGRAM_CHAT_ID}" \
        --arg text    "${text}" \
        --arg thread_id "${TELEGRAM_CHAT_THREAD_ID:-}" \
        '{chat_id: $chat_id, text: $text, parse_mode: "HTML"} | if $thread_id != "" then . + {message_thread_id: ($thread_id | tonumber)} else . end')

    local http_code
    http_code=$(curl -s -o /dev/null -w "%{http_code}" \
        --max-time 10 \
        --retry 3 \
        --retry-delay 2 \
        -H 'Content-Type: application/json' \
        -X POST \
        -d "$payload" \
        "${TELEGRAM_API_URL:-https://api.telegram.org}/bot${TELEGRAM_TOKEN}/sendMessage")

    if [[ "$http_code" != "200" ]]; then
        log_error "Telegram delivery failed (HTTP ${http_code})"
        return 1
    fi
    log_info "Telegram alert sent (HTTP ${http_code})"
}
