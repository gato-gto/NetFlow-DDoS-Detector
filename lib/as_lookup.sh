#!/usr/bin/env bash
# lib/as_lookup.sh — AS lookup with TTL-aware file cache
# Depends on: log.sh
# Cache format (TSV): IP <TAB> TIMESTAMP <TAB> ASN <TAB> ASNAME

# as_lookup IP
# Prints: "ASN ASNAME"
as_lookup() {
    local ip="$1"
    local now
    now=$(date +%s)

    # --- Check cache ---
    if [[ -f "$AS_CACHE_FILE" ]]; then
        local cached
        cached=$(grep -m1 $'^'"${ip}"$'\t' "$AS_CACHE_FILE" 2>/dev/null || true)
        if [[ -n "$cached" ]]; then
            local cached_ts
            cached_ts=$(echo "$cached" | cut -f2)
            local age=$(( now - cached_ts ))
            if (( age < AS_CACHE_TTL )); then
                echo "$cached" | cut -f3,4 | tr '\t' ' '
                return 0
            else
                log_debug "AS cache expired for $ip (age=${age}s)"
                # Remove stale entry
                local tmp
                tmp=$(mktemp)
                grep -v $'^'"${ip}"$'\t' "$AS_CACHE_FILE" > "$tmp" && mv "$tmp" "$AS_CACHE_FILE"
            fi
        fi
    fi

    # --- Whois lookup ---
    local raw
    raw=$(whois -h whois.cymru.com " -v ${ip}" 2>/dev/null) || true

    local asn asname
    asn=$(echo "$raw"   | awk -F'|' 'NR==2{gsub(/^ +| +$/,"",$1); print $1}')
    asname=$(echo "$raw" | awk -F'|' 'NR==2{gsub(/^ +| +$/,"",$7); print $7}')

    [[ -z "$asn"    ]] && asn="AS-?"
    [[ -z "$asname" ]] && asname="UNKNOWN"

    # --- Store in cache ---
    local cache_dir
    cache_dir=$(dirname "$AS_CACHE_FILE")
    [[ -d "$cache_dir" ]] || mkdir -p "$cache_dir"

    printf '%s\t%s\t%s\t%s\n' "$ip" "$now" "$asn" "$asname" >> "$AS_CACHE_FILE"

    echo "${asn} ${asname}"
}
