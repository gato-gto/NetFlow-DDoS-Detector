#!/usr/bin/env bash
# lib/as_lookup.sh — AS lookup with TTL-aware file cache
# Depends: log.sh
# Cache format (TSV): IP <TAB> TIMESTAMP <TAB> ASN <TAB> ASNAME

# as_lookup IP — prints "ASN ASNAME"
as_lookup() {
    local ip="$1" now=$(date +%s)

    if [[ -f "${AS_CACHE_FILE:-}" ]]; then
        local cached
        cached=$(grep -m1 $'^'"${ip}"$'\t' "$AS_CACHE_FILE" 2>/dev/null || true)
        if [[ -n "$cached" ]]; then
            local ts age
            ts=$(echo "$cached" | cut -f2)
            age=$(( now - ts ))
            if (( age < AS_CACHE_TTL )); then
                echo "$cached" | cut -f3,4 | tr '\t' ' '
                return 0
            fi
            log_debug "AS cache expired for $ip (age=${age}s)"
            local t
            t=$(mktemp) && grep -v $'^'"${ip}"$'\t' "$AS_CACHE_FILE" > "$t" && mv "$t" "$AS_CACHE_FILE"
        fi
    fi

    local raw result asn asname
    raw=$(whois -h whois.cymru.com " -v ${ip}" 2>/dev/null) || true
    result=$(echo "$raw" | awk -F'|' 'NR==2{
        gsub(/^ +| +$/,"",$1); gsub(/^ +| +$/,"",$7);
        print ($1==""?"AS-?":$1) " " ($7==""?"UNKNOWN":$7)
    }')
    asn="${result%% *}"; asname="${result#* }"

    mkdir -p "$(dirname "$AS_CACHE_FILE")"
    printf '%s\t%s\t%s\t%s\n' "$ip" "$now" "$asn" "$asname" >> "$AS_CACHE_FILE"
    echo "${asn} ${asname}"
}
