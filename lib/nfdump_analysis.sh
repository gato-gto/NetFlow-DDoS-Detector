#!/usr/bin/env bash
# lib/nfdump_analysis.sh — nfdump file discovery and flow parsing

# nfdump_find_last_file BASE_DIR
# Prints path to the newest nfcapd.20* file, or empty string.
# Supports: flat layout (base/nfcapd.20*) and NfSen layout (base/.../YYYY/MM/DD/nfcapd.20*).
nfdump_find_last_file() {
    local base="$1"
    find "$base" -mindepth 1 -maxdepth 4 -type f -name 'nfcapd.20*' \
        | sort | tail -n1
}

# nfdump_parse_interval FILEPATH
# Prints "DATE HOUR MIN" (e.g. "20250615 14 05")
nfdump_parse_interval() {
    local fpath="$1"
    local fname
    fname=$(basename "$fpath")
    local date_part="${fname:7:8}"
    local time_part="${fname:15:4}"
    local hour="${time_part:0:2}"
    local min="${time_part:2:2}"
    echo "${date_part} ${hour} ${min}"
}

# nfdump_run_analysis FILEPATH FILTER NETS TOP_N THRESHOLD [TOP_SORT]
# Prints TSV lines: SRC DST FLOWS PKTS BYTES
# TOP_SORT: record/flows (default), record/packets, record/bytes — order of top-N.
# When NFDUMP_DEBUG_STDERR is set (DEBUG=1), nfdump stderr is written there for logging.
nfdump_run_analysis() {
    local file="$1"
    local filter="$2"
    local nets="$3"
    local top_n="$4"
    local threshold="$5"
    local top_sort="${6:-record/flows}"
    case "$top_sort" in
        record/flows|record/packets|record/bytes) ;;
        *) top_sort="record/flows" ;;
    esac
    local stderr_dest="/dev/null"
    [[ -n "${NFDUMP_DEBUG_STDERR:-}" ]] && stderr_dest="$NFDUMP_DEBUG_STDERR"

    nfdump -r "$file" "${filter} and (${nets})" \
           -A srcip,dstip -s "$top_sort" -n "$top_n" \
        2>"$stderr_dest" \
    | awk -v thr="$threshold" '
        /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
            src = $4
            dst = $5
            flows = $NF

            # Detect M/G/K suffix on packets/bytes columns
            if ($(NF-2) ~ /^[GMK]$/) {
                bytes   = $(NF-3) $(NF-2)
                packets = $(NF-5) $(NF-4)
            } else {
                bytes   = $(NF-2)
                packets = $(NF-3)
            }

            if (flows + 0 > thr + 0) {
                print src "\t" dst "\t" flows "\t" packets "\t" bytes
            }
        }
    '
}
