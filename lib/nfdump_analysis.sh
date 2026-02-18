#!/usr/bin/env bash
# lib/nfdump_analysis.sh — nfdump file discovery and flow parsing

# build_traffic_scope
# Builds TRAFFIC_SCOPE for nfdump filter. Uses THREAT_SRC_NETS, INTERNAL_CIDR, INTERNAL_NETS from env.
# Prints the scope string to stdout.
build_traffic_scope() {
    if [[ -n "${THREAT_SRC_NETS:-}" ]]; then
        local cidr="${INTERNAL_CIDR:-10.0.0.0/8}"
        echo "(src net ${cidr}) or (dst net ${cidr} and (${THREAT_SRC_NETS}))"
    else
        echo "${INTERNAL_NETS}"
    fi
}

# nfdump_find_last_file BASE_DIR
# Prints path to the newest nfcapd.20* file, or empty string.
# Supports: flat layout (base/nfcapd.20*) and NfSen layout (base/.../YYYY/MM/DD/nfcapd.20*).
nfdump_find_last_file() {
    find "${1:?}" -mindepth 1 -maxdepth 4 -type f -name 'nfcapd.20*' 2>/dev/null \
        | sort -u | tail -n1
}

# nfdump_expected_previous_minute
# Prints timestamp for "previous minute" in nfcapd format: YYYYMMDDhhmm (e.g. 202602181714).
# Uses GNU date -d '1 minute ago' or BSD date -v-1M.
nfdump_expected_previous_minute() {
    date -d '1 minute ago' +%Y%m%d%H%M 2>/dev/null || date -v-1M +%Y%m%d%H%M 2>/dev/null
}

# nfdump_find_file_for_interval BASE_DIR YYYYMMDDhhmm
# Finds a file named nfcapd.YYYYMMDDhhmm under BASE_DIR (depth 1-4). Prints first path or empty string.
nfdump_find_file_for_interval() {
    find "${1:?}" -mindepth 1 -maxdepth 4 -type f -name "nfcapd.${2:?}" 2>/dev/null | head -n1
}

# nfdump_parse_interval FILEPATH
# Prints "DATE HOUR MIN" (e.g. "20250615 14 05")
nfdump_parse_interval() {
    local fname="${1##*/}"
    echo "${fname:7:8} ${fname:15:2} ${fname:17:2}"
}

# nfdump_run_analysis FILEPATH FILTER NETS TOP_N THRESHOLD [TOP_SORT]
# Prints TSV lines: SRC DST FLOWS PKTS BYTES
# TOP_SORT: record/flows (default), record/packets, record/bytes — order of top-N.
# When NFDUMP_DEBUG_STDERR is set (DEBUG=1), nfdump stderr is written there for logging.
nfdump_run_analysis() {
    local file="$1" filter="$2" nets="$3" top_n="$4" threshold="$5"
    local top_sort="${6:-record/flows}"
    [[ "$top_sort" == record/flows || "$top_sort" == record/packets || "$top_sort" == record/bytes ]] || top_sort="record/flows"
    local stderr_dest="${NFDUMP_DEBUG_STDERR:-/dev/null}"

    nfdump -r "$file" "${filter} and (${nets})" -A srcip,dstip -s "$top_sort" -n "$top_n" \
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

# nfdump_run_aggregated FILEPATH FILTER NETS TOP_N [TOP_SORT]
# Like nfdump_run_analysis but no threshold: prints all TSV lines SRC DST FLOWS PKTS BYTES.
# Used by ADB/Proxy/Staging analyzers for post-processing in awk.
nfdump_run_aggregated() {
    local file="$1" filter="$2" nets="$3" top_n="$4"
    local top_sort="${5:-record/flows}"
    [[ "$top_sort" == record/flows || "$top_sort" == record/packets || "$top_sort" == record/bytes ]] || top_sort="record/flows"
    local stderr_dest="${NFDUMP_DEBUG_STDERR:-/dev/null}"

    nfdump -r "$file" "${filter} and (${nets})" -A srcip,dstip -s "$top_sort" -n "$top_n" \
        2>"$stderr_dest" \
    | awk '
        /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
            src = $4
            dst = $5
            flows = $NF
            if ($(NF-2) ~ /^[GMK]$/) {
                bytes   = $(NF-3) $(NF-2)
                packets = $(NF-5) $(NF-4)
            } else {
                bytes   = $(NF-2)
                packets = $(NF-3)
            }
            print src "\t" dst "\t" flows "\t" packets "\t" bytes
        }
    '
}

# run_adb_scan_analysis FILEPATH NETS
# Uses: ADB_SCAN_NFDUMP_FILTER, ADB_SCAN_TOP_N, ADB_SCAN_UNIQUE_DST_PER_MIN, ADB_SCAN_MAX_BYTES_PER_FLOW.
# Prints TSV: SRC  unique_dst  total_flows  pkts  bytes  (one line per triggering SRC).
run_adb_scan_analysis() {
    local file="$1" nets="$2"
    local filter="${ADB_SCAN_NFDUMP_FILTER:-proto tcp and dst port 5555 and tcp flags syn}"
    local top_n="${ADB_SCAN_TOP_N:-5000}"
    local min_dst="${ADB_SCAN_UNIQUE_DST_PER_MIN:-50}"
    local max_bpf="${ADB_SCAN_MAX_BYTES_PER_FLOW:-300}"
    local raw
    raw=$(nfdump_run_aggregated "$file" "$filter" "$nets" "$top_n" "record/flows") || return 1
    [[ -z "$raw" ]] && return 0
    echo "$raw" | awk -v min_dst="$min_dst" -v max_bpf="$max_bpf" '
        function to_bytes(x) {
            if (x ~ /[Gg]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024*1024 }
            if (x ~ /[Mm]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024 }
            if (x ~ /[Kk]/) { gsub(/[^0-9.]/,"",x); return x * 1024 }
            gsub(/[^0-9.]/,"",x); return x + 0
        }
        BEGIN { OFS="\t" }
        {
            key = $1
            flows = $3 + 0
            pkts = $4 + 0
            bytes = to_bytes($5)
            dst_count[key]++; f[key]+=flows; p[key]+=pkts; b[key]+=bytes
        }
        END {
            for (src in dst_count) {
                u = dst_count[src]
                fl = f[src]; pk = p[src]; by = b[src]
                bpf = (fl > 0) ? (by / fl) : 0
                if (u >= min_dst + 0 && bpf <= max_bpf + 0)
                    print src, u, fl, pk, by
            }
        }
    '
}

# run_proxy_analysis FILEPATH NETS
# Uses: PROXY_PORTS, PROXY_MAX_PKTS_PER_FLOW, PROXY_SHORT_RATIO_PCT, PROXY_MIN_FLOWS_PER_SEC, PROXY_TOP_N.
# Interval assumed 1 min → min total flows = PROXY_MIN_FLOWS_PER_SEC * 60.
# Prints TSV: SRC  short_flows  total_flows  short_ratio  pkts  bytes
run_proxy_analysis() {
    local file="$1" nets="$2"
    local ports="${PROXY_PORTS:-80 443 8080}"
    local max_ppf="${PROXY_MAX_PKTS_PER_FLOW:-10}"
    local ratio_pct="${PROXY_SHORT_RATIO_PCT:-80}"
    local min_fps="${PROXY_MIN_FLOWS_PER_SEC:-500}"
    local top_n="${PROXY_TOP_N:-20000}"
    local min_flows=$(( min_fps * 60 ))
    local filter="proto tcp and (dst port ${ports// / or dst port })"
    local raw
    raw=$(nfdump_run_aggregated "$file" "$filter" "$nets" "$top_n" "record/flows") || return 1
    [[ -z "$raw" ]] && return 0
    echo "$raw" | awk -v max_ppf="$max_ppf" -v ratio_pct="$ratio_pct" -v min_flows="$min_flows" '
        function to_num(x) {
            if (x ~ /[Gg]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024*1024 }
            if (x ~ /[Mm]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024 }
            if (x ~ /[Kk]/) { gsub(/[^0-9.]/,"",x); return x * 1024 }
            gsub(/[^0-9.]/,"",x); return x + 0
        }
        BEGIN { OFS="\t" }
        {
            key = $1
            flows = $3 + 0
            pkts = to_num($4)
            bytes = to_num($5)
            short = (flows > 0 && pkts <= max_ppf) ? 1 : 0
            total[key] += flows
            short_count[key] += short
            p[key] += pkts
            b[key] += bytes
        }
        END {
            for (src in total) {
                fl = total[src]
                sh = short_count[src]
                ratio = (fl > 0) ? (sh / fl * 100) : 0
                if (ratio >= ratio_pct + 0 && fl >= min_flows)
                    print src, sh, fl, ratio, p[src], b[src]
            }
        }
    '
}

# run_staging_analysis FILEPATH NETS
# Uses: STAGING_MIN_UNIQUE_SRC, STAGING_MIN_TOTAL_FLOWS, STAGING_TOP_N, STAGING_PKT_SIZE_MIN/MAX (optional).
# Prints TSV: DST  unique_src  total_flows  pkts  bytes  avg_pkt_size
run_staging_analysis() {
    local file="$1" nets="$2"
    local filter="proto udp"
    local top_n="${STAGING_TOP_N:-5000}"
    local min_src="${STAGING_MIN_UNIQUE_SRC:-30}"
    local min_flows="${STAGING_MIN_TOTAL_FLOWS:-50000}"
    local pkt_min="${STAGING_PKT_SIZE_MIN:-0}"
    local pkt_max="${STAGING_PKT_SIZE_MAX:-999999999}"
    local raw
    raw=$(nfdump_run_aggregated "$file" "$filter" "$nets" "$top_n" "record/flows") || return 1
    [[ -z "$raw" ]] && return 0
    echo "$raw" | awk -v min_src="$min_src" -v min_flows="$min_flows" -v pkt_min="$pkt_min" -v pkt_max="$pkt_max" '
        function to_bytes(x) {
            if (x ~ /[Gg]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024*1024 }
            if (x ~ /[Mm]/) { gsub(/[^0-9.]/,"",x); return x * 1024*1024 }
            if (x ~ /[Kk]/) { gsub(/[^0-9.]/,"",x); return x * 1024 }
            gsub(/[^0-9.]/,"",x); return x + 0
        }
        BEGIN { OFS="\t" }
        {
            key = $2
            flows = $3 + 0
            pkts = $4 + 0
            bytes = to_bytes($5)
            src_count[key]++; f[key]+=flows; p[key]+=pkts; b[key]+=bytes
        }
        END {
            for (dst in src_count) {
                u = src_count[dst]
                fl = f[dst]; pk = p[dst]; by = b[dst]
                avg = (pk > 0) ? (by / pk) : 0
                if (u >= min_src + 0 && fl >= min_flows + 0) {
                    if (pkt_min + 0 <= 0 || pkt_max + 0 >= 999999999) print dst, u, fl, pk, by, avg
                    else if (avg >= pkt_min + 0 && avg <= pkt_max + 0) print dst, u, fl, pk, by, avg
                }
            }
        }
    '
}

# nfdump_run_pairs FILEPATH FILTER NETS TOP_N [TOP_SORT]
# Prints TSV lines (no threshold): SRC DST FLOWS PKTS BYTES
nfdump_run_pairs() {
    local file="$1" filter="$2" nets="$3" top_n="$4"
    local top_sort="${5:-record/flows}"
    [[ "$top_sort" == record/flows || "$top_sort" == record/packets || "$top_sort" == record/bytes ]] || top_sort="record/flows"
    local stderr_dest="${NFDUMP_DEBUG_STDERR:-/dev/null}"

    nfdump -r "$file" "${filter} and (${nets})" -A srcip,dstip -s "$top_sort" -n "$top_n" \
        2>"$stderr_dest" \
    | awk '
        /^[0-9]{4}-[0-9]{2}-[0-9]{2}/ {
            src = $4
            dst = $5
            flows = $NF

            if ($(NF-2) ~ /^[GMK]$/) {
                bytes   = $(NF-3) $(NF-2)
                packets = $(NF-5) $(NF-4)
            } else {
                bytes   = $(NF-2)
                packets = $(NF-3)
            }
            print src "\t" dst "\t" flows "\t" packets "\t" bytes
        }
    '
}

# nfdump_detect_adb_scan FILEPATH NETS
# Emits TSV: SRC UNIQUE_DST TOTAL_FLOWS TOTAL_PKTS TOTAL_BYTES
# Notes:
# - We DO NOT depend on TCP flags, because in some exporters flags can be absent/zero.
# - Detection is based on fan-out: many unique dst IPs on dst port ADB_SCAN_PORT (default 5555).
nfdump_detect_adb_scan() {
    local file="$1" nets="$2"
    local port="${ADB_SCAN_PORT:-5555}"
    local top_n="${ADB_SCAN_TOP_N:-5000}"
    local unique_thr="${ADB_SCAN_UNIQUE_DST_PER_MIN:-50}"
    local filter="proto tcp and dst port ${port}"

    nfdump_run_pairs "$file" "$filter" "$nets" "$top_n" "record/flows" \
    | awk -F"\t" -v uniq_thr="$unique_thr" '
        {
            src=$1; dst=$2; flows=$3+0; pkts=$4+0;
            bytes_raw=$5;
            # bytes_raw may contain suffix; we keep it as text and sum only when it is numeric.
            if (bytes_raw ~ /^[0-9]+(\.[0-9]+)?$/) { bytes=bytes_raw+0 } else { bytes=0 }

            k=src "\t" dst
            if (!(k in seen)) { seen[k]=1; uniq[src]++ }
            fsum[src]+=flows
            psum[src]+=pkts
            bsum[src]+=bytes
        }
        END {
            for (s in uniq) {
                if (uniq[s] + 0 >= uniq_thr + 0) {
                    printf "%s\t%d\t%d\t%d\t%d\n", s, uniq[s], fsum[s], psum[s], bsum[s]
                }
            }
        }
    ' | sort -t $'\t' -k2,2nr -k3,3nr
}

# nfdump_detect_udp_staging FILEPATH NETS
# Emits TSV: DST UNIQUE_SRC TOTAL_FLOWS TOTAL_PKTS TOTAL_BYTES AVG_PKT_SIZE
# Detection: many unique SRCs targeting the same DST with UDP.
nfdump_detect_udp_staging() {
    local file="$1" nets="$2"
    local top_n="${STAGING_TOP_N:-5000}"
    local min_src="${STAGING_MIN_UNIQUE_SRC:-30}"
    local min_flows="${STAGING_MIN_TOTAL_FLOWS:-50000}"
    local pkt_min="${STAGING_PKT_SIZE_MIN:-0}"
    local pkt_max="${STAGING_PKT_SIZE_MAX:-0}"
    local filter="proto udp"

    nfdump_run_pairs "$file" "$filter" "$nets" "$top_n" "record/flows" \
    | awk -F"\t" -v min_src="$min_src" -v min_flows="$min_flows" -v pkt_min="$pkt_min" -v pkt_max="$pkt_max" '
        {
            src=$1; dst=$2; flows=$3+0; pkts=$4+0;
            bytes_raw=$5;
            if (bytes_raw ~ /^[0-9]+(\.[0-9]+)?$/) { bytes=bytes_raw+0 } else { bytes=0 }

            k=dst "\t" src
            if (!(k in seen)) { seen[k]=1; uniq[dst]++ }
            fsum[dst]+=flows
            psum[dst]+=pkts
            bsum[dst]+=bytes
        }
        END {
            for (d in uniq) {
                if (uniq[d] + 0 >= min_src + 0 && fsum[d] + 0 >= min_flows + 0) {
                    avg=0
                    if (psum[d] > 0 && bsum[d] > 0) avg = bsum[d] / psum[d]
                    # Optional packet size gate (when pkt_min/pkt_max set to non-zero)
                    if (pkt_min + 0 > 0 && pkt_max + 0 > 0) {
                        if (!(avg >= pkt_min && avg <= pkt_max)) next
                    }
                    printf "%s\t%d\t%d\t%d\t%d\t%.0f\n", d, uniq[d], fsum[d], psum[d], bsum[d], avg
                }
            }
        }
    ' | sort -t $'\t' -k2,2nr -k3,3nr
}
