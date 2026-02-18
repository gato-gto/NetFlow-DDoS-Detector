#!/usr/bin/env bash
# lib/nfdump_analysis.sh — поиск nfcapd-файлов и построение scope. Данные — только через json_stream (nfdump -o json → normalize).
# Все функции анализа вызывают json_stream и парсят canonical TSV (FIRST_TS DURATION_MS PROTO SRC_IP DST_IP SRC_PORT DST_PORT PACKETS BYTES TCP_FLAGS XLAT_IP XLAT_PORT).

# Зависимость: json_stream (lib/json_stream.sh) и normalize (lib/normalize.sh) должны быть загружены до вызова функций анализа.
# detector.sh загружает: normalize.sh, json_stream.sh, затем этот файл.

# build_traffic_scope
# Строит TRAFFIC_SCOPE для фильтра nfdump. Использует THREAT_SRC_NETS, INTERNAL_CIDR, INTERNAL_NETS из env.
build_traffic_scope() {
    if [[ -n "${THREAT_SRC_NETS:-}" ]]; then
        local cidr="${INTERNAL_CIDR:-10.0.0.0/8}"
        echo "(src net ${cidr}) or (dst net ${cidr} and (${THREAT_SRC_NETS}))"
    else
        echo "${INTERNAL_NETS}"
    fi
}

# nfdump_find_last_file BASE_DIR
nfdump_find_last_file() {
    find "${1:?}" -mindepth 1 -maxdepth 4 -type f -name 'nfcapd.20*' 2>/dev/null \
        | sort -u | tail -n1
}

# nfdump_expected_previous_minute
nfdump_expected_previous_minute() {
    date -d '1 minute ago' +%Y%m%d%H%M 2>/dev/null || date -v-1M +%Y%m%d%H%M 2>/dev/null
}

# nfdump_find_file_for_interval BASE_DIR YYYYMMDDhhmm
nfdump_find_file_for_interval() {
    find "${1:?}" -mindepth 1 -maxdepth 4 -type f -name "nfcapd.${2:?}" 2>/dev/null | head -n1
}

# nfdump_parse_interval FILEPATH
nfdump_parse_interval() {
    local fname="${1##*/}"
    echo "${fname:7:8} ${fname:15:2} ${fname:17:2}"
}

# Canonical TSV колонки (после normalize): 1=FIRST_TS 2=DURATION_MS 3=PROTO 4=SRC_IP 5=DST_IP 6=SRC_PORT 7=DST_PORT 8=PACKETS 9=BYTES 10=TCP_FLAGS 11=XLAT_IP 12=XLAT_PORT

# nfdump_run_analysis FILEPATH FILTER NETS TOP_N THRESHOLD [TOP_SORT]
# Печатает TSV: SRC DST FLOWS PKTS BYTES (агрегация по canonical TSV; TOP_SORT по умолчанию record/flows).
nfdump_run_analysis() {
    local file="$1" filter="$2" nets="$3" top_n="$4" threshold="$5"
    local top_sort="${6:-record/flows}"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -v thr="$threshold" -v top_n="$top_n" -F'\t' '
        { key = $4 "\t" $5; flows[key]++; pkts[key]+=$8; bytes[key]+=$9 }
        END {
            for (k in flows) if (flows[k] + 0 > thr + 0) print flows[k], pkts[k], bytes[k], k
        }
    ' | sort -t$'\t' -k1,1nr | head -n "$top_n" | awk -v OFS='\t' '{ print $4, $5, $1, $2, $3 }'
}

# nfdump_run_aggregated FILEPATH FILTER NETS TOP_N [TOP_SORT]
# TSV: SRC DST FLOWS PKTS BYTES без порога.
nfdump_run_aggregated() {
    local file="$1" filter="$2" nets="$3" top_n="$4"
    local top_sort="${5:-record/flows}"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -F'\t' '
        { key = $4 "\t" $5; flows[key]++; pkts[key]+=$8; bytes[key]+=$9 }
        END { for (k in flows) print flows[k], pkts[k], bytes[k], k }
    ' | sort -t$'\t' -k1,1nr | head -n "$top_n" | awk -v OFS='\t' '{ print $4, $5, $1, $2, $3 }'
}

# nfdump_run_pairs FILEPATH FILTER NETS TOP_N [TOP_SORT]
# TSV: SRC DST FLOWS PKTS BYTES.
nfdump_run_pairs() {
    local file="$1" filter="$2" nets="$3" top_n="$4"
    local top_sort="${5:-record/flows}"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -F'\t' '
        { key = $4 "\t" $5; flows[key]++; pkts[key]+=$8; bytes[key]+=$9 }
        END { for (k in flows) print flows[k], pkts[k], bytes[k], k }
    ' | sort -t$'\t' -k1,1nr | head -n "$top_n" | awk -v OFS='\t' '{ print $4, $5, $1, $2, $3 }'
}

# run_adb_scan_analysis FILEPATH NETS — по canonical TSV: proto tcp, dst port 5555, агрегация по SRC.
run_adb_scan_analysis() {
    local file="$1" nets="$2"
    local filter="${ADB_SCAN_NFDUMP_FILTER:-proto tcp and dst port 5555}"
    local top_n="${ADB_SCAN_TOP_N:-5000}"
    local min_dst="${ADB_SCAN_UNIQUE_DST_PER_MIN:-50}"
    local max_bpf="${ADB_SCAN_MAX_BYTES_PER_FLOW:-300}"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -F'\t' -v min_dst="$min_dst" -v max_bpf="$max_bpf" '
        $3 == 6 && $7 == 5555 {
            src = $4; dst = $5; pkts = $8 + 0; bytes = $9 + 0
            k = src "\t" dst; if (!(k in seen)) { seen[k] = 1; uniq[src]++ }
            f[src]++; p[src] += pkts; b[src] += bytes
        }
        END {
            for (s in uniq)
                if (uniq[s] + 0 >= min_dst + 0 && f[s] > 0 && (b[s] / f[s]) <= max_bpf + 0)
                    print s, uniq[s], f[s], p[s], b[s]
        }
    ' | sort -t$'\t' -k2,2nr -k3,3nr
}

# run_proxy_analysis FILEPATH NETS — TCP 80/443/8080, микрофлоу по PACKETS.
run_proxy_analysis() {
    local file="$1" nets="$2"
    local ports="${PROXY_PORTS:-80 443 8080}"
    local max_ppf="${PROXY_MAX_PKTS_PER_FLOW:-10}"
    local ratio_pct="${PROXY_SHORT_RATIO_PCT:-80}"
    local min_fps="${PROXY_MIN_FLOWS_PER_SEC:-500}"
    local top_n="${PROXY_TOP_N:-20000}"
    local min_flows=$(( min_fps * 60 ))
    local filter="proto tcp and (dst port ${ports// / or dst port })"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -F'\t' -v max_ppf="$max_ppf" -v ratio_pct="$ratio_pct" -v min_flows="$min_flows" '
        { src = $4; flows[src]++; if ($8 + 0 <= max_ppf) short[src]++; pkts[src] += $8; bytes[src] += $9 }
        END {
            for (s in flows)
                if (flows[s] >= min_flows && (short[s] / flows[s] * 100) >= ratio_pct)
                    print s, short[s], flows[s], (short[s]/flows[s]*100), pkts[s], bytes[s]
        }
    ' | sort -t$'\t' -k3,3nr | head -n "$top_n"
}

# run_staging_analysis FILEPATH NETS — UDP, агрегация по DST.
run_staging_analysis() {
    local file="$1" nets="$2"
    local filter="proto udp"
    local top_n="${STAGING_TOP_N:-5000}"
    local min_src="${STAGING_MIN_UNIQUE_SRC:-30}"
    local min_flows="${STAGING_MIN_TOTAL_FLOWS:-50000}"
    local full_filter="${filter} and (${nets})"
    json_stream "$file" "$full_filter" | awk -F'\t' -v min_src="$min_src" -v min_flows="$min_flows" '
        { dst = $5; src = $4; k = dst "\t" src; if (!(k in seen)) { seen[k] = 1; uniq[dst]++ }; f[dst]++; p[dst] += $8; b[dst] += $9 }
        END {
            for (d in uniq)
                if (uniq[d] >= min_src + 0 && f[d] >= min_flows + 0)
                    print d, uniq[d], f[d], p[d], b[d], (p[d] > 0 ? b[d]/p[d] : 0)
        }
    ' | sort -t$'\t' -k2,2nr -k3,3nr | head -n "$top_n"
}

# nfdump_detect_adb_scan FILEPATH NETS
nfdump_detect_adb_scan() {
    run_adb_scan_analysis "$1" "$2"
}

# nfdump_detect_udp_staging FILEPATH NETS
nfdump_detect_udp_staging() {
    run_staging_analysis "$1" "$2"
}

# nfdump_detect_nat_burst_xlat FILEPATH NETS
# NAT BURST по canonical TSV: агрегация по XLAT_IP (col 11), unique XLAT_PORT (col 12), total flows.
# Выход TSV: XLAT_IP  create  delete  total_flows  uniq_ports (create/delete=0 в JSON-режиме; detector показывает ratio=uniq_ports).
# Порог: uniq_ports > NAT_BURST_PORT_THRESHOLD. Топ: NAT_BURST_TOP_N.
nfdump_detect_nat_burst_xlat() {
    local file="$1" nets="$2"
    local th_port="${NAT_BURST_PORT_THRESHOLD:-400}"
    local top_n="${NAT_BURST_TOP_N:-20}"
    local full_filter="${nets}"
    json_stream "$file" "$full_filter" | awk -F'\t' -v th="$th_port" -v top_n="$top_n" '
        $11 != "" && $11 != "0.0.0.0" {
            xlat = $11; port = $12
            k = xlat "\t" port; if (!(k in seen)) { seen[k] = 1; uniq[xlat]++ }
            flows[xlat]++
        }
        END {
            n = 0
            for (x in uniq)
                if (uniq[x] + 0 > th + 0 && n < top_n + 0) {
                    print x, 0, 0, flows[x], uniq[x]
                    n++
                }
        }
    ' | sort -t$'\t' -k4,4nr -k5,5nr
}
