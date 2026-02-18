#!/usr/bin/env bash
# lib/detectors/nat_burst.sh — NAT BURST detector (IPFIX Unsampled, FastDPI nat event)
#
# Detects anomalous NAT translation create/delete bursts per src IP.
# Input: nfdump -o raw (Flow Record blocks with src addr, nat event = 1|2).
# Output: TSV SRC CREATE DELETE TOTAL IMBALANCE
#
# Config: ENABLE_DETECT_NAT_BURST, NAT_BURST_* (see detector.conf.example)

# nat_burst_run FILEPATH TRAFFIC_SCOPE
# Prints TSV lines: SRC CREATE DELETE TOTAL IMBALANCE (top-N by total desc).
# Returns 0 on success; if no nat events in file, prints nothing and returns 0.
nat_burst_run() {
    local file="${1:?}"
    local scope="${2:?}"
    local count_create="${NAT_BURST_COUNT_CREATE:-1}"
    local count_delete="${NAT_BURST_COUNT_DELETE:-1}"
    local thr_create="${NAT_BURST_CREATE_THR:-2000}"
    local thr_delete="${NAT_BURST_DELETE_THR:-2000}"
    local thr_total="${NAT_BURST_TOTAL_THR:-3000}"
    local thr_imb="${NAT_BURST_IMBALANCE_RATIO_THR:-5}"
    local imb_min="${NAT_BURST_IMBALANCE_MIN_TOTAL:-200}"
    local top_n="${NAT_BURST_TOP_N:-20}"
    local stderr_dest="${NFDUMP_DEBUG_STDERR:-/dev/null}"

    local raw
    raw=$(nfdump -r "$file" -o raw "(${scope})" 2>"$stderr_dest") || {
        log_warn "NAT BURST: nfdump -o raw failed — skipping (graceful fallback)"
        return 0
    }

    local raw_lines=0
    [[ -n "$raw" ]] && raw_lines=$(wc -l <<< "$raw")
    log_debug "NAT BURST: raw lines from nfdump: $raw_lines"

    # Parse: src addr (first IPv4 per flow), nat event 1=create 2=delete
    # nfdump raw format: "  src addr = 10.0.0.1" or "src addr: 10.0.0.1"
    # "  nat event = 1: NAT translation create" or "nat event: 1"
    local parsed
    parsed=$(echo "$raw" | awk -v count_create="$count_create" -v count_delete="$count_delete" '
        /[Ss]rc addr[^a-zA-Z0-9]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/ {
            match($0, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/)
            if (RSTART > 0) cur_src = substr($0, RSTART, RLENGTH)
        }
        /[Nn]at event[^0-9]*1[^0-9]/ && cur_src != "" && count_create+0 == 1 {
            create[cur_src]++
            cur_src = ""
        }
        /[Nn]at event[^0-9]*2[^0-9]/ && cur_src != "" && count_delete+0 == 1 {
            del[cur_src]++
            cur_src = ""
        }
        END {
            for (s in create) { d[s] = del[s]+0 }
            for (s in del) if (!(s in create)) { create[s]=0; d[s]=del[s] }
            for (s in create) {
                c = create[s]+0
                dv = d[s]+0
                t = c + dv
                if (t == 0) continue
                mn = (c < dv) ? c : dv
                mx = (c > dv) ? c : dv
                imb = (mn > 0) ? (mx / mn) : mx
                printf "%s\t%d\t%d\t%d\t%.1f\n", s, c, dv, t, imb
            }
        }
    ')

    if [[ -z "$parsed" ]]; then
        if (( raw_lines > 0 )); then
            log_warn "NAT BURST: no nat events in file (nat event field may be absent in IPFIX template) — skipping"
        else
            log_debug "NAT BURST: empty nfdump output"
        fi
        return 0
    fi

    local src_count
    src_count=$(echo "$parsed" | wc -l)
    log_debug "NAT BURST: src with nat events: $src_count"

    # Apply thresholds and sort
    echo "$parsed" | awk -v thr_c="$thr_create" -v thr_d="$thr_delete" -v thr_t="$thr_total" \
        -v thr_imb="$thr_imb" -v imb_min="$imb_min" -v top="$top_n" '
        BEGIN { OFS="\t" }
        {
            src=$1; create=$2+0; del=$3+0; total=$4+0; imb=$5+0
            trigger = 0
            if (create >= thr_c) trigger = 1
            if (del >= thr_d) trigger = 1
            if (total >= thr_t) trigger = 1
            if (total >= imb_min && imb >= thr_imb) trigger = 1
            if (trigger) print src, create, del, total, imb
        }
    ' | sort -t $'\t' -k4,4nr -k2,2nr | head -n "$top_n"
}
