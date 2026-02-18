#!/usr/bin/env bash
# lib/json_flow.sh — JSON-парсер nfdump + нормализатор в FLOW_NDJSON_V1
# Единый вход для детекторов vNext и verify_analysis.sh --json.
# Зависимости: jq (предпочтительно) или python3 (fallback).

# nf_dump_json <nfcapd_file>
# Вызывает nfdump -r "$file" -o json. Вывод в stdout.
nf_dump_json() {
    local file="${1:?}"
    nfdump -r "$file" -o json 2>/dev/null
}

# _norm_ndjson_python — нормализация через python3 (fallback). INTERNAL_CIDR из env для is_internal_*.
_norm_ndjson_python() {
    python3 - "$(echo "${INTERNAL_CIDR:-10.0.0.0/8}" | tr ',' ' ')" << 'PYNORM'
import sys, json, re
try:
    from ipaddress import ip_address, ip_network
    def in_cidr(ip_s, cidrs):
        if not ip_s or not cidrs: return 0
        try:
            a = ip_address(ip_s)
            for c in cidrs:
                c = c.strip()
                if not c: continue
                try:
                    if a in ip_network(c): return 1
                except Exception: pass
        except Exception: pass
        return 0
except ImportError:
    def in_cidr(ip_s, cidrs): return 0

def iso_to_ms(s):
    if not s: return 0
    try:
        from datetime import datetime
        base = s[:19].replace("Z", "+00:00")
        sec = datetime.fromisoformat(base).timestamp()
        ms = int(sec * 1000)
        if len(s) > 19 and s[19] == '.':
            ms += int(s[20:23][:3].ljust(3, '0')[:3])
        return ms
    except Exception: return 0

def num(x): return int(x) if x is not None and str(x).strip() != "" else 0
def str_(x): return "" if x is None else str(x).strip()
def ip4_or_empty(x):
    if x is None or str(x).strip() in ("", "0.0.0.0"): return ""
    return str(x).strip()

def main():
    cidr_raw = sys.argv[1] if len(sys.argv) > 1 else "10.0.0.0/8"
    cidrs = [c.strip() for c in cidr_raw.split() if c.strip()]
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip()
            if not line: continue
            try: data = json.loads(line)
            except: continue
            emit(data, cidrs)
        return
    if isinstance(data, list):
        for obj in data: emit(obj, cidrs)
    else:
        emit(data, cidrs)

def emit(obj, cidrs):
    first = obj.get("first") or obj.get("first_switched")
    last = obj.get("last") or obj.get("last_switched")
    t_first = iso_to_ms(first)
    t_last = iso_to_ms(last)
    dur = max(0, t_last - t_first)
    proto = num(obj.get("proto"))
    src4 = obj.get("src4_addr") or obj.get("src_addr")
    dst4 = obj.get("dst4_addr") or obj.get("dst_addr")
    src_ip = str_(src4) if src4 else str_(obj.get("src6_addr"))
    dst_ip = str_(dst4) if dst4 else str_(obj.get("dst6_addr"))
    src_port = num(obj.get("src_port"))
    dst_port = num(obj.get("dst_port"))
    pkts = num(obj.get("in_packets") or obj.get("packets"))
    bytes_ = num(obj.get("in_bytes") or obj.get("bytes"))
    tcp_flags = str_(obj.get("tcp_flags"))
    exporter_ip = str_(obj.get("ip4_router") or obj.get("exporter_ip"))
    src_as = num(obj.get("src_as"))
    dst_as = num(obj.get("dst_as"))
    src_vlan = num(obj.get("src_vlan"))
    dst_vlan = num(obj.get("dst_vlan"))
    nat_src_ip = ip4_or_empty(obj.get("src4_xlt_ip") or obj.get("nat_src_ip"))
    nat_src_port = num(obj.get("src_xlt_port") or obj.get("nat_src_port"))
    nat_dst_ip = ip4_or_empty(obj.get("dst4_xlt_ip") or obj.get("nat_dst_ip"))
    nat_dst_port = num(obj.get("dst_xlt_port") or obj.get("nat_dst_port"))
    ip_ver = num(obj.get("ip_version")) or (4 if (src4 or ("." in str(src_ip))) else 6)
    is_src = in_cidr(src_ip, cidrs)
    is_dst = in_cidr(dst_ip, cidrs)
    out = {
        "t_first_ms": t_first, "t_last_ms": t_last, "dur_ms": dur,
        "proto": proto, "src_ip": src_ip, "dst_ip": dst_ip,
        "src_port": src_port, "dst_port": dst_port, "pkts": pkts, "bytes": bytes_,
        "tcp_flags": tcp_flags, "exporter_ip": exporter_ip,
        "src_as": src_as, "dst_as": dst_as, "src_vlan": src_vlan, "dst_vlan": dst_vlan,
        "nat_src_ip": nat_src_ip, "nat_src_port": nat_src_port,
        "nat_dst_ip": nat_dst_ip, "nat_dst_port": nat_dst_port,
        "ip_version": ip_ver, "is_internal_src": is_src, "is_internal_dst": is_dst
    }
    print(json.dumps(out, ensure_ascii=False))

if __name__ == "__main__":
    main()
PYNORM
}

# nf_norm_ndjson
# Читает JSON (массив объектов или NDJSON) из stdin, пишет FLOW_NDJSON_V1 в stdout.
# Использует jq (предпочтительно), при отсутствии или ошибке — python3. is_internal_* в jq = 0; в python — по INTERNAL_CIDR.
nf_norm_ndjson() {
    if command -v jq &>/dev/null; then
        # -R -s: stdin как массив строк. Если первая строка начинается с "[" — один JSON-массив; иначе NDJSON.
        jq -c -R -s '
            (if (.[0] | (.[0:1] == "[")) then (add | fromjson) else [.[] | select(length > 0) | fromjson?] end) as $arr
            | (if ($arr | type) == "array" then $arr[] else $arr end)
            | def iso_to_ms: (if . == null or . == "" then 0 else (.[0:19] | fromdateiso8601? // 0) * 1000 + (if length > 20 and .[19:20] == "." then (.[20:23] | tonumber? // 0) else 0 end) end);
            def num(x): x | if . == null then 0 else (. | tonumber? // 0) end;
            def str(x): x | if . == null then "" else tostring end;
            def ip4e(x): if x == null or x == "" then "" elif (x|tostring) | test("^0\\.0\\.0\\.0$") then "" else (x|tostring) end;
            (if .first != null then (.first|iso_to_ms) else 0 end) as $t1
            | (if .last != null then (.last|iso_to_ms) else 0 end) as $t2
            | (($t2-$t1) | if . < 0 then 0 else . end) as $dur
            | (if .src4_addr != null and (.src4_addr|tostring) != "" then (.src4_addr|tostring) elif .src6_addr != null then (.src6_addr|tostring) else "" end) as $si
            | (if .dst4_addr != null and (.dst4_addr|tostring) != "" then (.dst4_addr|tostring) elif .dst6_addr != null then (.dst6_addr|tostring) else "" end) as $di
            | { t_first_ms: $t1, t_last_ms: $t2, dur_ms: $dur, proto: num(.proto), src_ip: $si, dst_ip: $di,
                src_port: num(.src_port), dst_port: num(.dst_port), pkts: num(.in_packets), bytes: num(.in_bytes),
                tcp_flags: str(.tcp_flags), exporter_ip: str(.ip4_router),
                src_as: num(.src_as), dst_as: num(.dst_as), src_vlan: num(.src_vlan), dst_vlan: num(.dst_vlan),
                nat_src_ip: ip4e(.src4_xlt_ip), nat_src_port: num(.src_xlt_port), nat_dst_ip: ip4e(.dst4_xlt_ip), nat_dst_port: num(.dst_xlt_port),
                ip_version: (num(.ip_version) // 4), is_internal_src: 0, is_internal_dst: 0 }
        ' 2>/dev/null && return 0
    fi
    _norm_ndjson_python
}

# nf_stream_norm <nfcapd_file>
# nf_dump_json "$file" | nf_norm_ndjson. Вывод — FLOW_NDJSON_V1 в stdout.
# Не хранить результат в переменной (большие объёмы). Писать в файл: nf_stream_norm "$file" > "$TMPDIR/flows.ndjson"
nf_stream_norm() {
    local file="${1:?}"
    nf_dump_json "$file" | nf_norm_ndjson
}
