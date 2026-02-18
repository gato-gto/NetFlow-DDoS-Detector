#!/usr/bin/env bash
# lib/normalize.sh — приведение nfdump JSON к canonical TSV (единый поток для всех детекторов)
# Вход: stdin = JSON (массив или NDJSON). Выход: одна строка на flow, разделитель \t.
# Колонки: FIRST_TS DURATION_MS PROTO SRC_IP DST_IP SRC_PORT DST_PORT PACKETS BYTES TCP_FLAGS XLAT_IP XLAT_PORT
# Фильтры: ip_version != 4 → игнор; sampled != 0 → игнор; пустые src/dst → игнор.
# TCP_FLAGS: HAS_SYN или NO_SYN (для ADB/SYN logic). XLAT: src4_xlt_ip если не 0.0.0.0, иначе пусто.

_normalize_flows_jq() {
    jq -c -R -s '
        (if (.[0] | (.[0:1] == "[")) then (add | fromjson) else [.[] | select(length > 0) | fromjson?] end) as $arr
        | (if ($arr | type) == "array" then $arr[] else $arr end)
        | select(
            ((.ip_version // 4) == 4) and
            ((.sampled // 0) == 0) and
            ((.src4_addr // .src_addr // "") | tostring | length > 0) and
            ((.dst4_addr // .dst_addr // "") | tostring | length > 0)
        )
        | def iso_to_ms: (if . == null or . == "" then 0 else (.[0:19] | fromdateiso8601? // 0) * 1000 + (if length > 20 and .[19:20] == "." then (.[20:23] | tonumber? // 0) else 0 end) end);
        def num(x): x | if . == null then 0 else (. | tonumber? // 0) end;
        def str(x): x | if . == null then "" else tostring end;
        def xlat_ip(x): if x == null or x == "" then "" elif (x|tostring) | test("^0\\.0\\.0\\.0$") then "" else (x|tostring) end;
        def has_syn: (if (.tcp_flags | type) == "number" then (((.tcp_flags // 0) / 2 | floor) % 2) != 0 else (str(.tcp_flags) | test("S"; "i")) end);
        (if .first != null then (.first | iso_to_ms) else 0 end) as $first
        | (if .last != null then (.last | iso_to_ms) else 0 end) as $last
        | (($last - $first) | if . < 0 then 0 else . end) as $dur
        | (str(.src4_addr // .src_addr)) as $src
        | (str(.dst4_addr // .dst_addr)) as $dst
        | (if has_syn then "HAS_SYN" else "NO_SYN" end) as $tcp_flags
        | (xlat_ip(.src4_xlt_ip)) as $xlat_ip
        | [ $first, $dur, num(.proto), $src, $dst, num(.src_port), num(.dst_port), num(.in_packets), num(.in_bytes), $tcp_flags, $xlat_ip, num(.src_xlt_port) ]
        | @tsv
    ' 2>/dev/null
}

_normalize_flows_python() {
    python3 - << 'PYNORM'
import sys, json

def iso_to_ms(s):
    if not s: return 0
    try:
        from datetime import datetime
        base = s[:19].replace("Z", "+00:00")
        sec = datetime.fromisoformat(base).timestamp()
        ms = int(sec * 1000)
        if len(s) > 19 and s[19] == '.': ms += int(s[20:23][:3].ljust(3, '0')[:3])
        return ms
    except Exception: return 0

def num(x): return int(x) if x is not None and str(x).strip() != "" else 0
def str_(x): return "" if x is None else str(x).strip()
def xlat_ip(x):
    if x is None or str(x).strip() in ("", "0.0.0.0"): return ""
    return str(x).strip()

def has_syn(obj):
    f = obj.get("tcp_flags")
    if f is None: return False
    if isinstance(f, (int, float)): return (int(f) & 2) != 0
    return "S" in str(f).upper()

def main():
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        for line in raw.splitlines():
            line = line.strip()
            if not line: continue
            try: data = json.loads(line)
            except: continue
            if isinstance(data, dict): emit(data)
            elif isinstance(data, list): [emit(o) for o in data]
        return
    if isinstance(data, list):
        for obj in data: emit(obj)
    else:
        emit(data)

def emit(obj):
    ip_ver = num(obj.get("ip_version")) or 4
    if ip_ver != 4: return
    if num(obj.get("sampled")) != 0: return
    src = str_(obj.get("src4_addr") or obj.get("src_addr"))
    dst = str_(obj.get("dst4_addr") or obj.get("dst_addr"))
    if not src or not dst: return
    first = iso_to_ms(obj.get("first"))
    last = iso_to_ms(obj.get("last"))
    dur = max(0, last - first)
    proto = num(obj.get("proto"))
    src_port = num(obj.get("src_port"))
    dst_port = num(obj.get("dst_port"))
    pkts = num(obj.get("in_packets") or obj.get("packets"))
    bytes_ = num(obj.get("in_bytes") or obj.get("bytes"))
    tcp_flags = "HAS_SYN" if has_syn(obj) else "NO_SYN"
    xlat_ip_val = xlat_ip(obj.get("src4_xlt_ip"))
    xlat_port = num(obj.get("src_xlt_port"))
    print("\t".join(str(x) for x in [first, dur, proto, src, dst, src_port, dst_port, pkts, bytes_, tcp_flags, xlat_ip_val, xlat_port]))

if __name__ == "__main__":
    main()
PYNORM
}

# normalize_flows
# Читает JSON со stdin, печатает canonical TSV в stdout (одна строка на flow).
# Колонки: FIRST_TS DURATION_MS PROTO SRC_IP DST_IP SRC_PORT DST_PORT PACKETS BYTES TCP_FLAGS XLAT_IP XLAT_PORT
normalize_flows() {
    if command -v jq &>/dev/null; then
        _normalize_flows_jq && return 0
    fi
    _normalize_flows_python
}
