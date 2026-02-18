#!/usr/bin/env bash
# lib/detectors/nat_burst.sh — NAT BURST по canonical TSV (XLAT_IP + XLAT_PORT)
# Работает на потоке от json_stream → normalize. Вызывает nfdump_detect_nat_burst_xlat из nfdump_analysis.sh.
# Ожидает: nfdump_analysis.sh уже загружен (detector.sh загружает его до этого файла).

# nat_burst_run FILEPATH NETS
# Печатает TSV: XLAT_IP  create  delete  total_flows  uniq_ports (create/delete=0 в JSON-режиме).
nat_burst_run() {
    nfdump_detect_nat_burst_xlat "$1" "$2"
}
