#!/usr/bin/env bash
# nfdd_minute.sh — хук для nfcapd (-x). Обрабатывает ровно тот файл, который передал nfcapd.
# nfcapd передаёт: %d/%f (путь к файлу), %t (время YYYYMMDDhhmm), %i (ident).
# Пример: nfcapd -x /opt/nfdd/bin/nfdd_minute.sh %d/%f %t %i

set -euo pipefail

FILE_PATH="${1:-}"
FLOW_END_TS="${2:-}"
IDENT="${3:-}"

if [[ -z "$FILE_PATH" ]]; then
    exit 0
fi
# Сделать путь абсолютным, если относительный (cwd при вызове — каталог nfcapd)
if [[ "$FILE_PATH" != /* ]]; then
    FILE_PATH="$(pwd)/$FILE_PATH"
fi
if [[ ! -f "$FILE_PATH" ]]; then
    exit 0
fi

# Неблокирующая блокировка: не ждём, выходим тихо при занятости
mkdir -p /run/lock 2>/dev/null || true
exec 9>/run/lock/nfdd.lock
flock -n 9 || exit 0

NFDD_ROOT="${NFDD_ROOT:-/opt/nfdd}"
export NFDD_ROOT
export NFSEN_BASE="$(dirname "$FILE_PATH")"
export WAIT_FOR_PREVIOUS_INTERVAL=0
export HOOK_MODE=1

logger -t nfdd "hook: file=$FILE_PATH t=$FLOW_END_TS i=$IDENT"

cd "$NFDD_ROOT" && exec ./bin/detector.sh --config "$NFDD_ROOT/etc/detector.conf" --file "$FILE_PATH"
