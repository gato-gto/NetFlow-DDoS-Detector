# NetFlow DDoS Detector (NFDD)

Детектор DDoS/UDP-флуда по данным nfcapd/nfdump с оповещением в Telegram.

---

## Использование

### Запуск

Из корня проекта (скрипт должен лежать в `bin/`):

```bash
./bin/detector.sh [ОПЦИИ]
```

**Опции:**

| Опция | Описание |
|-------|----------|
| `--config FILE` | Путь к конфигу (по умолчанию: `etc/detector.conf`) |
| `--dry-run` | Не отправлять в Telegram; вывести сообщение в лог |
| `--debug` | Включить уровень лога DEBUG |
| `-h`, `--help` | Краткая справка по опциям |

**Примеры:**

```bash
# Обычный запуск (конфиг по умолчанию)
./bin/detector.sh

# Проверка без отправки в Telegram
./bin/detector.sh --dry-run

# Свой конфиг и отладочный вывод
./bin/detector.sh --config /etc/nfdd.conf --debug

# Справка
./bin/detector.sh --help
```

### Первый запуск

1. **Установить зависимости:** `nfdump`, `curl`, `jq`, `whois`.

2. **Создать конфиг** (скопировать шаблон при наличии и отредактировать):
   ```bash
   cp etc/detector.conf.example etc/detector.conf
   nano etc/detector.conf
   ```
   Обязательно задать: `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID`, `NFSEN_BASE`.

3. **Проверить без отправки:**
   ```bash
   ./bin/detector.sh --dry-run
   ```

4. **Добавить в cron** (например, каждые 5 минут):
   ```bash
   echo "*/5 * * * * root /opt/nfdd/bin/detector.sh" >> /etc/cron.d/nfdd
   ```

Каталоги логов, кэша и состояния создаются при первом запуске (если нет `setup.sh`).

---

## Структура проекта

```
bin/detector.sh          ← оркестратор (точка входа)
lib/log.sh               ← логирование (stdout + файл)
lib/telegram.sh          ← отправка через Bot API
lib/as_lookup.sh         ← whois с TTL-кэшем
lib/dedup.sh             ← дедупликация алертов
lib/nfdump_analysis.sh   ← работа с nfdump
lib/classify.sh          ← классификация угрозы
etc/detector.conf        ← конфиг (не в git — см. .gitignore)
etc/detector.conf.example ← шаблон конфига
```

Запуск только так: `./bin/detector.sh` из корня проекта — скрипт сам находит `etc/detector.conf` и `lib/*.sh` относительно корня. Секреты только в `etc/detector.conf`; конфиг в `.gitignore` и `.cursorignore`.

---

## Конфигурация

Все параметры в `etc/detector.conf`. Основные:

- `NFSEN_BASE` — каталог с nfcapd-файлами
- `TELEGRAM_TOKEN`, `TELEGRAM_CHAT_ID` — бот и чат для алертов
- `TELEGRAM_CHAT_THREAD_ID` — (опционально) ID топика в супергруппе
- `THRESHOLD_SUSPICIOUS` — порог по числу flow'ов для алерта
- `ALERT_DEDUP_TTL` — секунды, в течение которых не повторять алерт по одной паре SRC→DST

Все параметры перечислены в `etc/detector.conf.example` с комментариями.

---

## Зависимости

- `nfdump` — чтение NetFlow
- `curl` — Telegram API
- `jq` — JSON для сообщений
- `whois` — AS lookup (whois.cymru.com)

При отсутствии нужной команды скрипт завершится с ошибкой при старте.

