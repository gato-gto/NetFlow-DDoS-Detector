# NetFlow DDoS Detector (NFDD)

Детектор DDoS/UDP-флуда по данным nfcapd/nfdump с оповещением в Telegram.

---

## Системные пакеты

Скрипт при старте проверяет наличие четырёх программ (`check_deps` в `bin/detector.sh`). Остальные команды (`find`, `awk`, `grep`, `cut`, `date`, `mkdir` и т.д.) входят в базовую поставку Linux (GNU coreutils, grep, gawk).

| Программа | Назначение в NFDD | Пакет (Debian/Ubuntu) | Пакет (RHEL/CentOS/Rocky/Fedora) |
|-----------|-------------------|------------------------|----------------------------------|
| **nfdump** | Чтение nfcapd, агрегация flow'ов | `nfdump` | `nfdump` (часто из EPEL) |
| **curl** | Запросы к Telegram Bot API | `curl` | `curl` |
| **jq** | Сборка JSON для сообщений в Telegram | `jq` | `jq` |
| **whois** | AS lookup (whois.cymru.com) | `whois` | `whois` |

**Установка:**

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y nfdump curl jq whois

# RHEL / CentOS / Rocky / Alma (при необходимости включите EPEL)
sudo dnf install -y epel-release
sudo dnf install -y nfdump curl jq whois
```

Без любой из этих четырёх программ скрипт при запуске выведет `Missing required tools: ...` и завершится.

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

1. **Установить системные пакеты** (см. таблицу выше): `nfdump`, `curl`, `jq`, `whois`.

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

## Зависимости (кратко)

- **nfdump** — чтение NetFlow (nfcapd)
- **curl** — отправка алертов в Telegram API
- **jq** — безопасная сборка JSON для Telegram
- **whois** — запросы к whois.cymru.com для определения AS по IP

Подробнее и команды установки — в разделе [Системные пакеты](#системные-пакеты) выше.

