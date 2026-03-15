# Глубокий статический анализ бинарного файла `mg` (Media Gateway)
## GoIP GST1610 Firmware

---

## 1. ELF-заголовок и метаданные

| Параметр | Значение |
|----------|----------|
| **Файл** | `/usr/bin/mg` |
| **Размер** | 117,032 байт (114 КБ) |
| **Формат** | ELF 32-bit LSB executable |
| **Архитектура** | ARM (machine=40) |
| **Порядок байт** | Little-endian |
| **OS/ABI** | ARM (0x61) |
| **Точка входа** | `0x00009614` (начало `.text`) |
| **Program headers** | 5 шт, offset 52 |
| **Section headers** | 24 шт, offset 116072 |
| **Компилятор** | GCC 3.3.5 / GCC 3.3.2 20031005 (Debian prerelease) |
| **C библиотека** | uClibc (`/lib/ld-uClibc.so.0`, `libc.so.0`) |

---

## 2. Карта ELF-секций

| # | Секция | Тип | Адрес | Смещение | Размер |
|---|--------|-----|-------|----------|--------|
| 0 | (null) | NULL | 0x00000000 | 0x000000 | 0 |
| 1 | `.interp` | PROGBITS | 0x000080D4 | 0x0000D4 | 20 |
| 2 | `.hash` | HASH | 0x000080E8 | 0x0000E8 | 812 |
| 3 | `.dynsym` | DYNSYM | 0x00008414 | 0x000414 | 1,664 |
| 4 | `.dynstr` | STRTAB | 0x00008A94 | 0x000A94 | 821 |
| 5 | `.gnu.version` | VERSYM | 0x00008DCA | 0x000DCA | 208 |
| 6 | `.gnu.version_r` | VERNEED | 0x00008E9C | 0x000E9C | 32 |
| 7 | `.rel.dyn` | REL | 0x00008EBC | 0x000EBC | 16 |
| 8 | `.rel.plt` | REL | 0x00008ECC | 0x000ECC | 728 |
| 9 | `.init` | PROGBITS | 0x000091A4 | 0x0011A4 | 24 |
| 10 | `.plt` | PROGBITS | 0x000091BC | 0x0011BC | 1,112 |
| 11 | **`.text`** | PROGBITS | 0x00009614 | 0x001614 | **98,840** |
| 12 | `.fini` | PROGBITS | 0x0002182C | 0x01982C | 20 |
| 13 | **`.rodata`** | PROGBITS | 0x00021840 | 0x019840 | **9,580** |
| 14 | `.eh_frame` | PROGBITS | 0x00023DAC | 0x01BDAC | 4 |
| 15 | `.ctors` | PROGBITS | 0x0002BDB0 | 0x01BDB0 | 8 |
| 16 | `.dtors` | PROGBITS | 0x0002BDB8 | 0x01BDB8 | 8 |
| 17 | `.jcr` | PROGBITS | 0x0002BDC0 | 0x01BDC0 | 4 |
| 18 | `.dynamic` | DYNAMIC | 0x0002BDC4 | 0x01BDC4 | 208 |
| 19 | `.got` | PROGBITS | 0x0002BE94 | 0x01BE94 | 380 |
| 20 | `.data` | PROGBITS | 0x0002C010 | 0x01C010 | 412 |
| 21 | `.bss` | NOBITS | 0x0002C1AC | 0x01C1AC | 3,380 |
| 22 | `.comment` | PROGBITS | 0x00000000 | 0x01C1AC | 778 |
| 23 | `.shstrtab` | STRTAB | 0x00000000 | 0x01C4B6 | 176 |

**Ключевое:** `.text` = ~97 КБ кода, `.rodata` = ~9.4 КБ строковых/табличных данных, `.bss` = 3.4 КБ неинициализированных данных.

---

## 3. Импортируемые функции (PLT / динамические символы)

### Сетевые / сокетные
| Функция | Назначение |
|---------|------------|
| `socket` | Создание UDP/TCP сокетов |
| `bind` | Привязка к порту |
| `connect` | Подключение (TCP/UNIX) |
| `send` / `sendto` / `sendmsg` | Отправка RTP/RTCP/данных |
| `recv` / `recvfrom` / `recvmsg` | Приём RTP/RTCP/данных |
| `listen` / `accept` | TCP-сервер (управляющий CLI) |
| `select` / `poll` | Мультиплексирование ввода-вывода |
| `setsockopt` / `getsockopt` | Настройка сокетов (TOS/QoS) |
| `getsockname` | Определение локального адреса |
| `inet_aton` / `inet_ntoa` / `inet_ntop` | Преобразование IP-адресов |
| `gethostbyname` / `gethostname` | DNS-разрешение |

### Системные
| Функция | Назначение |
|---------|------------|
| `ioctl` | Управление DSP-устройством |
| `mmap` / `munmap` | Маппинг памяти (DSP-буфера) |
| `fcntl` | Управление файловыми дескрипторами |
| `signal` / `kill` | Обработка сигналов |
| `setitimer` | Таймеры (RTP-пакетизация) |
| `sched_setscheduler` | Приоритет реального времени |
| `usleep` | Микросекундные задержки |
| `fopen` / `fclose` / `fwrite` / `fgets` | Файловый ввод-вывод |
| `readlink` | Чтение символических ссылок |

### Строковые/Память
`malloc`, `calloc`, `realloc`, `free`, `memcpy`, `memset`, `memmove`, `memcmp`, `strlen`, `strcpy`, `strncpy`, `strcat`, `strcmp`, `strncmp`, `strcasecmp`, `strchr`, `strdup`, `strtol`, `strtoul`, `atoi`, `atol`, `sscanf`, `sprintf`, `vsnprintf`, `fprintf`

---

## 4. Извлечённые строки по категориям

### 4.1 IPC / DSP-интерфейс (FVDSP)

MG общается с DSP-процессором через UNIX-доменные сокеты:

| Строка | Назначение |
|--------|------------|
| `/tmp/.fvdsp_mgcmd%d` | Сокет отправки команд MG → DSP (на канал) |
| `/tmp/.fvdsp_data_out%d` | Сокет приёма аудиоданных от DSP |
| `/tmp/.fvdsp_cmd_in` | Сокет приёма ответов/событий от DSP |
| `/tmp/.fvdsp_data_in%d` | Сокет отправки аудиоданных в DSP |
| `FVDSP_DEV%d_TYPE` | Переменная окружения — тип DSP-устройства |
| `SLIC` / `slic` | Тип — абонентский интерфейс (Subscriber Line Interface Circuit) |
| `/tmp/.ippui%d` | IPC-сокет для IPPUI (IP Phone UI?) |
| `fvdsp` | Имя DSP-подсистемы |

### DSP-команды (протокол FVDSP)

| Команда | Значение |
|---------|----------|
| `open %d` | Открыть DSP-канал |
| `close %d` | Закрыть DSP-канал |
| `cfg %d codec %d %d` | Настройка кодека канала (id_канала, тип_кодека, параметр) |
| `cfg %d mr %d` | Настройка media rate |
| `cfg %d fax %d` | Настройка факса на канале |
| `cfg %d set` | Применить конфигурацию канала |
| `remote %d` | Установить удалённый адрес |
| `mstop %d` | Остановить медиа-поток канала |
| `fax %d` | Переключить канал в режим факса |
| `DTMF %c` | Событие DTMF (символ) |

### 4.2 Кодеки

| Строка | Кодек |
|--------|-------|
| `ulaw` | G.711 μ-law (PCMU) |
| `alaw` | G.711 A-law (PCMA) |
| `g7231` | G.723.1 (общий) |
| `g723l` | G.723.1 low rate (5.3 kbps) |
| `g723h` | G.723.1 high rate (6.3 kbps) |
| `g729` | G.729 |
| `g729a` | G.729 Annex A |
| `g729ab` | G.729 Annex A/B (с VAD) |
| `t38fax` | T.38 факс |
| `rfc2833` | RFC 2833 DTMF (telephone-event) |
| `audio` | Тип медиа |
| `video` | Тип медиа (видео — поддержка?) |
| `gsm` | GSM кодек (по умолчанию отключён: `!gsm`) |

### 4.3 Шифрование RTP

| Строка | Назначение |
|--------|------------|
| `rc4-key` | CLI-параметр: ключ RC4-шифрования |
| `rc4 encrypt/decrypt key` | Описание параметра |
| `ECM_CRYPT_KEY` | Переменная окружения для ключа шифрования |
| `enable-et263-crypt` | CLI-параметр: включить ET263 |
| `MG_ET263_CRYPT` | Конфиг-ключ ET263 |
| `et263-crypt-type` | Тип шифрования ET263 |
| `MG_ET263_CRYPT_TYPE` | Конфиг-ключ типа ET263 |
| `et263-crypt-depth` | Глубина шифрования ET263 |
| `MG_ET263_CRYPT_DEP` | Конфиг-ключ глубины ET263 |
| `avs-crypt-port` | Порт шифрования для AVS-сервера |
| `MG_AVS_CRYPT` | Конфиг-ключ AVS-шифрования |
| `ET263` | Идентификатор алгоритма |
| `VOS2000` | Второй алгоритм/система (?) |
| `X-ACrypt` | SIP-заголовок для согласования шифрования |
| `rtp_decrypt(): cc=%d` | Отладка дешифрования RTP |
| `Encode[%d]= %d` | Отладка кодирования |

#### Модуль `et263_crypt.c` — реконструированный API:

| Функция | Назначение |
|---------|------------|
| `convert_16_encode` | 16-байтное преобразование (шифрование) |
| `create_convert_16` | Создание 16-байтного шифратора |
| `convert_8_encode` | 8-байтное преобразование |
| `create_convert_8` | Создание 8-байтного шифратора |
| `parity_exchange_16_encode` | Обмен чётности, 16 байт |
| `create_parity_exchange_16` | Создание обмена чётности 16 |
| `parity_exchange_8_encode` | Обмен чётности, 8 байт |
| `create_parity_exchange_8` | Создание обмена чётности 8 |
| `create_et263_crypt` | Главный конструктор ET263 |

**Сообщения об ошибках ET263:**
- `encrypt length is less than 4` — минимальная длина шифрования 4 байта
- `encrypt length is too short`
- `ET263 crypt create error`
- `ET263 crypt type error` — неверный тип
- `ET263 crypt depth error` — неверная глубина

### 4.4 RTP/RTCP

| Строка | Назначение |
|--------|------------|
| `rtpstat %s %d %d %d %d %d %d %d %d %08lx` | Формат статистики RTP (направление, пакеты, потери, джиттер, etc.) |
| `start %s %c %08lx:%d %08lx:%d` | Старт медиа-сессии (направление, локальный и удалённый IP:port) |
| `media_channel_do_rtcp` | Функция обработки RTCP |
| `rtp-tos` | QoS: поле TOS/DSCP для RTP-пакетов |
| `rtp-port` / `RTP_PORT` | Диапазон RTP-портов |
| `rtp-report-interval` | Интервал RTCP-отчётов (секунды) |
| `rtp-priority` | Приоритет RTP-потока |
| `symmetric-rtp` / `SYMMETRIC_RTP` | Симметричный RTP (отправка на адрес, откуда получены данные) |
| `rtprelay_transmitter_timeout` | Таймаут передатчика в relay-режиме |
| `rtprelay_session_retry` | Повтор сессии relay |
| `rtprelay: too many errors, exit!` | Критическая ошибка relay |
| `callReferenceValue` | Ссылочное значение вызова |
| `dtmfstart` | Начало DTMF-события |
| `s%.04d@` | Формат SDP Session ID |
| `send_trysend_rtcp` | Отправка RTCP |
| `send_trysend_rtp` | Отправка RTP |

### 4.5 NAT/STUN

| Строка | Назначение |
|--------|------------|
| `stun-server` / `MG_STUN_SERVER` | Адрес STUN-сервера |
| **Файл `stunlib.c`** | Встроенная STUN-библиотека |
| `send_bindingreq` | Отправка STUN Binding Request |
| `recv_bindingresp` | Приём STUN Binding Response |
| `send_shsreq` / `recv_shsresp` | Shared Secret STUN |
| `rtpstun_session_create` | Создание STUN-сессии для RTP |
| `send try(ttl=%d) to %s:%d` | Попытка отправки STUN с TTL |
| `sendmessage` | Отправка STUN-сообщения |
| `HMAC with password: %s` | HMAC-аутентификация STUN |
| `mappedAddress is` | Разбор MappedAddress |
| `responseAddress is` | ResponseAddress |
| `sourceAddress is` | SourceAddress |
| `changedAddress is` | ChangedAddress |
| `reflectedFrom is` | ReflectedFrom |
| `ChangeRequest = %x` | ChangeRequest |
| `Username = %s` / `Password = %s` | Аутентификация STUN |
| `Error = %d %d %s` | Ошибка STUN |
| `Encoding stun message:` / `Received stun message: %d bytes` | Отладка STUN |
| `MessageIntegrity must be 20 bytes` | Проверка целостности (HMAC-SHA1) |
| `hmac-not-implemented` | HMAC не реализован в этой сборке (!) |

#### Обнаружение Echo-сервера / Port Forward:
| Строка | Назначение |
|--------|------------|
| `ECHOGWADDRRQ` | Запрос адреса Echo-шлюза |
| `ECHOSVR_ADDR` | Адрес Echo-сервера |
| `ECHOGWADDRRP` | Ответ адреса Echo-шлюза |
| `:54210` | Порт Echo-сервера (54210) |
| `GKADDR` | Адрес Gatekeeper |
| `202.96.136.145` | Жёстко вшитый DNS-сервер (China Telecom) |
| `portfwd-gwaddr` / `MG_PORTFWD_GWADDR` | Адрес шлюза для port forward |

### 4.6 Relay (проприетарный RTP-relay)

| Строка | Назначение |
|--------|------------|
| `relay-server` / `MG_RELAY_SERVER` | IP relay-сервера |
| `relay-port` / `MG_RELAY_PORT` | Порт relay-сервера |
| `relay-username` / `MG_RELAY_USER` | Логин для relay |
| `relay-password` / `MG_RELAY_PASSWD` | Пароль для relay |
| `relay-encrypt` | Шифрование relay |
| `relay-udp-ext1` | UDP-расширение 1 (режим relay) |
| `relay-bind-ext1` | Bind-расширение 1 |
| `relay-sn-needed` | Регистрация на relay с серийным номером |
| `relay-udp-over-tcp` | UDP over TCP (туннелирование) |
| `relay-V5` | Версия протокола relay (V5) |
| `relay_tcp_keepalive_timeout` | Keepalive таймаут TCP |
| `relay_cmd_timeout` | Таймаут команд relay |

### 4.7 CLI-параметры (командная строка mg)

| Параметр | Переменная окружения | Описание |
|----------|---------------------|----------|
| `-n` | — | Количество RTP-каналов (`TELPORT`) |
| `-t` | `TRANSPORT` | Транспортный уровень: `normal`, `portfwd`, `relay`, `stun` |
| `--mgdir` | `MGDIR` | Каталог UNIX-сокетов MG |
| `--mgaddr` | `MGADDR` | Адрес прослушивания (TCP/UNIX) |
| `--codec-preference` | `AUDIO_CODEC_PREFERENCE` | Приоритет кодеков (глобальный) |
| `--codec-preference0..7` | `AUDIO_CODEC_PREFERENCE0..7` | Приоритет кодеков для каждого канала |
| `--input` | `INPUT_DEVICE` | Входное устройство |
| `--rtp-tos` | — | TOS-бит для RTP-пакетов |
| `--symmetric-rtp` | `SYMMETRIC_RTP` | Симметричный RTP |
| `--relay-server` | `MG_RELAY_SERVER` | Relay-сервер |
| `--relay-port` | `MG_RELAY_PORT` | Порт relay |
| `--relay-username` | `MG_RELAY_USER` | Пользователь relay |
| `--relay-password` | `MG_RELAY_PASSWD` | Пароль relay |
| `--relay-encrypt` | — | Шифрование relay |
| `--relay-udp-ext1` | — | Relay UDP ext1 |
| `--relay-bind-ext1` | — | Relay bind ext1 |
| `--relay-sn-needed` | — | Relay с SN |
| `--relay-udp-over-tcp` | — | UDP over TCP |
| `--portfwd-gwaddr` | `MG_PORTFWD_GWADDR` | Адрес шлюза port forward |
| `--stun-server` | `MG_STUN_SERVER` | STUN-сервер |
| `--rtp-port` | `RTP_PORT` | Диапазон RTP-портов |
| `--record-device` | `RECORD_DEV` | Устройство записи |
| `--playback-device` | `PLAYBACK_DEV` | Устройство воспроизведения |
| `--silence-threshold` | `SILENCE_THRESHOLD` | Порог подавления тишины |
| `--vpdsp-device` | `VPDSP_DEV` | Устройство VoicePump DSP |
| `--hw-jitter` | `USE_HW_JITTER` | Аппаратный джиттер-буфер |
| `--packetize-period` | `PACKETIZE_PERIOD` | Период пакетизации (мс) |
| `--rtp-report-interval` | — | Интервал RTCP-отчётов |
| `--rc4-key` | — | Ключ RC4-шифрования |
| `--poll-inval` | — | Интервал poll (мс) |
| `--enable-fax` | — | Включить поддержку T.38 |
| `--enable-et263-crypt` | `MG_ET263_CRYPT` | Включить ET263 |
| `--avs-crypt-port` | `MG_AVS_CRYPT` | Порт AVS-шифрования |
| `--et263-crypt-type` | `MG_ET263_CRYPT_TYPE` | Тип ET263 |
| `--et263-crypt-depth` | `MG_ET263_CRYPT_DEP` | Глубина ET263 |
| `--t38_wait_count` | `T38_WAIT_COUNT` | Ожидание T.38 |
| `--t38_mute_timeout` | `T38_MUTE_TIMEOUT` | Таймаут тишины T.38 |
| `--t38_mode` | `T38_MODE` | Режим T.38 |
| `--enable-payload-buf` | — | Буфер DSP payload |
| `--enable-watchdog` | — | Watchdog `/dev/watchdog` |
| `--start-dsp` | — | Только запуск DSP |
| `--dsp-delay` | — | Задержка эхокомпенсатора |
| `--rtp-dt` | — | RTP dead time |

### 4.8 Конфигурационные ключи (syscfg)

| Ключ | Тип | Описание |
|------|-----|----------|
| `PREFER_CODEC1..7` | string | Предпочтительные кодеки |
| `CODEC1_DISABLE..7_DISABLE` | bool | Отключение кодека |
| `AUDIO_CODEC_PREFERENCE` | string | Строка приоритетов кодеков |
| `RTP_PORT` | string | Диапазон RTP-портов |
| `RTP_QOS` | choice | QoS: NONE/IPTOS/DIFFSERV |
| `RTP_TOS` | integer | Значение TOS |
| `RTP_DIFFSERV` | integer | Значение DiffServ |
| `SYMMETRIC_RTP` | bool | Симметричный RTP |
| `MG_NAT_TRAVERSAL` | choice | NAT: NONE/PORTFWD/RELAY/STUN |
| `MG_RELAY_SERVER` | string | Relay-сервер |
| `MG_RELAY_SERVER1..4` | string | Дополнительные relay-серверы (до 5!) |
| `MG_RELAY_PORT` | integer | Порт relay |
| `MG_RELAY_USER` | string | Пользователь relay |
| `MG_RELAY_PASSWD` | string | Пароль relay |
| `MG_RELAY_ENCRYPT` | bool | Шифрование relay |
| `MG_RELAY_MODE` | integer | Режим relay (0=обычный, 1=udp-ext1, 2=udp-over-tcp) |
| `MG_PORTFWD_TYPE` | choice | Port forward: AUTO/MANUAL |
| `MG_PORTFWD_GW` | ip | Шлюз port forward |
| `MG_STUN_SERVER` | string | STUN-сервер |
| `MG_RC4_CRYPT` | bool | RC4-шифрование |
| `MG_RC4_KEY` | string | Ключ RC4 |
| `MG_CRYPT` | string | Тип шифрования: NONE/RC4/ET263 |
| `MG_ET263_CRYPT` | bool | ET263 вкл/выкл |
| `MG_ET263_CRYPT_TYPE` | integer | Тип ET263 |
| `MG_ET263_CRYPT_DEP` | integer | Глубина ET263 |
| `MG_RTP_DT` | string | RTP dead time |
| `INBAND_DTMF` | bool | Внутриполосный DTMF |
| `SIP_OUTBAND_DTMF_TYPE` | — | Тип внеполосного DTMF |
| `VPDSP_STATE` | string | Состояние VoicePump DSP |
| `AUDIO_DEVICE` | — | Аудиоустройство |

### 4.9 Управляющий интерфейс (syscfg IPC)

| Строка | Назначение |
|--------|------------|
| `/tmp/.syscfg-server` | Сервер системной конфигурации (UNIX-сокет) |
| `.syscfg-client-%d` | Клиентский сокет (PID) |
| `%s=%s` | Формат установки значения |
| `%list` | Запрос списка |
| `%%apply` | Применить конфигурацию |
| `%%save` | Сохранить конфигурацию |
| `%%reload` | Перезагрузить конфигурацию |
| `unix_bind(): %s` | Ошибка привязки UNIX-сокета |

### 4.10 Конфигурационные файлы

| Строка | Назначение |
|--------|------------|
| `HOME` | Переменная окружения |
| `%s/.%src` | Файл конфигурации `~/.mgrc` |
| `/etc/%s.conf` | Системный конфиг `/etc/mg.conf` |
| `true` | Значение булевого параметра |
| `datalist` / `dataset` | Форматы данных конфигурации |

### 4.11 Сетевые утилиты

| Строка | Назначение |
|--------|------------|
| `/proc/net/route` | Чтение таблицы маршрутизации |
| `Iface` / `%s %x %x %d %d %d %d %x` | Парсинг маршрутов |
| `IP addr: %s` | IP-адрес интерфейса |
| `Broadcast addr: %s` | Широковещательный адрес |
| `Destination addr: %s` | Адрес назначения |
| `Subnet mask: %s` | Маска подсети |
| `P2P`, `LOOP`, `MCAST`, `BCAST` | Флаги интерфейса |
| `GATE_METRIC` / `GATE_TIMEOUT` | Метрика/таймаут шлюза |
| `USE_INTERFACE` | Выбор сетевого интерфейса |
| `%d.%d.%d.%d:%d` | Формат IP:port |
| `sockaddr` | Структура адреса |

### 4.12 Медиа-канал — ошибки и состояния

| Строка | Значение |
|--------|----------|
| `open chanel: %d %s` | Открытие канала (опечатка "chanel" в оригинале) |
| `<<no fmt>>` | Нет формата |
| `operation failed` | Операция неуспешна |
| `invalid request` | Недопустимый запрос |
| `invalid channel id` | Недопустимый ID канала |
| `no format` | Кодек не задан |
| `request event not support` | Событие не поддерживается |
| `process request failed` | Ошибка обработки запроса |
| `unknown request` | Неизвестный запрос |
| `internal error` | Внутренняя ошибка |

### 4.13 Обработка сигналов

| Строка | Значение |
|--------|----------|
| `sighandler:` | Заголовок обработчика |
| `Illegal instruction` | SIGILL |
| `Aborted` | SIGABRT |
| `Bus error` | SIGBUS |
| `Sigment fault` | SIGSEGV (опечатка "Sigment") |
| `Kill by signal` | SIGKILL |
| `Terminated` | SIGTERM |
| `scheduler_callback` | Обратный вызов планировщика |
| `Logged Call Stack` / `%d: %s[%p]` | Трассировка стека (backtrace) |
| `/proc/%u/exe` | Чтение пути исполняемого файла |

### 4.14 Отладочные / логирование

| Строка | Назначение |
|--------|------------|
| `%s:%s:%d: Warning:` | Формат предупреждения (файл:функция:строка) |
| `%s:%s():%d : %s` | Формат ошибки |
| `SYSERROR: %s(): %s: %d: %s` | Системная ошибка |
| `FAILED: %s(): %s: %d` | Сбой |
| `CHECKPOINT: %s(): %s: %d` | Контрольная точка |
| `tcp_gets(): %d` / `tcp_gets(): %s` | Отладка TCP |
| `set poll interval: %d` | Установка интервала poll |
| `using audio device: %s` | Используемое аудиоустройство |
| `cannot initialize relay sockets!` | Ошибка инициализации relay |
| `cannot initial devices!` | Ошибка инициализации устройств |
| `cannot create mg#%d` | Ошибка создания MG-канала |
| `cannot initialize audio device!` | Ошибка инициализации аудио |
| `invalid transport type: "%s"` | Неверный тип транспорта |
| `unsing default transport type: %d` | Использование умолчания (опечатка "unsing") |

### 4.15 ELF self-analysis (backtrace)

Бинарник содержит встроенный ELF-парсер для создания трассировки стека:
- `the symbol table didn't have an associated string table, wtf??`
- `there were no symbols in the symbol table!`
- `the associated string table for the symbol table is not valid!`
- `no symbols were associated to this file`
- `invalid data encoding`
- `invalid ELF file version`
- `not an executable ELF file`
- `wrong version number in ELF file`
- `program header not found`
- `section header not found`
- `file class not supported`
- `not a valid ELF file`

---

## 5. Реконструкция архитектуры и пайплайна обработки RTP

### 5.1 Общая архитектура

```
┌──────────────────────────────────────────────────────────────────────┐
│                         mg (Media Gateway)                          │
│                                                                      │
│  ┌─────────┐   ┌──────────┐   ┌────────────┐   ┌──────────────┐   │
│  │ CLI/Cfg  │──▶│ Main Loop│──▶│ Media Chan │──▶│ RTP Engine   │   │
│  │ Parser   │   │ (poll)   │   │ Manager    │   │              │   │
│  └─────────┘   └────┬─────┘   └─────┬──────┘   └──────┬───────┘   │
│                      │               │                  │           │
│                      ▼               ▼                  ▼           │
│             ┌────────────┐  ┌────────────────┐  ┌──────────────┐   │
│             │ syscfg IPC │  │ FVDSP IPC      │  │ Network I/O  │   │
│             │ client     │  │ (UNIX sockets) │  │ (UDP sockets)│   │
│             └─────┬──────┘  └───┬────────┬───┘  └──────┬───────┘   │
│                   │             │        │              │           │
│  ┌────────────────┼─────────────┼────────┼──────────────┼────────┐ │
│  │ Encryption Layer (RC4 / ET263)                                │ │
│  └───────────────────────────────────────────────────────────────┘ │
│                                                                      │
│  ┌─────────┐  ┌──────────┐  ┌─────────┐  ┌──────────────────────┐ │
│  │ STUN    │  │ Relay    │  │ PortFwd │  │ Normal (direct UDP)  │ │
│  │ Client  │  │ Client   │  │ Manager │  │                      │ │
│  └─────────┘  └──────────┘  └─────────┘  └──────────────────────┘ │
│                     Transport Layer                                  │
└──────────────────────────────────────────────────────────────────────┘
         │                                           │
         ▼                                           ▼
┌──────────────────┐                     ┌──────────────────────┐
│ FVDSP daemon     │                     │ Remote RTP endpoint  │
│ (DSP hardware)   │                     │ (SIP UA / PBX)       │
│ - Codec encode   │                     └──────────────────────┘
│ - Codec decode   │
│ - Echo cancel    │
│ - VAD/CNG        │
│ - DTMF detect    │
└──────────────────┘
```

### 5.2 Пайплайн обработки RTP (приём)

```
Сеть (UDP) ──▶ recvfrom()
    │
    ▼
[Транспортный уровень]
    ├── Normal: прямой приём UDP
    ├── STUN: recv_bindingresp → mapped address → данные
    ├── Relay: relay TCP/UDP → декапсуляция
    └── PortFwd: через echo-шлюз
    │
    ▼
[Дешифрование] rtp_decrypt()
    ├── RC4: дешифрование с ключом (rc4-key)
    └── ET263: create_et263_crypt → convert_8/16_encode / parity_exchange
    │
    ▼
[Разбор RTP-заголовка]
    - SSRC, sequence number, timestamp, payload type
    - Проверка RFC 2833 (DTMF → "DTMF %c" → событие)
    │
    ▼
[Джиттер-буфер]
    ├── Программный (в MG) — packetize-period
    └── Аппаратный (USE_HW_JITTER → DSP hw jitter)
    │
    ▼
[FVDSP IPC] → /tmp/.fvdsp_data_in%d
    - Передача payload в DSP для декодирования
    - cfg канала: codec, mr, fax, set
```

### 5.3 Пайплайн обработки RTP (передача)

```
FVDSP ──▶ /tmp/.fvdsp_data_out%d ──▶ mg
    │
    ▼
[Пакетизация]
    - Период: PACKETIZE_PERIOD (мс)
    - Формирование RTP-заголовка
    - DTMF: RFC 2833 payload / SIP INFO (INBAND_DTMF / SIP_OUTBAND_DTMF_TYPE)
    │
    ▼
[Шифрование]
    ├── RC4
    └── ET263
    │
    ▼
[Транспортный уровень]
    ├── Normal: sendto() на UDP-сокет
    ├── Symmetric RTP: отправка на адрес источника
    ├── STUN: send_bindingreq → mapped → send
    ├── Relay: relay tunnel (send_trysend_rtp, send_trysend_rtcp)
    └── PortFwd: через шлюз
    │
    ▼
[RTCP] media_channel_do_rtcp()
    - Формат: rtpstat %s %d %d %d %d %d %d %d %d %08lx
    - Интервал: rtp-report-interval
```

### 5.4 Пайплайн T.38 (факс)

```
Детекция факса → "cfg %d fax %d" → переключение канала
    │
    ▼
[T.38 режим]
    - t38_mode: режим работы
    - t38_wait_count: ожидание
    - t38_mute_timeout: таймаут тишины
    - Кодеки: t38fax, или alaw/ulaw для G.711 passthrough
    │
    ▼
fax %d → DSP обработка факса
```

---

## 6. Согласование кодеков (Codec Negotiation)

### Логика выбора кодека:

1. **Глобальный приоритет**: `AUDIO_CODEC_PREFERENCE` — строка вида `ulaw,alaw,g729,g723h,g723l,g729a,!gsm`
   - Префикс `!` = кодек отключён
   
2. **Per-channel override**: `codec-preference0..7` позволяет задать приоритет для каждого из 8 каналов

3. **Из start_mg:**
   ```
   PREFER_CODEC1..6 → codec1..6
   CODEC1_DISABLE..6_DISABLE → !codec
   setsyscfg AUDIO_CODEC_PREFERENCE="$codec1,$codec2,...,!gsm"
   ```

4. **Факс-каналы:**
   - T.38: `--codec-preference0=<основные>,t38` + `--enable-fax`
   - G.711 passthrough: `--codec-preference0=alaw,ulaw`

5. **DSP-команда**: `cfg %d codec %d %d` — задание кодека DSP-каналу (числовые ID)

### Поддерживаемые кодеки (полный список):

| Строка в MG | Кодек | Bitrate |
|-------------|-------|---------|
| `ulaw` | G.711 μ-law | 64 kbps |
| `alaw` | G.711 A-law | 64 kbps |
| `g7231` | G.723.1 | 5.3/6.3 kbps |
| `g723l` | G.723.1 low | 5.3 kbps |
| `g723h` | G.723.1 high | 6.3 kbps |
| `g729` | G.729 | 8 kbps |
| `g729a` | G.729 Annex A | 8 kbps |
| `g729ab` | G.729 A/B (VAD) | 8 kbps |
| `gsm` | GSM FR | 13 kbps |
| `t38fax` | T.38 fax relay | variable |
| `rfc2833` | DTMF events | — |

---

## 7. Интерфейс DSP (FVDSP / ACI)

### Архитектура взаимодействия MG ↔ FVDSP

MG **не** производит кодирование/декодирование аудио — это делает отдельный демон `fvdsp`, управляющий DSP-аппаратурой. Общение через **4 пары UNIX-сокетов** на каждый канал:

| Сокет | Направление | Назначение |
|-------|-------------|------------|
| `/tmp/.fvdsp_mgcmd%d` | MG → DSP | Управляющие команды |
| `/tmp/.fvdsp_cmd_in` | DSP → MG | Ответы/события (один на все каналы) |
| `/tmp/.fvdsp_data_in%d` | MG → DSP | Аудио-данные для кодирования |
| `/tmp/.fvdsp_data_out%d` | DSP → MG | Закодированные/декодированные данные |

### Команды протокола FVDSP:

```
open <channel>                  — открыть DSP-канал
close <channel>                 — закрыть DSP-канал
cfg <ch> codec <codec_id> <param>  — задать кодек
cfg <ch> mr <rate>              — задать media rate
cfg <ch> fax <mode>             — переключить в режим факса
cfg <ch> set                    — применить конфигурацию
remote <ch>                     — задать параметры удалённой стороны
mstop <ch>                      — остановить медиа-поток
fax <ch>                        — начать факс-обмен
```

### DSP-устройство:

- `VPDSP_DEV` — путь к устройству VoicePump DSP (например `/dev/vpdsp`)
- `AUDIO_DEVICE` — аудиоустройство
- `FVDSP_DEV%d_TYPE` — тип DSP (SLIC — для аналоговых FXS-линий)
- `VPDSP_VAD` — всегда включать VAD (Voice Activity Detection)

---

## 8. Реализация джиттер-буфера

Обнаружены **два режима** джиттер-буфера:

### 8.1 Программный джиттер-буфер (по умолчанию)
- Реализован внутри MG
- Управляется параметрами:
  - `packetize-period` / `PACKETIZE_PERIOD` — период пакетизации в миллисекундах
  - Основной цикл: `poll()` с настраиваемым интервалом (`--poll-inval`)
  - `setitimer()` — таймер для точной пакетизации
  
### 8.2 Аппаратный джиттер-буфер
- `hw-jitter` / `USE_HW_JITTER` — использование аппаратного джиттер-буфера DSP
- Передача управления буферизацией DSP-процессору
- `enable-payload-buf` — буфер DSP payload (вероятно, дополнительная буферизация)

### Параметры, влияющие на джиттер:
- `poll-inval` — интервал poll (по умолчанию увеличивается до 25 мс при >6 каналах)
- `silence-threshold` / `SILENCE_THRESHOLD` — порог подавления тишины (сжатие тишины)

---

## 9. Шифрование RTP — детальный анализ

### 9.1 RC4

- Стандартный потоковый шифр RC4
- Ключ задаётся через `--rc4-key=<key>` или `MG_RC4_KEY` (или наследуется от `SIP_RC4_KEY`)
- Применяется к RTP payload (не заголовку)
- `rtp_decrypt(): cc=%d` — функция дешифрования с отладкой

### 9.2 ET263 (проприетарный)

Модуль `et263_crypt.c` реализует проприетарное шифрование с несколькими режимами:

**Типы (et263-crypt-type):**
- 8-байтное преобразование (`create_convert_8`, `convert_8_encode`)
- 16-байтное преобразование (`create_convert_16`, `convert_16_encode`)
- Обмен чётности 8 байт (`create_parity_exchange_8`, `parity_exchange_8_encode`)
- Обмен чётности 16 байт (`create_parity_exchange_16`, `parity_exchange_16_encode`)

**Глубина (et263-crypt-depth):** настраиваемая глубина шифрования

**Ограничения:**
- Минимальная длина данных = 4 байта
- При ошибке создания → предупреждение, продолжение без шифрования

### 9.3 AVS Crypt
- `avs-crypt-port` / `MG_AVS_CRYPT` — шифрование RTP для AVS-сервера
- Отдельный порт для шифрованного трафика

### 9.4 Согласование шифрования
- SIP-заголовок `X-ACrypt` — сигнализация типа шифрования удалённой стороне
- Поддерживаемые значения: `ET263`, `VOS2000`

---

## 10. Стартовый скрипт `start_mg`

### Логика запуска:

```
1. Определение числа каналов (-n ${TELPORT})
2. При TELPORT > 6: poll-inval=25, enable-watchdog
3. Формирование строки кодеков из PREFER_CODEC1..6
4. Настройка факса на линиях 1-2 (T38 / G711)
5. Выбор NAT traversal (NONE/PORTFWD/RELAY/STUN)
6. Выбор шифрования (NONE/RC4/ET263)
7. Настройка relay (до 5 серверов, шифрование, режим)
8. Настройка QoS (IPTOS/DIFFSERV)
9. RTP-отчёты (если включён лог и окно мониторинга > 2 сек)
10. exec /usr/bin/mg $params $rtp_tos $transport $log_params $rtp_dt_params
```

---

## 11. Управляющий интерфейс (runtime)

MG создаёт UNIX-сокет `/tmp/mg%d` (или `%s/mg%%d` в каталоге `--mgdir`) для каждого канала, через который `sipcli` (SIP-клиент) отправляет команды управления медиа:

- `start` — начать RTP-сессию
- `remote` — задать удалённый адрес
- `mstop` — остановить
- `fax` — переключить в режим факса
- `rtpstat` — запросить статистику

Также MG может слушать на TCP-адресе (`--mgaddr`, `tcp:` или `unix:`).

---

## 12. Особенности и наблюдения

### Опечатки в исходном коде:
- `chanel` вместо `channel`
- `unsing` вместо `using`
- `Sigment fault` вместо `Segmentation fault`
- `recieved` вместо `received`

### Жёстко вшитые значения:
- `202.96.136.145` — DNS-сервер China Telecom (указывает на китайское происхождение)
- `:54210` — порт Echo-сервера
- GSM-кодек по умолчанию отключён (`!gsm`)

### Безопасность:
- RC4 — устаревший и небезопасный шифр
- ET263 — проприетарный, нестандартный, криптографическая стойкость неизвестна
- Пароли relay передаются в командной строке (видны через `/proc`)
- `hmac-not-implemented` — HMAC для STUN не реализован
- STUN-аутентификация в открытом виде (`Username = %s`, `Password = %s`)

### Поддержка платформы:
- До 8 одновременных RTP-каналов (индексы 0-7 в codec-preference)
- Соответствует GST1610 (16-портовый GSM-шлюз, но MG обслуживает до 8 на экземпляр)
- Watchdog включается при >6 каналах
- `sched_setscheduler()` — работа в реальном времени

### Компиляция:
- GCC 3.3.5 (uClibc) — очень старый тулчейн
- 34 объектных файла (33 × GCC 3.3.5 + 1 × GCC 3.3.2 Debian)
- ARM 32-bit, OABI совместимый

---

## 13. Полный список всех 538 строк (для справки)

Все извлечённые строки сохранены в файле `c:\goip\mg_strings.txt`.

Сгруппированный подсчёт:
- Импортируемые символы (libc/uClibc): ~85 строк
- IPC/DSP (FVDSP): ~15 строк  
- Кодеки: ~12 строк
- Шифрование (RC4/ET263): ~25 строк
- RTP/RTCP: ~15 строк
- NAT/STUN (stunlib.c): ~45 строк
- Relay: ~15 строк
- CLI-параметры и описания: ~80 строк
- Конфигурационные ключи: ~40 строк
- Сетевые утилиты: ~15 строк
- Ошибки/отладка: ~30 строк
- ELF self-parse (backtrace): ~15 строк
- Обработчики сигналов: ~8 строк
- GCC-версии (comment): ~38 строк
- Имена секций (shstrtab): ~22 строк
- Прочие служебные: ~98 строк
