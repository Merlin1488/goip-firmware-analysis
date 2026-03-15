# Глубокий статический анализ `radmcli` (GoIP GST1610 Remote Admin Client)

## 1. Общая информация о файле

| Параметр | Значение |
|---|---|
| **Путь** | `c:\goip\fw_new\squashfs-root\usr\bin\radmcli` |
| **Размер** | 51 296 байт (≈50 KB) |
| **Формат** | ELF 32-bit LSB executable |
| **Архитектура** | ARM (machine=40) |
| **Endianness** | Little Endian |
| **OS/ABI** | 0x61 (ARM EABI) |
| **Entry Point** | `0x000094DC` |
| **Компилятор** | GCC 3.3.2/3.3.5 (Debian), uClibc |
| **Версия** | `version:2.0` |

### ELF Header (hex dump первых 64 байт)
```
7F 45 4C 46 01 01 01 61 00 00 00 00 00 00 00 00
02 00 28 00 01 00 00 00 DC 94 00 00 34 00 00 00
A0 C4 00 00 02 00 00 00 34 00 20 00 05 00 28 00
18 00 17 00 06 00 00 00 34 00 00 00 34 80 00 00
```

---

## 2. Карта секций ELF

| # | Секция | Тип | VAddr | Offset | Размер | Флаги |
|---|--------|-----|-------|--------|--------|-------|
| 0 | (null) | NULL | 0x00000000 | 0x000000 | 0x000000 | — |
| 1 | `.interp` | PROGBITS | 0x000080D4 | 0x0000D4 | 0x000014 | A |
| 2 | `.hash` | HASH | 0x000080E8 | 0x0000E8 | 0x000314 | A |
| 3 | `.dynsym` | DYNSYM | 0x000083FC | 0x0003FC | 0x000620 | A |
| 4 | `.dynstr` | STRTAB | 0x00008A1C | 0x000A1C | 0x000306 | A |
| 5 | `.gnu.version` | VERSYM | 0x00008D22 | 0x000D22 | 0x0000C4 | A |
| 6 | `.gnu.version_r` | VERNEED | 0x00008DE8 | 0x000DE8 | 0x000020 | A |
| 7 | `.rel.dyn` | REL | 0x00008E08 | 0x000E08 | 0x000018 | A |
| 8 | `.rel.plt` | REL | 0x00008E20 | 0x000E20 | 0x0002A0 | A |
| 9 | `.init` | PROGBITS | 0x000090C0 | 0x0010C0 | 0x000018 | AX |
| 10 | `.plt` | PROGBITS | 0x000090D8 | 0x0010D8 | 0x000404 | AX |
| 11 | `.text` | PROGBITS | 0x000094DC | 0x0014DC | 0x008E60 | AX |
| 12 | `.fini` | PROGBITS | 0x0001233C | 0x00A33C | 0x000014 | AX |
| 13 | `.rodata` | PROGBITS | 0x00012350 | 0x00A350 | 0x00105C | A |
| 14 | `.eh_frame` | PROGBITS | 0x000133AC | 0x00B3AC | 0x000004 | A |
| 15 | `.ctors` | PROGBITS | 0x0001C000 | 0x00C000 | 0x000008 | WA |
| 16 | `.dtors` | PROGBITS | 0x0001C008 | 0x00C008 | 0x000008 | WA |
| 17 | `.jcr` | PROGBITS | 0x0001C010 | 0x00C010 | 0x000004 | WA |
| 18 | `.dynamic` | DYNAMIC | 0x0001C014 | 0x00C014 | 0x0000D0 | WA |
| 19 | `.got` | PROGBITS | 0x0001C0E4 | 0x00C0E4 | 0x000160 | WA |
| 20 | `.data` | PROGBITS | 0x0001C244 | 0x00C244 | 0x00001C | WA |
| 21 | `.bss` | NOBITS | 0x0001C260 | 0x00C260 | 0x004D60 | WA |
| 22 | `.comment` | PROGBITS | 0x00000000 | 0x00C260 | 0x000190 | — |
| 23 | `.shstrtab` | STRTAB | 0x00000000 | 0x00C3F0 | 0x0000B0 | — |

**Ключевые наблюдения:**
- `.text` = 36 448 байт (код)
- `.rodata` = 4 188 байт (строки/константы)
- `.bss` = 19 808 байт (неинициализированные данные, включая буферы туннеля)
- Нет секции `.symtab` — символы стрипнуты, остались только динамические

---

## 3. Извлечённые строки по категориям (всего 341 строка)

### 3.1 Сеть (Network)

| Адрес | Строка | Описание |
|-------|--------|----------|
| 0x00AEE4 | `tcp_connect` | Функция TCP-подключения |
| 0x00AF04 | `tcp_bind` | Привязка TCP-сокета |
| 0x00AF10 | `tcp_listen` | Прослушивание TCP |
| 0x00AF1C | `udp_connect` | UDP-подключение |
| 0x00AF28 | `udp_bind` | Привязка UDP-сокета |
| 0x00AF34 | `unix_listen` | Unix-сокет прослушивание |
| 0x00AF40 | `unix_connect` | Unix-сокет подключение |
| 0x00AF50 | `unix_datagram_listen` | Unix datagram |
| 0x00AF68 | `send_ctlmsg` | Отправка управляющего сообщения |
| 0x00AF74 | `recv_ctlmsg` | Получение управляющего сообщения |
| 0x00AF80 | `broadcast` | Широковещание |
| 0x00AF8C | `get_ifi_info` | Информация о сетевых интерфейсах |
| 0x00AFE0 | `/proc/net/route` | Таблица маршрутов |
| 0x00B000 | `findsaddr` | Поиск исходного адреса |
| 0x00B1B0 | `getifaddr` | Получение адреса интерфейса |
| 0x00B1D8 | `getsockifaddr` | Адрес сокета интерфейса |
| 0x00B1E8 | `USE_INTERFACE` | Конфигурация интерфейса |
| 0x00B1F8 | `port=%d` | Форматирование порта |

### 3.2 Аутентификация и криптография (Authentication / Encryption)

| Адрес | Строка | Описание |
|-------|--------|----------|
| 0x00A504 | `RADMIN_KEY` | Конфигурационный ключ шифрования |
| 0x00A510 | **`dbl#admin`** | **Ключ шифрования по умолчанию (hardcoded!)** |
| 0x00A51C | `RADMIN_ID` | Идентификатор устройства |
| 0x00A52C | `RADMIN_SERVER` | Адрес сервера управления |
| 0x00A53C | `RADMIN_PORT` | Порт сервера управления |
| 0x00A4F8 | `RADM_WLIST` | Белый список серверов |
| 0x00A4BC | `1234567890` | Набор цифр (валидация) |
| 0x00A4C8 | `1234567890.` | Набор цифр с точкой (валидация IP) |

**Критическая находка:** Ключ шифрования по умолчанию — **`dbl#admin`**. Это жёстко зашитое значение, используемое если `RADMIN_KEY` не задан.

### 3.3 Аргументы командной строки (CLI args)

| Адрес | Строка | Описание |
|-------|--------|----------|
| 0x00A5A4 | `usage: radmc -r <remote_ip>:<port> -al <RADMIN_local_ip>:<port> -ll <RLOGIN_local_ip>:<port> -k <encrypt_key> -i <id> -t <timeout>` | Полная строка использования |
| 0x00A548 | `radmcli: arg=%s` | Отладка аргументов |
| 0x00A628 | `version:2.0` | Версия |
| 0x00A648 | `radmc` | Имя приложения |

**Разбор аргументов:**
- `-r SERVER:PORT` — адрес удалённого сервера управления
- `-al IP:PORT` — локальный адрес для RADMIN (HTTP-доступ, обычно 127.0.0.1:80)
- `-ll IP:PORT` — локальный адрес для RLOGIN (telnet/SSH, обычно 127.0.0.1:13000 или :23)
- `-k KEY` — ключ шифрования
- `-i ID` — идентификатор устройства
- `-t TIMEOUT` — таймаут keepalive (по умолчанию 30 секунд)

### 3.4 IPC и системные пути

| Адрес | Строка | Описание |
|-------|--------|----------|
| 0x00A38C | `/etc/ramdcli` | **FIFO-файл для IPC** |
| 0x00B26E | `/tmp/.syscfg-server` | Unix-сокет syscfg (конфигурация) |
| 0x00B2F0 | `.syscfg-client-%d` | Клиентский сокет syscfg |
| 0x00A874 | `/dev/ttyS0` | Последовательный порт |
| 0x00A900 | `/dev/audio` | Аудиоустройство |
| 0x00AAB0 | `/proc/%u/exe` | Путь к исполняемому файлу |
| 0x00ACB4 | `/proc/%d/maps` | Карта памяти процесса |
| 0x00AA58 | `/etc/%s.conf` | Файл конфигурации |
| 0x00AA4C | `%s/.%src` | RC-файл в домашней директории |

### 3.5 Туннельный протокол (Tunneling Protocol)

| Адрес | Строка | Описание |
|-------|--------|----------|
| 0x00A684 | `radmc_callback` | Callback-функция обработки данных |
| 0x00A694 | `radmc.c` | Исходный файл протокола |
| 0x00A710 | `radmc_reconnect` | Переподключение к серверу |
| 0x00A79C | `radmc_keepalive` | Поддержание соединения |
| 0x00A7AC | `radmc_timeout_callback` | Обработка таймаута |
| 0x00A7C4 | `radmc_create` | Создание экземпляра клиента |
| 0x00A674 | `radmc_release` | Освобождение ресурсов |
| 0x00A408 | `psock_read_callback` | Чтение с проксирующего сокета |
| 0x00A3F4 | `tsock_read_callback` | Чтение с туннельного сокета |
| 0x00A3C4 | `fwd_count_timer_init` | Инициализация таймера пересылки |
| 0x00A3B0 | `fwd_count_timeout` | Таймаут счётчика пересылки |
| 0x00A740 | `RADMIN: %s` | Логирование RADMIN-канала |
| 0x00A74C | `TELNET: %s` | Логирование TELNET-канала |
| 0x00A7D4 | `RADMIN local addr: %s:%d` | Локальный адрес HTTP-туннеля |
| 0x00A7F0 | `RLOGIN local addr: %s:%d` | Локальный адрес telnet-туннеля |
| 0x00A350 | `working` | Состояние — работает |
| 0x00A358 | `idle` | Состояние — простой |
| 0x00A968 | `dispatch_sock_events` | Диспетчер событий сокетов |
| 0x00A98C | `app_run` | Главный цикл |

### 3.6 Hardcoded серверные адреса и порты

| Адрес | Строка | Назначение |
|-------|--------|------------|
| 0x00A41C | **`118.140.127.90`** | Белый список серверов (#1) — Гонконг |
| 0x00A42C | **`47.242.142.229`** | Белый список серверов (#2) — Alibaba Cloud HK |
| 0x00A43C | **`202.104.186.90`** | Белый список серверов (#3) — Шэньчжэнь, Китай |
| 0x00AD28 | **`fspipsev.net`** | Домен для отправки баг-репортов (email) |
| 0x00AD38 | **`61.141.247.7`** | IP SMTP-сервера для баг-репортов |
| 0x00B114 | **`202.96.136.145`** | DNS/echo-сервер |
| 0x00B124 | **`:54210`** | Порт echo-сервера |
| Порт `1920` | **RADMIN** (по умолчанию) | Сервер удалённого управления |
| Порт `13000` | **RLOGIN/telnet** (по умолчанию) | Локальный telnet |

### 3.7 Сообщения об ошибках / отладка

| Адрес | Строка |
|-------|--------|
| 0x00A360 | `try to send fifo:%s` |
| 0x00A378 | `can not open fifo` |
| 0x00A39C | `Failed to open fifo` |
| 0x00A3DC | `%s():%d: CHECK POINT` |
| 0x00A44C | `gethostbyname(%s):%m` |
| 0x00A464 | `can not get ip from:%s` |
| 0x00A47C | `white server:%s, %u` |
| 0x00A494 | `got white server:%s` |
| 0x00A4AC | `can not get ip` |
| 0x00A568 | `invailid address: %s` |
| 0x00A58C | `cannot parse arg: %s` |
| 0x00A650 | `cannot create radmc` |
| 0x00A69C | `recv error:%m` |
| 0x00A6AC | `cannot create socket: %m` |
| 0x00A6C8 | `cannot connect to %s:%d` |
| 0x00A720 | `cannot connect to %s:%d: %m` |
| 0x00A758 | `send error: %m, exit!!!!` |
| 0x00A774 | `send RADMIN: %s` |
| 0x00A788 | `send RLOGIN: %s` |
| 0x00A80C | `SIGPIPE!` |
| 0x00A894 | `SIGALRM caught!!!!!!` |
| 0x00A8AC | `signal error: %s` |
| 0x00A8C0 | `Aborted` |
| 0x00A8C8 | `Illegal instruction` |
| 0x00A8DC | `Sigment fault` |
| 0x00A8EC | `Kill by %d` |
| 0x00A920 | `exiting ...` |
| 0x00A980 | `error: %d` |
| 0x00AD48 | `bugreport: E%.03d cannot connect to server!` |
| 0x00AD78 | `bugreport: E%.03d: connection error` |
| 0x00ADA4 | `bugreport: E%.03d: server error: %s` |
| 0x00AE3C | `log buffer overflow!` |
| 0x00AEBC | `Logged Call Stack` |
| 0x00B030 | `no matching route!` |
| 0x00B044 | `junk in buffer` |
| 0x00B12C | `echo server address is not correct.` |
| 0x00B200 | `cannot get sockport: %s` |
| 0x00B324 | `write failed!` |
| 0x00B35C | `requested block size exceeds the maximun limit(%d): %d` |

### 3.8 Конфигурационные ключи (syscfg)

| Адрес | Ключ | Описание |
|-------|------|----------|
| 0x00A504 | `RADMIN_KEY` | Ключ шифрования туннеля |
| 0x00A51C | `RADMIN_ID` | ID устройства |
| 0x00A52C | `RADMIN_SERVER` | Адрес сервера |
| 0x00A53C | `RADMIN_PORT` | Порт сервера |
| 0x00A4F8 | `RADM_WLIST` | Белый список серверов |
| 0x00B0FC | `ECHOSVR_ADDR` | Адрес echo-сервера |
| 0x00B184 | `GATE_METRIC` | Метрика шлюза |
| 0x00B190 | `GATE_TIMEOUT` | Таймаут шлюза |
| 0x00B1E8 | `USE_INTERFACE` | Сетевой интерфейс |
| 0x00A938 | `DEBUG_SERVER` | Сервер отладки |
| 0x00A90C | `USERNAME` | Имя пользователя |
| 0x00A918 | `USER` | Пользователь |
| 0x00AA44 | `HOME` | Домашний каталог |

Из `common.def`:
```
RADMIN_SERVER  string           # Адрес сервера управления
RADMIN_PORT    string           # Порт (по умолчанию 1920)
RADMIN_ID      string           # Идентификатор устройства
RADMIN_KEY     string           # Ключ шифрования
RADMIN_ENABLE  bool             # Включить/выключить
RADM_WLIST     -n string        # Белый список серверов (массив)
HTTP_PORT      integer          # HTTP-порт (по умолчанию 80)
FTN            -n bool          # Режим FTN (telnet порт 23 вместо 13000)
```

### 3.9 Имена функций (из строк исходных файлов)

| Функция | Исходный файл | Роль |
|---------|---------------|------|
| `radmc_create` | `radmc.c` | Инициализация туннельного клиента |
| `radmc_release` | `radmc.c` | Освобождение ресурсов |
| `radmc_callback` | `radmc.c` | Обработка данных туннеля |
| `radmc_reconnect` | `radmc.c` | Переподключение при обрыве |
| `radmc_keepalive` | `radmc.c` | Keepalive-пакеты |
| `radmc_timeout_callback` | `radmc.c` | Обработка таймаута |
| `tsock_read_callback` | `radmc.c` | Чтение из туннельного сокета |
| `psock_read_callback` | `radmc.c` | Чтение из проксирующего сокета |
| `fwd_count_timer_init` | `radmc.c` | Инициализация таймера пересылки |
| `fwd_count_timeout` | `radmc.c` | Таймаут счётчика |
| `tcp_connect` | `net.c` | TCP-подключение |
| `udp_connect` | `net.c` | UDP-подключение |
| `unix_listen` | `net.c` | Unix-сокет прослушивание |
| `unix_connect` | `net.c` | Unix-сокет подключение |
| `dispatch_sock_events` | `app.c` | Диспетчер событий |
| `app_run` | `app.c` | Главный цикл |
| `app_atexit` | `app.c` | Обработчик выхода |
| `send_debug_message` | `app.c` | Отправка отладки |
| `echo_gateway_addr` | — | Echo-запрос адреса шлюза |
| `is_valid_addr` | `sockaddr.c` | Валидация адреса |
| `memblk_alloc` | `utils.c` | Аллокатор блоков памяти |

### 3.10 Встроенный механизм багрепортов (email)

| Адрес | Строка |
|-------|--------|
| 0x00ADCC | `HELO fspipsev.net` |
| 0x00ADE4 | `MAIL FROM:<bug@fspipsev.net>` |
| 0x00AE04 | `RCPT TO:<bug@fspipsev.net>` |
| 0x00AE24 | `DATA` |
| 0x00AE34 | `QUIT` |

**Бинарник содержит встроенный SMTP-клиент** для отправки багрепортов на `bug@fspipsev.net` через сервер `61.141.247.7`.

### 3.11 ELF self-analysis (backtrace)

| Адрес | Строка |
|-------|--------|
| 0x00AADC | `no symbols were associated to this file` |
| 0x00AB08 | `the symbol table didn't have an associated string table, wtf??` |
| 0x00AB48 | `the associated string table for the symbol table is not valid!` |
| 0x00AB88 | `there were no symbols in the symbol table!` |
| 0x00ABC4 | `not a valid ELF file` |
| 0x00ABDC | `file class not supported` |
| 0x00ABF8 | `invalid data encoding` |
| 0x00AC10 | `invalid ELF file version` |
| 0x00AC2C | `not an executable ELF file` |
| 0x00AC48 | `wrong version number in ELF file` |
| 0x00AC6C | `program header not found` |
| 0x00AC88 | `section header not found` |

Бинарник содержит **встроенный ELF-парсер** для самоанализа стека вызовов при крашах.

---

## 4. Стартовый скрипт `start_radm`

```bash
#!/bin/sh

[ -z "${RADMIN_KEY}" ] && RADMIN_KEY="dbl#admin"          # Ключ по умолчанию
[ -z "${RADMIN_PORT}" ] && setsyscfg RADMIN_PORT=1920     # Порт по умолчанию
eval "id=${RADMIN_ID}"

HTTP_PORT=`getsyscfg HTTP_PORT`
[ -z ${HTTP_PORT} ] && HTTP_PORT="80"

TPORT=13000                                                # Порт telnet по умолчанию
[ "${FTN}" = "1" ] && TPORT=23                            # Если FTN=1, используем стандартный telnet

exec /usr/bin/radmcli \
  -r ${RADMIN_SERVER}:${RADMIN_PORT} \
  -al 127.0.0.1:$HTTP_PORT \
  -ll 127.0.0.1:$TPORT \
  -k "${RADMIN_KEY}" \
  -i "$id" \
  -t 30
```

---

## 5. Протокол обратного туннеля — полная реконструкция

### Архитектура

```
┌─────────────────┐                          ┌──────────────────────┐
│ GoIP устройство  │                          │  Сервер управления    │
│                  │                          │  (RADMIN_SERVER:PORT) │
│ ┌──────────────┐ │    TCP reverse tunnel    │                      │
│ │ HTTP (:80)   │◄├──────────────────────────┤  Оператор/Админ      │
│ │ веб-UI       │ │    Шифрование: XOR-like  │                      │
│ └──────────────┘ │    с ключом RADMIN_KEY   │                      │
│ ┌──────────────┐ │                          │                      │
│ │ Telnet/SSH   │◄├──────────────────────────┤                      │
│ │ (:13000/:23) │ │    Второй канал          │                      │
│ └──────────────┘ │                          │                      │
└─────────────────┘                          └──────────────────────┘
```

### Последовательность установления туннеля

1. **Инициализация** (`radmc_create`)
   - Парсинг аргументов: удалённый сервер, локальные адреса, ключ, ID, таймаут
   - Резолв DNS через `gethostbyname()`
   - Проверка белого списка серверов (`RADM_WLIST`)

2. **Подключение** (`tcp_connect` → `connect()`)
   - Клиент инициирует **исходящее TCP-соединение** к `RADMIN_SERVER:RADMIN_PORT`
   - Это **обратный туннель** — устройство само звонит серверу

3. **Аутентификация**
   - Отправка идентификатора (`RADMIN_ID`) и ключа (`RADMIN_KEY`)
   - Шифрование трафика (проприетарное)

4. **Проксирование (два канала)**
   - **RADMIN**: Туннель → `127.0.0.1:HTTP_PORT` (HTTP веб-интерфейс)
   - **RLOGIN**: Туннель → `127.0.0.1:TPORT` (telnet/SSH)

5. **Мультиплексирование**
   - `dispatch_sock_events` + `select()`/`poll()` — event-driven цикл
   - `send_ctlmsg` / `recv_ctlmsg` — управляющие сообщения

---

## 6. Шифрование туннельного трафика

- **Нет использования**: SSL/TLS, OpenSSL, SHA, AES, RSA — ни одна криптографическая библиотека не импортирована
- **Используется**: `random`, `srand`, `time` — генерация псевдослучайных данных
- **Ключ**: передаётся через `-k` (по умолчанию `dbl#admin`)

**Вывод: используется проприетарное симметричное шифрование** (вероятно XOR с ключом). **Это НЕ криптографически стойкое шифрование.**

---

## 7. Механизм Keepalive / Reconnect

| Компонент | Описание |
|-----------|----------|
| `radmc_keepalive` | Периодическая отправка keepalive-пакетов |
| `radmc_timeout_callback` | Обработка таймаута |
| `radmc_reconnect` | Переподключение при обрыве |
| `setitimer` | Системный таймер (SIGALRM) |
| `-t 30` | Интервал keepalive = 30 секунд |

**Бесконечный цикл переподключений (нет лимита попыток).**

---

## 8. Протокол управления (Command & Control)

```
┌──── Один TCP-сокет к серверу ────┐
│  ┌─ RADMIN ──────────────────┐   │
│  │ → HTTP (:80) проксирование│   │
│  └───────────────────────────┘   │
│  ┌─ RLOGIN ──────────────────┐   │
│  │ → Telnet (:13000) проксир.│   │
│  └───────────────────────────┘   │
│  ┌─ Control ─────────────────┐   │
│  │ Keepalive, статус, команды│   │
│  └───────────────────────────┘   │
└──────────────────────────────────┘
```

---

## 9. Итоговая оценка безопасности

| Проблема | Критичность |
|----------|-------------|
| Ключ по умолчанию `dbl#admin` жёстко зашит | **КРИТИЧЕСКАЯ** |
| Проприетарное шифрование (не TLS, вероятно XOR) | **ВЫСОКАЯ** |
| Три жёстко зашитых IP серверов в Китае | **ВЫСОКАЯ** |
| Встроенный SMTP-клиент отправляет данные на fspipsev.net | **СРЕДНЯЯ** |
| Бесконечный reconnect без лимита | **СРЕДНЯЯ** |
| eval в shell-скрипте (`eval "id=${RADMIN_ID}"`) | **СРЕДНЯЯ** (инъекция) |
| Нет проверки сертификатов/TLS | **ВЫСОКАЯ** |
| Полный удалённый доступ к HTTP + telnet через обратный туннель | **Архитектурная** |
