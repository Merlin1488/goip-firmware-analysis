# Глубокий статический анализ smb_module (GoIP GST1610)

**Файл:** `fw_new/squashfs-root/usr/bin/smb_module`  
**Назначение:** Клиент SIM-банка — подключает GoIP к удалённому SIM Bank серверу, обеспечивая удалённую коммутацию SIM-карт через TCP/UDP.

---

## 1. Заголовок ELF и метаданные

| Параметр | Значение |
|----------|----------|
| **Размер файла** | 67 916 байт (66.3 КБ) |
| **Формат** | ELF 32-bit LSB executable |
| **Архитектура** | ARM (machine=40, EI_OSABI=0x61/ARM_AEABI) |
| **Порядок байт** | Little-endian |
| **Entry point** | `0x00009570` (`_start`) |
| **Линковщик** | `/lib/ld-uClibc.so.0` |
| **Компилятор** | GCC 3.3.2/3.3.5 (Debian) |
| **Зависимости** | `libgcc_s.so.1`, `libc.so.0` (uClibc) |

### Hex-дамп первых 64 байт (ELF Header)
```
7F 45 4C 46 01 01 01 61 00 00 00 00 00 00 00 00
02 00 28 00 01 00 00 00 70 95 00 00 34 00 00 00
8C 05 01 00 02 00 00 00 34 00 20 00 05 00 28 00
18 00 17 00 06 00 00 00 34 00 00 00 34 80 00 00
```

---

## 2. Карта сегментов (Program Headers)

| # | Тип | Offset | Vaddr | FileSize | MemSize | Flags |
|---|-----|--------|-------|----------|---------|-------|
| 0 | PHDR | 0x000034 | 0x00008034 | 0xA0 | 0xA0 | R+X |
| 1 | INTERP | 0x0000D4 | 0x000080D4 | 0x14 | 0x14 | R |
| 2 | LOAD (text) | 0x000000 | 0x00008000 | 0xFE60 | 0xFE60 | R+X |
| 3 | LOAD (data) | 0x010000 | 0x00018000 | 0x2CC | 0x4FB4 | R+W |
| 4 | DYNAMIC | 0x010014 | 0x00018014 | 0xD0 | 0xD0 | R+W |

## 3. Карта секций (Section Headers)

| # | Имя | Тип | Addr | Offset | Размер | Описание |
|---|-----|-----|------|--------|--------|----------|
| 01 | `.interp` | PROGBITS | 0x80D4 | 0x00D4 | 0x14 | Путь линковщика |
| 02 | `.hash` | HASH | 0x80E8 | 0x00E8 | 0x320 | Хеш-таблица символов |
| 03 | `.dynsym` | DYNSYM | 0x8408 | 0x0408 | 0x650 | Динамические символы (101 запись) |
| 04 | `.dynstr` | STRTAB | 0x8A58 | 0x0A58 | 0x31E | Строки символов |
| 07 | `.rel.dyn` | REL | 0x8E60 | 0x0E60 | 0x18 | Релокации данных |
| 08 | `.rel.plt` | REL | 0x8E78 | 0x0E78 | 0x2B8 | Релокации PLT |
| 09 | `.init` | PROGBITS | 0x9130 | 0x1130 | 0x18 | Код инициализации |
| 10 | `.plt` | PROGBITS | 0x9148 | 0x1148 | 0x428 | PLT (87 записей) |
| **11** | **`.text`** | PROGBITS | **0x9570** | **0x1570** | **0xD09C** | **Код программы (53.4 КБ)** |
| 12 | `.fini` | PROGBITS | 0x1660C | 0xE60C | 0x14 | Финализация |
| **13** | **`.rodata`** | PROGBITS | **0x16620** | **0xE620** | **0x183C** | **Строки и константы (6.2 КБ)** |
| 14 | `.eh_frame` | PROGBITS | 0x17E5C | 0xFE5C | 0x4 | Exception handling |
| 15 | `.ctors` | PROGBITS | 0x18000 | 0x10000 | 0x8 | Конструкторы |
| 16 | `.dtors` | PROGBITS | 0x18008 | 0x10008 | 0x8 | Деструкторы |
| 18 | `.dynamic` | DYNAMIC | 0x18014 | 0x10014 | 0xD0 | Динамическая информация |
| 19 | `.got` | PROGBITS | 0x180E4 | 0x100E4 | 0x16C | GOT (364 байт) |
| **20** | **`.data`** | PROGBITS | **0x18250** | **0x10250** | **0x7C** | **Данные (APDU шаблоны)** |
| **21** | **`.bss`** | NOBITS | **0x182CC** | --- | **0x4CE8** | **BSS (19.7 КБ)** |

---

## 4. ВСЕ извлечённые строки по категориям

**Всего строк (≥4 символа): 469**

### 4.1 SIM / APDU команды

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xE620 | `+SIMDATA: "%s"` | Приём APDU от модема |
| 0xE630 | `cli%d error SIMDATA` | Ошибка обработки SIMDATA |
| 0xE644 | `handle_sim_data` | Функция обработки SIM данных |
| 0xE660 | `AT+SIMDATA="9f0f"` | SW: 15 байт данных доступно |
| 0xE674 | `AT+SIMDATA="9404"` | SW: файл не найден (GSM) |
| 0xE688 | `AT+SIMDATA="611b"` | SW: 27 байт данных (USIM) |
| 0xE69C | `AT+SIMDATA="6a82"` | SW: файл не найден (USIM) |
| 0xE6B0 | `A0C000000F` | GET RESPONSE (GSM, Le=15) |
| 0xE6BC | `AT+SIMDATA="c0000000b06f3c..."` | Ответ SELECT EF_ADN (6F3C) |
| 0xE6F0 | `A0B2` | READ RECORD (GSM SIM) |
| 0xE6F8 | `A0DC` | UPDATE RECORD (GSM SIM) |
| 0xE700 | `AT+SIMDATA="c0000001186f3b..."` | Ответ SELECT EF_FDN (6F3B) |
| 0xE734 | `00C000001B` | GET RESPONSE (USIM, Le=27) |
| 0xE740 | `AT+SIMDATA="c062198205422100b0..."` | FCP ответ EF_ADN (BER-TLV) |
| 0xE78C | `00B2` | READ RECORD (USIM) |
| 0xE794 | `AT+SIMDATA="b200ffff...9000"` | Пустая запись ADN (176 байт FF) |
| 0xE908 | `00DC` | UPDATE RECORD (USIM) |
| 0xE910 | `AT+SIMDATA="c0621982054221001c..."` | FCP ответ EF_FDN |
| 0xE95C | `AT+SIMDATA="b2fffff...9000"` | Пустая запись FDN (28 байт FF) |
| 0xE9A8 | `AT+SIMDATA="9000"` | SW: Успех |
| 0xE9BC | `+SIMDATA` | Маркер URC от модема |
| 0xE9C8 | `+SIMRESET` | SIM reset от модема |
| 0xEB68 | `simReset` | Команда сброса SIM |
| 0xED08 | `AT+SIMDATA="` | Начало APDU ответа |

**APDU шаблоны в .data секции (0x10258):**
```
A0 A4 00 00 02 6F 3C   — SELECT EF_ADN (6F3C)
A0 A4 00 00 02 6F 3B   — SELECT EF_FDN (6F3B) 
00 A4 08 04 04 7F FF 6F 3C — SELECT EF_ADN (USIM path)
00 A4 08 04 04 7F FF 6F 3B — SELECT EF_FDN (USIM path)
A0 A4 00 00 02 6F 4D   — SELECT EF_SPN (6F4D)
A0 A4 00 00 02 6F 49   — SELECT EF_SDN (6F49)
A0 A4 00 00 02 6F B7   — SELECT EF_ECC (6FB7)
A0 A4 00 00 02 6F 50   — SELECT EF_CBMID (6F50)
00 A4 08 04 04 7F FF 6F 4D — SELECT EF_SPN (USIM path)
00 A4 08 04 04 7F FF 6F 49 — SELECT EF_SDN (USIM path)
00 A4 08 04 04 7F FF 6F 50 — SELECT EF_CBMID (USIM path)
```

**SIM файлы (EF):**
| File ID | Имя | Описание |
|---------|-----|----------|
| 6F3C | EF_SMS | Хранилище SMS |
| 6F3B | EF_FDN | Фиксированный набор номеров |
| 6F4D | EF_SPN | Имя оператора |
| 6F49 | EF_SDN | Служебные номера |
| 6FB7 | EF_ECC | Экстренные вызовы |
| 6F50 | EF_CBMID | ID сообщений Cell Broadcast |
| 7FFF | DF_TELECOM/ADF | Родительский каталог |

### 4.2 Сетевые функции (Network)

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xADE | `recv` | Приём данных из сокета |
| 0xAE6 | `connect` | Подключение к серверу |
| 0xB54 | `recvfrom` | UDP приём |
| 0xB65 | `socket` | Создание сокета |
| 0xB71 | `send` | Отправка данных |
| 0xB99 | `bind` | Привязка сокета |
| 0xB9E | `setsockopt` | Настройка сокета |
| 0xBBC | `sendmsg` | Отправка datagram |
| 0xBE6 | `sendto` | UDP отправка |
| 0xBFC | `listen` | Прослушивание TCP |
| 0xC7A | `gethostbyname` | DNS разрешение |
| 0xC88 | `gethostname` | Имя хоста |
| 0xCDE | `inet_ntop` | IP в строку |
| 0xCD4 | `inet_ntop` | IP в строку |
| 0xF970 | `tcp_connect` | Функция TCP подключения |
| 0xF990 | `tcp_bind` | Функция TCP привязки |
| 0xF99C | `tcp_listen` | Функция TCP прослушивания |
| 0xF9A8 | `udp_connect` | Функция UDP подключения |
| 0xF9B4 | `udp_bind` | Функция UDP привязки |
| 0xF9C0 | `unix_listen` | UNIX сокет прослушивание |
| 0xF9CC | `unix_connect` | UNIX сокет подключение |
| 0xF9DC | `unix_datagram_listen` | UNIX DGRAM прослушивание |
| 0xECA4 | `channel%d tcp recv error` | Ошибка TCP приёма канала |
| 0xECC0 | `more tcp packets! now len:%d, msg_type=%d...` | Парсинг TCP пакетов |
| 0xEF08 | `tcp sock failed!: %m` | Ошибка создания TCP сокета |
| 0xEF30 | `id:%d, before connect` | Лог перед подключением |
| 0xEF48 | `cli:%d, cannot connect to %s:%d: %m` | Ошибка подключения |
| 0xEF70 | `id:%d, after connect` | Лог после подключения |
| 0xEF88 | `dns name error:%m` | Ошибка DNS |
| 0xEF9C | `server ip: %s:%d` | IP и порт сервера |
| 0xEFC0 | `cli_change_local_port` | Смена локального порта |
| 0xEFD8 | `listen sock failed!: %m` | Ошибка listen |
| 0xEFF0 | `cli%d change local port:%d` | Лог смены порта |
| 0xFA6C | `/proc/net/route` | Таблица маршрутизации |

### 4.3 Аутентификация / шифрование (Auth/RC4)

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xF0C8 | `SMB_KEY` | **Ключ аутентификации** |
| 0xF134 | `SMB_RC4_KEY` | **Ключ RC4 шифрования** |
| 0xEB08 | `SMB_LOGIN` | Статус входа |
| 0xF154 | `LINE%d_SMB_LOGIN` | Статус входа по линии |

**Внешняя утилита `decrypt.RC4`** (1332 байта):
- Формат: ELF 32-bit ARM
- Использование: `rc4 -k <key> <input> <output>`
- Реализация: Классический RC4 (S-box 256 байт, KSA + PRGA)
- Содержит характерный цикл инициализации S-box (0..255)

### 4.4 IPC (межпроцессное взаимодействие)

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xEAA4 | `/tmp/.smb_cli%d` | **Сокет smb_module (приём от ata)** |
| 0xEAC0 | `/tmp/.smb%d` | **Сокет ata (приём от smb_module)** |
| 0xEA64 | `unix_datagram_sock_create` | Создание UNIX DGRAM сокета |
| 0xEAB4 | `unix_write` | Запись в UNIX сокет |
| 0xF9DC | `unix_datagram_listen` | Прослушивание UNIX DGRAM |
| 0xF9F4 | `send_ctlmsg` | Отправка управляющего сообщения |
| 0xFA00 | `recv_ctlmsg` | Приём управляющего сообщения |
| 0xFA0C | `broadcast` | Широковещательная рассылка |
| 0xFD0E | `/tmp/.syscfg-server` | Сокет конфигурации |
| 0xFD90 | `.syscfg-client-%d` | Клиент конфигурации |

### 4.5 Магические байты и протокол

**Magic: `0x43215678`** (little-endian: `78 56 21 43`, ASCII: `"xV!C"`)

Встречается **12 раз** в коде (`.text` секция) — маркер заголовка каждого сетевого пакета.

Позиции в бинарном файле:
```
0x002C30, 0x002EB4, 0x00312C, 0x003360,
0x0035A0, 0x0038AC, 0x003B3C, 0x003D98,
0x004410, 0x004874, 0x004EF4, 0x005E40
```

Каждое вхождение окружено ARM-кодом загрузки в регистры — magic используется при формировании/проверке заголовков пакетов в 12 различных функциях протокола.

**Структура пакета (реконструкция):**
```c
struct smb_packet_header {
    uint32_t magic;       // 0x43215678 — маркер пакета
    uint32_t session_id;  // ID сессии (напр. 0x0001B1FD)
    uint16_t msg_type;    // тип сообщения 
    uint16_t flags;       // флаги/подтип
    // ... данные пакета
};
```

### 4.6 M-команды (протокол состояний модуля)

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xE9D4 | `MBUSY` | Модуль занят (звонок) |
| 0xE9DC | `MIDLE` | Модуль свободен |
| 0xE9E4 | `MLOGIN` | Логин на SMB сервер |
| 0xE9EC | `MLOGOUT` | Выход |
| 0xE9F4 | `MDOWN` | Модуль выключен |
| 0xEA00 | `MCUE` | Канал включён |
| 0xEA08 | `MCUD` | Канал отключён |
| 0xEBC0 | `MSTATE` | Запрос/отчёт состояния |
| 0xED74 | `MSRB` | Soft reboot модуля |
| 0xED9C | `MEXPIRY` | Истечение срока SIM |
| 0xEDB0 | `MIMEIRS` | Сброс IMEI |
| 0xEDB8 | `MRSIMEI%s` | Новый удалённый IMEI |
| 0xEE50 | `MHRB` | Hard reboot |
| 0xEE58 | `MNOBND` | Нет привязки |

### 4.7 Информационные сообщения (ata ↔ smb)

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xEA10 | `GEXP` | Expiry данные |
| 0xEA1C | `SMSID` | SMS ID |
| 0xEA24 | `IMEI` | IMEI модема |
| 0xEA2C | `IMSI` | IMSI SIM |
| 0xEA34 | `SMSLM` | SMS лимит |
| 0xEA3C | `REGSTART` | Начало регистрации |
| 0xEE60 | `DIAL%s,%d` | Исходящий звонок |
| 0xEE6C | `SMS%s` | SMS |
| 0xEE74 | `BAL%s` | Баланс |
| 0xEE7C | `SIMNUM%s` | Номер SIM |
| 0xEE88 | `RSMS%s` | Принятая SMS |
| 0xEE90 | `SMSLM%d,%d` | Лимит SMS |
| 0xEE9C | `CALLNOCON%d` | Вызов без ответа |
| 0xEDC4 | `MLIMITT%d,%d` | Лимит времени |
| 0xEDD4 | `NMLIMITT%d,%d,%d,%d,%d,%d,%d,%d` | Расширенные лимиты |
| 0xEE0C | `SIMPWROFF` | Выключение SIM питания |
| 0xEE44 | `MACHINERB` | Перезагрузка машины |

### 4.8 AT-команды

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xE660 | `AT+SIMDATA="9f0f"` | SW ответ: данные готовы |
| 0xE674 | `AT+SIMDATA="9404"` | SW: файл не найден |
| 0xE688 | `AT+SIMDATA="611b"` | SW: ответ ещё не полный |
| 0xE69C | `AT+SIMDATA="6a82"` | SW: файл не найден (USIM) |
| 0xE9A8 | `AT+SIMDATA="9000"` | SW: успех |
| 0xED08 | `AT+SIMDATA="` | Формирование APDU ответа |

### 4.9 Конфигурационные ключи

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xF0B0 | `TELPORT` | Номер порта для telnet |
| 0xF0B8 | `SMB_SVR` | **Адрес SIM Bank сервера** |
| 0xF0C0 | `SMB_ID` | **ID клиента на сервере** |
| 0xF0C8 | `SMB_KEY` | **Ключ аутентификации** |
| 0xF0D0 | `SMB_RMSIM` | Включение удалённой SIM |
| 0xF0DC | `SMB_NET_TYPE` | Тип сети (0=UDP, 1=TCP) |
| 0xF0EC | `SMB_SVR1` | Резервный сервер |
| 0xF134 | `SMB_RC4_KEY` | **Ключ шифрования RC4** |
| 0xF140 | `GSM_MODULE` | Тип GSM модема |
| 0xF154 | `LINE%d_SMB_LOGIN` | Статус логина по линии |
| 0xF168 | `SMB_G%d` | Группа канала |
| 0xF170 | `SMB_SVR%d` | Сервер по каналу |
| 0xF17C | `SMB_ID%d` | ID по каналу |
| 0xF188 | `SMB_PASSWD%d` | Пароль по каналу |
| 0xED34 | `CLITYPE1` | Тип клиента |
| 0xF100 | `svr=%s type=%s id=%d key=%s` | Лог подключения |

### 4.10 Сообщения об ошибках и отладке

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xEB54 | `id:%d,send error:%m` | Ошибка отправки |
| 0xEB74 | `Send simrst: %m` | Ошибка отправки SIM reset |
| 0xEB84 | `net send` | Лог сетевой отправки |
| 0xEBE4 | `Send module state: %m` | Ошибка отправки состояния |
| 0xEC64 | `cli %d no response resend` | Переотправка при нет ответа |
| 0xECA4 | `channel%d tcp recv error` | Ошибка TCP приёма |
| 0xED4C | `cli %d module reboot` | Перезагрузка модуля |
| 0xED7C | `cli %d module expiry` | Истечение модуля |
| 0xED9C | `cli %d IMEI reset` | Сброс IMEI |
| 0xEDF4 | `cli %d SIM power off` | Отключение SIM |
| 0xEE1C | `cli %d sim change` | Смена SIM |
| 0xEE2C | `cli %d machine reboot` | Ребут машины |
| 0xEEC8 | `gethostbyname error for host %s:%m` | DNS ошибка |
| 0xEEEC | `unknown address type:%s` | Неизвестный тип адреса |
| 0xF1C0 | `create channels failed!` | Ошибка создания каналов |
| 0xF2EC | `ooh my god!` | Критическая ошибка |
| 0xF2F8 | `SIGPIPE!` | Обработчик SIGPIPE |

### 4.11 Имена функций (из строк .rodata)

| Офсет | Функция | Исходный файл |
|-------|---------|---------------|
| 0xE644 | `handle_sim_data` | callback.c |
| 0xEA50 | `ata_info_callback` | — |
| 0xEA64 | `unix_datagram_sock_create` | — |
| 0xEA80 | `ata_callback_init` | — |
| 0xEA94 | `callback_create` | — |
| 0xEAF4 | `dump_msg` | cli.c |
| 0xEB20 | `logout_timeout` | — |
| 0xEB30 | `resend_msg` | — |
| 0xEB3C | `rsmsg_create` | — |
| 0xEB90 | `send_uart_msg` | — |
| 0xEBD0 | `report_module_state` | — |
| 0xEC10 | `report_module_call_limit` | — |
| 0xEC2C | `report_module_sms_limit` | — |
| 0xEC44 | `cli_type_check` | — |
| 0xEC54 | `sim_no_response` | — |
| 0xEC80 | `cli_callback` | — |
| 0xEC90 | `cli_tcp_callback` | — |
| 0xED20 | `network_checking` | — |
| 0xED64 | `handle_net_msg` | — |
| 0xEF20 | `cli_reconnect` | — |
| 0xEFB0 | `fixed_server` | — |
| 0xEFC0 | `cli_change_local_port` | — |
| 0xF00C | `Creating cli%d` → `cli_create` | — |
| 0xF028 | `mstate_report` | — |
| 0xF038 | `uart_write` | — |
| 0xF044 | `net_write` | — |
| 0xF050 | `cli_type_check_unmask` | — |
| 0xF078 | `msg_create` | — |
| 0xF084 | `msg_destory` (sic) | — |
| 0xF090 | `report_module_message` | — |
| 0xF11C | `create_channels` | main.c |
| 0xF198 | `SIGKILL handler` → `handle_kill` | — |
| 0xF214 | `mmon_create` | mmon.c |
| 0xF228 | `module_state_moning` | mmon.c |
| 0xF268 | `uart_create` | uart.c |
| 0xF2A0 | `uart_callback` | uart.c |
| 0xF2C8 | `handle_uart_callback` | uart.c |
| 0xF304 | `sigio_handler` | app.c |
| 0xF31C | `send_debug_message` | app.c |
| 0xF3A4 | `dispatch_sock_events` | app.c |
| 0xF3C8 | `app_run` | app.c |
| 0xFCB8 | `scheduler_callback` | — |
| 0xFCDC | `is_valid_addr` | sockaddr.c |
| 0xFCA0 | `socket_init` | net_utils.c |
| 0xFDF0 | `call_back` | — |
| 0xFE14 | `memblk_alloc` | — |

### 4.12 Исходные файлы (.c)

| Офсет | Файл | Описание |
|-------|------|----------|
| 0xE654 | `callback.c` | Обработка обратных вызовов (SIM data, ATA info) |
| 0xEB00 | `cli.c` | **Основной клиентский код** (TCP/UDP, протокол) |
| 0xF12C | `main.c` | Точка входа, инициализация |
| 0xF220 | `mmon.c` | Мониторинг модулей |
| 0xF274 | `uart.c` | Работа с UART/serial |
| 0xF314 | `app.c` | Каркас приложения (event loop) |
| 0xF97C | `net.c` | Сетевые утилиты (TCP/UDP/Unix) |
| 0xFCEC | `sockaddr.c` | Адресация сокетов |
| 0xFCAC | `net_utils.c` | Сетевые утилиты |

### 4.13 Файловые пути

| Офсет | Путь | Описание |
|-------|------|----------|
| 0xD4 | `/lib/ld-uClibc.so.0` | Динамический линковщик |
| 0xEAA4 | `/tmp/.smb_cli%d` | Сокет smb_module |
| 0xEAC0 | `/tmp/.smb%d` | Сокет ata |
| 0xEEA8 | `/etc/hosts` | Файл хостов |
| 0xF27C | `/dev/ttyS%d` | Серийный порт |
| 0xF360 | `/dev/ttyS0` | Основной UART |
| 0xF36C | `/dev/audio` | Аудио устройство |
| 0xF4EC | `/proc/%u/exe` | Путь процесса |
| 0xF6F0 | `/proc/%d/maps` | Карта памяти процесса |
| 0xFA6C | `/proc/net/route` | Таблица маршрутов |
| 0xFD0E | `/tmp/.syscfg-server` | Конфигурационный сокет |

### 4.14 Особые строки

| Офсет | Строка | Описание |
|-------|--------|----------|
| 0xF784 | `fspipsev.net` | **Сервер отправки ошибок (email)** |
| 0xF794 | `61.141.247.7` | **Захардкоженный IP (fallback email)** |
| 0xF7A4 | `bugreport: E%.03d cannot connect to server!` | Email баг-репорт |
| 0xF828 | `HELO fspipsev.net` | SMTP HELO |
| 0xF840 | `MAIL FROM:<bug@fspipsev.net>` | SMTP отправитель |
| 0xF860 | `RCPT TO:<bug@fspipsev.net>` | SMTP получатель |
| 0xFBA0 | `202.96.136.145` | **Захардкоженный DNS IP (China Telecom)** |
| 0xFBB0 | `:54210` | **Порт Echo сервера** |
| 0xFB64 | `ECHOGWADDRRQ` | Echo Gateway Address Request |
| 0xFB88 | `ECHOSVR_ADDR` | Echo Server Address |
| 0xFB98 | `GKADDR` | Gatekeeper Address |
| 0xFC10 | `GATE_METRIC` | Метрика шлюза |
| 0xFC1C | `GATE_TIMEOUT` | Таймаут шлюза |
| 0xFC70 | `USE_INTERFACE` | Используемый интерфейс |
| 0xF1B4 | `smb_module` | Имя процесса |
| 0xEA48 | `DEBUG` | Маркер отладки |
| 0xF0A8 | `timeout` | Таймаут |

---

## 5. Запуск smb_module

### Скрипт `start_smb`:
```bash
#!/bin/sh
while [ "${AREA}" = "CHN"  -a "${REMOTE_SIM}" = "0" ]
do
    sleep 3600
done
sleep 2
exec /usr/bin/smb_module -t 50
```

**Ключевые моменты:**
- Если регион `CHN` и `REMOTE_SIM=0` — модуль **не запускается** (бесконечный sleep)
- Параметр `-t 50` — таймаут (в соответствии со строкой `timeout=%d` в binary)
- Запуск через `exec` — замена PID процесса оболочки

### Упоминания в других скриптах:
- `start_ata:5: killall sipcli ipp smb_module` — принудительная остановка перед запуском ata
- `start_ddnscli`: использует `${SMB_SVR}` для DDNS резолвинга

---

## 6. Конфигурация (smb.def)

```
SMB_SVR      string      — Адрес SIM Bank сервера
SMB_ID       integer     — ID клиента (целое число)
SMB_KEY      string      — Ключ аутентификации
SMB_RC4_KEY  string      — Ключ шифрования RC4 (пустой = без шифрования)
RMSIM_ENABLE bool        — Включение удалённой SIM
SMB_NET_TYPE integer     — Тип сети (0=UDP, 1=TCP)
SMB_RMSIM    bool        — Режим удалённой SIM
```

Дополнительно в `ata.def`:
```
LINE1_SMB_LOGIN  -n string  — Статус входа SMB по линии
SIMPIPE          integer    — Режим SIM pipe (0/1/2)
```

---

## 7. Протокол SIM-банка (полная реконструкция)

### 7.1 Установление соединения

```
1. smb_module читает конфигурацию:
   - SMB_SVR → адрес сервера (DNS или IP)
   - SMB_ID  → целочисленный ID клиента
   - SMB_KEY → строковый ключ
   - SMB_NET_TYPE → 0=UDP, 1=TCP
   - SMB_RC4_KEY → ключ RC4 (необязательный)

2. DNS разрешение (gethostbyname → /etc/hosts fallback)

3. Создание сокета:
   - UDP: udp_connect() → socket(AF_INET, SOCK_DGRAM, 0) + connect()
   - TCP: tcp_connect() → socket(AF_INET, SOCK_STREAM, 0) + connect()

4. Лог: "svr=%s type=%s id=%d key=%s"
5. Лог: "server ip: %s:%d"
```

### 7.2 Аутентификация

```
1. Клиент отправляет пакет LOGIN:
   - Заголовок: magic=0x43215678, msg_type=LOGIN
   - Данные: SMB_ID + SMB_KEY
   - Если SMB_RC4_KEY задан → данные шифруются RC4

2. Формат ключа идентификации: "%s%d%x" (rsmsg_create)

3. Статус входа сохраняется в LINE%d_SMB_LOGIN через syscfg
```

### 7.3 RC4 шифрование

**Реализация:** Классический RC4 (ARC4)

1. **KSA** (Key-Scheduling Algorithm):
   - S-box: массив 256 байт, инициализация S[i] = i
   - Перемешивание по ключу SMB_RC4_KEY
   
2. **PRGA** (Pseudo-Random Generation Algorithm):
   - Генерация keystream
   - XOR с данными пакета

3. **Утилита** `decrypt.RC4`:
   - Отдельный binary (ELF ARM)
   - Использование: `rc4 -k <key> <input> <output>`
   - Используется для офлайн-дешифровки

4. **Символы из SMB сервера:**
   - `svr_callback` — обычный обработчик пакетов
   - `svr_callback_rc4` — обработчик с RC4 дешифровкой

### 7.4 Структура пакета

```
Offset  Size    Описание
0x00    4       Magic: 0x43215678
0x04    4       Session ID / Sequence
0x08    2       Msg Type (тип сообщения)
0x0A    2       Flags / Sub-type
0x0C    ...     Payload (данные, опционально зашифрованы RC4)
```

Строка `more tcp packets! now len:%d, msg_type=%d; all len=%d, next msg_type=%d` подтверждает:
- Протокол поддерживает **потоковое TCP** с несколькими пакетами в буфере
- Каждый пакет имеет `len` (длина) и `msg_type` (тип)
- Обработка цепочки пакетов в одном recv()

### 7.5 Назначение SIM (SIM Assignment)

```
1. Сервер назначает SIM → отправляет APDU пакет
2. smb_module формирует AT+SIMDATA="<hex>" → отправляет в /tmp/.smb1
3. ata пересылает в модем через /dev/ttyS0
4. Модем работает с SIM как с локальной картой

Обратный путь:
1. Модем → +SIMDATA: "<hex>" URC в ata
2. ata → unix_write() в /tmp/.smb_cli1
3. smb_module → UDP/TCP sendto() на SIM Bank сервер
4. SIM Bank пересылает APDU на физическую SIM карту
```

### 7.6 Горячая замена SIM (Hotswap)

Сигналы и команды:
- `+SIMRESET` — модем запрашивает сброс SIM
- `simReset` — smb_module инициирует сброс
- `cli %d sim change` — смена SIM через сервер
- `SIMPWROFF` → `AT+CFUN=0` — выключение SIM питания
- `MACHINERB` → полная перезагрузка устройства
- `MSRB` → мягкая перезагрузка модуля

### 7.7 Heartbeat / Keepalive

```
- keepAlive — периодическая отправка (функция keepAlive)
- Таймаут: -t 50 (50 секунд, из start_smb)
- logout_timeout — таймаут выхода при отсутствии ответа
- sim_no_response → "cli %d no response resend" — переотправка
- cli_reconnect — переподключение при полной потере связи
```

---

## 8. Управление каналами (мульти-линейная поддержка)

Строки `SMB_SVR%d`, `SMB_ID%d`, `SMB_PASSWD%d`, `SMB_G%d`, `channel%d` указывают на поддержку **нескольких каналов/линий**:

```c
// Инициализация (create_channels в main.c):
for (d = 0; d < num_channels; d++) {
    // Читает SMB_SVR%d, SMB_ID%d, SMB_PASSWD%d
    // Создаёт /tmp/.smb_cli%d и /tmp/.smb%d
    // Подключается к назначенному серверу
    // Открывает /dev/ttyS%d для UART
}
```

**Для GST1610** (16-портовый GoIP):
- До 16 каналов (channel0..channel15)
- Каждый канал имеет собственный UART (`/dev/ttyS0`..`/dev/ttyS15`)
- Каждый канал может быть подключён к разному SMB серверу
- Статус каждого канала: `LINE%d_GSM_STATUS`, `LINE%d_SMB_LOGIN`

---

## 9. Захардкоженные адреса и порты

| Значение | Тип | Описание |
|----------|-----|----------|
| `0x43215678` | Magic | Маркер пакета протокола |
| `fspipsev.net` | Хост | SMTP сервер для баг-репортов |
| `61.141.247.7` | IP | Fallback IP для SMTP |
| `bug@fspipsev.net` | Email | Адрес баг-репортов |
| `202.96.136.145` | IP | DNS-сервер (China Telecom) |
| `:54210` | Порт | Echo-сервер для NAT traversal |
| `50000` (0xC350) | Значение | Присутствует в .data (возможный порт/размер) |

**Примечание**: Порт `56011`, упомянутый в описании, **не найден** как строка в бинарнике. Вероятно передаётся от конфигурации (SMB_SVR содержит `host:port`) или зашит как числовая константа в ARM immediate.

---

## 10. Импортируемые функции (динамические символы)

### Сетевые (17 функций):
`socket`, `connect`, `bind`, `listen`, `send`, `recv`, `sendto`, `recvfrom`, `sendmsg`, `recvmsg`, `setsockopt`, `getsockopt`, `getsockname`, `gethostbyname`, `gethostname`, `inet_aton`, `inet_ntoa`, `inet_ntop`

### Файловые/системные (15):
`open`, `close`, `read`, `write`, `fopen`, `fclose`, `fwrite`, `fgets`, `fputs`, `fstat`, `mmap`, `munmap`, `readlink`, `unlink`, `fsync`

### Строковые/память (18):
`strcpy`, `strncpy`, `strcat`, `strcmp`, `strncmp`, `strcasecmp`, `strchr`, `strdup`, `strlen`, `strtol`, `strtoul`, `memcpy`, `memcmp`, `memset`, `memmove`, `malloc`, `calloc`, `realloc`, `free`

### Форматирование (7):
`printf`, `fprintf`, `sprintf`, `snprintf`, `vsnprintf`, `sscanf`, `atoi`, `atol`

### Терминал/UART (4):
`tcgetattr`, `tcsetattr`, `tcflush`, `ioctl`

### Сигналы/время (6):
`signal`, `setitimer`, `gettimeofday`, `localtime`, `time`, `poll`

---

## 11. Архитектурная схема

```
                        ┌─────────────────────────┐
                        │   SIM Bank Server        │
                        │   (dbltek.com и др.)     │
                        │   Физические SIM карты   │
                        └────────┬────────────────┘
                                 │
                          UDP/TCP│(magic=0x43215678)
                    (RC4 опцион.)│
                                 │
┌────────────────────────────────┼────────────────────────────┐
│ GoIP GST1610                   │                            │
│                                │                            │
│  ┌──────────────┐    ┌─────────┴──────────┐                 │
│  │  start_smb   │───>│   smb_module       │                 │
│  │  (shell)     │    │   PID ~12778       │                 │
│  └──────────────┘    │                    │                 │
│                      │ cli.c: TCP/UDP     │                 │
│                      │ callback.c: APDU   │                 │
│                      │ uart.c: serial     │                 │
│                      │ mmon.c: monitor    │                 │
│                      └───┬──────────┬─────┘                 │
│               Unix DGRAM │          │ /dev/ttyS%d           │
│              /tmp/.smb%d │          │ (прямой UART)         │
│           /tmp/.smb_cli%d│          │                       │
│                      ┌───┴──────────┴─────┐                 │
│                      │      ata           │                 │
│                      │   PID ~221         │                 │
│                      │   GSM контроллер   │                 │
│                      └───┬────────────────┘                 │
│                          │ /dev/ttyS0                       │
│                      ┌───┴────────────────┐                 │
│                      │   GSM Модем (M25)  │                 │
│                      │   AT+SIMDATA       │                 │
│                      │   +SIMDATA URC     │                 │
│                      │   +SIMRESET URC    │                 │
│                      └────────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

---

## 12. Выводы

1. **smb_module** — компактный (67 КБ) ARM бинарник, клиент проприетарного протокола SIM-банка DBLTEK
2. **Протокол** использует фиксированный magic `0x43215678`, поддерживает TCP и UDP
3. **RC4 шифрование** опционально (SMB_RC4_KEY), реализация — стандартный ARC4
4. **12 точек использования** magic в коде — 12 различных типов пакетов
5. **Захардкоженные APDU** — fallback ответы для EF_ADN, EF_FDN (пустые записи)
6. **Мульти-канальная** архитектура: поддержка до 16 GSM каналов
7. **IPC** через Unix DGRAM сокеты (`/tmp/.smb%d` ↔ `/tmp/.smb_cli%d`)
8. **Bagreport** через SMTP на `bug@fspipsev.net` (захардкожен!)
9. **Echo/NAT traversal** на `202.96.136.145:54210`
10. **Исходники** написаны на C (GCC 3.3.x), модульная структура: 9 файлов .c
