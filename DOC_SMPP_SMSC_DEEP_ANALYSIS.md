# Глубокий статический анализ бинарного файла smpp_smsc

## GoIP GST1610 Firmware — SMPP/SMSC сервер

**Дата анализа:** 15 марта 2026 г.  
**Файл:** `fw_new/squashfs-root/usr/bin/smpp_smsc`  
**Размер:** 43 080 байт (42.07 KB)  
**Дата модификации:** 10.10.2020 05:41:31  

---

## 1. ELF-заголовок

| Параметр | Значение | Описание |
|----------|----------|----------|
| Magic | `7F 45 4C 46` | ELF |
| Класс | 32-bit (ELF32) | ARM 32-bit |
| Порядок байт | Little Endian | LE |
| OS/ABI | 0x61 (97) — ARM EABI | Встроенный ARM |
| Тип | ET_EXEC (2) | Исполняемый файл |
| Архитектура | ARM (0x28) | ARM процессор |
| Entry Point | `0x000094D8` | Точка входа (_start) |
| Program Headers | 5 записей @ offset 52 | |
| Section Headers | 24 записи @ offset 42120 | |
| Flags | `0x00000002` | ARM EABI version |
| Интерпретатор | `/lib/ld-uClibc.so.0` | uClibc линковщик |

### Зависимости (DT_NEEDED)
- `libgcc_s.so.1` — GCC runtime support
- `libc.so.0` — uClibc (облегчённая C-библиотека)

### Компилятор
- **GCC 3.3.2** 20031005 (Debian prerelease) — основной код
- **GCC 3.3.5** — связанные библиотечные модули (15 объектных файлов)

---

## 2. Карта ELF-секций

| # | Имя | Тип | Флаги | Виртуальный адрес | Смещение | Размер | Описание |
|---|-----|-----|-------|-------------------|----------|--------|----------|
| 0 | (null) | NULL | — | 0x0 | 0 | 0 | Пустая |
| 1 | .interp | PROGBITS | A | 0x80D4 | 212 | 20 | Путь к линковщику |
| 2 | .hash | HASH | A | 0x80E8 | 232 | 788 | Хеш-таблица символов |
| 3 | .dynsym | DYNSYM | A | 0x83FC | 1020 | 1568 | Динамические символы (98 записей) |
| 4 | .dynstr | STRTAB | A | 0x8A1C | 2588 | 771 | Строки дин. символов |
| 5 | .gnu.version | VERSYM | A | 0x8D20 | 3360 | 196 | Версии символов |
| 6 | .gnu.version_r | VERNEED | A | 0x8DE4 | 3556 | 32 | Требуемые версии |
| 7 | .rel.dyn | REL | A | 0x8E04 | 3588 | 24 | Релокации данных |
| 8 | .rel.plt | REL | A | 0x8E1C | 3612 | 672 | Релокации PLT (84 записи) |
| 9 | .init | PROGBITS | AX | 0x90BC | 4284 | 24 | Инициализация |
| 10 | .plt | PROGBITS | AX | 0x90D4 | 4308 | 1028 | Таблица связывания |
| 11 | **.text** | PROGBITS | AX | 0x94D8 | 5336 | **30 272** | **Код программы** |
| 12 | .fini | PROGBITS | AX | 0x10B18 | 35608 | 20 | Финализация |
| 13 | **.rodata** | PROGBITS | A | 0x10B2C | 35628 | **2 736** | **Константные данные** |
| 14 | .eh_frame | PROGBITS | A | 0x115DC | 38364 | 4 | Exception handling |
| 15 | .ctors | PROGBITS | WA | 0x1A000 | 40960 | 8 | Конструкторы |
| 16 | .dtors | PROGBITS | WA | 0x1A008 | 40968 | 8 | Деструкторы |
| 17 | .jcr | PROGBITS | WA | 0x1A010 | 40976 | 4 | Java class registration |
| 18 | .dynamic | DYNAMIC | WA | 0x1A014 | 40980 | 208 | Динамическая секция |
| 19 | .got | PROGBITS | WA | 0x1A0E4 | 41188 | 352 | Global Offset Table |
| 20 | .data | PROGBITS | WA | 0x1A244 | 41540 | 40 | Инициализированные данные |
| 21 | **.bss** | NOBITS | WA | 0x1A26C | 41580 | **19 548** | **Неинициализированные данные** |
| 22 | .comment | PROGBITS | — | 0x0 | 41580 | 364 | Комментарии компилятора |
| 23 | .shstrtab | STRTAB | — | 0x0 | 41944 | 176 | Таблица имён секций |

### Ключевые метрики
- **Код (.text):** 30 272 байт — основная логика SMPP-сервера
- **Константы (.rodata):** 2 736 байт — строки, форматы, конфигурация
- **BSS (.bss):** 19 548 байт — буферы, состояния подключений, очереди SMS
- **PLT записей:** ~84 — импортированные функции

---

## 3. Извлечённые строки — классификация

### 3.1 SMPP-протокол

| Строка | Описание |
|--------|----------|
| `smsc` | Идентификатор модуля — Short Message Service Center |
| `SMPP_PORT` | Конфигурационный ключ порта SMPP |
| `SMPP_ENABLE` | Включение/выключение SMPP-сервера |
| `SMPP_ID` | System ID для аутентификации SMPP |
| `SMPP_KEY` | Пароль для аутентификации SMPP |
| `SMPP_GNUM_EN` | Разрешение использования GSM-номера |
| `SMPP_ENROUTE_DISABLE` | Отключение статуса ENROUTE |
| `SMPP_DEBUG%d` | Флаг отладки SMPP (из ata) |

### 3.2 SMS / Сообщения

| Строка | Описание |
|--------|----------|
| `SMS%d %d %s %d %d %d` | Формат SMS-команды (канал, статус, номер, параметры) |
| `del_sms_send` | Функция удаления отправленного SMS |
| `DELIVER` | Команда доставки SMS |
| `DELIVER%d %d %d %s` | Формат отчёта о доставке |
| `RECEIVE` | Команда приёма SMS |
| `SMSSTATUS` | Запрос статуса SMS |
| `SMSSTATUS%d %d %d %d` | Формат ответа статуса (канал, sms_no, pdu_code, state) |
| `GSMSTATUS` | Статус GSM-модуля |
| `GSMSTATUS%d %d` | Формат статуса GSM (канал, статус) |
| `LINESTATUS` | Статус линии/канала |
| `LINESTATUS%d %d` | Формат статуса линии |
| `L%d_GSM_NUMBER` | GSM-номер для линии N |

### 3.3 Delivery Report (DLR) форматы

```
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:DELIVRD err:0 Text:%.20s
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:UNDELIV err:501 Text:%.20s
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:ENROUTE err:0 Text:%.20s
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:UNDELIV err:%d Text:%.20s
```

**Поддерживаемые статусы DLR:**
| Статус | Код ошибки | Описание |
|--------|-----------|----------|
| `DELIVRD` | 0 | Успешная доставка |
| `UNDELIV` | 501 | Не доставлено (фиксированная ошибка) |
| `UNDELIV` | %d | Не доставлено (динамический код ошибки) |
| `ENROUTE` | 0 | В пути (промежуточный статус) |

**Формат даты:** `%02d%02d%02d%02d%02d` — YYMMDDhhmm (5 пар цифр)

### 3.4 Сетевые функции

| Функция/строка | Описание |
|----------------|----------|
| `socket` | Создание сокета |
| `bind` | Привязка к адресу |
| `listen` | Прослушивание порта |
| `accept` | Принятие входящего соединения |
| `recv` / `recvfrom` | Получение данных |
| `send` / `sendto` / `sendmsg` | Отправка данных |
| `connect` | Исходящее подключение |
| `poll` | Мультиплексирование I/O |
| `setsockopt` / `getsockopt` | Опции сокета |
| `getsockname` | Получение адреса сокета |
| `gethostbyname` | DNS-резолвинг |
| `inet_pton` / `inet_ntop` / `inet_aton` / `inet_ntoa` | Конвертация IP-адресов |
| `accept failed: %m` | Ошибка принятия соединения |
| `cannot bind address: %s:%d: %m` | Ошибка привязки к адресу:порту |
| `cannot listen: %m` | Ошибка прослушивания |
| `tcp_gets(): %d` / `tcp_gets(): %s` | TCP-чтение строки |
| `127.0.0.1` | Loopback-адрес (IPC с ata) |

### 3.5 IPC (Inter-Process Communication)

| Строка | Описание |
|--------|----------|
| `/tmp/.syscfg-server` | UNIX-сокет syscfg-сервера |
| `.syscfg-client-%d` | Шаблон имени клиентского UNIX-сокета |
| `unix_bind(): %s` | Привязка UNIX-сокета |
| `sockaddr` | Структура адреса |
| `%s=%s` | Формат запроса/ответа конфигурации |
| `%list` | Команда syscfg: получить список |
| `%%apply` | Команда syscfg: применить изменения |
| `%%save` | Команда syscfg: сохранить |
| `%%reset` | Команда syscfg: сброс |
| `%%reload` | Команда syscfg: перезагрузка |
| `call_back` | Регистрация callback-а в syscfg |
| `scheduler_callback` | Callback планировщика |
| `smsc_callback` | Callback SMSC (в ata) |
| `sendto_smpp` | Отправка данных в SMPP из ata |

### 3.6 Аутентификация

| Строка | Описание |
|--------|----------|
| `SMPP_ID` | System ID (идентификатор системы для SMPP bind) |
| `SMPP_KEY` | Пароль (password для SMPP bind) |
| `USERNAME` | Имя пользователя (для системы) |
| `USER` | Пользователь |
| `TELPORT` | Порт телефонии |
| `%s%02d` | Формат: system_id + двузначный номер |

### 3.7 Конфигурационные ключи

| Ключ | Тип | Описание |
|------|-----|----------|
| `SMPP_PORT` | string | TCP-порт SMPP-сервера |
| `SMPP_ID` | string | System ID для аутентификации |
| `SMPP_KEY` | string | Пароль для аутентификации |
| `SMPP_ENABLE` | bool | Включение SMPP-сервера |
| `SMPP_GNUM_EN` | bool | Использование GSM-номера в SMPP |
| `SMPP_ENROUTE_DISABLE` | bool | Отключение ENROUTE DLR |
| `SMPP_DEBUG` | integer | Уровень отладки (из ata) |
| `L%d_GSM_NUMBER` | string | GSM-номер линии |
| `GSMSTATUS` | — | IPC-команда статуса GSM |
| `LINESTATUS` | — | IPC-команда статуса линии |
| `ECHOGWADDRRQ` | — | Запрос адреса echo-шлюза |
| `ECHOSVR_ADDR` | — | Адрес echo-сервера |
| `GKADDR` | — | Адрес gatekeeper |
| `GATE_METRIC` | — | Метрика шлюза |
| `GATE_TIMEOUT` | — | Таймаут шлюза |
| `USE_INTERFACE` | — | Используемый сетевой интерфейс |

### 3.8 Сообщения об ошибках и отладке

| Строка | Контекст |
|--------|----------|
| `accept failed: %m` | Ошибка accept() |
| `cannot bind address: %s:%d: %m` | Ошибка привязки TCP |
| `cannot listen: %m` | Ошибка listen() |
| `write failed!` | Ошибка записи в syscfg |
| `tcp_gets(): %d` | Отладка TCP-чтения (код) |
| `tcp_gets(): %s` | Отладка TCP-чтения (строка) |
| `invalid line %d` | Неверный номер линии |
| `couldn't open "%s"` | Не удалось открыть файл |
| `cannot open %s` | Ошибка открытия файла |
| `invalid line:` | Неверная строка в /proc/maps |
| `not a valid ELF file` | ELF-валидация (встроенная) |
| `log buffer overflow!` | Переполнение буфера логов |
| `%s(): %s: %d: %s` | Общий формат логирования |
| `SYSERROR: %s(): %s: %d: %s` | Системная ошибка |
| `FAILED: %s(): %s: %d` | Ошибка функции |
| `CHECKPOINT: %s(): %s: %d` | Контрольная точка |
| `Logged Call Stack` | Лог стека вызовов |
| `smpp not enable!` | SMPP не включён (из ata) |

### 3.9 Встроенные имена функций

| Функция | Источник | Описание |
|---------|----------|----------|
| `smsc` | smpp_smsc | Главный модуль |
| `del_sms_send` | smpp_smsc | Удаление отправленного SMS |
| `tcp_gets` | smpp_smsc | TCP-чтение строки |
| `scheduler_callback` | smpp_smsc | Callback планировщика |
| `call_back` | smpp_smsc | syscfg callback |
| `sendto_smpp` | ata | Отправка в SMPP-сокет |
| `smsc_callback` | ata (smsc.c) | Callback обработки SMPP |
| `smpp_init` | ata (smsc.c) | Инициализация SMPP-подсистемы |
| `receive_and_parse_uimsg` | ata | Парсинг UI-сообщений |
| `report_sms_deliver` | ata | Отчёт о доставке SMS |

### 3.10 Файловые пути

| Путь | Описание |
|------|----------|
| `/lib/ld-uClibc.so.0` | Динамический загрузчик |
| `/tmp/.syscfg-server` | Сокет конфигурационного сервера |
| `/dev/ttyS0` | Последовательный порт (модем) |
| `/dev/audio` | Аудио-устройство |
| `/etc/%s.conf` | Шаблон конфигурационного файла |
| `/proc/%u/exe` | Ссылка на исполняемый файл процесса |
| `/proc/%d/maps` | Карта памяти процесса |
| `/proc/net/route` | Таблица маршрутизации |
| `%s/.%src` | Домашний RC-файл |

### 3.11 Встроенная система отчётов об ошибках (Bug Report)

| Строка | Описание |
|--------|----------|
| `fspipsev.net` | Сервер отчётов об ошибках HyberTone |
| `61.141.247.7` | IP-адрес сервера (Китай, Guangdong) |
| `HELO fspipsev.net` | SMTP HELO |
| `MAIL FROM:<bug@fspipsev.net>` | Отправитель |
| `RCPT TO:<bug@fspipsev.net>` | Получатель |
| `bugreport: E%.03d cannot connect to server!` | Ошибка подключения |
| `bugreport: E%.03d: connection error` | Ошибка соединения |
| `bugreport: E%.03d: server error: %s` | Ошибка сервера |

> **Примечание:** В бинарник встроена система автоматической отправки crash-отчётов по SMTP на сервер производителя (HyberTone/DBL Technology).

### 3.12 Сетевая диагностика

| Строка | Описание |
|--------|----------|
| `ECHOGWADDRRQ` | Запрос адреса echo-шлюза |
| `ECHOGWADDRRP` | Ответ адреса echo-шлюза |
| `ECHOSVR_ADDR` | Адрес echo-сервера |
| `202.96.136.145` | DNS-сервер (China Telecom) |
| `:54210` | Порт echo-сервера |
| `IP addr: %s` | IP-адрес |
| `Broadcast addr: %s` | Широковещательный адрес |
| `Destination addr: %s` | Адрес назначения |
| `Subnet mask: %s` | Маска подсети |
| `Iface` | Сетевой интерфейс |
| `BCAST`, `MCAST`, `LOOP`, `P2P`, `UP` | Флаги интерфейса |

---

## 4. Конфигурация SMPP (smpp.def)

```
SMPP_PORT string          # TCP-порт SMPP-сервера
SMPP_ID string            # System ID для bind
SMPP_KEY string           # Пароль для bind
SMPP_ENABLE bool          # Включение/выключение сервера
SMPP_GNUM_EN bool         # Использование GSM-номера
SMPP_ENROUTE_DISABLE bool # Отключение ENROUTE DLR-статуса
```

### Связанные настройки из ata.def

| Ключ | Тип | Описание |
|------|-----|----------|
| `L1_GSM_NUMBER` | string | GSM-номер линии 1 |
| `L1_SMSC_NUM` | string | Номер SMSC SIM-карты |
| `LINE1_SIM_SMSC` | bool | Использовать SMSC из SIM |
| `SMS_DELIVER` | bool | Включение доставки SMS |
| `LINE1_SEND_SMS_STATUS` | string | Статус отправки SMS |
| `LINE1_SEND_SMS_ERROR` | string | Ошибка отправки SMS |
| `LINE1_SMS_VALIDITY_TIME` | integer | Время действия SMS |
| `LINE1_SMS_INTERVAL` | integer | Интервал отправки SMS |
| `LINE1_SMS_REMAIN` | string | Остаток SMS |
| `LINE1_SMS_LIMIT` | string | Лимит SMS |
| `LINE1_SMS_NUM_MAP` | string | Маппинг номеров SMS |
| `L1_SMS_SERVER` | string | SMS-сервер |
| `L1_SMS_PORT` | string | Порт SMS-сервера |
| `L1_SMS_CLI_ID` | string | ID клиента SMS |
| `L1_SMS_CLI_PASSWD` | string | Пароль клиента SMS |

---

## 5. Механизм запуска

### Отсутствует отдельный стартовый скрипт

В отличие от других сервисов (`start_sip`, `start_ata`, `start_fvdsp` и т.д.), для `smpp_smsc` **не существует отдельного скрипта `start_smpp`**.

### Запуск из процесса `ata`

Из анализа строк бинарника `ata` следует:
1. **`ata`** содержит модуль `smsc.c` со следующими функциями:
   - `smpp_init` — инициализация SMPP (проверяет `SMPP_ENABLE`)
   - `smsc_callback` — callback для обработки событий SMPP
   - `sendto_smpp` — отправка данных в SMPP-сервер
2. При вызове `smpp_init`:
   - Проверяется флаг `SMPP_ENABLE`
   - Если не включён → `"smpp not enable!"`
   - Если включён → устанавливается соединение с `127.0.0.1` (loopback)
   - Выполняется `bind:%s` — привязка к серверу

### Архитектура взаимодействия

```
┌──────────┐     TCP/localhost      ┌───────────┐     TCP/SMPP      ┌────────────┐
│   ata    │ ◄──────────────────► │ smpp_smsc │ ◄──────────────► │ Внешний    │
│ (smsc.c) │     IPC команды      │  (сервер) │     SMPP PDU     │ SMPP-клиент│
└──────────┘                       └───────────┘                   └────────────┘
     │                                   │
     │  syscfg UNIX socket               │  syscfg UNIX socket
     ▼                                   ▼
┌──────────────────────────────────────────┐
│        /tmp/.syscfg-server               │
│     Конфигурационный сервер              │
└──────────────────────────────────────────┘
```

---

## 6. Реализация SMPP-протокола

### 6.1 Роль

`smpp_smsc` работает как **SMPP-сервер (SMSC)**, принимающий входящие подключения от внешних SMPP-клиентов.

### 6.2 Поддерживаемые операции

| Операция | Доказательство | Роль |
|----------|---------------|------|
| **bind** | `SMPP_ID`, `SMPP_KEY`, `bind:%s` | Аутентификация клиентов |
| **submit_sm** | `SMS%d %d %s %d %d %d`, `del_sms_send` | Приём SMS от клиента для отправки через GSM |
| **deliver_sm** | `DELIVER%d %d %d %s`, DLR-форматы | Доставка SMS клиенту (MO SMS) |
| **enquire_link** | (подразумевается TCP keepalive через `poll`) | Поддержание соединения |
| **DLR** | Все 4 формата DLR | Отчёты о доставке |

### 6.3 Формат DLR (Delivery Receipt)

Формат соответствует **SMPP 3.4 стандартному DLR**:
```
id:{id} sub:{sub} dlvrd:{dlvrd} submit date:{date} done date:{date} stat:{stat} err:{err} Text:{text}
```

### 6.4 Поддерживаемые статусы DLR

| Статус | Описание | Код ошибки |
|--------|----------|-----------|
| `DELIVRD` | Доставлено успешно | 0 |
| `UNDELIV` | Не доставлено | 501 или динамический |
| `ENROUTE` | В пути (промежуточный) | 0 |

### 6.5 Протокольный поток

```
SMPP-клиент → [bind_transceiver] → smpp_smsc
              ← [bind_transceiver_resp] ←

SMPP-клиент → [submit_sm] → smpp_smsc → [IPC] → ata → GSM-модем → SMS
              ← [submit_sm_resp] ←
              
GSM-модем → SMS → ata → [IPC] → smpp_smsc → [deliver_sm] → SMPP-клиент
                                             ← [deliver_sm_resp] ←

GSM-модем → DLR → ata → [IPC SMSSTATUS/DELIVER] → smpp_smsc → [deliver_sm (DLR)] → SMPP-клиент
```

### 6.6 IPC-протокол (smpp_smsc ↔ ata)

Основан на текстовых командах через TCP/localhost:

| Команда | Формат | Направление | Описание |
|---------|--------|-------------|----------|
| `SMS` | `SMS%d %d %s %d %d %d` | smsc→ata | Отправить SMS через канал |
| `GSMSTATUS` | `GSMSTATUS%d %d` | ata→smsc | Статус GSM-модуля |
| `DELIVER` | `DELIVER%d %d %d %s` | ata→smsc | Уведомление о доставке |
| `SMSSTATUS` | `SMSSTATUS%d %d %d %d` | ata→smsc | Статус SMS |
| `LINESTATUS` | `LINESTATUS%d %d` | ata→smsc | Статус линии |
| `RECEIVE` | `RECEIVE%d,%s,%d,%d,` | ata→smsc | Входящее SMS |

---

## 7. Версия SMPP-протокола

### Определение версии

На основе анализа:

| Критерий | Значение | Вывод |
|----------|----------|-------|
| Формат DLR | `id:X sub:X dlvrd:X submit date:X done date:X stat:X err:X Text:X` | Стандартный SMPP 3.4 DLR |
| Статусы DLR | DELIVRD, UNDELIV, ENROUTE | SMPP 3.4 spec |
| Аутентификация | system_id + password | SMPP 3.3+ |
| Отсутствие TLV | Нет строк о TLV-параметрах | Не SMPP 5.0 |
| Формат даты | YYMMDDhhmm (5 пар) | SMPP 3.4 формат |

**Заключение: Реализация соответствует SMPP 3.4** (наиболее распространённый для GSM-шлюзов).

Отсутствие:
- TLV-параметров (SMPP 5.0)
- `outbind` операции
- Расширенных команд SMPP 3.4 (`broadcast_sm`, `cancel_sm`, `replace_sm`)
- Поддержки множественных `bind` типов в строках (отсутствуют строки `bind_transmitter`, `bind_receiver`, `bind_transceiver` как явные)

---

## 8. Импортированные функции (84 PLT записи)

### Сокеты и сеть (18 функций)
`socket`, `bind`, `listen`, `accept`, `connect`, `recv`, `recvfrom`, `recvmsg`, `send`, `sendto`, `sendmsg`, `setsockopt`, `getsockopt`, `getsockname`, `poll`, `inet_pton`, `inet_ntop`, `inet_aton`, `inet_ntoa`, `gethostbyname`, `gethostname`

### Файловый I/O (10 функций)
`open`, `read`, `write`, `close`, `fopen`, `fclose`, `fgets`, `fputs`, `fwrite`, `fprintf`, `fstat`, `fsync`

### Память (6 функций)
`malloc`, `calloc`, `realloc`, `free`, `mmap`, `munmap`

### Строки (14 функций)
`strcpy`, `strncpy`, `strcat`, `strcmp`, `strncmp`, `strcasecmp`, `strchr`, `strlen`, `strdup`, `memcpy`, `memset`, `memcmp`, `sprintf`, `snprintf`, `vsnprintf`, `sscanf`

### Процессы и сигналы (6 функций)
`signal`, `setitimer`, `getpid`, `getenv`, `setenv`, `exit`, `abort`

### Время (4 функции)
`gettimeofday`, `localtime`, `time`, `srand`, `srandom`, `random`

### Прочие (6 функций)
`ioctl`, `perror`, `strerror`, `readlink`, `unlink`, `atoi`, `atol`, `strtol`, `puts`, `printf`

---

## 9. Анализ BSS (неинициализированные данные)

**Размер BSS: 19 548 байт** — это значительный объём для бинарника в 43 KB.

### Вероятная структура BSS:

| Область | Оценка размера | Описание |
|---------|---------------|----------|
| Буферы подключений | ~4 KB | Массив TCP-соединений (состояния, буферы чтения) |
| Буферы SMS | ~8 KB | Очередь SMS-сообщений (до 160 символов × N) |
| Конфигурация | ~2 KB | Кэшированные значения syscfg |
| Состояния GSM | ~2 KB | Массив состояний линий/каналов |
| Буферы IPC | ~2 KB | Буферы обмена с ata |
| Буфер логирования | ~1 KB | Циклический лог-буфер |

---

## 10. Безопасность

### Обнаруженные проблемы

| Проблема | Уровень | Описание |
|----------|---------|----------|
| **Аутентификация в открытом тексте** | Высокий | SMPP_ID и SMPP_KEY передаются/хранятся без шифрования |
| **Нет TLS/SSL** | Высокий | Весь SMPP-трафик незашифрован |
| **Жёстко вшитые адреса** | Средний | `fspipsev.net`, `61.141.247.7`, `202.96.136.145` |
| **sprintf/strcpy** | Средний | Использование небезопасных строковых функций |
| **SMTP без аутентификации** | Средний | Отправка bugreport без SMTP auth |
| **Loopback IPC** | Низкий | Связь с ata через TCP/localhost (перехватываемо локально) |
| **GCC 3.3** | Средний | Очень старый компилятор, отсутствуют современные защиты (stack canary, ASLR, PIE) |

---

## 11. Сводная архитектура

```
┌─────────────────────────────────────────────────────────────────┐
│                        GoIP GST1610                             │
│                                                                 │
│  ┌─────────┐    TCP/SMPP     ┌───────────┐                     │
│  │ Внешний │ ◄────────────► │ smpp_smsc │                      │
│  │ SMPP    │   порт: SMPP_  │ (43 KB)   │                      │
│  │ клиент  │   PORT         │           │                      │
│  └─────────┘                 └─────┬─────┘                      │
│                                    │ TCP/localhost               │
│                                    │ (IPC команды)              │
│                              ┌─────▼─────┐                      │
│                              │    ata     │                      │
│                              │ (smsc.c)  │                      │
│                              └─────┬─────┘                      │
│                                    │ AT-команды                  │
│                              ┌─────▼─────┐                      │
│                              │ GSM-модем │                      │
│                              │ /dev/ttyS0│                      │
│                              └───────────┘                      │
│                                                                 │
│  ┌───────────────────────────────────────┐                      │
│  │ syscfg (/tmp/.syscfg-server)          │                      │
│  │ Конфигурация: SMPP_PORT, SMPP_ID,     │                      │
│  │ SMPP_KEY, SMPP_ENABLE, SMPP_GNUM_EN,  │                      │
│  │ SMPP_ENROUTE_DISABLE                  │                      │
│  └───────────────────────────────────────┘                      │
└─────────────────────────────────────────────────────────────────┘
```

---

## 12. Ключевые выводы

1. **SMPP 3.4 сервер** — базовая реализация SMSC для GoIP-шлюза, обеспечивающая приём/передачу SMS через SMPP-протокол.

2. **Минимальный бинарник** (43 KB) — содержит SMPP-сервер, TCP-стек, IPC-клиент syscfg, буфер логирования, систему crash-отчётов, и диагностику сети. Всё статически связано с общими утилитами HyberTone.

3. **Нет собственного стартового скрипта** — запускается из процесса `ata` при `SMPP_ENABLE=true`.

4. **IPC через TCP/localhost** — обмен с `ata` через текстовые команды (DELIVER, RECEIVE, SMS, SMSSTATUS, GSMSTATUS, LINESTATUS).

5. **Простая аутентификация** — единственная пара system_id/password (`SMPP_ID`/`SMPP_KEY`) для всех клиентов.

6. **4 статуса DLR** — DELIVRD, UNDELIV (501 и динамический), ENROUTE. Возможно отключить ENROUTE через `SMPP_ENROUTE_DISABLE`.

7. **Встроенный crash-reporter** — отправляет отчёты на `fspipsev.net` (61.141.247.7) по SMTP.

8. **Общая библиотечная база** с другими бинарниками HyberTone — встроенные функции: ELF-парсер (для stack trace), сетевая диагностика, syscfg-клиент, TCP-утилиты.

9. **Скомпилирован GCC 3.3.2/3.3.5** для ARM EABI, с использованием uClibc — типично для встраиваемых Linux-систем начала 2000-х.

10. **Безопасность минимальна** — нет TLS, нет защиты стека, открытая аутентификация, жёстко вшитые серверные адреса.
