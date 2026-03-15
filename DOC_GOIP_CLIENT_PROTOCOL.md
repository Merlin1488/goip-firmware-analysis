# GoIP GST1610 — Полное описание клиентского SIP-протокола

> Реверс-инжиниринг бинарника `/usr/bin/sipcli` (658 064 байт, ARM OABI)
> Прошивка: GHSFVT-1.1-68-11 (DBLTek / HYBERTONE GST1610)
> SIP-стек: GNU oSIP (libosip2) — статическая линковка
> Прикладной уровень: 28 проприетарных .c файлов DBLTek

---

## ЧАСТЬ 1: АРХИТЕКТУРА КЛИЕНТА

### 1.1 Процессная модель

GoIP GST1610 запускает 3 ключевых процесса для VoIP:

```
┌─────────────────┐    unix socket      ┌──────────────┐    /dev/aci     ┌──────────────┐
│     sipcli      │◄──────────────────►│      mg      │◄──────────────►│    fvdsp     │
│ (PID ~335)      │  /tmp/.mg_cli0      │ (PID 179)    │  fvaci.ko      │ (PID 139-145)│
│                 │                     │              │  kernel mod    │ 7 потоков    │
│ SIP User Agent  │                     │ Media Gateway│                │ DSP/RTP      │
│ порт 5060/UDP   │                     │ RTP кодеки   │                │ аппаратный   │
└────────┬────────┘                     └──────┬───────┘                └──────────────┘
         │ SIP/UDP                              │ RTP/UDP
         ▼                                      ▼
   SIP-сервер                            Удалённый RTP endpoint
```

| Процесс | Бинарник | Назначение |
|---------|----------|------------|
| `sipcli` | `/usr/bin/sipcli` | SIP UA: регистрация, сигнализация, управление вызовами |
| `mg` | `/usr/bin/mg` | Media Gateway: кодеки, RTP, шифрование медиа-потока |
| `fvdsp` | `/usr/bin/fvdsp` | DSP: аппаратное кодирование/декодирование через драйвер fvaci.ko |

### 1.2 Вспомогательные процессы

| PID | Процесс | Назначение |
|-----|---------|------------|
| 116 | `/sbin/sysinfod` | Системная конфигурация (syscfg) |
| 117 | `/sbin/svcd` | Service controller — запуск/остановка/перезапуск сервисов |
| 151 | `/usr/sbin/httpd` | Web-интерфейс управления |
| 174 | `telnetd -p 13000` | CLI через telnet |
| 176 | `/sbin/ntp` | Синхронизация времени |
| 177 | `/usr/bin/rstdt` | Reset/watchdog |
| 178 | `/usr/bin/smb_module` | SimBank клиент (RSIM протокол) |
| 183 | `/usr/bin/ata` | ATA-контроллер GSM-модема |

### 1.3 Исходная структура кода DBLTek (28 файлов)

Восстановлено из отладочных строк бинарника:

| Файл | Назначение |
|------|------------|
| `main.c` | Точка входа, парсинг ~60 CLI-аргументов |
| `app.c` | Главный цикл приложения |
| `sipmsg.c` | Построение и парсинг SIP-сообщений |
| `call.c` | Управление вызовами (INVITE/BYE/CANCEL) |
| `callback.c` | Коллбэки событий oSIP (транзакционные автоматы) |
| `session.c` | Управление SIP-сессиями |
| `contact.c` | Управление SIP-контактами (регистрациями) |
| `alias.c` | Alias-система маппинга линий |
| `line.c` | Управление телефонными линиями |
| `group.c` | Группировка линий |
| `num2line.c` | Маршрутизация номеров на линии/каналы |
| `phone.c` | Телефонная логика (hook, DTMF, hold) |
| `proxy.c` | SIP-прокси режим (GoIP как SBC) |
| `transport.c` | UDP транспорт SIP |
| `uitrans.c` | UI-транспорт (взаимодействие с sysinfo/IPC) |
| `mgcli.c` | Клиент Media Gateway (протокол к `mg`) |
| `mgproto.c` | Протокол Media Gateway |
| `mgtrans.c` | Транспорт Media Gateway |
| `relay.c` | DBLTek Relay для NAT traversal |
| `stun.c` | STUN клиент |
| `srv.c` | DNS SRV resolve |
| `resolv.c` | DNS resolver |
| `ksock.c` | Сокеты ядра |
| `avscrypt.c` | AVS-шифрование |
| `voscrypt.c` | VOS-шифрование (совместимость с VOS2000) |
| `n2c_crypt.c` | N2C map-шифрование |
| `et263_encrypt.c` | ET263/HYBERTONE шифрование |

### 1.4 Взаимодействие sipcli ↔ MG (Media Gateway)

Протокол общения через unix socket `/tmp/.mg_cli0`:

| Функция MG-клиента | Действие |
|---------------------|----------|
| `mgcli_init` | Подключение к mg daemon |
| `mgcli_create_session` | Создание медиа-сессии для нового звонка |
| `mgcli_close_session` | Закрытие сессии при завершении звонка |
| `mgcli_open_channel` | Открытие аудио-канала |
| `mgcli_close_channel` | Закрытие канала |
| `mgcli_get_channel_info` | Запрос информации о канале |
| `mgcli_set_channel_info` | Установка параметров (кодек, адрес, порт) |
| `mgcli_set_channel_enable` | Включение/выключение канала |
| `mgcli_set_session_attr` | Установка атрибутов сессии (ключи шифрования) |
| `mgcli_send_event` | Отправка событий (DTMF, сигналы) |

Высокоуровневые операции:

| Функция sipcli | Когда вызывается |
|----------------|-----------------|
| `call_open_media` | При установке звонка (200 OK получен) |
| `call_close_media` | При завершении звонка (BYE) |
| `phone_enable_media` | Включение RTP-потока |
| `phone_disable_media` | Hold — приостановка |
| `phone_init_media` | Инициализация медиа из SDP |
| `phone_init_t38_media` | Инициализация T.38 факс-медиа |
| `phone_set_channel_info` | Настройка канала (кодек, RTP-адрес) |
| `phone_set_rfc2833_channel_info` | Настройка DTMF RFC 2833 |

### 1.5 IPC через /etc/ipin

| Сообщение | Когда записывается |
|-----------|-------------------|
| `IPPSTART` | Запуск в SINGLE/LINE/GROUP mode → SIP зарегистрирован |
| `TRUNKSTART` | Запуск в TRUNK_GW_MODE |
| `CLOSEMEDIA` | Медиа закрыто |
| `SIP_DEBUG=1` | Включение отладки (через `infosip`) |

---

## ЧАСТЬ 2: КОНФИГУРАЦИЯ И ЗАПУСК

### 2.1 Скрипт `/usr/bin/start_sip` — единственная точка запуска

`start_sip` — shell-скрипт, который:
1. Читает ~100 переменных из syscfg
2. Собирает CLI-аргументы для sipcli
3. Выполняет `exec /usr/bin/sipcli` с набором параметров

### 2.2 Четыре режима работы (SIP_CONFIG_MODE)

#### SINGLE_MODE — один аккаунт на все каналы
```
Логика start_sip:
1. Отключает все per-line контакты: SIP_CONTACT0..N_DISABLE=1
2. Настраивает единый контакт: SIP_CONTACT8_* (основной), SIP_CONTACT9_* (backup)
3. SIP_GROUP_NUM=1, все линии в группу 0
4. Флаги: --line-prefix 1 --syscfg --gateway 1 [--backup_svr]
5. При успехе: echo IPPSTART > /etc/ipin
```

#### TRUNK_GW_MODE — прямой транк без регистрации
```
Логика start_sip:
1. Добавляет --trunk-gw GW1,GW2,GW3 --proxy GW1
2. auth: -l AUTH_ID -p AUTH_PASSWD
3. регистрация: -e REGISTER_EXPIRED (0 = без регистрации)
4. порт: --lport LOCAL_PORT
5. echo TRUNKSTART > /etc/ipin
6. Флаги: --line-prefix 1 --gateway 1
```

#### LINE_MODE — отдельный аккаунт на каждый канал
```
sipcli читает SIP_CONTACT%d_* из syscfg для каждого канала.
До 4 суб-аккаунтов: _DIAL_DIGITS, _DIAL_DIGITS_2/3/4
Каждый канал регистрируется независимо.
Флаги: --line-prefix 1 --syscfg
```

#### GROUP_MODE — каналы сгруппированы
```
SIP_GROUP_NUM групп. SIP_LINE%d_GROUP привязывает канал к группе.
Одна регистрация на группу (не на канал).
Флаги: --line-prefix 1 --syscfg
```

### 2.3 Конфигурационная база — sip.def  

Файл `/usr/etc/syscfg/sip.def` определяет ~100 параметров:

**Alias-маппинг (SINGLE_MODE)**:
```
SIP_PROXY        → SIP_CONTACT8_PROXY
SIP_REGISTRAR    → SIP_CONTACT8_SERVER
SIP_DISPLAY_NAME → SIP_CONTACT8_DISPLAY_NAME, SIP_CONTACT9_DISPLAY_NAME
SIP_HOME_DOMAIN  → SIP_CONTACT8_HOME_DOMAIN
SIP_REGISTER_EXPIRED → SIP_CONTACT8_EXPIRED, SIP_CONTACT9_EXPIRED
SIP_PHONE_NUMBER → SIP_CONTACT8_DIAL_DIGITS, SIP_CONTACT9_DIAL_DIGITS
SIP_AUTH_ID      → SIP_CONTACT8_LOGIN, SIP_CONTACT9_LOGIN
SIP_AUTH_PASSWD  → SIP_CONTACT8_PASSWD, SIP_CONTACT9_PASSWD
SIP_BACKUP_REGISTRAR → SIP_CONTACT9_SERVER
SIP_BACKUP_PROXY     → SIP_CONTACT9_PROXY
```

### 2.4 Полный список CLI-аргументов sipcli (~60)

#### Основные
| Аргумент | Config | Описание |
|----------|--------|----------|
| `--line-prefix <N>` | — | Всегда 1 |
| `--gateway <N>` | — | Режим шлюза (SINGLE, TRUNK) |
| `--syscfg` | — | Читать конфиг из syscfg |
| `--agent <name>` | VENID | User-Agent header |
| `--nowait` | — | Не ждать SIM READY |
| `--lport <port>` | SIP_LOCAL_PORT | Локальный SIP-порт |
| `--random-port <port>` | CLI_PORT | Рандомизация порта |

#### Регистрация
| Аргумент | Config | Описание |
|----------|--------|----------|
| `-u <number>` | SIP_TRUNK_NUMBER | Номер пользователя |
| `-l <login>` | SIP_TRUNK_AUTH_ID | Логин auth |
| `-p <passwd>` | SIP_TRUNK_AUTH_PASSWD | Пароль auth |
| `-e <seconds>` | SIP_TRUNK_REGISTER_EXPIRED | Expires (0=без регистрации) |
| `--reg-mode <0\|1>` | SIP_REG_MODE | Режим регистрации |
| `--exp-mode <mode>` | SIP_EXP_MODE | Режим expires |
| `--backup_svr` | SIP_SMODE_USE_BSVR=1 | Backup SIP-сервер |
| `--rereg-inval <sec>` | SIP_FAIL_RETRY_INTERVAL | Retry при ошибке |
| `--link-test` | SIP_LINK_TEST=1 | Тест связи |

#### Вызовы и медиа
| Аргумент | Config | Описание |
|----------|--------|----------|
| `--ptime <ms>` | PACKETIZE_PERIOD | Packetization (20 мс) |
| `--dtmf <pt>` | DTMF_PAYLOAD_TYPE | DTMF payload type (101) |
| `--obddtmf <1\|2\|3>` | SIP_OUTBAND_DTMF_TYPE | 1=RFC2833, 2=INFO, 3=inband |
| `--early-media <N>` | SIP_183 | 1=183 early-media, 2=180 |
| `--inv-auth <N>` | SIP_INV_AUTH | Auth входящих INVITE |
| `--cid-fw-mode <N>` | SIP_CID_FW_MODE | CallerID forwarding |
| `--mwi <N>` | SIP_MWI | MWI подписка |
| `--vrb` | SIP_VIRTUAL_RB_TONE=1 | Виртуальный ringback |
| `--pkey` | POUND_KEY_AS_DIGIT=1 | # как цифра |
| `--busy-code <code>` | SIP_BUSY_CODE | SIP-код busy (480/486/603) |
| `--sms-tonum` | SIP_SMS_RTN=1 | SMS на номер |
| `--callee-mode 1` | SIP_CALLEE_MODE=1 | Режим callee |

#### Trunk / Proxy
| Аргумент | Config | Описание |
|----------|--------|----------|
| `--trunk-gw <gw1,gw2,gw3>` | SIP_TRUNK_GW1/2/3 | Trunk gateways |
| `--proxy <addr>` | auto | SIP proxy |
| `--proxy-mode` | SIP_AS_PROXY=1 | GoIP как SIP proxy |
| `--proxy-passwd <p>` | SIP_PROXY_PASSWD | Пароль proxy mode |
| `--prefix-del 1` | SIP_PREFIX_DEL=1 | Удалять префикс |
| `--dialler-cmp 1` | SIP_PREFIX_DIALLER_CMP=1 | Сравнение с dialler |
| `--sip-rsp-mode 1` | SIP_RSP_MODE=1 | Режим SIP-ответов |
| `-r 1` | SIP_ROUTE_FIELD_DISABLE=1 | Отключить Route |

#### NAT Traversal
| Аргумент | Config | Описание |
|----------|--------|----------|
| `-x <stun>` | SIP_STUN_SERVER | STUN сервер |
| `--relay-server <s>` | SIP_RELAY_SERVER* | DBLTek relay (до 5) |
| `--relay-port <port>` | SIP_RELAY_PORT | Порт relay |
| `--relay-user <user>` | SIP_RELAY_USER | Логин relay |
| `--relay-passwd <pass>` | SIP_RELAY_PASSWD | Пароль relay |
| `--relay-encrypt` | SIP_RELAY_ENCRYPT=1 | Шифрование relay |
| `--wan-addr <ip>` | WAN_ADDR | Внешний IP |
| `--nat-fw` | — | NAT port forwarding |

#### Шифрование (8 проприетарных методов)
| Аргумент | Config | Описание |
|----------|--------|----------|
| `--rc4-crypt` | SIP_CRYPT=RC4 | RC4 потоковый шифр |
| `--rc4-key <key>` | SIP_RC4_KEY | Ключ RC4 (по умолчанию `etoall.net`) |
| `--fast-crypt` | SIP_CRYPT=FAST | Быстрый проприетарный |
| `--xor-crypt` | — | Простой XOR |
| `--vos-crypt` | SIP_CRYPT=VOS | VOS2000 PBX совместимый |
| `--avs-crypt` | SIP_CRYPT=AVS | AVS проприетарный |
| `--n2c-crypt` | SIP_CRYPT=N2C | Подстановочный шифр |
| `--ecm-crypt` | SIP_CRYPT=ECM | ECM (ключ ECM_CRYPT_KEY) |
| `--et263-crypt` | SIP_CRYPT=ET263 | ET263/HYBERTONE |
| `--et263-crypt-type <T>` | SIP_ET263_CRYPT_TYPE | Тип ET263 |
| `--et263-crypt-dep <D>` | SIP_ET263_CRYPT_DEP | Глубина ET263 |

### 2.5 Anti-detection механизм: start_sip_port_change

```bash
# Каждые RANDOM_LC_PORT_INT минут:
killall sipcli  →  svcd перезапускает  →  CLI_PORT инкрементируется (5060→5061→...→6060→5060)
```

### 2.6 User-Agent маскировка

| VENID | User-Agent | Комментарий |
|-------|------------|-------------|
| `dble` | `dble` | Стандартный (DBLTek) |
| `et` | `HYBERTONE` | Переименовывается в start_sip |
| `et263` | `HYBERTONE` | Переименовывается в start_sip |
| `pak` | `pak` | Пакистанская версия |

---

## ЧАСТЬ 3: SIP-ПРОТОКОЛ — ЧТО ИМЕННО ОТПРАВЛЯЕТ КЛИЕНТ

### 3.1 Транзакционные автоматы (RFC 3261, реализация oSIP)

GoIP реализует все 4 автомата:

| Автомат | Роль | Коллбэки |
|---------|------|----------|
| **ICT** (INVITE Client Transaction) | GoIP отправляет INVITE | `ict_status_1xx_received`, `ict_status_2xx_received`, `ict_status_3xx_received`, `ict_status_4xx_received` |
| **NICT** (Non-INVITE Client Transaction) | GoIP отправляет REGISTER/BYE/OPTIONS | `nict_status_2xx_received`, `nict_status_4xx_received`, `nict_status_err_received` |
| **IST** (INVITE Server Transaction) | GoIP получает INVITE | `ist_invite_received` |
| **NIST** (Non-INVITE Server Transaction) | GoIP получает BYE/OPTIONS/INFO | `nist_register_received`, `nist_bye_received`, `nist_cancel_received`, `nist_info_received`, `nist_options_received`, `nist_notify_received` |

### 3.2 Формат Via

```
SIP/2.0/UDP <local_ip>:<local_port>;rport;branch=z9hG4bK<random_uint32>
```
- Всегда UDP (TCP не поддерживается sipcli)
- rport включён всегда (RFC 3581)
- branch: магический cookie `z9hG4bK` + случайное uint32

### 3.3 Формат From / To

| Контекст | Шаблон |
|----------|--------|
| Стандартный | `"DisplayName" <sip:user@domain>` |
| С портом | `"DisplayName" <sip:user@domain:port>` |
| С user=phone | `"DisplayName" <sip:user@domain:port;user=phone>` |
| Без display name | `<sip:user@domain>` |
| CLIR (скрытие номера) | `Anonymous <sip:user@domain>` |
| Полный CLIR | `Anonymous <sip:anonymous@domain>` |

From всегда содержит `;tag=<random>`.

### 3.4 Формат Contact

| Контекст | Шаблон |
|----------|--------|
| REGISTER | `<sip:user@local_ip:port>;expires=N` |
| INVITE | `<sip:user@local_ip:port>` |
| Deregister | `<sip:user@local_ip:port>;expires=0` |

### 3.5 Request-URI

| Контекст | Шаблон |
|----------|--------|
| REGISTER | `sip:server_domain` |
| INVITE исходящий | `sip:called_number@server_domain` |
| INVITE с портом | `sip:called_number@server:port` |
| С user=phone | `sip:called_number@server:port;user=phone` |
| BYE/ACK | `sip:called_number@remote_ip:port` (из Contact ответа) |

### 3.6 Allow (всегда одинаковый)

```
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
```

### 3.7 Поддерживаемые заголовки (полный список)

**Генерируемые (отправляемые):**
- Via, From, To, Contact, Call-ID, CSeq, Max-Forwards, Content-Type, Content-Length
- User-Agent, Authorization, Proxy-Authorization, Allow, Supported
- Route (если не отключён), Refer-To, P-Asserted-Identity
- **X-ACrypt** (проприетарный — при шифровании)

**Парсируемые (принимаемые):**
```
Via, From, To, Call-ID, CSeq, Contact, Content-Type, Content-Length,
Max-Forwards, User-Agent, Record-Route, Route,
WWW-Authenticate, Proxy-Authenticate, Proxy-Authorization,
Expires, Allow, Supported, Alert-Info,
Accept-Encoding, Accept-Language, Authentication-Info,
Content-Encoding, Error-Info, Min-Expires, MIME-Version, Call-Info,
P-Asserted-Identity, Remote-Party-ID, Referred-By, Refer-To,
Subscription-State, Message-ID, Messages-Waiting, Voice-Message,
X-ACrypt
```

### 3.8 Content-Type значения

| Content-Type | Использование |
|-------------|---------------|
| `application/sdp` | SDP в INVITE/re-INVITE/200 OK |
| `application/dtmf-relay` | DTMF через SIP INFO |
| `application/simple-message-summary` | MWI NOTIFY |
| `application/simple-message-status` | Статус сообщений |
| `application/broadsoft` | BroadSoft совместимость |
| `text/plain` | SIP MESSAGE (SMS) |

---

## ЧАСТЬ 4: СЦЕНАРИИ SIP-ДИАЛОГОВ

### 4.1 REGISTER — регистрация (полный цикл)

```
GoIP (sipcli)                                    SIP Server
    │                                                 │
    │ ─── REGISTER (без auth) ──────────────────────► │
    │                                                 │
    │ ◄── 401 Unauthorized ──────────────────────────  │
    │     WWW-Authenticate: Digest realm="...",        │
    │     nonce="...", algorithm=MD5, qop="auth"       │
    │                                                 │
    │ ─── REGISTER (с Authorization) ───────────────► │
    │     Authorization: Digest username=...,          │
    │     realm=..., nonce=..., response=...,          │
    │     cnonce=..., qop=auth                        │
    │                                                 │
    │ ◄── 200 OK ─────────────────────────────────────│
    │                                                 │
    │  ... каждые SIP_REGISTER_EXPIRED секунд ...      │
    │                                                 │
    │ ─── REGISTER (перерегистрация) ─────────────── ► │
```

**Ключевые особенности:**
- CSeq инкрементируется при каждом REGISTER (1 → 2)
- Call-ID остаётся одним на всю сессию регистрации
- Tag в From остаётся постоянным
- При неудаче: retry через `SIP_FAIL_RETRY_INTERVAL` секунд
- При полном отказе основного: fallback на backup сервер (CONTACT9)
- При `SIP_REG_MODE=1` (ET263): специальный режим регистрации

### 4.2 INVITE исходящий (GoIP → SIP Server) — полный цикл

```
GSM                GoIP (sipcli)                         SIP Server
 │                      │                                     │
 │── Входящий GSM ─────►│                                     │
 │   звонок              │                                     │
 │                      │─── INVITE (SDP) ──────────────────►│
 │                      │                                     │
 │                      │◄── 100 Trying ──────────────────── │
 │                      │                                     │
 │                      │◄── 407 Proxy Auth Required ─────── │ (если proxy auth)
 │                      │                                     │
 │                      │─── INVITE (Proxy-Authorization) ──►│ (повторный с auth)
 │                      │                                     │
 │                      │◄── 180 Ringing ─────────────────── │
 │                      │                                     │
 │                      │◄── [183 Session Progress + SDP] ── │ (early media)
 │                      │    → GoIP начинает RTP к серверу    │
 │                      │    → GSM-абонент слышит КПВ/IVR    │
 │                      │                                     │
 │                      │◄── 200 OK (SDP) ────────────────── │
 │                      │                                     │
 │                      │─── ACK ──────────────────────────► │
 │                      │                                     │
 │◄═══ GSM аудио ═══════│════════════ RTP ═══════════════════│
 │                      │                                     │
```

**Ключевые особенности:**
- From: `"DisplayName" <sip:registered_user@domain>;tag=<random>`
- To: `<sip:dialed_number@domain>` (без tag)
- Contact: `<sip:registered_user@local_ip:port>`
- Call-ID: `<random>@<local_ip>`
- CSeq: начинается с 1 INVITE
- ACK: Request-URI берётся из Contact ответа (не из оригинального INVITE!)
- При 407: повторный INVITE с CSeq=2, тем же Call-ID, новым branch

### 4.3 INVITE входящий (SIP Server → GoIP) — полный цикл

```
SIP Server                    GoIP (sipcli)                    GSM
    │                              │                             │
    │─── INVITE (SDP) ───────────►│                             │
    │                              │                             │
    │◄── 100 Trying ──────────────│                             │
    │                              │                             │
    │ (если SIP_INV_AUTH=1):       │                             │
    │◄── 401 Unauthorized ────────│                             │
    │    WWW-Authenticate: realm= │                             │
    │    "goip", nonce="..."      │                             │
    │─── INVITE (Authorization) ─►│                             │
    │                              │                             │
    │                              │─── MG: setup_channel ─────►│
    │                              │─── AT: ATD<number> ────────►│
    │                              │                             │
    │◄── 180 Ringing ─────────────│ ◄── GSM: набирает номер    │
    │                              │                             │
    │                              │     GSM: абонент ответил ──►│
    │◄── 200 OK (SDP) ────────────│                             │
    │                              │                             │
    │─── ACK ────────────────────►│                             │
    │                              │─── MG: start_rtp ──────────►│
    │                              │                             │
    │═══════════ RTP ══════════════│════════ GSM аудио ══════════│
```

**Ответы GoIP при busy/недоступности:**
| Ситуация | Ответ GoIP | Примечание |
|----------|-----------|------------|
| GSM занят | `480 Remote Busy` | **Нестандартный!** RFC говорит 480=Temporarily Unavailable |
| SIP_BUSY_CODE=603 | `603 Decline` | Настраиваемый |
| SIP_BUSY_CODE=486 | `486 Busy Here` | Настраиваемый |
| Нет свободных каналов | Зависит от SIP_BUSY_CODE | |

### 4.4 BYE — завершение вызова

GoIP отправляет BYE когда:
- GSM-абонент повесил трубку
- Таймаут без ответа (UNANSWER_EXP)
- RTP dead-time (MG_RTP_DT секунд без RTP)

```
BYE sip:<called>@<remote_ip>:<port> SIP/2.0
Via: SIP/2.0/UDP <local_ip>:<port>;rport;branch=z9hG4bK<rand>
From: <original_from>;tag=<tag>
To: <original_to>;tag=<remote_tag>
Call-ID: <same_call_id>
CSeq: <N> BYE          ← N = последний CSeq + 1
Max-Forwards: 70
User-Agent: dble
Content-Length: 0
```

### 4.5 CANCEL — отмена исходящего INVITE

Отправляется когда GSM-абонент повесил трубку **до получения 200 OK**:

```
CANCEL sip:<called>@<server> SIP/2.0
Via: SIP/2.0/UDP <local_ip>:<port>;rport;branch=<SAME_BRANCH_AS_INVITE>
From: <original_from>;tag=<tag>
To: <original_to>
Call-ID: <same_call_id>
CSeq: 1 CANCEL          ← CSeq номер тот же, метод CANCEL
```

**КРИТИЧЕСКИ ВАЖНО:** Via branch в CANCEL **ДОЛЖЕН** совпадать с branch в оригинальном INVITE.

### 4.6 re-INVITE — Hold / Retrieve

**Hold (sendonly):**
```
INVITE sip:<called>@<remote_ip>:<port> SIP/2.0
...
CSeq: <N+1> INVITE
...
a=sendonly
```

**Retrieve (sendrecv):**
```
...
a=sendrecv
```

SDP session version инкрементируется: `o=userX 20000001 20000002 ...` → `o=userX 20000001 20000003 ...`

### 4.7 REFER — трансфер вызова

```
REFER sip:<called>@<remote_ip>:<port> SIP/2.0
...
Refer-To: <sip:new_destination@server>
```

Ожидаемый ответ: `202 Accepted`.

### 4.8 MESSAGE — SMS через SIP

**Входящее SMS (GSM → SIP):**
```
MESSAGE sip:<sms_admin>@<server> SIP/2.0
...
Content-Type: text/plain
Content-Length: <len>

<текст SMS>
```

**Исходящее SMS (SIP → GSM):**
```
MESSAGE sip:<goip_user>@<goip_ip>:<port> SIP/2.0
...
Content-Type: text/plain
Content-Length: <len>

Номер:<dst_number> <текст>
```

При `SIP_SMS_RTN=1`: GoIP отправляет ответ на номер отправителя.

### 4.9 INFO — DTMF

```
INFO sip:<called>@<remote_ip>:<port> SIP/2.0
...
Content-Type: application/dtmf-relay
Content-Length: 26

Signal=5
Duration=160
```

Значения Signal: `0`-`9`, `*`, `#`. Duration: `80` или `160` мс.

### 4.10 OPTIONS — keepalive

При `SIP_NO_ALIVE=0` GoIP периодически отправляет:
```
OPTIONS sip:<server> SIP/2.0
...
```

Также GoIP поддерживает keep-alive пакеты с характерным форматом: `Content-Length:     4` (5 пробелов).

### 4.11 SUBSCRIBE — MWI

При `SIP_MWI=1`:
```
SUBSCRIBE sip:<user>@<server> SIP/2.0
...
Event: message-summary
```

---

## ЧАСТЬ 5: SDP — MEDIA DESCRIPTION

### 5.1 Шаблон SDP GoIP

```
v=0
o=userX 20000001 20000001 IN IP4 <LOCAL_IP>
s=DBL Session
c=IN IP4 <LOCAL_IP>
t=0 0
m=audio <RTP_PORT> RTP/AVP <codec_list> <dtmf_pt>
a=rtpmap:<pt> <codec>/<rate>
[a=rtpmap:...]
a=fmtp:<dtmf_pt> 0-15
a=ptime:<PACKETIZE_PERIOD>
a=sendrecv
```

### 5.2 Фиксированные значения SDP (fingerprint!)

| Поле SDP | Значение | Примечание |
|----------|----------|------------|
| `o=` username | `userX` | **Всегда** — fingerprint! |
| `o=` session-id | `20000001` | **Всегда начальное** — fingerprint! |
| `o=` session-version | `20000001` → инкремент | +1 при re-INVITE |
| `s=` | `DBL Session` | **Всегда** — явный fingerprint DBLTek! |
| `c=` | `IN IP4 <LOCAL_IP>` | Реальный IP (или STUN/WAN_ADDR) |
| RTP порт | `10000` (типичный) | Конфигурируемый |

### 5.3 Кодеки и payload types

| PT | Кодек | rtpmap | a=fmtp |
|----|-------|--------|--------|
| 0 | PCMU | `PCMU/8000` | — |
| 3 | GSM | `GSM/8000` | — |
| 4 | G723 | `G723/8000` | — |
| 8 | PCMA | `PCMA/8000` | — |
| 18 | G729 | `G729/8000` | — |
| 101 | telephone-event | `telephone-event/8000` | `0-15` |

Порядок кодеков определяется `AUDIO_CODEC_PREFERENCE`:
```
alaw,ulaw,g729,g729a,g729ab,g7231,!gsm
```
Префикс `!` = отключён.

### 5.4 При шифровании

```diff
- m=audio 10000 RTP/AVP 8 0 101
+ m=audio 10000 RTP/SAVP 8 0 101
```

**ВАЖНО**: GoIP **НЕ** добавляет `a=crypto:` строку (стандартный SDES). Вместо этого ключи обмениваются через `X-ACrypt`.

### 5.5 T.38 Fax

```
m=image <port> udptl t38
a=T38FaxVersion:0
a=T38FaxRateManagement:transferredTCF
a=T38FaxMaxBuffer:200
a=T38FaxMaxDatagram:72
a=T38FaxUdpEC:t38UDPRedundancy
```

---

## ЧАСТЬ 6: ШИФРОВАНИЕ (8 проприетарных методов)

### ВАЖНО: GoIP НЕ использует стандартные SRTP/SDES/DTLS-SRTP!

### 6.1 Механизм обмена ключами

1. GoIP добавляет проприетарный заголовок `X-ACrypt` в SIP-сообщения
2. В SDP меняет `RTP/AVP` на `RTP/SAVP`
3. Ключ передаётся на Media Gateway через `mgcli_set_session_attr`
4. MG/fvdsp выполняет шифрование/дешифрование RTP

### 6.2 Таблица методов

| # | Метод | CLI | Ключ | Алгоритм |
|---|-------|-----|------|----------|
| 1 | **RC4** | `--rc4-crypt --rc4-key <k>` | По умолчанию `etoall.net` | Потоковый RC4 (модифицированный, 13 пар S-box swap) |
| 2 | **FAST** | `--fast-crypt` | SCNo + Factor | Проприетарный быстрый |
| 3 | **XOR** | `--xor-crypt` | — | Простой XOR |
| 4 | **VOS** | `--vos-crypt` | VOSID | Совместимость с VOS2000 PBX |
| 5 | **AVS** | `--avs-crypt` | — | Проприетарный (TKPT_DeSecret) |
| 6 | **N2C** | `--n2c-crypt` | — | Подстановочное шифрование |
| 7 | **ECM** | `--ecm-crypt` | ECM_CRYPT_KEY | ECM |
| 8 | **ET263** | `--et263-crypt` | type+dep | HYBERTONE, авто SIP_REG_MODE=1 |

### 6.3 RC4 — детали модификации DBLTek

Из `udp_sniffer.js` — DBLTek использует **модифицированный RC4** с 13 дополнительными S-box свопами после стандартной инициализации:

```javascript
const EXTRA_SWAPS = [
  [1,5], [4,56], [10,47], [15,185], [23,74],
  [28,129], [33,42], [44,66], [55,73], [77,99],
  [88,124], [111,250], [200,220]
];
```

Известные ключи: `dbl#admin`, `1111`, `dbltek`, `admin`, `simbank`, `etoall.net`.

### 6.4 X-ACrypt формат

```
X-ACrypt: RC4:etoall.net
X-ACrypt: FAST
X-ACrypt: ET263
```

---

## ЧАСТЬ 7: NAT TRAVERSAL

### 7.1 STUN
```bash
sipcli ... -x stun.server.com
```
GoIP выполняет STUN Binding Request, получает mapped address, использует в Via/Contact/SDP.

### 7.2 DBLTek Relay (проприетарный)
```bash
sipcli ... --relay-server relay1.com,relay2.com --relay-port 1701 \
  --relay-bind-ext1 --relay-user user --relay-passwd pass
```
- Порт по умолчанию: 1701
- До 5 серверов для failover
- Опциональное шифрование: `--relay-encrypt`
- Функции: `relay_bind`, `relay_sendto`, `relay_recvfrom`, `relay_keepalive`

### 7.3 Port Forwarding
```bash
sipcli ... --wan-addr <PUBLIC_IP> --nat-fw
```

---

## ЧАСТЬ 8: ТАЙМЕРЫ И ТАЙМАУТЫ

| Параметр | По умолчанию | Диапазон | Описание |
|----------|-------------|----------|----------|
| `SIP_REGISTER_EXPIRED` | 60 | — | Интервал перерегистрации (сек) |
| `SIP_TRUNK_REGISTER_EXPIRED` | 0 | — | Trunk регистрация (0 = отключена) |
| `RETRANSMIT_T1` | 200 | 200-2000 | SIP Timer T1 (мс, RTT estimate) |
| `RETRANSMIT_T2` | 2000 | 2000-8000 | SIP Timer T2 (мс, max retransmit) |
| `INVITE_TS_EXP` | 5 | 5-360 | Таймаут INVITE транзакции (сек) |
| `NON_INVITE_TS_EXP` | 2 | 2-180 | Таймаут non-INVITE транзакции (сек) |
| `UNANSWER_EXP` | 180 | 32-180 | Таймаут без ответа (сек) |
| `SIP_FAIL_RETRY_INTERVAL` | — | 1-60 | Retry при ошибке регистрации (сек) |
| `NONE_RB_EXP` | — | — | Таймаут без ringback tone (сек) |
| `MG_RTP_DT` | 10 | — | RTP dead-time detector (сек) |
| `SIP_KEEPALIVE_INTERVAL` | — | — | Keep-alive интервал (сек) |

Лог таймеров: `t1=%d t2=%d iv_ts=%d non_iv_ts=%d unanswer_exp=%d`

---

## ЧАСТЬ 9: FINGERPRINTING GoIP

### Уникальные признаки в SIP-трафике

| Признак | Значение | Вероятность GoIP |
|---------|----------|-----------------|
| User-Agent | `dble` или `HYBERTONE` | Очень высокая |
| SDP `s=` | `DBL Session` | Абсолютная |
| SDP `o=` | `o=userX 20000001 ...` | Абсолютная |
| Response 480 | `480 Remote Busy` | Абсолютная (нестандартный reason phrase) |
| Header `X-ACrypt` | Присутствует | Абсолютная (проприетарный) |
| SDP `RTP/SAVP` без `a=crypto:` | Присутствует | Очень высокая |
| Contact format | `<sip:user@ip>;expires=N` | Средняя |
| Via branch | `z9hG4bK` + uint32 | Средняя (oSIP формат) |
| keep-alive | `Content-Length:     4` | Высокая (5 пробелов) |

### Рекомендации по маскировке

1. Заменить `User-Agent: dble` через SBC/прокси
2. Заменить `s=DBL Session` на `s=-` или `s=SIP Call`
3. Рандомизировать `o=userX 20000001` → `o=- <random> <random>`
4. Перехватывать `480 Remote Busy` → `480 Temporarily Unavailable`
5. Удалять `X-ACrypt` если не нужно шифрование
6. Использовать B2BUA/SBC для полной маскировки

---

## ЧАСТЬ 10: СВОДНАЯ ДИАГРАММА ВСЕХ ПОТОКОВ

### Входящий SIP → GSM (полный)

```
SIP Server                GoIP (sipcli)              mg/fvdsp             GSM модем
    │                         │                          │                    │
    │── INVITE (SDP) ────────►│                          │                    │
    │◄── 100 Trying ──────────│                          │                    │
    │                         │── mgcli_create_session ─►│                    │
    │                         │── mgcli_open_channel ───►│                    │
    │                         │                          │── ATD<number> ────►│
    │◄── 180 Ringing ─────────│                          │                    │
    │                         │                          │◄── CONNECT ────────│
    │◄── 200 OK (SDP) ────────│                          │                    │
    │── ACK ─────────────────►│                          │                    │
    │                         │── mgcli_set_channel_info►│                    │
    │                         │── phone_enable_media ───►│                    │
    │◄════════ RTP ═══════════│═════════════════════════►│◄══ GSM аудио ═════►│
    │                         │                          │                    │
    │── BYE ─────────────────►│  или GSM hangup ────────►│                    │
    │◄── 200 OK ──────────────│                          │                    │
    │                         │── mgcli_close_session ──►│                    │
```

### Исходящий GSM → SIP (полный)

```
GSM модем              GoIP (sipcli)              mg/fvdsp             SIP Server
    │                         │                          │                    │
    │── RING (входящий) ─────►│                          │                    │
    │                         │── INVITE (SDP) ─────────────────────────────►│
    │                         │◄── 100 Trying ──────────────────────────────│
    │                         │◄── [407 Proxy Auth] ────────────────────────│
    │                         │── INVITE (Auth) ────────────────────────────►│
    │                         │◄── 180 Ringing ─────────────────────────────│
    │◄── CONNECT (ответ) ─────│                          │                    │
    │                         │◄── 200 OK (SDP) ────────────────────────────│
    │                         │── ACK ──────────────────────────────────────►│
    │                         │── mgcli_create_session ─►│                    │
    │                         │── phone_enable_media ───►│                    │
    │◄══ GSM аудио ═══════════│═════════════════════════►│═══════ RTP ═══════►│
    │                         │                          │                    │
    │── GSM hangup ──────────►│── BYE ──────────────────────────────────────►│
    │                         │◄── 200 OK ──────────────────────────────────│
    │                         │── mgcli_close_session ──►│                    │
```
