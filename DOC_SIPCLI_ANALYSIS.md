# Анализ SIP-стека GoIP — `/usr/bin/sipcli`

> Результат реверс-инжиниринга бинарника `sipcli` (658 064 байт)  
> Платформа: ARM (OABI), uClibc 0.9.29, GCC 3.3.5 (Debian)  
> Производитель: DBLTek / HYBERTONE (GoIP VoIP-шлюз)

---

## 1. SIP-стек: GNU oSIP (libosip2)

**Библиотека**: GNU oSIP / libosip2 + osipparser2  
**Линковка**: **статическая** (все функции встроены в бинарник, внешних `.so` нет)  
**eXosip2**: НЕ используется — прикладной уровень полностью кастомный DBLTek

### Доказательства

| Строка из бинарника | Значение |
|---|---|
| `set_osip_default_value` | Инициализация конфигурации oSIP |
| `OSIP message init error!` | Ошибка создания SIP-сообщения |
| `../../src/osipparser2/osip_message_parse.c` | Парсер SIP из libosip2 |
| `error in msg_osip_body_parse()` | Парсинг тела SIP-сообщения |

### Транзакционные автоматы (RFC 3261, реализация libosip2)

**INVITE Client Transaction (ICT):**
- `ict_status_1xx_received` — получен provisional ответ (100 Trying, 180 Ringing)
- `ict_status_2xx_received` — получен успешный ответ (200 OK)
- `ict_status_3xx_received` — получен redirect (301, 302)
- `ict_status_4xx_received` — получена ошибка (4xx, 5xx, 6xx)

**Non-INVITE Client Transaction (NICT):**
- `nict_status_2xx_received`
- `nict_status_4xx_received`
- `nict_status_err_received`

**INVITE Server Transaction (IST):**
- `ist_invite_received`

**Non-INVITE Server Transaction (NIST):**
- `nist_register_received`
- `nist_bye_received`
- `nist_cancel_received`
- `nist_info_received`
- `nist_options_received`
- `nist_notify_received`

---

## 2. Исходная структура проекта DBLTek

Пути из отладочных строк бинарника — полная карта исходников:

| Файл | Назначение |
|---|---|
| `../src/main.c` | Точка входа, парсинг CLI-аргументов |
| `../src/app.c` | Логика приложения, главный цикл |
| `../src/sipmsg.c` | Построение/парсинг SIP-сообщений |
| `../src/call.c` | Управление звонками (INVITE/BYE) |
| `../src/callback.c` | Коллбэки событий oSIP |
| `../src/session.c` | Управление SIP-сессиями |
| `../src/contact.c` | Управление SIP-контактами (линиями) |
| `../src/alias.c` | Alias-система (маппинг линий) |
| `../src/line.c` | Управление телефонными линиями |
| `../src/group.c` | Группировка линий |
| `../src/num2line.c` | Маршрутизация номеров на линии |
| `../src/phone.c` | Телефонная логика (hook off/on, DTMF) |
| `../src/proxy.c` | SIP-прокси режим |
| `../src/transport.c` | UDP/TCP транспорт SIP |
| `../src/uitrans.c` | UI-транспорт (взаимодействие с sysinfo) |
| `../src/mgcli.c` | Клиент Media Gateway (unix socket `/tmp/.mg_cli0`) |
| `../src/mgproto.c` | Протокол Media Gateway |
| `../src/mgtrans.c` | Транспорт Media Gateway |
| `../src/relay.c` | DBLTek Relay NAT traversal |
| `../src/stun.c` | STUN клиент |
| `../src/srv.c` | DNS SRV resolve |
| `../src/resolv.c` | DNS resolver |
| `../src/ksock.c` | Сокеты ядра |
| `../src/avscrypt.c` | AVS-шифрование |
| `../src/voscrypt.c` | VOS-шифрование (совместимость с VOS2000) |
| `../src/n2c_crypt.c` | N2C map-шифрование |
| `../src/et263_encrypt.c` | ET263/HYBERTONE шифрование |
| `../../src/osipparser2/osip_message_parse.c` | Парсер oSIP (статически влинкован) |

---

## 3. Архитектура медиа-подсистемы

```
┌─────────────┐     unix socket      ┌──────────────┐      ┌──────────────┐
│   sipcli    │ ──────────────────── │      mg      │ ──── │    fvdsp     │
│ (SIP UA)    │   /tmp/.mg_cli0      │ (Media GW)   │      │ (DSP/RTP)    │
│             │                      │              │      │ 7 потоков    │
│ SIP ←→ oSIP│                      │ RTP/кодеки   │      │ /dev/aci     │
└─────────────┘                      └──────────────┘      └──────────────┘
       ↕                                    ↕                      ↕
   UDP/TCP                             UDP (RTP)            kernel module
   порт 5060                           динамич. порт        fvaci.ko
```

### Взаимодействие sipcli → mg (Media Gateway)

Протокол общения через unix socket `/tmp/.mg_cli0`:

| Функция | Назначение |
|---|---|
| `mgcli_init` | Подключение к Media Gateway |
| `mgcli_create_session` | Создание медиа-сессии |
| `mgcli_close_session` | Закрытие медиа-сессии |
| `mgcli_open_channel` | Открытие аудио-канала |
| `mgcli_close_channel` | Закрытие канала |
| `mgcli_get_channel_info` | Информация о канале |
| `mgcli_set_channel_info` | Установка параметров канала (кодек, адрес, порт) |
| `mgcli_set_channel_enable` | Включение/выключение канала |
| `mgcli_set_session_attr` | Установка атрибутов сессии (**включая ключи шифрования**) |
| `mgcli_send_event` | Отправка событий (DTMF и др.) |
| `mgcli_send_packet` | Отправка пакетов |
| `mgcli_get_session_info` | Информация о сессии |

### Высокоуровневые медиа-операции (в sipcli)

| Функция | Действие |
|---|---|
| `call_open_media` / `phone_open_media` | Открытие медиа при установке звонка |
| `call_close_media` / `phone_close_media` | Закрытие медиа при завершении звонка |
| `phone_enable_media` | Включение медиа-потока |
| `phone_disable_media` | Выключение (hold) |
| `phone_enable_media_conf` | Включение конференции |
| `phone_init_media` | Инициализация медиа из SDP |
| `phone_init_t38_media` | Инициализация T.38 факс-медиа |
| `phone_set_channel_info` | Настройка канала (кодек, RTP-адрес) |
| `phone_set_rfc2833_channel_info` | Настройка DTMF через RFC 2833 |
| `phone_set_t38_channel_info` | Настройка T.38 канала |

### Управляющие сообщения к /etc/ipin

| Сообщение | Событие |
|---|---|
| `IPPSTART` | SIP registered, система готова |
| `TRUNKSTART` | Trunk-режим запущен |
| `CLOSEMEDIA` | Медиа закрыто |

---

## 4. SIP-заголовки — шаблоны и форматы

### Генерируемые заголовки исходящих сообщений

| Заголовок | Шаблон/формат |
|---|---|
| **Via** | `SIP/2.0/UDP %s;branch=z9hG4bK%u` |
| **Via (с rport)** | `SIP/2.0/UDP %s;rport;branch=z9hG4bK%u` |
| **From/To** | `<sip:%s@%s>` |
| **Contact** | `<sip:%s@%s>;expires=%d` |
| **Route (lr)** | `<sip:%s;lr>` |
| **Replace-ID** | `%s;to-tag=%s;from-tag=%s` |
| **Content-Length** | `Content-Length:     4` (keep-alive) |
| **Max-Forwards** | стандартный (обычно 70) |
| **User-Agent** | задаётся через `--agent` (`dble`, `HYBERTONE`, или `pak`) |
| **X-ACrypt** | проприетарный заголовок — обмен ключами шифрования |

### Обрабатываемые заголовки (парсинг)

```
Via:                    Record-Route:           Route:
From:                   To:                     Call-ID:
CSeq:                   Contact:                Content-Type:
Content-Length:          Max-Forwards:           User-Agent:
WWW-Authenticate:       Proxy-Authenticate:     Proxy-Authorization:
Expires:                Allow:                  Supported:
Alert-Info:             Accept-Encoding:        Accept-Language:
Authentication-Info:    Content-Encoding:       Error-Info:
Min-Expires:            MIME-Version:           Call-Info:
P-Asserted-Identity:    Remote-Party-ID:        Referred-By:
Refer-To:               Subscription-State:     Message-ID:
Messages-Waiting:       Voice-Message:          X-ACrypt:
```

### Методы SIP

| Метод | Поддержка |
|---|---|
| **REGISTER** | ✅ Регистрация, backup server, trunk |
| **INVITE** | ✅ Входящие/исходящие вызовы, re-INVITE |
| **ACK** | ✅ |
| **BYE** | ✅ |
| **CANCEL** | ✅ |
| **OPTIONS** | ✅ Keep-alive и capabilities |
| **INFO** | ✅ DTMF через SIP INFO |
| **NOTIFY** | ✅ MWI (Message Waiting) |
| **SUBSCRIBE** | ✅ Подписки (MWI) |
| **REFER** | ✅ Call transfer |
| **MESSAGE** | ✅ SIP SMS |

---

## 5. SDP — шаблоны и медиа-описание

### Шаблон генерируемого SDP

```
v=0
o=userX 20000001 20000001 IN IP4 TOREPLACE
s=(session name)
c=IN IP4 TOREPLACE
t=0 0
m=audio <port> RTP/AVP <payload_types>
a=rtpmap:<pt> <codec>/<rate>
a=ptime:<ms>
a=sendrecv
```

> `TOREPLACE` — заменяется на реальный IP при отправке  
> При шифровании: `RTP/AVP` → `RTP/SAVP`

### Функции создания SDP

| Функция | Назначение |
|---|---|
| `call_create_local_sdp` | SDP для исходящего INVITE |
| `call_create_t38_sdp` | SDP для факса T.38 |
| `line_create_local_sdp` | SDP при входящем вызове |
| `line_create_sdp_with_call` | SDP на основе параметров текущего звонка |
| `line_create_sdp` | Общее создание SDP |
| `line_create_t38_sdp` | SDP для T.38 входящего |
| `sdp_get_ptime` | Извлечение ptime из SDP |
| `sdp_set_acrypt_key` | Установка ключа шифрования в SDP (через `X-ACrypt`) |
| `encode_media_fmt` | Кодирование формата медиа |
| `encode_media_gateway_info` | Кодирование информации для MG |

### Атрибуты direction

| Атрибут SDP | Использование |
|---|---|
| `a=sendrecv` | Нормальный двусторонний вызов |
| `a=sendonly` | Hold — отправка (локальный hold) |
| `a=recvonly` | Hold — приём |
| `a=inactive` | Полный hold |

### Поддержка T.38 Fax over IP

```
m=image <port> udptl t38
a=T38FaxVersion
a=T38FaxFillBitRemoval
a=T38FaxTranscodingJBIG
a=T38FaxTranscodingMMR
a=T38FaxRateManagement
a=T38FaxMaxBuffer
a=T38FaxMaxDatagram
a=T38FaxUdpEC: t38UDPFEC / t38UDPRedundancy
```

---

## 6. Поддерживаемые аудио-кодеки

| Кодек | SDP rtpmap | Payload Type |
|---|---|---|
| **G.711 μ-law (PCMU)** | `PCMU/8000` | 0 |
| **G.711 A-law (PCMA)** | `PCMA/8000` | 8 |
| **GSM FR** | `GSM/8000` | 3 |
| **G.723.1** | `G723/8000` | 4 |
| **G.729** | `G729/8000` | 18 |
| **G.729a** | (вариант G.729) | 18 |
| **G.729ab** | (с VAD/CNG) | 18 |
| **telephone-event** | `telephone-event/8000` | настраиваемый (по умолчанию 101) |

Конфигурация: `P%d_AUDIO_CODEC_PREFERENCE` (приоритет кодеков на каждом порту)

> **Видео**: формально `Video codecs Supported:` присутствует в бинарнике, но реальных видеокодеков не обнаружено — скорее всего заглушка.

---

## 7. DTMF — три метода передачи

| Метод | Флаг `--obddtmf` | Описание |
|---|---|---|
| **RFC 2833** (out-of-band RTP) | `1` | telephone-event в RTP, настройка через `phone_set_rfc2833_channel_info` |
| **SIP INFO** | `2` | DTMF через SIP INFO method, `dtmf_with_sip_info` |
| **Inband** | `3` | DTMF тоны в аудио-потоке, `INBAND_DTMF=1` |

Payload type настраивается: `--dtmf <PT>` (обычно 101), `DTMF_PAYLOAD_TYPE`

---

## 8. Система шифрования — 8 проприетарных методов

> **ВАЖНО**: GoIP НЕ использует стандартные SRTP (RFC 3711), SDES (RFC 4568), DTLS-SRTP.  
> Все методы — проприетарные разработки DBLTek.

### Общий механизм

1. Ключи обмениваются через **проприетарный SIP-заголовок `X-ACrypt`**
2. В SDP медиа-линия указывает **`RTP/SAVP`** вместо `RTP/AVP`
3. Ключ передаётся на Media Gateway через `fast_crypt_set_session_attr` → `mgcli_set_session_attr`
4. MG/fvdsp выполняет шифрование/дешифрование RTP-пакетов

### Метод 1: RC4

| Параметр | Значение |
|---|---|
| **CLI** | `--rc4-crypt --rc4-key <key>` |
| **Конфиг** | `SIP_CRYPT=RC4`, `SIP_RC4_KEY=<key>` |
| **Алгоритм** | Потоковый шифр RC4 |
| **Ключ** | Пользовательский (по умолчанию `etoall.net`) |
| **Лог** | `rc4 crypt: %s` / `rc4 decrypt: %s` |

### Метод 2: Fast Crypt

| Параметр | Значение |
|---|---|
| **CLI** | `--fast-crypt` |
| **Конфиг** | `SIP_CRYPT=FAST` |
| **Алгоритм** | Проприетарный "быстрый" шифр |
| **Ключ сессии** | Генерируется через `SCNo` (sequence number) и `Factor` |
| **Лог** | `SCNo=%d Factor=%d raw_len=%d len=%d` |
| **Ошибка** | `fast_decrypt() error: len=%d` |

### Метод 3: XOR

| Параметр | Значение |
|---|---|
| **CLI** | `--xor-crypt` |
| **Алгоритм** | Простой XOR |
| **Уровень защиты** | Минимальный (обфускация) |

### Метод 4: VOS (совместимость с VOS2000 PBX)

| Параметр | Значение |
|---|---|
| **CLI** | `--vos-crypt` |
| **Конфиг** | `SIP_CRYPT=VOS` |
| **Исходник** | `../src/voscrypt.c` |
| **Функции** | `vos_crypt_encrypt`, `vos_crypt_decrypt`, `create_voscrypt`, `vos_crypt_release` |
| **Ключ** | На основе `VOSID` — `get_vos_key`, `get_vos_id_by_msg`, `get_vos_passwd_by_id` |
| **Совместимость** | VOS2000 IP PBX |
| **Лог** | `vos_key=%d`, `id=%s, key=%s` |

### Метод 5: AVS

| Параметр | Значение |
|---|---|
| **CLI** | `--avs-crypt` |
| **Конфиг** | `SIP_CRYPT=AVS` |
| **Исходник** | `../src/avscrypt.c` |
| **Функции** | `avs_encrypt` |
| **Детали** | `TKPT_DeSecret` — обратная функция |

### Метод 6: N2C (Number-to-Code mapping)

| Параметр | Значение |
|---|---|
| **CLI** | `--n2c-crypt` |
| **Конфиг** | `SIP_CRYPT=N2C` |
| **Исходник** | `../src/n2c_crypt.c` |
| **Функции** | `n2c_map_encrypt`, `n2c_map_decrypt` |
| **Алгоритм** | Подстановочное (mapping) шифрование |

### Метод 7: ECM

| Параметр | Значение |
|---|---|
| **CLI** | `--ecm-crypt` |
| **Конфиг** | `SIP_CRYPT=ECM` |
| **Ключ** | `ECM_CRYPT_KEY` |

### Метод 8: ET263 (HYBERTONE)

| Параметр | Значение |
|---|---|
| **CLI** | `--et263-crypt --et263-crypt-type <type> --et263-crypt-dep <depth>` |
| **Конфиг** | `SIP_CRYPT=ET263`, `SIP_ET263_CRYPT`, `SIP_ET263_CRYPT_TYPE`, `SIP_ET263_CRYPT_DEP` |
| **Исходник** | `../src/et263_encrypt.c` |
| **Особенности** | При включении автоматически устанавливается `SIP_REG_MODE=1`, `SIP_EXP_MODE=1`, `SIP_LINK_TEST=1` |

### Шифрование Relay-канала

| Параметр | Значение |
|---|---|
| **CLI** | `--relay-encrypt` |
| **Назначение** | Шифрование SIP/RTP при NAT traversal через DBLTek Relay |
| **Отдельно от RTP-шифрования** | Может комбинироваться с любым из 8 методов |

### "DBL Auth" — проприетарная аутентификация

```
using the dbl encrypt auth method     — проприетарный метод
using the new encrypt method          — "новый" метод
using the simple auth method          — "простой" метод
encrypt key: %08lx(%02lx)            — ключ шифрования
encrypt using key: %02lx             — ключ для шифрования
decrypt using key: %02lx             — ключ для расшифрования
relay_dbl_auth                        — аутентификация на relay
```

---

## 9. NAT Traversal — три метода

### STUN

| Параметр | Значение |
|---|---|
| **CLI** | `-x <stun_server>` |
| **Конфиг** | `SIP_NAT_TRAVERSAL=STUN`, `SIP_STUN_SERVER` |
| **Исходник** | `../src/stun.c` |
| **Функции** | `phone_stun`, STUN binding request/response |
| **Лог** | `mappedAddress is`, `NAT IP:%s:%d`, `Received stun message: %d bytes` |

### DBLTek Relay (проприетарный)

| Параметр | Значение |
|---|---|
| **CLI** | `--relay-server <addr> --relay-port <port> --relay-user <user> --relay-passwd <pass>` |
| **Конфиг** | `SIP_NAT_TRAVERSAL=RELAY`, `SIP_RELAY_SERVER` (до 5 серверов), `SIP_RELAY_PORT` |
| **Исходник** | `../src/relay.c` |
| **Режимы** | `relay-bind-ext1`, `relay-udp-ext1`, `relay-appoint-saddr` |
| **Шифрование** | `--relay-encrypt` |
| **Функции** | `relay_bind`, `relay_sendto`, `relay_recvfrom`, `relay_keepalive`, `relay_listen` |
| **Лог** | `relay bind ext1 mode used !!!`, `trying relay server: %s:%d` |

### Port Forwarding

| Параметр | Значение |
|---|---|
| **CLI** | `--portfwd` |
| **Конфиг** | `SIP_PORTFWD_GW` |

### Keep-alive

```
SIP_KEEPALIVE_INTERVAL  — интервал keep-alive
phone_check_keepalive   — проверка необходимости
no keepalive!           — keep-alive отключён
no need to keepalive!   — не требуется
UDP keepalive!          — UDP keep-alive отправлен
```

---

## 10. SIP-ответы (Status Codes)

### Полный набор поддерживаемых reason phrases

**1xx Provisional:**
- `Trying`
- `Ringing` (→ `REMOTE-RINGING`)
- `Queued`
- `Session Progress` (early media)

**2xx Success:**
- `OK`

**3xx Redirection:**
- `Multiple Choices`
- `Moved Permanently`
- `Moved Temporarily`
- `Use Proxy`
- `Alternative Service`

**4xx Client Error:**
- `Bad Request`
- `Unauthorized`
- `Payment Required`
- `Forbidden`
- `Not Found`
- `Method Not Allowed`
- `Not Acceptable`
- `Proxy Authentication Required`
- `Request Timeout`
- `Conflict`
- `Gone`
- `Request Entity Too Large`
- `Request-URI Too Large`
- `Unsupported Media Type`
- `Unsupported Uri Scheme`
- `Bad Extension`
- `Interval Too Short`
- `Temporarily Unavailable` / `Temporarily not available`
- `Call/Transaction Does Not Exist`
- `Address Incomplete`
- `Ambiguous`
- `Busy Here` (→ `REMOTE-BUSY`)
- `Decline`
- `Does not exist anywhere`
- `Busy Everywhere`
- `Not Acceptable Here`

**5xx Server Error:**
- `Internal Server Error`
- `Not Implemented`
- `Bad Gateway`
- `Service Unavailable`
- `Gateway Time-out`

### Жёстко закодированные ответы

```c
"SIP/2.0 200 OK"           // Успешный ответ
"SIP/2.0 480 Remote Busy"  // Кастомный (нестандартный reason phrase!)
```

> Стандартный 480 = "Temporarily Unavailable", но GoIP шлёт `480 Remote Busy` — это fingerprint DBLTek!

---

## 11. Режимы работы sipcli

### Конфигурационные режимы (SIP_CONFIG_MODE)

| Режим | Описание |
|---|---|
| **SINGLE_MODE** | Одна SIP-линия на все каналы |
| **LINE_MODE** | Отдельная SIP-линия на каждый канал |
| **TRUNK_GW_MODE** | Trunk-режим (до 3 шлюзов) |
| **GROUP_MODE** | Группировка каналов |

### Запуск sipcli (из start_sip)

**SINGLE_MODE:**
```bash
exec /usr/bin/sipcli --line-prefix 1 --syscfg --gateway 1 \
  --agent dble --nowait --ptime 20 --dtmf 101 \
  --reg-mode 0 --cid-fw-mode 1 --early-media 1 \
  --inv-auth 1 --sip-rsp-mode 1 \
  --random-port 5113 \
  --relay-server 194.99.21.42 --relay-port 1701 \
  --relay-bind-ext1 --relay-user 1 --relay-passwd 1
```

**TRUNK_GW_MODE:**
```bash
exec /usr/bin/sipcli --line-prefix 1 --gateway 1 \
  --trunk-gw <gw1>,<gw2>,<gw3> --proxy <gw1> \
  -u <number> -e <expires> --lport <port> \
  -l <auth_id> -p <auth_passwd> \
  $SIP_PARAMS $sip_tos $nat_params $sip_crypt
```

---

## 12. Полный список CLI-аргументов sipcli

### Основные

| Аргумент | Описание |
|---|---|
| `--agent <name>` | User-Agent (dble, HYBERTONE, pak) |
| `--syscfg` | Читать конфигурацию из syscfg |
| `--gateway <n>` | Номер шлюза |
| `--line-prefix <n>` | Префикс линии |
| `--nowait` | Не ждать |
| `--lport <port>` | Локальный SIP-порт |
| `--random-port <port>` | Случайный порт (начальный) |
| `--mode <n>` | Режим работы |
| `--no-ui` | Без UI |
| `--console-phone` | Консольный режим |

### SIP-регистрация

| Аргумент | Описание |
|---|---|
| `-u <number>` | SIP Phone Number |
| `-l <login>` | Auth ID |
| `-p <password>` | Auth Password |
| `-e <seconds>` | Registration expires |
| `--reg-mode <0\|1>` | Режим регистрации |
| `--exp-mode <mode>` | Режим expires |
| `--backup_svr` | Использовать backup SIP-сервер |
| `--rereg-inval <sec>` | Интервал повторной регистрации при ошибке |
| `--link-test` | Тест связи |
| `--subscribe-expiry <sec>` | Время подписки |

### Вызовы и медиа

| Аргумент | Описание |
|---|---|
| `--ptime <ms>` | Packetization time (обычно 20) |
| `--dtmf <PT>` | DTMF payload type (обычно 101) |
| `--obddtmf <1\|2\|3>` | Тип DTMF: 1=RFC2833, 2=SIP INFO, 3=inband |
| `--early-media <1\|2>` | Early media: 1=183, 2=180 |
| `--vrb` | Virtual ringback tone |
| `--cid-fw-mode <n>` | Caller ID forwarding mode |
| `--callee-mode <1>` | Режим callee |
| `--pkey` | Pound key (#) как цифра |
| `--inv-auth <n>` | INVITE authentication |
| `--mwi <mode>` | Message Waiting Indication |
| `--sms-tonum` | SMS на номер |
| `--max-pending-call <n>` | Макс. ожидающих вызовов |
| `--busy-code <code>` | SIP-код при busy (по умолчанию 603) |
| `--music-on-hold` | Музыка на удержании |

### Прокси/Trunk

| Аргумент | Описание |
|---|---|
| `--proxy <addr>` | SIP proxy (для trunk) |
| `--proxy-mode` | Работать как SIP-прокси |
| `--proxy-passwd <pass>` | Пароль прокси |
| `--trunk-gw <gw1,gw2,gw3>` | Trunk gateways |
| `--prefix-del <1>` | Удалять префикс |
| `--dialler-cmp <1>` | Сравнение с dialler |
| `--sip-rsp-mode <1>` | Режим SIP-ответов |
| `--wan-addr <ip>` | WAN IP-адрес |
| `--nat-fw` | NAT firewall mode |
| `-r <1>` | Отключить Route field |

### NAT Traversal

| Аргумент | Описание |
|---|---|
| `-x <server>` | STUN сервер |
| `--relay-server <addr>` | Relay сервер (до 5) |
| `--relay-port <port>` | Порт relay |
| `--relay-user <user>` | Пользователь relay |
| `--relay-passwd <pass>` | Пароль relay |
| `--relay-encrypt` | Шифрование relay |
| `--relay-bind-ext1` | Режим bind ext1 |
| `--relay-udp-ext1` | UDP ext1 |
| `--relay-appoint-saddr` | Назначенный source addr |
| `--portfwd` | Port forwarding |
| `--tos <value>` | ToS/DiffServ |

### Шифрование

| Аргумент | Описание |
|---|---|
| `--rc4-crypt` | RC4 шифрование |
| `--rc4-key <key>` | Ключ RC4 |
| `--fast-crypt` | "Быстрое" шифрование |
| `--xor-crypt` | XOR шифрование |
| `--vos-crypt` | VOS2000 шифрование |
| `--avs-crypt` | AVS шифрование |
| `--n2c-crypt` | N2C map-шифрование |
| `--ecm-crypt` | ECM шифрование |
| `--et263-crypt` | ET263 шифрование |
| `--et263-crypt-type <n>` | Тип ET263 |
| `--et263-crypt-dep <n>` | Глубина ET263 |

---

## 13. Взаимодействие с другими процессами

### Список процессов GoIP

| PID | Процесс | Назначение |
|---|---|---|
| 1 | `init` | Инициализация системы |
| 116 | `/sbin/sysinfod` | Системный информационный демон |
| 117 | `/sbin/svcd` | Service controller (управление службами) |
| 139-145 | `/usr/bin/fvdsp` | DSP-процессор (7 потоков) |
| 151 | `/usr/sbin/httpd` | Web-интерфейс |
| 156 | `udhcpc` | DHCP-клиент |
| 174 | `telnetd -p 13000` | CLI через telnet |
| 176 | `/sbin/ntp` | Синхронизация времени |
| 177 | `/usr/bin/rstdt` | Reset/watchdog |
| 178 | `/usr/bin/smb_module` | SimBank модуль |
| 179 | `/usr/bin/mg` | **Media Gateway** (RTP) |
| 181 | `start_sip_port_change` | Периодическая смена SIP-порта |
| 183 | `/usr/bin/ata` | ATA-контроллер (GSM модем) |
| ~335 | `/usr/bin/sipcli` | **SIP User Agent** |

### Вспомогательные скрипты

| Скрипт | Назначение |
|---|---|
| `/usr/bin/start_sip` | Запуск sipcli с параметрами из конфигурации |
| `/usr/bin/start_sip_port_change` | Периодический `killall sipcli` для смены порта |
| `/usr/sbin/infosip` | Включение SIP debug: `SIP_DEBUG=1 > /etc/ipin` |
| `/usr/sbin/infogsmsip` | Включение GSM+SIP debug |
| `/usr/sbin/sipdb` | SIP debug утилита |

### Управление через svcd

```
svcd_processServiceCallback(): SERVICE: sipcli callback event=1   — запуск
svcd_processServiceCallback(): SERVICE: sipcli callback event=2   — завершение
svcd_do_stop(): stop service : sipcli                             — остановка
svcd_restart_service(): restart service: sipcli                   — перезапуск
svcd_processSyscfgChange(): process service sipcli dependent syscfg — изменение конфигурации
svcd_reload_service(): processing service sipcli                  — перезагрузка
```

---

## 14. DNS и SRV

| Функция/строка | Описание |
|---|---|
| `../src/srv.c` | DNS SRV resolve |
| `../src/resolv.c` | DNS resolver |
| `using SRV record: %s.%s:%i` | Использование SRV-записи |
| `Domain name not found` | DNS ошибка |
| `Could not contact DNS servers` | DNS недоступен |
| `dnssrv-enable` | Включение/выключение DNS SRV |

---

## 15. SIP Timers (конфигурируемые)

| Параметр | Диапазон | Описание |
|---|---|---|
| `RETRANSMIT_T1` | 200-2000 мс | Timer T1 (RTT estimate) |
| `RETRANSMIT_T2` | 2000-8000 мс | Timer T2 (max retransmit) |
| `INVITE_TS_EXP` | 5-360 сек | INVITE transaction timeout |
| `NON_INVITE_TS_EXP` | 2-180 сек | Non-INVITE transaction timeout |
| `UNANSWER_EXP` | 32-180 сек | No answer timeout |
| `UNANSWER_FW_EXP` | — | No answer forward timeout |
| `NONE_RB_EXP` | — | No ringback timeout |
| `SIP_REGISTER_EXPIRED` | — | Registration expires (обычно 60 сек) |
| `SIP_KEEPALIVE_INTERVAL` | — | Keep-alive интервал |
| `SIP_FAIL_RETRY_INTERVAL` | 1-60 сек | Повтор при ошибке регистрации |

Лог: `t1=%d t2=%d iv_ts=%d non_iv_ts=%d unanswer_exp=%d`

---

## 16. Fingerprinting GoIP по SIP-трафику

### Уникальные идентификаторы

| Признак | Значение |
|---|---|
| **User-Agent** | `dble` или `HYBERTONE` |
| **Via branch** | `z9hG4bK` + unsigned int (стандартный oSIP формат) |
| **Session origin** | `o=userX 20000001 20000001 IN IP4 ...` |
| **480 response** | `SIP/2.0 480 Remote Busy` (нестандартный reason phrase) |
| **X-ACrypt header** | Проприетарный заголовок шифрования |
| **RTP/SAVP без стандартного crypto=** | SAVP без `a=crypto` строки в SDP |
| **keep-alive** | `Content-Length:     4` (5 пробелов — характерное форматирование) |

---

## 17. Резюме

**SIP-стек**: GNU oSIP (libosip2) — статически скомпонован  
**Прикладной уровень**: полностью проприетарный код DBLTek (28 исходных файлов)  
**Шифрование**: 8 проприетарных методов (RC4, Fast, XOR, VOS, AVS, N2C, ECM, ET263) — НЕ стандартный SRTP  
**Медиа**: через отдельный процесс `mg` (Media Gateway) по unix socket  
**NAT**: STUN + проприетарный Relay DBLTek  
**Кодеки**: PCMU, PCMA, GSM, G.723.1, G.729/a/ab + T.38 факс  
**DTMF**: RFC 2833 / SIP INFO / Inband  
