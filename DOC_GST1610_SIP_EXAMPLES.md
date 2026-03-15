# GST1610 (GHSFVT-1.1-68-11) — SIP протокол: полный справочник с примерами

> Реверс-инжиниринг прошивки GHSFVT-1.1-68-11 (DBLTek / HYBERTONE GST1610)
> Бинарный: `/usr/bin/sipcli` (658,064 bytes, ARM OABI, uClibc 0.9.29, GCC 3.3.5)
> SIP-стек: **GNU oSIP (libosip2 + osipparser2)**, статически скомпилирован
> Прикладной уровень: полностью проприетарный (28 .c файлов из `../src/`)

---

## Содержание

1. [Архитектура и процессы](#1-архитектура-и-процессы)
2. [Режимы конфигурации](#2-режимы-конфигурации-sip_config_mode)
3. [Параметры SIP-заголовков](#3-параметры-sip-заголовков)
4. [REGISTER — регистрация](#4-register--регистрация)
5. [INVITE — исходящий вызов](#5-invite--исходящий-вызов)
6. [Входящий INVITE — ответ GoIP](#6-входящий-invite--ответ-goip)
7. [BYE — завершение вызова](#7-bye--завершение-вызова)
8. [CANCEL — отмена вызова](#8-cancel--отмена-вызова)
9. [re-INVITE — смена параметров сессии](#9-re-invite--смена-параметров-сессии)
10. [REFER — трансфер вызова](#10-refer--трансфер-вызова)
11. [MESSAGE — SMS через SIP](#11-message--sms-через-sip)
12. [INFO — DTMF через SIP INFO](#12-info--dtmf-через-sip-info)
13. [OPTIONS — keepalive / проверка доступности](#13-options--keepalive--проверка-доступности)
14. [SUBSCRIBE/NOTIFY — MWI (голосовая почта)](#14-subscribenotify--mwi)
15. [Шифрование SIP и RTP](#15-шифрование-sip-и-rtp)
16. [SDP-шаблон и кодеки](#16-sdp-шаблон-и-кодеки)
17. [DTMF — три режима](#17-dtmf--три-режима)
18. [NAT Traversal](#18-nat-traversal)
19. [Примеры для SINGLE_MODE](#19-примеры-для-single_mode)
20. [Примеры для TRUNK_GW_MODE](#20-примеры-для-trunk_gw_mode)
21. [Примеры для LINE_MODE](#21-примеры-для-line_mode)
22. [Примеры для GROUP_MODE](#22-примеры-для-group_mode)
23. [CLI-параметры sipcli](#23-cli-параметры-sipcli)
24. [Таймеры и таймауты](#24-таймеры-и-таймауты)
25. [Фингерпринтинг GoIP](#25-фингерпринтинг-goip)

---

## 1. Архитектура и процессы

```
┌────────────┐     unix socket      ┌──────────┐     /dev/aci      ┌──────────┐
│  sipcli    │ ◄──────────────────► │    mg    │ ◄──────────────► │  fvdsp   │
│ SIP UA     │   /tmp/.mg_cli0      │ Media GW │   kernel module   │ DSP/RTP  │
│ port 5060  │                      │          │   fvaci.ko         │ 7 threads│
└────────────┘                      └──────────┘                   └──────────┘
      │                                  │
      │ SIP/UDP                          │ RTP/UDP
      ▼                                  ▼
  SIP Server                        Remote RTP endpoint
```

**Процессы:**
- `sipcli` — SIP User Agent (регистрация, сигнализация, управление вызовами)
- `mg` — Media Gateway (кодеки, RTP, шифрование медиа)
- `fvdsp` — DSP процессор (аппаратное кодирование/декодирование через fvaci.ko)

**Запуск:**
```bash
# start_sip вызывает:
exec /usr/bin/sipcli --line-prefix 1 [--gateway 1] [--syscfg] $SIP_PARAMS $sip_tos $nat_params $sip_crypt

# start_mg вызывает:
exec /usr/bin/mg $params $rtp_tos $transport $log_params $rtp_dt_params
```

---

## 2. Режимы конфигурации (SIP_CONFIG_MODE)

### 2.1 SINGLE_MODE
- **Одна регистрация** для всех GSM-каналов
- Используются параметры `SIP_CONTACT8_*` (основной сервер) и `SIP_CONTACT9_*` (резервный)
- Все каналы разделяют один SIP-аккаунт
- Вызовы маршрутизируются на любой свободный GSM-канал
- Флаги запуска: `--line-prefix 1 --syscfg --gateway 1 [--backup_svr]`

### 2.2 LINE_MODE
- **Отдельная регистрация** для каждого GSM-канала
- Канал N использует `SIP_CONTACT<N>_*` параметры
- До **4 суб-аккаунтов** на каждый контакт: `_DIAL_DIGITS`, `_DIAL_DIGITS_2`, `_DIAL_DIGITS_3`, `_DIAL_DIGITS_4`
- Каждый канал может иметь свой SIP-сервер, логин, пароль
- Флаги запуска: `--line-prefix 1 --syscfg`

### 2.3 TRUNK_GW_MODE
- **Прямой транк** к SIP-серверу/PBX без регистрации (или с trunk-регистрацией)
- До **3 транк-шлюзов**: `SIP_TRUNK_GW1`, `SIP_TRUNK_GW2`, `SIP_TRUNK_GW3`
- Опциональная аутентификация: `SIP_TRUNK_AUTH_ID`, `SIP_TRUNK_AUTH_PASSWD`
- CLI порт может отличаться от SIP порта (рандомизация)
- Флаги запуска: `--line-prefix 1 --gateway 1 --trunk-gw GW1,GW2,GW3 --proxy GW1`

### 2.4 GROUP_MODE
- **Группировка каналов** — несколько каналов в одну SIP-группу
- `SIP_GROUP_NUM` — количество групп
- `SIP_LINE<N>_GROUP` — привязка канала к группе
- `SIP_CONTACT<GROUP>_*` — параметры SIP для группы
- Каждая группа регистрируется независимо
- Флаги запуска: `--line-prefix 1 --syscfg`

---

## 3. Параметры SIP-заголовков

### Формат URI (From, To, Contact)

| Шаблон | Когда используется |
|--------|-------------------|
| `"%s" <sip:%s@%s>` | Стандартный: `"Display" <sip:user@server>` |
| `"%s" <sip:%s@%s:%s>` | С портом: `"Display" <sip:user@server:5060>` |
| `"%s" <sip:%s@%s:%s;user=phone>` | С `user=phone`: `"Display" <sip:1001@pbx:5060;user=phone>` |
| `<sip:%s@%s>` | Без display name |
| `<sip:%s@%s>;expires=0` | UNREGISTER (отмена регистрации) |
| `<sip:%s@%s>;expires=%d` | REGISTER Contact с expires |
| `Anonymous <sip:%s@%s>` | Скрытие CallerID (CLIR) |
| `Anonymous <sip:anonymous@%s>` | Полное скрытие CallerID |
| `"%s" <sip:%s@%s>;party=calling;screen=no;privacy=off` | P-Asserted-Identity формат |
| `<sip:%s;lr>` | Route / loose routing |
| `sip:%s@%s` | Request-URI |
| `sip:%s@%s:%s` | Request-URI с портом |
| `sip:%s@%s:%s;user=phone` | Request-URI с user=phone |

### Via

```
SIP/2.0/UDP <local_ip>:<local_port>;rport;branch=z9hG4bK<random_uint32>
SIP/2.0/UDP <local_ip>:<local_port>;branch=z9hG4bK<random_uint32>
```

### Поддерживаемые методы (Allow)

```
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
```

### Заголовки поддерживаемые sipcli

| Заголовок | Описание |
|-----------|----------|
| `Via` | Маршрутизация (UDP only) |
| `From` / `To` | Адресация, с tag |
| `Contact` | Адрес контакта с expires |
| `Call-ID` | Идентификатор сессии |
| `CSeq` | Последовательность запросов |
| `Max-Forwards` | Ограничение хопов |
| `Content-Type` | Тип тела сообщения |
| `Content-Length` | Длина тела |
| `User-Agent` | Идентификатор UA (VENID) |
| `Authorization` | Digest auth |
| `Proxy-Authorization` | Proxy auth |
| `Route` / `Record-Route` | Маршрутизация |
| `Refer-To` | Цель трансфера |
| `P-Asserted-Identity` | Идентификация звонящего |
| `Subscription-State` | Состояние подписки |
| `Event` | Тип события (message-summary) |
| `Supported` | Поддерживаемые расширения |
| `X-ACrypt` | **Проприетарный** — обмен ключами шифрования |

### Content-Type значения

| Content-Type | Использование |
|-------------|---------------|
| `application/sdp` | SDP в INVITE/re-INVITE/200 OK |
| `application/dtmf-relay` | DTMF через SIP INFO |
| `application/simple-message-summary` | MWI уведомления |
| `application/simple-message-status` | Статус сообщений |
| `application/broadsoft` | BroadSoft совместимость |
| `text/plain` | SIP MESSAGE (SMS) |

---

## 4. REGISTER — регистрация

### 4.1 Начальный REGISTER (без аутентификации)

```
REGISTER sip:sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK847291563
From: "GoIP_1" <sip:1001@sip.example.com>;tag=82945612
To: "GoIP_1" <sip:1001@sip.example.com>
Call-ID: 7483920156@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:1001@192.168.50.66:5060>;expires=60
Max-Forwards: 70
User-Agent: dble
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
Content-Length: 0

```

### 4.2 Ответ 401 от сервера

```
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK847291563
From: "GoIP_1" <sip:1001@sip.example.com>;tag=82945612
To: "GoIP_1" <sip:1001@sip.example.com>;tag=as3f7c4b21
Call-ID: 7483920156@192.168.50.66
CSeq: 1 REGISTER
WWW-Authenticate: Digest realm="asterisk", nonce="4a1b2c3d", algorithm=MD5, qop="auth"
Content-Length: 0

```

### 4.3 REGISTER с аутентификацией (Digest)

```
REGISTER sip:sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK947382156
From: "GoIP_1" <sip:1001@sip.example.com>;tag=82945612
To: "GoIP_1" <sip:1001@sip.example.com>
Call-ID: 7483920156@192.168.50.66
CSeq: 2 REGISTER
Contact: <sip:1001@192.168.50.66:5060>;expires=60
Max-Forwards: 70
User-Agent: dble
Authorization: Digest username=1001, realm=asterisk, nonce=4a1b2c3d, response=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6, cnonce=1234abcd, qop=auth
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
Content-Length: 0

```

### 4.4 Успешный ответ 200 OK

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK947382156
From: "GoIP_1" <sip:1001@sip.example.com>;tag=82945612
To: "GoIP_1" <sip:1001@sip.example.com>;tag=as3f7c4b21
Call-ID: 7483920156@192.168.50.66
CSeq: 2 REGISTER
Contact: <sip:1001@192.168.50.66:5060>;expires=60
Content-Length: 0

```

### 4.5 Deregister (снятие регистрации)

```
REGISTER sip:sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK147382956
From: "GoIP_1" <sip:1001@sip.example.com>;tag=82945612
To: "GoIP_1" <sip:1001@sip.example.com>
Call-ID: 7483920156@192.168.50.66
CSeq: 3 REGISTER
Contact: <sip:1001@192.168.50.66:5060>;expires=0
Max-Forwards: 70
User-Agent: dble
Authorization: Digest username=1001, realm=asterisk, nonce=4a1b2c3d, response=f1e2d3c4b5a6f7e8d9c0b1a2f3e4d5c6, cnonce=5678efgh, qop=auth
Content-Length: 0

```

### Ключевые особенности REGISTER в GoIP:
- **`SIP_REG_MODE=0`** — стандартная регистрация (CSeq REGISTER)
- **`SIP_REG_MODE=1`** — ET263 режим (используется с ET263-шифрованием)
- **Таймер перерегистрации** = `SIP_REGISTER_EXPIRED` (по умолчанию 60 сек)
- **Retry при провале** = `SIP_FAIL_RETRY_INTERVAL` секунд
- **Fallback на backup сервер**: `register failed. login to backup server`
- При TRUNK_GW_MODE и `SIP_TRUNK_REGISTER_EXPIRED=0` — регистрация НЕ выполняется

---

## 5. INVITE — исходящий вызов

### 5.1 Исходящий INVITE (GoIP → SIP Server → PSTN/VoIP)

Пользователь звонит с GSM на GoIP, GoIP отправляет INVITE на SIP-сервер:

```
INVITE sip:79161234567@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>
Call-ID: 9182736450@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
Content-Type: application/sdp
Content-Length: 307

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 0 18 4 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:4 G723/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

### 5.2 Ответ 100 Trying

```
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>
Call-ID: 9182736450@192.168.50.66
CSeq: 1 INVITE
Content-Length: 0

```

### 5.3 Ответ 180 Ringing

```
SIP/2.0 180 Ringing
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:79161234567@10.0.0.1:5060>
Content-Length: 0

```

### 5.4 Ответ 183 Session Progress (Early Media)

При `SIP_183=2` (early-media 1) или `SIP_183=1` (early-media 2) GoIP обрабатывает раннюю медиа:

```
SIP/2.0 183 Session Progress
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:79161234567@10.0.0.1:5060>
Content-Type: application/sdp
Content-Length: 185

v=0
o=server 234 567 IN IP4 10.0.0.1
s=SIP Call
c=IN IP4 10.0.0.1
t=0 0
m=audio 20000 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
```

> GoIP начинает отправлять RTP на указанный адрес — GSM-абонент слышит КПВ/IVR.

### 5.5 Ответ 200 OK

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:79161234567@10.0.0.1:5060>
Content-Type: application/sdp
Content-Length: 185

v=0
o=server 234 567 IN IP4 10.0.0.1
s=SIP Call
c=IN IP4 10.0.0.1
t=0 0
m=audio 20000 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=sendrecv
```

### 5.6 ACK

```
ACK sip:79161234567@10.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK385720146
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 1 ACK
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 5.7 INVITE с Proxy-Authorization (407)

Если прокси требует аутентификацию (407 Proxy Authentication Required):

```
INVITE sip:79161234567@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK584739201
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>
Call-ID: 9182736450@192.168.50.66
CSeq: 2 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Proxy-Authorization: Digest username=1001, realm=asterisk, nonce=5b2c3d4e, response=b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6a7, cnonce=abcd1234, qop=auth
Content-Type: application/sdp
Content-Length: 307

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 0 18 4 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:4 G723/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

---

## 6. Входящий INVITE — ответ GoIP

### 6.1 Входящий INVITE (SIP Server → GoIP → GSM)

```
INVITE sip:1001@192.168.50.66:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
Contact: <sip:79031234567@10.0.0.1:5060>
Max-Forwards: 70
Content-Type: application/sdp
Content-Length: 200

v=0
o=server 100 100 IN IP4 10.0.0.1
s=SIP Call
c=IN IP4 10.0.0.1
t=0 0
m=audio 30000 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
a=sendrecv
```

### 6.2 GoIP отвечает 100 Trying

```
SIP/2.0 100 Trying
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
Content-Length: 0

```

### 6.3 GoIP отвечает 180 Ringing (набирает GSM-номер)

```
SIP/2.0 180 Ringing
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>;tag=goiptag456
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Content-Length: 0

```

### 6.4 GoIP отвечает 200 OK (GSM абонент снял трубку)

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>;tag=goiptag456
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Content-Type: application/sdp
Content-Length: 280

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

### 6.5 GoIP отвечает 480 Remote Busy (GSM абонент занят)

> **ВНИМАНИЕ**: Это нестандартный reason phrase! По RFC 480 = "Temporarily Unavailable". GoIP отправляет `480 Remote Busy` — это уникальный фингерпринт DBLTek.

```
SIP/2.0 480 Remote Busy
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>;tag=goiptag456
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
Content-Length: 0

```

### 6.6 GoIP отвечает кодом SIP_BUSY_CODE (настраиваемый)

При `SIP_BUSY_CODE=603`:
```
SIP/2.0 603 Decline
```
При `SIP_BUSY_CODE=486`:
```
SIP/2.0 486 Busy Here
```

### 6.7 Аутентификация входящего INVITE (SIP_INV_AUTH)

При `SIP_INV_AUTH=1` GoIP требует аутентификацию от инициатора входящего INVITE:

```
SIP/2.0 401 Unauthorized
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKserver123
From: "Caller" <sip:79031234567@10.0.0.1>;tag=svrtag789
To: <sip:1001@192.168.50.66:5060>;tag=goiptag456
Call-ID: srv-call-123@10.0.0.1
CSeq: 1 INVITE
WWW-Authenticate: Digest realm="goip", nonce="abc123def"
Content-Length: 0

```

---

## 7. BYE — завершение вызова

### 7.1 GoIP инициирует BYE (GSM абонент повесил трубку)

```
BYE sip:79161234567@10.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK673829145
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 2 BYE
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 7.2 Ответ 200 OK на BYE

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK673829145
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 2 BYE
Content-Length: 0

```

---

## 8. CANCEL — отмена вызова

### 8.1 GoIP отменяет исходящий INVITE (GSM абонент повесил трубку до ответа)

```
CANCEL sip:79161234567@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK284719365
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>
Call-ID: 9182736450@192.168.50.66
CSeq: 1 CANCEL
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

> **Обратите внимание**: Via branch в CANCEL ДОЛЖЕН совпадать с branch в оригинальном INVITE.

---

## 9. re-INVITE — смена параметров сессии

### 9.1 re-INVITE для Hold (удержание вызова)

GoIP ставит вызов на hold (отправляет `a=sendonly`):

```
INVITE sip:79161234567@10.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK773920815
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 3 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Content-Type: application/sdp
Content-Length: 245

v=0
o=userX 20000001 20000002 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
a=sendonly
```

### 9.2 re-INVITE для Retrieve (снятие с удержания)

```
...
a=sendrecv
```

> Версия SDP (второе число в `o=`) инкрементируется: `20000002` → `20000003`

---

## 10. REFER — трансфер вызова

### 10.1 GoIP инициирует blind transfer

```
REFER sip:79161234567@10.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK882937461
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 4 REFER
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Refer-To: <sip:79039876543@sip.example.com>
Content-Length: 0

```

### 10.2 Ответ 202 Accepted

```
SIP/2.0 202 Accepted
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK882937461
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 4 REFER
Content-Length: 0

```

---

## 11. MESSAGE — SMS через SIP

### 11.1 Входящее SMS (GSM → GoIP → SIP MESSAGE)

Когда на SIM-карту GoIP приходит SMS, он отправляет SIP MESSAGE:

```
MESSAGE sip:sms_admin@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK192038475
From: "GoIP_1" <sip:1001@sip.example.com>;tag=44827361
To: <sip:sms_admin@sip.example.com>
Call-ID: msg-7294810@192.168.50.66
CSeq: 1 MESSAGE
Max-Forwards: 70
User-Agent: dble
Content-Type: text/plain
Content-Length: 25

Привет, это тестовое SMS
```

### 11.2 Исходящее SMS (SIP MESSAGE → GoIP → GSM)

SIP-сервер отправляет MESSAGE на GoIP для отправки SMS через GSM:

```
MESSAGE sip:1001@192.168.50.66:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsrv-msg-456
From: <sip:sms_service@10.0.0.1>;tag=srvmsg123
To: <sip:1001@192.168.50.66:5060>
Call-ID: sms-send-789@10.0.0.1
CSeq: 1 MESSAGE
Content-Type: text/plain
Content-Length: 30

Номер:79161234567 Текст сообщения
```

> При `SIP_SMS_RTN=1` (`--sms-tonum`) — GoIP отправляет ответное SMS на номер отправителя.

---

## 12. INFO — DTMF через SIP INFO

### 12.1 SIP INFO с DTMF (SIP_OUTBAND_DTMF_TYPE=2)

```
INFO sip:79161234567@10.0.0.1:5060 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK291038467
From: "GoIP_1" <sip:1001@sip.example.com>;tag=31749825
To: <sip:79161234567@sip.example.com>;tag=remote456
Call-ID: 9182736450@192.168.50.66
CSeq: 5 INFO
Max-Forwards: 70
User-Agent: dble
Content-Type: application/dtmf-relay
Content-Length: 26

Signal=5
Duration=160

```

### 12.2 Возможные значения Signal

```
Signal=0     Duration=160
Signal=1     Duration=160
Signal=2     Duration=160
...
Signal=9     Duration=160
Signal=*     Duration=160
Signal=#     Duration=160
```

> GoIP использует два варианта Duration: `80` и `160` (в миллисекундах).

---

## 13. OPTIONS — keepalive / проверка доступности

### 13.1 OPTIONS как keepalive

При `SIP_NO_ALIVE=0` (по умолчанию) GoIP периодически отправляет OPTIONS:

```
OPTIONS sip:sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK502918374
From: "GoIP_1" <sip:1001@sip.example.com>;tag=99182736
To: <sip:sip.example.com>
Call-ID: keepalive-1234@192.168.50.66
CSeq: 1 OPTIONS
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 13.2 Ответ 200 OK на OPTIONS

```
SIP/2.0 200 OK
Via: SIP/2.0/UDP 192.168.50.66:5060;rport=5060;branch=z9hG4bK502918374
From: "GoIP_1" <sip:1001@sip.example.com>;tag=99182736
To: <sip:sip.example.com>;tag=opttag123
Call-ID: keepalive-1234@192.168.50.66
CSeq: 1 OPTIONS
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
Content-Length: 0

```

---

## 14. SUBSCRIBE/NOTIFY — MWI

### 14.1 SUBSCRIBE на message-summary (MWI)

При `SIP_MWI=1` (`--mwi 1`):

```
SUBSCRIBE sip:1001@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK601928375
From: "GoIP_1" <sip:1001@sip.example.com>;tag=55291837
To: <sip:1001@sip.example.com>
Call-ID: mwi-sub-5678@192.168.50.66
CSeq: 1 SUBSCRIBE
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Event: message-summary
Content-Length: 0

```

### 14.2 NOTIFY (сервер → GoIP)

```
NOTIFY sip:1001@192.168.50.66:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKsrv-notify-789
From: <sip:1001@sip.example.com>;tag=srvnotify
To: "GoIP_1" <sip:1001@sip.example.com>;tag=55291837
Call-ID: mwi-sub-5678@192.168.50.66
CSeq: 1 NOTIFY
Subscription-State: active
Event: message-summary
Content-Type: application/simple-message-summary
Content-Length: 50

Messages-Waiting: yes
Voice-Message: 2/0
```

---

## 15. Шифрование SIP и RTP

### 15.1 Типы шифрования

| Тип | CLI-флаг | Описание |
|-----|---------|----------|
| **RC4** | `--rc4-crypt --rc4-key <key>` | RC4 шифрование SIP + RTP |
| **FAST** | `--fast-crypt` | Быстрое XOR-шифрование |
| **XOR** | (см. внутренний код) | Простой XOR |
| **VOS** | `--vos-crypt` | VOS проприетарный (`voscrypt.c`) |
| **AVS** | `--avs-crypt` | AVS проприетарный (`avscrypt.c`) |
| **N2C** | `--n2c-crypt` | N2C проприетарный (`n2c_crypt.c`) |
| **ECM** | `--ecm-crypt` | ECM с ключом `ECM_CRYPT_KEY` |
| **ET263** | `--et263-crypt --et263-crypt-type <T> --et263-crypt-dep <D>` | ET263 проприетарный (`et263_encrypt.c`) |

### 15.2 X-ACrypt заголовок (обмен ключами)

При включённом шифровании GoIP добавляет проприетарный заголовок `X-ACrypt` для обмена ключами:

```
INVITE sip:79161234567@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK182736495
...
X-ACrypt: RC4:etoall.net
Content-Type: application/sdp
Content-Length: 290

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/SAVP 8 0 101
...
```

> **Ключевое отличие**: при шифровании в SDP используется `RTP/SAVP` вместо `RTP/AVP`.

### 15.3 Шифрование MG (Media Gateway)

MG шифрует RTP-поток отдельно от SIP:
- `MG_CRYPT=RC4` → `--rc4-key=<MG_RC4_KEY>` (или `SIP_RC4_KEY` если MG_RC4_KEY пуст)
- `MG_CRYPT=ET263` → устанавливает `MG_ET263_CRYPT=1` через syscfg

### 15.4 ET263 режим особенности

При ET263 автоматически включаются:
```bash
SIP_REG_MODE="1"        # Спец. режим регистрации
SIP_EXP_MODE="1"        # Спец. режим expires  
SIP_LINK_TEST="1"       # Проверка связи
```

---

## 16. SDP-шаблон и кодеки

### 16.1 Полный SDP-шаблон GoIP

```
v=0
o=userX 20000001 20000001 IN IP4 <LOCAL_IP>
s=DBL Session
c=IN IP4 <LOCAL_IP>
t=0 0
m=audio <RTP_PORT> RTP/AVP <codec_list> <dtmf_pt>
a=rtpmap:<pt> <codec>/<rate>
...
a=fmtp:<dtmf_pt> 0-15
a=ptime:<PACKETIZE_PERIOD>
a=sendrecv
```

### 16.2 Кодеки

| Payload Type | Кодек | Rate | Описание |
|-------------|-------|------|----------|
| 0 | PCMU | 8000 | G.711 μ-law |
| 8 | PCMA | 8000 | G.711 A-law |
| 3 | GSM | 8000 | GSM FR |
| 4 | G723 | 8000 | G.723.1 |
| 18 | G729 | 8000 | G.729/a/ab |
| 101 (config) | telephone-event | 8000 | RFC 2833 DTMF |

### 16.3 Порядок кодеков

Определяется конфигурацией `AUDIO_CODEC_PREFERENCE`:
```
alaw,ulaw,g729,g729a,g729ab,g7231,!gsm
```

Кодек с `!` перед именем — **отключён**. Порядок = приоритет SDP предложения.

### 16.4 Особые SDP для FAX

- `LINE1_FAX=T38` → `--codec-preference0=<codecs>,t38` (T.38 факс)
- `LINE1_FAX=G711` → `--codec-preference0=alaw,ulaw` (факс через G.711)

---

## 17. DTMF — три режима

### 17.1 RFC 2833 (SIP_OUTBAND_DTMF_TYPE=1)

DTMF передаётся в RTP-потоке с payload type из `DTMF_PAYLOAD_TYPE` (обычно 101):

```
m=audio 10000 RTP/AVP 8 101
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
```

### 17.2 SIP INFO (SIP_OUTBAND_DTMF_TYPE=2)

DTMF передаётся отдельными SIP INFO запросами:

```
Content-Type: application/dtmf-relay

Signal=5
Duration=160
```

### 17.3 Inband (INBAND_DTMF=1)

DTMF кодируется внутри аудио-потока (тоны в G.711). Все OOB методы отключены.

---

## 18. NAT Traversal

### 18.1 STUN (SIP_NAT_TRAVERSAL=STUN)

```bash
sipcli ... -x stun.server.com
```
GoIP определяет внешний IP/порт через STUN и использует их в Via, Contact, SDP `c=`.

### 18.2 DBLTek Relay (SIP_NAT_TRAVERSAL=RELAY)

```bash
sipcli ... --relay-server relay1.com,relay2.com --relay-port 8000 --relay-bind-ext1 --relay-user user --relay-passwd pass
```

Проприетарный relay-сервер DBLTek для обхода NAT. До 5 серверов для failover.

### 18.3 Port Forwarding / NAT-FW

```bash
sipcli ... --wan-addr <PUBLIC_IP> --nat-fw
```

GoIP использует `WAN_ADDR` как внешний адрес в SIP-заголовках.

### 18.4 rport (RFC 3581)

GoIP всегда включает `rport` в Via для определения NAT-маппинга:
```
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK...
```

---

## 19. Примеры для SINGLE_MODE

### 19.1 Конфигурация

```ini
SIP_CONFIG_MODE="SINGLE_MODE"
SIP_REGISTRAR="sip.example.com"
SIP_PROXY="sip.example.com"
SIP_HOME_DOMAIN="example.com"
SIP_DISPLAY_NAME="GoIP_GST1610"
SIP_PHONE_NUMBER="1001"
SIP_AUTH_ID="1001"
SIP_AUTH_PASSWD="secret123"
SIP_REGISTER_EXPIRED="60"
SIP_LOCAL_PORT="5060"
SIP_SMODE_USE_BSVR="1"          # Использовать backup-сервер
SIP_BACKUP_REGISTRAR="sip2.example.com"
SIP_BACKUP_PROXY="sip2.example.com"
```

### 19.2 Что происходит при запуске

```bash
# start_sip формирует и выполняет:
# 1. Отключает все per-line контакты:
setsyscfg SIP_CONTACT0_DISABLE=1
setsyscfg SIP_CONTACT10_DISABLE=1
setsyscfg SIP_LINE0_GROUP=0

# 2. Настраивает единый контакт:
setsyscfg SIP_GROUP_NUM=1
setsyscfg SIP_CONTACT8_GROUP=0
setsyscfg SIP_CONTACT8_DISABLE=0
setsyscfg SIP_CONTACT9_GROUP=0
setsyscfg SIP_CONTACT9_DISABLE=0    # backup включён

# 3. Запускает sipcli:
exec /usr/bin/sipcli --line-prefix 1 --syscfg --gateway 1 --backup_svr \
  --agent dble --nowait --ptime 20 --dtmf 101 --obddtmf 1 \
  --early-media 1 --inv-auth 1 --sip-rsp-mode 1
```

### 19.3 Маппинг параметров (aliases)

```
SIP_REGISTRAR       → SIP_CONTACT8_SERVER      = "sip.example.com"
SIP_PROXY           → SIP_CONTACT8_PROXY       = "sip.example.com"
SIP_HOME_DOMAIN     → SIP_CONTACT8_HOME_DOMAIN = "example.com"
SIP_DISPLAY_NAME    → SIP_CONTACT8_DISPLAY_NAME = "GoIP_GST1610"
                    → SIP_CONTACT9_DISPLAY_NAME = "GoIP_GST1610"
SIP_PHONE_NUMBER    → SIP_CONTACT8_DIAL_DIGITS  = "1001"
                    → SIP_CONTACT9_DIAL_DIGITS  = "1001"
SIP_AUTH_ID         → SIP_CONTACT8_LOGIN        = "1001"
                    → SIP_CONTACT9_LOGIN        = "1001"
SIP_AUTH_PASSWD     → SIP_CONTACT8_PASSWD       = "secret123"
                    → SIP_CONTACT9_PASSWD       = "secret123"
SIP_REGISTER_EXPIRED → SIP_CONTACT8_EXPIRED    = 60
                      → SIP_CONTACT9_EXPIRED    = 60
SIP_BACKUP_REGISTRAR → SIP_CONTACT9_SERVER     = "sip2.example.com"
SIP_BACKUP_PROXY     → SIP_CONTACT9_PROXY      = "sip2.example.com"
```

### 19.4 REGISTER в SINGLE_MODE

Один REGISTER на основной сервер:

```
REGISTER sip:sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK847291563
From: "GoIP_GST1610" <sip:1001@example.com>;tag=82945612
To: "GoIP_GST1610" <sip:1001@example.com>
Call-ID: single-reg-1@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:1001@192.168.50.66:5060>;expires=60
Max-Forwards: 70
User-Agent: dble
Allow: INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE
Content-Length: 0

```

При неудаче → `register failed. login to backup server` → REGISTER на `sip2.example.com`.

### 19.5 INVITE исходящий в SINGLE_MODE

GSM-абонент звонит на GoIP, GoIP маршрутизирует через SIP:

```
INVITE sip:74951234567@sip.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK384729156
From: "GoIP_GST1610" <sip:1001@example.com>;tag=19283746
To: <sip:74951234567@sip.example.com>
Call-ID: call-out-single-1@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:1001@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Content-Type: application/sdp
Content-Length: 320

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 0 18 4 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:18 G729/8000
a=rtpmap:4 G723/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

### 19.6 INVITE входящий в SINGLE_MODE

SIP → GoIP → первый свободный GSM канал:

```
INVITE sip:1001@192.168.50.66:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpbx_single_456
From: "External" <sip:74951234567@10.0.0.1>;tag=pbx789
To: <sip:1001@192.168.50.66:5060>
Call-ID: call-in-single-1@10.0.0.1
CSeq: 1 INVITE
...
```

GoIP маршрутизирует вызов на **любой свободный GSM-канал** (round-robin или по приоритету).

---

## 20. Примеры для TRUNK_GW_MODE

### 20.1 Конфигурация

```ini
SIP_CONFIG_MODE="TRUNK_GW_MODE"
SIP_TRUNK_GW1="10.0.0.1"         # Основной SIP-сервер/PBX
SIP_TRUNK_GW2=""                  # Backup (опционально)
SIP_TRUNK_GW3=""                  # Backup 2 (опционально)
SIP_TRUNK_NUMBER=""               # Номер для транка (если нужен)
SIP_TRUNK_AUTH_ID="1101"
SIP_TRUNK_AUTH_PASSWD="1101"
SIP_TRUNK_REGISTER_EXPIRED="0"   # 0 = без регистрации
SIP_LOCAL_PORT="5060"
CLI_PORT="5063"                   # Порт управления (может рандомизироваться)
```

### 20.2 Что происходит при запуске

```bash
# start_sip формирует:
exec /usr/bin/sipcli --line-prefix 1 --gateway 1 \
  --trunk-gw 10.0.0.1,, \
  --proxy 10.0.0.1 \
  --lport 5060 \
  -l 1101 -p 1101 \
  --agent dble --nowait --ptime 20 --dtmf 101 --obddtmf 1 \
  --early-media 1 --inv-auth 1 --sip-rsp-mode 1 --cid-fw-mode 1

# Записывает в /etc/ipin:
echo TRUNKSTART > /etc/ipin
```

### 20.3 TRUNK — без регистрации (REGISTER не отправляется)

При `SIP_TRUNK_REGISTER_EXPIRED=0` GoIP НЕ отправляет REGISTER. 
Он просто слушает на `SIP_LOCAL_PORT` и обрабатывает входящие INVITE от trunk gateway.

### 20.4 TRUNK — с регистрацией

При `SIP_TRUNK_REGISTER_EXPIRED=300`:

```
REGISTER sip:10.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK571839264
From: <sip:1101@10.0.0.1>;tag=trunk_reg_001
To: <sip:1101@10.0.0.1>
Call-ID: trunk-reg-1234@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:1101@192.168.50.66:5060>;expires=300
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 20.5 Входящий INVITE в TRUNK_GW_MODE (PBX → GoIP → GSM)

PBX отправляет INVITE с номером для набора по GSM:

```
INVITE sip:79161234567@192.168.50.66:5060 SIP/2.0
Via: SIP/2.0/UDP 10.0.0.1:5060;branch=z9hG4bKpbx_trunk_123
From: "PBX User" <sip:100@10.0.0.1>;tag=pbxtrunk456
To: <sip:79161234567@192.168.50.66>
Call-ID: trunk-call-in-1@10.0.0.1
CSeq: 1 INVITE
Contact: <sip:100@10.0.0.1:5060>
Max-Forwards: 70
Content-Type: application/sdp
Content-Length: 200

v=0
o=pbx 100 100 IN IP4 10.0.0.1
s=SIP Call
c=IN IP4 10.0.0.1
t=0 0
m=audio 20000 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=ptime:20
a=sendrecv
```

GoIP:
1. Проверяет, что INVITE пришёл от одного из `SIP_TRUNK_GW1/2/3` (или от `--proxy`)
2. При `SIP_INV_AUTH=1` → отвечает 401 и требует Digest auth
3. Выбирает свободный GSM-канал
4. Набирает `79161234567` через GSM
5. Отвечает `180 Ringing`, затем `200 OK` с SDP

### 20.6 Исходящий INVITE в TRUNK_GW_MODE (GSM → GoIP → PBX)

GSM-абонент звонит на SIM GoIP:

```
INVITE sip:+79031234567@10.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK482917365
From: <sip:79161234567@192.168.50.66>;tag=trkout789
To: <sip:+79031234567@10.0.0.1>
Call-ID: trunk-call-out-1@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:79161234567@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
Content-Type: application/sdp
Content-Length: 280

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/AVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

> **From**: CallerID GSM-абонента (номер звонящего)
> **To**: может зависеть от `SIP_CID_FW_MODE` и `SIP_TRUNK_NUMBER`

### 20.7 CallerID forwarding (SIP_CID_FW_MODE)

| Значение | Поведение |
|----------|-----------|
| 1 | Передать GSM CallerID в From |
| 2 | Передать CallerID в P-Asserted-Identity |
| 3 | Стандартное (не настраивается) |

При `SIP_CID_FW_MODE=2`:
```
INVITE sip:+79031234567@10.0.0.1 SIP/2.0
From: <sip:1101@10.0.0.1>;tag=trkout789
P-Asserted-Identity: "79161234567" <sip:79161234567@10.0.0.1>;party=calling;screen=no;privacy=off
...
```

### 20.8 Prefix (SIP_LINE1_PREFIX)

При `SIP_LINE1_PREFIX="7"` и `SIP_PREFIX_DEL=1`:
- Входящий INVITE на `sip:79161234567@goip` → GoIP набирает GSM `9161234567` (удаляет префикс `7`)
- `SIP_PREFIX_DIALLER_CMP=1` → сравнивает префикс перед маршрутизацией

---

## 21. Примеры для LINE_MODE

### 21.1 Конфигурация

Для GST1610 с 1 GSM-каналом (TELPORT=1), но формат поддерживает до 16+ каналов:

```ini
SIP_CONFIG_MODE="LINE_MODE"

# Канал 0 (line0) — отдельная SIP регистрация
SIP_CONTACT0_SERVER="sip1.example.com"
SIP_CONTACT0_PROXY="sip1.example.com"
SIP_CONTACT0_HOME_DOMAIN="example.com"
SIP_CONTACT0_DISPLAY_NAME="Line_0"
SIP_CONTACT0_DIAL_DIGITS="2001"
SIP_CONTACT0_LOGIN="2001"
SIP_CONTACT0_PASSWD="pass2001"
SIP_CONTACT0_EXPIRED="120"
SIP_CONTACT0_DISABLE="0"
SIP_CONTACT0_GROUP="0"

# Суб-аккаунт 2 на канале 0 (опционально)
SIP_CONTACT0_DIAL_DIGITS_2="2002"
SIP_CONTACT0_DISPLAY_NAME_2="Line_0_alt"
SIP_CONTACT0_LOGIN_2="2002"
SIP_CONTACT0_PASSWD_2="pass2002"

# Суб-аккаунт 3 (опционально)
SIP_CONTACT0_DIAL_DIGITS_3="2003"
SIP_CONTACT0_LOGIN_3="2003"
SIP_CONTACT0_PASSWD_3="pass2003"

# Суб-аккаунт 4 (опционально)
SIP_CONTACT0_DIAL_DIGITS_4="2004"
SIP_CONTACT0_LOGIN_4="2004"
SIP_CONTACT0_PASSWD_4="pass2004"

# Если TELPORT > 1, канал 1:
SIP_CONTACT1_SERVER="sip2.example.com"
SIP_CONTACT1_DIAL_DIGITS="3001"
SIP_CONTACT1_LOGIN="3001"
SIP_CONTACT1_PASSWD="pass3001"
SIP_CONTACT1_EXPIRED="120"
SIP_CONTACT1_DISABLE="0"
SIP_CONTACT1_GROUP="0"
```

### 21.2 Запуск

```bash
exec /usr/bin/sipcli --line-prefix 1 --syscfg \
  --agent dble --nowait --ptime 20 --dtmf 101 --obddtmf 1
```

> В LINE_MODE start_sip **НЕ** обрабатывает конфигурацию контактов — всё делает sipcli через `--syscfg`, читая `SIP_CONTACT%d_*` из syscfg.

### 21.3 REGISTER в LINE_MODE

**Каждый канал регистрируется отдельно!**

Канал 0 → основная регистрация:

```
REGISTER sip:sip1.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK192837465
From: "Line_0" <sip:2001@example.com>;tag=line0_reg_001
To: "Line_0" <sip:2001@example.com>
Call-ID: line0-reg-main@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:2001@192.168.50.66:5060>;expires=120
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

Канал 0 → суб-аккаунт 2:

```
REGISTER sip:sip1.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK293847561
From: "Line_0_alt" <sip:2002@example.com>;tag=line0_sub2_001
To: "Line_0_alt" <sip:2002@example.com>
Call-ID: line0-reg-sub2@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:2002@192.168.50.66:5060>;expires=120
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 21.4 INVITE в LINE_MODE

Каждый канал использует свои учётные данные. From/Contact берутся из `SIP_CONTACT<N>_*`:

```
INVITE sip:74951234567@sip1.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK394827165
From: "Line_0" <sip:2001@example.com>;tag=line0_call_001
To: <sip:74951234567@sip1.example.com>
Call-ID: line0-call-out-1@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:2001@192.168.50.66:5060>
...
```

### 21.5 GW_PREFIX — маршрутизация по префиксу

`SIP_CONTACT0_GW_PREFIX="7495"` — входящие INVITE с номером, начинающимся на `7495`, маршрутизируются на канал 0.

---

## 22. Примеры для GROUP_MODE

### 22.1 Конфигурация

Пример: 4 GSM-канала, 2 группы.

```ini
SIP_CONFIG_MODE="GROUP_MODE"
SIP_GROUP_NUM="2"

# Привязка каналов к группам
SIP_LINE0_GROUP="0"    # Канал 0 → Группа 0
SIP_LINE1_GROUP="0"    # Канал 1 → Группа 0
SIP_LINE2_GROUP="1"    # Канал 2 → Группа 1
SIP_LINE3_GROUP="1"    # Канал 3 → Группа 1

# Группа 0 — SIP сервер для каналов 0,1
SIP_CONTACT8_SERVER="sip-group0.example.com"
SIP_CONTACT8_PROXY="sip-group0.example.com"
SIP_CONTACT8_HOME_DOMAIN="group0.example.com"
SIP_CONTACT8_DISPLAY_NAME="GoIP_Group0"
SIP_CONTACT8_DIAL_DIGITS="5001"
SIP_CONTACT8_LOGIN="5001"
SIP_CONTACT8_PASSWD="grp0pass"
SIP_CONTACT8_EXPIRED="60"
SIP_CONTACT8_GROUP="0"
SIP_CONTACT8_DISABLE="0"

# Группа 1 — SIP сервер для каналов 2,3
SIP_CONTACT9_SERVER="sip-group1.example.com"
SIP_CONTACT9_PROXY="sip-group1.example.com"
SIP_CONTACT9_HOME_DOMAIN="group1.example.com"
SIP_CONTACT9_DISPLAY_NAME="GoIP_Group1"
SIP_CONTACT9_DIAL_DIGITS="5002"
SIP_CONTACT9_LOGIN="5002"
SIP_CONTACT9_PASSWD="grp1pass"
SIP_CONTACT9_EXPIRED="60"
SIP_CONTACT9_GROUP="1"
SIP_CONTACT9_DISABLE="0"
```

### 22.2 Запуск

```bash
exec /usr/bin/sipcli --line-prefix 1 --syscfg \
  --agent dble --nowait --ptime 20 --dtmf 101 --obddtmf 1
```

### 22.3 REGISTER в GROUP_MODE

**Одна регистрация на группу** (не на канал!):

Группа 0:

```
REGISTER sip:sip-group0.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK482917365
From: "GoIP_Group0" <sip:5001@group0.example.com>;tag=grp0_reg_001
To: "GoIP_Group0" <sip:5001@group0.example.com>
Call-ID: group0-reg@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:5001@192.168.50.66:5060>;expires=60
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

Группа 1:

```
REGISTER sip:sip-group1.example.com SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK582937164
From: "GoIP_Group1" <sip:5002@group1.example.com>;tag=grp1_reg_001
To: "GoIP_Group1" <sip:5002@group1.example.com>
Call-ID: group1-reg@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:5002@192.168.50.66:5060>;expires=60
Max-Forwards: 70
User-Agent: dble
Content-Length: 0

```

### 22.4 INVITE в GROUP_MODE

Входящий INVITE на группу → GoIP выбирает свободный канал из группы:

```
INVITE sip:5001@192.168.50.66:5060 SIP/2.0
From: <sip:79031234567@sip-group0.example.com>;tag=grp0_inv_001
To: <sip:5001@192.168.50.66>
...
```

GoIP проверяет, что вызов адресован номеру группы 0 (`5001`), выбирает свободный канал из каналов 0 или 1, и набирает GSM.

### 22.5 Маршрутизация по PREFIX в GROUP_MODE

```ini
SIP_LINE0_PREFIX="7495"   # Канал 0 — только для 7495...
SIP_LINE1_PREFIX="7903"   # Канал 1 — только для 7903...
```

При `SIP_PREFIX_DEL=1` → префикс удаляется перед набором GSM.
При `SIP_PREFIX_DIALLER_CMP=1` (`--dialler-cmp 1`) → GoIP сравнивает набранный номер с префиксом линии для определения маршрута.

---

## 23. CLI-параметры sipcli

### 23.1 Полный список параметров

| Параметр | Описание | Источник конфига |
|----------|----------|-----------------|
| `--line-prefix <N>` | Префикс номера линии | Всегда 1 |
| `--gateway <N>` | Режим шлюза (1=да) | SINGLE, TRUNK |
| `--syscfg` | Читать конфиг из syscfg | SINGLE, LINE, GROUP |
| `--trunk-gw <gw1,gw2,gw3>` | Адреса trunk gateway | `SIP_TRUNK_GW1/2/3` |
| `--proxy <addr>` | SIP proxy | `SIP_TRUNK_GW1` или `SIP_PROXY` |
| `-u <number>` | Номер пользователя | `SIP_TRUNK_NUMBER` |
| `-l <login>` | Логин аутентификации | `SIP_TRUNK_AUTH_ID` |
| `-p <passwd>` | Пароль аутентификации | `SIP_TRUNK_AUTH_PASSWD` |
| `-e <seconds>` | Expires регистрации | `SIP_TRUNK_REGISTER_EXPIRED` |
| `--lport <port>` | Локальный SIP-порт | `SIP_LOCAL_PORT` |
| `--agent <name>` | User-Agent header | `VENID` |
| `--nowait` | Не ждать SIM READY | Всегда |
| `--noalive` | Отключить keepalive | `SIP_NO_ALIVE=1` |
| `--ptime <ms>` | Packetization period | `PACKETIZE_PERIOD` |
| `--dtmf <pt>` | DTMF payload type | `DTMF_PAYLOAD_TYPE` |
| `--obddtmf <type>` | DTMF метод (1=RFC2833, 2=INFO, 3=оба) | `SIP_OUTBAND_DTMF_TYPE` |
| `--mode <mode>` | Режим работы | `SIP_OPERATION_MODE` |
| `--early-media <N>` | Early media (183) | `SIP_183` |
| `--inv-auth <N>` | Аутентификация INVITE | `SIP_INV_AUTH` |
| `--backup_svr` | Использовать backup сервер | `SIP_SMODE_USE_BSVR=1` |
| `--random-port <port>` | Рандомизация порта | `SIP_RANDOM_LC_PORT` + `CLI_PORT` |
| `--wan-addr <ip>` | Внешний IP для NAT | `WAN_ADDR` |
| `--nat-fw` | NAT port forwarding | с `WAN_ADDR` |
| `-x <stun>` | STUN сервер | `SIP_STUN_SERVER` |
| `--relay-server <s1,s2,..>` | DBLTek relay серверы | `SIP_RELAY_SERVER*` |
| `--relay-port <port>` | Порт relay | `SIP_RELAY_PORT` |
| `--relay-bind-ext1` | Bind external 1 | Всегда при RELAY |
| `--relay-user <user>` | Relay логин | `SIP_RELAY_USER` |
| `--relay-passwd <passwd>` | Relay пароль | `SIP_RELAY_PASSWD` |
| `--relay-encrypt` | Шифрование relay | `SIP_RELAY_ENCRYPT=1` |
| `--rc4-crypt` | RC4 шифрование | `SIP_CRYPT=RC4` |
| `--rc4-key <key>` | RC4 ключ | `SIP_RC4_KEY` |
| `--fast-crypt` | Быстрое шифрование | `SIP_CRYPT=FAST` |
| `--vos-crypt` | VOS шифрование | `SIP_CRYPT=VOS` |
| `--avs-crypt` | AVS шифрование | `SIP_CRYPT=AVS` |
| `--n2c-crypt` | N2C шифрование | `SIP_CRYPT=N2C` |
| `--ecm-crypt` | ECM шифрование | `SIP_CRYPT=ECM` |
| `--et263-crypt` | ET263 шифрование | `SIP_CRYPT=ET263` |
| `--et263-crypt-type <T>` | Тип ET263 | `SIP_ET263_CRYPT_TYPE` |
| `--et263-crypt-dep <D>` | Глубина ET263 | `SIP_ET263_CRYPT_DEP` |
| `--reg-mode <N>` | Режим регистрации | `SIP_REG_MODE` |
| `--exp-mode <N>` | Режим expires | `SIP_EXP_MODE` |
| `--link-test` | Тест связи | `SIP_LINK_TEST=1` |
| `--cid-fw-mode <N>` | Пересылка CallerID | `SIP_CID_FW_MODE` |
| `-r 1` | Отключить Route header | `SIP_ROUTE_FIELD_DISABLE=1` |
| `--pkey` | # как цифра | `POUND_KEY_AS_DIGIT=1` |
| `--vrb` | Виртуальный ringback | `SIP_VIRTUAL_RB_TONE=1` |
| `--mwi <N>` | MWI подписка | `SIP_MWI` |
| `--rereg-inval <sec>` | Интервал повтора регистрации | `SIP_FAIL_RETRY_INTERVAL` |
| `--proxy-mode` | GoIP как SIP proxy | `SIP_AS_PROXY=1` |
| `--proxy-passwd <p>` | Пароль proxy mode | `SIP_PROXY_PASSWD` |
| `--prefix-del 1` | Удалять префикс | `SIP_PREFIX_DEL=1` |
| `--dialler-cmp 1` | Сравнивать с dialler | `SIP_PREFIX_DIALLER_CMP=1` |
| `--sip-rsp-mode 1` | Режим SIP ответов | `SIP_RSP_MODE=1` |
| `--callee-mode 1` | Режим callee | `SIP_CALLEE_MODE=1` |
| `--sms-tonum` | SMS на номер | `SIP_SMS_RTN=1` |

### 23.2 User-Agent значение

```bash
VENID="dble"      →  User-Agent: dble
VENID="et"        →  User-Agent: HYBERTONE    # Переименовывается в start_sip
VENID="et263"     →  User-Agent: HYBERTONE    # Переименовывается в start_sip
VENID="pak"       →  User-Agent: pak          # Пакистанская версия
```

---

## 24. Таймеры и таймауты

| Параметр | Значение по умолчанию | Описание |
|----------|----------------------|----------|
| `SIP_REGISTER_EXPIRED` | 60 | Интервал перерегистрации (сек) |
| `SIP_TRUNK_REGISTER_EXPIRED` | 0 | Интервал trunk регистрации (0=отключена) |
| `UNANSWER_EXP` | 180 | Таймаут без ответа (сек, 32-180) |
| `SIP_FAIL_RETRY_INTERVAL` | - | Интервал повтора при ошибке (сек, 1-60) |
| `RETRANSMIT_T1` | 200 | SIP Timer T1 (мс, 200-2000) |
| `RETRANSMIT_T2` | 2000 | SIP Timer T2 (мс, 2000-8000) |
| `NON_INVITE_TS_EXP` | 2 | Таймаут non-INVITE транзакции (сек, 2-180) |
| `INVITE_TS_EXP` | 5 | Таймаут INVITE транзакции (сек, 5-360) |
| `NONE_RB_EXP` | - | Таймаут без ringback tone (сек) |
| `MG_RTP_DT` | 10 | RTP dead-time detector (сек) |

### Внутренние таймеры sipcli (из oSIP)

| Таймер | Назначение |
|--------|-----------|
| `ict_*` | INVITE Client Transaction (отпр. INVITE) |
| `nict_*` | Non-INVITE Client Transaction (отпр. REGISTER, BYE, etc.) |
| `ist_*` | INVITE Server Transaction (прием INVITE) |
| `nist_*` | Non-INVITE Server Transaction (прием REGISTER, etc.) |

---

## 25. Фингерпринтинг GoIP

### Уникальные признаки GoIP в SIP-трафике

| Признак | Значение |
|---------|----------|
| User-Agent | `dble`, `HYBERTONE`, `pak` |
| SDP session name | `s=DBL Session` |
| SDP origin username | `o=userX` |
| SDP origin session-id | `20000001` |
| 480 reason phrase | `480 Remote Busy` (нестандартный!) |
| Заголовок | `X-ACrypt` (проприетарный) |
| Contact формат | `<sip:user@ip>;expires=N` |
| Via branch prefix | `z9hG4bK` + uint32 |
| Allow | Включает полный набор методов вкл. REFER, MESSAGE, SUBSCRIBE |

### Рекомендации по маскировке (при необходимости)

1. Заменить `User-Agent` через прокси
2. Заменить `s=DBL Session` на `s=SIP Call` или `s=-`
3. Заменить `o=userX 20000001` на случайные значения
4. Перехватывать `480 Remote Busy` и заменять на `480 Temporarily Unavailable`
5. Удалять `X-ACrypt` если не используется шифрование
6. Менять `Contact` формат через B2BUA/SBC

---

## Приложение A: Сводная таблица режимов

| Параметр | SINGLE_MODE | LINE_MODE | TRUNK_GW_MODE | GROUP_MODE |
|----------|-------------|-----------|---------------|------------|
| Регистрация | 1 (+ backup) | N (per-line) | 0 или 1 (trunk) | Per-group |
| Сервер | SIP_REGISTRAR | SIP_CONTACT%d_SERVER | SIP_TRUNK_GW1 | SIP_CONTACT%d_SERVER |
| Логин | SIP_AUTH_ID | SIP_CONTACT%d_LOGIN | SIP_TRUNK_AUTH_ID | SIP_CONTACT%d_LOGIN |
| Пароль | SIP_AUTH_PASSWD | SIP_CONTACT%d_PASSWD | SIP_TRUNK_AUTH_PASSWD | SIP_CONTACT%d_PASSWD |
| Номер | SIP_PHONE_NUMBER | SIP_CONTACT%d_DIAL_DIGITS | SIP_TRUNK_NUMBER | SIP_CONTACT%d_DIAL_DIGITS |
| Expires | SIP_REGISTER_EXPIRED | SIP_CONTACT%d_EXPIRED | SIP_TRUNK_REGISTER_EXPIRED | SIP_CONTACT%d_EXPIRED |
| Выбор канала | Round-robin | По номеру линии | Свободный | По группе |
| Флаг запуска | `--syscfg --gateway 1` | `--syscfg` | `--gateway 1 --trunk-gw` | `--syscfg` |
| Суб-аккаунты | Нет | До 4 (_2, _3, _4) | Нет | По контакту |
| Backup сервер | CONTACT9 | SIP_CONTACT%d-based | GW2, GW3 | Per-group |

---

## Приложение B: Процесс вызова (последовательность)

### B.1 Входящий SIP → GSM

```
SIP Server                GoIP (sipcli)              GoIP (mg/fvdsp)         GSM
    |                         |                          |                    |
    |-- INVITE (SDP) -------->|                          |                    |
    |<---- 100 Trying --------|                          |                    |
    |                         |-- MG: setup_channel ---->|                    |
    |                         |                          |-- ATDxxxxxxxxx --->|
    |                         |                          |                    |
    |<---- 180 Ringing -------|                          |<-- CONNECT --------|
    |                         |                          |                    |
    |                         |                          |<-- ANSWER ---------|
    |<---- 200 OK (SDP) ------|                          |                    |
    |-- ACK ----------------->|                          |                    |
    |                         |-- MG: start_rtp -------->|                    |
    |<======= RTP ============|==========================>|<== GSM аудио ====>|
    |                         |                          |                    |
    |-- BYE ----------------->| или GSM hangup:          |                    |
    |<---- 200 OK ------------|-- BYE ------------------>|                    |
    |                         |-- MG: stop_rtp --------->|                    |
```

### B.2 Исходящий GSM → SIP

```
GSM                    GoIP (sipcli)              GoIP (mg/fvdsp)         SIP Server
 |                         |                          |                    |
 |-- Incoming Call ------->|                          |                    |
 |                         |-- INVITE (SDP) ----------------------------------------->|
 |                         |<---- 100 Trying ------------------------------------------|
 |                         |<---- 180 Ringing ------------------------------------------|
 |<-- CONNECT (answer) ----|                          |                    |
 |                         |<---- 200 OK (SDP) ----------------------------------------|
 |                         |-- ACK ---------------------------------------------------->|
 |                         |-- MG: start_rtp -------->|                    |
 |<===== GSM аудио ========|==========================>|======= RTP ===================>|
 |                         |                          |                    |
 |-- GSM hangup ---------->|-- BYE ---------------------------------------------------->|
 |                         |<---- 200 OK ------------------------------------------------|
 |                         |-- MG: stop_rtp --------->|                    |
```

---

## Приложение C: IPC-сигналы через /etc/ipin

| Команда | Описание |
|---------|----------|
| `IPPSTART` | Записывается при запуске в SINGLE/LINE/GROUP mode |
| `TRUNKSTART` | Записывается при запуске в TRUNK_GW_MODE |
| `SIP_DEBUG=1` | Включает SIP debug (через `/usr/sbin/infosip`) |
| `info-type: REGISTER` | Информация о состоянии регистрации |

### Включение debug

```bash
/usr/sbin/infosip        # → echo SIP_DEBUG=1 > /etc/ipin
/usr/sbin/infogsmsip     # → echo SIP_DEBUG=1 > /etc/ipin + GSM debug
```

Вывод debug пишется в консоль (`callback.c`, `sipmsg.c`, `call.c` и др.).

---

## Приложение D: Пример полного сценария TRUNK_GW_MODE с шифрованием

### Конфигурация

```ini
SIP_CONFIG_MODE="TRUNK_GW_MODE"
SIP_TRUNK_GW1="10.0.0.1"
SIP_TRUNK_AUTH_ID="trunk01"
SIP_TRUNK_AUTH_PASSWD="secretpass"
SIP_TRUNK_REGISTER_EXPIRED="300"
SIP_LOCAL_PORT="5060"
SIP_CRYPT="RC4"
SIP_RC4_KEY="my_encryption_key"
MG_CRYPT="RC4"
```

### Запуск

```bash
exec /usr/bin/sipcli --line-prefix 1 --gateway 1 \
  --trunk-gw 10.0.0.1,, --proxy 10.0.0.1 \
  --lport 5060 -l trunk01 -p secretpass -e 300 \
  --agent dble --nowait \
  --rc4-crypt --rc4-key my_encryption_key
```

### REGISTER с шифрованием

```
REGISTER sip:10.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK718293645
From: <sip:trunk01@10.0.0.1>;tag=enc_reg_001
To: <sip:trunk01@10.0.0.1>
Call-ID: enc-trunk-reg@192.168.50.66
CSeq: 1 REGISTER
Contact: <sip:trunk01@192.168.50.66:5060>;expires=300
Max-Forwards: 70
User-Agent: dble
X-ACrypt: RC4:my_encryption_key
Content-Length: 0

```

### INVITE с шифрованием

```
INVITE sip:79161234567@10.0.0.1 SIP/2.0
Via: SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK819273645
From: <sip:trunk01@10.0.0.1>;tag=enc_inv_001
To: <sip:79161234567@10.0.0.1>
Call-ID: enc-trunk-call@192.168.50.66
CSeq: 1 INVITE
Contact: <sip:trunk01@192.168.50.66:5060>
Max-Forwards: 70
User-Agent: dble
X-ACrypt: RC4:my_encryption_key
Content-Type: application/sdp
Content-Length: 290

v=0
o=userX 20000001 20000001 IN IP4 192.168.50.66
s=DBL Session
c=IN IP4 192.168.50.66
t=0 0
m=audio 10000 RTP/SAVP 8 0 101
a=rtpmap:8 PCMA/8000
a=rtpmap:0 PCMU/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=ptime:20
a=sendrecv
```

> **Обратите внимание**: `m=audio 10000 RTP/SAVP` вместо `RTP/AVP` и наличие `X-ACrypt`.

---

*Документ создан на основе реверс-инжиниринга бинарного файла sipcli из прошивки GHSFVT-1.1-68-11 (GST1610/GoIP).*
*Все примеры реконструированы из строковых данных бинарника и скриптов конфигурации.*
*Для получения реальных SIP-дампов используйте: `echo SIP_DEBUG=1 > /etc/ipin` на устройстве.*
