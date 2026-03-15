# Глубокий анализ вспомогательных бинарных файлов GoIP GST1610

**Версия прошивки:** GHSFVT-1, PATCH=1-68-11, FW_VER=8  
**Архитектура:** ARM 32-bit, Little Endian (ELF32)  
**Линкер:** /lib/ld-uClibc.so.0  
**Компилятор:** GCC 3.3.2/3.3.5 (Debian prerelease)  
**Дата анализа:** 15.03.2026  

---

## Оглавление

1. [Обзор всех бинарных файлов](#1-обзор)
2. [ep — Event Processor](#2-ep)
3. [ipp — IP Phone / H.323 модуль](#3-ipp)
4. [ioctl — Утилита шифрования/дешифрования](#4-ioctl)
5. [gsmdb — GSM Debug](#5-gsmdb)
6. [smail — SMTP-клиент для email-уведомлений](#6-smail)
7. [start_ddnscli — DDNS-клиент (скрипт запуска)](#7-ddnscli)
8. [mg — Media Gateway (RTP/аудио)](#8-mg)
9. [smb_module — Remote SIM Module](#9-smb-module)
10. [smpp_smsc — SMPP-сервер SMS](#10-smpp-smsc)
11. [radmcli — Клиент удалённого администрирования](#11-radmcli)
12. [rstdt — Reset/Watchdog Daemon](#12-rstdt)
13. [pppmon — PPP Connection Monitor](#13-pppmon)
14. [unimac — MAC Address Manager](#14-unimac)
15. [decrypt.RC4 — RC4 шифрование/дешифрование](#15-decrypt-rc4)
16. [getipbyname — DNS-резолвер](#16-getipbyname)
17. [l1_set_oper — Выбор GSM-оператора](#17-l1-set-oper)
18. [Утилиты из /usr/sbin](#18-sbin-утилиты)
19. [svcd — Менеджер сервисов (init-система)](#19-svcd)
20. [Стартовые скрипты](#20-стартовые-скрипты)
21. [Общая карта IPC](#21-карта-ipc)
22. [Захардкоженные адреса и учётные данные](#22-захардкоженные-данные)
23. [Общая схема запуска системы](#23-схема-запуска)

---

## 1. Обзор всех бинарных файлов {#1-обзор}

### Файлы в `/usr/bin/`

| Файл | Размер | Тип | Назначение |
|------|--------|-----|------------|
| `ata` | 317 060 | ELF ARM | Главный ATA/GSM-контроллер |
| `ipp` | 539 992 | ELF ARM | H.323 IP Phone / VoIP-эндпоинт |
| `sipcli` | 658 064 | ELF ARM | SIP-клиент |
| `fvdsp` | 903 784 | ELF ARM | DSP-процессор голоса |
| `mg` | 117 032 | ELF ARM | Media Gateway (RTP) |
| `smb_module` | 67 916 | ELF ARM | Remote SIM модуль |
| `radmcli` | 51 296 | ELF ARM | Клиент удалённого администрирования |
| `smail` | 47 152 | ELF ARM | SMTP email-клиент |
| `smpp_smsc` | 43 080 | ELF ARM | SMPP SMS-сервер |
| `rstdt` | 43 048 | ELF ARM | Reset/Watchdog Daemon |
| `pppmon` | 14 108 | ELF ARM | PPP Monitor |
| `unimac` | 6 816 | ELF ARM | MAC-адрес из MTD |
| `ioctl` | 6 048 | ELF ARM | Шифровальщик файлов |
| `getipbyname` | 6 288 | ELF ARM | DNS-резолвер |
| `decrypt.RC4` | 6 012 | ELF ARM | RC4 шифрование |
| `ep` | 31 | Shell | Event Processor — запись в /etc/ipin |
| `gsmdb` | 40 | Shell | GSM Debug — запись в /etc/ipin |
| `echocmd` | 38 | Shell | Отправка эхо-команды |
| `getuptime` | 47 | Shell | Запись uptime |
| `l1_set_oper` | 1 020 | Shell | Выбор GSM-оператора Line1 |
| `start_ipp` | 21 771 | Shell | Запуск ipp с параметрами H.323 |
| `start_sip` | 6 737 | Shell | Запуск sipcli с SIP-параметрами |
| `start_mg` | 2 777 | Shell | Запуск mg с codec/relay параметрами |
| `start_ddnscli` | 2 268 | Shell | Запуск DDNS-клиента |
| `start_radm` | 433 | Shell | Запуск radmcli |
| `start_waddrmon` | 491 | Shell | Запуск мониторинга доменов |
| `start_httpd` | 648 | Shell | Запуск HTTP-сервера |
| `start_ata` | 118 | Shell | Запуск ATA |
| `start_smb` | 125 | Shell | Запуск smb_module |
| `start_fvdsp` | 48 | Shell | Запуск fvdsp |
| `start_ntp2` | 61 | Shell | Запуск NTP через gontp.com |
| `start_imeimon` | 68 | Shell | IMEI Monitor |
| `start_sip_port_change` | 275 | Shell | Ротация SIP-портов |
| `stop_fvdsp` | 25 | Shell | Остановка fvdsp |
| `stop_mg` | 31 | Shell | Остановка mg |
| `backup_config` | 200 | Shell | Бэкап конфигурации |
| `restore_config` | 191 | Shell | Восстановление конфигурации |
| `update` | 768 | Shell | Обновление прошивки |

### Файлы в `/usr/sbin/`

| Файл | Размер | Тип | Назначение |
|------|--------|-----|------------|
| `httpd` | 71 020 | ELF ARM | HTTP-сервер (Web UI) |
| `pppoecd` | 85 120 | ELF ARM | PPPoE-клиент |
| `dnscli` | 43 084 | ELF ARM | DDNS-клиент |
| `mon_waddr` | 38 900 | ELF ARM | Мониторинг WAN-адреса |
| `ping2` | 9 784 | ELF ARM | Утилита ping |
| `sysinfo` | 3 680 | ELF ARM | Сборщик диагностики |
| `sh` | 44 748 | ELF ARM | Оболочка (ash/sh) |
| `brctl` | 21 500 | ELF ARM | Управление bridge |

### Файлы в `/sbin/`

| Файл | Размер | Тип | Назначение |
|------|--------|-----|------------|
| `svcd` | 91 068 | ELF ARM | **Init-система / менеджер сервисов** |
| `init` | 13 180 | ELF ARM | PID 1 — первый процесс |
| `up` | 119 512 | ELF ARM | Обновление прошивки (updater) |
| `ntp` | 51 268 | ELF ARM | NTP-клиент |
| `iptables` | 68 320 | ELF ARM | Файрвол |
| `arp` | 37 316 | ELF ARM | ARP-утилита |
| `hwinfo` | 10 804 | ELF ARM | Чтение/запись аппаратной информации |
| `sysinfod` | 6 632 | ELF ARM | Демон системной информации |
| `ps` | 3 832 | ELF ARM | Список процессов |

---

## 2. ep — Event Processor {#2-ep}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 31 байт |
| Тип | Shell-скрипт |
| Entry point | N/A |

### Содержимое

```bash
#/!/bin/sh
echo $1 > /etc/ipin
```

### Анализ

**`ep` — НЕ бинарный файл**, а микро-скрипт из 2 строк. Его единственная задача — записать первый аргумент командной строки в файл `/etc/ipin`.

**Механизм IPC:** Файл `/etc/ipin` является центральным механизмом IPC для всей прошивки GoIP. Это именованный pipe или файл, через который различные процессы (прежде всего `ata`, то есть главный контроллер GSM-линий) получают управляющие команды.

**Примеры команд, отправляемых через `/etc/ipin`:**
- `IPPSTART` — запуск IPP/SIP
- `TRUNKSTART` — запуск Trunk-режима
- `IMEISET` — установка IMEI
- `GSM_DEBUG=N` — включение GSM-отладки
- `SIP_DEBUG=N` — включение SIP-отладки
- произвольные команды событий

**Дубликат:** Идентичная копия существует в `/usr/sbin/ep`.

---

## 3. ipp — IP Phone / H.323 модуль {#3-ipp}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 539 992 байт (~527 КБ) |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009854 |
| Строки | 4457 |
| Компилятор | GCC 3.3.5 |

### Назначение

`ipp` — полноценный H.323-эндпоинт (IP Phone Protocol). Это один из двух VoIP-стеков прошивки (второй — `sipcli` для SIP). Реализует:

- Регистрацию на H.323 Gatekeeper
- Установку/завершение вызовов по H.323
- H.245 согласование медиа (Master/Slave Determination)
- H.235 аутентификацию (MD5, SHA1, пароли)
- NAT Traversal (STUN, Relay, Port Forward, Citron)
- Шифрование (VOS2000, AVS, ET263)
- Управление до 8 линий / 8 групп
- DTMF (inband и outband)
- T.38 FAX
- Billing support
- Dial plan с префиксами

### Ключевые исходные файлы

```
gateway.c           — основная логика шлюза
main.c              — точка входа
ippui.c             — UI-интерфейс (управление линиями)
linectrl.c          — контроллер линий
groupctrl.c         — управление группами
dial_plan.c         — план набора
call-connection.c   — соединение вызовов
callctrl_ses.c      — управление сессиями
channel-ctrl.c      — управление каналами
endpoint.c          — H.323-эндпоинт
gkclient_ses.c      — клиент Gatekeeper
h235_ses.c          — H.235 аутентификация
h245_pe.c           — H.245 протокольные элементы
q931.c / q931_pe.c  — Q.931 (setup/connect/release)
mediactrl_ses.c     — управление медиа
msd_se.c            — Master/Slave Determination
nat_ses.c / nat_se.c — NAT Traversal
incoming-call_se.c  — входящие вызовы
outgoing-call_se.c  — исходящие вызовы
progress_se.c       — прогресс вызова
ras_pe.c            — RAS (Registration/Admission/Status)
registraion_se.c    — регистрация (заметьте опечатку в исходнике!)
admission_se.c      — admission на GK
mgcli_h323dev.c     — интерфейс с MG (Media Gateway)
mgcli.c / mgproto.c — протокол управления MG
avscrypt.c          — AVS-шифрование
voscrypt.c          — VOS2000-шифрование
protocol_transport.c — транспортный уровень
tpktconn.c / tpktlsn.c — TPKT TCP-соединения
relay.c             — relay-транспорт
asn1per.c / asn1type.c — ASN.1 PER кодирование
app.c               — общий фреймворк приложения
net.c               — сетевой слой
sockaddr.c          — адресация сокетов
syscfg.c            — интерфейс с syscfg
utils.c             — утилиты
datalist.c          — списки данных
scheduler.c         — планировщик событий
```

### IPC-интерфейсы

| Путь | Тип | Направление | Описание |
|------|-----|-------------|----------|
| `/tmp/mg%d` | Unix Socket | ipp → mg | Управление Media Gateway (0-7) |
| `/tmp/.ippui%d` | Unix Socket | ippui → ipp | UI-управление (DTMF, набор) |
| `/tmp/.ippui_cli%d` | Unix Socket | ipp → CLI | Клиентская часть UI |
| `/tmp/.syscfg-server` | Unix Socket | ipp → svcd | Чтение/запись syscfg |
| `/proc/net/route` | procfs | Read | Маршрутизация |
| `/proc/%u/exe` | procfs | Read | Путь к исполняемому файлу |
| `/dev/urandom` | Device | Read | Генерация случайных чисел |
| `/etc/%s.conf` | File | Read | Файлы конфигурации |

### Конфигурационные переменные syscfg

```
H323_GROUP[1-8]_GKADDR      — адреса Gatekeeper для групп
H323_GROUP[1-8]_NUMBER       — номера телефонов для групп
H323_GROUP[1-8]_GW_PREFIX    — префиксы шлюза
H323_GROUP[1-8]_H235_ID      — H.235 ID для аутентификации
H323_GROUP[1-8]_H235_PASSWD  — H.235 пароли
H323_CONFIG_MODE             — SINGLE_MODE / LINE_MODE / GROUP_MODE
H323_ENDPOINT_MODE           — DIRECT_MODE / через GK
H323_NAT_TRAVERSAL           — NONE / STUN / RELAY / CITRON
H323_RELAY_SERVER[1-4]       — адреса relay-серверов
H323_QOS                     — DIFFSERV / IPTOS
PHONE_NUMBER                 — номер телефона
ENDPOINT_TYPE                — H323 / SIP
BILLING_SUPPORT              — поддержка биллинга
```

### Поддерживаемые кодеки

```
ulaw, alaw, g7231, g723l, g723h, g729, g729a, g729ab, t38fax, rfc2833
```

### Режимы шифрования

| Режим | Описание |
|-------|----------|
| VOS2000 | Шифрование VOS (proprietary) |
| AVS | AVS-шифрование |
| ET263 | ET263-шифрование с типом и глубиной |
| RC4 | RC4-шифрование с ключом |

### Захардкоженные адреса

| Адрес | Назначение |
|-------|------------|
| `202.96.136.145` | Echo/NAT сервер (China Telecom DNS) |
| `:54210` | Порт echo-сервера |
| `fspipsev.net` | Bugreport SMTP-сервер |
| `bug@fspipsev.net` | Email для bugreport-ов |

### Командная строка запуска (из `start_ipp`)

```bash
/usr/bin/ipp \
  --enable-early-media 1 --faststart-extend 1 --billing_support 1 \
  --group0_gkaddr <ADDR> --group0_number <NUM> \
  --group0_h235_id <ID> --group0_h235_passwd <PASSWD> \
  --group0_crypt_mode <MODE> \
  --group0_lines 0,1,2,... \
  [transport options] [ICEv1 options]
```

---

## 4. ioctl — Утилита шифрования/дешифрования {#4-ioctl}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 6 048 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00008564 |
| Строки | 56 |

### КРИТИЧЕСКОЕ ОТКРЫТИЕ

**Несмотря на имя `ioctl`, этот файл НЕ является утилитой аппаратного ввода-вывода!** Это утилита **шифрования/дешифрования файлов**.

### Usage

```
usage:enc -k <key> <input> <ofpput>
```

> Примечание: `ofpput` — опечатка в исходном коде, должно быть `output`.

### Критическое использование в системе

**Файл `ioctl` используется в стартовом скрипте `/sbin/network` для расшифровки критических системных файлов:**

```bash
#!/bin/sh
/usr/bin/ioctl -k ${CPU} /etc/init.d/df.b /tmp/default.bound
chmod 755 /tmp/default.bound

/usr/bin/ioctl -k ${CPU} /etc/init.d/lglm /tmp/loginlimit
chmod 755 /tmp/loginlimit

/usr/bin/ioctl -k ${CPU} /etc/init.d/lg /tmp/login
chmod 755 /tmp/login
```

### Анализ безопасности

| Зашифрованный файл | Расшифрованный файл | Назначение |
|---------------------|----------------------|------------|
| `/etc/init.d/df.b` | `/tmp/default.bound` | Скрипт DHCP lease получения |
| `/etc/init.d/lglm` | `/tmp/loginlimit` | Ограничение попыток входа |
| `/etc/init.d/lg` | `/tmp/login` | Скрипт аутентификации при входе |

**Ключ шифрования:** `${CPU}` — переменная среды, содержащая идентификатор процессора (CPU ID). Это означает, что:
- Зашифрованные файлы привязаны к конкретному CPU
- Ключ шифрования — простой, основан на аппаратном ID
- Алгоритм, вероятно, идентичен `decrypt.RC4` или похожий симметричный шифр

### Зависимые библиотеки

```
libgcc_s.so.1, libc.so.0 (uClibc)
```

### Используемые функции

```
read, write, open, close, strlen, fprintf, fputs
```

---

## 5. gsmdb — GSM Debug {#5-gsmdb}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер (/usr/bin) | 40 байт |
| Размер (/usr/sbin) | 69 байт |
| Тип | Shell-скрипт |

### Содержимое

**/usr/bin/gsmdb:**
```bash
#!/bin/sh
echo GSM_DEBUG=$1 > /etc/ipin
```

**/usr/sbin/gsmdb:**
```bash
#!/bin/sh
echo GSM_DEBUG=0 > /etc/ipin
echo GSM_DEBUG=$1 > /etc/ipin
```

### Анализ

`gsmdb` — микро-утилита для управления уровнем GSM-отладки. Записывает команду `GSM_DEBUG=N` в `/etc/ipin`, откуда её считывает главный процесс `ata`.

**Уровни отладки** (из скриптов `infogsm*`):
- `0` — отладка выключена
- `1` — базовый GSM-дебаг
- `17` — расширенный GSM-дебаг (GSM + SIP)

Связанные утилиты:
- `sipdb` — аналог для SIP (`echo SIP_DEBUG=$1 > /etc/ipin`)
- `infogsm1`, `infogsmclose`, `infogsmsip`, `infosip` — комбинированные скрипты

---

## 6. smail — SMTP-клиент для email-уведомлений {#6-smail}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 47 152 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009508 |
| Строки | 340 |

### Назначение

`smail` — полноценный SMTP-клиент для отправки email-уведомлений (SMS-to-Email, bugreport). Поддерживает:

- SMTP с аутентификацией (AUTH LOGIN)
- MIME multi-part сообщения
- Вложения (base64-кодирование)
- Base64 для тела сообщения (UTF-8)

### Ключевые исходные файлы

```
smail.c       — SMTP-клиент
app.c         — фреймворк приложения
net.c         — сетевой слой
sockaddr.c    — адресация
syscfg.c      — интерфейс syscfg
utils.c       — утилиты
```

### SMTP-протокол

```
smtp_connect    → подключение к серверу
smtp_hello      → HELO/EHLO
smtp_login      → AUTH LOGIN (base64)
smtp_send       → MAIL FROM / RCPT TO / DATA
smtp_quit       → QUIT
smtp_check_status → проверка кодов ответа
```

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `LINE%d_MAIL_SVR` | SMTP-сервер для линии N |
| `LINE%d_MAIL_ID` | Логин для SMTP |
| `LINE%d_MAIL_PASSWD` | Пароль для SMTP |
| `LINE%d_MAIL_TO` | Адрес получателя |
| `SN` | Серийный номер устройства |

### Формат сообщений

```
From: <отправитель>
To: <получатель>
Subject: SN:<серийный_номер> Channel:<номер_канала>
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="<boundary>"
X-Mailer: smail 0.1
```

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| `/tmp/.syscfg-server` | Unix Socket | Чтение syscfg |
| `.syscfg-client-%d` | Unix Socket | Клиентский сокет |

### Захардкоженные адреса — Bugreport

| Параметр | Значение |
|----------|----------|
| SMTP-сервер | `fspipsev.net` |
| IP-адрес | `61.141.247.7` |
| Email отправителя | `bug@fspipsev.net` |
| Email получателя | `bug@fspipsev.net` |
| HELO домен | `fspipsev.net` |

**Bugreport-ы отправляются при ошибках подключения:**
```
bugreport: E%.03d cannot connect to server!
bugreport: E%.03d: connection error
bugreport: E%.03d: server error: %s
```

### Подсистема отладки

```
/dev/ttyS0      — последовательный порт для отладки
/dev/audio      — аудио-устройство
DEBUG_SERVER    — адрес сервера отладки
```

---

## 7. start_ddnscli — DDNS-клиент {#7-ddnscli}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Скрипт запуска | `/usr/bin/start_ddnscli` (2 268 байт) |
| Бинарный файл | `/usr/sbin/dnscli` (43 084 байт, ELF ARM) |

### Анализ скрипта запуска

Скрипт `start_ddnscli` конфигурирует до 9 доменов для мониторинга и запускает `dnscli`:

```bash
exec /usr/sbin/dnscli --server ${DDNS_ADDR} --port ${DDNS_PORT} \
  $PARAMS -f /var/tmp/hosts -t ${DDNS_UPDATE_INTERVAL} --sn ${SN}
```

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `DDNS_ADDR` | Основной DDNS-сервер |
| `DDNS_PORT` | Порт DDNS-сервера |
| `DDNS_BACKUP_ADDR` | Резервный DDNS-сервер |
| `DDNS_BACKUP_PORT` | Порт резервного сервера |
| `DDNS_UPDATE_INTERVAL` | Интервал обновления |
| `DDNS_ENABLE` | Включить/выключить DDNS |
| `SN` | Серийный номер устройства |
| `SIP_PROXY` / `SIP_CONTACT[0-7]_PROXY` | Домены для мониторинга |
| `SMB_SVR` | Домен SIM-сервера |

### Функция DDNS

- Резолвит домены SIP-прокси в IP-адреса
- Записывает результат в `/var/tmp/hosts`
- Поддерживает до 9 доменов
- Работает в SINGLE_MODE и мульти-режиме
- Зависимость: `LAN_PORT_STATE=up`, `DDNS_ENABLE=1`

---

## 8. mg — Media Gateway (RTP/аудио) {#8-mg}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 117 032 байт (~114 КБ) |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009614 |
| Строки | 538 |

### Назначение

`mg` — Media Gateway, отвечающий за:
- RTP/RTCP транспорт аудио
- Кодирование/декодирование голоса
- Управление DSP через fvdsp
- Jitter buffer
- NAT Traversal для медиа
- STUN для RTP
- Relay для RTP (через TCP и UDP)
- Шифрование RTP (RC4, ET263, VOS2000, AVS, ECM)
- T.38 FAX поддержка
- Watchdog

### Ключевые исходные файлы

```
main.c              — точка входа, парсинг аргументов
et263_crypt.c       — ET263-шифрование
stunlib.c           — STUN-библиотека
app.c               — фреймворк приложения
net.c               — сетевой уровень
sockaddr.c          — адресация
syscfg.c            — интерфейс syscfg
utils.c             — утилиты
```

### IPC-интерфейсы

| Путь | Тип | Направление | Описание |
|------|-----|-------------|----------|
| `/tmp/.fvdsp_cmd_in` | Unix Socket | mg → fvdsp | Команды DSP |
| `/tmp/.fvdsp_mgcmd%d` | Unix Socket | mg → fvdsp | Команды для канала N |
| `/tmp/.fvdsp_data_out%d` | Unix Socket | fvdsp → mg | Аудио-данные от DSP |
| `/tmp/.fvdsp_data_in%d` | Unix Socket | mg → fvdsp | Аудио-данные к DSP |
| `/tmp/.ippui%d` | Unix Socket | mg → ipp/sipcli | UI-события |
| `/tmp/mg%d` | Unix Socket | ipp/sipcli → mg | Управление MG |
| `/tmp/.syscfg-server` | Unix Socket | mg → svcd | Syscfg |
| `/dev/watchdog` | Device | Write | Watchdog feed |
| `/dev/urandom` | Device | Read | Случайные числа |
| `/proc/net/route` | procfs | Read | Маршрутизация |

### Командная строка запуска

```bash
/usr/bin/mg \
  [-n <NUM_CHANNELS>] \
  [--poll-inval 25] [--enable-watchdog] \
  [--codec-preference0=alaw,ulaw,...] \
  [-t <transport_type>] \
  [--rc4-key=<KEY>] \
  [--relay-server=<ADDR>] \
  [--relay-encrypt] \
  [--rtp-tos=<TOS>] \
  [--rtp-report-interval <N>]
```

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `AUDIO_CODEC_PREFERENCE[0-7]` | Предпочтения кодеков по каналам |
| `AUDIO_DEVICE` | Аудио-устройство |
| `MG_RELAY_SERVER[1-4]` | Relay-серверы |
| `MG_RELAY_PORT` | Порт relay-сервера |
| `MG_RELAY_USER` | Имя пользователя relay |
| `MG_RELAY_PASSWD` | Пароль relay |
| `MG_STUN_SERVER` | STUN-сервер |
| `MG_ET263_CRYPT` | ET263-шифрование |
| `MG_ET263_CRYPT_TYPE` | Тип ET263-шифрования |
| `MG_ET263_CRYPT_DEP` | Глубина ET263-шифрования |
| `ECM_CRYPT_KEY` | ECM-ключ шифрования |
| `RTP_PORT` | Диапазон RTP-портов |
| `SYMMETRIC_RTP` | Симметричный RTP |
| `PACKETIZE_PERIOD` | Период пакетизации |
| `SILENCE_THRESHOLD` | Порог тишины (VAD) |
| `FVDSP_DEV%d_TYPE` | Тип DSP-устройства |
| `SLIC` | Тип SLIC |
| `INBAND_DTMF` | Inband DTMF |
| `SIP_OUTBAND_DTMF_TYPE` | Outband DTMF тип |
| `USE_HW_JITTER` | Аппаратный jitter buffer |

### Команды DSP (через fvdsp)

```
open %d            — открыть канал
close %d           — закрыть канал
cfg %d codec %d %d — настроить кодек
cfg %d mr %d       — media rate
cfg %d fax %d      — FAX-режим
cfg %d set         — применить настройки
remote %d          — remote endpoint
mstop %d           — остановить медиа
fax %d             — начать FAX
DTMF %c            — отправить DTMF
```

### Поддерживаемые кодеки

```
ulaw, alaw, g7231 (5.3/6.3 kbps), g723l, g723h, g729, g729a, g729ab, t38fax, 
rfc2833 (DTMF)
```

### Режимы шифрования RTP

| Режим | Описание |
|-------|----------|
| RC4 | RC4-шифрование с ключом |
| ET263 | ET263 с типами: convert_16, convert_8, parity_exchange_16, parity_exchange_8 |
| VOS2000 | Proprietary VOS-шифрование |
| AVS | AVS-шифрование (через порт) |
| ECM | ECM-шифрование с ключом из `ECM_CRYPT_KEY` |
| X-ACrypt | Заголовок расширения RTP для индикации шифрования |

---

## 9. smb_module — Remote SIM Module {#9-smb-module}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 67 916 байт (~66 КБ) |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009570 |
| Строки | 469 |

### Назначение

`smb_module` (SIM Bank Module) — клиент для подключения к удалённому SIM-серверу (SIM Bank). Обеспечивает:

- Подключение к серверу SIM Bank (SMB_SVR)
- Проксирование APDUкоманд к локальному GSM-модему
- Передачу IMEI модема серверу
- Замену SIM-карты (hot-swap через сервер)
- Мониторинг состояния SIM
- Аутентификацию на SIM-сервере
- SMS forwarding

### Ключевые исходные файлы

```
main.c          — точка входа, конфигурация
callback.c      — обработка SIM-данных (APDU)
cli.c           — клиентский протокол
mmon.c          — мониторинг модемов
uart.c          — работа с UART (/dev/ttyS*)
app.c           — фреймворк
net.c           — сетевой уровень
net_utils.c     — сетевые утилиты
sockaddr.c      — адресация
syscfg.c        — интерфейс syscfg
```

### IPC-интерфейсы

| Путь | Тип | Направление | Описание |
|------|-----|-------------|----------|
| `/tmp/.smb_cli%d` | Unix Socket | Клиент → smb | CLI-интерфейс |
| `/tmp/.smb%d` | Unix Socket | smb → ATA | Данные SIM |
| `/dev/ttyS%d` | Serial | smb ↔ Modem | UART к GSM-модему |
| `/etc/hosts` | File | Read | Резолвинг хостов |
| `/tmp/.syscfg-server` | Unix Socket | smb → svcd | Syscfg |

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `SMB_SVR` | Основной SIM Bank сервер |
| `SMB_SVR1` | Резервный SIM Bank сервер |
| `SMB_SVR%d` | Дополнительные серверы |
| `SMB_ID` | ID устройства на сервере |
| `SMB_ID%d` | ID по группам |
| `SMB_KEY` | Ключ аутентификации |
| `SMB_PASSWD%d` | Пароли по группам |
| `SMB_RC4_KEY` | RC4-ключ шифрования |
| `SMB_RMSIM` | Режим Remote SIM |
| `SMB_NET_TYPE` | Тип сети |
| `SMB_LOGIN` | Тип авторизации |
| `SMB_G%d` | Настройки групп |
| `LINE%d_SMB_LOGIN` | Логин SMB для линии |
| `TELPORT` | Количество линий |

### APDU-команды SIM

Захардкоженные APDU-команды для работы с SIM-картой:

| APDU | Описание |
|------|----------|
| `9f0f` | GET RESPONSE |
| `9404` | File not found |
| `611b` | SW: more data available |
| `6a82` | File not found (error) |
| `c0000000b06f3c...` | SELECT EF_MSISDN |
| `c0000001186f3b...` | SELECT EF_SMS |
| `c062198205422100b0...` | READ RECORD (FCP template) |
| `b200ff...` | READ BINARY (полный буфер) |
| `9000` | SUCCESS ответ |

### Протокол SIM

```
+SIMDATA: "<hex>"     — ответ SIM-модуля
+SIMRESET             — сброс SIM-карты
AT+SIMDATA="<hex>"    — отправка APDU-команды
SIMPWROFF             — выключение SIM
MIMEIRS               — запрос IMEI Reset
MRSIMEI<IMEI>         — установка Remote SIM IMEI
SMSID                 — идентификатор SMS
SMSLM                 — SMS лимит
SMS<data>             — SMS-сообщение
SIMNUM<num>           — номер SIM-карты
RSMS<data>            — Remote SMS
```

### Командная строка запуска

```bash
/usr/bin/smb_module -t 50
```

Параметр `-t 50` — таймаут в секундах.

**Условие запуска (из `start_smb`):**
```bash
while [ "${AREA}" = "CHN" -a "${REMOTE_SIM}" = "0" ]; do sleep 3600; done
```
> В Китае Remote SIM отключён по умолчанию. Скрипт ждёт бесконечно, если AREA=CHN и REMOTE_SIM=0.

---

## 10. smpp_smsc — SMPP-сервер SMS {#10-smpp-smsc}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 43 080 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009508 |
| Строки | 256 |

### Назначение

`smpp_smsc` — SMPP (Short Message Peer-to-Peer) сервер, позволяющий внешним SMPP-клиентам (ESME) отправлять и принимать SMS через GSM-модемы GoIP.

### SMPP-протокол

Поддерживаемые операции:
- **DELIVER** — доставка входящих SMS клиенту
- **SUBMIT** — приём SMS от клиента для отправки
- **DELIVER ACK** — подтверждение доставки

### Формат отчётов о доставке

```
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:DELIVRD err:0 Text:%.20s
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:UNDELIV err:501 Text:%.20s
id:%d sub:%d dlvrd:%d submit date:%s done date:%s stat:ENROUTE err:0 Text:%.20s
```

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| TCP (SMPP_PORT) | TCP Socket | SMPP-сервер для ESME-клиентов |
| `/tmp/.syscfg-server` | Unix Socket | Syscfg |

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `SMPP_ENABLE` | Включить/выключить SMPP |
| `SMPP_PORT` | TCP-порт SMPP-сервера |
| `SMPP_ID` | System ID для SMPP |
| `SMPP_KEY` | Password для SMPP |
| `SMPP_GNUM_EN` | Включение GNUM |
| `SMPP_ENROUTE_DISABLE` | Отключить ENROUTE-статус |
| `TELPORT` | Количество GSM-линий |

### Команды к ATA

```
SMS%d %d %s %d %d %d      — отправка SMS через линию N
GSMSTATUS                  — запрос статуса GSM
GSMSTATUS%d %d             — статус конкретной линии
DELIVER%d %d %d %s         — доставка SMS
SMSSTATUS%d %d %d %d       — статус SMS
```

### Зависимость от сервисов

В `svc.conf`:
```
service smpp
  exec /usr/bin/smpp_smsc
  depends LAN_PORT_STATE=up SMPP_ENABLE=1
  syscfg SMPP_*
```

---

## 11. radmcli — Клиент удалённого администрирования {#11-radmcli}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 51 296 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x0000949C |
| Строки | 341 |

### Назначение

`radmcli` (Remote Admin Client) — клиент для установления обратного туннеля к серверу удалённого управления. Позволяет производителю/оператору удалённо управлять шлюзом через NAT.

### Ключевые исходные файлы

```
radmc.c     — основная логика клиента
app.c       — фреймворк приложения
net.c       — сетевой уровень
sockaddr.c  — адресация
syscfg.c    — интерфейс syscfg
utils.c     — утилиты
```

### Протокол работы

1. Подключается к серверу `RADMIN_SERVER:RADMIN_PORT`
2. Аутентифицируется ключом `RADMIN_KEY`
3. Проксирует HTTP (Web UI) и Telnet
4. Поддерживает keepalive
5. Поддерживает белый список серверов (`RADM_WLIST`)
6. При разрыве — автоматическое переподключение

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| `/etc/ramdcli` | FIFO | Команды от локальных процессов |
| TCP (RADMIN_SERVER:RADMIN_PORT) | TCP | Обратный туннель к серверу |
| TCP (127.0.0.1:HTTP_PORT) | TCP | Проксирование Web UI |
| TCP (127.0.0.1:TPORT) | TCP | Проксирование Telnet |

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `RADMIN_ENABLE` | Включить удалённое управление |
| `RADMIN_SERVER` | Адрес сервера |
| `RADMIN_PORT` | Порт сервера (default: 1920) |
| `RADMIN_KEY` | Ключ шифрования |
| `RADMIN_ID` | ID устройства |
| `RADM_WLIST` | Белый список серверов |
| `HTTP_PORT` | HTTP-порт (default: 80) |
| `FTN` | Режим FTN (Telnet порт: 1→23, 0→13000) |

### Захардкоженные адреса — **КРИТИЧЕСКОЕ ОТКРЫТИЕ**

| Адрес | Тип | Описание |
|-------|-----|----------|
| `118.140.127.90` | IP | **White-list сервер #1** (Гонконг) |
| `47.242.142.229` | IP | **White-list сервер #2** (Alibaba Cloud, Гонконг) |
| `202.104.186.90` | IP | **White-list сервер #3** (Shenzhen Telecom) |
| `dbl#admin` | String | **Дефолтный ключ шифрования** |

### Анализ безопасности

**КРИТИЧЕСКАЯ УЯЗВИМОСТЬ:** Дефолтный ключ `dbl#admin` прошит в бинарном файле:
```c
RADMIN_KEY = "dbl#admin"  // default if not set
```

Это означает:
- Если `RADMIN_KEY` не задан в конфигурации, используется `dbl#admin`
- Любой, кто знает этот ключ, может получить удалённый доступ к HTTP и Telnet
- Три захардкоженных IP-адреса — это серверы производителя (DBL Technology, Shenzhen)

### Командная строка запуска

```bash
/usr/bin/radmcli \
  -r ${RADMIN_SERVER}:${RADMIN_PORT} \
  -al 127.0.0.1:${HTTP_PORT} \
  -ll 127.0.0.1:${TPORT} \
  -k "${RADMIN_KEY}" \
  -i "${RADMIN_ID}" \
  -t 30
```

| Параметр | Описание |
|----------|----------|
| `-r` | Remote server address:port |
| `-al` | Admin local (HTTP proxy) |
| `-ll` | Login local (Telnet proxy) |
| `-k` | Encryption key |
| `-i` | Device ID |
| `-t` | Timeout (30 сек) |

---

## 12. rstdt — Reset/Watchdog Daemon {#12-rstdt}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 43 048 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00009390 |
| Строки | 304 |

### Назначение

`rstdt` — демон сброса и watchdog. Отвечает за:
- Мониторинг кнопки RESET (через GPIO)
- Перезагрузку устройства по команде
- Управление таймером watchdog
- Обработку команд из `/tmp/svcctl`

### Ключевые исходные файлы

```
main.c      — основная логика, обработка GPIO
gpio.c      — работа с GPIO-устройством
app.c       — фреймворк приложения
net.c       — сетевой уровень
sockaddr.c  — адресация
syscfg.c    — интерфейс syscfg
utils.c     — утилиты
```

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| `/dev/gpio1` | Device | Чтение кнопки RESET |
| `/dev/watchdog` | Device | Watchdog timer |
| `/tmp/svcctl` | Unix Socket/FIFO | Управляющие команды |
| `/tmp/.syscfg-server` | Unix Socket | Syscfg |

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `WD_TIMER` | Таймер watchdog (ms) |
| `RESET_KEY` | Конфигурация кнопки сброса |

### Логика работы

```
1. gpio_init() — инициализация GPIO (/dev/gpio1)
2. Мониторинг RESET_KEY (кнопка на корпусе)
3. rstdt_timeout() — обработка таймаута
4. "Doing confirm" → подтверждение сброса
5. "Reset now" / "Reboot now" → выполнение reboot()
6. WD_TIMER → управление watchdog (default: 60000ms)
```

### Взаимодействие с svcctl

```
start reboot        — инициировать перезагрузку
/tmp/svcctl         — сокет для приёма команд
```

---

## 13. pppmon — PPP Connection Monitor {#13-pppmon}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 14 108 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00008E80 |
| Строки | 166 |

### Назначение

`pppmon` — мониторинг PPP/PPPoE-соединения. Следит за:
- Состоянием PPP-интерфейса (ppp0/pptp0)
- Прохождением пакетов
- Доступностью сети (ping)
- Автоматическим перезапуском PPPoE при потере связи

### Ключевые исходные файлы

```
pppmon.c     — основная логика
syscfg.c     — интерфейс syscfg
```

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| `/proc/net/dev` | procfs | Статистика пакетов |
| `/bin/restart_pppd` | exec | Перезапуск PPP-демона |
| `/tmp/.syscfg-server` | Unix Socket | Syscfg |

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `LAN_PORT_STATE` | Состояние LAN-порта (up/down) |

### Логика работы

```
1. Принимает 2 аргумента: dev (интерфейс) и pid (PID ppppoecd)
2. Мониторинг /proc/net/dev — счётчики пакетов
3. "No packet changed!" → пакеты не меняются
4. Ping шлюза для проверки связности
5. "No response" → нет ответа
6. kill_pid → kill(pid) для pppoecd
7. "/bin/restart_pppd" → перезапуск PPPoE
```

---

## 14. unimac — MAC Address Manager {#14-unimac}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 6 816 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00008540 |
| Строки | 53 |

### Назначение

`unimac` — утилита для чтения/записи MAC-адреса из/в MTD-раздел flash-памяти.

### Ключевые особенности

- **MTD-раздел:** `/dev/mtd/7` — раздел flash для хранения MAC-адреса
- **Формат вывода:** `00:%02x:%02x:%02x:%02x:%02x` (MAC-адрес с ведущим `00:`)
- **Операции:** ioctl к MTD для чтения/записи
- **Обфускация:** Строка `QZ^&` — возможно, ключ или маркер

### Минимальный набор функций

```
ioctl, open, close, memcpy, memset, atoi, printf
```

---

## 15. decrypt.RC4 — RC4 шифрование/дешифрование {#15-decrypt-rc4}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 6 012 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x00008564 |
| Строки | 55 |

### Usage

```
usage:rc4 -k <key> <input> <ofpput>
```

### Назначение

Утилита RC4-шифрования/дешифрования файлов. Используется в скриптах:
- `backup_config` — шифрование конфигурации при экспорте
- `restore_config` — дешифрование конфигурации при импорте

### Использование в конфигурации

**Экспорт (backup_config):**
```bash
getsyscfg > $1.tmp
decrypt.RC4 -k "$2@dbl" $1.tmp $1    # шифрование с ключом "$VENDOR_KEY@dbl"
```

**Импорт (restore_config):**
```bash
decrypt.RC4 -k "$2@dbl" $1 $1.tmp    # дешифрование
setsyscfg -f $1.tmp && syscfgctl save
```

### Анализ безопасности

- **Ключ формата:** `${VENDOR_KEY}@dbl` — суффикс `@dbl` (DBL Technology) всегда добавляется
- **RC4** — слабый алгоритм шифрования, легко взламывается
- **Двунаправленный:** одна и та же операция для шифрования и дешифрования (свойство RC4)

---

## 16. getipbyname — DNS-резолвер {#16-getipbyname}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 6 288 байт |
| Тип | ELF 32-bit ARM LE |
| Entry point | 0x000087D4 |
| Строки | 80 |

### Назначение

Простой DNS-резолвер, который переводит доменное имя в IP-адрес и сохраняет в syscfg.

### Конфигурационные переменные

| Переменная | Описание |
|-----------|----------|
| `VPN_DNS` | DNS-сервер для VPN |

### IPC

```
/tmp/.syscfg-server     — Unix Socket для syscfg
.syscfg-client-%d       — клиентский сокет
```

### Используемые функции

```
gethostbyname() — стандартный DNS-резолвинг
inet_ntop()     — преобразование адреса в строку
```

---

## 17. l1_set_oper — Выбор GSM-оператора {#17-l1-set-oper}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 1 020 байт |
| Тип | Shell-скрипт |

### Содержимое (сокращённо)

```bash
#!/bin/sh
if [ "${LINE1_GSM_OPER}" = "AUTO" ]; then
    setsyscfg L1_GSM_OPERATOR=AUTO
elif [ "${LINE1_GSM_OPER}" = 1 ]; then
    setsyscfg L1_GSM_OPERATOR=${LINE1_GSM_OPER_CODE1}
# ... до 10 кодов операторов
fi
setsyscfg LINE1_GSM_OPER=
syscfgctl save
```

### Назначение

Скрипт для ручного/автоматического выбора GSM-оператора на Линии 1. Поддерживает до 10 предварительно настроенных кодов операторов (`LINE1_GSM_OPER_CODE1` ... `LINE1_GSM_OPER_CODE10`).

---

## 18. Утилиты из /usr/sbin {#18-sbin-утилиты}

### sipdb — SIP Debug

```bash
#!/bin/sh
echo SIP_DEBUG=$1 > /etc/ipin
```
Включение/выключение отладки SIP-протокола.

### HWINFO — Hardware Info

```bash
#!/bin/sh
/sbin/hwinfo -r hwinfo
```
Чтение аппаратной информации из flash.

### rbm — Reboot Module

```bash
#!/bin/sh
echo MHRB$1 > /etc/ipin
```
Отправка команды перезагрузки модуля через IPC.

### KILL — Selective Kill

```bash
#!/bin/sh
[ "$1" = "httpd" ] && killall httpd
[ "$1" = "sipcli" ] && killall sipcli
[ "$1" = "mg" ] && killall mg
[ "$1" = "ata" ] && killall ata
```
Безопасное завершение конкретных сервисов.

### set_venid — Set Vendor ID

```bash
#!/bin/sh
/sbin/hwinfo -r hwinfo /tmp/hwinfo
echo VENID=$1 >> /tmp/hwinfo
/sbin/hwinfo -w hwinfo /tmp/hwinfo
```
Запись идентификатора вендора (OEM) в flash.

### infogsm1/infogsmclose/infogsmsip/infosip

Скрипты для включения различных комбинаций GSM/SIP отладки и запуска `sysinfo` для вывода диагностики.

### sysinfo

ELF-бинарник (3 680 байт) — подключается к Unix-сокету `/tmp/.sysinfo.sock` для сбора диагностической информации.

---

## 19. svcd — Менеджер сервисов (Init-система) {#19-svcd}

### Основные характеристики

| Параметр | Значение |
|----------|----------|
| Размер | 91 068 байт (~89 КБ) |
| Расположение | `/sbin/svcd` |
| Тип | ELF 32-bit ARM LE |
| Строки | 653 |

### Назначение

`svcd` — кастомная init-система, управляющая всеми сервисами GoIP. Это самый важный системный процесс после PID 1 (`init`).

### Ключевые исходные файлы

```
main.c          — точка входа
svcd.c          — ядро менеджера сервисов
svcfg.c         — парсер конфигурации svc.conf
cfgdb.c         — база конфигурации
proc_se.c       — управление процессами (fork/exec)
script.c        — выполнение скриптов init.d
sched.c         — планировщик (cron)
reboot.c        — перезагрузка
watchdog.c      — watchdog
netmon.c        — мониторинг сети
syscfg.c        — системная конфигурация
registry.c      — реестр (MTD flash)
resolver.c      — DNS-резолвер
rtems_bsdnet_ntp.c — NTP-клиент
app.c           — фреймворк приложения
net.c           — сетевой уровень
sockaddr.c      — адресация
```

### Конфигурационный файл: `/usr/etc/svc.conf`

Определяет все сервисы системы:

```
service ata         — GSM/ATA-контроллер
service mg          — Media Gateway
service fvdsp       — DSP-процессор
service ipp         — H.323-эндпоинт
service sipcli      — SIP-клиент
service radm        — Удалённое администрирование
service pptp        — PPTP VPN
service ddnscli     — DDNS-клиент
service monwaddr    — Мониторинг WAN
service smb         — SIM Bank модуль
service rstdt       — Reset/Watchdog
service smpp        — SMPP SMS-сервер
service sipport     — Ротация SIP-портов
service imei_mon    — Мониторинг IMEI
service ntp2        — NTP-синхронизация
service autocfg-refresh — Авто-конфигурация (refresh)
service autocfg-retry   — Авто-конфигурация (retry)
```

### IPC-интерфейсы

| Путь | Тип | Описание |
|------|-----|----------|
| `/tmp/svcctl` | Unix Socket | **Основной управляющий сокет** |
| `/tmp/.syscfg-server` | Unix Socket | Syscfg-сервер |
| `/dev/watchdog` | Device | Watchdog feed |
| `/dev/gpio0` | Device | GPIO для watchdog |

### Управление syscfg

Файлы определений и дефолтов:

| Файл | Описание |
|------|----------|
| `/usr/etc/syscfg.def` | Определения переменных |
| `/usr/etc/syscfg.default` | Значения по умолчанию |
| `/usr/etc/syscfg.default.{VENID}` | Дефолты для OEM |
| `/usr/etc/syscfg.constant` | Константы (FW_VER=8) |
| `/usr/etc/syscfg.constant.{VENID}` | Константы для OEM |
| `/usr/etc/VERSION` | Версия прошивки |
| `/usr/etc/PATCH` | Номер патча |
| `/dev/mtdblock/5` | MTD: syscfg storage |
| `/dev/mtdblock/6` | MTD: registry |
| `/dev/mtdblock/7` | MTD: hardware info |

### Зависимости сервисов (из svc.conf)

```
ipp       → depends LAN_PORT_STATE=up ENDPOINT_TYPE=H323
sipcli    → depends LAN_PORT_STATE=up ENDPOINT_TYPE=SIP
ddnscli   → depends LAN_PORT_STATE=up DDNS_ENABLE=1
smb       → depends LAN_PORT_STATE=up RMSIM_ENABLE=1
smpp      → depends LAN_PORT_STATE=up SMPP_ENABLE=1
radm      → depends RADMIN_ENABLE=1
pptp      → depends PPTP_ENABLE=1
sipport   → depends SIP_RANDOM_LC_PORT=1
imei_mon  → depends LAN_PORT_STATE=up
ntp2      → depends LAN_PORT_STATE=up
autocfg*  → depends AUTOCFG=1 NTP_SYNC=1
```

### Управление процессами

```
svcd_do_start(service)    — запуск сервиса
svcd_do_stop(service)     — остановка сервиса
svcd_do_reload(service)   — перезагрузка конфигурации
svcd_restart_service()    — перезапуск
proc_svcent_run()         — fork() + execv()
proc_svcent_signal_init() — инициализация сигналов
proc_svcent_kill()        — kill процесса
```

**Сигналы для управления:**
- `SIGHUP` — reload конфигурации (ata, mg, sipcli и др.)
- `SIGQUIT` — graceful stop (ata, sipcli, ipp и др.)
- `SIGKILL` — force kill

---

## 20. Стартовые скрипты {#20-стартовые-скрипты}

### update — Обновление прошивки

```bash
#!/bin/sh
svcctl stop ipp; svcctl stop sipcli; svcctl stop mg
svcctl stop dhcpd; svcctl stop ata
sleep 2
killall -9 ipp sipcli mg dhcpd ata telnetd
cp /sbin/up /tmp
setsyscfg WD_TIMER=100
/tmp/up $1       # выполнение обновления
# При ошибке — перезапуск сервисов
# При успехе — перезагрузка
```

### start_ata — Запуск ATA

```bash
setsyscfg LINE1_GSM_OPER_C=0
setsyscfg LINE2_GSM_OPER_C=0
killall sipcli ipp smb_module
exec /usr/bin/ata
```

### start_ntp2 — NTP

```bash
exec /usr/sbin/ntp2 -h www.gontp.com -c 4 -i 1800
```

> DNS: `www.gontp.com` — кастомный NTP-сервер DBL Technology.

---

## 21. Общая карта IPC {#21-карта-ipc}

### Unix-сокеты

```
/tmp/.syscfg-server        ← svcd (syscfg server)
                            ↑ Все процессы читают/пишут конфигурацию
                            
/tmp/svcctl                ← svcd (service control)
                            ↑ start/stop/reload сервисов

/tmp/.fvdsp_cmd_in         ← fvdsp (DSP command input)
/tmp/.fvdsp_mgcmd%d        ← fvdsp (MG-specific commands)
/tmp/.fvdsp_data_in%d      ← fvdsp (audio data input)
/tmp/.fvdsp_data_out%d     → fvdsp (audio data output)

/tmp/mg%d                  ← mg (media gateway control)
                            ↑ ipp/sipcli управляют MG

/tmp/.ippui%d              ← ipp (UI control input)
/tmp/.ippui_cli%d          → ipp (UI client)

/tmp/.smb_cli%d            ← smb_module (SIM Bank CLI)
/tmp/.smb%d                ← smb_module (SIM data)

/tmp/.sysinfo.sock         ← sysinfo (diagnostics)
```

### Файловый IPC

```
/etc/ipin                  ← ep, gsmdb, sipdb, echocmd, rbm
                            ↑ Главный механизм IPC для ata
                            
/var/tmp/hosts             ← dnscli (resolved hosts)
/etc/resolv.conf           ← svcd (DNS config)
```

### Устройства

```
/dev/ttyS0..N              — UART к GSM-модемам
/dev/watchdog              — Watchdog timer
/dev/gpio0, /dev/gpio1     — GPIO (кнопки, LED)
/dev/audio                 — Аудио-устройство
/dev/mtd/7, /dev/mtdblock/5..7 — Flash-память
/dev/urandom               — Случайные числа
```

### Диаграмма взаимодействия

```
                    ┌──────────┐
                    │   svcd   │  ← PID manager, syscfg server
                    │ /sbin/   │
                    └────┬─────┘
                         │ /tmp/.syscfg-server, /tmp/svcctl
            ┌────────────┼────────────────────────┐
            │            │                        │
       ┌────▼───┐   ┌────▼────┐             ┌────▼────┐
       │  ata   │   │ipp/sip  │             │ rstdt   │
       │GSM ctrl│   │VoIP EP  │             │watchdog │
       └───┬────┘   └────┬────┘             └─────────┘
           │              │
    /etc/ipin        /tmp/mg%d
           │              │
       ┌───▼────┐   ┌────▼────┐
       │ fvdsp  │   │   mg    │
       │  DSP   │◄──│  RTP    │
       └────────┘   └─────────┘
     /tmp/.fvdsp_*

          ┌──────────┐  ┌──────────┐  ┌──────────┐
          │smb_module│  │smpp_smsc │  │ radmcli  │
          │SIM Bank  │  │SMS SMPP  │  │Remote Adm│
          └──────────┘  └──────────┘  └──────────┘
```

---

## 22. Захардкоженные адреса и учётные данные {#22-захардкоженные-данные}

### IP-адреса

| Адрес | Бинарный файл | Назначение |
|-------|---------------|------------|
| `202.96.136.145` | ipp, mg, smail, radmcli, rstdt, smb_module, smpp_smsc | **China Telecom DNS** — echo/NAT сервер |
| `61.141.247.7` | smail, radmcli, rstdt | **Bugreport SMTP** (Shenzhen) |
| `118.140.127.90` | radmcli | **RADM White-list #1** (Гонконг) |
| `47.242.142.229` | radmcli | **RADM White-list #2** (Alibaba Cloud HK) |
| `202.104.186.90` | radmcli | **RADM White-list #3** (Shenzhen Telecom) |

### Домены

| Домен | Бинарный файл | Назначение |
|-------|---------------|------------|
| `fspipsev.net` | smail, radmcli, rstdt | Bugreport SMTP-сервер |
| `www.gontp.com` | start_ntp2 | NTP-сервер DBL Technology |

### Учётные данные

| Элемент | Значение | Источник | Описание |
|---------|----------|----------|----------|
| RADM Key | `dbl#admin` | radmcli, start_radm | Дефолтный ключ удалённого администрирования |
| Email | `bug@fspipsev.net` | smail, radmcli | Email для bugreport-ов |
| RC4 suffix | `@dbl` | backup_config, restore_config | Суффикс ключа шифрования конфигурации |
| Root password | *(пустой)* | flash/etc/passwd | `root::0:0:root:/root:/bin/ash` |

### Порты

| Порт | Протокол | Назначение |
|------|----------|------------|
| 54210 | UDP | Echo/NAT сервер |
| 1920 | TCP | RADMIN (default) |
| 80 | TCP | HTTP Web UI (default) |
| 13000/23 | TCP | Telnet (FTN=0/1) |
| 1720 | TCP | H.323 Q.931 |
| 5060 | UDP | SIP |

---

## 23. Схема запуска системы {#23-схема-запуска}

### Последовательность загрузки

```
1. init (PID 1)
   └── /etc/init.d/rcS
       ├── mount proc, sysfs
       ├── mount jffs2 /dev/mtdblock/3 → /flash
       ├── mount ramfs → /var
       └── exec /etc/init.d/rc
           └── (загрузка конфигурации)

2. /sbin/network
   ├── ioctl -k ${CPU} /etc/init.d/df.b → /tmp/default.bound  (расшифровка DHCP)
   ├── ioctl -k ${CPU} /etc/init.d/lglm → /tmp/loginlimit     (расшифровка login limit)
   └── ioctl -k ${CPU} /etc/init.d/lg → /tmp/login             (расшифровка login)

3. svcd (service manager)
   ├── Загрузка /usr/etc/svc.conf
   ├── Загрузка конфигурации из MTD flash
   ├── Инициализация syscfg
   ├── Инициализация watchdog (/dev/watchdog, /dev/gpio0)
   └── Запуск сервисов в порядке зависимостей:
       ├── fvdsp      → start_fvdsp → /usr/bin/fvdsp
       ├── ata        → start_ata → /usr/bin/ata
       ├── mg         → start_mg → /usr/bin/mg
       ├── rstdt      → /usr/bin/rstdt
       ├── ntp2       → start_ntp2 → /usr/sbin/ntp2
       ├── imei_mon   → start_imeimon
       │
       │   (зависят от LAN_PORT_STATE=up)
       ├── sipcli     → start_sip → /usr/bin/sipcli    (если ENDPOINT_TYPE=SIP)
       ├── ipp        → start_ipp → /usr/bin/ipp        (если ENDPOINT_TYPE=H323)
       ├── ddnscli    → start_ddnscli → /usr/sbin/dnscli (если DDNS_ENABLE=1)
       ├── monwaddr   → start_waddrmon → /usr/sbin/mon_waddr
       ├── smb        → start_smb → /usr/bin/smb_module  (если RMSIM_ENABLE=1)
       ├── smpp       → /usr/bin/smpp_smsc               (если SMPP_ENABLE=1)
       ├── radm       → start_radm → /usr/bin/radmcli    (если RADMIN_ENABLE=1)
       └── pptp       → start_pptp                        (если PPTP_ENABLE=1)
```

### OEM-режимы (VENID)

Из списка `syscfg.default.*`:
- `dbl` — DBL Technology (производитель)
- `dble` — DBL Enterprise
- `pak` — Пакистан OEM (doodle-${SN})
- `et` / `et263` → HYBERTONE
- `A100`, `Bernie`, `CMS`, `EC`, `ipconnex`, `oxmundi`, `perse`, `speak2phone`, `VOIspeed-GSM`

---

## Итоговая сводка критических находок

### 1. Безопасность

| Уровень | Находка | Бинарный файл |
|---------|---------|---------------|
| 🔴 КРИТИЧЕСКИЙ | Пустой пароль root | passwd |
| 🔴 КРИТИЧЕСКИЙ | Дефолтный ключ RADM `dbl#admin` | radmcli |
| 🔴 КРИТИЧЕСКИЙ | 3 захардкоженных IP RADM-серверов (backdoor) | radmcli |
| 🟠 ВЫСОКИЙ | Шифрование конфигурации RC4 с суффиксом `@dbl` | decrypt.RC4 |
| 🟠 ВЫСОКИЙ | Системные файлы зашифрованы ключом CPU ID | ioctl |
| 🟡 СРЕДНИЙ | Bugreport-ы отправляются на `fspipsev.net` | smail, radmcli |
| 🟡 СРЕДНИЙ | NTP через кастомный сервер `www.gontp.com` | start_ntp2 |
| 🟡 СРЕДНИЙ | SMTP AUTH LOGIN (base64) без TLS | smail |

### 2. Архитектура IPC

| Механизм | Количество | Примеры |
|----------|-----------|---------|
| Unix Domain Sockets | ~15+ | syscfg-server, svcctl, fvdsp_*, mg*, ippui* |
| Файловый IPC | 2 | /etc/ipin, /var/tmp/hosts |
| GPIO/Device | 5+ | gpio0, gpio1, watchdog, ttyS*, audio |
| TCP сокеты | 3+ | SMPP, RADM, SIP/H.323 |
| Сигналы | SIGHUP/SIGQUIT/SIGKILL | Управление сервисами |

### 3. Общая библиотечная база

Все бинарные файлы используют общий фреймворк:
- `app.c` — обработка сигналов, отладка, общий цикл событий
- `net.c` — сетевые операции, TCP/UDP/Unix сокеты
- `sockaddr.c` — управление адресами
- `syscfg.c` — интерфейс с системной конфигурацией через Unix socket `/tmp/.syscfg-server`
- `utils.c` — аллокация памяти, утилиты

### 4. Ключевые переменные среды

| Переменная | Описание | Scope |
|-----------|----------|-------|
| `CPU` | ID процессора (ключ шифрования) | system |
| `SN` | Серийный номер устройства | global |
| `VENID` | Идентификатор OEM-вендора | global |
| `TELPORT` | Количество GSM-линий (до 8) | global |
| `AREA` | Регион (CHN для Китая) | global |
| `LANG` | Язык интерфейса | global |
| `FW_VER` | Версия прошивки | constant (8) |
| `ENDPOINT_TYPE` | SIP или H323 | runtime |
| `LAN_PORT_STATE` | up/down | runtime |

---

*Документ создан на основе статического анализа бинарных файлов прошивки GoIP GST1610*  
*Версия прошивки: GHSFVT-1 PATCH 1-68-11*  
*rversion: 202508011044*
