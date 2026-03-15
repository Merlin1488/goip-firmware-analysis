# GoIP GST1610 — Полная сводка глубокого анализа прошивки

**Версия прошивки:** GHSFVT-1.1-68-11  
**Платформа:** ARM 32-bit (ARMv5), SoC FV13xx (5VTechnologies / Rapid)  
**Ядро:** Linux 2.6.17  
**C-библиотека:** uClibc 0.9.29  
**Компилятор:** GCC 3.3.5 (Debian)  
**Дата анализа:** Июль 2025

---

## 1. Архитектура системы

```
┌────────────────────────────────────────────────────────────────────────────────┐
│                           GoIP GST1610 (16 GSM-каналов)                       │
│                                                                                │
│  ┌─────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐  ┌──────────────┐      │
│  │ sipcli  │  │   ata   │  │    mg    │  │  fvdsp   │  │  smb_module  │      │
│  │ 658 KB  │  │ 317 KB  │  │ 117 KB   │  │ 903 KB   │  │   68 KB      │      │
│  │ SIP B2B │  │ GSM Ctl │  │ RTP/Med  │  │ DSP HW   │  │ SIM Bank     │      │
│  └────┬────┘  └────┬────┘  └────┬─────┘  └────┬─────┘  └──────┬───────┘      │
│       │            │            │              │               │              │
│  ┌────┴────────────┴────────────┴──────────────┴───────────────┴────────┐     │
│  │              IPC: Unix DGRAM сокеты (/tmp/.*)                        │     │
│  │  .ippui%d  .smb%d  .fvdsp_mgcmd%d  .fvdsp_data_in/out%d  .dspcli%d │     │
│  └──────────────────────────────────────────────────────────────────────┘     │
│                                                                                │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐  ┌──────────┐       │
│  │ radmcli   │  │ smpp_smsc│  │   svcd   │  │   ipp   │  │   ep     │       │
│  │  51 KB    │  │  43 KB   │  │  91 KB   │  │  ~50 KB │  │  ~20 KB  │       │
│  │ Rev.Tunnel│  │ SMPP Svr │  │ Init Sys │  │ IVR/TUI │  │ GPIO Evt │       │
│  └───────────┘  └──────────┘  └──────────┘  └─────────┘  └──────────┘       │
│                                                                                │
│  ┌──────────────────────────── Kernel 2.6.17 ─────────────────────────┐       │
│  │  fvaci.ko   fvmac.ko   fvgpio.ko   fvspi.ko   fvmem.ko   wd.ko  │       │
│  │  (52KB)     (55KB)     (6.7KB)     (6.8KB)    (7.5KB)    (4.5KB) │       │
│  │  nfext.ko   fvipdef.ko  vtag.ko    fvnet.ko   fv_alg_*.ko       │       │
│  └────────────────────────────────────────────────────────────────────┘       │
│                                                                                │
│  ┌──────────── Hardware ──────────────────────────────────────────────┐       │
│  │  FV13xx SoC  │  Si3217x SLIC  │  16× GSM модемов  │  2× Ethernet │       │
│  │  DSP PL040   │  SPI Bus       │  UART /dev/ttyS*   │  Switch PHY  │       │
│  └──────────────┴────────────────┴────────────────────┴──────────────┘       │
└────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Компоненты — сводная таблица

| Бинарник | Размер | Роль | Ключевые функции |
|----------|--------|------|-----------------|
| **sipcli** | 658 KB | SIP UA/B2BUA | 370 функций, 8 методов шифрования, MD5, 116 state handlers |
| **ata** | 317 KB | GSM контроллер | 127 AT-команд, управление модемами, SIM, SMS, IMEI, IPC |
| **mg** | 117 KB | Media Gateway | RTP, 10 кодеков, RC4/ET263, STUN/Relay, джиттер-буфер |
| **fvdsp** | 903 KB | DSP демон | HSmedia v3.7, AMR-NB, T.38, G.711 HW, 22 набора тонов |
| **smb_module** | 68 KB | SIM Bank клиент | Magic 0x43215678, RC4, APDU forwarding, 16 каналов |
| **radmcli** | 51 KB | Обратный туннель | HTTP+Telnet проксирование, XOR шифрование |
| **smpp_smsc** | 43 KB | SMPP 3.4 сервер | SMS маршрутизация через GSM модемы |
| **svcd** | 91 KB | Init-система | 17 сервисов, svc.conf, watchdog |
| **ipp** | ~50 KB | IVR/TUI | Голосовые меню, DTMF навигация |
| **ep** | ~20 KB | Event Processor | GPIO события, кнопки, LED |
| **ioctl** | ~8 KB | Крипто-утилита | Шифрование файлов (RC4 с CPU ID) |

### Ядерные модули (31 шт.)

| Модуль | Размер | Категория | Назначение |
|--------|--------|-----------|------------|
| **fvaci.ko** | 52 KB | DSP/Аудио | ACI PL040, G.711, DTMF Гёрцель, Caller ID |
| **fvmac.ko** | 55 KB | Сеть | Ethernet MAC AMBA, 2 порта, switch PHY |
| **nfext.ko** | 35 KB | Firewall | NAT hairpin, cone NAT, CT strict |
| **vtag.ko** | 16 KB | VLAN | VLAN-тегирование для VoIP |
| **fvipdef.ko** | 10 KB | IDS | LAND/SYN Flood/Port Scan защита |
| **fvnet.ko** | 7 KB | Сеть | IP fastpath |
| **fvgpio.ko** | 7 KB | GPIO | LED, GSM-reset, SIM-detect |
| **fvspi.ko** | 7 KB | SPI | SPI-шина для SLIC |
| **fvmem.ko** | 8 KB | Memory | Прямой доступ к HW регистрам |
| **wd.ko** | 5 KB | Watchdog | Аппаратный watchdog |
| **fv_alg_*.ko** | 7 шт. | ALG | DNS, FTP, SIP, ESP, IPSec, L2TP, MSN |
| **fv_ipt_*.ko** | 3 шт. | iptables | localport, trigger, webstr |

---

## 3. Межпроцессное взаимодействие (IPC)

```
sipcli ←──── /tmp/.ippui%d ────→ ata
sipcli ←──── /tmp/.dspcli%d ───→ fvdsp (через mg)
ata    ←──── /tmp/.smb%d / .smb_cli%d ──→ smb_module
mg     ←──── /tmp/.fvdsp_mgcmd%d ──→ fvdsp
mg     ←──── /tmp/.fvdsp_data_in%d ──→ fvdsp (аудио TX)
fvdsp  ←──── /tmp/.fvdsp_data_out%d ──→ mg (аудио RX)
fvdsp  ────→ /tmp/.fvdsp_cmd_in ────→ mg (события)
все    ←──── /tmp/.syscfg-server ───→ syscfg (конфигурация)
radmcli ←── /etc/ramdcli (FIFO) ───→ ata
ata    ←──── UDP localhost ─────→ smpp_smsc
```

---

## 4. Критические уязвимости безопасности

### КРИТИЧЕСКИЕ

| # | Уязвимость | Компонент | Детали |
|---|-----------|-----------|--------|
| 1 | **Пустой пароль root** | flash/etc/passwd | `root::0:0:root:/:/bin/sh` |
| 2 | **Hardcoded ключ `dbl#admin`** | radmcli | Ключ шифрования обратного туннеля по умолчанию |
| 3 | **Hardcoded ключ `root#admin`** | ata (lic.c) | Ключ лицензионного сервера |
| 4 | **3 захардкоженных IP управления** | radmcli | 118.140.127.90, 47.242.142.229, 202.104.186.90 |
| 5 | **IMEI auto-change** | ata | AT+EGMR/AT+GTSET — автоматическая смена IMEI |
| 6 | **Обратный туннель без TLS** | radmcli | Полный доступ к HTTP+Telnet через проприетарное XOR |

### ВЫСОКИЕ

| # | Уязвимость | Компонент | Детали |
|---|-----------|-----------|--------|
| 7 | **SMTP телеметрия** | все бинарники | Отправка crash-данных на bug@fspipsev.net (61.141.247.7) |
| 8 | **Захардкоженный DNS** | все | 202.96.136.145 (China Telecom) |
| 9 | **RC4 шифрование** | mg, smb_module | Устаревший, небезопасный шифр |
| 10 | **STUN без HMAC** | mg | `hmac-not-implemented` — STUN аутентификация не работает |
| 11 | **AREA_LOCK** | ata | Привязка к операторам с захардкоженными MCC/MNC |
| 12 | **Пароли в CLI args** | mg, smpp_smsc | Видимы через /proc/cmdline |

### СРЕДНИЕ

| # | Уязвимость | Компонент |
|---|-----------|-----------|
| 13 | `eval` в start_radm (инъекция) | radmcli |
| 14 | sprintf/strcpy без проверки | все бинарники |
| 15 | ioctl — прямой доступ к HW | fvmem.ko |
| 16 | Бесконечный reconnect radmcli | radmcli |

---

## 5. Захардкоженные адреса и учётные данные

| Значение | Тип | Источник | Назначение |
|----------|-----|----------|------------|
| `61.141.247.7` | IP | все | SMTP баг-репорты (Шэньчжэнь) |
| `202.96.136.145` | IP | все | DNS/Echo сервер (China Telecom) |
| `192.168.2.1` | IP | ata | Лицензионный сервер |
| `118.140.127.90` | IP | radmcli | Управляющий сервер #1 (HK) |
| `47.242.142.229` | IP | radmcli | Управляющий сервер #2 (Alibaba HK) |
| `202.104.186.90` | IP | radmcli | Управляющий сервер #3 (Шэньчжэнь) |
| `fspipsev.net` | Домен | все | SMTP домен |
| `bug@fspipsev.net` | Email | все | Адрес баг-репортов |
| `dbl#admin` | Ключ | radmcli | Дефолтный ключ шифрования туннеля |
| `root#admin` | Ключ | ata | Ключ лицензионного сервера |
| `0x43215678` | Magic | smb_module | Маркер пакета SMB протокола |
| `:54210` | Порт | все | Echo-сервер (NAT traversal) |
| `:1920` | Порт | radmcli | RADMIN сервер по умолчанию |
| `:56011` | Порт | smb_module | SIM Bank (конфигурируемый) |

---

## 6. Шифрование

| Алгоритм | Бинарник | Назначение | Стойкость |
|----------|----------|------------|-----------|
| **RC4** | mg, smb_module, sipcli, ioctl | RTP, SIM Bank, конфигурация | Устаревший |
| **ET263** | mg, sipcli | RTP (4 типа: convert_8/16, parity_8/16) | Проприетарный |
| **XOR-like** | radmcli | Туннельный трафик | Слабый |
| **MD5** | sipcli | SIP Digest Auth, хеширование | OK для auth |
| **EOR (XOR)** | sipcli | 142 точки — обфускация строк | Слабый |
| **VOS2000** | mg | RTP шифрование | Проприетарный |
| **AVS** | mg | RTP для AVS-сервера | Проприетарный |
| **N2C** | sipcli | Шифрование N2C | Проприетарный |
| **FAST** | sipcli | Быстрое шифрование | Проприетарный |
| **ECM** | mg | ECM Crypt Key | Проприетарный |

---

## 7. Поддерживаемые GSM модемы

| Модем | Производитель | Особенности |
|-------|---------------|-------------|
| SIMCOM SIM800/900 | SIMCOM | Базовый |
| Quectel M25 | Quectel | 2G |
| Quectel M26 | Quectel | 2G |
| Quectel M35 | Quectel | 2G |
| Quectel EC20 | Quectel | 4G LTE |
| Gosuncn G610 | Gosuncn | AT+GTSET для IMEI |
| Huawei H330 | Huawei | 3G |
| ZTE MC8618 | ZTE | 3G |
| GTM900 | Option | 2G/3G |
| ME200 | — | — |

---

## 8. Протоколы

| Протокол | Компонент | Стандарт | Детали |
|----------|-----------|----------|--------|
| **SIP** | sipcli | RFC 3261 | UA + B2BUA, REGISTER/INVITE/BYE/REFER |
| **RTP/RTCP** | mg | RFC 3550 | UDP, симметричный, relay, STUN |
| **DTMF** | mg/fvdsp | RFC 2833 | + inband, SIP INFO |
| **T.38** | mg/fvdsp | ITU-T | Факс relay |
| **STUN** | mg | RFC 3489 | Без HMAC |
| **SMPP** | smpp_smsc | v3.4 | Сервер, DLR |
| **SMB** | smb_module | Проприетарный | Magic 0x43215678, RC4 |
| **RADMIN** | radmcli | Проприетарный | Обратный TCP туннель |
| **FVDSP** | mg↔fvdsp | Проприетарный | Unix DGRAM, текстовые команды |
| **syscfg** | все | Проприетарный | Unix DGRAM /tmp/.syscfg-server |
| **UDP IPC** | ata↔sipcli | Проприетарный | ATSTART/DIAL/SMS/LINESTATUS |
| **AT** | ata | 3GPP TS 27.007 | 127 команд, 10 категорий |

---

## 9. Полный список созданных документов анализа

| Файл | Строк | Предмет |
|------|-------|---------|
| `DOC_SIPCLI_DEEP_ANALYSIS.md` | ~1050 | SIP клиент — 370 функций, шифрование, state machine |
| `DOC_ATA_DEEP_ANALYSIS.md` | ~750 | GSM контроллер — 127 AT-команд, процессы, SIM |
| `DOC_MG_DEEP_ANALYSIS.md` | ~790 | Media Gateway — RTP pipeline, кодеки, NAT, шифрование |
| `DOC_FVDSP_DEEP_ANALYSIS.md` | ~800 | DSP демон — HSmedia, AMR, тоны, ACI |
| `DOC_RADMCLI_DEEP_ANALYSIS.md` | ~400 | Обратный туннель — протокол, hardcoded IPs, XOR |
| `DOC_SMB_MODULE_DEEP_ANALYSIS.md` | ~690 | SIM Bank — протокол 0x43215678, RC4, APDU |
| `DOC_SMPP_SMSC_DEEP_ANALYSIS.md` | ~400 | SMPP сервер — SMS маршрутизация |
| `DOC_MINOR_BINARIES_DEEP_ANALYSIS.md` | ~600 | ep, ipp, ioctl, svcd, smail, ddnscli, и др. |
| `DOC_KERNEL_MODULES_DEEP_ANALYSIS.md` | ~500 | 31 модуль .ko — fvaci, fvmac, GPIO, VLAN, IDS |
| **DOC_FIRMWARE_ANALYSIS_SUMMARY.md** | — | **Этот файл — общая сводка** |

---

## 10. Статистика анализа

- **Бинарников проанализировано:** 13 ELF executables + 22 shell-скрипта
- **Ядерных модулей:** 31 .ko
- **Строк извлечено:** >5000 уникальных
- **AT-команд каталогизировано:** 127
- **Функций идентифицировано:** >500
- **Исходных .c файлов реконструировано:** >50
- **Уязвимостей найдено:** 6 критических, 6 высоких, 4 средних
- **Захардкоженных IP/доменов:** 8
- **Методов шифрования:** 10
- **Поддерживаемых GSM модемов:** 10
- **IPC каналов:** ~15 Unix сокетов + FIFO + UDP

---

## 11. Вывод

GoIP GST1610 — сложное промышленное embedded-устройство с **крайне слабой безопасностью**:

1. **Архитектурно** — все демоны работают от root, без изоляции, с прямым доступом к hw
2. **Криптографически** — только проприетарные/устаревшие алгоритмы (RC4, XOR, ET263), нет TLS
3. **Бэкдоры** — предустановленный обратный туннель (`radmcli`) с захардкоженными серверами в Китае
4. **Телеметрия** — все бинарники отправляют crash-данные на fspipsev.net (DBLTek)
5. **IMEI spoofing** — встроенная возможность автоматической смены IMEI
6. **Root без пароля** — прямой доступ через telnet/SSH

Устройство предназначено для VoIP-телефонии (SIP↔GSM шлюз) с поддержкой SIM Bank, SMPP SMS-маршрутизации и удалённого администрирования. Весь софт написан на C (GCC 3.3.5) без каких-либо современных практик безопасности.
