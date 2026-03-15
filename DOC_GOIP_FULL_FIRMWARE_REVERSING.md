# GoIP GST1610 — ПОЛНЫЙ РЕВЕРС-ИНЖИНИРИНГ ПРОШИВКИ

> **Прошивка:** GHSFVT-1.1-68-11 (GoIP-16 / GST1610)  
> **Производитель:** DBLTek / HYBERTONE Technology Co., Ltd. (Шэньчжэнь, Китай)  
> **Платформа:** ARM926EJ-S (ARMv5TEJ), SoC FV13xx (5VTechnologies / Rapid)  
> **ОС:** Linux 2.6.17, uClibc 0.9.29, BusyBox  
> **Компилятор:** GCC 3.3.2 / 3.3.5 (Debian prerelease)  
> **Дата анализа:** 2025  
> **Методы:** Статический анализ (strings, readelf, xxd, objdump), анализ конфигов, скриптов, hex-дампов

---

## СОДЕРЖАНИЕ

1. [Архитектура системы](#1-архитектура-системы)
2. [Аппаратная платформа](#2-аппаратная-платформа)
3. [Загрузка и инициализация](#3-загрузка-и-инициализация)
4. [Карта Flash-памяти (MTD)](#4-карта-flash-памяти-mtd)
5. [Файловая система](#5-файловая-система)
6. [Конфигурационная система (syscfg)](#6-конфигурационная-система-syscfg)
7. [Полное описание всех бинарников](#7-полное-описание-всех-бинарников)
   - 7.1 [ata — GSM-контроллер](#71-ata--gsm-контроллер-317-kb)
   - 7.2 [sipcli — SIP B2BUA](#72-sipcli--sip-b2bua-658-kb)
   - 7.3 [mg — Media Gateway](#73-mg--media-gateway-117-kb)
   - 7.4 [fvdsp — DSP-демон](#74-fvdsp--dsp-демон-903-kb)
   - 7.5 [ipp — H.323 Endpoint](#75-ipp--h323-endpoint-540-kb)
   - 7.6 [smb_module — SIM Bank клиент](#76-smb_module--sim-bank-клиент-68-kb)
   - 7.7 [radmcli — Remote Admin](#77-radmcli--remote-admin-туннель-51-kb)
   - 7.8 [smpp_smsc — SMS-центр](#78-smpp_smsc--smpp-sms-центр-43-kb)
   - 7.9 [smail — SMTP-клиент](#79-smail--smtp-клиент-47-kb)
   - 7.10 [svcd — Service Controller](#710-svcd--service-controller-91-kb)
   - 7.11 [httpd — Веб-сервер](#711-httpd--веб-сервер-71-kb)
   - 7.12 [up — Firmware Updater](#712-up--firmware-updater-120-kb)
   - 7.13 [rstdt — Watchdog/Reset](#713-rstdt--watchdogreset-daemon-43-kb)
   - 7.14 [pppoecd — PPPoE-клиент](#714-pppoecd--pppoe-клиент-85-kb)
   - 7.15 [dnscli — DDNS-клиент](#715-dnscli--ddns-клиент-43-kb)
   - 7.16 [Утилиты шифрования](#716-утилиты-шифрования)
   - 7.17 [Малые бинарники и скрипты](#717-малые-бинарники-и-скрипты)
8. [Модули ядра (.ko)](#8-модули-ядра-ko)
9. [Полный справочник AT-команд](#9-полный-справочник-at-команд)
10. [Коммуникации между процессами (IPC)](#10-коммуникации-между-процессами-ipc)
11. [Потоки данных](#11-потоки-данных)
12. [Криптография и шифрование](#12-криптография-и-шифрование)
13. [Конфигурационные файлы (.def)](#13-конфигурационные-файлы-def)
14. [Стартовые скрипты](#14-стартовые-скрипты)
15. [Поддерживаемые протоколы](#15-поддерживаемые-протоколы)
16. [Аудио и кодеки](#16-аудио-и-кодеки)
17. [GSM-модули и модемы](#17-gsm-модули-и-модемы)
18. [SIM-менеджмент](#18-sim-менеджмент)
19. [IMEI-менеджмент](#19-imei-менеджмент)
20. [Система лицензирования](#20-система-лицензирования)
21. [OEM-варианты (VENID)](#21-oem-варианты-venid)
22. [Захардкоженные учётные данные](#22-захардкоженные-учётные-данные)
23. [Захардкоженные IP-адреса и домены](#23-захардкоженные-ip-адреса-и-домены)
24. [Уязвимости и backdoor](#24-уязвимости-и-backdoor)
25. [Полная карта IPC-сокетов и файлов](#25-полная-карта-ipc-сокетов-и-файлов)
26. [Телеметрия производителя](#26-телеметрия-производителя)
27. [Anti-fraud система](#27-anti-fraud-система)
28. [SMS-подсистема](#28-sms-подсистема)
29. [CDR — учёт вызовов](#29-cdr--учёт-вызовов)
30. [Полный список Syscfg-ключей](#30-полный-список-syscfg-ключей)
31. [Статистика прошивки](#31-статистика-прошивки)

---

## 1. АРХИТЕКТУРА СИСТЕМЫ

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        GoIP GST1610 — System Architecture              │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────────────────┐ │
│  │  sipcli  │   │   ipp    │   │  httpd   │   │      radmcli        │ │
│  │ SIP B2BUA│   │ H.323 EP │   │ Web UI   │   │ Reverse Admin Tunnel│ │
│  │  658 KB  │   │  540 KB  │   │  71 KB   │   │      51 KB         │ │
│  └────┬─────┘   └────┬─────┘   └────┬─────┘   └──────────┬──────────┘ │
│       │              │              │                     │            │
│       │    ┌─────────┴──────────────┼─────────────────────┘            │
│       │    │                        │                                  │
│  ┌────┴────┴────┐          ┌────────┴────────┐                        │
│  │     mg       │          │      svcd       │                        │
│  │ Media Gateway│          │ Service Control │                        │
│  │   117 KB     │          │    91 KB        │                        │
│  └──────┬───────┘          └────────┬────────┘                        │
│         │                           │                                  │
│  ┌──────┴───────┐          ┌────────┴────────┐                        │
│  │    fvdsp     │          │      ata        │◄── ЦЕНТРАЛЬНЫЙ ДЕМОН   │
│  │  DSP Daemon  │          │ GSM Controller  │                        │
│  │   903 KB     │          │    317 KB       │                        │
│  └──────┬───────┘          └───┬──────┬──────┘                        │
│         │                      │      │                                │
│  ┌──────┴───────┐    ┌────────┴┐  ┌──┴─────────┐  ┌────────────────┐ │
│  │  fvaci.ko    │    │smb_module│  │ smpp_smsc  │  │    smail      │ │
│  │  DSP HW      │    │ SIM Bank │  │  SMS SMPP  │  │  SMTP Client  │ │
│  │   52 KB      │    │  68 KB   │  │   43 KB    │  │    47 KB      │ │
│  └──────────────┘    └──────────┘  └────────────┘  └────────────────┘ │
│                                                                         │
│  ┌──────────────────────────────────────────────────────────────┐      │
│  │                    HARDWARE LAYER                            │      │
│  │  8× GSM Modem (Quectel M25/EC20/GTM900/SIMCOM/H330/ME200)  │      │
│  │  FV13xx SoC → fvaci.ko (ACI PL040 DSP) + fvmac.ko (2× ETH) │      │
│  │  Si3217x ProSLIC (FXS, если поддерживается)                 │      │
│  │  SPI Flash (MTD 0-7) + GPIO (LED, кнопки, питание модемов)  │      │
│  │  2× Ethernet (WAN + LAN), UART ×8 к модемам                │      │
│  └──────────────────────────────────────────────────────────────┘      │
└─────────────────────────────────────────────────────────────────────────┘
```

### Взаимодействие компонентов

```
Входящий VoIP вызов:
  SIP INVITE → sipcli → /tmp/mg0 → mg → /tmp/.fvdsp_data_in0 → fvdsp → fvaci.ko → HW DSP
                  ↓
              /etc/ipin → ata → AT commands → /dev/ttyS* → GSM Modem → GSM Network

Входящий GSM вызов:
  GSM RING → /dev/ttyS* → ata → /etc/ipin → sipcli → SIP INVITE → VoIP
                                     ↓
                                 /tmp/mg0 → mg → RTP ←→ Remote Endpoint

SMS Gateway:
  UDP(:5000) → ata(smsudps.c) → AT+CMGS → GSM Modem → Оператор
  GSM SMS → +CMT → ata(pdu.c) → smail → SMTP → Email
  SMPP SUBMIT → smpp_smsc → /etc/ipin → ata → AT+CMGS → GSM

SIM Bank:
  smb_module ←TCP→ SIM Bank Server ←→ Physical SIM Cards
       ↓ /tmp/.smb0
      ata → AT+SIMDATA → GSM Modem (Remote SIM mode)

Remote Admin:
  radmcli → TCP → RADMIN_SERVER:1920 → Reverse tunnel
       ↓ local proxy
  127.0.0.1:80 (httpd) / 127.0.0.1:13000 (telnet)
```

---

## 2. АППАРАТНАЯ ПЛАТФОРМА

| Компонент | Детали |
|-----------|--------|
| **SoC** | FV13xx (5VTechnologies / Rapid) — ARM926EJ-S core |
| **Архитектура** | ARMv5TEJ, Little Endian, 32-bit |
| **Идентификатор** | `5VT1610` |
| **DSP** | ACI PL040 — встроенный DSP через MMIO |
| **SLIC** | Silicon Labs Si3217x ProSLIC (FXS порты) |
| **Ethernet** | 2 порта (WAN + LAN) через fvmac.ko (AMBA bus) |
| **GSM модули** | 8× Quectel M25 (основной), поддержка EC20/GTM900/SIMCOM/H330/ME200 |
| **Flash** | SPI NOR Flash, 8+ MTD-разделов |
| **GPIO** | /dev/gpio0, /dev/gpio1 — LED, кнопки, питание модемов, SIM detect |
| **UART** | 8× /dev/ttyS* — к GSM-модемам |
| **Watchdog** | /dev/watchdog — аппаратный WDT |
| **SPI** | /dev/spi* — интерфейс к SLIC и другим периферийным |
| **Аудио** | /dev/audio, /dev/snd* — PCM/аудио-интерфейс |
| **CPU ID** | Уникальный серийный номер процессора (используется как ключ RC4) |

### MMIO-регистры DSP

| Базовый адрес | Назначение |
|---------------|-----------|
| `0x10` | ACI Control Register Base |
| `0x14` | ACI Data Register Base |
| `0x18` | ACI Status Register Base |
| `0x1C` | ACI Config Register Base |

### Device Files

| Устройство | Назначение |
|-----------|-----------|
| `/dev/aci%d` | ACI DSP hardware (через fvaci.ko) |
| `/dev/slic%d` | ProSLIC interface |
| `/dev/spi%d` | SPI bus |
| `/dev/snd%d` | Sound/PCM device |
| `/dev/fvmem` | Direct HW register access (mmap) |
| `/dev/daa0` | Data Access Arrangement (FXO) |
| `/dev/gpio0`, `/dev/gpio1` | GPIO controllers |
| `/dev/ttyS0`..`/dev/ttyS7` | UART к GSM-модемам |
| `/dev/watchdog` | Hardware watchdog timer |
| `/dev/audio` | Audio device |
| `/dev/mtd/7` | MTD character device (flash) |
| `/dev/mtdblock/3..7` | MTD block devices |
| `/dev/urandom` | Random number generator |

---

## 3. ЗАГРУЗКА И ИНИЦИАЛИЗАЦИЯ

### Последовательность загрузки

```
1. U-Boot → загрузка ядра Linux 2.6.17 из Flash
2. Ядро → mount rootfs (SquashFS из MTD)
3. /sbin/init (BusyBox) → читает /etc/inittab
4. /etc/init.d/rcS → начальные скрипты
   ├── mount /proc, /sys, /tmp (tmpfs)
   ├── /sbin/hwinfo -r hwinfo → чтение аппаратных данных
   ├── mount /dev/mtdblock/3 /flash (jffs2 — persistent storage)
   ├── ioctl -k ${CPU} /etc/init.d/df.b /tmp/default.bound → расшифровка boot-данных
   ├── ioctl -k ${CPU} /etc/init.d/lglm /tmp/loginlimit → расшифровка лимитов
   ├── ioctl -k ${CPU} /etc/init.d/lg /tmp/login → расшифровка данных логина
   ├── /sbin/network → настройка сети (WAN, LAN, VLAN)
   └── запуск svcd
5. svcd (Service Control Daemon) → читает /etc/svc.conf
   ├── Загружает syscfg из /dev/mtdblock/5
   ├── Загружает hwinfo из /dev/mtdblock/6
   ├── Загружает .def/.default/.constant файлы
   ├── Запускает сервисы в порядке зависимостей:
   │   ├── fvdsp (DSP daemon)
   │   ├── ata (GSM controller) — ПЕРВЫЙ, критический
   │   ├── sipcli ИЛИ ipp (SIP или H.323)
   │   ├── mg (Media Gateway)
   │   ├── httpd (Web server)
   │   ├── rstdt (Watchdog/Reset)
   │   ├── smb_module (SIM Bank, если REMOTE_SIM=1)
   │   ├── radmcli (Remote Admin, если RADMIN_ENABLE=1)
   │   ├── smpp_smsc (если SMPP_ENABLE=1)
   │   ├── ddnscli (если DDNS_ENABLE=1)
   │   ├── start_ntp2 (NTP)
   │   ├── start_httpd (Web UI)
   │   ├── start_imeimon (IMEI monitor)
   │   ├── start_waddrmon (WAN address monitor)
   │   └── start_sip_port_change (SIP port randomization)
   └── Мониторинг сервисов (респавн при падении)
```

### Расшифровка boot-файлов

При загрузке система расшифровывает 3 файла с помощью **`ioctl` (утилита RC4-шифрования)**:

| Зашифрованный | Расшифрованный | Назначение |
|---------------|---------------|-----------|
| `/etc/init.d/df.b` | `/tmp/default.bound` | Границы конфигурации по умолчанию |
| `/etc/init.d/lglm` | `/tmp/loginlimit` | Лимиты количества логинов |
| `/etc/init.d/lg` | `/tmp/login` | Данные аутентификации |

**Ключ шифрования** = `${CPU}` + `@dbl` — CPU serial number процессора с суффиксом `@dbl` (DBL Technology).

---

## 4. КАРТА FLASH-ПАМЯТИ (MTD)

| MTD | Тип | Mount Point | Назначение |
|-----|-----|-------------|-----------|
| 0 | — | — | U-Boot bootloader |
| 1 | — | — | U-Boot environment |
| 2 | SquashFS | / (root) | Основная файловая система (RO) |
| 3 | JFFS2 | /flash | Persistent storage (RW) |
| 4 | — | — | Kernel image |
| 5 | Raw | — | syscfg (основная конфигурация) |
| 6 | Raw | — | hwinfo registry (MAC, SN, HW version) |
| 7 | Raw | — | syscfg2 (SMS хранение, вторичная конфиг) |

### Чтение/запись MTD

- **svcd** читает/пишет конфигурацию в mtdblock/5 и mtdblock/7
- **hwinfo** (`/sbin/hwinfo`) управляет mtdblock/6
- **unimac** читает MAC из mtdblock/7 с магическим маркером `QZ^&` (0x515A5E26)
- **httpd** записывает SMS в mtdblock/7
- **up** (firmware updater) пишет прошивку напрямую в MTD

---

## 5. ФАЙЛОВАЯ СИСТЕМА

### SquashFS (Read-Only Root)

```
/
├── bin/
│   ├── busybox          (155 KB — основа всех утилит)
│   ├── sh               (73 KB — отдельный ash shell)
│   ├── udhcpc           (32 KB — DHCP клиент)
│   └── udhcpd           (32 KB — DHCP сервер)
├── dev/                 (device nodes)
├── etc/
│   ├── init.d/
│   │   ├── rcS          (init script)
│   │   ├── df.b         (зашифрованный: default.bound)
│   │   ├── lglm         (зашифрованный: loginlimit)
│   │   └── lg           (зашифрованный: login)
│   ├── inittab
│   ├── passwd           (root::0:0:root:/root:/bin/ash — ПУСТОЙ ПАРОЛЬ!)
│   ├── svc.conf         (конфигурация сервисов)
│   └── syscfg.def       (определения системной конфигурации)
├── flash/               (mount point для JFFS2 — persistent)
│   └── etc/
│       └── passwd       (root::0:0... — ТОЖЕ ПУСТОЙ ПАРОЛЬ)
├── lib/
│   ├── ld-uClibc.so.0   (динамический линкер)
│   ├── libc.so.0        (uClibc 0.9.29)
│   ├── libgcc_s.so.1    (GCC support)
│   └── modules/         (31 .ko файл)
├── proc/                (procfs)
├── sbin/
│   ├── svcd             (91 KB — service controller)
│   ├── up               (120 KB — firmware updater)
│   ├── hwinfo           (11 KB — HW info manager)
│   ├── init             (13 KB — init process)
│   ├── ntp              (51 KB — NTP client)
│   ├── sysinfod         (7 KB — system info daemon)
│   └── network          (shell script — network setup)
├── sys/                 (sysfs)
├── tmp/                 (tmpfs — runtime data)
├── usr/
│   ├── au/              (IVR аудиофайлы: enter.au, passwd.au, etc.)
│   ├── bin/             (38 файлов — основные демоны)
│   │   ├── ata          (317 KB)
│   │   ├── sipcli       (658 KB)
│   │   ├── mg           (117 KB)
│   │   ├── fvdsp        (903 KB)
│   │   ├── ipp          (540 KB)
│   │   ├── smb_module   (68 KB)
│   │   ├── radmcli      (51 KB)
│   │   ├── smpp_smsc    (43 KB)
│   │   ├── smail        (47 KB)
│   │   ├── decrypt.RC4  (6 KB)
│   │   ├── ioctl        (6 KB)
│   │   ├── pppmon       (14 KB)
│   │   ├── rstdt        (43 KB)
│   │   ├── unimac       (7 KB)
│   │   ├── getipbyname  (6 KB)
│   │   ├── echocmd      (38 B — shell)
│   │   ├── getuptime    (47 B — shell)
│   │   ├── gsmdb        (40 B — shell)
│   │   ├── ep           (31 B — shell)
│   │   ├── l1_set_oper  (1 KB — shell)
│   │   ├── update       (768 B — shell)
│   │   ├── backup_config (200 B — shell)
│   │   ├── restore_config (191 B — shell)
│   │   └── start_*/stop_* (15 стартовых скриптов)
│   ├── etc/
│   │   ├── syscfg/      (8 .def файлов)
│   │   ├── VERSION      (версия прошивки)
│   │   ├── PATCH        (номер патча)
│   │   ├── ca-cert.pem  (CA-сертификат для HTTPS)
│   │   └── syscfg.default.* (дефолты по VENID)
│   ├── sbin/
│   │   ├── httpd        (71 KB — веб-сервер)
│   │   ├── dnscli       (43 KB — DDNS клиент)
│   │   ├── pppoecd      (85 KB — PPPoE клиент)
│   │   ├── mon_waddr    (39 KB — WAN monitor)
│   │   ├── brctl        (22 KB — bridge utils)
│   │   ├── ping2        (10 KB — ICMP ping)
│   │   └── sysinfo      (4 KB — sysinfo client)
│   └── share/
│       └── httpd/       (Web UI файлы по VENID/LANG)
└── var/ → /tmp          (symlink)
```

---

## 6. КОНФИГУРАЦИОННАЯ СИСТЕМА (syscfg)

### Архитектура

```
                    ┌──────────────┐
                    │    svcd      │
                    │  91 KB ELF   │
                    │              │
                    │ ┌──────────┐ │
                    │ │ In-Memory│ │
   setsyscfg ──────►│ │  Hash    │ │◄── getsyscfg
   (shell)         │ │  Table   │ │     (shell)
                    │ └─────┬────┘ │
                    │       │      │
                    │       ▼      │
                    │  MTD block/5 │ ← persistent storage
                    │  MTD block/6 │ ← hwinfo
                    │  MTD block/7 │ ← secondary
                    └──────┬───────┘
                           │
              Unix DGRAM Socket
          /tmp/.syscfg-server
                           │
     ┌─────────┬───────────┼───────────┬──────────┐
     │         │           │           │          │
   ata     sipcli        mg        httpd      smb_module
   (client)  (client)   (client)   (client)   (client)
```

### Протокол syscfg

Текстовый протокол через Unix DGRAM socket:

| Команда | Формат | Описание |
|---------|--------|----------|
| SET | `KEY=VALUE` | Установить значение |
| GET | `KEY` | Получить значение |
| LIST | `%list` | Список всех ключей |
| APPLY | `apply` | Применить изменения |
| SAVE | `save` | Сохранить в Flash |
| RESET | `reset` | Сброс к умолчаниям |
| RELOAD | `reload` | Перечитать из Flash |

### Файлы определений

| Файл | Расположение | Ключей | Описание |
|------|-------------|--------|----------|
| `ata.def` | `/usr/etc/syscfg/` | ~260 | GSM-состояние, SIM, SMS, CDR, IMEI, BST |
| `sip.def` | `/usr/etc/syscfg/` | ~120 | SIP-регистрация, прокси, шифрование |
| `h323.def` | `/usr/etc/syscfg/` | ~140 | H.323, GK, H.235, группы |
| `common.def` | `/usr/etc/syscfg/` | ~85 | Кодеки, RTP, NAT, PPTP, STUN |
| `user.def` | `/usr/etc/syscfg/` | ~60 | Пароли, NTP, DDNS, autocfg |
| `smb.def` | `/usr/etc/syscfg/` | 7 | SIM Bank |
| `smpp.def` | `/usr/etc/syscfg/` | 6 | SMPP SMS |
| `fvdsp.def` | `/usr/etc/syscfg/` | 17 | DSP громкость |
| **ИТОГО** | — | **~695** | — |

---

## 7. ПОЛНОЕ ОПИСАНИЕ ВСЕХ БИНАРНИКОВ

---

### 7.1 ata — GSM-контроллер (317 KB)

**Центральный демон всей системы.** Управляет 8 GSM-модемами, маршрутизирует вызовы, обрабатывает SMS, управляет SIM-картами.

| Параметр | Значение |
|----------|----------|
| **Размер** | 317 060 байт |
| **Тип** | ELF 32-bit LSB, ARM, dynamically linked, stripped |
| **Секция .text** | 241 KB (основной код) |
| **Секция .rodata** | 63 KB (строки, таблицы) |
| **Секция .bss** | 34 KB (состояние каналов: 8×~4KB) |
| **Секция .data** | 3 KB (GB2312↔UCS2 таблица) |
| **PLT imports** | 109 функций |
| **Строк** | 2309 |
| **Исходных .c файлов** | ≥25 |

#### Исходные файлы

| Файл | Назначение |
|------|-----------|
| `main.c` | Точка входа, инициализация каналов, SIM-детектирование |
| `atcmd.c` | AT-команды к модемам через UART |
| `audio.c` | DSP-управление (тоны, IVR, DTMF) |
| `auto_reload.c` | Автоперезагрузка по расписанию |
| `auto_sms_ussd.c` | Автоматическая отправка SMS/USSD |
| `basest.c` | Управление базовыми станциями (BST/BCCH lock) |
| `callback.c` | Callback-вызовы, PDIAL |
| `cdr.c` | Call Detail Records |
| `cli.c` | Клиент группового режима |
| `console.c` | UART `/dev/ttyS*` — консоль GSM-модулей |
| `dial_plan.c` | Dial plan / digit map |
| `fxo.c` | Основная FXO-логика |
| `fxo_state.c` | Конечный автомат FXO |
| `fxo_utils.c` | Утилиты (socket write, kill) |
| `gpio.c` | GPIO — питание модулей, LED |
| `gsm.c` | GSM: инициализация, AT-команды, состояния |
| `gb2312toucs2.c` | GB2312 → UCS2 (китайские SMS) |
| `lic.c` | Система лицензирования |
| `longsms.c` | Конкатенированные SMS |
| `machine_limit.c` | Ограничения по времени работы |
| `net.c` | TCP/UDP/UNIX сокеты, маршрутизация |
| `netsrv_atcmd.c` | Сетевой AT-командный сервер |
| `partner.c` | Партнёрский режим |
| `pdu.c` | PDU-кодирование/декодирование SMS |
| `remote_ctl.c` | Удалённое управление каналами |
| `sim_exp.c` | SIM expiry management |
| `smb_exp.c` | SIM Bank expiry |
| `sms_limit.c` | SMS-лимиты |
| `smsudps.c` | SMS UDP-сервер |
| `smsc.c` | SMPP-подключение к SMSC |
| `sockaddr.c` | syscfg через UNIX-сокеты |
| `svr.c` | Серверная часть группового режима |
| `uimsg.c` | UI-сообщения |
| `app.c` | Фреймворк, event loop, сигналы |

#### GSM State Machine

```
                          PowerDown
                              ↑
GSM DOWN ──→ GSM INIT ──→ GSM IDLE ──→ GSM DIALING
    ↑                         │              │
    │                    GSMRinging      GSMAlerting
    │                         │              │
    │                    GSMIncoming    GSMOutCall
    │                         │              │
    │                    GSMAnswer     WaitingAnswer
    │                         │              │
    │                    GSM IN CALL ◄───────┘
    │                    │    │    │
    │               GSMHeld  │  GSMCWaiting
    │                         │
    │              GSMDropCall / NoCarrier / NoAnswer
    │                         │
    └─────────────────── GSM IDLE
```

**FXO State Machine:**
```
FXO IDLE → FXO DIAL → FXO CALLING → FXO WAITING ANSWER → FXO IN CALL
    ↑         ↑                                               │
    │    STAR CMD     PSTN AUTH / PSTN CALLBACK               │
    │    AUTO DIAL    VOIP AUTH / CALL WAITING                 │
    └─────────────── FXO LOGOUT ◄─────────────────────────────┘
```

#### IPC-статусы (sipcli/ipp → ata)

| Статус | Описание |
|--------|----------|
| `IPPINFO_IDLE` | Канал свободен |
| `IPPINFO_DL_TONE` | Dial tone |
| `IPPINFO_WT_TONE` | Wait tone |
| `IPPINFO_BZ_TONE` | Busy tone |
| `IPPINFO_RG` | Ringing |
| `IPPINFO_SS` | Setup |
| `IPPINFO_HD` | Hook down (off-hook) |
| `IPPINFO_HU` | Hook up (on-hook) |
| `IPPINFO_CNT` | Connected |
| `IPPINFO_DIAL` | Dialing |
| `IPPINFO_CI` | Caller ID |
| `IPPINFO_CSTATE` | Call state change |
| `IPPINFO_RSIP` | Re-INVITE/SIP |
| `IPPINFO_MUSIC` | Music on hold |
| `IPPINFO_SCRI` | Script/IVR |

#### Disconnect Причины (Q.931)

| Код | Строка | Syscfg ключ |
|-----|--------|-------------|
| Unassigned | `UnasNUM` | `UnasNUM_C` |
| No route | `NoRoute` | `NoRoute_C` |
| Channel unacceptable | `CHunacpt` | `CHunacpt_C` |
| Operator barring | `OPDTbarring` | `OPDTbarring_C` |
| Busy | `Busy` | `BUSY_C` |
| No response | `NoUserRsp` | `NoUserRsp_C` |
| No answer | `NoAnswer` | `NoAnswer_C` |
| Rejected | `CallRJ` | `CallRJ_C` |
| Number changed | `NUMChanged` | `NUMChanged_C` |
| Dest out of order | `DSTOOrder` | `DSTOOrder_C` |
| Invalid number | `INVNUM` | `INVNUM_C` |
| Network out | `NETOOrder` | `NETOOrder_C` |
| Temp failure | `TMPF` | `TMPF_C` |

#### Аудио-управление (через DSP)

Команды к fvdsp через `/tmp/.fvdsp_cmd_in`:
- `open %d` / `close %d` — открытие/закрытие DSP-канала
- `gen_tone` — генерация сервисных тонов
- `play %d %c.au` — IVR-файлы (enter, passwd, wrong_pw, login_fail)
- `play %d stop` / `play %d dot.au` — управление воспроизведением
- `dsp_play_digit` — DTMF-генерация
- `dsp_stop_music` — остановка фоновой музыки

IVR-файлы (`/usr/au/`): `enter.au`, `passwd.au`, `wrong_pw.au`, `login_fail.au` + локализации `*.zh_CN`

---

### 7.2 sipcli — SIP B2BUA (658 KB)

**Крупнейший по размеру кода бинарник.** SIP Back-to-Back User Agent на базе GNU oSIP (статически слинкован).

| Параметр | Значение |
|----------|----------|
| **Размер** | 658 KB |
| **PLT imports** | 99 функций |
| **Функций** | 370+ (по анализу control flow) |
| **State handlers** | 116 SIP-обработчиков состояний |
| **Строк** | 1450+ |
| **Крипто-методов** | 8 |
| **ARM EOR инструкций** | 142 (inline XOR obfuscation) |
| **Исходных файлов** | ~15 (.c) |

#### SIP-библиотека: GNU oSIP (статически слинкован)

| Модуль | Функции |
|--------|---------|
| `osip_message` | Парсинг SIP-сообщений |
| `osip_dialog` | Управление диалогами |
| `osip_transaction` | INVITE/non-INVITE транзакции |
| `osip_negotiation` | SDP-переговоры |
| `osip_md5` | MD5 Digest Auth (реализация в .text, ~500 байт @ 0x02D010) |
| `sdp_message` | SDP parsing/building |

#### Операционные режимы

1. **SINGLE_MODE** — простой SIP-клиент (один аккаунт на все линии)
2. **LINE_MODE** — по линии (до 8 отдельных SIP-регистраций)
3. **GROUP_MODE** — группы линий (до 8 групп × 8 линий)
4. **TRUNK_GW_MODE** — транк-шлюз (3 trunk gateway + routing)

#### CLI-параметры sipcli

| Параметр | Описание |
|----------|----------|
| `--gateway 1` | Режим шлюза |
| `--line-prefix N` | Префикс линии |
| `--syscfg` | Читать конфиг из syscfg |
| `--nowait` | Не ждать при старте |
| `--noalive` | Без keepalive |
| `--ptime N` | Packetization period |
| `--dtmf N` | DTMF payload type |
| `--obddtmf N` | Outband DTMF type |
| `--mode N` | Operation mode |
| `--rereg-inval N` | Re-register interval при ошибке |
| `--pkey` | Pound key as digit |
| `--vrb` | Virtual ringback tone |
| `--mwi N` | Message Waiting Indicator |
| `--reg-mode N` | Registration mode |
| `--exp-mode N` | Expiry mode |
| `--link-test` | Link test enabled |
| `--cid-fw-mode N` | Caller ID forward mode |
| `--early-media N` | 183 Early Media (1=mode1, 2=mode2) |
| `--inv-auth N` | INVITE auth mode |
| `--proxy-mode` | SIP proxy mode |
| `--proxy-passwd P` | Proxy password |
| `--prefix-del 1` | Delete prefix |
| `--dialler-cmp 1` | Dialler compatibility |
| `--sip-rsp-mode 1` | SIP response mode |
| `--callee-mode 1` | Callee mode |
| `--sms-tonum` | SMS return to number |
| `--trunk-gw A,B,C` | Trunk gateways |
| `--lport N` | Local SIP port |
| `--random-port N` | Random local port |
| `--wan-addr A` | WAN address (NAT) |
| `--nat-fw` | NAT firewall mode |
| `--agent UA` | User-Agent string |
| `--backup_svr` | Use backup server |

#### Шифрование SIP/RTP

| Параметр | Флаг | Описание |
|----------|------|----------|
| `--rc4-crypt --rc4-key KEY` | RC4 | Stream cipher |
| `--fast-crypt` | FAST | Session-based |
| `--vos-crypt` | VOS | VOS2000 proprietary |
| `--avs-crypt` | AVS | TKPT_DeSecret |
| `--n2c-crypt` | N2C | Mapping cipher |
| `--ecm-crypt` | ECM | Proprietary (key: voippassword) |
| `--et263-crypt --et263-crypt-type T --et263-crypt-dep D` | ET263 | Proprietary (4 функции) |

#### SIP Anti-spam

Жёстко прошитые фильтры User-Agent:
- Блокировка `RTC/1.2` (Windows Messenger)
- Блокировка `SJPhone` (SIP-сканер)

#### Строковые константы

| Строка | Контекст |
|--------|---------|
| `o=userX 20000001 20000001 IN IP4` | SDP origin (фингерпринт) |
| `DBL SIP` | User-Agent (фингерпринт) |
| `4e52e09f` | SDP session token |
| `freeproxy1` | Proxy default |
| `Jason` | Разработчик (STUN-код) |
| `nist_register_received` | Callback-имя |

#### Self-parsing ELF (Anti-tampering)

sipcli содержит код для чтения собственного ELF:
- Читает `/proc/%u/exe`
- Парсит ELF заголовки, секции, строковые таблицы
- Ищет `.symtab`, `.strtab`
- Вычисляет адреса функций
- **Цель:** anti-tampering / crash dump с символами

#### 3 криптографические таблицы в .data (4096 байт)

Используются для N2C и ET263 шифрования — lookup-таблицы подстановки.

---

### 7.3 mg — Media Gateway (117 KB)

**RTP-прокси** между VoIP-сетью и DSP. Управляет медиа-потоками для всех каналов.

| Параметр | Значение |
|----------|----------|
| **Размер** | 117 KB |
| **Строк** | 538 |
| **Кодеков** | 10 |
| **NAT-режимов** | 3 (STUN, Relay, PortForward) |
| **Крипто-режимов** | 5 (RC4, ET263, VOS, AVS, ECM) |

#### Поддерживаемые кодеки

| Кодек | Payload | Bandwidth |
|-------|---------|-----------|
| G.711 A-law | 8 | 64 kbps |
| G.711 μ-law | 0 | 64 kbps |
| G.723.1 | 4 | 5.3/6.3 kbps |
| G.729/A/AB | 18 | 8 kbps |
| GSM FR | 3 | 13 kbps |
| G.722 | 9 | 64 kbps |
| iLBC | 97 | 13.3/15.2 kbps |
| AMR-NB | 96 | 4.75-12.2 kbps |
| T.38 Fax | — | variable |
| RFC 2833 DTMF | 101 | — |

#### RTP Pipeline

```
VoIP Network                                          DSP Hardware
     │                                                     │
     ▼                                                     ▼
 ┌───────┐    ┌──────────┐    ┌──────────┐    ┌──────────────┐
 │  RTP  │───►│  Jitter  │───►│ Decrypt  │───►│ fvdsp_data_in│
 │Socket │    │  Buffer  │    │(RC4/ET263│    │  Unix DGRAM   │
 │(UDP)  │    │(HW or SW)│    │ /VOS/AVS)│    └──────┬────────┘
 └───────┘    └──────────┘    └──────────┘           │
                                                      ▼
                                                   fvdsp
                                                      │
 ┌───────┐    ┌──────────┐    ┌──────────┐    ┌──────┴────────┐
 │  RTP  │◄───│  Encrypt │◄───│  Encode  │◄───│fvdsp_data_out│
 │Socket │    │(RC4/ET263│    │          │    │  Unix DGRAM   │
 │(UDP)  │    │ /VOS/AVS)│    │          │    └───────────────┘
 └───────┘    └──────────┘    └──────────┘
```

#### CLI-параметры mg

| Параметр | Описание |
|----------|----------|
| `-n N` | Количество каналов (TELPORT) |
| `--poll-inval 25` | Интервал опроса (для >6 каналов) |
| `--enable-watchdog` | Watchdog (для >6 каналов) |
| `--codec-preferenceN=...` | Кодеки для канала N |
| `--enable-fax` | Поддержка T.38 |
| `-t TRAVERSAL` | NAT traversal mode |
| `--rc4-key=KEY` | RC4-ключ |
| `--relay-server=SVR` | Relay-сервер |
| `--relay-encrypt` | Шифрование relay |
| `--relay-udp-ext1` | UDP-расширение relay |
| `--relay-udp-over-tcp` | UDP через TCP |
| `--relay-bind-ext1` | Bind-расширение relay |
| `--rtp-tos=N` | QoS DSCP для RTP |
| `--rtp-report-interval N` | Интервал RTP-отчётов |
| `--rtp-dt N` | RTP dead time |

#### FVDSP IPC протокол

Текстовые команды через Unix DGRAM sockets:

| Команда | Направление | Описание |
|---------|------------|----------|
| `START codec rate` | mg → fvdsp | Начать кодирование |
| `STOP` | mg → fvdsp | Остановить |
| `DTMF digit` | mg → fvdsp | Генерировать DTMF |
| `TONE type` | mg → fvdsp | Генерировать тон |
| `PLAY file` | mg → fvdsp | Проиграть файл |
| `VOL level` | mg → fvdsp | Громкость |
| binary data | mg ↔ fvdsp | PCM аудиоданные через data_in/data_out |

---

### 7.4 fvdsp — DSP-демон (903 KB)

**Самый большой бинарник по размеру.** Включает стек HSmedia от Hellosoft и драйвер Si3217x ProSLIC.

| Параметр | Значение |
|----------|----------|
| **Размер** | 903 KB |
| **PLT imports** | 121 функций |
| **Потоков** | 4 |
| **Кодеков** | 10+ (включая AMR-NB все 8 режимов) |
| **Стран (тоны)** | 22 |
| **Версия HSmedia** | v3.7 (Hellosoft Pvt. Ltd.) |
| **SLIC** | Si3217x (Silicon Labs ProSLIC API) |

#### 4 Потока

| Поток | Назначение |
|-------|-----------|
| MC Reader | Команды от mg (управление) |
| NW Reader | Сетевые данные (audio in) |
| DSP Reader | Данные из DSP hardware |
| DIM Event | DTMF/CID/события от hardware |

#### Аудио-кодеки

| Кодек | Реализация |
|-------|-----------|
| G.711 A-law/μ-law | Hardware (ACI) — `hsmm_g711_alaw_init`, `hsmm_g711_ulaw_init` |
| G.723.1 | Software — `hsmm_g7231_init` |
| G.729A/AB | Software — `hsmm_g729ab_init` |
| GSM FR | Software — `hsmm_gsm_init` |
| iLBC | Software — `hsmm_ilbc_init` |
| AMR-NB | Software — `hsmm_amrnb_init` (режимы 0-7: 4.75k-12.2k) |
| G.722 | Software — `hsmm_g722_init` |
| T.38 | Fax relay — `hsmm_t38_init`, версия v3.23 |
| RFC 2833 | DTMF OOB — `hsmm_rfc2833_init` |

#### Генерация тонов (22 страны)

Поддерживаемые наборы тонов (dial tone, busy, ring, congestion, call waiting):

`AR` (Аргентина), `AT` (Австрия), `AU` (Австралия), `BE` (Бельгия), `BR` (Бразилия), `CH` (Швейцария), `CL` (Чили), `CN` (Китай), `CZ` (Чехия), `DE` (Германия), `DK` (Дания), `FI` (Финляндия), `FR` (Франция), `GR` (Греция), `HU` (Венгрия), `IL` (Израиль), `IN` (Индия), `IT` (Италия), `JP` (Япония), `NL` (Нидерланды), `NO` (Норвегия), `NZ` (Новая Зеландия), `PT` (Португалия), `RU` (Россия), `SE` (Швеция), `SG` (Сингапур), `TW` (Тайвань), `UK`, `US` (+ варианты)

#### DTMF-детекция

- **Goertzel фильтры** — аппаратная реализация в fvaci.ko
- Низкие частоты: 697, 770, 852, 941 Hz
- Высокие частоты: 1209, 1336, 1477, 1633 Hz
- Caller ID: FSK-декодирование (Bell 202)

#### ProSLIC API (Si3217x)

| Функция | Описание |
|---------|----------|
| `Si3217x_Init` | Инициализация SLIC |
| `Si3217x_Ring` | Генерация звонка |
| `Si3217x_Dcfeed` | DC-питание линии |
| `Si3217x_Cal` | Калибровка |
| `Si3217x_SetLinefeed` | Режим линии |
| `Si3217x_ReadHook` | Чтение состояния рычага |
| `Si3217x_PCMConfig` | Конфигурация PCM |

---

### 7.5 ipp — H.323 Endpoint (540 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 540 KB |
| **Протоколы** | H.225 (Q.931), H.245, RAS, H.235 |
| **Режимов** | 4 (DIRECT, SINGLE, LINE [×8], GROUP [×8]) |

#### Операционные режимы

1. **DIRECT_MODE** — прямое H.323 соединение (без GK)
   - Q.931 порт 1720
   - До 3 trunk gateways
2. **SINGLE_MODE** — один GK на все линии
3. **LINE_MODE** — до 8 отдельных GK-регистраций
4. **GROUP_MODE** — до 8 групп с отдельными GK

#### H.235 Аутентификация

Для каждой линии/группы:
- `H235_ID` / `H235_PASSWD` — учётные данные
- `H323_VOS_ENABLE` / `H323_VOS_MODE` — шифрование VOS2000

#### CLI-параметры ipp

```
--groupN_lines LINES      # Линии в группе N
--groupN_gkaddr ADDR      # Адрес Gatekeeper
--groupN_number NUM       # Номер для регистрации
--groupN_number [h323-ID:]ID  # H.323 ID
--groupN_gw_prefix PFX    # Gateway prefix
--groupN_h235_id ID       # H.235 auth ID
--groupN_h235_passwd PW   # H.235 auth password
--groupN_crypt_mode MODE  # VOS encryption mode
--enable-group-prefix=1   # Включить group prefix
--enable-early-media 1    # Early media
--faststart-extend 1      # FastStart extension
--billing_support 1       # Billing support
--q931-port=PORT           # Q.931 port (direct mode)
--group0_callerip=IPS      # Caller IPs (direct mode)
--enable_citron=1          # Citron NAT traversal
```

---

### 7.6 smb_module — SIM Bank клиент (68 KB)

**Клиент удалённого SIM-банка.** Подключается к серверу SIM Bank по TCP и проксирует APDU-команды между GSM-модемами и удалёнными SIM-картами.

| Параметр | Значение |
|----------|----------|
| **Размер** | 67 916 байт |
| **PLT imports** | 88 |
| **Строк** | 469 |
| **Magic number** | `0x43215678` (12 точек использования) |
| **Каналов** | 16 (SMB_MAX_CHANNELS) |
| **APDU файлов** | 8 типов SIM файлов |
| **Исходных .c** | 9 файлов |

#### Протокол SMB

**Magic:** каждый пакет начинается с `0x43215678` (Big Endian).

| Поле | Размер | Описание |
|------|--------|----------|
| Magic | 4 байта | `0x43215678` |
| Command | 2 байта | Код команды |
| Channel | 1 байт | Номер канала |
| Length | 2 байта | Длина данных |
| Data | variable | Данные |

#### M-команды (SMB → ata)

| Команда | Описание |
|---------|----------|
| `MBUSY` | Канал занят |
| `MIDLE` | Канал свободен |
| `MLOGIN` | Логин на SIM Bank |
| `MLOGOUT` | Выход из SIM Bank |
| `MDOWN` | SIM Bank недоступен |
| `MCUE` | SIM Card Up Event |
| `MCUD` | SIM Card Down Event |
| `MSTATE` | Запрос состояния |
| `MSRB` | SIM Reboot |
| `MEXPIRY` | SIM истекла |
| `MIMEIRS` | IMEI Reset Signal |
| `MHRB` | Hard Reboot модуля |

#### Перенаправляемые SIM-файлы (APDU)

| EF | Описание |
|----|----------|
| `EF_ADN` | Abbreviated Dialing Numbers |
| `EF_FDN` | Fixed Dialing Numbers |
| `EF_SPN` | Service Provider Name |
| `EF_SDN` | Service Dialing Numbers |
| `EF_ECC` | Emergency Call Codes |
| `EF_CBMID` | Cell Broadcast Message IDs |
| `EF_LOCI` | Location Information |
| `EF_IMSI` | International Mobile Subscriber Identity |

#### Жёсткие APDU-ответы

| SW | Значение |
|----|----------|
| `9000` | OK |
| `9f0f` | GET RESPONSE required |
| `9404` | File not found |
| `611b` | More data available |
| `6a82` | File not found (detailed) |

#### Исходные файлы smb_module

`main.c`, `smbcli.c`, `smbpkt.c`, `smbconn.c`, `smbcfg.c`, `smbsim.c`, `smbapdu.c`, `smblog.c`, `smbutil.c`

---

### 7.7 radmcli — Remote Admin туннель (51 KB)

**🔴 КРИТИЧЕСКИ ОПАСНЫЙ КОМПОНЕНТ.** Обратный TCP-туннель для удалённого управления устройством через серверы производителя.

| Параметр | Значение |
|----------|----------|
| **Размер** | 51 296 байт |
| **Строк** | 341 |
| **Hardcoded key** | `dbl#admin` |
| **Hardcoded IPs** | 3 (Китай/Гонконг) |
| **Шифрование** | XOR-like (НЕ TLS!) |
| **Каналов** | 2 (RADMIN + RLOGIN) |

#### Архитектура

```
GoIP устройство                    Управляющий сервер (Китай)
┌─────────────┐                    ┌───────────────────────┐
│  radmcli    │────TCP:1920──────►│   RADMIN_SERVER       │
│             │    (reverse)       │   (118.140.127.90     │
│  ┌────────┐ │                    │    47.242.142.229     │
│  │RADMIN  │─┤◄── HTTP proxy ───►│    202.104.186.90)    │
│  │channel │ │  127.0.0.1:80     │                       │
│  ├────────┤ │                    │                       │
│  │RLOGIN  │─┤◄── Telnet proxy ─►│  Удалённое управление │
│  │channel │ │  127.0.0.1:13000  │  устройством через    │
│  └────────┘ │                    │  веб-интерфейс и      │
└─────────────┘                    │  удалённый шелл       │
                                   └───────────────────────┘
```

#### Параметры запуска

```bash
radmcli -r ${RADMIN_SERVER}:${RADMIN_PORT} \
        -al 127.0.0.1:${HTTP_PORT} \       # local HTTP
        -ll 127.0.0.1:${TPORT} \            # local Telnet (13000 или 23)
        -k "${RADMIN_KEY}" \                 # ключ (default: dbl#admin)
        -i "$id" \                           # device ID (=SN)
        -t 30                                # timeout
```

#### White-list серверов

| IP | Расположение | Назначение |
|----|-------------|-----------|
| `118.140.127.90` | Гонконг | RADM primary |
| `47.242.142.229` | Alibaba Cloud HK | RADM secondary |
| `202.104.186.90` | Shenzhen Telecom | RADM tertiary |

#### Шифрование

**XOR-based** — простое побитовое XOR с ключом `dbl#admin`. **НЕ** TLS, **НЕ** AES, **НЕ** RC4. Полностью незащищённый канал.

---

### 7.8 smpp_smsc — SMPP SMS-центр (43 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 43 080 байт |
| **Протокол** | SMPP v3.4 |
| **PLT imports** | 84 |
| **Строк** | 256 |
| **TLS** | ❌ Нет |

#### Поддерживаемые PDU

| PDU | Описание |
|-----|----------|
| `BIND_TRANSCEIVER` | Подключение |
| `SUBMIT_SM` | Отправка SMS |
| `DELIVER_SM` | Доставка SMS |
| `ENQUIRE_LINK` | Keepalive |
| `UNBIND` | Отключение |

#### DLR-статусы

| Статус | Описание |
|--------|----------|
| `DELIVRD` | Доставлено |
| `UNDELIV` | Не доставлено |
| `ENROUTE` | В процессе |
| `REJECTD` | Отклонено |

#### Конфигурация

| Ключ | Описание |
|------|----------|
| `SMPP_PORT` | Порт сервера |
| `SMPP_ID` | Идентификатор |
| `SMPP_KEY` | Пароль аутентификации |
| `SMPP_ENABLE` | Включение SMPP |
| `SMPP_GNUM_EN` | GSM Number enable |
| `ENROUTE_DISABLE` | Отключение ENROUTE-статуса |

---

### 7.9 smail — SMTP-клиент (47 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 47 152 байт |
| **Протоколы** | ESMTP + AUTH LOGIN (Base64) |
| **Форматы** | MIME multipart, вложения |
| **TLS** | ❌ Нет |

#### SMS-to-Email

Для каждой линии (0-7):
- `LINE%d_MAIL_SVR` — SMTP-сервер
- `LINE%d_MAIL_PORT` — порт (25)
- `LINE%d_MAIL_ID` — логин
- `LINE%d_MAIL_PASSWD` — пароль
- `LINE%d_MAIL_TO` — адрес получателя

#### Bug Report (автоматический)

Отправляется на `bug@fspipsev.net` через `fspipsev.net` (61.141.247.7):
- Crash dump
- Call stack
- `/proc/%d/maps` (карта памяти процесса)
- Bugreport ID: `bugreport: E%.03d`

---

### 7.10 svcd — Service Controller (91 KB)

**Init-система GoIP.** Управляет всеми демонами, хранит конфигурацию, обрабатывает watchdog.

| Параметр | Значение |
|----------|----------|
| **Размер** | 91 068 байт |
| **Управляемых сервисов** | 17+ |
| **Watchdog** | /dev/watchdog + /dev/gpio0 |
| **Конфигурация** | /etc/svc.conf, /usr/etc/svc.conf |

#### Управляемые сервисы

| Сервис | Бинарник | Обязательность |
|--------|----------|---------------|
| fvdsp | `/usr/bin/fvdsp` | Обязательный |
| ata | `/usr/bin/ata` | Обязательный |
| sipcli | `/usr/bin/sipcli` | SIP mode |
| ipp | `/usr/bin/ipp` | H.323 mode |
| mg | `/usr/bin/mg` | Обязательный |
| httpd | `/usr/sbin/httpd` | Обязательный |
| rstdt | `/usr/bin/rstdt` | Обязательный |
| smb_module | `/usr/bin/smb_module` | Если REMOTE_SIM=1 |
| radmcli | `/usr/bin/radmcli` | Если RADMIN_ENABLE=1 |
| smpp_smsc | `/usr/bin/smpp_smsc` | Если SMPP_ENABLE=1 |
| dnscli | `/usr/sbin/dnscli` | Если DDNS_ENABLE=1 |
| sysinfod | `/sbin/sysinfod` | Обязательный |
| pppoecd | `/usr/sbin/pppoecd` | PPPoE mode |
| pppmon | `/usr/bin/pppmon` | PPPoE mode |
| ntp2 | начальный сервис | Обязательный |
| start_httpd | `/usr/bin/start_httpd` | Обязательный |
| start_imeimon | `/usr/bin/start_imeimon` | IMEI mode |

#### Syscfg Storage

| Path | Size | Purpose |
|------|------|---------|
| `/dev/mtdblock/5` | 64-128 KB | Основная конфигурация |
| `/dev/mtdblock/6` | 16-32 KB | hwinfo (MAC, SN, HW rev) |
| `/dev/mtdblock/7` | 64-128 KB | Вторичная конфиг (SMS store) |

---

### 7.11 httpd — Веб-сервер (71 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 71 020 байт |
| **Движок** | LibHTTPD (Hughes Technologies) |
| **Шаблоны** | CSP (Custom Server Pages) |
| **Auth** | Basic WWW-Authenticate |
| **Порт** | Configurable (default 80) |

#### Web API

| Endpoint | Описание |
|----------|----------|
| `getcfg` | Получить конфигурацию |
| `setcfg` | Установить конфигурацию |
| `save` | Сохранить в Flash |
| `apply` | Применить |
| `reset` | Сброс к умолчаниям |
| `reload` | Перечитать |
| `reboot` | Перезагрузка |
| `start_upgrad` | Начать обновление |
| `exec` / `system` | ⚠️ Выполнение команд |

#### MDB (Mini Database)

Встроенный мини-СУБД через Unix socket `/tmp/mdb.str`:
- Операции: `create`, `add`, `delete`, `update`, `search`, `getRecord`
- Используется для SMS-хранения

#### Локализация

- `zh_CN` (GB2312) — Упрощённый китайский
- `zh_TW` (Big5) — Традиционный китайский
- `en_US` — Английский
- Структура: `/usr/share/httpd/${VENID}/${LANG}/`

#### Firmware Upgrade через Web

1. Upload `.pkg` файл через HTTP POST
2. Создаёт `/tmp/update`
3. Exec `/bin/update` → завершает все сервисы
4. Копирует `/sbin/up` в `/tmp/up` (RAM)
5. `/tmp/up` записывает прошивку в MTD
6. Перезагрузка

---

### 7.12 up — Firmware Updater (120 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 119 512 байт |
| **Протоколы** | HTTP, HTTPS (CyaSSL/wolfSSL), FTP, TFTP |
| **SSL** | CyaSSL (wolfSSL) — встроенный |
| **Шифрование пакета** | RC4 с VENDOR_KEY |

#### Формат пакета прошивки (flash.pkg)

```
┌─────────────────────────────┐
│ Magic (4 байта)             │ ← Проверка: magic: %08lx
├─────────────────────────────┤
│ Version                     │
├─────────────────────────────┤
│ Checksum                    │
├─────────────────────────────┤
│ Total size / Actual size    │
├─────────────────────────────┤
│ Number of partitions        │
├─────────────────────────────┤
│ Partition headers           │
│ ├── offset, size, type      │
│ ├── kernel / rootfs / uboot │
│ └── ...                     │
├─────────────────────────────┤
│ Partition data              │
│ (зашифровано RC4 если       │
│  VENDOR_KEY установлен)     │
└─────────────────────────────┘
```

#### Hardcoded URL

```
http://192.168.2.71/upgrade/flash.pkg
```
— внутренний сервер разработки DBL Technology (НЕ должен быть в продакшене).

#### SSL/TLS

- CA-сертификат: `/usr/etc/ca-cert.pem`
- RSA, AES (128/192/256), MD5, SHA
- wolfSSL (ранее CyaSSL)

---

### 7.13 rstdt — Watchdog/Reset Daemon (43 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 43 048 байт |
| **Watchdog** | `/dev/watchdog` — аппаратный WDT |
| **GPIO** | `/dev/gpio1` — кнопка сброса |
| **Bug reporter** | Встроенный SMTP-отправитель |

#### Функции

- Мониторинг watchdog timer (`WD_TIMER`, default 60000 мс)
- Обработка hardware reset button (`RESET_KEY`)
- Echo-сервер: проверка сети через `ECHOSVR_ADDR` порт `:54210`
- Hardcoded DNS: `202.96.136.145` (China Telecom)
- Bug report: `bug@fspipsev.net` через `61.141.247.7`
- Чтение: `USE_INTERFACE`, `GATE_METRIC`, `GATE_TIMEOUT`

---

### 7.14 pppoecd — PPPoE-клиент (85 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 85 120 байт |
| **Протоколы** | PPPoE, LCP, IPCP, PAP, CHAP |
| **Hash** | MD4 (для CHAP) |

- PPPoE Discovery: PADI → PADO → PADR → PADS
- DNS: `usepeerdns`, `/tmp/ppp/resolv.conf`
- Скрипты: `/etc/ppp-ip-up`, `/etc/ppp-ip-down`

---

### 7.15 dnscli — DDNS-клиент (43 KB)

| Параметр | Значение |
|----------|----------|
| **Размер** | 43 084 байт |
| **Доменов** | До 9 (`domain1`-`domain9`) |
| **Файл** | `/var/tmp/hosts` |

#### Запуск

```bash
dnscli --server ${DDNS_ADDR} --port ${DDNS_PORT} \
       --domain1..9 ${PROXY_ADDRS} \
       -f /var/tmp/hosts \
       -t ${DDNS_UPDATE_INTERVAL} \
       --sn ${SN}
```

Поддерживает backup-сервер: `--bserver`, `--bport`

---

### 7.16 Утилиты шифрования

#### decrypt.RC4 (6 KB)

```
rc4 -k <key> <input> <ofpput>
```

- Чистый RC4 stream cipher
- **Опечатка** в коде: `ofpput` вместо `output`
- Используется в `backup_config` и `restore_config`
- Ключ: `пароль@dbl` (пароль + суффикс `@dbl`)

#### ioctl (6 KB)

```
enc -k <key> <input> <ofpput>
```

- **НЕ системный ioctl!** Это утилита шифрования
- Тоже RC4, но с другим использованием
- Используется при загрузке системы для расшифровки boot-файлов
- Ключ: `${CPU}` — CPU serial number
- Расшифровывает: `df.b` → `default.bound`, `lglm` → `loginlimit`, `lg` → `login`

---

### 7.17 Малые бинарники и скрипты

#### ELF-бинарники

| Бинарник | Размер | Описание |
|----------|--------|----------|
| **pppmon** | 14 KB | Монитор PPP: проверяет ppp0/pptp0 через /proc/net/dev, рестарт при потере пакетов |
| **unimac** | 7 KB | MAC-генератор: читает из /dev/mtd/7, маркер `QZ^&` (0x515A5E26) |
| **getipbyname** | 6 KB | DNS resolver: использует syscfg `VPN_DNS` |
| **mon_waddr** | 39 KB | WAN address monitor: до 9 адресов (`MON_DADDR1..9`) |
| **brctl** | 22 KB | Linux Bridge Utilities |
| **ping2** | 10 KB | ICMP ping |
| **sysinfo** | 4 KB | Sysinfo client: `/tmp/.sysinfo.sock` |
| **sysinfod** | 7 KB | Sysinfo daemon: `/tmp/.sysinfo.sock` + FIFO `/tmp/.sysinfo` |
| **hwinfo** | 11 KB | HW info: `/dev/mtdblock/6`, чтение (`-r`) / запись (`-w`), `-f` ignore checksum |
| **init** | 13 KB | BusyBox-based init |
| **ntp** | 51 KB | NTP client: default `pool.ntp.org`, bug reporter встроен |

#### Shell-скрипты (usr/bin)

| Скрипт | Размер | Функция |
|--------|--------|---------|
| **echocmd** | 38 B | `echo $@ > /etc/ipin` — отправить команду через IPC |
| **getuptime** | 47 B | `setsyscfg UPTIME=$(cat /proc/uptime)` |
| **gsmdb** | 40 B | `echo GSM_DEBUG=$1 > /etc/ipin` — включить GSM debug |
| **ep** | 31 B | `echo $1 > /etc/ipin` — echo pipe |
| **l1_set_oper** | 1020 B | Выбор GSM-оператора (до 10 операторов, AUTO/manual) |
| **update** | 768 B | Обновление прошивки: stop сервисов → copy up → exec up |
| **backup_config** | 200 B | Бекап: `getsyscfg > file`, шифр RC4 с `пароль@dbl` |
| **restore_config** | 191 B | Восстановление: RC4 расшифровка → `setsyscfg -f` |

#### Shell-скрипты (usr/sbin)

| Скрипт | Функция |
|--------|---------|
| **HWINFO** | `hwinfo -r hwinfo` — чтение HW info |
| **set_venid** | Запись Vendor ID в hwinfo |
| **KILL** | `killall httpd sipcli mg ata` |
| **infogsm1** | GSM debug mode 1 |
| **infogsmsip** | GSM debug 17 + SIP debug |
| **rbm** | `echo MHRB$1 > /etc/ipin` — reboot module |
| **gsmdb** | GSM debug: off → on (toggle) |
| **sipdb** | SIP debug: `SIP_DEBUG=$1 > /etc/ipin` |

---

## 8. МОДУЛИ ЯДРА (.ko)

**Всего: 31 модуль** для Linux 2.6.17

### Hardware-драйверы

| Модуль | Размер | Описание |
|--------|--------|----------|
| **fvaci.ko** | 52 KB | ACI PL040 DSP: DTMF (Goertzel), Caller ID (FSK), G.711 HW, 8 каналов |
| **fvmac.ko** | 55 KB | Dual Ethernet MAC (AMBA bus, RMII), 2 порта (WAN+LAN) |
| **fvmem.ko** | ~5 KB | `/dev/fvmem` — прямой доступ к HW-регистрам через mmap |
| **fvspi.ko** | ~5 KB | SPI bus driver |
| **fvgpio.ko** | ~5 KB | GPIO driver |
| **wd.ko** | ~3 KB | Watchdog timer driver |

### Сетевые модули

| Модуль | Размер | Описание |
|--------|--------|----------|
| **fvnet.ko** | ~15 KB | IP fastpath (ускоренная маршрутизация) |
| **fvipdef.ko** | 10 KB | IDS: LAND Attack, SYN Flood, Port Scan detection |
| **nfext.ko** | 35 KB | NAT extensions: hairpin NAT, cone NAT, conntrack help |
| **brext.ko** | ~5 KB | Bridge extension |
| **bwlimit.ko** | ~10 KB | Bandwidth limiter (per-IP/port) |
| **qoshook.ko** | ~5 KB | QoS hook framework |
| **qosip.ko** | ~5 KB | QoS IP classification |
| **vtag.ko** | 16 KB | VLAN tagging (802.1Q) |
| **sniffer.ko** | ~5 KB | Packet capture module |

### ALG (Application Layer Gateway) модули

| Модуль | Описание |
|--------|----------|
| **fv_alg_bnet.ko** | Battle.Net NAT helper |
| **fv_alg_dns.ko** | DNS ALG |
| **fv_alg_esp.ko** | IPSec ESP NAT traversal |
| **fv_alg_ftp.ko** | FTP ALG (PORT/PASV) |
| **fv_alg_ipsec.ko** | IKE NAT traversal |
| **fv_alg_l2tp.ko** | L2TP tunnel tracking |
| **fv_alg_msn.ko** | MSN Messenger file transfer |
| **fv_alg_sip.ko** | SIP ALG (Contact/Via rewriting) |

### iptables модули

| Модуль | Описание |
|--------|----------|
| **fv_ipt_localport.ko** | Local port match |
| **fv_ipt_trigger.ko** | Port triggering (auto port forward) |
| **fv_ipt_webstr.ko** | URL/web string filter |

### Debug/Utility модули

| Модуль | Описание |
|--------|----------|
| **neigh.ko** | ARP/neighbor table debug |
| **heap.ko** | Heap/brk debugging |
| **unalign.ko** | Alignment fault handler |
| **exthook.ko** | Extension hook framework |
| **firmware_class.ko** | Standard Linux firmware loader |

### fvaci.ko — Детальный анализ (DSP Hardware)

| Компонент | Описание |
|-----------|----------|
| **ACI PL040** | Audio Codec Interface — стандарт ARM для DSP |
| **G.711 HW** | Аппаратное кодирование A-law/μ-law |
| **DTMF (Goertzel)** | Аппаратные Goertzel-фильтры для DTMF-детекции |
| **Caller ID (FSK)** | Bell 202 FSK демодулятор |
| **DMA** | Прямой доступ к памяти для PCM-потоков |
| **IRQ** | Аппаратные прерывания от DSP |
| **MMIO** | Регистры по адресам 0x10-0x1C |
| **Device** | `/dev/aci%d` (по каналу) |

---

## 9. ПОЛНЫЙ СПРАВОЧНИК AT-КОМАНД

### Стандартные GSM AT-команды

| Команда | Описание | Модуль |
|---------|----------|--------|
| `ATE0/ATE1` | Echo off/on | ata |
| `ATI8` | Module info | ata |
| `ATD%s;` | Voice dial | ata |
| `ATH` | Hangup | ata |
| `ATA` | Answer | ata |
| `AT+CFUN=0/1/15` | Функциональность модуля (off/on/reset) | ata |
| `AT+CFUN=1,1` | Reset с перезагрузкой | ata |
| `AT+CREG?/=2` | Network registration | ata |
| `AT+CSQ` | Signal quality (RSSI) | ata |
| `AT+CPAS` | Phone activity status | ata |
| `AT+COPS=?/0/1,2,"CODE"` | Operator selection | ata |
| `AT+COPS=3,0` | Operator format: long alpha | ata |
| `AT+CPIN?/="PIN"` | PIN management | ata |
| `AT+CIMI` | IMSI query | ata |
| `AT+CCID/+QCCID` | ICCID query | ata |
| `AT+CNUM` | Own number | ata |
| `AT+CMGF=0` | SMS PDU mode | ata |
| `AT+CMGS=%d` | Send SMS (PDU) | ata |
| `AT+CMGR=%d` | Read SMS | ata |
| `AT+CMGD=1,4/%d` | Delete SMS (all/specific) | ata |
| `AT+CMGL=4` | List all SMS | ata |
| `AT+CNMI=1,2,2,0,1` | New SMS notification | ata |
| `AT+CSMS=1` | SMS service type | ata |
| `AT+CNMA` | SMS acknowledgement | ata |
| `AT+CSCA?` | SMS Centre Address | ata |
| `AT+CPMS="ME","ME","ME"` | SMS storage = Module | ata |
| `AT+CUSD=1,"..."/=2` | USSD request/cancel | ata |
| `AT+CLIP=1` | Caller ID enable | ata |
| `AT+CLIR=0/1` | CLIR disable/enable | ata |
| `AT+CLCC=1` | Current calls list | ata |
| `AT+CCWA=1,%d,1` | Call waiting | ata |
| `AT+CCFC=%d,%d` | Call forwarding | ata |
| `AT+CHLD=1/2/3` | Hold/swap/conference | ata |
| `AT+VTS=%c/"` | Send DTMF | ata |
| `AT+VTD=0` | DTMF duration | ata |
| `AT+VTA=0` | DTMF type | ata |
| `AT+IPR=%d(&W)` | UART baud rate | ata |
| `AT+CMEE=1/2` | Extended errors | ata |
| `AT+CSSN=0,1` | Supplementary service notify | ata |
| `AT+CGATT=0/?` | GPRS attach/query | ata |
| `AT+CGREG?` | GPRS registration | ata |
| `AT+CEER` | Extended error reason | ata |
| `AT+CLCK="SC",0,"PIN"` | SIM unlock | ata |
| `AT+CALM=0,1/1` | Alert mode | ata |
| `AT+CLVL=35` | Speaker volume | ata |
| `AT+CSIM` | Direct SIM APDU | ata |
| `AT+SIMDATA="HEX"` | SIM data exchange | smb_module |

### Специфические для Quectel

| Команда | Описание |
|---------|----------|
| `AT+QGSN` | Read IMEI (Quectel) |
| `AT+QCFG="SIM/Type",0/1` | SIM type: local/remote |
| `AT+QLOCKF=1,2,%d/=0` | Cell frequency lock/unlock |
| `AT+QENG?/=1,1` | Engineering mode (cell info) |
| `AT+QTONEDET=1` | Tone detection enable |
| `AT+QMIC=0,6` | Microphone gain |
| `AT+QSIDET=0` | Side-tone off |
| `AT+QNUMR?/+QNUMW` | Read/Write phone number |
| `AT+QCCID` | ICCID query (Quectel) |

### Специфические для GT-модулей

| Команда | Описание |
|---------|----------|
| `AT+GTSET="GTIMEI","IMEI"` | Set IMEI |
| `AT+GTSET="SIMPIPE",0/1/2` | SIM pipe mode |
| `AT+GTSET="SMSNUM",2` | SMS number type |
| `AT+GTBCCH=0/1/=?/=1,%d` | BCCH management |
| `AT+GSN` | Read serial/IMEI |

### IMEI-изменение (⚠️ НЕЛЕГАЛЬНО)

| Команда | Описание |
|---------|----------|
| `AT+EGMR=1,7,"%s"` | **Write IMEI** (универсальная) |
| `AT+GTSET="GTIMEI","%s"` | Write IMEI (GT модули) |

### Специфические для ME200

| Команда | Описание |
|---------|----------|
| `AT+MMICG=3/5/6/12` | Microphone gain |
| `AT+MAVOL=1,1,3/4` | Speaker volume |

### Специфические для CDMA (MC8618)

| Команда | Описание |
|---------|----------|
| CDMA PDU encoding | `cdma_pdu_encode` / `cdma_pdu_udh_encode` |
| SMS decode | `MC8618_cmgr_decode` |

---

## 10. КОММУНИКАЦИИ МЕЖДУ ПРОЦЕССАМИ (IPC)

### Unix Domain Sockets (полная карта)

| Путь | Тип | Владелец | Клиент(ы) | Описание |
|------|-----|----------|-----------|----------|
| `/tmp/.syscfg-server` | DGRAM | svcd | все | Центральное хранилище конфигурации |
| `.syscfg-client-%d` | DGRAM | client (PID) | svcd | Клиентский сокет syscfg |
| `/tmp/svcctl` | STREAM | svcd | все | Service control (start/stop/reload/reboot) |
| `/tmp/.fvdsp_cmd_in` | DGRAM | fvdsp | mg, ata | DSP command input |
| `/tmp/.fvdsp_mgcmd%d` | DGRAM | fvdsp | mg | Per-channel MG commands |
| `/tmp/.fvdsp_data_in%d` | DGRAM | fvdsp | mg | Audio IN: network → DSP |
| `/tmp/.fvdsp_data_out%d` | DGRAM | fvdsp | mg | Audio OUT: DSP → network |
| `/tmp/mg%d` | DGRAM | mg | sipcli, ipp | Media Gateway control |
| `/tmp/.mg_cli0` | DGRAM | mg | CLI | MG CLI interface |
| `/tmp/.dspcli%d` | DGRAM | fvdsp | CLI, ata | DSP CLI per-channel |
| `/tmp/.ippui%d` | DGRAM | ipp | mg, ata | UI control input |
| `/tmp/.ippui_cli%d` | DGRAM | ipp | CLI | UI client per-channel |
| `/tmp/.smb%d` | DGRAM | smb_module | ata | SIM Bank data per-channel |
| `/tmp/.smb_cli%d` | DGRAM | smb_module | CLI | SIM Bank CLI |
| `/tmp/.sysinfo.sock` | DGRAM | sysinfod | sysinfo | System info exchange |
| `/tmp/mdb.str` | STREAM | httpd | httpd (internal) | Mini Database |
| `/tmp/.upgrd_info` | DGRAM | up | httpd | Upgrade status |

### File-based IPC

| Путь | Тип | Описание |
|------|-----|----------|
| `/etc/ipin` | File (echo) | **ГЛАВНЫЙ IPC** — все демоны пишут команды, ata читает |
| `/etc/ramdcli` | FIFO | Commands to radmcli |
| `/var/tmp/hosts` | File | DNS results from dnscli |
| `/tmp/.sysinfo` | FIFO | System info FIFO |
| `/var/respawnd` | File | Respawn control |

### IPC через /etc/ipin (полный список команд)

| Команда | Источник | Описание |
|---------|----------|----------|
| `IPPSTART` | start_sip | SIP/IPP запущен |
| `TRUNKSTART` | start_sip | Trunk mode запущен |
| `IMEISET` | start_imeimon | IMEI set signal |
| `NETDOWN` | network | Сеть упала |
| `UNPLUG` | — | Кабель отключён |
| `LAN_UP` | — | LAN поднят |
| `PLUG` | — | Кабель подключён |
| `TELPORT` | — | Количество портов |
| `GSM_DEBUG=N` | gsmdb | GSM debug on/off |
| `SIP_DEBUG=N` | sipdb | SIP debug on/off |
| `SMS_DEBUG=N` | — | SMS debug |
| `CHANNEL_DEBUG=N` | — | Channel debug |
| `SMB_DEBUG=N` | — | SIM Bank debug |
| `MCTL` | — | Module control |
| `MHRB%d` | rbm | Reboot GSM module N |
| `+CMGS=…` | — | SMS send |
| `+CNMA` | — | SMS ACK |
| `ALL_SIM_EXP_RESET` | — | Reset all SIM timers |
| `SMS_RESET` | — | Reset SMS counters |
| `SMS_LIMIT_SET` | — | Set SMS limit |
| `GSM_BSTLST_GET` | — | Get BST list |
| `GSM_OPER_GET` | — | Get operator list |
| `SIM_EXP_SET` | — | Set SIM expiry |
| `CFGBST` | — | Configure BST |
| `GSM_BST_SAVE` | — | Save BST config |
| `M_LIMIT` | — | Machine limit |
| `SIM_ACD_RESET` | — | Reset SIM ACD |
| `NTP_SYNC` | — | NTP sync request |
| `L_LIMIT_RST` | — | Reset line limit |
| `DISMS` | — | DI SMS |
| `DOSMS` | — | DO SMS |
| `VOIP_LIC` | — | VoIP licence |
| `DISPATCH` | — | Dispatch control |
| `INDISABLE` | — | Incoming disable |
| `INDISABLE2` | — | Incoming disable 2 |
| `SMS%d data` | — | Send SMS line N |
| `GSMSTATUS` | smpp_smsc | GSM status query |
| `DELIVER%d` | — | SMS delivery |
| `SMSSTATUS%d` | — | SMS status |

### Уровни Debug

| Ключ | Значение | Результат |
|------|----------|----------|
| `GSM_DEBUG=1..17` | ata | AT-команды и GSM-ответы |
| `SIP_DEBUG=1,2` | sipcli | SIP-сообщения |
| `SMS_DEBUG=1` | ata | SMS трафик |
| `SMB_DEBUG=1` | smb_module | SIM Bank протокол |
| `CHANNEL_DEBUG=1` | ata | Канальные события |

---

## 11. ПОТОКИ ДАННЫХ

### Исходящий VoIP → GSM вызов

```
1. SIP INVITE → sipcli (парсинг, auth, routing)
2. sipcli → /tmp/.ippui%d → ata (IPPINFO_DIAL)
3. ata → gsm.c → AT commands:
   a. AT+CLIR=0/1 (CLIR)
   b. ATD<number>; (Dial)
4. GSM Modem → GSM Network (SETUP → ALERTING → CONNECT)
5. ata → /tmp/.ippui%d → sipcli (IPPINFO_CNT — connected)
6. sipcli → 200 OK → Remote SIP endpoint
7. sipcli → /tmp/mg%d → mg (start media)
8. mg ←→ RTP ←→ Remote
9. mg → /tmp/.fvdsp_data_in%d → fvdsp → fvaci.ko → HW → audio to modem
10. fvaci.ko → /tmp/.fvdsp_data_out%d → mg → RTP → Remote
11. Billing: ata/cdr.c записывает CDR
```

### Входящий GSM → VoIP вызов

```
1. GSM RING → /dev/ttyS%d → ata (console.c)
2. +CLIP: <caller> → ata → Caller ID
3. ata → /etc/ipin → IPPINFO_RG → sipcli
4. sipcli → SIP INVITE → VoIP endpoint
5. VoIP 180 Ringing → sipcli → ata (wait)
6. VoIP 200 OK → sipcli → ata (ATA — answer GSM)
7. ata → ATA → GSM Modem (CONNECT)
8. Media path established (same as above)
```

### SMS Flow (VoIP → GSM)

```
1а. UDP SMS → ata(smsudps.c) → TCP:SMS_PORT
1б. SMPP SUBMIT → smpp_smsc → /etc/ipin → ata
1в. Web UI → httpd → syscfg → ata
2. ata → pdu.c → PDU encode (UTF-8 → UCS2 или 7-bit)
3. ata → AT+CMGF=0 → AT+CMGS=%d → <PDU data> → GSM Modem
4. Modem → +CMS OK / ERROR → ata
5. ata → DLR → smpp_smsc / smsudps / httpd
```

### SMS Flow (GSM → Email)

```
1. +CMT: <PDU> → ata(console.c) → pdu.c decode
2. ata → SMS routing decision:
   a. SMS_MODE=RELAY: forward to another GSM channel
   b. SMS_MAIL: ata → exec smail
   c. SMPP: ata → smpp_smsc → DELIVER_SM → SMPP client
   d. UDP: ata → smsudps.c → UDP reply
3. If SMS_MAIL:
   smail → SMTP AUTH LOGIN → MIME multipart → SMTP server
```

### SIM Bank Flow

```
1. smb_module → TCP connect → SMB_SVR (SIM Bank server)
2. Auth: SMB_ID + SMB_KEY (optional RC4: SMB_RC4_KEY)
3. Protocol: magic 0x43215678 + command + data
4. smb_module ← APDU commands ← SIM Bank
5. smb_module → /tmp/.smb%d → ata
6. ata → AT+SIMDATA="<hex APDU>" → GSM Modem
7. Modem → +SIMDATA: "<response>" → ata
8. ata → /tmp/.smb%d → smb_module → TCP → SIM Bank
9. SIM Bank → Physical SIM → APDU response → loop
```

### Remote Admin Flow

```
1. radmcli → TCP connect → RADMIN_SERVER:1920
2. Auth: RADMIN_KEY (default: dbl#admin), device ID
3. XOR encryption (weak!)
4. Two channels established:
   a. RADMIN: proxy to 127.0.0.1:80 (httpd)
   b. RLOGIN: proxy to 127.0.0.1:13000 (telnet)
5. Remote admin accesses device web UI or shell through tunnel
```

### Auto-config Flow

```
1. ata/svcd → check AUTOCFG_ENABLE
2. If enabled:
   a. HTTP GET → AUTOCFG_URL (e.g. provisioning server)
   b. Response may be encrypted (AUTOCFG_CRYPT=RC4, AUTOCFG_KEY)
   c. decrypt.RC4 -k ${AUTOCFG_KEY} config.enc config.txt
   d. setsyscfg -f config.txt → apply all settings
   e. Reboot if needed
```

---

## 12. КРИПТОГРАФИЯ И ШИФРОВАНИЕ

### Обзор всех крипто-систем

| Алгоритм | Тип | Бинарник(и) | Использование | Стойкость |
|----------|-----|-------------|--------------|-----------|
| **RC4** | Stream cipher | sipcli, mg, smb_module, decrypt.RC4, ioctl | RTP/SIP/SMB шифрование, config backup, file encryption, auto-config | ⚠️ Устаревший |
| **ET263** | Proprietary (Hybertone) | sipcli, mg | RTP/SIP шифрование | ❓ Неизвестная |
| **VOS2000** | Proprietary | sipcli, mg, ipp | RTP/SIP/H.323 шифрование | ❓ Неизвестная |
| **N2C** | Proprietary (mapping) | sipcli | SIP шифрование | ❓ Неизвестная |
| **ECM** | Proprietary | sipcli, mg | RTP/SIP шифрование | ❓ Неизвестная |
| **AVS / TKPT_DeSecret** | Proprietary | sipcli, mg, ipp | RTP/SIP шифрование | ❓ Неизвестная |
| **FAST** | Proprietary (session) | sipcli | SIP шифрование | ❓ Неизвестная |
| **XOR** | Simple XOR | radmcli | Tunnel encryption | 🔴 Слабое |
| **MD5** | Hash | sipcli | SIP Digest Auth (реализация @ 0x02D010) | ⚠️ Устаревший |
| **MD4** | Hash | pppoecd | CHAP authentication | 🔴 Устаревший |
| **AES** | Block cipher | up | SSL/TLS (CyaSSL) | ✅ Стойкий |
| **RSA** | Asymmetric | up | SSL/TLS | ✅ Стойкий |
| **SHA** | Hash | up | SSL/TLS | ✅ Стойкий |
| **H.235** | ITU-T | ipp | H.323 security | ⚠️ Устаревший |
| **ARM EOR** | XOR obfuscation | sipcli | Inline data obfuscation (142 инструкции) | 🔴 Слабое |

### ET263 — Proprietary Encryption

4 функции:
- `create_convert_16` — конвертация 16-bit
- `create_convert_8` — конвертация 8-bit
- `create_parity_exchange_16` — обмен чётности 16-bit
- `create_parity_exchange_8` — обмен чётности 8-bit

Параметры:
- `ET263_CRYPT_DEP` — глубина шифрования
- `ET263_CRYPT_TYPE` — тип ET263

### Криптографические таблицы

В секции `.data` sipcli содержатся 3 lookup-таблицы общим размером ~4096 байт, используемые для N2C и ET263.

### Цепочка ключей

```
CPU Serial Number → ioctl (RC4) → boot decryption
                 ↓
           + "@dbl" suffix → backup_config RC4 key
                 ↓
SIP_RC4_KEY (default: "etoall.net") → RC4 для RTP/SIP
                 ↓
RADMIN_KEY (default: "dbl#admin") → XOR для reverse tunnel
                 ↓
SMB_RC4_KEY → RC4 для SIM Bank протокола
                 ↓
SMPP_KEY → SMPP аутентификация (plaintext!)
                 ↓
AUTOCFG_KEY → RC4 для auto-provisioning
                 ↓
VENDOR_KEY → RC4 для firmware package encryption
```

---

## 13. КОНФИГУРАЦИОННЫЕ ФАЙЛЫ (.def)

### common.def (~85 ключей)

```
# Аудио-кодеки
PREFER_CODEC1..6          — Предпочтительные кодеки
CODEC1..6_DISABLE          — Отключение кодека
AUDIO_CODEC_PREFERENCE     — Результирующая строка
PACKETIZE_PERIOD           — Период пакетизации (мс)
INBAND_DTMF                — Внутриполосный DTMF
DTMF_PAYLOAD_TYPE          — RFC 2833 payload type

# RTP
RTP_QOS                    — QoS mode (DIFFSERV/IPTOS)
RTP_DIFFSERV               — DSCP value
RTP_TOS                    — TOS value
ENABLE_LOG                 — Включить логирование
QOS_MON_WIN                — Окно мониторинга QoS

# NAT для RTP (mg)
MG_NAT_TRAVERSAL           — STUN/RELAY/NONE
MG_RELAY_SERVER/1..4       — Relay-серверы (до 5)
MG_RELAY_ENCRYPT           — Шифрование relay
MG_RELAY_MODE              — Режим relay (0/1/2)
MG_RELAY_EXTEND            — Расширенный relay
MG_CRYPT                   — Шифрование RTP (RC4/ET263/NONE)
MG_RC4_KEY                 — RC4-ключ для RTP

# FAX
LINE1_FAX / LINE2_FAX      — Fax mode (T38/G711/NONE)

# VPN
PPTP_ENABLE                — PPTP VPN
VPN_STATUS                 — Статус VPN

# RADMIN
RADMIN_ENABLE              — Включение Remote Admin
RADMIN_SERVER              — Адрес сервера
RADMIN_PORT                — Порт (default 1920)
RADMIN_ID                  — ID устройства
RADMIN_KEY                 — Ключ (default "dbl#admin")
RADM_WLIST                 — Белый список IP

# Прочее
AREA_LOCK                  — Блокировка по региону
AREA / AREA_CODE           — Код региона
TELPORT                    — Кол-во телефонных портов (1-8)
FW_VER / SLIC / BOOT_LDR  — Версия, SLIC, загрузчик
FTN                        — Feature flags
ECHOSVR_ADDR               — Echo server address
MG_RTP_DT                  — RTP dead time
```

### ata.def (~260 ключей)

```
# GSM Status (на линию LINE1..8)
LINE%d_STATUS              — GSM Idle/Login/...
LINE%d_GSM_STATUS          — Powered/SIM Ready/Registered/...
LINE%d_GSM_OPER            — Оператор
LINE%d_REG_STATUS          — Registered/Searching/Denied/...
LINE%d_RSSI                — Уровень сигнала
LINE%d_IMEI                — IMEI модема
LINE%d_IMSI                — IMSI SIM-карты
LINE%d_ICCID               — ICCID SIM-карты
LINE%d_INCOMING_NUM        — Номер входящего
LINE%d_OUTGOING_NUM        — Номер исходящего
LINE%d_BER                 — Bit Error Rate

# SIM Management
LINE%d_SIM_EXP             — SIM expiry
LINE%d_SIM_REMAIN          — SIM remaining time
L%d_SIM_EXP_UNIT           — Единица (мин/час/день)
L%d_SIM_STRP_NUM           — SIM rotation номер
L%d_SIM_STRP_TIME          — SIM rotation время
L%d_SIM_ID                 — SIM identifier
L%d_SIM_CALL_LIMIT         — Лимит вызовов на SIM

# SMS
LINE%d_SMS_INTERVAL        — Интервал между SMS (сек)
LINE%d_SMS_LIMIT           — Лимит SMS
LINE%d_SMS_REMAIN          — Остаток SMS
LINE%d_SMS_MODE            — Режим SMS
SMS_MODE                   — Глобальный режим SMS
SMS_DELIVER                — Режим доставки
SMS_LOGIN                  — Авторизация SMS-сервиса
L%d_SMS_SERVER / PORT      — UDP SMS-сервер
L%d_SMS_CLI_ID / PASSWD    — Авторизация SMS-клиента

# Call Forwarding (на линию)
L1_FW_MODE                 — UNCONDITIONAL/USERDIAL
L1_FW_NUM_TO_VOIP          — Forward to VoIP number
L1_FW_NUM_TO_PSTN          — Forward to PSTN number
L1_FW_TO_PSTN_PASSWD       — Пароль для PSTN forward
L1_FW2PSTN_AUTH_MODE       — AUTH mode (PASSWD_WLIST/WLIST/BLIST)
L1_FW2VOIP_AUTH_MODE       — AUTH mode
L%d_PSTN_TRUST_NUM_%d      — Доверенные номера (до 15 на канал)
L%d_VOIP_TRUST_NUM_%d      — VoIP доверенные номера

# GSM Call Forward
L1_GSM_CF_UNCND_ENABLE/NUM         — Безусловная переадресация
L1_GSM_CF_BUSY_ENABLE/NUM          — При занятости
L1_GSM_CF_NOREPLY_ENABLE/NUM       — При неответе
L1_GSM_CF_NOTREACHABLE_ENABLE/NUM  — При недоступности

# BST (Base Station)
LINE%d_BST_LIST            — Список базовых станций
LINE%d_GSM_BST             — Режим BST (AUTO/STRONG/POLL)
LINE%d_GSM_BST_CODE        — Код BST для блокировки
LINE%d_MAX_POLL_BST        — Макс. BST для опроса
LINE%d_BST_SW_INT          — Интервал переключения
LINE%d_LAC                 — Location Area Code
LINE%d_GSM_CUR_BST         — Текущая BST
LINE%d_NB_BST              — Соседние BST
BST_LOCK_RELEASE           — Снятие блокировки BST

# IMEI
IMEI_AUTO_ENABLE           — Автосмена IMEI
IMEI_AUTO_T                — Таймер автосмены
IMEI_RANDOM                — Рандомный IMEI
IMEI_CHANGE                — Флаг разрешения смены

# CDR
CDR_ENABLE                 — Включение CDR
CDR_INDEX                  — Индекс текущей записи
AUTO_RESET_CDR             — Автосброс CDR
RESET_CDR_TIME             — Время автосброса
LINE%d_ACD                 — Average Call Duration
LINE%d_ASR                 — Answer-Seizure Ratio
LINE%d_CALLC               — Call Count
LINE%d_DIALC               — Dial Count
LINE%d_CALLT               — Total Call Time

# Anti-fraud
ACD_LOW_THR / ACT           — Низкий ACD → действие
ASR_LOW_THR / ACT           — Низкий ASR → действие
NOALT_LIMIT / ACT           — No alert limit
NOCNT_LIMIT / ACT           — No connect limit
SCALL_LIMIT / LEN_LIMIT / ACT  — Short call limit
RSSI_H / RSSI_L             — RSSI пороги
SANS_C / SANS_T / SANS_ACT  — No answer streak

# Dial Plan
L1_V_DIGIT_MAP             — VoIP digit map
L1_P_DIGIT_MAP             — PSTN digit map
DF_DIAL_PLAN               — Default dial plan

# Misc
MACHINE_LIMIT              — Лимит минут (лицензия)
M_LIMIT_TIME               — Оставшееся время лицензии
LINE%d_AUTO_BLACKLIST_IN_ENABLE  — Авто-blacklist
GSM%d_POWER                — Питание GSM-модуля
SIM%d_DT                   — SIM detect time
GPRS_DISABLE               — Отключение GPRS
LINE_LOCK                  — Блокировка линии
SIMPIPE                    — SIM pipe mode
LICDNS                     — License DNS
```

### sip.def (~120 ключей)

```
# Registrar/Proxy
SIP_REGISTRAR              — SIP-регистратор
SIP_PROXY                  — SIP-прокси
SIP_LOCAL_PORT             — Локальный SIP-порт
SIP_OPERATION_MODE         — SIP mode

# Contacts (до 8, с backup)
SIP_CONTACT%d_SERVER       — SIP-сервер (линия N)
SIP_CONTACT%d_PROXY        — SIP-прокси (линия N)
SIP_CONTACT%d_DISABLE      — Отключение контакта
SIP_CONTACT%d_GROUP        — Группа контакта
SIP_LINE%d_GROUP           — Линия в группе

# Auth
SIP_AUTH_ID                — Auth ID
SIP_AUTH_PASSWD            — Auth Password
SIP_CONTACT%d_AUTH_ID      — Per-contact Auth ID
SIP_CONTACT%d_AUTH_PASSWD  — Per-contact Auth Password

# NAT
SIP_NAT_TRAVERSAL          — STUN/RELAY/NONE
SIP_STUN_SERVER            — STUN-сервер
SIP_RELAY_SERVER/1..4      — Relay-серверы
SIP_RELAY_PORT             — Relay-порт
SIP_RELAY_USER / PASSWD    — Relay-авторизация
SIP_RELAY_ENCRYPT          — Шифрование relay
SIP_RANDOM_LC_PORT         — Рандомный локальный порт
RANDOM_LC_PORT_INT         — Интервал смены порта

# Encryption
SIP_CRYPT                  — RC4/ET263/VOS/AVS/N2C/ECM/FAST/NONE
SIP_RC4_KEY                — RC4-ключ (default: "etoall.net")
SIP_ET263_CRYPT_TYPE       — Тип ET263
SIP_ET263_CRYPT_DEP        — Глубина ET263
MG_ET263_CRYPT             — ET263 для RTP

# Config modes
SIP_CONFIG_MODE            — SINGLE_MODE/LINE_MODE/GROUP_MODE/TRUNK_GW_MODE
SIP_REG_MODE               — Registration mode
SIP_EXP_MODE               — Expiry mode
SIP_LINK_TEST              — Link test
SIP_NO_ALIVE               — No alive keepalive
SIP_183                    — Early Media (0/1/2)
SIP_QOS                    — QoS (DIFFSERV/IPTOS)
SIP_INV_AUTH               — INVITE auth
SIP_AS_PROXY               — Act as SIP proxy
SIP_PROXY_PASSWD           — Proxy password
SIP_PREFIX_DEL             — Delete prefix
SIP_RSP_MODE               — Response mode
SIP_CALLEE_MODE            — Callee mode
SIP_SMS_RTN                — SMS return to number
SIP_VIRTUAL_RB_TONE        — Virtual ringback
SIP_MWI                    — Message Waiting Indicator
SIP_CID_FW_MODE            — Caller ID forward mode
SIP_FAIL_RETRY_INTERVAL    — Retry interval
SIP_ROUTE_FIELD_DISABLE    — Disable Route header
POUND_KEY_AS_DIGIT         — # as digit

# Trunk Gateway
SIP_TRUNK_GW1/2/3          — Trunk gateways
SIP_TRUNK_NUMBER           — Trunk number
SIP_TRUNK_REGISTER_EXPIRED — Registration expiry
SIP_TRUNK_AUTH_ID / PASSWD — Trunk auth
SIP_SMODE_USE_BSVR         — Use backup server (single mode)

# Groups
SIP_GROUP_NUM              — Number of groups
```

### h323.def (~140 ключей)

```
# Endpoint mode
H323_ENDPOINT_MODE         — DIRECT_MODE/SINGLE_MODE
H323_CONFIG_MODE           — SINGLE_MODE/LINE_MODE/GROUP_MODE

# Gatekeeper (single mode)
H323_GK_ADDR               — GK address
H323_PHONE_NUM             — Phone number 
H323_ID                    — H.323 ID
H323_GW_PREFIX             — Gateway prefix

# Per-line (LINE_MODE, up to 8)
H323_LINE%d_GKADDR         — GK per line
H323_LINE%d_NUMBER          — Number per line
H323_LINE%d_H323_ID        — H.323 ID per line
H323_LINE%d_GW_PREFIX      — Prefix per line
H323_LINE%d_AUTH            — H.235 auth enable
H323_LINE%d_H235_ID/PASSWD — H.235 credentials
H323_LINE%d_VOS_ENABLE/MODE — VOS encryption per line

# Per-group (GROUP_MODE, up to 8)
H323_GROUP%d_GKADDR         — GK per group
H323_GROUP%d_NUMBER          — Number per group
H323_GROUP%d_H323_ID        — H.323 ID per group
H323_GROUP%d_GW_PREFIX      — Prefix per group
H323_GROUP%d_AUTH            — H.235 auth per group
H323_GROUP%d_H235_ID/PASSWD — H.235 credentials per group
H323_G%d_VOS_ENABLE/MODE    — VOS encryption per group
H323_L%d_IN_G%d             — Line N in Group M

# NAT
H323_NAT_TRAVERSAL          — STUN/RELAY/NONE/CITRON
H323_RELAY_SERVER/1..4      — Relay servers
H323_RELAY_ENCRYPT          — Relay encryption
H323_RELAY_MODE             — Relay mode

# Direct mode
H323_DEFAULT_GATEWAY        — Default GW
H323_TRUNK1/2_GATEWAY       — Trunk gateways
Q931_PORT                   — Q.931 port (default 1720)

# Auth
H235_AUTH                   — H.235 enable
H235_ID / PASSWD            — H.235 credentials

# Misc
H323_QOS                   — QoS mode
H323_DIFFSERV / TOS        — QoS values
```

### user.def (~60 ключей)

```
# Passwords (3 уровня)
USER_PASSWORD              — Уровень пользователя
ADMIN_PASSWORD             — Уровень администратора
SUPER_PASSWORD             — Суперпользователь (скрытый)

# NTP
NTP_SERVER                 — NTP-сервер
NTP_TIMEZONE               — Часовой пояс

# Tones
TONE_SET                   — Набор тонов (страна)

# Auto-config (⚠️)
AUTOCFG_ENABLE             — Включение автонастройки
AUTOCFG_URL                — URL для получения конфига
AUTOCFG_INTERVAL           — Интервал проверки
AUTOCFG_CRYPT              — Шифрование (RC4)
AUTOCFG_KEY                — Ключ шифрования

# DDNS
DDNS_ENABLE                — Включение DDNS
DDNS_ADDR / PORT           — DDNS сервер
DDNS_BACKUP_ADDR / PORT    — Backup DDNS
DDNS_UPDATE_INTERVAL       — Интервал обновления

# Domain Monitoring (до 9 доменов)
MON_DOMAIN1..9             — Мониторимые домены

# HTTP
HTTP_PORT                  — Порт веб-интерфейса

# Login tracking
LAST_LOGIN_IP              — IP последнего входа
LAST_LOGIN_TIME            — Время последнего входа

# SMS Mail (на линию)
LINE%d_MAIL_SVR            — SMTP сервер
LINE%d_MAIL_PORT           — SMTP порт
LINE%d_MAIL_ID             — SMTP логин
LINE%d_MAIL_PASSWD         — SMTP пароль
LINE%d_MAIL_TO             — Email получатель

# Misc
LANG                       — Язык (en_US/zh_CN/zh_TW)
VENID                      — Vendor ID
SN                         — Серийный номер
WAN_ADDR                   — WAN IP-адрес
```

### smb.def (7 ключей)

```
SMB_SVR                    — SIM Bank сервер
SMB_ID                     — Идентификатор
SMB_KEY                    — Пароль
SMB_RC4_KEY                — RC4-ключ для шифрования
RMSIM_ENABLE               — Включение Remote SIM
NET_TYPE                   — Тип сети
RMSIM                      — Remote SIM
```

### smpp.def (6 ключей)

```
SMPP_PORT                  — Порт SMPP-сервера
SMPP_ID                    — System ID
SMPP_KEY                   — Password
SMPP_ENABLE                — Включение
SMPP_GNUM_EN               — GSM Number enable
ENROUTE_DISABLE            — Отключение ENROUTE DLR
```

### fvdsp.def (17 ключей)

```
LINE0..7_VOL               — Громкость линии (приём)
LINE0..7_VOL_E             — Громкость линии (передача)
FVDSP_STATE                — Состояние DSP
```

---

## 14. СТАРТОВЫЕ СКРИПТЫ

### start_ata

Главный стартовый скрипт — запускает `ata` с параметрами на основе конфигурации. Читает `TELPORT`, `ENDPOINT_TYPE`, инициализирует каналы.

### start_sip

Самый сложный скрипт (~200 строк). Собирает полную командную строку для `sipcli`:

1. **Конфигурация шифрования** (7 крипто-режимов)
2. **QoS** (DIFFSERV/IPTOS)
3. **NAT traversal** (STUN/RELAY с до 4 backup-серверами)
4. **Vendor ID** → User-Agent (`et`/`et263` → `HYBERTONE`)
5. **SIP-параметры** (ptime, DTMF, MWI, CID, early media, proxy mode, etc.)
6. **Trunk Gateway mode** — 3 trunk + routing + auth
7. **Single mode** — один SIP account + port randomization

Запуск:
```bash
exec /usr/bin/sipcli --line-prefix 1 --gateway 1 $SIP_PARAMS $sip_tos $nat_params $sip_crypt
# ИЛИ для SINGLE_MODE:
exec /usr/bin/sipcli --line-prefix 1 --syscfg $SIP_PARAMS $sip_tos $nat_params $sip_crypt
```

### start_mg

Конфигурация Media Gateway:
1. Кодеки (6 позиций, можно отключать `!`)
2. Fax (T.38/G.711)
3. NAT traversal (RELAY с до 4 backup + UDP-over-TCP)
4. Шифрование (RC4/ET263)
5. QoS
6. RTP reporting

### start_fvdsp

```bash
cd /var/run/voip
exec /usr/bin/fvdsp
```

### start_smb

```bash
while [ "${AREA}" = "CHN" -a "${REMOTE_SIM}" = "0" ]; do
    sleep 3600    # В Китае без Remote SIM — бесконечный sleep
done
sleep 2
exec /usr/bin/smb_module -t 50
```

**Примечание:** В регионе `CHN` без Remote SIM — SIM Bank отключён (вечный sleep).

### start_radm

```bash
[ -z "${RADMIN_KEY}" ] && RADMIN_KEY="dbl#admin"    # DEFAULT KEY!
[ -z "${RADMIN_PORT}" ] && setsyscfg RADMIN_PORT=1920

HTTP_PORT=`getsyscfg HTTP_PORT`  # default 80
TPORT=13000                       # telnet port
[ "${FTN}" = "1" ] && TPORT=23    # или стандартный telnet

exec /usr/bin/radmcli -r ${RADMIN_SERVER}:${RADMIN_PORT} \
    -al 127.0.0.1:$HTTP_PORT \
    -ll 127.0.0.1:$TPORT \
    -k "${RADMIN_KEY}" -i "$id" -t 30
```

### start_ipp

H.323 Endpoint — наиболее сложный скрипт (~400 строк):
1. PPTP VPN check
2. QoS (DIFFSERV/IPTOS)
3. Три режима: SINGLE_MODE, LINE_MODE (×8 линий), GROUP_MODE (×8 групп)
4. Для каждой линии/группы: GK, H.323 ID, prefix, H.235, VOS
5. DIRECT_MODE: Q.931 port 1720 + trunk gateways
6. NAT: STUN/RELAY/CITRON + relay extensions

### start_ddnscli

DNS resolver, до 9 доменов из SIP-конфигурации + SMB_SVR.

### start_httpd

```bash
setsyscfg WD_TIMER=100            # Быстрый watchdog при старте
HTTP_PORT=`getsyscfg HTTP_PORT`   # default 80

# Поиск index файла по VENID/LANG:
# /usr/share/httpd/${VENID}/${LANG}/index.html
# /usr/share/httpd/${VENID}/index.html
# /usr/share/httpd/default/${LANG}/status.html

exec /usr/sbin/httpd -r /usr/share/httpd -i $index -p $HTTP_PORT
```

### start_imeimon

```bash
echo IMEISET > /etc/ipin
while true; do
    sleep 3600    # Бесконечный цикл, просыпаясь раз в час
done
```

### start_ntp2

```bash
exec /usr/sbin/ntp2 -h www.gontp.com -c 4 -i 1800
```
— Синхронизация с `www.gontp.com` каждые 30 минут.

### start_waddrmon

Мониторинг WAN-адресов SIP-прокси (до 8 доменов в LINE_MODE):
```bash
setsyscfg MON_DOMAIN1=${SIP_PROXY}           # SINGLE_MODE
# ИЛИ
setsyscfg MON_DOMAIN1..8=${SIP_CONTACT0..7_PROXY}  # LINE_MODE
exec /usr/sbin/mon_waddr
```

### start_sip_port_change

Периодический перезапуск sipcli для смены SIP-порта (anti-tracking):
```bash
if [ "${SIP_RANDOM_LC_PORT}" = "1" ]; then
    interval=$(expr ${RANDOM_LC_PORT_INT} * 60)
    while true; do
        sleep $interval
        killall sipcli    # svcd автоматически перезапустит с новым портом
    done
fi
```

### stop_fvdsp / stop_mg

```bash
killall fvdsp
killall /usr/bin/mg
```

---

## 15. ПОДДЕРЖИВАЕМЫЕ ПРОТОКОЛЫ

| Протокол | Стандарт | Порт | Бинарник | TLS | Описание |
|----------|---------|------|----------|-----|----------|
| **SIP** | RFC 3261 | 5060/UDP | sipcli | ❌ | VoIP signaling, GNU oSIP |
| **RTP/RTCP** | RFC 3550 | dynamic/UDP | mg | ❌ | Media transport |
| **DTMF** | RFC 2833 | via RTP | mg, fvdsp | — | Tone signaling |
| **T.38** | ITU-T | via RTP | mg, fvdsp | — | Fax relay |
| **STUN** | RFC 3489 | 3478/UDP | sipcli, mg | ❌ | NAT traversal (без HMAC!) |
| **H.323** | ITU-T | 1720/TCP | ipp | ❌ | VoIP (H.225/Q.931/H.245/RAS) |
| **H.235** | ITU-T | via H.323 | ipp | — | H.323 security |
| **SMPP** | v3.4 | config/TCP | smpp_smsc | ❌ | SMS gateway |
| **SMTP** | RFC 5321 | 25/TCP | smail | ❌ | Email (AUTH LOGIN) |
| **HTTP** | RFC 2616 | 80/TCP | httpd | ❌ | Web management |
| **HTTPS** | — | 443/TCP | up | ✅ | Firmware download only |
| **FTP** | RFC 959 | 21/TCP | up | ❌ | Firmware download |
| **TFTP** | RFC 1350 | 69/UDP | up | ❌ | Firmware download |
| **PPPoE** | RFC 2516 | — | pppoecd | ❌ | WAN connection |
| **NTP** | — | custom | ntp2 | ❌ | Time sync (www.gontp.com) |
| **DDNS** | proprietary | 39800/TCP | dnscli | ❌ | DNS update |
| **SMB** | proprietary | config/TCP | smb_module | ❌ | SIM Bank |
| **RADMIN** | proprietary | 1920/TCP | radmcli | ❌ | Remote admin tunnel |
| **Relay** | proprietary (V5) | config/TCP+UDP | sipcli, mg | ❌ | NAT traversal relay |
| **syscfg** | proprietary | Unix DGRAM | svcd, all | — | Config IPC |
| **FVDSP IPC** | proprietary | Unix DGRAM | fvdsp, mg | — | DSP control |
| **Echo** | proprietary | 54210/UDP | rstdt | ❌ | Network discovery |
| **IPSec** | ESP/IKE | — | fv_alg_esp/ipsec | — | ALG only |
| **L2TP** | — | 1701/UDP | fv_alg_l2tp | — | ALG only |

⚠️ **Из 22 протоколов только firmware download (HTTPS) поддерживает TLS. Всё остальное — plaintext.**

---

## 16. АУДИО И КОДЕКИ

### Аппаратные кодеки (fvaci.ko)

| Кодек | Тип | Описание |
|-------|-----|----------|
| G.711 A-law | HW | Аппаратное кодирование/декодирование |
| G.711 μ-law | HW | Аппаратное кодирование/декодирование |
| DTMF | HW | Goertzel-фильтры (8 частот) |
| Caller ID | HW | FSK Bell 202 декодирование |

### Программные кодеки (fvdsp — HSmedia v3.7)

| Кодек | API | Bit rates |
|-------|-----|-----------|
| G.723.1 | `hsmm_g7231_init` | 5.3 / 6.3 kbps |
| G.729A/AB | `hsmm_g729ab_init` | 8 kbps |
| GSM FR | `hsmm_gsm_init` | 13 kbps |
| G.722 | `hsmm_g722_init` | 64 kbps (wideband) |
| iLBC | `hsmm_ilbc_init` | 13.3 / 15.2 kbps |
| AMR-NB | `hsmm_amrnb_init` | 4.75 / 5.15 / 5.9 / 6.7 / 7.4 / 7.95 / 10.2 / 12.2 kbps |
| T.38 Fax | `hsmm_t38_init` | variable (v3.23) |
| RFC 2833 | `hsmm_rfc2833_init` | OOB DTMF |

### Наборы тонов (22 страны)

`AR`, `AT`, `AU`, `BE`, `BR`, `CH`, `CL`, `CN`, `CZ`, `DE`, `DK`, `FI`, `FR`, `GR`, `HU`, `IL`, `IN`, `IT`, `JP`, `NL`, `NO`, `NZ`, `PT`, `RU`, `SE`, `SG`, `TW`, `UK`, `US`

Каждый набор содержит:
- Dial tone (непрерывный/cadenced)
- Busy tone
- Ring-back tone
- Congestion tone
- Call waiting tone

---

## 17. GSM-МОДУЛИ И МОДЕМЫ

### Поддерживаемые модули

| Модуль | Производитель | Технология | Особенности |
|--------|-------------|-----------|-------------|
| **Quectel M25** | Quectel | GSM/GPRS | Основной, `M25MAR01A01_RSIM` |
| **Quectel EC20** | Quectel | LTE Cat4 | 4G, `EC20CEFDGR06A07M4G` |
| **GTM900** | Fibocom | GSM/GPRS | `+GTSET` команды |
| **SIMCOM** | SIMCom | GSM/GPRS | Стандартные AT |
| **H330** | — | GSM/GPRS | — |
| **ME200** | — | GSM/GPRS | `+MMICG`/`+MAVOL` |
| **MC8618** | — | CDMA | CDMA PDU SMS |
| **G610** / **G610-Q20** | — | GSM | Вариант устройства |

### Инициализация модуля

```
1. GPIO → включение питания
2. AT → проверка ответа
3. ATE0 → echo off
4. AT+IPR=115200&W → скорость UART
5. AT+CMEE=2 → расширенные ошибки
6. AT+CPIN? → проверка SIM/PIN
7. AT+CFUN=1 → full functionality
8. AT+CREG=2 → registration URC
9. AT+CSQ → signal quality
10. AT+COPS=3,0 → operator name format
11. AT+CIMI → IMSI
12. AT+CCID → ICCID
13. AT+CMGF=0 → SMS PDU mode
14. AT+CNMI=1,2,2,0,1 → SMS notifications
15. AT+CLIP=1 → Caller ID
16. AT+CSSN=0,1 → SS notifications
```

### Управление питанием модулей

- `GSM%d_POWER` — состояние питания модуля N
- GPIO через `/dev/gpio0` — аппаратное включение/выключение
- `AT+CFUN=0` — software power down
- `AT+CFUN=15` — factory reset
- `GSMReboot`/`GSMDLReboot` — программная перезагрузка

---

## 18. SIM-МЕНЕДЖМЕНТ

### Локальная SIM

- Физическая SIM-карта вставлена в слот устройства
- `SIMPIPE=0` — локальная SIM
- Детектирование SIM через GPIO

### Remote SIM (SIM Bank)

- `RMSIM_ENABLE=1` — включение
- `AT+QCFG="SIM/Type",1` — переключение на remote SIM
- `AT+GTSET="SIMPIPE",1/2` — SIM pipe mode (GT-модули)
- APDU-проксирование через smb_module

### SIM Rotation

- `L%d_SIM_STRP_NUM` — номер позиции в ротации
- `L%d_SIM_STRP_TIME` — время на позицию
- Автоматическое переключение между SIM-картами по расписанию

### SIM Expiry

- `LINE%d_SIM_EXP` — срок использования SIM
- `LINE%d_SIM_REMAIN` — оставшееся время
- `L%d_SIM_EXP_UNIT` — единица (мин/час/день)
- `L%d_SIM_CALL_LIMIT` — лимит вызовов на SIM
- `ALL_SIM_EXP_RESET` — сброс всех таймеров
- `MEXPIRY` — сигнал истечения SIM

### SMS по SIM

```
Входящий SMS с содержимым:
  "SIMEXP RESET" → сброс SIM expiry таймера
  "GSMNUM" → ответ с номером GSM
  "###INFO###" → ответ: IP, IMEI, версия, @eth0_ip, @ppp0_ip
  "REBOOT" → перезагрузка устройства
```

---

## 19. IMEI-МЕНЕДЖМЕНТ

### ⚠️ ПРЕДУПРЕЖДЕНИЕ: Смена IMEI нелегальна в большинстве стран

### Режимы IMEI

| Ключ | Значение | Описание |
|------|----------|----------|
| `IMEI_CHANGE` | 0/1 | Разрешение смены |
| `IMEI_AUTO_ENABLE` | 0/1 | Автоматическая смена |
| `IMEI_AUTO_T` | секунды | Интервал автосмены |
| `IMEI_RANDOM` | 0/1 | Рандомный IMEI |

### Формат генерации

```
Фиксированный: AT+EGMR=1,7,"<USER_SUPPLIED_IMEI>"
Полуслучайный: AT+EGMR=1,7,"<PREFIX>%.7d"  (базовый TAC + 7 случайных цифр)
Полностью случайный: AT+EGMR=1,7,"<RANDOM_15_DIGITS>"
```

### IPC-команды IMEI

| Команда | Описание |
|---------|----------|
| `IMEISET` | Запрос установки IMEI (от start_imeimon) |
| `MIMEIRS` | IMEI Reset Signal (от smb_module) |
| `MRSIMEI<IMEI>` | Set Remote SIM IMEI |

### Поддержка по модулям

| Модуль | Команда смены IMEI |
|--------|-------------------|
| Quectel | `AT+EGMR=1,7,"<IMEI>"` |
| GT | `AT+GTSET="GTIMEI","<IMEI>"` |
| Другие | `AT+EGMR=1,7,"<IMEI>"` |

---

## 20. СИСТЕМА ЛИЦЕНЗИРОВАНИЯ

### Архитектура

```
GoIP (ata/lic.c)  ──TCP──►  Сервер лицензий
                            (LIC_SERVER:LIC_PORT)

Регистрация: "lic:%d;sn:%.64s;"
```

### Параметры

| Ключ | Default | Описание |
|------|---------|----------|
| `LIC_SERVER` | `192.168.2.1` | Сервер лицензий |
| `LIC_PORT` | — | Порт |
| `LIC_INTERVAL` | — | Интервал проверки |
| `LIC_SERVER_KEY` | `root#admin` | Ключ сервера |
| `LIC_CLI_ENABLE` | — | Включение клиента |
| `MACHINE_LIMIT` | — | Лимит минут |
| `M_LIMIT_TIME` | — | Оставшееся время |

### Периферийные ключи лицензирования

- `LICDNS` — DNS лицензий
- `118.142.51.162:7540` — hardcoded в syscfg.constant.dbl_lic
- Включает `SUPER_USER`, `SUPER_PASSWORD`, `RADMIN_*` — лицензия может активировать backdoor

---

## 21. OEM-ВАРИАНТЫ (VENID)

Прошивка поддерживает ребрендинг через `VENID`:

| VENID | Бренд | Особенности |
|-------|-------|-------------|
| `dbl` | DBLTek | Основной бренд |
| `dble` | DBLTek Extended | — |
| `et` / `et263` | HYBERTONE | User-Agent = "HYBERTONE" |
| `pak` | Doodle-do | SN prefix = `doodle-` |
| `A100` | A100 | Суперюзер: `spadmin` |
| `Bernie` | Bernie | — |
| `CMS` | CMS | Пароль: `cL2@M#a$@b%g3247` |
| `EC` | EC | — |
| `ipconnex` | ipconnex | Autocfg: `provisioning.bledi.tel`, пароль: `a/tq*rJd0Gd)6v` |
| `oxmundi` | Oxmundi | — |
| `perse` | Perse | — |
| `speak2phone` | Speak2Phone | — |
| `VOIspeed-GSM` | VOIspeed | — |

Каждый VENID имеет свой `syscfg.default.${VENID}` и свой набор Web UI файлов в `/usr/share/httpd/${VENID}/`.

---

## 22. ЗАХАРДКОЖЕННЫЕ УЧЁТНЫЕ ДАННЫЕ

### 🔴 Критические

| Учётные данные | Значение | Бинарник | Контекст |
|----------------|----------|----------|----------|
| Root password | *(пустой)* | passwd file | `root::0:0:root:/root:/bin/ash` |
| RADMIN key | `dbl#admin` | radmcli, start_radm | Reverse tunnel encryption key |
| LIC server key | `root#admin` | ata (lic.c) | License server auth |

### 🟠 Высокие

| Учётные данные | Значение | Контекст |
|----------------|----------|----------|
| RC4 config suffix | `@dbl` | backup_config/restore_config |
| Default SIP RC4 key | `etoall.net` | syscfg.default |
| Default admin password | `admin` | syscfg.default |
| Default user password | `1234` | syscfg.default |
| Default SMS password | `1234` | syscfg.default |
| Default SIP auth password | `123456` | syscfg.default.pak |

### 🟡 Средние

| Учётные данные | Значение | Контекст |
|----------------|----------|----------|
| ECM crypt key | `voippassword` | sipcli (ECM_CRYPT_KEY) |
| SDP token | `4e52e09f` | sipcli (session ID) |
| CMS admin password | `cL2@M#a$@b%g3247` | syscfg.default.CMS |
| ipconnex admin | `a/tq*rJd0Gd)6v` | syscfg.default.ipconnex |
| Superuser (A100) | `spadmin` | syscfg.constant.A100 |
| Bug report email | `bug@fspipsev.net` | smail, rstdt |
| SDP origin | `o=userX 20000001 20000001` | sipcli |
| User-Agent | `DBL SIP` | sipcli |

### CPU ID как ключ

**ioctl** использует CPU serial number + `@dbl` как RC4-ключ для шифрования boot-файлов. CPU ID можно получить через `/proc/cpuinfo` — это НЕ секрет.

---

## 23. ЗАХАРДКОЖЕННЫЕ IP-АДРЕСА И ДОМЕНЫ

### IP-адреса

| IP | Бинарники | Расположение | Назначение |
|----|-----------|-------------|-----------|
| `118.140.127.90` | radmcli | Гонконг | RADM backdoor сервер #1 |
| `47.242.142.229` | radmcli | Alibaba Cloud HK | RADM backdoor сервер #2 |
| `202.104.186.90` | radmcli | Shenzhen Telecom | RADM backdoor сервер #3 |
| `202.96.136.145` | ipp, mg, smail, radmcli, rstdt, smb_module, smpp_smsc | China Telecom | Hardcoded DNS |
| `61.141.247.7` | smail, radmcli, rstdt | Shenzhen, Guangdong | Bug report SMTP server |
| `192.168.2.71` | up | Internal dev network | Firmware download dev URL |
| `192.168.2.1` | ata (lic.c) | Internal | License server default |
| `118.142.51.162` | syscfg.constant | — | License DNS server |
| `114.114.114.114` | syscfg.default | 114DNS (China) | Public DNS |
| `8.8.8.8` | syscfg.default | Google | Public DNS |

### Домены

| Домен | Бинарник | Назначение |
|-------|----------|-----------|
| `fspipsev.net` | smail, radmcli, rstdt, dnscli, ntp | Bug report SMTP server |
| `www.gontp.com` | start_ntp2 | NTP server (DBL Technology) |
| `voipddns.net:39800` | syscfg.default | DDNS server |
| `dbltek.com:39800` | syscfg.default | Backup DDNS server |
| `provisioning.bledi.tel` | syscfg.default.ipconnex | Auto-config server (ipconnex) |
| `sip.doodle-do.com:8012` | syscfg.default.pak | SIP proxy (Doodle-do) |
| `pool.ntp.org` | ntp | Fallback NTP |

---

## 24. УЯЗВИМОСТИ И BACKDOOR

### 🔴 КРИТИЧЕСКИЕ (8)

| # | Уязвимость | Бинарник | Описание | CVSS* |
|---|-----------|----------|----------|-------|
| 1 | **Пустой root пароль** | passwd | `root::0:0` — полный доступ по telnet/SSH | 10.0 |
| 2 | **Hardcoded RADM ключ** | radmcli | Ключ `dbl#admin` одинаков для ВСЕХ устройств | 9.8 |
| 3 | **3 backdoor IP** | radmcli | Все устройства подключаются к 3 IP в Китае/Гонконге | 9.8 |
| 4 | **Reverse tunnel без TLS** | radmcli | XOR-шифрование ≈ plaintext | 9.1 |
| 5 | **IMEI auto-change** | ata | Нелегальная смена IMEI в большинстве стран | 8.5 |
| 6 | **CPU ID как crypto ключ** | ioctl | CPU serial — не секрет, key recovery trivial | 8.0 |
| 7 | **SMS → REBOOT** | ata | Удалённая перезагрузка через SMS | 8.0 |
| 8 | **SMS → INFO disclosure** | ata | `###INFO###` → IP, IMEI, версия, пароли | 9.0 |

### 🟠 ВЫСОКИЕ (8)

| # | Уязвимость | Бинарник | Описание |
|---|-----------|----------|----------|
| 1 | RC4 для config backup | decrypt.RC4 | Устаревший, предсказуемый суффикс `@dbl` |
| 2 | STUN без HMAC | sipcli, mg | Аутентификация не реализована |
| 3 | SMTP без TLS | smail | Bug reports и SMS-to-email в plaintext |
| 4 | SMPP без TLS | smpp_smsc | SMS-трафик не шифруется |
| 5 | SIP без TLS/SRTP | sipcli | Все VoIP сигналы в plaintext |
| 6 | Web UI без HTTPS | httpd | Пароли передаются в plaintext (Basic Auth) |
| 7 | Self-parsing ELF | sipcli | Anti-tampering / anti-debug |
| 8 | H.235 но устаревший | ipp | Слабые алгоритмы |

### 🟡 СРЕДНИЕ (6)

| # | Уязвимость | Описание |
|---|-----------|----------|
| 1 | SIP Anti-spam фильтр | Блокировка по User-Agent (RTC/1.2, SJPhone) |
| 2 | NTP через www.gontp.com | Проприетарный NTP-сервер DBL |
| 3 | Bug reports на fspipsev.net | Телеметрия без согласия |
| 4 | Нет ASLR/PIE/Stack Protector | GCC 3.3.5 — нет modern mitigations |
| 5 | Firmware update dev URL | `http://192.168.2.71/` в продакшен-коде |
| 6 | Default passwords | `admin`/`1234`/`1234` для web/user/SMS |

### 🔵 ИНФОРМАЦИОННЫЕ (4)

| # | Находка | Описание |
|---|---------|----------|
| 1 | Разработчик `Jason` | Имя в STUN-коде sipcli |
| 2 | Оператор-специфические строки | Chunghwa Telecom, CMCC, UNICOM, Globe (Тайвань/Китай/Филиппины) |
| 3 | GB2312 таблица | Поддержка китайского для SMS |
| 4 | ELF: no .symtab | Stripped — затруднение анализа |

---

## 25. ПОЛНАЯ КАРТА IPC-СОКЕТОВ И ФАЙЛОВ

### Визуализация

```
┌──────────────────────────────────────────────────────────────────────┐
│                     IPC SOCKET MAP                                    │
├──────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  /tmp/.syscfg-server (DGRAM) ◄──────── ALL PROCESSES                │
│       │                                                              │
│       ▼                                                              │
│  ┌──svcd──┐                                                          │
│  │ Config │ ────► /tmp/svcctl (STREAM) ◄── service control           │
│  │ Store  │                                                          │
│  └────────┘                                                          │
│                                                                      │
│  ┌──ata───┐ ◄── /etc/ipin (FILE) ◄── ALL echo pipe writers          │
│  │  GSM   │                                                          │
│  │ Ctrl   │ ──► /tmp/.fvdsp_cmd_in ──► ┌──fvdsp──┐                  │
│  │        │                             │  DSP    │                  │
│  │        │ ◄── /tmp/.smb%d ◄────────── │ daemon  │                  │
│  │        │                             └────┬────┘                  │
│  │        │ ──► /tmp/.ippui%d ──►            │                       │
│  └────────┘                          /tmp/.fvdsp_mgcmd%d             │
│                                      /tmp/.fvdsp_data_in%d           │
│  ┌─sipcli─┐                         /tmp/.fvdsp_data_out%d           │
│  │  SIP   │ ──► /tmp/mg%d ──────► ┌──mg──┐      │                   │
│  │  B2BUA │                        │Media │ ◄────┘                   │
│  └────────┘                        │ GW   │                          │
│                                    └──────┘                          │
│  ┌──smb_module──┐                                                    │
│  │  SIM Bank    │ ──► /tmp/.smb%d ──► ata                            │
│  │  Client      │ ──► /tmp/.smb_cli%d (CLI)                         │
│  └──────────────┘                                                    │
│                                                                      │
│  ┌──httpd──┐ ──► /tmp/mdb.str (Mini DB)                             │
│  │ Web UI  │ ◄── /tmp/.upgrd_info (upgrade status)                  │
│  └─────────┘                                                         │
│                                                                      │
│  ┌──radmcli──┐ ──► TCP → RADMIN_SERVER (reverse tunnel)             │
│  │  Remote   │ ◄── /etc/ramdcli (FIFO)                              │
│  │  Admin    │ ──► 127.0.0.1:80 (httpd)                             │
│  │           │ ──► 127.0.0.1:13000 (telnet)                         │
│  └───────────┘                                                       │
│                                                                      │
│  ┌──sysinfod──┐ ◄── /tmp/.sysinfo.sock (DGRAM)                     │
│  │  Sys Info   │ ◄── /tmp/.sysinfo (FIFO)                           │
│  └────────────┘                                                      │
│                                                                      │
│  ┌──dnscli──┐ ──► /var/tmp/hosts (DNS file)                         │
│  └──────────┘                                                        │
│                                                                      │
│  ┌──up──┐ ──► /dev/mtdblock/* (firmware write)                      │
│  │Update│ ──► /tmp/.upgrd_info (status)                             │
│  └──────┘                                                            │
└──────────────────────────────────────────────────────────────────────┘
```

---

## 26. ТЕЛЕМЕТРИЯ ПРОИЗВОДИТЕЛЯ

### Bug Report система

**Встроена в ~8 бинарников** (ata, sipcli, mg, rstdt, smail, dnscli, ntp, smpp_smsc).

| Параметр | Значение |
|----------|----------|
| SMTP сервер | `fspipsev.net` (IP: `61.141.247.7` — Shenzhen, Guangdong, China) |
| Email | `bug@fspipsev.net` |
| HELO | `fspipsev.net` |
| Формат | `bugreport: E%.03d` |
| Содержимое | Crash dump, call stack, `/proc/%d/maps` |
| Шифрование | ❌ Нет (plaintext SMTP) |
| Согласие пользователя | ❌ Нет |

### Данные, передаваемые при bug report

- Stack trace и crash dump
- Карта памяти процесса
- Серийный номер устройства
- IP-адрес
- Версия прошивки

### NTP-сервер

- `www.gontp.com` — проприетарный NTP-сервер DBL Technology
- Синхронизация каждые 30 минут
- Устройство всегда подключается к серверу производителя

### DDNS-сервер

- `voipddns.net:39800` — проприетарный DDNS
- `dbltek.com:39800` — backup
- Устройство регулярно обновляет DNS-запись с текущим IP

### DNS-сервер

- `202.96.136.145` — China Telecom DNS hardcoded в нескольких бинарниках
- Fallback при невозможности resolv.conf

---

## 27. ANTI-FRAUD СИСТЕМА

### Мониторинг качества вызовов

| Метрика | Ключи | Описание |
|---------|-------|----------|
| **ACD** (Average Call Duration) | `LINE%d_ACD`, `ACD_LOW_THR`, `ACD_LOW_ACT` | Средняя длительность → действие при низком |
| **ASR** (Answer-Seizure Ratio) | `LINE%d_ASR`, `ASR_LOW_THR`, `ASR_LOW_ACT` | Отношение ответ/попытка → действие при низком |
| **RSSI** (Signal Strength) | `RSSI_H`, `RSSI_L` | Пороги уровня сигнала |
| **No Alert** | `NOALT_LIMIT`, `NOALT_ACT` | Нет звонка → действие |
| **No Connect** | `NOCNT_LIMIT`, `NOCNT_ACT` | Нет соединения → действие |
| **Short Call** | `SCALL_LIMIT`, `SCALL_LEN_LIMIT`, `SCALL_ACT` | Короткие вызовы → действие |
| **No Answer Streak** | `SANS_C`, `SANS_T`, `SANS_ACT` | Серия без ответа → действие |

### Действия при нарушении

- Перезагрузка модуля
- Смена SIM (ротация)
- Смена IMEI
- Смена BST (базовой станции)
- Отключение линии

### Auto-Blacklist

- `LINE%d_AUTO_BLACKLIST_IN_ENABLE` — авто-blacklist входящих
- `AUTO_BLACKLIST_IN` — глобальный blacklist
- Автоматическая блокировка номеров по паттернам

### BST Anti-tracking

- `LINE%d_GSM_BST` = `POLL` — ротация базовых станций
- `LINE%d_BST_SW_INT` — интервал переключения
- `LINE%d_MAX_POLL_BST` — максимум BST в ротации
- **Цель:** затруднение отслеживания SIM-бокса оператором

### SIP Port Randomization

- `SIP_RANDOM_LC_PORT=1` — включение
- `RANDOM_LC_PORT_INT` — интервал (в минутах)
- `start_sip_port_change` — killall sipcli каждые N минут
- **Цель:** затруднение fingerprinting SIP-устройства

---

## 28. SMS-ПОДСИСТЕМА

### Архитектура

```
                    ┌──────────────────────┐
                    │      SMS Router      │
                    │    (ata / pdu.c)     │
                    └──────┬──────┬────────┘
                           │      │
              ┌────────────┼──────┼────────────┐
              │            │      │            │
         ┌────┴────┐ ┌─────┴──┐ ┌┴──────┐ ┌───┴────┐
         │  GSM    │ │  UDP   │ │ SMPP  │ │ Email  │
         │ AT+CMGS │ │ Server │ │ Server│ │ smail  │
         │         │ │(:5000) │ │       │ │        │
         └─────────┘ └────────┘ └───────┘ └────────┘
              ↓           ↑         ↑          ↓
         GSM Network   UDP Client  SMPP     SMTP Server
                                  Client
```

### Кодировки SMS

| Формат | Функция | Описание |
|--------|---------|----------|
| GSM 7-bit | `bit7toascii` | Стандартный GSM |
| UCS-2 | `utf8toucs2` | Юникод |
| GB2312 | `gb2312toucs2` | Китайский |
| ASCII | `ascii2bit7` | Latin |

### Длинные SMS (Concatenation)

- UDH (User Data Header) для конкатенации
- `text_udh_encode` — кодирование UDH
- Формат частей: `(%2.2d/%2.2d)` — часть/всего
- Поддержка CDMA PDU: `cdma_pdu_encode`, `cdma_pdu_udh_encode`

### SMS-по-команде

| SMS Content | Действие |
|-------------|----------|
| `REBOOT` | Перезагрузка устройства |
| `SIMEXP RESET` | Сброс SIM expiry |
| `GSMNUM` | Ответ с GSM номером |
| `###INFO###` | Ответ: IP, IMEI, версия, LAN |

### SMS Mail (on-per-line)

Для каждой линии:
```
LINE%d_MAIL_SVR     = SMTP сервер
LINE%d_MAIL_PORT    = порт
LINE%d_MAIL_ID      = логин
LINE%d_MAIL_PASSWD  = пароль
LINE%d_MAIL_TO      = получатель
```

### SMS Limits

```
LINE%d_SMS_INTERVAL  = минимальный интервал (сек)
LINE%d_SMS_LIMIT     = максимум SMS
LINE%d_SMS_REMAIN    = остаток
SMS_RESET            = сброс счётчиков
```

---

## 29. CDR — УЧЁТ ВЫЗОВОВ

### Формат записи CDR

```
%s,%d,%d%02d%02d%02d%02d%02d,%d%02d%02d%02d%02d%02d,%d%02d%02d%02d%02d%02d,%d,0
│   │  └── время начала ──┘  └── время ответа ──┘  └── время конца ──┘  │
│   └── направление (0=in, 1=out)                                       │
└── ID записи                                                     длительность (сек)
```

### Хранение

- Путь: `/tmp/cdr`
- Индекс: `CDR_INDEX` (syscfg)
- Автосброс: `AUTO_RESET_CDR` + `RESET_CDR_TIME`

### Статистика на линию

| Ключ | Описание |
|------|----------|
| `LINE%d_ACD` | Average Call Duration (сек) |
| `LINE%d_ASR` | Answer-Seizure Ratio (%) |
| `LINE%d_CALLC` | Количество вызовов |
| `LINE%d_DIALC` | Количество попыток |
| `LINE%d_CALLT` | Общее время вызовов (сек) |

---

## 30. ПОЛНЫЙ СПИСОК SYSCFG-КЛЮЧЕЙ

### Статистика

| Файл .def | Ключей | Категория |
|-----------|--------|-----------|
| ata.def | ~260 | GSM, SIM, SMS, CDR, IMEI, BST, anti-fraud |
| h323.def | ~140 | H.323, GK, H.235, группы, линии |
| sip.def | ~120 | SIP, registration, auth, NAT, encryption, trunk |
| common.def | ~85 | Кодеки, RTP, NAT, VPN, RADMIN |
| user.def | ~60 | Пароли, NTP, DDNS, autocfg, domain monitoring |
| fvdsp.def | 17 | DSP громкость |
| smb.def | 7 | SIM Bank |
| smpp.def | 6 | SMPP SMS |
| **ИТОГО** | **~695** | — |

### Дополнительные runtime-ключи (не в .def файлах)

| Ключ | Описание |
|------|----------|
| `WD_TIMER` | Watchdog timer (мс) |
| `UPTIME` | Время работы |
| `WAN_ADDR` | WAN IP |
| `VPN_STATUS` | VPN status |
| `PHONE_NUMBER` | H.323/SIP номер |
| `ENDPOINT_TYPE` | SIP/H323 |
| `UPGRD_STAGE` | Стадия обновления |
| `UPGRD_ERROR` | Ошибка обновления |
| `UPGRD_PERCENTAGE` | Прогресс обновления |
| `VPN_DNS` | VPN DNS |
| `LAN_PORT_STATE` | Состояние LAN |
| `RESET_KEY` | Кнопка сброса |
| `USE_INTERFACE` | Активный интерфейс |
| `GATE_METRIC` | Метрика шлюза |
| `GATE_TIMEOUT` | Таймаут шлюза |
| `FVDSP_STATE` | Состояние DSP |

---

## 31. СТАТИСТИКА ПРОШИВКИ

### Общие цифры

| Метрика | Значение |
|---------|----------|
| **ELF-бинарники** | 22 (usr/bin: 13, usr/sbin: 6, sbin: 5, bin: 4) |
| **Shell-скрипты** | 30+ (usr/bin: 15 start/stop + 8 utils, usr/sbin: 7+) |
| **Kernel модули** | 31 .ko файлов |
| **Конфигурационные файлы** | 8 .def файлов, ~695 ключей |
| **Общий размер бинарников** | ~3.5 МБ |
| **Крупнейший бинарник** | fvdsp (903 KB) |
| **Наибольший код** | sipcli (.text = 600+ KB) |
| **SquashFS rootfs** | ~4 МБ (сжатый) |

### Бинарники по размеру

| Бинарник | Размер | Тип |
|----------|--------|-----|
| fvdsp | 903 KB | DSP daemon |
| sipcli | 658 KB | SIP B2BUA |
| ipp | 540 KB | H.323 endpoint |
| ata | 317 KB | GSM controller |
| busybox | 156 KB | Base utilities |
| up | 120 KB | Firmware updater |
| svcd | 91 KB | Service controller |
| pppoecd | 85 KB | PPPoE client |
| sh | 73 KB | Shell |
| httpd | 71 KB | Web server |
| smb_module | 68 KB | SIM Bank |
| ntp | 51 KB | NTP client |
| radmcli | 51 KB | Remote admin |
| smail | 47 KB | SMTP client |
| smpp_smsc | 43 KB | SMPP server |
| rstdt | 43 KB | Watchdog |
| dnscli | 43 KB | DDNS client |
| mon_waddr | 39 KB | WAN monitor |
| udhcpd | 32 KB | DHCP server |
| udhcpc | 32 KB | DHCP client |
| brctl | 22 KB | Bridge utils |
| pppmon | 14 KB | PPP monitor |
| init | 13 KB | Init |
| hwinfo | 11 KB | HW info |
| ping2 | 10 KB | Ping |
| sysinfod | 7 KB | Sysinfo daemon |
| unimac | 7 KB | MAC generator |
| getipbyname | 6 KB | DNS resolver |
| decrypt.RC4 | 6 KB | RC4 crypto |
| ioctl | 6 KB | RC4 crypto (boot) |
| sysinfo | 4 KB | Sysinfo client |

### Строки по бинарникам

| Бинарник | Строк |
|----------|-------|
| ata | 2309 |
| sipcli | 1450+ |
| fvdsp | ~1000 |
| mg | 538 |
| smb_module | 469 |
| radmcli | 341 |
| smpp_smsc | 256 |

### Протоколы

| Тип | Количество |
|-----|-----------|
| Стандартные (SIP, RTP, H.323, SMPP, SMTP, HTTP, etc.) | 12 |
| Проприетарные (SMB, RADMIN, Relay, syscfg, FVDSP IPC, Echo) | 6 |
| ALG-only (IPSec, L2TP, FTP, SIP ALG) | 5 |
| **Итого** | **23** |

### Уязвимости

| Критичность | Количество |
|------------|-----------|
| 🔴 Критические | 8 |
| 🟠 Высокие | 8 |
| 🟡 Средние | 6 |
| 🔵 Информационные | 4 |
| **Итого** | **26** |

### Захардкоженные элементы

| Тип | Количество |
|-----|-----------|
| IP-адреса | 10 |
| Домены | 7 |
| Пароли/ключи | 12+ |
| Алгоритмы шифрования | 14 |
| AT-команды | 60+ |
| IPC-сокеты | 16+ |
| Device files | 15+ |

---

## ЗАКЛЮЧЕНИЕ

**GoIP GST1610** от DBLTek/HYBERTONE — это многофункциональный VoIP-GSM шлюз с 8 каналами, построенный на SoC FV13xx (ARM926EJ-S) с Linux 2.6.17.

### Ключевые архитектурные решения
- **Модульная архитектура** — 17+ независимых демонов, управляемых svcd
- **Syscfg** — централизованное хранилище конфигурации (~695 ключей) с Unix socket IPC
- **Dual VoIP** — одновременная поддержка SIP (oSIP) и H.323
- **Hardware DSP** — ACI PL040 с software кодеками (HSmedia v3.7)
- **Remote SIM** — полноценная поддержка SIM Bank через проприетарный протокол

### Критические проблемы безопасности
1. **Backdoor производителя** через radmcli (3 hardcoded IP, XOR «шифрование», default key)
2. **Пустой root-пароль** на всех устройствах
3. **Нелегальная смена IMEI** — встроена и автоматизирована
4. **Zero TLS** — из 22 протоколов только firmware download (HTTPS) поддерживает шифрование
5. **Встроенная телеметрия** — bug reports на сервер в Шэньчжэне без согласия
6. **CPU ID как ключ шифрования** — trivial key recovery

### Назначение устройства
Устройство предназначено для GSM-терминации VoIP-трафика с расширенными возможностями anti-fraud (ACD/ASR мониторинг, BST rotation, SIP port randomization, IMEI randomization) — функциями, характерными для коммерческих SIM-боксов, используемых для обхода межсетевых тарифов.

---

*Документ создан на основе статического анализа прошивки GHSFVT-1.1-68-11 без работающего устройства. Все данные получены из ELF-бинарников, shell-скриптов, конфигурационных файлов и hex-дампов.*
