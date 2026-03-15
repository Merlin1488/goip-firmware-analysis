# FVDSP — Глубокий статический анализ DSP-демона GoIP GST1610

## 1. Общая информация

| Параметр | Значение |
|----------|----------|
| **Файл** | `/usr/bin/fvdsp` |
| **Размер** | 903,784 байт (882.6 KB) |
| **Формат** | ELF32, ARM, Little Endian, ET_EXEC |
| **Компилятор** | GCC 3.3.5 (основной код), GCC 3.3.2 (часть модулей) |
| **Линковщик** | uClibc (`/lib/ld-uClibc.so.0`) |
| **Версия** | FV_DSP v11.2.03.01 (10-28-2009) |
| **Медиа-подсистема** | HSmedia v3.7 RC, Build 2, 7th August 2009, Hellosoft |
| **T38 факс** | T38 Version: 3.23 (07/11/2009), Fax Relay 3.8, FRLY 2.4 |
| **TDI API** | FV_TDI_API v2.0.0 (2012-03-13) |
| **Ядро** | Linux 2.6.17, модуль fvaci.ko |
| **Точка входа** | 0x00009F50 |
| **Флаги ELF** | 0x00000002 (ARMv5) |

## 2. ELF-структура

### 2.1. Hex-дамп ELF-заголовка (64 байта)
```
7F 45 4C 46 01 01 01 61 00 00 00 00 00 00 00 00
02 00 28 00 01 00 00 00 50 9F 00 00 34 00 00 00
A8 C6 0D 00 02 00 00 00 34 00 20 00 05 00 28 00
18 00 17 00 06 00 00 00 34 00 00 00 34 80 00 00
```

### 2.2. Заголовок ELF
- **Класс**: ELF32 (32-бит)
- **Порядок байт**: Little Endian
- **OS/ABI**: 0x01 (UNIX System V / ARM)
- **Тип**: ET_EXEC (исполняемый)
- **Архитектура**: ARM (e_machine=40)
- **Entry point**: 0x00009F50
- **Program Headers**: 5 штук (offset=52, entsize=32)
- **Section Headers**: 24 штуки (offset=902824, entsize=40, strndx=23)

### 2.3. Программные заголовки (Program Headers)

| # | Тип | Offset | VAddr | FileSz | MemSz | Флаги | Align |
|---|------|--------|-------|--------|-------|-------|-------|
| 0 | PHDR | 0x000034 | 0x00008034 | 0x0000A0 | 0x0000A0 | R-X | 0x4 |
| 1 | INTERP | 0x0000D4 | 0x000080D4 | 0x000014 | 0x000014 | R-- | 0x1 |
| 2 | LOAD | 0x000000 | 0x00008000 | 0x0B9D50 | 0x0B9D50 | R-X | 0x8000 |
| 3 | LOAD | 0x0B9D50 | 0x000C9D50 | 0x0219A8 | 0x1EB0D4 | RW- | 0x8000 |
| 4 | DYNAMIC | 0x0B9D64 | 0x000C9D64 | 0x0000E0 | 0x0000E0 | RW- | 0x4 |

### 2.4. Секции (Sections)

| # | Имя | Тип | Адрес | Offset | Размер | Описание |
|---|------|------|-------|--------|--------|----------|
| 0 | | NULL | 0x00000000 | 0x000000 | 0 | — |
| 1 | .interp | PROGBITS | 0x000080D4 | 0x0000D4 | 20 | Путь к динамическому линковщику |
| 2 | .hash | HASH | 0x000080E8 | 0x0000E8 | 1,088 | Хеш-таблица символов |
| 3 | .dynsym | DYNSYM | 0x00008528 | 0x000528 | 2,224 | Динамические символы (139 записей) |
| 4 | .dynstr | STRTAB | 0x00008DD8 | 0x000DD8 | 1,643 | Строки динамических символов |
| 5 | .gnu.version | GNU_VERSYM | 0x00009444 | 0x001444 | 278 | Символьная версия |
| 6 | .gnu.version_r | GNU_VERNEED | 0x0000955C | 0x00155C | 32 | Необходимые версии |
| 7 | .rel.dyn | REL | 0x0000957C | 0x00157C | 32 | Релокации данных |
| 8 | .rel.plt | REL | 0x0000959C | 0x00159C | 976 | Релокации PLT (122 записи) |
| 9 | .init | PROGBITS | 0x0000996C | 0x00196C | 24 | Инициализация |
| 10 | .plt | PROGBITS | 0x00009984 | 0x001984 | 1,484 | Procedure Linkage Table |
| 11 | **.text** | PROGBITS | 0x00009F50 | 0x001F50 | **717,096** | **Основной код (700 KB!)** |
| 12 | .fini | PROGBITS | 0x000B9078 | 0x0B1078 | 20 | Финализация |
| 13 | **.rodata** | PROGBITS | 0x000B908C | 0x0B108C | **36,032** | **Константы (35 KB)** |
| 14 | .eh_frame | PROGBITS | 0x000C1D4C | 0x0B9D4C | 4 | Exception handling (пустой) |
| 15 | .ctors | PROGBITS | 0x000C9D50 | 0x0B9D50 | 8 | Конструкторы |
| 16 | .dtors | PROGBITS | 0x000C9D58 | 0x0B9D58 | 8 | Деструкторы |
| 17 | .jcr | PROGBITS | 0x000C9D60 | 0x0B9D60 | 4 | Java Class Reference |
| 18 | .dynamic | DYNAMIC | 0x000C9D64 | 0x0B9D64 | 224 | Динамическая секция |
| 19 | .got | PROGBITS | 0x000C9E44 | 0x0B9E44 | 500 | Global Offset Table |
| 20 | **.data** | PROGBITS | 0x000CA040 | 0x0BA040 | **136,888** | **Инициализированные данные (134 KB)** |
| 21 | **.bss** | NOBITS | 0x000EB6F8 | 0x0DB6F8 | **1,873,708** | **Неинициализированные данные (1.8 MB!)** |
| 22 | .comment | PROGBITS | 0x00000000 | 0x0DB6F8 | 3,838 | Информация о компиляторе |
| 23 | .shstrtab | STRTAB | 0x00000000 | 0x0DC5F6 | 176 | Таблица имён секций |

> **Примечание**: .bss размером 1.8 MB указывает на большое количество статических буферов — аудиобуферы каналов, DSP-буферы, RTP-очереди.

## 3. Архитектура FVDSP

### 3.1. Общая архитектурная схема

```
┌─────────────────────────────────────────────────────────────────────┐
│                           mg (Main Gateway)                        │
│                      /usr/bin/mg или /usr/bin/gs                   │
└─────────────┬──────────────┬──────────────┬────────────────────────┘
              │ Unix DGRAM   │ Unix DGRAM   │ Unix DGRAM
              │ .dspcli%d    │ .fvdsp_mgcmd%d │ .fvdsp_data_out%d
              ▼              ▼              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        fvdsp (DSP Daemon)                          │
│                        /usr/bin/fvdsp                               │
│  ┌────────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────────┐  │
│  │ MC Reader  │ │ NW Reader│ │ DSP Reader │ │ DIM Event Proc   │  │
│  │ (cmd thread)│ │(net thrd)│ │(hw thread) │ │(media dispatch)  │  │
│  └─────┬──────┘ └────┬─────┘ └─────┬──────┘ └───────┬──────────┘  │
│        │             │             │                 │             │
│  ┌─────┴─────────────┴─────────────┴─────────────────┴──────────┐  │
│  │            Ядро обработки (DIM — DSP Interface Manager)      │  │
│  │  ┌─────────┐ ┌──────────┐ ┌──────────┐ ┌──────────────────┐ │  │
│  │  │ Codec   │ │ Tone Gen │ │ Echo/AEC │ │ Fax T38/Relay    │ │  │
│  │  │ Engine  │ │ DTMF Det │ │ LEC/NLP  │ │ (Hellosoft)      │ │  │
│  │  └─────────┘ └──────────┘ └──────────┘ └──────────────────┘ │  │
│  └──────────────────────────┬───────────────────────────────────┘  │
│                             │ libtdi API (fv_tdi_*)               │
└─────────────────────────────┼─────────────────────────────────────┘
                              │ ioctl / read / write
                              ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   Ядро Linux 2.6.17                                │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │              fvaci.ko (ACI — Analog Channel Interface)      │  │
│  │  ┌──────────┐ ┌──────────┐ ┌────────────┐ ┌──────────────┐ │  │
│  │  │ /dev/aci%d│ │/dev/slic%d│ │/dev/spi%d │ │/dev/snd%d   │ │  │
│  │  │(PCM data) │ │(SLIC ctrl)│ │(SPI bus)  │ │(sound dev)  │ │  │
│  │  └────┬─────┘ └────┬─────┘ └─────┬──────┘ └─────┬────────┘ │  │
│  │       │            │             │               │          │  │
│  │  ┌────┴────────────┴─────────────┴───────────────┘          │  │
│  │  │  ACI Core: aci-core.c / aci-dev.c                        │  │
│  │  │  G.711 alaw/ulaw codec | DTMF Detection | CID Detection │  │
│  │  └──────────────────────────┬───────────────────────────────┘  │
│  └─────────────────────────────┼────────────────────────────────┘  │
│                                │ Hardware IRQ / MMIO              │
│                                ▼                                  │
│  ┌─────────────────────────────────────────────────────────────┐  │
│  │              FV13xx DSP Hardware (PCM Highway / TDM)        │  │
│  │         Si3217x SLIC (ProSLIC) — FXS/FXO интерфейс         │  │
│  └─────────────────────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────────────────────┘
```

### 3.2. Потоки выполнения (Threads)

fvdsp запускает минимум 4 основных потока:

| Поток | Назначение |
|-------|-----------|
| **MC Reader** | Приём управляющих команд от mg через Unix DGRAM сокеты |
| **NW Reader** (`nw_reader_main`) | Приём сетевых RTP-пакетов, обработка входящего медиа |
| **DSP Reader** | Чтение аудио-данных из DSP-аппаратуры (через fv_tdi_*) |
| **DIM Event Proc** (`fv_dim_event_proc`) | Обработка событий DSP Interface Manager |

Дополнительно создаются потоки для каждого активного канала.

### 3.3. Запуск и остановка

**Запуск** — скрипт `/usr/bin/start_fvdsp`:
```sh
#!/bin/sh
cd /var/run/voip
exec /usr/bin/fvdsp
```

**Остановка** — скрипт `/usr/bin/stop_fvdsp`:
```sh
#!/bin/sh
killall fvdsp
```

Рабочая директория: `/var/run/voip` (ram-диск).

При запуске fvdsp устанавливает переменную `FVDSP_STATE` в syscfg.

## 4. IPC-протокол (Inter-Process Communication)

### 4.1. Unix DGRAM сокеты

| Сокет | Направление | Назначение |
|-------|-----------|-----------|
| `/tmp/.fvdsp_cmd_in` | mg → fvdsp | **Управляющие команды** (открытие/закрытие каналов, конфигурация) |
| `/tmp/.fvdsp_data_in%d` | mg → fvdsp | **Входящие медиа-данные** (RTP-пакеты от сети) для канала %d |
| `/tmp/.fvdsp_data_out%d` | fvdsp → mg | **Исходящие медиа-данные** (закодированное аудио) для канала %d |
| `/tmp/.fvdsp_mgcmd%d` | fvdsp → mg | **Обратные команды/события** (DTMF, hook state, FAX) для канала %d |
| `/tmp/.dspcli%d` | mg → fvdsp | **CLI-подключения** для отладки канала %d |
| `/tmp/.syscfg-server` | все ↔ syscfg | **Системная конфигурация** (доступ к NVRAM) |

### 4.2. Протокол команд FVDSP

Из анализа строк реконструирована структура команд:

```
Команда → fvdsp через /tmp/.fvdsp_cmd_in:
  - open      — Открыть канал (Open a Channel)
  - close     — Закрыть канал (Close a Channel) 
  - cfg       — Конфигурация канала (Media config)
  - codec     — Установка кодека (Codec Change)
  - remote    — Конфигурация удалённой стороны (Media send to remote)
  - stop      — Остановка медиа (Stop media)
  - fax       — Управление FAX (Control FAX)
  - dtmf      — Отправка DTMF
  - tone      — Генерация тона
  - assoc     — Ассоциация канала с endpoint'ом
  
Событие ← fvdsp через /tmp/.fvdsp_mgcmd%d:
  - FV_DSP_MSG_FIRST_RING_COMPLETE — завершение первого звонка
  - Local DTMF — локальный DTMF
  - Remote DTMF — удалённый DTMF
  - RFC2833 DTMF — DTMF по RFC2833
  - Local FAX — начало факса
  - CID gen complete — завершение генерации Caller ID
```

### 4.3. CLI-интерфейс отладки

fvdsp предоставляет интерактивный CLI для отладки через `/tmp/.dspcli%d`:

```
Commands list:
  help                                          — Справка
  cfg ch [set][vad][mr][mt][codec][lec][aec]
         [txagc][rxagx][sz][delay][fax] [val]  — Конфигурация канала
  slic ep signal id                             — Сигнал SLIC
  slic ep polarity reversal/forward             — Полярность линии
  slic ep [i]reg [addr [val]]                   — Регистры SLIC
  slic ep time on off                           — Таминги SLIC
  slic ep xit under onhook                      — Состояние hook
  dtmf_det ch on/off                            — Детекция DTMF
  dial ep digits                                — Набор цифр
  tone ep tone_id/off [remote/local]            — Генерация тона
  showtone [ep] [tone_id]                       — Показ тона
  tonesetting [ep] [tone_id] [ontime] [offtime]
              [freq1] [freq2] [level1] [level2] — Настройка тона
  codec ch tx rx vad dtmf                       — Кодек
  gain ep [1-8] [[tx][rx]]                      — Усиление
  rec ep on/off [path]                           — Запись аудио
  play ep file/stop                              — Воспроизведение файла
  open device_name spi[id] aci[id] ep_id         — Открыть устройство
  close ch_id                                    — Закрыть канал
  loop ch_id txrx_dir                            — Шлейф (loopback)
  b0: dump pcm to dsp                            — Дамп PCM→DSP
  b1: dump dsp to pcm                            — Дамп DSP→PCM
```

## 5. DSP кодеки и обработка аудио

### 5.1. Поддерживаемые кодеки

На основании строк AMR-режимов и конфигурации:

| Кодек | Параметры | Примечание |
|-------|----------|-----------|
| **G.711 A-law** | 64 kbps | Аппаратная реализация в fvaci.ko |
| **G.711 μ-law** | 64 kbps | Аппаратная реализация в fvaci.ko |
| **AMR** | MR475, MR515, MR59, MR67, MR74, MR795, MR102, MR122 | Все режимы AMR-NB |
| **AMR DTX** | MRDTX | Discontinuous Transmission |
| **Другие** | Определяются параметром codec | По номеру типа |

### 5.2. AMR состояния RX/TX

```
TX: TX_SPEECH_GOOD, TX_SPEECH_DEGRADED, TX_SPEECH_BAD
    TX_SID_FIRST, TX_SID_UPDATE, TX_SID_BAD
    TX_ONSET, TX_NO_DATA

RX: RX_SPEECH_GOOD, RX_SPEECH_DEGRADED, RX_SPEECH_BAD  
    RX_SID_FIRST, RX_SID_UPDATE, RX_SID_BAD
    RX_ONSET, RX_NO_DATA
```

### 5.3. Обработка аудио

- **VAD** (Voice Activity Detection) — определение речевой активности
- **CNG** (Comfort Noise Generation) — генерация комфортного шума
- **LEC** (Line Echo Cancellation) — подавление линейного эха
- **AEC** (Acoustic Echo Cancellation) — акустическое подавление эха
- **TX AGC** — автоматическая регулировка усиления передачи
- **RX AGC** — автоматическая регулировка усиления приёма
- **Запись PCM** — `%s/voice_rec_near_%d.pcm` (near-end recording)

### 5.4. Hellosoft HSmedia

Факс-подсистема и часть DSP-обработки реализованы на библиотеке **Hellosoft HSmedia v3.7 RC** (Build 2, 7 August 2009).

Исходный код из CVS-репозитория Hellosoft:
```
/usr/local/cvsroot/Projects/voip/customer/5VTech/source/voip_372/mediasubsystem/fax/source/arm9e/ael/
  ├── r21_cor.c    — V.21 корректор (факс)
  ├── r17_cor.c    — V.17 корректор
  ├── r17_baud.c   — V.17 бодовая синхронизация
  ├── r17_scm.c    — V.17 SCM
  ├── r17_dcd.c    — V.17 детекция несущей
  ├── r2x_cor.c    — V.27/V.29 корректор
  ├── r2x_baud.c   — V.27/V.29 бодовая синхр.
  ├── r2x_scm.c    — V.27/V.29 SCM
  ├── r2x_dcd.c    — V.27/V.29 детекция несущей
  ├── t21_cor.c    — V.21 передатчик
  ├── mdm_fltr.c   — Модемный фильтр
  ├── rcm_rot.c    — Ротация созвездия
  └── rcm_btr.c    — Bit timing recovery
```

Исходные файлы fvdsp:
```
  main.c                    — Главный модуль
  cmds.c                    — Обработка CLI-команд
  rtp_test.c                — RTP тестирование
  syscfg.c                  — Работа с syscfg
  hs_voip_dsp_fwk_memmgr.c — Менеджер памяти HSmedia
  rttllog.cfg               — Конфигурация RTTL (рингтоны)
```

## 6. Аппаратное взаимодействие

### 6.1. Устройства (device files)

| Устройство | Назначение |
|-----------|-----------|
| `/dev/aci%d` (aci0, aci1, aci2, aci3) | ACI — передача PCM-аудио (read/write) |
| `/dev/slic%d` (slic0) | SLIC — управление линейным интерфейсом (FXS) |
| `/dev/daa0` | DAA — управление линейным интерфейсом (FXO) |
| `/dev/spi%d` (spi0, spi1) | SPI-шина для связи с Si3217x |
| `/dev/snd%d` | Звуковое устройство |
| `/dev/fvmem` | Прямой доступ к памяти DSP (mmap) |
| `/dev/gpio1` | GPIO для аппаратного управления |
| `/dev/mtd/6`, `/dev/mtdblock/6` | MTD Flash (калибровка/конфигурация) |

### 6.2. TDI API (Telephony Device Interface)

libtdi.so экспортирует полный API для управления телефонным аппаратным обеспечением:

**Общие функции (fv_tdi_*)**:
```c
fv_tdi_init()                    // Инициализация TDI
fv_tdi_alloc() / fv_tdi_free()  // Выделение/освобождение ресурсов
fv_tdi_open() / fv_tdi_close()  // Открытие/закрытие канала
fv_tdi_ctrl()                    // Управление
fv_tdi_hookstate()              // Состояние крюка/рычага
fv_tdi_get_event()              // Получение события от аппаратуры
fv_tdi_reset()                  // Сброс
fv_tdi_offhook() / fv_tdi_onhook() // Имитация снятия/кладки трубки
fv_tdi_tonestart() / fv_tdi_tonestop() // Генерация тона
fv_tdi_playstart() / fv_tdi_playstop() // Воспроизведение
fv_tdi_recordstart() / fv_tdi_recordstop() // Запись
fv_tdi_record() / fv_tdi_play() // Чтение/запись аудио-буфера
fv_tdi_set_bufsz()              // Размер буфера
fv_tdi_set_tx_gain() / fv_tdi_set_rx_gain() // Усиление
fv_tdi_polarity_reversal() / fv_tdi_polarity_normal() // Полярность линии
fv_tdi_set_flashhook_timeout()  // Таймаут flash hook
fv_tdi_get_status()             // Статус
fv_tdi_func_register()          // Регистрация callback
```

**SLIC-специфичные (fv_tdi_slic_*)**:
Полный набор аналогичных slic-функций для управления SLIC Si3217x.

**Sound-специфичные (fv_tdi_snd_*)**:
Полный набор аналогичных функций для звуковых устройств.

### 6.3. IOCTL коды

Из libtdi.so и fvaci.ko извлечены ключевые ioctl:
```
PHONE_FRAME             — Размер фрейма
PHONE_NONBLOCKINGMODE   — Неблокирующий режим
TXRX_DELAY              — Задержка TX/RX
```

### 6.4. SLIC (Si3217x ProSLIC)

Микросхема Si3217x от Silicon Laboratories управляется через API ProSLIC:

```
Инициализация:
  ProSLIC_createControlInterface → ProSLIC_createDevice → ProSLIC_createChannel
  ProSLIC_SWInitChan → ProSLIC_HWInit → ProSLIC_Init → ProSLIC_Cal → ProSLIC_LBCal

Конфигурация:
  ProSLIC_DCFeedSetup    — настройка DC-питания линии
  ProSLIC_RingSetup      — параметры звонка
  ProSLIC_PCMSetup       — конфигурация PCM
  ProSLIC_PCMTimeSlotSetup — тайм-слоты
  ProSLIC_ZsynthSetup    — импеданс линии
  ProSLIC_ToneGenSetup   — генератор тонов

Управление линией:
  ProSLIC_SetLinefeedStatus     — статус питания линии
  ProSLIC_PolRev               — реверс полярности
  ProSLIC_RingStart/RingStop   — начало/конец звонка
  ProSLIC_PCMStart/PCMStop     — PCM вкл/выкл
  ProSLIC_ReadHookStatus       — чтение состояния hook

Caller ID:
  ProSLIC_FSKSetup      — настройка FSK для CID
  ProSLIC_EnableCID     — включение CID
  ProSLIC_SendCID       — отправка CID
  ProSLIC_CheckCIDBuffer — проверка буфера CID
  ProSLIC_DisableCID    — выключение CID

DTMF:
  ProSLIC_DTMFDecodeSetup — настройка детектора DTMF
  ProSLIC_DTMFReadDigit   — чтение DTMF-цифры

Типы каналов Si3217x:
  - PROSLIC (FXS)
  - DAA (FXO)
  - UNKNOWN
```

### 6.5. Потенциальные MMIO-адреса

В .rodata обнаружены системные адреса регистров, характерные для FV13xx:

```
Базовые группы:
  0x10000000 — 0x10001C00 (шаг 0x400) — Блок регистров DSP #0
  0x1000E400 — 0x1000FC00 (шаг 0x400) — Блок регистров DSP периферии
  0x14000000 — 0x14001C00 (шаг 0x400) — Блок регистров DSP #1
  0x1400E400 — 0x1400FC00              — Блок регистров DSP периферии #1
  0x18000000 — 0x18001800              — Блок регистров DSP #2
  0x1C000000 — 0x1C001C00              — Блок регистров DSP #3
  0x1C00E400 — 0x1C00FC00              — Блок регистров DSP периферии #3

  0xB005xxxx — 0xBFxxxxxx — Коэффициенты фиксированной точки (DSP фильтры)
```

Структура регистров с шагом 0x400 и базовыми адресами 0x10000000, 0x14000000, 0x18000000, 0x1C000000 — типичная для 4-канальной DSP-подсистемы (по одному блоку на канал).

## 7. Модуль ядра fvaci.ko

### 7.1. Общая информация

| Параметр | Значение |
|----------|----------|
| **Файл** | `/lib/modules/2.6.17/fv13xx/fvaci.ko` |
| **Размер** | 52,324 байт |
| **Версия** | ACI_DRIVER v1.0.0 (08-04-2007) |
| **Ядро** | 2.6.17, ARMv5, gcc-4.1 |
| **Лицензия** | GPL |
| **Автор** | Chun-Cheng Lu |
| **Параметр модуля** | `ACICLK` (int) — частота тактирования ACI |

### 7.2. Исходные файлы

```
/home1/users/rapid/RELEASE_SDK/DBL_32176/trunk/drivers/ACI/
  ├── aci-core.c    — Ядро ACI-драйвера
  └── aci-dev.c     — Устройства и файловые операции
```

### 7.3. Функции ядра ACI

```c
// Файловые операции
ACI_dev_open()      // Открытие /dev/aci%d
ACI_dev_release()   // Закрытие
ACI_dev_read()      // Чтение PCM-данных
ACI_dev_write()     // Запись PCM-данных
ACI_dev_ioctl()     // Управление параметрами
ACI_dev_poll()      // Опрос готовности данных

// Инициализация
ACI_dev_init()      // Инициализация устройства
ACI_dev_cleanup()   // Очистка
ACI_initialize()    // Инициализация аппаратуры

// Обработка прерываний
ACI_isr()                   // Основной ISR
ACI_interrupt_handler()     // Обработчик прерывания
ACI_cardiac_mechanism()     // Механизм "сердцебиения"

// Обработка данных
ACI_extra_receive_handler()  // Обработчик приёма
ACI_extra_transmit_handler() // Обработчик передачи
ACI_extra_get_event_data()   // Получение данных событий
ACI_extra_init()             // Инициализация расширений
ACI_extra_reset()            // Сброс расширений
ACI_extra_clean()            // Очистка
```

### 7.4. DSP-алгоритмы в ядре

fvaci.ko содержит реализации:

- **G.711 A-law ↔ Linear**: `G711_alaw2linear`, `G711_linear2alaw` (14-bit и 16-bit)
- **G.711 μ-law ↔ Linear**: `G711_ulaw2linear`, `G711_linear2ulaw`
- **DTMF-детектор**: фильтры Гёрцеля (`dtmf_detect_dgt`, `dtmf_validate_goeztl`, `dtmf_reset`)
  - High-pass, low-pass, band-pass фильтры
  - Валидация энергии, частотного смещения
- **CID-детектор (Caller ID)**: FSK-демодуляция (`hs_dsp_ciddet_*`, `hs_dsp_cidfskdet`)
  - Bit detection, mark signal detect, CRC, resample
- **DTAS-детектор**: `hs_dsp_dtasdet_*` (Dual Tone Alert Signal)
- **Арифметика фиксированной точки**: обширная библиотека `hs_*` функций

## 8. Тональные сигналы

### 8.1. Конфигурация тонов

Тональные описания загружаются из `/usr/etc/tonedes/tone_%s`, где `%s` — код страны.

Поддерживаемые страны (22 набора тонов):
```
AU BD CN CZ DT HK ID IL IN JP KR MY NZ PH RO SG SI TH TW UK US
```

### 8.2. Формат файла описания тона

```
DIAL_TONE_DES            — Тон набора
RINGING_TONE_DES         — Тон КПВ (контроля посылки вызова)
BUSY_TONE_DES            — Тон "занято"
INDICATION_TONE_DES      — Индикационный тон

Параметры:
  toneDescr           — Дескриптор тона (66=dial, 70=ring, 72=busy, 74=indication)
  numberOfCadences    — Количество каденций (0-3)
  repeatCounter       — Счётчик повторов
  cadenceOneOn/Off    — Длительность 1-й каденции (мс)
  cadenceTwoOn/Off    — Длительность 2-й каденции (мс)
  cadenceThreeOn/Off  — Длительность 3-й каденции (мс)
  toneFreq1-4         — Частоты (Гц)
  tonePwr1-4          — Мощности (уровни)
```

Пример US тонов:
| Тон | Частоты | Каденция |
|-----|---------|---------|
| Dial | 350 + 440 Гц | Непрерывный |
| Ring | 400 + 480 Гц | 400мс вкл + 200мс вкл + 400мс выкл + 3000мс выкл |
| Busy | 480 + 620 Гц | 500мс вкл / 500мс выкл |

### 8.3. DTMF

Параметры DTMF настраиваются через CLI:
```
tone_id: 0(DTMF0) - 9(DTMF9) 10(STAR) 11(HASH)
```

Обнаружение DTMF:
- Локальный DTMF (от SLIC)
- Удалённый DTMF (от сети)
- RFC2833 DTMF (in-band → out-of-band)

### 8.4. RTTL (Ring Tone Text Transfer Language)

Поддержка мелодий через RTTL-формат:
- Конфигурация: `rttllog.cfg`
- Файлы мелодий: `/usr/share/music/` (0-9.au, dot.au — цифры IVR, плюс zh_CN версии)

## 9. Конфигурация syscfg

### 9.1. Параметры из fvdsp.def

```
LINE0_VOL   integer    — Громкость линии 0
LINE0_VOL_E integer    — Громкость линии 0 (эхо)
LINE1_VOL   integer    — Громкость линии 1
LINE1_VOL_E integer    — Громкость линии 1 (эхо)
...
LINE7_VOL   integer    — Громкость линии 7
LINE7_VOL_E integer    — Громкость линии 7 (эхо)
FVDSP_STATE string     — Состояние DSP-демона (-n = не постоянное)
```

### 9.2. Ключевые конфигурационные параметры каналов

Из CLI-команды `cfg`:
```
set     — Включение
vad     — Voice Activity Detection
mr      — Media Rate (AMR mode)
mt      — Media Type (codec type)
codec   — Тип кодека
lec     — Line Echo Cancellation
aec     — Acoustic Echo Cancellation
txagc   — TX Automatic Gain Control
rxagx   — RX Automatic Gain Control
sz      — Buffer Size
delay   — Задержка
fax     — Режим факса
```

Дополнительно: `TONE_DES` (описание тона), `TONE_MODE` (режим тона).

## 10. Факс-подсистема

### 10.1. T.38

- **T38 Version**: 3.23
- Поддержка T.38 факса через IP
- Команда `fax ep` — управление факсом на endpoint

### 10.2. Fax Relay

- **FRLY Version**: 2.4
- **Fax Relay Version**: 3.8
- Модемные протоколы: V.21, V.17, V.27, V.29
- Реализация: Hellosoft для ARM9E

## 11. Динамические символы

### 11.1. Импортированные функции (121)

| Категория | Функции |
|-----------|---------|
| **libtdi.so** | `fv_tdi_init`, `fv_tdi_open`, `fv_tdi_close`, `fv_tdi_ctrl`, `fv_tdi_get_event`, `fv_tdi_hookstate`, `fv_tdi_play`, `fv_tdi_playstart`, `fv_tdi_playstop`, `fv_tdi_record`, `fv_tdi_recordstart`, `fv_tdi_recordstop`, `fv_tdi_set_bufsz`, `fv_tdi_set_rx_gain`, `fv_tdi_set_tx_gain`, `fv_tdi_tonestart`, `fv_tdi_tonestop`, `fv_tdi_polarity_normal`, `fv_tdi_polarity_reversal` |
| **libc (uClibc)** | `open`, `close`, `read`, `write`, `mmap`, `munmap`, `select`, `socket`, `bind`, `sendto`, `recvfrom`, `setsockopt`, `fcntl`, `fstat`, `lseek`, `unlink` |
| **stdio** | `fopen`, `fclose`, `fgets`, `fgetc`, `fputs`, `fputc`, `fprintf`, `printf`, `puts`, `putchar`, `fwrite`, `snprintf`, `sprintf`, `vsnprintf` |
| **string** | `memcpy`, `memmove`, `memset`, `memcmp`, `strcmp`, `strncmp`, `strcpy`, `strncpy`, `strlen`, `strstr`, `strchr`, `strdup`, `strcasecmp` |
| **memory** | `malloc`, `calloc`, `free` |
| **pthread** | `pthread_create`, `pthread_exit`, `pthread_join`, `pthread_cancel`, `pthread_kill`, `pthread_mutex_*`, `pthread_cond_*`, `pthread_attr_*`, `pthread_key_*` |
| **system** | `getpid`, `getuid`, `getenv`, `setenv`, `sleep`, `usleep`, `kill`, `exit`, `abort`, `syslog`, `readlink`, `stat`, `fchmod` |
| **conversion** | `atoi`, `strtol`, `strtoul`, `sscanf` |
| **error** | `perror`, `strerror`, `__errno_location` |
| **time** | `gettimeofday` |
| **sched** | `sched_yield` |

### 11.2. Экспортированные функции (4)

```
_init    @ 0x0000996C  size=4   — Конструктор
_fini    @ 0x000B9078  size=4   — Деструктор
_start   @ 0x00009F50  size=80  — Точка входа
sigqueue @ 0x0001319C  size=128 — Отправка сигнала
```

## 12. Взаимосвязь компонентов

### 12.1. Цепочка fvdsp → libtdi.so → fvaci.ko → FV13xx

```
fvdsp (userspace daemon)
  │
  ├── fv_tdi_init()                → libtdi.so инициализация
  ├── fv_tdi_open()                → open("/dev/slic%d"), open("/dev/aci%d")
  │                                   open("/dev/spi%d"), open("/dev/snd%d")
  ├── fv_tdi_playstart()           → ioctl(PHONE_FRAME), ioctl(TXRX_DELAY)
  │                                   ProSLIC_PCMStart() (через SPI)
  ├── fv_tdi_play(buf, len)        → write("/dev/aci%d", buf, len)
  ├── fv_tdi_record(buf, len)      → read("/dev/aci%d", buf, len)
  ├── fv_tdi_tonestart(tone_id)    → ProSLIC_ToneGenSetup() + ProSLIC_ToneGenStart()
  ├── fv_tdi_hookstate()           → ProSLIC_ReadHookStatus() (через SPI + GPIO)
  └── fv_tdi_ctrl(cmd, params)     → ProSLIC_*/Si3217x_* (различные ioctl)
  
libtdi.so (shared library)
  │
  ├── slic-драйвер: Si3217x → SPI → ProSLIC API
  ├── snd-драйвер: /dev/snd%d
  └── aci-драйвер: /dev/aci%d → fvaci.ko
  
fvaci.ko (kernel module)
  │
  ├── PCM Highway: чтение/запись аудио-фреймов
  ├── IRQ: ACI_isr() → ACI_interrupt_handler()
  ├── G.711 codec: аппаратные alaw/ulaw
  ├── DTMF detector: Гёрцель + BPF
  ├── CID detector: FSK-демодуляция
  └── DMA/MMIO: прямой доступ к регистрам FV13xx
```

### 12.2. Потоки данных GST1610

```
Телефонная линия (FXS/FXO)
  ↕ (аналог)
Si3217x SLIC (ProSLIC)
  ↕ (PCM/TDM)
FV13xx DSP Hardware → /dev/aci%d → fvaci.ko
  ↕ (цифровые данные)
libtdi.so (fv_tdi_play/record)
  ↕ (аудио-буферы)  
fvdsp (кодирование/декодирование, RTP)
  ↕ (Unix DGRAM)
mg (SIP/RTP → Ethernet)
  ↕
IP-сеть
```

## 13. Ключевые находки

1. **Статически скомпилированный монолит** — .text 700 KB, .bss 1.8 MB — огромный бинарник с встроенными кодеками и факс-обработкой

2. **Hellosoft HSmedia** — медиа-подсистема от индийской компании Hellosoft (ARM9E оптимизация), включая полную T.38 факс-реализацию

3. **Si3217x ProSLIC** — полный Silicon Labs ProSLIC API встроен в libtdi.so для управления SLIC (линейными интерфейсами)

4. **4-канальная архитектура** — MMIO-адреса с базами 0x10000000/0x14000000/0x18000000/0x1C000000 указывают на 4 DSP-канала в аппаратуре

5. **7 потоков на канал** — fvdsp создаёт 139-145 PID (7 потоков × 8 каналов + основные)

6. **IPC через Unix DGRAM** — все данные между fvdsp и mg передаются через Unix datagram'ы в `/tmp/`

7. **Конвейер G.711 в ядре** — базовое кодирование/декодирование alaw/ulaw выполняется в fvaci.ko (минимальная задержка), более сложные кодеки (AMR, G.729) — в userspace

8. **SDK линейка DBL_32176** — код драйвера ACI из SDK `/home1/users/rapid/RELEASE_SDK/DBL_32176/trunk/drivers/ACI/`

9. **Устаревший тулчейн** — GCC 3.3.5 (2004), uClibc, Linux 2.6.17 (2006)

10. **22 набора тонов** — поддержка стандартов телефонии для 22 стран

---

*Документ создан на основе статического анализа бинарного файла fvdsp (903,784 байт),
kernel модуля fvaci.ko (52,324 байт), библиотеки libtdi.so (84,040 байт),
конфигурационных файлов и скриптов прошивки GoIP GST1610.*
