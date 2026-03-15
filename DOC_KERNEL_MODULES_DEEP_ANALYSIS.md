# Глубокий анализ модулей ядра GoIP GST1610

## Общая информация

- **Платформа**: ARM 32-bit (ARMv5), Little-Endian
- **Ядро**: Linux 2.6.17
- **Компилятор**: GCC 4.1.1 / GCC 3.3.5 (для DSP-кода)
- **Производитель платформы**: 5VTechnologies (FV13xx SoC)
- **Расположение модулей**: `/lib/modules/2.6.17/fv13xx/` и `/lib/modules/2.6.17/kernel/drivers/base/`
- **Всего модулей**: 31 файлов (.ko)
- **Общий размер**: ~380 KB

## Сводная таблица модулей

| # | Модуль | Размер | Категория | Описание |
|---|--------|--------|-----------|----------|
| 1 | fvaci.ko | 52 324 | DSP/Аудио | ACI (Analog Channel Interface) — драйвер DSP-оборудования |
| 2 | fvmac.ko | 54 880 | Сеть/Ethernet | MAC/Ethernet AMBA-контроллер |
| 3 | fvmem.ko | 7 528 | Аппаратное обесп. | Прямой доступ к памяти (memory-mapped I/O) |
| 4 | fvspi.ko | 6 800 | Шины/SPI | Драйвер SPI-шины |
| 5 | fvgpio.ko | 6 720 | GPIO | Управление GPIO-линиями |
| 6 | fvnet.ko | 6 872 | Сеть | Быстрый путь (fastpath) для IP-пакетов |
| 7 | fvipdef.ko | 9 612 | Безопасность | Защита от IP-атак (IDS) |
| 8 | nfext.ko | 35 288 | Сеть/NAT | Netfilter Extension (NAT hairpin, NAPT) |
| 9 | exthook.ko | 6 260 | Ядро | Механизм расширяемых хуков (exthook framework) |
| 10 | brext.ko | 7 236 | Сеть/Bridge | Расширения бриджинга |
| 11 | bwlimit.ko | 7 648 | Сеть/QoS | Ограничение пропускной способности |
| 12 | qoshook.ko | 7 344 | Сеть/QoS | QoS-хуки для планировщика |
| 13 | qosip.ko | 10 108 | Сеть/QoS | QoS по IP-протоколам/портам |
| 14 | vtag.ko | 15 592 | Сеть/VLAN | VLAN-тегирование |
| 15 | sniffer.ko | 18 368 | Сеть/Диагностика | Пакетный сниффер |
| 16 | neigh.ko | 5 392 | Сеть/ARP | Отладка ARP-соседей |
| 17 | heap.ko | 4 084 | Ядро/Отладка | Мониторинг использования кучи (brk) |
| 18 | unalign.ko | 4 780 | Ядро/Отладка | Отслеживание невыровненных обращений |
| 19 | wd.ko | 4 464 | Аппаратное обесп. | Watchdog-таймер |
| 20 | fv_alg_bnet.ko | 22 556 | Сеть/ALG | ALG для Battle.Net / Starcraft |
| 21 | fv_alg_dns.ko | 2 564 | Сеть/ALG | ALG для DNS |
| 22 | fv_alg_esp.ko | 5 172 | Сеть/ALG | ALG для ESP (IPSec) |
| 23 | fv_alg_ftp.ko | 11 600 | Сеть/ALG | ALG для FTP (NAT traversal) |
| 24 | fv_alg_ipsec.ko | 3 972 | Сеть/ALG | ALG для IPSec (IKE) |
| 25 | fv_alg_l2tp.ko | 5 460 | Сеть/ALG | ALG для L2TP |
| 26 | fv_alg_msn.ko | 9 868 | Сеть/ALG | ALG для MSN Messenger |
| 27 | fv_alg_sip.ko | 2 716 | Сеть/ALG | ALG для SIP (VoIP) |
| 28 | fv_ipt_localport.ko | 3 212 | Сеть/iptables | Модуль iptables: match по локальным портам |
| 29 | fv_ipt_trigger.ko | 3 700 | Сеть/iptables | Модуль iptables: port triggering |
| 30 | fv_ipt_webstr.ko | 5 972 | Сеть/iptables | Модуль iptables: фильтрация по URL/HTTP |
| 31 | firmware_class.ko | 10 256 | Ядро | Загрузка firmware через sysfs |

---

## Детальный анализ по каждому модулю

---

### 1. fvaci.ko — ACI (Analog Channel Interface) — DSP/Аудио

**Размер**: 52 324 байт  
**Категория**: DSP / Аудио / Телефония  
**Версия**: ACI_DRIVER v1.0.0 08-04-2007  
**Автор**: Chun-Cheng Lu  
**Лицензия**: GPL  
**Исходный путь**: `/home1/users/rapid/RELEASE_SDK/DBL_32176/trunk/drivers/ACI/aci-dev.c`, `aci-core.c`

#### Назначение
Основной драйвер аналогового канального интерфейса (ACI PL040). Обеспечивает:
- Приём/передачу голосовых данных из/в DSP-оборудование
- Детекцию DTMF-тонов (включая детектор FSK CID для Caller ID)
- Преобразование кодеков G.711 (A-law ↔ μ-law ↔ Linear PCM)
- Обработку аудио-прерываний

#### Устройства
- `/dev/aci0`, `/dev/aci1`, ... (char-устройства, dynamic major)

#### Параметры модуля
- `ACICLK` (int) — тактовая частота ACI

#### Экспортируемые символы / Ключевые функции
```
ACI_dev_init, ACI_dev_open, ACI_dev_release, ACI_dev_read, ACI_dev_write
ACI_dev_ioctl, ACI_dev_poll, ACI_dev_cleanup
ACI_interrupt_handler, ACI_isr
ACI_initialize, ACI_extra_init, ACI_extra_clean
ACI_extra_receive_handler, ACI_extra_transmit_handler
ACI_extra_reset, ACI_extra_get_event_data
ACI_cardiac_mechanism
ACI_proc_read
```

#### DSP-функции (G.711, DTMF, CID)
```
G711_linear2alaw, G711_alaw2linear, G711_linear2ulaw, G711_ulaw2linear
hs_voip_dsp_g711_lin2alaw, hs_voip_dsp_g711_lin2ulaw
hs_voip_dsp_g711_alaw2lin, hs_voip_dsp_g711_ulaw2lin
hs_voip_dsp_g711_conv14bitlin_ala, hs_voip_dsp_g711_conv14bitlin_ula
hs_voip_dsp_g711_conv16bitlin_ala, hs_voip_dsp_g711_conv16bitlin_ula
hs_voip_dsp_g711_conv2lin

dtmf_detect_dgt, dtmf_reset, dtmf_bpf, dtmf_gff
dtmf_validate_energy, dtmf_validate_goeztl, dtmf_validate_offset
dtmf_cal_gf_coeff, dtmf_cal_frq_offset, dtmf_find_zc
dtmf_high_pass_filter, dtmf_low_pass_filter

hs_voip_dsp_dtmf_detect, hs_voip_dsp_dtmf_detinit
hs_dsp_dtmfdet_init, hs_dsp_dtmfdet_process
hs_voip_dsp_dtmfdet_keypad

hs_dsp_ciddet_init, hs_dsp_ciddet_process
hs_dsp_ciddet_fsk_dmod, hs_dsp_cidfskdet
hs_dsp_ciddet_message_check, hs_dsp_ciddet_resample
hs_dsp_ciddet_filter_bp, hs_dsp_ciddet_bit_det
hs_dsp_ciddet_chsync_check, hs_dsp_ciddet_norm

hs_dsp_dtasdet_init, hs_dsp_dtasdet_process
```

#### Аппаратные регистры
- Прерывания передачи и приёма (IRQ)
- FIFO-буферы Tx/Rx
- `ACICLK` — тактирование
- `CDLDVAL` — регистр загрузки
- Адреса iobase через `__ioremap`

#### DSP-алгоритмы ассемблерного уровня (ARM)
Детектор DTMF реализован на уровне ARM-ассемблера с использованием фильтров Гёрцеля:
```
GoertFilt_REGSAVE_SIZE, GoertFiltILoop, GoertFiltJLoop
BP_ForHigerFreq, BP_StageLoop, BP_JLoop
dtmf_LP_filter, dtmf_val_goeztl, dtmf_fra_ene
ZcPredictLoop, ZcHF1..ZcLF8
```

Таблицы преобразования:
```
Ala2Lin14Tab, Ala2Lin16Tab, Ula2Lin14Tab, Ula2Lin16Tab
hs_voip_dsp_dtmfdet_keypad, hs_voip_dsp_dtmfdet_lfreq, hs_voip_dsp_dtmfdet_hfreq
hs_voip_dsp_dtmfdet_lcos, hs_voip_dsp_dtmfdet_hcos
hs_voip_dsp_dtmfdet_al, hs_voip_dsp_dtmfdet_ah
hs_voip_dsp_dtmfdet_bl, hs_voip_dsp_dtmfdet_bh
hs_voip_dsp_dtmfdet_lslope, hs_voip_dsp_dtmfdet_hslope
hs_voip_dsp_dtmf_tablog
```

#### Зависимости
Нет зависимостей от других .ko модулей (depends= пусто).

---

### 2. fvmac.ko — Ethernet MAC-контроллер (AMBA)

**Размер**: 54 880 байт  
**Категория**: Сеть / Ethernet  
**Версия**: 1.18, дата 2009/03/27  
**Автор**: 5VTechnologies  
**Лицензия**: 5VT

#### Назначение
Драйвер встроенного Ethernet MAC-контроллера (FVMAC core with AMBA). Поддерживает:
- Два MAC-порта (mac0/mac1 = eth0/eth1)
- Множество switch-PHY: Infeion 6996M, ICPlus IC175C/IC175D, Realtek 8305SB/8305SC
- Режим бриджинга между портами
- Store & Forward, polling mode
- Flow control (pause frames)
- RMII-интерфейс

#### Устройства
- `eth0`, `eth1` (сетевые интерфейсы)

#### Параметры модуля
```
polling_mode — режим поллинга (int)
fpga — зондирование FPGA MAC (int)
debug_mii — отладка MII (int)
share_mii — общий MDC/MDIO для двух MAC (int)
mac0_phyaddr, mac1_phyaddr — PHY-адреса (int)
mac0_devname, mac1_devname — имена интерфейсов (charp)
wan_interface — WAN-интерфейс (charp)
linkup_script, linkdown_script — скрипты при изменении линка (charp)
```

#### Экспортируемые символы
```
fvmac_mii_read — чтение MII-регистра PHY
fvmac_mii_write — запись MII-регистра PHY
```

#### Аппаратные регистры (CSR — Control/Status Registers)
```
CSR0, CSR3, CSR4, CSR5, CSR6, CSR7, CSR8, CSR11
RDES (Receive Descriptor), TDES (Transmit Descriptor)
```

#### Внешние ссылки
- `/etc/init.d/wan.sh start` / `stop` — вызывается при смене линка

#### Зависимости
Нет зависимостей от других .ko модулей.

#### Поддерживаемые PHY-чипы
- Infeion 6996M (switch)
- ICPlus IC175C, IC175D (switch)
- Realtek 8305SB, 8305SC (switch)

---

### 3. fvmem.ko — Прямой доступ к памяти

**Размер**: 7 528 байт  
**Категория**: Аппаратное обеспечение / Отладка  
**Версия**: 1.00  
**Автор**: 5VTechnologies  
**Лицензия**: 5VT

#### Назначение
Драйвер для прямого чтения/записи физической и виртуальной памяти через char-устройство. Используется для отладки и доступа к hardware-регистрам (memory-mapped I/O).

#### Устройство
- `/dev/fvmem` (char-устройство, minor 0)

#### Команды через proc
```
base [address]              — установка базового адреса
md[.b|.w|.l] [addr] [count] — дамп памяти (byte/word/long)
mw[.b|.w|.l] [addr] [val]  — запись в память
vmd, vmw                    — аналогично для виртуальных адресов
```

#### Ключевые функции
```
fvmem_dev_init, fvmem_dev_open, fvmem_dev_release
fvmem_dev_read, fvmem_dev_write, fvmem_dev_ioctl, fvmem_dev_poll
fvmem_proc_read, fvmem_proc_write
fvmem_cmd_process, fvmem_cmd_baseaddr
```

#### Зависимости
Нет зависимостей.

---

### 4. fvspi.ko — Драйвер SPI-шины

**Размер**: 6 800 байт  
**Категория**: Шины / SPI  
**Версия**: v2.0  
**Автор**: 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Драйвер SPI-шины для FV13xx SoC. Используется для связи с периферией: SLIC (Si3210/Si3215), возможно flash, и другими SPI-устройствами.

#### Регистры SPI-контроллера
```
IER, FCR, FWCR, DLYCR, TxCR, RxCR, SSCR, ISR
SPI_CONFIG_N_SET: fwcr, dlycr, sscr, io_size
```

#### Экспортируемые символы
```
spi_show_reg     — показать регистры SPI
fvspi_config_io  — конфигурация SPI I/O
```

#### Ключевые функции
```
fvspi_init, fvspi_exit, fvspi_open, fvspi_release, fvspi_ioctl
fvspi_init_config, fvspi_deinit_config
spi_config, spi_config_pool
```

#### Зависимости
Нет зависимостей.

---

### 5. fvgpio.ko — Управление GPIO

**Размер**: 6 720 байт  
**Категория**: GPIO  
**Версия**: v0.1  
**Автор**: Scott Shu  
**Лицензия**: GPL

#### Назначение
Универсальный драйвер GPIO для FV13xx (MPW1). Используется для управления:
- LED-индикаторами
- Сбросом GSM-модемов
- Детекцией SIM-карт
- Управление реле/переключателями

#### Устройство
- `/dev/gpio0`, `/dev/gpio1`, ... (char-устройства)

#### Proc-интерфейс
```
/proc/gpio/direction — направление (вход/выход)
/proc/gpio/data      — данные
/proc/gpio/bitmask   — битовая маска
```

#### Ключевые функции
```
init_gpio_module, cleanup_gpio_module
device_open, device_release, device_read, device_write, device_ioctl, device_llseek
gpio_read_proc, gpio_reg
fv_get_cpuid — получение ID процессора
```

#### Зависимости
Нет зависимостей.

---

### 6. fvnet.ko — Fastpath для IP-пакетов

**Размер**: 6 872 байт  
**Категория**: Сеть  
**Версия**: 2008/11/11  
**Автор**: YFCHOU, 5VT Software  
**Лицензия**: 5VT

#### Назначение
Модуль быстрого пути (fastpath) для маршрутизации IP-пакетов в обход стандартного стека. Использует netfilter-хуки (pre-routing, forwarding). Ускоряет обработку пакетов за счёт кэша conntrack.

#### Proc-интерфейс
```
enable [0|1]    — включить/выключить fastpath
urlchk [0|1]    — проверка URL
ct_cleanup      — очистка conntrack
reset           — сброс счётчиков
```

#### Счётчики
```
fastpath_hh       — обработано через header cache
fastpath_neighbour — через neighbour cache
slowpath          — через стандартный стек
```

#### Ключевые функции
```
fvnet_init, fvnet_cleanup
fvnet_pre, fvnet_fwd — хуки netfilter
fvnet_proc_read, fvnet_proc_write
```

#### Зависимости
Нет зависимостей (использует ip_conntrack из ядра).

---

### 7. fvipdef.ko — Защита от IP-атак (IDS)

**Размер**: 9 612 байт  
**Категория**: Безопасность / IDS  
**Автор**: ROGER, 5VT Software  
**Лицензия**: GPL

#### Назначение
Модуль обнаружения и блокировки сетевых атак:
- LAND Attack
- TCP NULL Scan
- TCP SYN Flood
- Port Scan
- Ping of Death
- SMURF Attack
- UDP Flood
- IP Spoofing
- ICMP Flood
- Zero Payload Length

#### Параметры модуля
```
ps_weight, ps_delay — параметры обнаружения port scan
lo_ports_weight, hi_ports_weight — веса портов
tcp_maxpps, udp_maxpps, icmp_maxpps — лимиты пакетов/сек
wanspoofip_s, lanspoofip_s — IP для проверки спуфинга
def_ifname — интерфейс защиты
policy — политика
masktime — время блокировки
```

#### Зависимости
Нет зависимостей.

---

### 8. nfext.ko — Netfilter Extension (NAT Hairpin, NAPT, CT Strict)

**Размер**: 35 288 байт  
**Категория**: Сеть / NAT  
**Автор**: 5VT Software  
**Лицензия**: GPL  
**Исходный путь**: `/home1/users/rapid/RELEASE_SDK/DBL_32176/trunk/drivers/NFEXT/`

#### Назначение
Расширение Netfilter с тремя подсистемами:

1. **CT Strict** — строгая проверка conntrack (TCP SYN reopen, TCP flag errors)
2. **NAPT/NATAMAP** — расширенное NAT с поддержкой cone NAT, port restricted, symmetric NAT
3. **NAT Hairpin** — поддержка NAT hairpin (loopback NAT)

#### Экспортируемые символы
```
exthook_nat_hairpin_modified_src_occupied
exthook_nat_hairpin_src_nat
```

#### Режимы NATAMAP
```
0: symmetric
1: port restricted
2: addr restricted
3: full cone
```

#### Proc-интерфейсы
```
/proc/nfext/ct_strict — управление CT strict
/proc/nfext/natamap   — настройки NAPT
/proc/nfext/nat_hairpin — настройки NAT hairpin
```

#### Зависимости
Нет зависимостей в поле depends=, но использует символы из: `exthook.ko`, ядро conntrack.

---

### 9. exthook.ko — Framework расширяемых хуков

**Размер**: 6 260 байт  
**Категория**: Ядро / Framework  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Базовый фреймворк для регистрации хуков ядра по именам. Позволяет другим модулям (brext, bwlimit, neigh, heap, unalign, qoshook, qosip, nfext, vtag) регистрировать свои обработчики через символические имена ядра.

#### Экспортируемые символы
```
exthook_find_addr_by_name  — найти адрес по имени символа
exthook_find_name_by_addr  — найти имя по адресу
exthook_find_module_by_addr — найти модуль по адресу
exthook_register           — зарегистрировать хук
exthook_unregister         — снять хук
```

#### Зависимости
Нет. **Является базовой зависимостью для множества модулей.**

---

### 10. brext.ko — Расширения бриджинга

**Размер**: 7 236 байт  
**Категория**: Сеть / Bridge  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Расширения для Linux bridge: контроль пересылки, multicast pass-up, multicast deliver, статические ID.

#### Хуки через exthook
```
exthook_br_should_forward
exthook_br_should_mpassup
exthook_br_should_mdeliver
exthook_br_use_staticid
exthook_br_debug_print
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 11. bwlimit.ko — Ограничение пропускной способности

**Размер**: 7 648 байт  
**Категория**: Сеть / QoS  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Ограничение исходящей пропускной способности по интерфейсам. Пакеты сверх лимита отбрасываются.

#### Настройки
```
interface [ifname|none]
max N (kbit/s, 0 = disabled)
interval N (seconds)
debug N (0..2)
```

#### Хуки
```
exthook_bwlimit_update
exthook_bwlimit_is_over_max
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 12. qoshook.ko — QoS-хуки для планировщика

**Размер**: 7 344 байт  
**Категория**: Сеть / QoS  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Перехват планировщика задач для QoS: управление приоритетами soft-interrupts, real-time задач, и стандартных процессов.

#### Экспортируемые символы
```
qoshook_add_pack    — добавить обработчик пакетов
qoshook_remove_pack — удалить обработчик
```

#### Хуки
```
exthook_sched_wake_up
exthook_sched_switch_tasks
exthook_sched_rt
```

#### Режимы приоритетов
```
0: si > rt > np (soft-irq > real-time > normal)
1: rt > si > np
2: rt > np > si
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 13. qosip.ko — QoS по IP-протоколам

**Размер**: 10 108 байт  
**Категория**: Сеть / QoS  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Управление приоритетами сетевых пакетов на основе:
- IP-протокола
- TCP/UDP портов
- Привязки к интерфейсу

#### Хуки
```
exthook_sock_set_priority
exthook_sock_release
```

#### Зависимости
Зависит от: `exthook.ko`, `qoshook.ko`

---

### 14. vtag.ko — VLAN-тегирование

**Размер**: 15 592 байт  
**Категория**: Сеть / VLAN  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
VLAN-тегирование для VoIP-трафика. Разделяет голосовой и обычный трафик с разными VLAN-тегами. Поддерживает:
- Дублирование ARP, DHCP, ICMP пакетов
- Режимы: bypass, force tag, no tag, smart tag
- Таблицу клиентов с таймаутами

#### Настройки
```
wan_interface [devname|none]
vtag_lan2wan_voice [vlan_tag]
vtag_lan2wan_nonvoice [vlan_tag]
vtag_local2wan_voice [vlan_tag]
vtag_local2wan_nonvoice [vlan_tag]
mode_lan2wan [0..2]
mode_wan2lan [0..2]
mode_lan2lan [0..2]
mode_local2wan [0|1]
mode_local2lan [0|1]
client_max [n]
client_timeout [seconds]
duparp_enable, dupdhcp_enable, dupicmp_enable [0|1]
```

#### Зависимости
Зависит от: `qoshook.ko`

---

### 15. sniffer.ko — Пакетный сниффер

**Размер**: 18 368 байт  
**Категория**: Сеть / Диагностика  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Встроенный пакетный сниффер с поддержкой декодирования:
- Ethernet (IP, ARP, RARP, IPX, PPPoE, 802.1Q, EAPOL)
- IP (TCP, UDP, ICMP, IGMP, GRE, ESP)
- Прикладные протоколы (DHCP, NetBios, PauseFrame)
- PPPoE сессии (CHAP, IPCP, IPV6CP, IPV6)

#### Фильтры
```
level [N]          — уровень детализации
dev [devname|any]  — интерфейс
dir [T|R|B]        — направление (Tx/Rx/Both)
eth_proto          — Ethernet-протокол
ip_proto           — IP-протокол
ip_addr            — IP-адрес
port               — порт
mac_addr           — MAC-адрес
skbcb_range        — диапазон skb->cb
ignore_smb [0|1]   — игнорировать SMB
contchk            — проверка непрерывности
```

#### Зависимости
Зависит от: `qoshook.ko`

---

### 16. neigh.ko — Отладка ARP-соседей

**Размер**: 5 392 байт  
**Категория**: Сеть / Отладка  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Отладочный модуль для отслеживания состояний ARP-соседей: INCOMPLETE, REACHABLE, STALE, DELAY, PROBE, FAILED, NOARP, PERMANENT.

#### Хуки
```
exthook_neigh_debug_print
exthook_neigh_state_check
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 17. heap.ko — Мониторинг кучи

**Размер**: 4 084 байт  
**Категория**: Ядро / Отладка  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Отслеживание использования кучи (brk) процессами. Перехватывает sys_brk.

#### Хуки
```
exthook_sys_brk
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 18. unalign.ko — Отслеживание невыровненных обращений

**Размер**: 4 780 байт  
**Категория**: Ядро / Отладка  
**Автор**: 5VT Software  
**Лицензия**: 5VT

#### Назначение
Ведение статистики и отладка невыровненных обращений к памяти (ARM alignment faults).

#### Хуки
```
exthook_alignment_update
```

#### Зависимости
Зависит от: `exthook.ko`

---

### 19. wd.ko — Watchdog-таймер

**Размер**: 4 464 байт  
**Категория**: Аппаратное обеспечение  
**Лицензия**: —

#### Назначение
Аппаратный watchdog-таймер. При отсутствии обновления вызывает перезагрузку устройства.

#### Устройство
- `/dev/watchdog` (misc-устройство)

#### Ключевые функции
```
wd_init, wd_reset, wd_reboot
wd_open, wd_release, wd_write, wd_ioctl
wd_keepalive, wd_reset_tick, wd_reset_count
wait_for_reboot
```

#### Зависимости
Нет зависимостей.

---

### 20. fv_alg_bnet.ko — ALG для Battle.Net / Starcraft

**Размер**: 22 556 байт  
**Категория**: Сеть / ALG  
**Автор**: Lance Wu, yf@5vtechnologies  
**Лицензия**: GPL

#### Назначение
Application Layer Gateway для игры Starcraft и Battle.Net. Обеспечивает проброс портов и NAT traversal для игровых сессий через NAT/маршрутизатор.

#### Ключевые функции
```
sc_help, sc_nat_help — хелперы conntrack/NAT
bnet_nat_hairpin_modified_src_occupied
bnet_nat_hairpin_src_nat
ip_conntrack_sc_expect — ожидание соединений
record_client, record_client_port, record_client_gameserver
```

#### Зависимости
Зависит от: ядро conntrack/NAT, `nfext.ko` (exthook_nat_hairpin_*)

---

### 21. fv_alg_dns.ko — ALG для DNS

**Размер**: 2 564 байт  
**Категория**: Сеть / ALG  
**Автор**: ALG-DNS, 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Conntrack-хелпер для DNS-трафика. Обновляет таймауты conntrack для DNS-соединений.

#### Зависимости
Нет зависимостей.

---

### 22. fv_alg_esp.ko — ALG для ESP (IPSec)

**Размер**: 5 172 байт  
**Категория**: Сеть / ALG  
**Автор**: Harald Welte, 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Conntrack protocol helper и NAT helper для ESP (Encapsulating Security Payload) протокола IPSec. Позволяет ESP-туннелям проходить через NAT.

#### Ключевые функции
```
esp_pkt_to_tuple, esp_invert_tuple, esp_packet, esp_new
esp_print_conntrack, esp_print_tuple
esp_help, esp_nat_expected, esp_expectfn
```

#### Зависимости
Нет зависимостей.

---

### 23. fv_alg_ftp.ko — ALG для FTP

**Размер**: 11 600 байт  
**Категория**: Сеть / ALG  
**Автор**: Rusty Russell  
**Лицензия**: GPL

#### Назначение
FTP conntrack и NAT helper. Обеспечивает:
- Отслеживание PORT и PASV/EPSV/EPRT команд
- Перезапись IP-адресов в FTP-данных для NAT traversal
- Поддержка нестандартных FTP-портов

#### Параметры модуля
```
ports — массив портов FTP (array of ushort)
loose — режим loose tracking (bool)
```

#### Экспортируемые символы
```
ip_nat_ftp_hook
```

#### Зависимости
Нет зависимостей.

---

### 24. fv_alg_ipsec.ko — ALG для IPSec (IKE)

**Размер**: 3 972 байт  
**Категория**: Сеть / ALG  
**Автор**: 5VTechnologies  
**Лицензия**: 5VT

#### Назначение
Conntrack-хелпер для IPSec IKE (порт 500 UDP). Отслеживает IKE-сессии и связанные ESP-потоки.

#### Ключевые функции
```
conntrack_ipsec_help
ipsec_info_add, ipsec_info_list
find_IKE, IKE_destroy
udp_ike_find_tuple, ike_udp_destroy
```

#### Зависимости
Нет зависимостей.

---

### 25. fv_alg_l2tp.ko — ALG для L2TP

**Размер**: 5 460 байт  
**Категория**: Сеть / ALG  
**Автор**: 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Conntrack-хелпер для L2TP VPN-туннелей. Отслеживает L2TP Tunnel ID и обеспечивает NAT traversal.

#### Ключевые функции
```
conntrack_l2tp_help
l2tp_GetTunnelId
l2tp_info_add, l2tp_info_destroy
l2tp_info_nat_tid_used, l2tp_info_nat_tid_find
l2tp_info_r_tid_find, l2tp_info_check_ct_tid
```

#### Зависимости
Поле depends содержит `l2tp`. 

---

### 26. fv_alg_msn.ko — ALG для MSN Messenger

**Размер**: 9 868 байт  
**Категория**: Сеть / ALG  
**Автор**: 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Conntrack и NAT хелпер для MSN Messenger. Обрабатывает:
- Invitation-Command в MSG пакетах
- IP-Address и Port в приглашениях
- Автоматическую DNAT для входящих соединений файлопередачи

#### Парсинг MIME-заголовков
```
MSG, MIME-Version, Content-Type: text/x-msmsgsinvite
Invitation-Command, Invitation-Cookie
IP-Address, Port, IP-Address-Enc64, Context-Data
```

#### Ключевые функции
```
conntrack_msn_help
msn_nat_expected, msn_expectfn
ip_nat_msn, ip_nat_msn_hook, ip_nat_msn_hook_expectfn
parse_ipaddr, get_string, get_num
file_transfer_ip_addr, file_transfer_port
```

#### Зависимости
Нет зависимостей.

---

### 27. fv_alg_sip.ko — ALG для SIP

**Размер**: 2 716 байт  
**Категория**: Сеть / ALG / VoIP  
**Автор**: 5VT  
**Лицензия**: GPL

#### Назначение
Минимальный conntrack-хелпер для SIP (Session Initiation Protocol). Управляет sysctl-переменной `ip_conntrack_sip_enable` для включения/выключения SIP ALG.

#### Ключевые функции
```
nf_ct_sip_init, nf_ct_sip_fini
ip_conntrack_sip_enable (sysctl)
```

#### Зависимости
Нет зависимостей.

---

### 28. fv_ipt_localport.ko — iptables: match по локальным портам

**Размер**: 3 212 байт  
**Категория**: Сеть / iptables  
**Лицензия**: —

#### Назначение
Модуль iptables match для проверки, используется ли порт локальным сокетом (TCP/UDP). Проверяет `tcp_hashinfo` и `udp_hash`.

#### Зарегистрированный match
- `localport`

#### Зависимости
Нет зависимостей.

---

### 29. fv_ipt_trigger.ko — iptables: Port Triggering

**Размер**: 3 700 байт  
**Категория**: Сеть / iptables  
**Автор**: 5VTechnologies  
**Лицензия**: GPL

#### Назначение
Модуль iptables target для динамического проброса портов (port triggering). При обнаружении исходящего соединения на trigger-порт автоматически создаётся правило DNAT для входящих соединений.

#### Зарегистрированный target
- `PORTTRIG`

#### Зависимости
Нет зависимостей.

---

### 30. fv_ipt_webstr.ko — iptables: фильтрация по URL/HTTP

**Размер**: 5 972 байт  
**Категория**: Сеть / iptables / Фильтрация  
**Лицензия**: —

#### Назначение
Модуль iptables match для фильтрации HTTP-трафика по URL и заголовку Host. Распознаёт метода GET, POST, HEAD.

#### Sysctl
- `ipt_webstr_debug` — отладка

#### Алгоритм работы
1. Определяет HTTP-метод (GET/POST/HEAD)
2. Извлекает заголовок `Host:`
3. Извлекает URL из строки запроса
4. Сравнивает со списком фильтров (строковое сравнение)

#### Зарегистрированный match
- `webstr`

#### Зависимости
Нет зависимостей.

---

### 31. firmware_class.ko — Загрузка firmware через sysfs

**Размер**: 10 256 байт  
**Категория**: Ядро  
**Автор**: Manuel Estrada Sainz  
**Лицензия**: GPL

#### Назначение
Стандартный Linux-модуль для загрузки firmware из пользовательского пространства через sysfs-интерфейс. Используется другими драйверами для запроса бинарных firmware-файлов.

#### Экспортируемые символы
```
release_firmware
request_firmware
request_firmware_nowait
```

#### Sysfs-интерфейс
```
/sys/class/firmware/
  timeout   — таймаут ожидания firmware
  loading   — статус загрузки (0/1/-1)
  data      — данные firmware (binary)
```

#### Зависимости
Нет зависимостей.

---

## Граф зависимостей между модулями

```
firmware_class.ko  (standalone)
    |
    +-- (используется ядром для загрузки firmware)

exthook.ko  (базовый фреймворк хуков)
    |
    +-- brext.ko
    +-- bwlimit.ko
    +-- neigh.ko
    +-- heap.ko
    +-- unalign.ko
    +-- qoshook.ko ──> qosip.ko
    |                    +-- vtag.ko
    |                    +-- sniffer.ko
    +-- nfext.ko ──> fv_alg_bnet.ko (hairpin NAT)

fvaci.ko     (standalone — ACI DSP)
fvmac.ko     (standalone — Ethernet MAC)
fvmem.ko     (standalone — memory access)
fvspi.ko     (standalone — SPI bus)
fvgpio.ko    (standalone — GPIO)
fvnet.ko     (standalone — fastpath)
fvipdef.ko   (standalone — IP defense)
wd.ko        (standalone — watchdog)

fv_alg_*.ko  (standalone — ALG helpers, используют ядро conntrack/NAT)
fv_ipt_*.ko  (standalone — iptables matches/targets)
```

## Загрузка модулей

В прошивке не обнаружен явный shell-скрипт загрузки модулей. Загрузка осуществляется бинарным файлом `/sbin/up` (119 512 байт) — кастомная программа инициализации системы, которая вызывается из цепочки:

```
inittab → /etc/init.d/rcS → /etc/init.d/rc → (вероятно, /sbin/up)
```

Утилиты `/sbin/insmod`, `/sbin/modprobe`, `/sbin/rmmod`, `/sbin/lsmod` присутствуют (символические ссылки на busybox, size=0).

Порядок загрузки модулей не зафиксирован в текстовых конфигах — он встроен в бинарный код `/sbin/up`.

**Предполагаемый порядок загрузки** (на основе зависимостей):
1. `firmware_class.ko` — базовый firmware loader
2. `exthook.ko` — фреймворк хуков (нужен почти всем)
3. `fvmem.ko` — доступ к памяти
4. `fvgpio.ko` — GPIO-управление
5. `fvspi.ko` — SPI-шина
6. `fvaci.ko` — ACI DSP (голос)
7. `fvmac.ko` — Ethernet MAC
8. `wd.ko` — watchdog
9. `fvnet.ko` — fastpath
10. `nfext.ko` — NAT extensions
11. `brext.ko` — bridge extensions
12. `bwlimit.ko` — bandwidth limit
13. `qoshook.ko` — QoS hooks
14. `qosip.ko` — QoS by IP
15. `vtag.ko` — VLAN tagging
16. `fvipdef.ko` — IP defense
17. `neigh.ko`, `heap.ko`, `unalign.ko` — отладка
18. `sniffer.ko` — сниффер
19. `fv_alg_*.ko` — ALG-хелперы
20. `fv_ipt_*.ko` — iptables-модули

## Аппаратная карта GoIP GST1610

На основе анализа модулей:

| Компонент | Модуль | Детали |
|-----------|--------|--------|
| **CPU** | — | ARM926EJ-S (ARMv5), FV13xx SoC (5VTechnologies) |
| **Ethernet** | fvmac.ko | Встроенный AMBA MAC, 2 порта, RMII |
| **PHY/Switch** | fvmac.ko | Infeion 6996M / ICPlus IC175C/D / Realtek 8305SB/SC |
| **SPI** | fvspi.ko | Встроенный SPI-контроллер FV13xx |
| **ACI/DSP** | fvaci.ko | PL040 ACI — аналоговый канальный интерфейс |
| **GPIO** | fvgpio.ko | Встроенный GPIO FV13xx |
| **Memory I/O** | fvmem.ko | Прямой доступ к hardware-регистрам |
| **Watchdog** | wd.ko | Аппаратный watchdog FV13xx |
| **Кодеки** | fvaci.ko | G.711 A-law/μ-law, 14/16-bit linear PCM |
| **DTMF детектор** | fvaci.ko | Аппаратно-программный, фильтры Гёрцеля |
| **Caller ID** | fvaci.ko | FSK CID детектор |
| **NAT/Firewall** | nfext.ko, fvipdef.ko, fv_ipt_*.ko | Full cone NAT, IDS, URL filter |

## Ключевые выводы

1. **Нет отдельного GSM-модуля** — управление GSM-модемами осуществляется из userspace через AT-команды по UART/USB (программы `ata`, `smb_module`), а не через kernel-модуль.

2. **Нет SLIC-модуля** (fvslic.ko) и **нет звукового модуля** (fvsnd.ko) — SLIC-управление интегрировано в ACI-драйвер fvaci.ko (через SPI / fvspi.ko).

3. **Нет USB-модуля** — USB-взаимодействие обеспечивается стандартными модулями ядра или встроено в ядро.

4. **5VTechnologies FV13xx** — вся платформа построена на SoC FV13xx от 5VTechnologies (тайваньская компания, специализирующаяся на VoIP SoC).

5. **SDK**: RELEASE_SDK/DBL_32176 — версия SDK разработки.

6. **Архитектура сети** — полноценный маршрутизатор с fastpath, NAT hairpin, QoS, VLAN, IDS, ALG для множества протоколов.

7. **Телефонная подсистема** — целиком реализована в fvaci.ko (DSP DTMF/CID/G.711) + userspace программы fvdsp/ata/mg/sipcli.
