# Полная инвентаризация SIP-связанных файлов в workspace c:\goip

> Дата: 2026-03-15  
> Найдено систематическим поиском по: файлам с "sip" в имени, файлам с SIP-кодом, эмуляторам GoIP, серверам, прокси, Media Gateway

---

## ИТОГ КЛЮЧЕВОГО ВОПРОСА

**Файлы, программно отправляющие/принимающие SIP-сообщения (REGISTER/INVITE/etc):** — **НЕТ НИ ОДНОГО** в workspace.

Все SIP-сигнализация выполняется бинарником `/usr/bin/sipcli` (ARM, oSIP, внутри прошивки GoIP).  
В workspace есть только:
- **Документация** по результатам реверс-инжиниринга sipcli
- **Конфигурационные скрипты**, задающие SIP-параметры (SIP_PROXY, SIP_REGISTRAR и т.д.)
- **Эмуляторы GoIP**, запускающие оригинальный sipcli в QEMU chroot
- **SMB/RSIM серверы и прокси** (протокол SIM-банка, НЕ SIP)
- **UDP-снифферы**, слушающие в том числе порт 5060

---

## 1. ДОКУМЕНТАЦИЯ (DOC_* файлы)

| Файл | Строк | Описание |
|------|-------|----------|
| [DOC_SIPCLI_ANALYSIS.md](DOC_SIPCLI_ANALYSIS.md) | 744 | Полный реверс-инжиниринг бинарника `sipcli` — oSIP стек, CLI-аргументы, шифрование, кодеки, MG протокол |
| [DOC_GST1610_SIP_EXAMPLES.md](DOC_GST1610_SIP_EXAMPLES.md) | 1800 | Справочник SIP-протокола GoIP с примерами REGISTER/INVITE/BYE/MESSAGE/etc для всех режимов |
| [RSIM_PROTOCOL_ANALYSIS.md](RSIM_PROTOCOL_ANALYSIS.md) | 461 | Анализ протокола RSIM (SIM-банк), включая взаимодействие smb_module ↔ ata ↔ sipcli |

---

## 2. ЭМУЛЯТОРЫ GoIP (запуск оригинальных ARM-бинарников через QEMU)

> **Роль**: Запускают оригинальный `sipcli` внутри QEMU-эмуляции ARM-прошивки GoIP.  
> Это **не** собственная реализация SIP — это запуск vendor-бинарника.

| Файл | Описание | Запускает sipcli? |
|------|----------|-------------------|
| [run_goip_emu.sh](run_goip_emu.sh) | Базовый эмулятор GoIP (chroot + qemu-arm-static) | Нет, только sysinfod + svcd + httpd |
| [run_goip_v3.sh](run_goip_v3.sh) | Эмуляция v3 — chroot + dynamic qemu-arm + LD_PRELOAD fix_bind | Нет, sysinfod + svcd + httpd |
| [run_goip_v4.sh](run_goip_v4.sh) | Эмуляция v4 — patched ARM binaries (addrlen 112→110) | Нет, sysinfod + svcd + httpd |
| [run_goip_v5.sh](run_goip_v5.sh) | Эмуляция v5 — без sysinfod (CPU 100%), с FIFO-feeder | Нет, svcd + httpd |
| [run_goip_v6.sh](run_goip_v6.sh) | Эмуляция v6 — persistent background services | Нет, svcd + httpd |
| [run_goip_full.sh](run_goip_full.sh) | Полная эмуляция с LD_PRELOAD | Нет, sysinfod + svcd + httpd |
| [run_goip_dynamic.sh](run_goip_dynamic.sh) | Эмуляция с dynamic qemu-arm | Нет, sysinfod + svcd + httpd |
| [setup_chroot_qemu.sh](setup_chroot_qemu.sh) | Подготовка chroot — копирование x86_64 библиотек для QEMU | Нет, вспомогательный |

> **Важно**: Ни один эмулятор НЕ запускает `sipcli` или `mg` — только инфраструктурные сервисы (svcd, httpd, sysinfod). SIP-стек не эмулируется.

---

## 3. ПРОШИВКА GoIP — БИНАРНИКИ SIP-СТЕКА

> Это бинарные файлы ARM из распакованной прошивки, НЕ исходный код.

| Файл | Описание | Тип |
|------|----------|-----|
| `fw_new/squashfs-root/usr/bin/sipcli` | **SIP User Agent** — основной SIP-клиент GoIP (658 KB, ARM OABI, oSIP) | Бинарник, SIP-КЛИЕНТ |
| `fw_new/squashfs-root/usr/bin/start_sip` | Shell-скрипт запуска sipcli с параметрами из syscfg (190 строк) | Скрипт запуска |
| `fw_new/squashfs-root/usr/bin/start_sip_port_change` | Периодический killall sipcli для смены порта | Вспомогательный |
| `fw_new/squashfs-root/usr/sbin/infosip` | Включение SIP debug (SIP_DEBUG=1 → /etc/ipin) | Утилита отладки |
| `fw_new/squashfs-root/usr/sbin/infogsmsip` | Включение GSM+SIP debug | Утилита отладки |
| `fw_new/squashfs-root/usr/sbin/sipdb` | SIP debug утилита | Утилита отладки |
| `fw_new/squashfs-root/usr/etc/syscfg/sip.def` | Определения конфигурационных параметров SIP (110 строк) | Конфигурация |
| `fw_new/sqfs_test/usr/bin/sipcli` | Копия sipcli в тестовой файловой системе | Бинарник |
| `fw_new/sqfs_test/usr/bin/start_sip` | Копия start_sip | Скрипт |
| `fw_new/sqfs_test/usr/bin/start_sip_port_change` | Копия | Скрипт |
| `fw_new/sqfs_test/usr/sbin/infosip` | Копия | Утилита |
| `fw_new/sqfs_test/usr/sbin/infogsmsip` | Копия | Утилита |
| `fw_new/sqfs_test/usr/sbin/sipdb` | Копия | Утилита |
| `fw_new/sqfs_test/usr/etc/syscfg/sip.def` | Копия | Конфигурация |

### Kernel modules (SIP ALG)

| Файл | Описание |
|------|----------|
| `extracted/qosip.ko` | Модуль ядра QoS для SIP |
| `extracted/fv_alg_sip.ko` | SIP ALG (Application Layer Gateway) для NAT |
| `fw_new/squashfs-root/lib/modules/2.6.17/fv13xx/qosip.ko` | То же, в squashfs |
| `fw_new/squashfs-root/lib/modules/2.6.17/fv13xx/fv_alg_sip.ko` | То же, в squashfs |

---

## 4. КОНФИГУРАЦИОННЫЕ СКРИПТЫ (задают SIP-параметры)

> Эти файлы НЕ генерируют SIP-сообщения, но конфигурируют SIP-параметры GoIP.

| Файл | Описание | Роль |
|------|----------|------|
| [flash_mod/flash_root/etc/init.d/custom_config.sh](flash_mod/flash_root/etc/init.d/custom_config.sh) | Пример persistent конфигурации — `setsyscfg SIP_PROXY=...` | Конфигурация SIP-сервера |
| [flash_mod/flash_root/etc/init.d/dnsmasq.sh](flash_mod/flash_root/etc/init.d/dnsmasq.sh) | DNS-конфиг: резолвит `sip_port0_registar_server_addr`, `sip_port0_proxy_server_addr` и т.д. | DNS для SIP |
| [flash_mod/flash_root/etc/init.d/nat.sh](flash_mod/flash_root/etc/init.d/nat.sh) | NAT: функция `nat_sip_alg()` — управление `/proc/sys/net/ipv4/ip_sip_conntrack` | NAT traversal для SIP |
| [fix_goip_device.sh](fix_goip_device.sh) | MySQL: задаёт SIP_CONFIG_MODE, SIP_LOCAL_PORT, SIP_REGISTER_EXPIRED, SIP_OUTBAND_DTMF_TYPE, etc | Конфигурация GoIP через autocfg БД |
| [add_goip_device.sh](add_goip_device.sh) | MySQL: SELECT SIP_LOCAL_PORT, RADMIN_PORT из GoIP_chanpin | Просмотр конфигурации |
| [verify_goip_autocfg2.sh](verify_goip_autocfg2.sh) | Проверка SIP_PROXY в конфигурации autocfg | Диагностика |
| [goip_build_jffs2.js](goip_build_jffs2.js) | Сборка JFFS2-образа /flash с возможностью задать SIP_PROXY/SIP_REGISTRAR | Сборка образа |
| [goip_method2.js](goip_method2.js) | Flash Method 2 — перезапись /flash через telnet, может задать SIP_SERVER | Прошивка |
| [goip_method2_v2.js](goip_method2_v2.js) | Flash Method 2 v2 — то же, улучшенная версия | Прошивка |

---

## 5. SMB/RSIM СЕРВЕРЫ И ПРОКСИ (SIM-банк, НЕ SIP)

> Протокол SMB (SIM Bank Module) — бинарный UDP, magic 0x43215678, порт 56011.  
> Это **НЕ** SIP, но тесно связано: smb_module на GoIP доставляет SIM-данные, а sipcli регистрирует GSM-каналы через SIP.

| Файл | Описание | Роль |
|------|----------|------|
| [smb_udp_server2.js](smb_udp_server2.js) | **Наиболее полный** виртуальный SIM-банк сервер (UDP 56011). 360 строк. Парсит KEEPALIVE, LOGIN, CSQ, IMEI, APDU. Отвечает BINDING_BOUND/BINDING_NONE. | СЕРВЕР (принимает GoIP) |
| [smb_udp_server.js](smb_udp_server.js) | Более ранняя версия виртуального SIM-банка (161 строк) | СЕРВЕР (принимает GoIP) |
| [smb_server.js](smb_server.js) | TCP SMB сервер на порту 56030 — захватывает raw GoIP smb_module данные | СЕРВЕР (TCP вариант) |
| [rsim_proxy.js](rsim_proxy.js) | **Transparent UDP proxy**: GoIP:56011 → PC:56011 → реальный RSIM 194.99.21.42:56011. Логирует всё. | ПРОКСИ (man-in-the-middle) |
| [rsim_mitm_proxy.js](rsim_mitm_proxy.js) | **MITM прокси**: перехватывает BINDING_NONE → инъектирует BINDING_BOUND + SIM_TYPE + START. Превращает GoIP в RSIM-клиент без реального SIM-банка. 311 строк. | ПРОКСИ (MITM с инъекцией) |
| [simbank_proxy.js](simbank_proxy.js) | UDP/TCP порт-прокси: Windows → WSL. Форвардит порты 56011 (UDP), 56012 (TCP). | СЕТЕВОЙ ПРОКСИ |
| [simbank_proxy.py](simbank_proxy.py) | Python-версия прокси SimBank | СЕТЕВОЙ ПРОКСИ |
| [rsim_real_client.js](rsim_real_client.js) | UDP-клиент RSIM — подключается к реальному SIM-банку | КЛИЕНТ (притворяется GoIP) |

---

## 6. UDP-СНИФФЕРЫ (слушают порт 5060 среди прочих)

| Файл | Описание | Слушает 5060? |
|------|----------|---------------|
| [udp_sniffer.js](udp_sniffer.js) | Слушает UDP на 11 портах, включая **5060** (SIP), пытает RC4-дешифрование DBLTEK | **ДА, порт 5060** |

---

## 7. ДИАГНОСТИЧЕСКИЕ СКРИПТЫ (проверяют SIP-конфигурацию)

| Файл | Описание |
|------|----------|
| [dump_rsim.py](dump_rsim.py) | Дампит SIP_REGISTRAR, SIP_PHONE_NUMBER, SIP_AUTH_ID, SIP_AUTH_PASSWD, SIP_CONFIG_MODE из GoIP по telnet |
| [test_persist5.py](test_persist5.py) | Тестирует getsyscfg/setsyscfg для SIP-параметров (SIP_REGISTRAR, SIP_LOCAL_PORT, etc) |
| [test_persist4.py](test_persist4.py) | Читает sip.def, проверяет syscfg SIP_HOST |
| [test_gsm_status.js](test_gsm_status.js) | Считывает ENDPOINT_TYPE, SIP_SVR, SIP_PORT из GoIP через telnet |
| [test_sim_diag.py](test_sim_diag.py) | Диагностика SIM: проверяет процессы ata/smb/sipcli |
| [rsim_apdu_test4.py](rsim_apdu_test4.py) | APDU тест: проверяет ata/smb/sipcli процессы |
| [rsim_apdu_test7.py](rsim_apdu_test7.py) | То же, проверяет /usr/bin/ata, /usr/bin/smb, sipcli |
| [check_smb2.js](check_smb2.js) | Мониторит процессы: ata, smb, start_smb, start_sip |
| [test_shell4.py](test_shell4.py) | Исследование: «infosip НЕ принимает $1 как exec arg», «sipdb echo $1 to /etc/ipin» |

---

## 8. ПРОШИВОЧНЫЕ UPDATE-СКРИПТЫ (останавливают sipcli)

| Файл | Описание |
|------|----------|
| `update_analysis/m_upgrd_1610_byline.sh` | `svcctl stop sipcli` перед обновлением |
| `update_analysis/m_upgrd_1310_byline.sh` | `svcctl stop sipcli` |
| `update_analysis/m_upgrd_1610.sh` | `svcctl stop sipcli` |
| `update_analysis/m_upgrd_1310.sh` | `svcctl stop sipcli` |
| `update_analysis/m35up.sh` | `svcctl stop sipcli` |
| `update_analysis/mxxup.sh` | `svcctl stop sipcli` |
| `update_analysis/h330up.sh` | `svcctl stop sipcli` |
| `update_analysis/h330up2.sh` | `svcctl stop sipcli` |
| `update_analysis/h330uptest.sh` | `svcctl stop sipcli` |
| `dbltek_update/m_upgrd_1610_byline.sh` | Копии в `dbltek_update/` — аналогично |
| `dbltek_update/m_upgrd_1610.sh` | |
| `dbltek_update/m_upgrd_1310_byline.sh` | |
| `dbltek_update/m_upgrd_1310.sh` | |
| `dbltek_update/mxxup.sh` | |
| `dbltek_update/m35up.sh` | |
| `dbltek_update/h330up.sh` | |
| `dbltek_update/h330up2.sh` | |
| `dbltek_update/h330uptest.sh` | |

---

## 9. AUTOCFG HTML-ШАБЛОНЫ (SIP Timer настройки)

Веб-шаблоны конфигурации SIP-таймеров для разных моделей:

| Директория | Модель | Вариант |
|-----------|--------|---------|
| `goip-auto-config/.../autocfg_en/template/admin/goip/` | GoIP | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/4goip/` | GoIP-4 | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/8goip/` | GoIP-8 | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/16goip/` | GoIP-16 | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/32goip/` | GoIP-32 | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/fxs/` | FXS | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/fxo/` | FXO | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/fxsp/` | FXSP | `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/fxso/` | FXSO | `siptimer.htm` / `siptimer_ata.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/fxsg/` | FXSG | `siptimer.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/htm/` | Generic | `sip_timer.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/vp102/` | VP102 | `siptimer_phone.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/vp202/` | VP202 | `siptimer_phone.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/ep838/` | EP838 | `siptimer_phone.htm` |
| `goip-auto-config/.../autocfg_en/template/admin/8201/` | 8201 | `siptimer_phone.htm` |

Аналогичный набор в `autocfg_utf8/` для UTF-8 версий.

HTML SIP Timer страницы в squashfs:
- `fw_new/squashfs-root/usr/share/httpd/default/en_US/include/sip_timer.html`
- `fw_new/squashfs-root/usr/share/httpd/default/en_US/include/gsm_sip_code_map.html`
- `fw_new/squashfs-root/usr/share/httpd/default/zh_CN/include/sip_timer.html`

---

## 10. АРХИТЕКТУРА SIP НА GoIP (из реверс-инжиниринга)

```
                    SIP Server (Asterisk, FreeSWITCH, VOS2000)
                           ▲
                           │ SIP/UDP port 5060
                           │ REGISTER, INVITE, BYE, MESSAGE...
                           ▼
┌──────────────────────────────────────────────────────────┐
│  GoIP Device (ARM, Linux 2.6.17)                        │
│                                                          │
│  /usr/bin/sipcli ─── SIP UA (GNU oSIP, 658 KB)         │
│       │                                                  │
│       │ unix socket /tmp/.mg_cli0                        │
│       ▼                                                  │
│  /usr/bin/mg ──── Media Gateway (RTP/кодеки)            │
│       │                                                  │
│       │ /dev/aci (kernel module fvaci.ko)                │
│       ▼                                                  │
│  /usr/bin/fvdsp ─ DSP процессор (7 потоков)             │
│                                                          │
│  /usr/bin/ata ──── GSM-контроллер (/dev/tts/0)          │
│       │                                                  │
│       │ unix socket /tmp/.smb1                           │
│       ▼                                                  │
│  /usr/bin/smb_module ── RSIM клиент (UDP 56011)         │
│                          → SIM-банк сервер               │
└──────────────────────────────────────────────────────────┘
```

---

## 11. КЛАССИФИКАЦИЯ: CLIENT vs SERVER

### Серверная сторона (принимает подключения GoIP)

| Файл | Протокол | Что делает |
|------|----------|-----------|
| `smb_udp_server2.js` | SMB/RSIM (UDP 56011) | Виртуальный SIM-банк — принимает GoIP smb_module |
| `smb_udp_server.js` | SMB/RSIM (UDP 56011) | Ранняя версия виртуального SIM-банка |
| `smb_server.js` | SMB (TCP 56030) | TCP-сервер для SMB-данных |
| `udp_sniffer.js` | Multi-port (вкл. 5060) | Пассивный UDP-мониторинг |

### Клиентская сторона (притворяется GoIP)

| Файл | Протокол | Что делает |
|------|----------|-----------|
| `rsim_real_client.js` | SMB/RSIM (UDP 56011) | Подключается к реальному SIM-банку как GoIP |

### Прокси (man-in-the-middle)

| Файл | Протокол | Что делает |
|------|----------|-----------|
| `rsim_proxy.js` | SMB/RSIM (UDP 56011) | Transparent proxy GoIP ↔ реальный RSIM сервер |
| `rsim_mitm_proxy.js` | SMB/RSIM (UDP 56011) | MITM прокси с инъекцией BINDING_BOUND |
| `simbank_proxy.js` | SMB (UDP 56011, TCP 56012) | Порт-прокси Windows → WSL |
| `simbank_proxy.py` | SMB | Python-версия порт-прокси |

### Нет SIP-серверов/клиентов!

**В workspace НЕТ файлов, которые программно создают/парсят SIP-сообщения (REGISTER, INVITE и т.д.).** Вся SIP-логика заключена в ARM-бинарнике `sipcli`, который запускается только на реальном GoIP или в QEMU-эмуляции.

---

## 12. КЛЮЧЕВЫЕ ФАЙЛЫ ДЛЯ ПОНИМАНИЯ SIP-ПРОТОКОЛА

Приоритет чтения для разработки SIP-сервера/клиента:

1. **[DOC_GST1610_SIP_EXAMPLES.md](DOC_GST1610_SIP_EXAMPLES.md)** — полные примеры SIP-сообщений GoIP (1800 строк)
2. **[DOC_SIPCLI_ANALYSIS.md](DOC_SIPCLI_ANALYSIS.md)** — архитектура sipcli, CLI-параметры, шифрование (744 строки)
3. **[fw_new/squashfs-root/usr/bin/start_sip](fw_new/squashfs-root/usr/bin/start_sip)** — как sipcli запускается с параметрами (190 строк)
4. **[fw_new/squashfs-root/usr/etc/syscfg/sip.def](fw_new/squashfs-root/usr/etc/syscfg/sip.def)** — все конфигурационные ключи SIP (110 строк)
5. **[smb_udp_server2.js](smb_udp_server2.js)** — пример реализации сервера для GoIP (SMB-протокол, 360 строк)
6. **[rsim_mitm_proxy.js](rsim_mitm_proxy.js)** — MITM-прокси с инъекцией (311 строк)
