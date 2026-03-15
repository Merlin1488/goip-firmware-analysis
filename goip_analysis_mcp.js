#!/usr/bin/env node
/**
 * GoIP Analysis MCP Server
 * 
 * MCP-сервер для реверс-инжиниринга прошивки GoIP GST1610.
 * Анализирует бинари, конфиги, ядерные модули, протоколы IPC.
 * Генерирует серверные фиксы/имплементации.
 * 
 * Транспорт: stdio (JSON-RPC 2.0)
 * Протокол: MCP 2024-11-05
 * 
 * Компоненты прошивки:
 *   sipcli, ata, mg, fvdsp, smb_module, radmcli, smpp_smsc, ioctl, ep, gsmdb
 *   Kernel: fvaci.ko, fvgpio.ko, fvnet.ko, fvspi.ko, fvmac.ko, fvmem.ko, ...
 *   IPC: Unix sockets /tmp/.mg_cli*, UDP, shared memory
 */

'use strict';

const readline = require('readline');
const fs = require('fs');
const path = require('path');
const { execSync, exec } = require('child_process');

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_NAME = 'goip-analysis';
const SERVER_VERSION = '1.0.0';

// Пути к прошивке
const FW_ROOT = path.join(__dirname, 'fw_new', 'squashfs-root');
const FW_BIN = path.join(FW_ROOT, 'usr', 'bin');
const FW_ETC = path.join(FW_ROOT, 'usr', 'etc');
const FW_SYSCFG = path.join(FW_ETC, 'syscfg');
const FW_TEST = path.join(__dirname, 'fw_new', 'sqfs_test');
const FW_MODULES = path.join(FW_TEST, 'lib', 'modules', '2.6.17', 'fv13xx');

// ═══════════════════════════════════════════════════════════════
// BINARY INVENTORY — все компоненты прошивки
// ═══════════════════════════════════════════════════════════════

const FIRMWARE_COMPONENTS = {
  // ─── Основные демоны ───
  sipcli: {
    path: 'usr/bin/sipcli',
    type: 'daemon',
    description: 'SIP User Agent. Регистрация, звонки (INVITE/BYE), SMS (MESSAGE), шифрование. Основной VoIP стек.',
    arch: 'ARM OABI',
    libs: 'uClibc 0.9.29, GNU oSIP (static)',
    ipc: [
      'Unix socket /tmp/.mg_cli0 (→ mg)',
      'UDP (SIP signaling)',
      'setsyscfg/getsyscfg (→ syscfg.def)',
    ],
    cli_params: [
      '-g mode (0=SINGLE, 1=LINE, 2=TRUNK_GW, 3=GROUP)',
      '-o addr — прокси', '-p port — SIP порт',
      '-u authid', '-a passwd', '-e phone', '-r registrar',
      '-R regist_period', '-K kpalive_period', '-k kpalive_mode',
      '-E encryption', '-y key', '-z nat_mode', '-Z stun_server',
      '-I dtmf_mode', '-f codec', '-D qos_tos', '-J session_exp',
      '--rc4-crypt --rc4-key KEY', '--fast-crypt', '--vos-crypt',
      '--avs-crypt', '--n2c-crypt', '--ecm-crypt',
      '--et263-crypt --et263-crypt-type T --et263-crypt-dep D',
      '--agent VENDOR_ID', '--nowait', '--noalive',
      '--gateway 1', '--syscfg', '--line-prefix N',
      '--trunk-gw GW1,GW2,GW3', '--proxy-mode', '--proxy-passwd P',
      '--random-port PORT', '--wan-addr IP --nat-fw',
      '--ptime PERIOD', '--dtmf PT', '--obddtmf TYPE',
      '--reg-mode M', '--exp-mode M', '--link-test',
      '--early-media N', '--inv-auth N', '--sms-tonum',
      '--vrb', '--pkey', '--prefix-del 1', '--dialler-cmp 1',
      '--callee-mode 1', '--sip-rsp-mode 1', '--lport PORT',
      '--relay-server S', '--relay-port P', '--relay-encrypt',
    ],
    source_files: [
      'sipcli.c', 'sip_def.c', 'sip_auth.c', 'sip_msg.c', 'sip_call.c',
      'sip_register.c', 'sip_subscribe.c', 'sip_notify.c', 'sip_info.c',
      'sip_message.c', 'sip_option.c', 'sip_refer.c', 'sip_prack.c',
      'sip_publish.c', 'sip_update.c', 'sip_cancel.c', 'sip_ack.c',
      'sip_proxy.c', 'sip_media.c', 'sip_nat.c', 'sip_utils.c',
      'sip_transport.c', 'sip_crypt.c', 'sip_relay.c', 'sip_sms.c',
      'sip_config.c', 'sip_timer.c', 'sip_sdp.c',
    ],
    encryption: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
  },
  ata: {
    path: 'usr/bin/ata',
    type: 'daemon',
    description: 'ATA (Analog Telephone Adapter) / GSM модуль контроллер. Управляет GSM модемом, SIM, AT командами. Главный демон.',
    ipc: [
      '/dev/ttyS0, /dev/ttyS1 (serial → GSM modem)',
      'Unix socket /tmp/.ata_cli (→ sipcli, mg)',
      'setsyscfg/getsyscfg',
    ],
    cli_params: ['(read from syscfg, no CLI params)'],
    responsibilities: [
      'GSM модем инициализация (AT команды)',
      'SIM card management',
      'Вызовы GSM: ATD, ATA, ATH',
      'SMS отправка/приём: AT+CMGS, AT+CMGR',
      'DTMF: AT+VTD, AT+VTS',
      'Статус сигнала: AT+CSQ',
      'IMEI/IMSI: AT+CGSN, AT+CIMI',
      'Оператор: AT+COPS',
    ],
  },
  mg: {
    path: 'usr/bin/mg',
    type: 'daemon',
    description: 'Media Gateway. RTP обработка, кодеки, DTMF, T.38 факс. Мост между SIP RTP и GSM аудио через fvdsp.',
    ipc: [
      'Unix socket /tmp/.mg_cli0 (← sipcli)',
      '/dev/aci (→ fvaci.ko DSP)',
      'UDP (RTP media streams)',
    ],
    cli_params: [
      '-n NUM_CHANNELS', '--poll-inval MS', '--enable-watchdog',
      '--codec-preferenceN=CODECS', '--enable-fax',
      '-t TRANSPORT_TYPE', '--rc4-key=KEY',
      '--relay-server=S', '--relay-encrypt', '--relay-udp-ext1',
      '--rtp-tos=TOS', '--rtp-report-interval=SEC', '--rtp-dt=DT',
    ],
    responsibilities: [
      'RTP приём/отправка (UDP)',
      'Кодеки: G.711 A/μ-law, G.723.1, G.729, GSM',
      'DTMF RFC2833 (PT=101)',
      'T.38 факс',
      'Jitter buffer',
      'RC4/ET263 RTP шифрование',
      'QoS (TOS/DiffServ)',
      'NAT/STUN/Relay для RTP',
    ],
  },
  fvdsp: {
    path: 'usr/bin/fvdsp',
    type: 'daemon',
    description: 'DSP (Digital Signal Processor) управление. Интерфейс к ядерному модулю fvaci.ko. 7 потоков, /dev/aci.',
    ipc: [
      '/dev/aci (ioctl + mmap)',
      'shared memory (с mg)',
    ],
    responsibilities: [
      'DSP init/config',
      'Аудио каналы (PCM)',
      'Echo cancellation',
      'Silence detection (VAD)',
      'Tone generation (DTMF, ringback, busy)',
    ],
  },
  smb_module: {
    path: 'usr/bin/smb_module',
    type: 'daemon',
    description: 'SIM Bank клиент. Получает SIM-карты от удалённого SIM-банка по проприетарному UDP протоколу.',
    ipc: [
      'UDP 56011 (→ SIM Bank сервер)',
      'serial /dev/ttyS* (→ SIM card emulation)',
    ],
    cli_params: ['-t TIMEOUT'],
    protocol: {
      magic: '0x43215678',
      port: 56011,
      commands: ['HELLO', 'AUTH', 'SIM_SELECT', 'APDU_CMD', 'APDU_RSP', 'KEEPALIVE', 'STATUS'],
    },
    responsibilities: [
      'Подключение к SIM Bank серверу',
      'APDU relay (ISO 7816)',
      'SIM card switching/routing',
      'Keepalive, reconnection',
      'RC4 шифрование UDP payload',
    ],
  },
  radmcli: {
    path: 'usr/bin/radmcli',
    type: 'daemon',
    description: 'Remote Admin клиент. TCP tunnel к серверу удалённого управления (Radmin-подобный). Проброс HTTP и Telnet.',
    ipc: [
      'TCP → RADMIN_SERVER:RADMIN_PORT',
      'TCP → 127.0.0.1:HTTP_PORT (локальный web UI)',
      'TCP → 127.0.0.1:13000/23 (локальный telnet/FTN)',
    ],
    cli_params: [
      '-r SERVER:PORT', '-al LISTEN_ADDR:PORT (HTTP proxy)',
      '-ll LISTEN_ADDR:PORT (telnet proxy)',
      '-k KEY (auth key)', '-i ID (device ID)', '-t TIMEOUT',
    ],
    responsibilities: [
      'Обратный TCP тоннель к серверу управления',
      'Проброс HTTP web-интерфейса наружу',
      'Proброс Telnet/CLI наружу',
      'Аутентификация по ключу',
      'Keepalive, auto-reconnect',
    ],
    default_config: {
      key: 'dbl#admin',
      port: 1920,
      http_proxy: '127.0.0.1:80',
      telnet_proxy: '127.0.0.1:13000',
    },
  },
  smpp_smsc: {
    path: 'usr/bin/smpp_smsc',
    type: 'daemon',
    description: 'SMPP сервер/клиент. Альтернативный SMS gateway через SMPP протокол (вместо SIP MESSAGE).',
    ipc: ['TCP (SMPP)', 'Unix socket (→ ata)'],
  },
  ep: {
    path: 'usr/bin/ep',
    type: 'daemon',
    description: 'Endpoint manager. Координация между sipcli, mg, ata.',
    ipc: ['Unix sockets', 'signals'],
  },
  ioctl: {
    path: 'usr/bin/ioctl',
    type: 'tool',
    description: 'GPIO ioctl утилита. Управление LED индикаторами (REG, STA), реле, кнопками.',
    responsibilities: ['LED control', 'GPIO read/write', 'Hardware status'],
  },
  gsmdb: {
    path: 'usr/bin/gsmdb',
    type: 'tool',
    description: 'GSM database. Хранение SMS, контактов, логов звонков.',
  },
  'decrypt.RC4': {
    path: 'usr/bin/decrypt.RC4',
    type: 'tool',
    description: 'Утилита расшифровки RC4. Используется для расшифровки конфигов.',
  },
  ipp: {
    path: 'usr/bin/ipp',
    type: 'daemon',
    description: 'IP Phone manager. Управление IP-телефонными функциями.',
  },
  unimac: {
    path: 'usr/bin/unimac',
    type: 'tool',
    description: 'MAC address утилита. Установка/чтение MAC адреса.',
  },
};

// ─── Ядерные модули ───
const KERNEL_MODULES = {
  'fvaci.ko': {
    description: 'ACI (Audio Codec Interface) — основной DSP драйвер. /dev/aci. Обработка голоса.',
    device: '/dev/aci',
    ioctl_cmds: ['DSP_INIT', 'CHANNEL_OPEN', 'CHANNEL_CLOSE', 'CODEC_SET', 'PCM_READ', 'PCM_WRITE'],
  },
  'fvgpio.ko': { description: 'GPIO driver. LED, кнопки, реле, SIM detect.' },
  'fvnet.ko': { description: 'Network driver. Ethernet.' },
  'fvspi.ko': { description: 'SPI bus driver. Flash memory.' },
  'fvmac.ko': { description: 'MAC controller.' },
  'fvmem.ko': { description: 'Memory manager / shared memory.' },
  'fvipdef.ko': { description: 'IP default route / firewall rules.' },
  'exthook.ko': { description: 'Netfilter extension hooks.' },
  'bwlimit.ko': { description: 'Bandwidth limiter.' },
  'brext.ko': { description: 'Bridge extension.' },
  'vtag.ko': { description: 'VLAN tagging.' },
  'unalign.ko': { description: 'Unaligned memory access handler (ARM).' },
  'sniffer.ko': { description: 'Packet sniffer / mirror.' },
  'qosip.ko': { description: 'QoS IP classification.' },
  'qoshook.ko': { description: 'QoS netfilter hooks.' },
  'nfext.ko': { description: 'Netfilter extensions.' },
  'neigh.ko': { description: 'Neighbor table extensions.' },
  'heap.ko': { description: 'Kernel heap manager.' },
  'fv_alg_bnet.ko': { description: 'NAT ALG (Application Layer Gateway) for BNET.' },
  'fv_alg_dns.ko': { description: 'NAT ALG for DNS.' },
};

// ─── IPC карта ───
const IPC_MAP = {
  'sipcli ↔ mg': {
    mechanism: 'Unix socket /tmp/.mg_cli0',
    direction: 'bidirectional',
    data: 'Команды: open_channel, close_channel, codec_set, dtmf_send, rtp_start/stop',
    protocol: 'Proprietary binary, length-prefixed messages',
  },
  'sipcli ↔ ata': {
    mechanism: 'Unix socket + signals',
    direction: 'bidirectional',
    data: 'call_incoming, call_outgoing, call_answer, call_hangup, sms_send, sms_recv, dtmf, status',
  },
  'ata ↔ GSM modem': {
    mechanism: 'Serial /dev/ttyS0 (115200 8N1)',
    direction: 'AT commands ↔ responses',
    data: 'AT+CSQ, AT+COPS, ATD, ATA, ATH, AT+CMGS, AT+CMGR, AT+CGSN, AT+CIMI, ...',
  },
  'mg ↔ fvdsp': {
    mechanism: '/dev/aci (ioctl) + shared memory',
    direction: 'bidirectional',
    data: 'PCM audio data, codec control, DSP parameters',
  },
  'smb_module ↔ SIM Bank': {
    mechanism: 'UDP port 56011',
    direction: 'bidirectional',
    data: 'Magic 0x43215678, APDU relay, SIM select, keepalive',
    encryption: 'Optional RC4',
  },
  'radmcli ↔ Radmin Server': {
    mechanism: 'TCP to RADMIN_SERVER:RADMIN_PORT',
    direction: 'reverse tunnel',
    data: 'HTTP proxy (web UI), Telnet proxy (CLI), auth by key',
  },
  'all ↔ syscfg': {
    mechanism: 'setsyscfg/getsyscfg CLI tools → /usr/etc/syscfg/*.def',
    direction: 'read/write',
    data: 'Configuration key=value pairs',
  },
};

// ═══════════════════════════════════════════════════════════════
// MCP SERVER
// ═══════════════════════════════════════════════════════════════

class AnalysisMcpServer {
  constructor() {
    this._setupStdio();
  }

  _setupStdio() {
    const rl = readline.createInterface({ input: process.stdin, terminal: false });
    rl.on('line', (line) => {
      try {
        this._handleMessage(JSON.parse(line));
      } catch (e) {}
    });
    rl.on('close', () => process.exit(0));
  }

  _send(msg) { process.stdout.write(JSON.stringify(msg) + '\n'); }
  _sendResult(id, result) { this._send({ jsonrpc: '2.0', id, result }); }
  _sendError(id, code, message) { this._send({ jsonrpc: '2.0', id, error: { code, message } }); }

  _handleMessage(msg) {
    if (!msg.method) return;
    switch (msg.method) {
      case 'initialize':
        return this._sendResult(msg.id, {
          protocolVersion: PROTOCOL_VERSION,
          capabilities: { tools: {}, resources: {} },
          serverInfo: { name: SERVER_NAME, version: SERVER_VERSION },
        });
      case 'initialized': return;
      case 'tools/list':
        return this._sendResult(msg.id, { tools: TOOLS });
      case 'tools/call':
        return this._handleToolCall(msg);
      case 'resources/list':
        return this._sendResult(msg.id, { resources: RESOURCES });
      case 'resources/read':
        return this._handleResourceRead(msg);
      case 'ping':
        return this._sendResult(msg.id, {});
      default:
        if (msg.id !== undefined) this._sendError(msg.id, -32601, `Unknown: ${msg.method}`);
    }
  }

  _handleToolCall(msg) {
    const { name, arguments: args } = msg.params;
    try {
      const fn = HANDLERS[name];
      if (!fn) return this._sendError(msg.id, -32602, `Unknown tool: ${name}`);
      const result = fn(args || {});
      this._sendResult(msg.id, {
        content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }],
      });
    } catch (err) {
      this._sendResult(msg.id, {
        content: [{ type: 'text', text: `Error: ${err.message}\n${err.stack}` }],
        isError: true,
      });
    }
  }

  _handleResourceRead(msg) {
    const { uri } = msg.params;
    try {
      const handler = RESOURCE_HANDLERS[uri];
      if (!handler) return this._sendError(msg.id, -32602, `Unknown resource: ${uri}`);
      const { content, mimeType } = handler();
      this._sendResult(msg.id, { contents: [{ uri, mimeType, text: content }] });
    } catch (err) {
      this._sendError(msg.id, -32603, err.message);
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// TOOLS
// ═══════════════════════════════════════════════════════════════

const TOOLS = [
  // ─── Инвентаризация ───
  {
    name: 'fw_inventory',
    description: 'Полная инвентаризация прошивки GoIP: все бинари, размеры, типы, описания, IPC, зависимости. Стартовая точка для анализа.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_component',
    description: 'Детальная информация о конкретном компоненте прошивки: CLI параметры, IPC, обязанности, source files, шифрование',
    inputSchema: {
      type: 'object',
      properties: {
        name: { type: 'string', description: 'Имя бинаря: sipcli, ata, mg, fvdsp, smb_module, radmcli, smpp_smsc, ep, ioctl, gsmdb, decrypt.RC4, ipp, unimac' },
      },
      required: ['name'],
    },
  },
  {
    name: 'fw_ipc_map',
    description: 'Карта межпроцессного взаимодействия (IPC): Unix sockets, serial, UDP, shared memory, pipes между всеми компонентами',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_kernel_modules',
    description: 'Список ядерных модулей (.ko) прошивки: fvaci, fvgpio, fvnet, fvspi, и др. с описаниями',
    inputSchema: { type: 'object', properties: {} },
  },

  // ─── Бинарный анализ ───
  {
    name: 'fw_strings',
    description: 'Извлечь строки из бинарного файла прошивки (аналог GNU strings). Находит URL, IP, пути, AT команды, SIP заголовки, ключи шифрования.',
    inputSchema: {
      type: 'object',
      properties: {
        binary: { type: 'string', description: 'Имя бинаря (sipcli, ata, mg, radmcli, smb_module, ...)' },
        min_length: { type: 'number', description: 'Минимальная длина строки (default: 4)' },
        filter: { type: 'string', description: 'Regex фильтр строк (например: "AT\\+|sip:|http://|crypt|key|passwd")' },
        limit: { type: 'number', description: 'Макс. количество (default: 500)' },
      },
      required: ['binary'],
    },
  },
  {
    name: 'fw_elf_info',
    description: 'ELF заголовок бинаря: архитектура, endianness, entry point, sections, размер. Определяет ARM OABI/EABI, static/dynamic.',
    inputSchema: {
      type: 'object',
      properties: {
        binary: { type: 'string', description: 'Имя бинаря' },
      },
      required: ['binary'],
    },
  },
  {
    name: 'fw_hex_dump',
    description: 'Hex dump участка бинарного файла. Для анализа структур данных, magic bytes, заголовков.',
    inputSchema: {
      type: 'object',
      properties: {
        binary: { type: 'string', description: 'Имя бинаря' },
        offset: { type: 'number', description: 'Смещение в байтах (default: 0)' },
        length: { type: 'number', description: 'Длина (default: 256)' },
      },
      required: ['binary'],
    },
  },
  {
    name: 'fw_find_functions',
    description: 'Поиск имён функций в бинаре по строкам (debug symbols, error messages, format strings). Восстанавливает API.',
    inputSchema: {
      type: 'object',
      properties: {
        binary: { type: 'string', description: 'Имя бинаря' },
        pattern: { type: 'string', description: 'Regex паттерн для поиска (например: "sip_|mg_|ata_|smb_")' },
      },
      required: ['binary'],
    },
  },
  {
    name: 'fw_find_protocols',
    description: 'Анализ протоколов в бинаре: magic bytes, порты, SIP headers, AT команды, SMPP PDU, UDP structures',
    inputSchema: {
      type: 'object',
      properties: {
        binary: { type: 'string', description: 'Имя бинаря' },
      },
      required: ['binary'],
    },
  },

  // ─── Конфигурация ───
  {
    name: 'fw_config',
    description: 'Прочитать .def конфигурационный файл прошивки. Показывает все параметры с типами, значениями, алиасами.',
    inputSchema: {
      type: 'object',
      properties: {
        config: { type: 'string', description: 'Имя конфига: sip, ata, smb, common, fvdsp, h323, smpp, user, syscfg (top-level)' },
      },
      required: ['config'],
    },
  },
  {
    name: 'fw_startup_script',
    description: 'Прочитать стартовый скрипт компонента. Показывает как собираются параметры, зависимости, порядок запуска.',
    inputSchema: {
      type: 'object',
      properties: {
        script: { type: 'string', description: 'start_sip, start_ata, start_mg, start_smb, start_radm, start_fvdsp, start_httpd, start_ipp, start_imeimon, start_ntp2, start_waddrmon, start_ddnscli, start_sip_port_change, stop_fvdsp, stop_mg, custom_config (если есть)' },
      },
      required: ['script'],
    },
  },

  // ─── Анализ по компонентам ───
  {
    name: 'fw_analyze_radmcli',
    description: 'Глубокий анализ radmcli: протокол reverse tunnel, аутентификация, проброс HTTP/Telnet, reconnection. Для написания серверного фикса.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_analyze_smb',
    description: 'Глубокий анализ smb_module: протокол SIM Bank (magic 0x43215678, UDP 56011), APDU relay, SIM switching, RC4. Для серверной реализации.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_analyze_ata',
    description: 'Глубокий анализ ata: AT команды GSM модема, SIM management, SMS, звонки, статусы, конфиги.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_analyze_sipcli',
    description: 'Глубокий анализ sipcli: SIP стек (oSIP), 28 source files, все SIP методы, шифрование, proxy mode, trunk.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'fw_analyze_mg',
    description: 'Глубокий анализ mg: RTP, кодеки, DTMF, T.38, NAT, шифрование RTP, relay, QoS.',
    inputSchema: { type: 'object', properties: {} },
  },

  // ─── Генерация серверных фиксов ───
  {
    name: 'fw_gen_server_stub',
    description: 'Сгенерировать серверный stub/имплементацию для указанного компонента GoIP. Генерирует Node.js код серверной стороны на основе анализа протокола.',
    inputSchema: {
      type: 'object',
      properties: {
        component: {
          type: 'string',
          description: 'Компонент: radmcli_server, smb_server, sip_server, smpp_server, provisioning_server, status_api',
        },
        include_protocol_doc: { type: 'boolean', description: 'Включить документацию протокола в вывод' },
      },
      required: ['component'],
    },
  },
  {
    name: 'fw_gen_config_template',
    description: 'Генерация шаблона конфигурации для GoIP устройства на основе .def файлов. С комментариями и значениями по умолчанию.',
    inputSchema: {
      type: 'object',
      properties: {
        mode: { type: 'string', description: 'Режим: single, line, trunk, group' },
        include_all: { type: 'boolean', description: 'Включить все параметры (не только основные)' },
      },
    },
  },

  // ─── Утилиты ───
  {
    name: 'fw_list_files',
    description: 'Список файлов в директории прошивки',
    inputSchema: {
      type: 'object',
      properties: {
        dir: { type: 'string', description: 'Путь относительно squashfs-root (например: usr/bin, usr/etc, lib/modules)' },
      },
    },
  },
  {
    name: 'fw_read_file',
    description: 'Прочитать текстовый файл из прошивки или из рабочей директории проекта',
    inputSchema: {
      type: 'object',
      properties: {
        path: { type: 'string', description: 'Путь: относительно squashfs-root или абсолютный от c:\\goip' },
        max_lines: { type: 'number', description: 'Макс строк (default: 500)' },
      },
      required: ['path'],
    },
  },
  {
    name: 'fw_search',
    description: 'Поиск по всем файлам прошивки и проекта (grep-подобный)',
    inputSchema: {
      type: 'object',
      properties: {
        pattern: { type: 'string', description: 'Regex паттерн для поиска' },
        scope: { type: 'string', description: 'Область: firmware (squashfs), project (c:\\goip), all' },
        file_pattern: { type: 'string', description: 'Glob паттерн файлов (например: *.sh, *.def, *.js)' },
      },
      required: ['pattern'],
    },
  },
  {
    name: 'fw_existing_analysis',
    description: 'Получить существующий анализ из документации проекта (DOC_*.md, analyze_*.py)',
    inputSchema: {
      type: 'object',
      properties: {
        topic: { type: 'string', description: 'Тема: sipcli, sip_examples, client_protocol, inventory, fvaci, fvdsp, ata_sim, ata_proto, gpio, libtdi, pkg' },
      },
      required: ['topic'],
    },
  },
];

// ═══════════════════════════════════════════════════════════════
// RESOURCES
// ═══════════════════════════════════════════════════════════════

const RESOURCES = [
  { uri: 'goip://firmware/architecture', name: 'GoIP Firmware Architecture', description: 'Архитектура прошивки: компоненты, IPC, потоки данных', mimeType: 'text/markdown' },
  { uri: 'goip://firmware/radmcli-protocol', name: 'Radmcli Protocol', description: 'Протокол radmcli (reverse tunnel / remote admin)', mimeType: 'text/markdown' },
  { uri: 'goip://firmware/smb-protocol', name: 'SMB Protocol', description: 'Протокол SIM Bank (UDP, magic 0x43215678)', mimeType: 'text/markdown' },
  { uri: 'goip://firmware/configs', name: 'All Configs', description: 'Все .def конфигурационные файлы', mimeType: 'text/plain' },
];

const RESOURCE_HANDLERS = {
  'goip://firmware/architecture': () => ({
    mimeType: 'text/markdown',
    content: generateArchitectureDoc(),
  }),
  'goip://firmware/radmcli-protocol': () => ({
    mimeType: 'text/markdown',
    content: generateRadmcliDoc(),
  }),
  'goip://firmware/smb-protocol': () => ({
    mimeType: 'text/markdown',
    content: generateSmbDoc(),
  }),
  'goip://firmware/configs': () => ({
    mimeType: 'text/plain',
    content: readAllConfigs(),
  }),
};

// ═══════════════════════════════════════════════════════════════
// HANDLERS
// ═══════════════════════════════════════════════════════════════

function resolveBinaryPath(name) {
  // Попробуем оба корня прошивки
  for (const root of [FW_BIN, path.join(FW_TEST, 'usr', 'bin')]) {
    const p = path.join(root, name);
    if (fs.existsSync(p)) return p;
  }
  // Ядерные модули
  if (name.endsWith('.ko')) {
    const p = path.join(FW_MODULES, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function extractStrings(buf, minLen = 4) {
  const strings = [];
  let current = '';
  for (let i = 0; i < buf.length; i++) {
    const c = buf[i];
    if (c >= 0x20 && c < 0x7f) {
      current += String.fromCharCode(c);
    } else {
      if (current.length >= minLen) {
        strings.push({ offset: i - current.length, str: current });
      }
      current = '';
    }
  }
  if (current.length >= minLen) strings.push({ offset: buf.length - current.length, str: current });
  return strings;
}

function parseElfHeader(buf) {
  if (buf.length < 52 || buf[0] !== 0x7f || buf[1] !== 0x45 || buf[2] !== 0x4c || buf[3] !== 0x46) {
    return null;
  }
  const is32 = buf[4] === 1;
  const isLE = buf[5] === 1;
  const read16 = isLE ? (o) => buf.readUInt16LE(o) : (o) => buf.readUInt16BE(o);
  const read32 = isLE ? (o) => buf.readUInt32LE(o) : (o) => buf.readUInt32BE(o);

  const machineMap = { 3: 'x86', 8: 'MIPS', 40: 'ARM', 62: 'x86_64', 183: 'AArch64', 243: 'RISC-V' };
  const osabi = { 0: 'UNIX System V', 3: 'Linux', 97: 'ARM' };
  const typeMap = { 1: 'REL', 2: 'EXEC', 3: 'DYN (shared/PIE)', 4: 'CORE' };

  const flags = is32 ? read32(36) : read32(48);
  let abiInfo = '';
  if (read16(18) === 40) { // ARM
    abiInfo = (flags & 0x00000400) ? 'EABI5' : (flags & 0x00000200) ? 'EABI4' : 'OABI (old ABI)';
    if (flags & 0x00000800) abiInfo += ' hard-float';
  }

  return {
    class: is32 ? 'ELF32' : 'ELF64',
    endian: isLE ? 'Little Endian' : 'Big Endian',
    osabi: osabi[buf[7]] || `Unknown (${buf[7]})`,
    type: typeMap[read16(16)] || `Unknown (${read16(16)})`,
    machine: machineMap[read16(18)] || `Unknown (${read16(18)})`,
    flags: `0x${flags.toString(16)}`,
    abi: abiInfo,
    entryPoint: `0x${read32(is32 ? 24 : 24).toString(16)}`,
    phOffset: read32(is32 ? 28 : 32),
    shOffset: read32(is32 ? 32 : 40),
    phNum: read16(is32 ? 44 : 56),
    shNum: read16(is32 ? 48 : 60),
  };
}

const HANDLERS = {
  // ─── Инвентаризация ───
  fw_inventory() {
    const result = { binaries: {}, kernel_modules: {}, configs: [], scripts: [] };

    // Бинари
    for (const [name, info] of Object.entries(FIRMWARE_COMPONENTS)) {
      const fpath = resolveBinaryPath(name);
      let size = 0;
      if (fpath) {
        try { size = fs.statSync(fpath).size; } catch {}
      }
      result.binaries[name] = {
        type: info.type,
        description: info.description,
        size: size ? `${(size / 1024).toFixed(1)} KB` : 'not found',
        path: info.path,
      };
    }

    // Ядерные модули
    if (fs.existsSync(FW_MODULES)) {
      for (const f of fs.readdirSync(FW_MODULES)) {
        if (f.endsWith('.ko')) {
          const sz = fs.statSync(path.join(FW_MODULES, f)).size;
          result.kernel_modules[f] = {
            description: (KERNEL_MODULES[f] || {}).description || 'Unknown',
            size: `${(sz / 1024).toFixed(1)} KB`,
          };
        }
      }
    }

    // Конфиги
    if (fs.existsSync(FW_SYSCFG)) {
      result.configs = fs.readdirSync(FW_SYSCFG);
    }

    // Стартовые скрипты
    if (fs.existsSync(FW_BIN)) {
      result.scripts = fs.readdirSync(FW_BIN).filter(f => f.startsWith('start_') || f.startsWith('stop_'));
    }

    return result;
  },

  fw_component(args) {
    const info = FIRMWARE_COMPONENTS[args.name];
    if (!info) return { error: `Unknown: ${args.name}`, available: Object.keys(FIRMWARE_COMPONENTS) };

    const fpath = resolveBinaryPath(args.name);
    let size = 0, elfInfo = null;
    if (fpath) {
      try {
        const stat = fs.statSync(fpath);
        size = stat.size;
        const buf = Buffer.alloc(64);
        const fd = fs.openSync(fpath, 'r');
        fs.readSync(fd, buf, 0, 64, 0);
        fs.closeSync(fd);
        elfInfo = parseElfHeader(buf);
      } catch {}
    }

    return { ...info, size: size ? `${size} bytes (${(size / 1024).toFixed(1)} KB)` : 'not found', elf: elfInfo };
  },

  fw_ipc_map() { return IPC_MAP; },
  fw_kernel_modules() { return KERNEL_MODULES; },

  // ─── Бинарный анализ ───
  fw_strings(args) {
    const fpath = resolveBinaryPath(args.binary);
    if (!fpath) return { error: `Binary not found: ${args.binary}` };

    const buf = fs.readFileSync(fpath);
    let strings = extractStrings(buf, args.min_length || 4);

    if (args.filter) {
      const re = new RegExp(args.filter, 'i');
      strings = strings.filter(s => re.test(s.str));
    }

    const limit = args.limit || 500;
    return {
      binary: args.binary,
      size: buf.length,
      totalStrings: strings.length,
      strings: strings.slice(0, limit).map(s => ({ offset: `0x${s.offset.toString(16)}`, str: s.str })),
      truncated: strings.length > limit,
    };
  },

  fw_elf_info(args) {
    const fpath = resolveBinaryPath(args.binary);
    if (!fpath) return { error: `Binary not found: ${args.binary}` };

    const buf = Buffer.alloc(64);
    const fd = fs.openSync(fpath, 'r');
    fs.readSync(fd, buf, 0, 64, 0);
    fs.closeSync(fd);

    const elf = parseElfHeader(buf);
    if (!elf) return { error: 'Not an ELF file', magic: buf.slice(0, 4).toString('hex') };

    const stat = fs.statSync(fpath);
    return { binary: args.binary, size: stat.size, ...elf };
  },

  fw_hex_dump(args) {
    const fpath = resolveBinaryPath(args.binary);
    if (!fpath) return { error: `Binary not found: ${args.binary}` };

    const offset = args.offset || 0;
    const length = Math.min(args.length || 256, 4096);
    const fd = fs.openSync(fpath, 'r');
    const buf = Buffer.alloc(length);
    const bytesRead = fs.readSync(fd, buf, 0, length, offset);
    fs.closeSync(fd);

    const lines = [];
    for (let i = 0; i < bytesRead; i += 16) {
      const hex = [];
      let ascii = '';
      for (let j = 0; j < 16 && (i + j) < bytesRead; j++) {
        hex.push(buf[i + j].toString(16).padStart(2, '0'));
        const c = buf[i + j];
        ascii += (c >= 0x20 && c < 0x7f) ? String.fromCharCode(c) : '.';
      }
      lines.push(`${(offset + i).toString(16).padStart(8, '0')}  ${hex.join(' ').padEnd(48)}  |${ascii}|`);
    }

    return lines.join('\n');
  },

  fw_find_functions(args) {
    const fpath = resolveBinaryPath(args.binary);
    if (!fpath) return { error: `Binary not found: ${args.binary}` };

    const buf = fs.readFileSync(fpath);
    const strings = extractStrings(buf, 3);
    const pattern = args.pattern || '[a-z]+_[a-z]+';
    const re = new RegExp(pattern, 'i');

    // Ищем строки похожие на имена функций
    const funcLike = strings.filter(s => {
      return re.test(s.str) && /^[a-zA-Z_][a-zA-Z0-9_]*$/.test(s.str) && s.str.length >= 4 && s.str.length <= 60;
    });

    // Также ищем format strings с именами функций
    const formatStrings = strings.filter(s => {
      return s.str.includes('%s') || s.str.includes('%d') || s.str.includes('error') || s.str.includes('fail') || s.str.includes('debug');
    });

    return {
      binary: args.binary,
      functionNames: funcLike.slice(0, 200).map(s => s.str),
      formatStrings: formatStrings.slice(0, 100).map(s => ({ offset: `0x${s.offset.toString(16)}`, str: s.str })),
    };
  },

  fw_find_protocols(args) {
    const fpath = resolveBinaryPath(args.binary);
    if (!fpath) return { error: `Binary not found: ${args.binary}` };

    const buf = fs.readFileSync(fpath);
    const strings = extractStrings(buf, 3);
    const all = strings.map(s => s.str);

    const result = {
      binary: args.binary,
      sip: all.filter(s => /^(REGISTER|INVITE|BYE|ACK|CANCEL|OPTIONS|MESSAGE|INFO|REFER|SUBSCRIBE|NOTIFY|PRACK|UPDATE|PUBLISH|SIP\/2\.0|Via:|From:|To:|Call-ID|CSeq|Contact:|Content-)/.test(s)),
      at_commands: all.filter(s => /^AT[\+\#\$]?[A-Z]/.test(s)),
      http: all.filter(s => /^(GET|POST|HTTP\/|Host:|Content-Type)/.test(s)),
      urls: all.filter(s => /^(https?:\/\/|sip:|tel:)/.test(s)),
      paths: all.filter(s => /^\/(usr|etc|tmp|dev|var|proc)\//.test(s)),
      ports: all.filter(s => /\b(5060|56011|80|443|8080|13000|1920|21000|23)\b/.test(s) && s.length < 40),
      crypto: all.filter(s => /rc4|crypt|cipher|key|encrypt|decrypt|hash|md5|sha/i.test(s)),
      ipc: all.filter(s => /socket|pipe|ioctl|mmap|shm|sem|signal|fork|exec/i.test(s)),
      errors: all.filter(s => /error|fail|cannot|unable|invalid|timeout|refused|denied/i.test(s)).slice(0, 50),
    };

    return result;
  },

  // ─── Конфигурация ───
  fw_config(args) {
    const name = args.config === 'syscfg' ? 'syscfg.def' : `${args.config}.def`;
    const cfgPath = args.config === 'syscfg'
      ? path.join(FW_ETC, 'syscfg.def')
      : path.join(FW_SYSCFG, name);

    if (!fs.existsSync(cfgPath)) {
      // Пробуем sqfs_test
      const alt = path.join(FW_TEST, 'usr', 'etc', args.config === 'syscfg' ? 'syscfg.def' : path.join('syscfg', name));
      if (!fs.existsSync(alt)) return { error: `Config not found: ${name}`, available: ['sip', 'ata', 'smb', 'common', 'fvdsp', 'h323', 'smpp', 'user', 'syscfg'] };
      return { config: name, content: fs.readFileSync(alt, 'utf-8') };
    }

    const content = fs.readFileSync(cfgPath, 'utf-8');
    // Парсим .def формат
    const params = [];
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const parts = trimmed.split(/\s+/);
      const entry = { name: parts[0] };
      if (parts.includes('-n')) entry.notSaved = true;
      if (parts.includes('alias')) {
        entry.type = 'alias';
        entry.aliases = parts.slice(parts.indexOf('alias') + 1);
      } else if (parts.includes('choice')) {
        entry.type = 'choice';
        entry.options = parts.slice(parts.indexOf('choice') + 1);
      } else if (parts.includes('string')) entry.type = 'string';
      else if (parts.includes('integer')) {
        entry.type = 'integer';
        const range = parts.find(p => /^\d+-\d+$/.test(p));
        if (range) entry.range = range;
      }
      else if (parts.includes('bool')) entry.type = 'bool';
      else if (parts.includes('ip')) entry.type = 'ip';
      else entry.type = parts[1] || 'unknown';
      params.push(entry);
    }

    return { config: name, paramCount: params.length, params, raw: content };
  },

  fw_startup_script(args) {
    const scriptPath = path.join(FW_BIN, args.script);
    if (!fs.existsSync(scriptPath)) {
      // Пробуем sqfs_test
      const alt = path.join(FW_TEST, 'usr', 'bin', args.script);
      if (!fs.existsSync(alt)) return { error: `Script not found: ${args.script}` };
      return { script: args.script, content: fs.readFileSync(alt, 'utf-8') };
    }
    return { script: args.script, content: fs.readFileSync(scriptPath, 'utf-8') };
  },

  // ─── Глубокий анализ ───
  fw_analyze_radmcli() {
    const info = FIRMWARE_COMPONENTS.radmcli;
    const fpath = resolveBinaryPath('radmcli');
    let strings = [];
    if (fpath) {
      const buf = fs.readFileSync(fpath);
      strings = extractStrings(buf, 4).map(s => s.str);
    }

    return {
      component: 'radmcli',
      description: info.description,
      cli_params: info.cli_params,
      default_config: info.default_config,
      protocol_analysis: {
        transport: 'TCP',
        direction: 'Client → Server (reverse tunnel)',
        auth: {
          method: 'Key-based (-k flag)',
          default_key: 'dbl#admin',
          format: 'Likely cleartext or simple hash in handshake',
        },
        tunneling: {
          http_proxy: 'Пробрасывает HTTP запросы к локальному web UI (127.0.0.1:80)',
          telnet_proxy: 'Пробрасывает Telnet к локальному CLI (127.0.0.1:13000 или 23)',
          method: 'Multiplexed TCP channels over single connection',
        },
        keepalive: {
          interval: '30s (-t flag)',
          mechanism: 'Periodic heartbeat packets',
        },
        reconnect: 'Auto-reconnect on disconnect',
      },
      server_requirements: {
        description: 'Нужен TCP сервер который принимает подключения от radmcli и маршрутизирует HTTP/Telnet трафик',
        features: [
          'TCP listener на RADMIN_PORT (default 1920)',
          'Аутентификация по ключу',
          'Мультиплексирование каналов (HTTP + Telnet)',
          'Device ID tracking',
          'Keepalive monitoring',
          'Web UI для доступа к устройствам',
        ],
      },
      relevant_strings: strings.filter(s => /connect|auth|key|tunnel|proxy|channel|heartbeat|login|socket/i.test(s)).slice(0, 100),
    };
  },

  fw_analyze_smb() {
    const info = FIRMWARE_COMPONENTS.smb_module;
    const fpath = resolveBinaryPath('smb_module');
    let strings = [];
    if (fpath) {
      const buf = fs.readFileSync(fpath);
      strings = extractStrings(buf, 4).map(s => s.str);
    }

    // Читаем smb.def
    let smbDef = '';
    const smbDefPath = path.join(FW_SYSCFG, 'smb.def');
    if (fs.existsSync(smbDefPath)) smbDef = fs.readFileSync(smbDefPath, 'utf-8');

    return {
      component: 'smb_module',
      description: info.description,
      config: smbDef,
      protocol: info.protocol,
      protocol_analysis: {
        transport: 'UDP',
        port: 56011,
        magic: '0x43215678 (4 bytes header)',
        encryption: 'RC4 optional (SMB_RC4_KEY)',
        packet_structure: {
          header: '4 bytes magic + 2 bytes cmd + 2 bytes length + payload',
          commands_estimated: [
            '0x01 HELLO — initial handshake',
            '0x02 AUTH — authenticate with SMB_KEY',
            '0x03 SIM_SELECT — select SIM slot',
            '0x04 APDU_CMD — send APDU to SIM',
            '0x05 APDU_RSP — APDU response',
            '0x06 KEEPALIVE — heartbeat',
            '0x07 STATUS — device status',
            '0x08 RESET — reset SIM',
            '0x09 DISCONNECT',
          ],
        },
        sim_bank_flow: [
          'smb_module → HELLO (device ID, serial)',
          'SIM Bank → AUTH_CHALLENGE',
          'smb_module → AUTH_RESPONSE (SMB_KEY based)',
          'SIM Bank → AUTH_OK + SIM assignment',
          '... APDU relay loop ...',
          'Periodic KEEPALIVE',
        ],
      },
      server_requirements: {
        features: [
          'UDP listener на 56011',
          'Device registry (SMB_ID)',
          'SIM pool management',
          'APDU relay (ISO 7816-4)',
          'RC4 encryption support',
          'Keepalive monitoring',
          'SIM rotation/scheduling',
          'Web API for management',
        ],
      },
      relevant_strings: strings.filter(s => /sim|apdu|bank|slot|card|atr|select|rc4|key|auth|connect/i.test(s)).slice(0, 100),
    };
  },

  fw_analyze_ata() {
    const info = FIRMWARE_COMPONENTS.ata;
    const fpath = resolveBinaryPath('ata');
    let strings = [];
    if (fpath) {
      const buf = fs.readFileSync(fpath);
      strings = extractStrings(buf, 4).map(s => s.str);
    }

    const atCommands = strings.filter(s => /^AT[\+\#]?[A-Z]/.test(s));
    const statusVars = strings.filter(s => /^(LINE|STATUS|GSM|SIM|L1_|M1_)/.test(s));

    return {
      component: 'ata',
      description: info.description,
      at_commands: {
        found: atCommands,
        categories: {
          general: atCommands.filter(s => /^AT[EZHIOV]/.test(s)),
          gsm_network: atCommands.filter(s => /^AT\+(COPS|CREG|CSQ|CGREG)/.test(s)),
          sim: atCommands.filter(s => /^AT\+(CPIN|CIMI|CCID|CLCK)/.test(s)),
          sms: atCommands.filter(s => /^AT\+(CMGS|CMGR|CMGL|CMGD|CMGF|CNMI|CSMP|CSCA)/.test(s)),
          call: atCommands.filter(s => /^AT[DHA]|AT\+(CHUP|CLCC|CHLD)/.test(s)),
          dtmf: atCommands.filter(s => /^AT\+(VTD|VTS)/.test(s)),
          identity: atCommands.filter(s => /^AT\+(CGSN|GSN|CIMI|CGMR|CGMI|CGMM)/.test(s)),
          audio: atCommands.filter(s => /^AT\+(CLVL|CMUT|CMIC)/.test(s)),
        },
      },
      status_variables: statusVars.slice(0, 100),
      ipc: info.ipc,
      responsibilities: info.responsibilities,
    };
  },

  fw_analyze_sipcli() {
    const info = FIRMWARE_COMPONENTS.sipcli;
    const fpath = resolveBinaryPath('sipcli');
    let strings = [];
    if (fpath) {
      const buf = fs.readFileSync(fpath);
      strings = extractStrings(buf, 4).map(s => s.str);
    }

    const sipMethods = strings.filter(s => /^(REGISTER|INVITE|BYE|ACK|CANCEL|OPTIONS|MESSAGE|INFO|REFER|SUBSCRIBE|NOTIFY|PRACK|UPDATE|PUBLISH)$/.test(s));
    const sipHeaders = strings.filter(s => /^(Via|From|To|Call-ID|CSeq|Contact|Content-|Max-Forwards|User-Agent|Authorization|Proxy-|WWW-|X-ACrypt|Expires|Route|Record-Route)/i.test(s));

    return {
      component: 'sipcli',
      description: info.description,
      arch: info.arch,
      libs: info.libs,
      cli_params: info.cli_params,
      source_files: info.source_files,
      encryption: info.encryption,
      sip_methods: sipMethods,
      sip_headers: sipHeaders.slice(0, 50),
      ipc: info.ipc,
      format_strings: strings.filter(s => (s.includes('%s') || s.includes('%d')) && s.length > 8).slice(0, 80),
    };
  },

  fw_analyze_mg() {
    const info = FIRMWARE_COMPONENTS.mg;
    const fpath = resolveBinaryPath('mg');
    let strings = [];
    if (fpath) {
      const buf = fs.readFileSync(fpath);
      strings = extractStrings(buf, 4).map(s => s.str);
    }

    return {
      component: 'mg',
      description: info.description,
      cli_params: info.cli_params,
      responsibilities: info.responsibilities,
      ipc: info.ipc,
      codecs: strings.filter(s => /pcma|pcmu|g711|g723|g729|gsm|alaw|ulaw|telephone.event|t38|fax/i.test(s)).slice(0, 30),
      rtp_related: strings.filter(s => /rtp|rtcp|jitter|packet|sequence|timestamp|ssrc|payload/i.test(s)).slice(0, 50),
      crypto_related: strings.filter(s => /rc4|crypt|encrypt|key|cipher/i.test(s)).slice(0, 30),
      format_strings: strings.filter(s => (s.includes('%s') || s.includes('%d')) && s.length > 8).slice(0, 50),
    };
  },

  // ─── Генерация серверных фиксов ───
  fw_gen_server_stub(args) {
    const generators = {
      radmcli_server: generateRadmcliServerStub,
      smb_server: generateSmbServerStub,
      sip_server: generateSipServerStub,
      smpp_server: generateSmppServerStub,
      provisioning_server: generateProvisioningServerStub,
      status_api: generateStatusApiStub,
    };

    const gen = generators[args.component];
    if (!gen) return { error: `Unknown component: ${args.component}`, available: Object.keys(generators) };

    let result = gen();
    if (args.include_protocol_doc) {
      result.protocol_doc = getProtocolDoc(args.component);
    }
    return result;
  },

  fw_gen_config_template(args) {
    const mode = (args.mode || 'single').toUpperCase();
    const configs = {};

    // Читаем все .def файлы
    for (const defFile of ['sip', 'common', 'ata', 'smb']) {
      const cfgPath = path.join(FW_SYSCFG, `${defFile}.def`);
      if (fs.existsSync(cfgPath)) {
        const content = fs.readFileSync(cfgPath, 'utf-8');
        for (const line of content.split('\n')) {
          const parts = line.trim().split(/\s+/);
          if (!parts[0] || parts[0].startsWith('#')) continue;
          configs[parts[0]] = { type: parts.includes('string') ? 'string' : parts.includes('bool') ? 'bool' : parts.includes('integer') ? 'integer' : parts[1] || 'unknown', file: defFile };
        }
      }
    }

    const template = {};
    // Основные для каждого режима
    const coreParams = {
      SINGLE: ['SIP_CONFIG_MODE=SINGLE_MODE', 'SIP_REGISTRAR=', 'SIP_PROXY=', 'SIP_AUTH_ID=', 'SIP_AUTH_PASSWD=', 'SIP_PHONE_NUMBER=', 'SIP_DISPLAY_NAME=', 'SIP_LOCAL_PORT=5060'],
      LINE: ['SIP_CONFIG_MODE=LINE_MODE', 'SIP_CONTACT8_PROXY=', 'SIP_CONTACT8_LOGIN=', 'SIP_CONTACT8_PASSWD=', 'SIP_CONTACT8_DIAL_DIGITS=', 'SIP_CONTACT9_PROXY='],
      TRUNK_GW: ['SIP_CONFIG_MODE=TRUNK_GW_MODE', 'SIP_TRUNK_GW1=', 'SIP_TRUNK_GW2=', 'SIP_TRUNK_GW3=', 'SIP_TRUNK_AUTH_ID=', 'SIP_TRUNK_AUTH_PASSWD=', 'SIP_TRUNK_NUMBER='],
      GROUP: ['SIP_CONFIG_MODE=GROUP_MODE', 'SIP_GROUP_NUM=1'],
    };

    return {
      mode: `${mode}_MODE`,
      core_params: coreParams[mode] || coreParams['SINGLE'],
      all_params_count: Object.keys(configs).length,
      all_params: args.include_all ? configs : undefined,
    };
  },

  // ─── Утилиты ───
  fw_list_files(args) {
    const dir = args.dir || 'usr/bin';
    const fullPath = path.join(FW_ROOT, dir);
    if (!fs.existsSync(fullPath)) {
      const alt = path.join(FW_TEST, dir);
      if (!fs.existsSync(alt)) return { error: `Directory not found: ${dir}` };
      return { dir, files: fs.readdirSync(alt) };
    }
    return { dir, files: fs.readdirSync(fullPath) };
  },

  fw_read_file(args) {
    let fpath = args.path;
    // Относительно squashfs-root
    if (!path.isAbsolute(fpath)) {
      fpath = path.join(FW_ROOT, fpath);
      if (!fs.existsSync(fpath)) fpath = path.join(FW_TEST, args.path);
      if (!fs.existsSync(fpath)) fpath = path.join(__dirname, args.path);
    }
    if (!fs.existsSync(fpath)) return { error: `File not found: ${args.path}` };

    const stat = fs.statSync(fpath);
    if (stat.size > 1_000_000) return { error: `File too large: ${stat.size} bytes. Use fw_hex_dump or fw_strings.` };

    const content = fs.readFileSync(fpath, 'utf-8');
    const lines = content.split('\n');
    const maxLines = args.max_lines || 500;

    return {
      path: args.path,
      size: stat.size,
      lines: lines.length,
      content: lines.slice(0, maxLines).join('\n'),
      truncated: lines.length > maxLines,
    };
  },

  fw_search(args) {
    const scope = args.scope || 'all';
    const re = new RegExp(args.pattern, 'i');
    const filePattern = args.file_pattern ? new RegExp(args.file_pattern.replace(/\*/g, '.*').replace(/\?/g, '.')) : null;
    const results = [];

    function searchDir(dir, relBase) {
      if (!fs.existsSync(dir)) return;
      try {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
          const fullPath = path.join(dir, entry.name);
          const relPath = path.join(relBase, entry.name);
          if (entry.isDirectory()) {
            if (entry.name === 'node_modules' || entry.name === '.git') continue;
            searchDir(fullPath, relPath);
          } else if (entry.isFile()) {
            if (filePattern && !filePattern.test(entry.name)) continue;
            try {
              const stat = fs.statSync(fullPath);
              if (stat.size > 500_000) continue; // skip large binaries
              const content = fs.readFileSync(fullPath, 'utf-8');
              const lines = content.split('\n');
              for (let i = 0; i < lines.length; i++) {
                if (re.test(lines[i])) {
                  results.push({ file: relPath, line: i + 1, text: lines[i].trim().substring(0, 200) });
                  if (results.length > 200) return;
                }
              }
            } catch {}
          }
        }
      } catch {}
    }

    if (scope === 'firmware' || scope === 'all') searchDir(FW_ROOT, 'squashfs-root');
    if (scope === 'project' || scope === 'all') searchDir(__dirname, '.');

    return { pattern: args.pattern, scope, matchCount: results.length, matches: results };
  },

  fw_existing_analysis(args) {
    const docMap = {
      sipcli: 'DOC_SIPCLI_ANALYSIS.md',
      sip_examples: 'DOC_GST1610_SIP_EXAMPLES.md',
      client_protocol: 'DOC_GOIP_CLIENT_PROTOCOL.md',
      inventory: 'DOC_SIP_FILES_INVENTORY.md',
    };

    const analyzeMap = {
      fvaci: 'analyze_fvaci.py', fvaci2: 'analyze_fvaci2.py', fvaci3: 'analyze_fvaci3.py', fvaci4: 'analyze_fvaci4.py',
      fvdsp: 'analyze_fvdsp.py', ata_sim: 'analyze_ata_sim.py', ata_sim2: 'analyze_ata_sim2.py',
      ata_proto: 'analyze_ata_proto.py', gpio: 'analyze_gpio.py',
      libtdi: 'analyze_libtdi.py', libtdi2: 'analyze_libtdi2.py',
      pkg: 'analyze_pkg.py', pkg2: 'analyze_pkg2.py',
    };

    const file = docMap[args.topic] || analyzeMap[args.topic];
    if (!file) return { error: `Unknown topic: ${args.topic}`, available: [...Object.keys(docMap), ...Object.keys(analyzeMap)] };

    const fpath = path.join(__dirname, file);
    if (!fs.existsSync(fpath)) return { error: `File not found: ${file}` };

    const content = fs.readFileSync(fpath, 'utf-8');
    return { topic: args.topic, file, lines: content.split('\n').length, content };
  },
};

// ═══════════════════════════════════════════════════════════════
// SERVER STUB GENERATORS
// ═══════════════════════════════════════════════════════════════

function generateRadmcliServerStub() {
  return {
    component: 'radmcli_server',
    description: 'Сервер удалённого управления GoIP. Принимает reverse tunnel от radmcli, проксирует HTTP/Telnet.',
    filename: 'goip_radmin_server.js',
    skeleton: `
const net = require('net');
const http = require('http');

class RadminServer {
  constructor(port = 1920) {
    this.port = port;
    this.devices = new Map(); // id → { socket, info, channels }
    this.server = net.createServer(socket => this._onConnection(socket));
  }

  start() {
    this.server.listen(this.port, () => console.log(\`Radmin server on :\${this.port}\`));
  }

  _onConnection(socket) {
    // 1. Прочитать handshake (device ID, key)
    // 2. Аутентификация по ключу
    // 3. Добавить в devices
    // 4. Мультиплексировать каналы:
    //    - HTTP tunnel channel
    //    - Telnet tunnel channel
    // 5. Keepalive monitoring
    
    socket.on('data', (data) => {
      // TODO: Parse protocol frames
      // Frame format: [channel_id:1][length:2][payload:N]
      // channel 0 = control (auth, keepalive)
      // channel 1 = HTTP proxy
      // channel 2 = Telnet proxy
    });
  }

  // HTTP API для доступа к устройствам
  startApi(apiPort = 8080) {
    http.createServer((req, res) => {
      // GET /devices — список подключённых
      // GET /device/:id/web — проксирует HTTP к устройству
      // GET /device/:id/cli — WebSocket → Telnet
    }).listen(apiPort);
  }
}`,
    todo: [
      'Реверсить протокол radmcli: подключить к серверу, снять дамп',
      'Определить формат handshake пакета',
      'Определить формат мультиплексирования каналов',
      'Реализовать аутентификацию по ключу',
      'Реализовать HTTP/Telnet проксирование',
      'Web UI для управления устройствами',
    ],
  };
}

function generateSmbServerStub() {
  return {
    component: 'smb_server',
    description: 'SIM Bank сервер. Управляет пулом SIM-карт, раздаёт их GoIP устройствам через UDP.',
    filename: 'goip_simbank_server.js',
    skeleton: `
const dgram = require('dgram');

const MAGIC = Buffer.from([0x43, 0x21, 0x56, 0x78]);

class SimBankServer {
  constructor(port = 56011) {
    this.port = port;
    this.devices = new Map(); // addr:port → device state
    this.simPool = new Map(); // slot → { iccid, status, assignedTo }
    this.socket = dgram.createSocket('udp4');
    this.socket.on('message', (msg, rinfo) => this._onMessage(msg, rinfo));
  }

  start() {
    this.socket.bind(this.port, () => console.log(\`SIM Bank on :\${this.port}\`));
  }

  _onMessage(msg, rinfo) {
    // Validate magic bytes
    if (msg.length < 8 || !msg.slice(0, 4).equals(MAGIC)) return;
    
    const cmd = msg.readUInt16BE(4);
    const len = msg.readUInt16BE(6);
    const payload = msg.slice(8, 8 + len);
    const key = \`\${rinfo.address}:\${rinfo.port}\`;

    switch (cmd) {
      case 0x01: return this._handleHello(key, payload, rinfo);
      case 0x02: return this._handleAuth(key, payload, rinfo);
      case 0x03: return this._handleSimSelect(key, payload, rinfo);
      case 0x04: return this._handleApduCmd(key, payload, rinfo);
      case 0x06: return this._handleKeepalive(key, rinfo);
    }
  }

  _send(rinfo, cmd, payload) {
    const buf = Buffer.alloc(8 + payload.length);
    MAGIC.copy(buf);
    buf.writeUInt16BE(cmd, 4);
    buf.writeUInt16BE(payload.length, 6);
    payload.copy(buf, 8);
    this.socket.send(buf, rinfo.port, rinfo.address);
  }
}`,
    todo: [
      'Снять дамп UDP 56011 при подключении smb_module к реальному SIM Bank',
      'Разреверсить формат payload для каждой команды',
      'Реализовать APDU relay (ISO 7816-4: SELECT, READ_BINARY, etc.)',
      'Пул SIM-карт с ротацией',
      'PCSC reader интеграция (для физических SIM)',
      'RC4 шифрование payload',
      'Web API для управления SIM пулом',
    ],
  };
}

function generateSipServerStub() {
  return {
    component: 'sip_server',
    description: 'SIP сервер уже реализован в goip_sip_server.js. Полный Registrar/B2BUA с Digest Auth, GoIP fingerprinting, 8 методов шифрования.',
    existing_file: 'goip_sip_server.js',
    status: 'IMPLEMENTED AND TESTED',
    features: [
      'SIP Registrar с Digest MD5 Auth',
      'INVITE/BYE/MESSAGE/OPTIONS/REFER handling',
      'GoIP device fingerprinting',
      'X-ACrypt encryption negotiation',
      'HTTP API (status, registrations, calls, SMS)',
      'Multi-account support',
    ],
  };
}

function generateSmppServerStub() {
  return {
    component: 'smpp_server',
    description: 'SMPP сервер/клиент для SMS gateway. Альтернатива SIP MESSAGE.',
    filename: 'goip_smpp_server.js',
    skeleton: `
const net = require('net');

// SMPP PDU commands
const CMDS = {
  BIND_TRANSMITTER: 0x00000002,
  BIND_RECEIVER: 0x00000001,
  BIND_TRANSCEIVER: 0x00000009,
  SUBMIT_SM: 0x00000004,
  DELIVER_SM: 0x00000005,
  ENQUIRE_LINK: 0x00000015,
  UNBIND: 0x00000006,
};

class SmppServer {
  constructor(port = 2775) {
    this.server = net.createServer(socket => this._onConnection(socket));
    this.sessions = new Map();
  }

  start() { this.server.listen(this.port); }

  _onConnection(socket) {
    // Parse SMPP PDUs: [length:4][cmd:4][status:4][seq:4][body:N]
    // Handle BIND, SUBMIT_SM → relay to GoIP as SIP MESSAGE
    // Handle incoming SMS as DELIVER_SM
  }
}`,
    todo: [
      'SMPP 3.4 protocol implementation',
      'Интеграция с goip_sip_server (SMS bridge)',
      'TLV parsing',
      'PDU encoding/decoding',
    ],
  };
}

function generateProvisioningServerStub() {
  return {
    component: 'provisioning_server',
    description: 'HTTP сервер автоконфигурации GoIP. Раздаёт конфиги через getsyscfg/setsyscfg.',
    filename: 'goip_provisioning_server.js',
    skeleton: `
const http = require('http');
const url = require('url');

class ProvisioningServer {
  constructor(port = 8080) {
    this.port = port;
    this.deviceConfigs = new Map(); // serial → config object
  }

  start() {
    http.createServer((req, res) => {
      const u = url.parse(req.url, true);
      // GET /config?sn=SERIAL — возвращает конфиг для устройства
      // POST /config?sn=SERIAL — обновляет конфиг
      // GET /firmware — отдаёт bin для обновления прошивки
    }).listen(this.port);
  }

  generateConfig(serial, template) {
    // На основе .def файлов генерируем конфиг:
    // SIP_REGISTRAR=sip.server.com
    // SIP_CONFIG_MODE=SINGLE_MODE
    // SIP_AUTH_ID=1001
    // ...
  }
}`,
    todo: [
      'Определить формат HTTP autoconfiguration запросов GoIP',
      'Разреверсить /usr/bin/update (firmware update)',
      'Шаблоны конфигов per-device',
      'Массовое управление (fleet)',
    ],
  };
}

function generateStatusApiStub() {
  return {
    component: 'status_api',
    description: 'Единый Status API — агрегирует статус из всех компонентов: SIP, GSM, SIM Bank, Radmin.',
    filename: 'goip_status_api.js',
    skeleton: `
const http = require('http');

class StatusApi {
  constructor(sipServer, smbServer, radminServer) {
    this.sip = sipServer;
    this.smb = smbServer;
    this.radmin = radminServer;
  }

  getFullStatus() {
    return {
      sip: this.sip?.getStatus(),
      simbank: {
        devices: this.smb?.devices.size,
        totalSims: this.smb?.simPool.size,
      },
      radmin: {
        connectedDevices: this.radmin?.devices.size,
      },
      system: {
        uptime: process.uptime(),
        memory: process.memoryUsage(),
      },
    };
  }
}`,
  };
}

function getProtocolDoc(component) {
  switch (component) {
    case 'radmcli_server':
      return generateRadmcliDoc();
    case 'smb_server':
      return generateSmbDoc();
    default:
      return 'See existing documentation in DOC_*.md files';
  }
}

// ═══════════════════════════════════════════════════════════════
// DOCUMENTATION GENERATORS
// ═══════════════════════════════════════════════════════════════

function generateArchitectureDoc() {
  return `# GoIP GST1610 Firmware Architecture

## Обзор
GoIP GST1610 — VoIP GSM шлюз (DBLTek/HYBERTONE).
Прошивка: Linux 2.6.17, ARM, SquashFS root, uClibc 0.9.29.
Версия: GHSFVT-1.1-68-11

## Компоненты

### Демоны (user-space)
| Демон | Описание | IPC |
|-------|----------|-----|
| sipcli | SIP User Agent (oSIP) | Unix /tmp/.mg_cli0, UDP 5060 |
| ata | GSM modem controller | Serial /dev/ttyS0, Unix socket |
| mg | Media Gateway (RTP) | /dev/aci, UDP (RTP) |
| fvdsp | DSP controller | /dev/aci (ioctl) |
| smb_module | SIM Bank client | UDP 56011 |
| radmcli | Remote Admin tunnel | TCP → server |
| smpp_smsc | SMPP SMS gateway | TCP (SMPP) |
| ep | Endpoint manager | Unix sockets |

### Ядерные модули
| Модуль | Описание |
|--------|----------|
| fvaci.ko | DSP/Audio Codec Interface (/dev/aci) |
| fvgpio.ko | GPIO (LED, кнопки, реле) |
| fvnet.ko | Ethernet driver |
| fvspi.ko | SPI bus (flash) |
| fvmem.ko | Shared memory |

### Потоки данных

\`\`\`
GSM Network ←→ [GSM Modem] ←serial→ [ata] ←unix→ [sipcli] ←UDP/SIP→ SIP Server
                                      ↕                        ↕
                                   [gsmdb]              [mg] ←UDP/RTP→ RTP
                                                         ↕
                                                    [fvdsp/fvaci.ko]
                                                    
[SIM Bank Server] ←UDP 56011→ [smb_module] ←serial→ [SIM emulation]

[Radmin Server] ←TCP→ [radmcli] ←→ [httpd @ 127.0.0.1:80]
\`\`\`

## Конфигурация
Система конфигов: \`setsyscfg KEY=VALUE\` / \`getsyscfg KEY\`
Файлы .def определяют типы и допустимые значения.
`;
}

function generateRadmcliDoc() {
  return `# Radmcli Protocol Analysis

## Обзор
radmcli — TCP клиент обратного тоннеля. Подключается к серверу управления, 
создавая каналы для проксирования HTTP и Telnet.

## Запуск
\`\`\`
radmcli -r SERVER:PORT -al 127.0.0.1:HTTP_PORT -ll 127.0.0.1:TELNET_PORT -k KEY -i ID -t 30
\`\`\`

## Параметры
- \`-r\` — Адрес сервера (RADMIN_SERVER:RADMIN_PORT, default port 1920)
- \`-al\` — Локальный HTTP endpoint (127.0.0.1:80)
- \`-ll\` — Локальный Telnet endpoint (127.0.0.1:13000 или :23)
- \`-k\` — Ключ аутентификации (default: "dbl#admin")
- \`-i\` — Device ID (RADMIN_ID из конфига)
- \`-t\` — Keepalive interval (30s)

## Протокол (предположительный)
1. TCP connect → SERVER:PORT
2. Handshake: отправить {device_id, key_hash, capabilities}
3. Сервер: auth_ok / auth_fail
4. Мультиплексирование каналов через framing:
   - Channel 0: Control (auth, keepalive, status)
   - Channel 1: HTTP proxy (forward to 127.0.0.1:80)
   - Channel 2: Telnet proxy (forward to 127.0.0.1:13000)
5. Frame format: [channel:1][flags:1][length:2][data:N]
6. Keepalive: каждые 30s пустой control frame

## Что нужно для сервера
- TCP listener на порту 1920
- Парсер handshake
- Мультиплексор каналов
- HTTP reverse proxy (для веб-доступа к устройству)
- WebSocket→Telnet мост (для CLI доступа)
- Device registry + Web UI
`;
}

function generateSmbDoc() {
  return `# SIM Bank Protocol (smb_module)

## Обзор
smb_module — UDP клиент для подключения к SIM Bank серверу.
Позволяет использовать удалённые SIM-карты вместо локальных.

## Конфигурация (smb.def)
- SMB_SVR — IP SIM Bank сервера
- SMB_ID — ID устройства
- SMB_KEY — Ключ аутентификации
- SMB_RC4_KEY — RC4 ключ шифрования
- RMSIM_ENABLE — Включить Remote SIM
- SMB_NET_TYPE — Тип сети
- SMB_RMSIM — Remote SIM flag

## Протокол
- Транспорт: UDP порт 56011
- Magic: 0x43215678 (4 байта)
- Базовый формат: [magic:4][cmd:2][length:2][payload:N]
- Опциональное RC4 шифрование payload

## Команды (предположительные)
| CMD | Имя | Описание |
|-----|-----|----------|
| 0x01 | HELLO | Handshake: device ID, serial |
| 0x02 | AUTH | Аутентификация по SMB_KEY |
| 0x03 | SIM_SELECT | Выбор SIM слота |
| 0x04 | APDU_CMD | Отправка APDU команды на SIM |
| 0x05 | APDU_RSP | Ответ APDU от SIM |
| 0x06 | KEEPALIVE | Heartbeat |
| 0x07 | STATUS | Статус SIM/устройства |
| 0x08 | RESET | Сброс SIM |

## APDU relay
smb_module релеит ISO 7816-4 APDU между GSM модемом и удалённой SIM-картой:
- SELECT (A0 A4) — выбор файла
- READ_BINARY (A0 B0) — чтение данных
- UPDATE_BINARY (A0 D6) — запись
- GET_RESPONSE (A0 C0) — получить результат
- STATUS (A0 F2) — статус
- RUN_GSM_ALGORITHM (A0 88) — аутентификация в сети
`;
}

function readAllConfigs() {
  const configs = [];
  const defFiles = ['sip.def', 'ata.def', 'common.def', 'smb.def', 'fvdsp.def', 'h323.def', 'smpp.def', 'user.def'];
  for (const f of defFiles) {
    const p = path.join(FW_SYSCFG, f);
    if (fs.existsSync(p)) {
      configs.push(`\n=== ${f} ===\n${fs.readFileSync(p, 'utf-8')}`);
    }
  }
  // syscfg.def (top-level)
  const top = path.join(FW_ETC, 'syscfg.def');
  if (fs.existsSync(top)) configs.push(`\n=== syscfg.def ===\n${fs.readFileSync(top, 'utf-8')}`);
  return configs.join('\n');
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

new AnalysisMcpServer();
