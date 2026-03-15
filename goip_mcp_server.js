#!/usr/bin/env node
/**
 * GoIP MCP Server
 * 
 * Model Context Protocol сервер для управления GoIP GST1610 SIP-шлюзами.
 * Объединяет: SIP Registrar, SMS, звонки, шифрование, анализ протокола.
 * 
 * Транспорт: stdio (JSON-RPC 2.0)
 * Протокол: MCP 2024-11-05
 * 
 * Запуск: node goip_mcp_server.js
 * 
 * Env:
 *   SIP_PORT=5060       — UDP порт SIP
 *   SIP_REALM=goip      — realm для Digest Auth
 *   ACCOUNTS=u1:p1,u2:p2 — начальные аккаунты
 */

'use strict';

const readline = require('readline');
const { GoIPSipServer, SipMessage, SDP, DigestAuth, GoIPFingerprint } = require('./goip_sip_server');
const { XACryptManager, RTPProcessor, GoIPRC4, RC4_EXTRA_SWAPS } = require('./goip_crypto');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

// ═══════════════════════════════════════════════════════════════
// MCP PROTOCOL LAYER
// ═══════════════════════════════════════════════════════════════

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_NAME = 'goip-gateway';
const SERVER_VERSION = '1.0.0';

class McpServer {
  constructor() {
    this.initialized = false;
    this.sipServer = null;
    this.eventLog = [];       // Лог событий (register, invite, message, etc.)
    this.maxEventLog = 500;
    this.smsInbox = [];       // Входящие SMS
    this.callHistory = [];    // История вызовов

    this._setupStdio();
  }

  // ─── stdio transport ───

  _setupStdio() {
    const rl = readline.createInterface({
      input: process.stdin,
      terminal: false,
    });

    let buffer = '';

    rl.on('line', (line) => {
      buffer += line;
      try {
        const msg = JSON.parse(buffer);
        buffer = '';
        this._handleMessage(msg);
      } catch (e) {
        // Может быть multi-line JSON, но MCP обычно single-line
        // Если не парсится — пробуем накопить
        if (buffer.length > 1_000_000) {
          buffer = '';
        }
      }
    });

    rl.on('close', () => {
      this._shutdown();
    });
  }

  _send(msg) {
    const json = JSON.stringify(msg);
    process.stdout.write(json + '\n');
  }

  _sendResult(id, result) {
    this._send({ jsonrpc: '2.0', id, result });
  }

  _sendError(id, code, message, data) {
    this._send({ jsonrpc: '2.0', id, error: { code, message, ...(data ? { data } : {}) } });
  }

  _sendNotification(method, params) {
    this._send({ jsonrpc: '2.0', method, params });
  }

  // ─── Message router ───

  _handleMessage(msg) {
    if (msg.method) {
      switch (msg.method) {
        case 'initialize':
          return this._handleInitialize(msg);
        case 'initialized':
          return this._handleInitialized(msg);
        case 'tools/list':
          return this._handleToolsList(msg);
        case 'tools/call':
          return this._handleToolsCall(msg);
        case 'resources/list':
          return this._handleResourcesList(msg);
        case 'resources/read':
          return this._handleResourcesRead(msg);
        case 'ping':
          return this._sendResult(msg.id, {});
        case 'notifications/cancelled':
          return; // ignore
        default:
          if (msg.id !== undefined) {
            this._sendError(msg.id, -32601, `Method not found: ${msg.method}`);
          }
      }
    }
  }

  // ═══════════════════════════════════════════════════════════
  // LIFECYCLE
  // ═══════════════════════════════════════════════════════════

  _handleInitialize(msg) {
    this._sendResult(msg.id, {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {
        tools: {},
        resources: {},
      },
      serverInfo: {
        name: SERVER_NAME,
        version: SERVER_VERSION,
      },
    });
  }

  _handleInitialized() {
    this.initialized = true;
    this._startSipServer();
    this._log('info', 'MCP server initialized, SIP engine started');
  }

  _shutdown() {
    if (this.sipServer) {
      this.sipServer.socket.close();
    }
    process.exit(0);
  }

  // ═══════════════════════════════════════════════════════════
  // SIP ENGINE
  // ═══════════════════════════════════════════════════════════

  _startSipServer() {
    const config = {
      sipPort: parseInt(process.env.SIP_PORT) || 5060,
      sipHost: process.env.SIP_HOST || '0.0.0.0',
      realm: process.env.SIP_REALM || 'goip-server',
      registerExpiry: 120,
      registrationCheckInterval: 30,
      inviteTimeout: 180,
      requireAuth: true,
      debug: false,
      logSipMessages: false,
    };

    this.sipServer = new GoIPSipServer(config);

    // Аккаунты
    if (process.env.ACCOUNTS) {
      process.env.ACCOUNTS.split(',').forEach(pair => {
        const [u, p] = pair.split(':');
        if (u && p) this.sipServer.addAccount(u.trim(), p.trim());
      });
    } else {
      // Дефолтные
      for (let i = 1; i <= 16; i++) {
        const id = String(1000 + i);
        this.sipServer.addAccount(id, id);
      }
      this.sipServer.addAccount('trunk01', 'trunkpass');
    }

    // Подписки на события
    this.sipServer.on('register', (data) => {
      this._pushEvent('register', data);

      if (data.fingerprint && data.fingerprint.isGoIP) {
        this._pushEvent('goip_detected', {
          username: data.username,
          device: data.fingerprint.deviceType,
          confidence: data.fingerprint.confidence,
          signs: data.fingerprint.signs,
        });
      }
    });

    this.sipServer.on('invite', (data) => {
      this._pushEvent('invite_incoming', {
        callId: data.callId,
        from: data.from,
        to: data.to,
        callerDisplay: data.callerDisplay,
        addr: data.addr,
        port: data.port,
      });

      // Автоответ: ring → ответ через 2с
      data.ring();
      setTimeout(() => data.answer(), 2000);

      this.callHistory.push({
        callId: data.callId,
        direction: 'incoming',
        from: data.from,
        to: data.to,
        callerDisplay: data.callerDisplay || '',
        time: new Date().toISOString(),
        state: 'answered',
      });
    });

    this.sipServer.on('bye', (data) => {
      this._pushEvent('bye', data);
      const hist = this.callHistory.find(c => c.callId === data.callId);
      if (hist) {
        hist.state = 'ended';
        hist.duration = data.duration;
      }
    });

    this.sipServer.on('cancel', (data) => {
      this._pushEvent('cancel', data);
      const hist = this.callHistory.find(c => c.callId === data.callId);
      if (hist) hist.state = 'cancelled';
    });

    this.sipServer.on('message', (data) => {
      this._pushEvent('sms_received', data);
      this.smsInbox.push({
        from: data.from,
        to: data.to,
        body: data.body,
        time: new Date().toISOString(),
        callId: data.callId,
      });
    });

    this.sipServer.on('dtmf', (data) => {
      this._pushEvent('dtmf', data);
    });

    this.sipServer.on('refer', (data) => {
      this._pushEvent('refer', data);
    });

    this.sipServer.on('subscribe', (data) => {
      this._pushEvent('subscribe', data);
    });

    // Запуск
    this.sipServer.start();
    this._log('info', `SIP listening on UDP ${config.sipHost}:${config.sipPort}`);
  }

  _pushEvent(type, data) {
    this.eventLog.push({
      type,
      time: new Date().toISOString(),
      data,
    });
    if (this.eventLog.length > this.maxEventLog) {
      this.eventLog.shift();
    }
  }

  _log(level, text) {
    this._sendNotification('notifications/message', {
      level,
      logger: SERVER_NAME,
      data: text,
    });
  }

  // ═══════════════════════════════════════════════════════════
  // TOOLS
  // ═══════════════════════════════════════════════════════════

  _handleToolsList(msg) {
    this._sendResult(msg.id, { tools: TOOLS_DEFINITIONS });
  }

  _handleToolsCall(msg) {
    const { name, arguments: args } = msg.params;

    try {
      const handler = TOOL_HANDLERS[name];
      if (!handler) {
        this._sendError(msg.id, -32602, `Unknown tool: ${name}`);
        return;
      }

      const result = handler.call(this, args || {});
      this._sendResult(msg.id, {
        content: [{
          type: 'text',
          text: typeof result === 'string' ? result : JSON.stringify(result, null, 2),
        }],
      });
    } catch (err) {
      this._sendResult(msg.id, {
        content: [{ type: 'text', text: `Error: ${err.message}` }],
        isError: true,
      });
    }
  }

  // ═══════════════════════════════════════════════════════════
  // RESOURCES
  // ═══════════════════════════════════════════════════════════

  _handleResourcesList(msg) {
    this._sendResult(msg.id, {
      resources: [
        {
          uri: 'goip://protocol/client-doc',
          name: 'GoIP Client Protocol Documentation',
          description: 'Полная документация клиентского протокола GoIP GST1610',
          mimeType: 'text/markdown',
        },
        {
          uri: 'goip://protocol/sip-examples',
          name: 'GoIP SIP Examples',
          description: 'Примеры SIP-диалогов с GoIP устройствами',
          mimeType: 'text/markdown',
        },
        {
          uri: 'goip://protocol/encryption',
          name: 'GoIP Encryption Reference',
          description: 'Описание 8 проприетарных методов шифрования DBLTek/HYBERTONE',
          mimeType: 'text/markdown',
        },
        {
          uri: 'goip://server/events',
          name: 'GoIP Event Log',
          description: 'Лог событий SIP-сервера (регистрации, вызовы, SMS)',
          mimeType: 'application/json',
        },
      ],
    });
  }

  _handleResourcesRead(msg) {
    const { uri } = msg.params;

    try {
      let content, mimeType;

      switch (uri) {
        case 'goip://protocol/client-doc': {
          const docPath = path.join(__dirname, 'DOC_GOIP_CLIENT_PROTOCOL.md');
          content = fs.existsSync(docPath) ? fs.readFileSync(docPath, 'utf-8') : 'File not found: DOC_GOIP_CLIENT_PROTOCOL.md';
          mimeType = 'text/markdown';
          break;
        }
        case 'goip://protocol/sip-examples': {
          const docPath = path.join(__dirname, 'DOC_GST1610_SIP_EXAMPLES.md');
          content = fs.existsSync(docPath) ? fs.readFileSync(docPath, 'utf-8') : 'File not found: DOC_GST1610_SIP_EXAMPLES.md';
          mimeType = 'text/markdown';
          break;
        }
        case 'goip://protocol/encryption':
          content = this._generateEncryptionDoc();
          mimeType = 'text/markdown';
          break;
        case 'goip://server/events':
          content = JSON.stringify(this.eventLog.slice(-100), null, 2);
          mimeType = 'application/json';
          break;
        default:
          this._sendError(msg.id, -32602, `Unknown resource: ${uri}`);
          return;
      }

      this._sendResult(msg.id, {
        contents: [{
          uri,
          mimeType,
          text: content,
        }],
      });
    } catch (err) {
      this._sendError(msg.id, -32603, err.message);
    }
  }

  _generateEncryptionDoc() {
    return `# GoIP Encryption Reference

## 8 проприетарных методов шифрования DBLTek/HYBERTONE

Все методы применяются к RTP payload (не к заголовку).
Ключ обменивается через SIP-заголовок \`X-ACrypt: <method>:<key>\`.
SDP использует \`RTP/SAVP\` без стандартной строки \`a=crypto:\`.

### 1. RC4 (модифицированный)
Стандартный RC4 KSA + 13 дополнительных swap в S-box:
\`\`\`
Swap-позиции: ${JSON.stringify(RC4_EXTRA_SWAPS)}
\`\`\`

### 2. FAST
Быстрый XOR с генерированным из ключа 256-байтным паттерном (PRNG seed).

### 3. XOR
Простой циклический XOR с ключом.

### 4. VOS (Voice Obfuscation Simple)
Побайтовая перестановка через S-box + XOR с ключом.

### 5. AVS (Advanced Voice Scrambling)
Двухраундовый XOR с rotate left 3.

### 6. N2C
XOR с каскадным carry-переносом.

### 7. ECM (Encrypted Communication Mode)
Трёхраундовый S-box + XOR.

### 8. ET263 (HYBERTONE-specific)
RC4-подобный с 8 дополнительными swap (вместо 13).
Swap-позиции: \`[[0,128],[32,192],[64,224],[96,160],[48,176],[80,208],[112,240],[16,144]]\`

## X-ACrypt заголовок
\`\`\`
INVITE sip:number@host SIP/2.0
X-ACrypt: RC4:a1b2c3d4e5f6
\`\`\`

При получении INVITE с X-ACrypt сервер должен тоже добавить X-ACrypt в 200 OK со своим ключом.
`;
  }
}

// ═══════════════════════════════════════════════════════════════
// TOOLS DEFINITIONS
// ═══════════════════════════════════════════════════════════════

const TOOLS_DEFINITIONS = [
  // ─── Статус и мониторинг ───
  {
    name: 'goip_status',
    description: 'Получить полный статус GoIP SIP-сервера: зарегистрированные устройства, активные вызовы, статистика, конфигурация',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'goip_registrations',
    description: 'Список зарегистрированных GoIP устройств с их адресами, fingerprint\'ами и временем регистрации',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'goip_calls',
    description: 'Список активных вызовов через GoIP (callId, направление, стороны, длительность, состояние)',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },
  {
    name: 'goip_events',
    description: 'Получить лог последних событий SIP-сервера (регистрации, вызовы, SMS, DTMF, REFER и т.д.)',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Макс. количество последних событий (по умолчанию 50)',
        },
        type: {
          type: 'string',
          description: 'Фильтр по типу события: register, invite_incoming, bye, cancel, sms_received, dtmf, refer, goip_detected, subscribe',
        },
      },
    },
  },
  {
    name: 'goip_call_history',
    description: 'История завершённых и активных вызовов (направление, номера, длительность, статус)',
    inputSchema: {
      type: 'object',
      properties: {
        limit: {
          type: 'number',
          description: 'Макс. количество (по умолчанию 100)',
        },
      },
    },
  },

  // ─── Управление аккаунтами ───
  {
    name: 'goip_add_account',
    description: 'Добавить SIP-аккаунт для GoIP устройства (username + password для Digest Auth)',
    inputSchema: {
      type: 'object',
      properties: {
        username: { type: 'string', description: 'SIP username (например, 1001)' },
        password: { type: 'string', description: 'SIP password' },
      },
      required: ['username', 'password'],
    },
  },
  {
    name: 'goip_list_accounts',
    description: 'Список всех настроенных SIP-аккаунтов с информацией о регистрации каждого',
    inputSchema: {
      type: 'object',
      properties: {},
    },
  },

  // ─── Звонки ───
  {
    name: 'goip_make_call',
    description: 'Инициировать исходящий звонок через GoIP (SIP→GSM). Отправляет INVITE на зарегистрированное GoIP устройство для набора указанного номера.',
    inputSchema: {
      type: 'object',
      properties: {
        target_user: {
          type: 'string',
          description: 'SIP username зарегистрированного GoIP устройства (например, 1001)',
        },
        called_number: {
          type: 'string',
          description: 'Номер телефона для набора через GSM (например, +79001234567)',
        },
        caller_display: {
          type: 'string',
          description: 'Отображаемое имя вызывающего (CallerID name)',
        },
        caller_number: {
          type: 'string',
          description: 'Номер вызывающего (CallerID number)',
        },
      },
      required: ['target_user', 'called_number'],
    },
  },
  {
    name: 'goip_hangup',
    description: 'Завершить активный вызов (отправить BYE)',
    inputSchema: {
      type: 'object',
      properties: {
        call_id: { type: 'string', description: 'Call-ID вызова для завершения' },
      },
      required: ['call_id'],
    },
  },

  // ─── SMS ───
  {
    name: 'goip_send_sms',
    description: 'Отправить SMS через GoIP устройство (SIP MESSAGE). GoIP отправит SMS через GSM-модуль.',
    inputSchema: {
      type: 'object',
      properties: {
        target_user: {
          type: 'string',
          description: 'SIP username зарегистрированного GoIP устройства',
        },
        text: {
          type: 'string',
          description: 'Текст SMS-сообщения',
        },
        from_number: {
          type: 'string',
          description: 'Номер отправителя (опционально)',
        },
      },
      required: ['target_user', 'text'],
    },
  },
  {
    name: 'goip_sms_inbox',
    description: 'Показать входящие SMS, полученные от GoIP устройств',
    inputSchema: {
      type: 'object',
      properties: {
        limit: { type: 'number', description: 'Макс. количество (по умолчанию 50)' },
      },
    },
  },

  // ─── Анализ протокола ───
  {
    name: 'goip_parse_sip',
    description: 'Разобрать сырое SIP-сообщение: парсинг заголовков, SDP, определение GoIP fingerprint, X-ACrypt',
    inputSchema: {
      type: 'object',
      properties: {
        raw_message: {
          type: 'string',
          description: 'Сырой текст SIP-сообщения для парсинга',
        },
      },
      required: ['raw_message'],
    },
  },
  {
    name: 'goip_fingerprint',
    description: 'Проанализировать SIP-сообщение на признаки GoIP устройства (User-Agent, SDP, Via branch, X-ACrypt, Content-Length padding)',
    inputSchema: {
      type: 'object',
      properties: {
        raw_message: {
          type: 'string',
          description: 'Сырой текст SIP-сообщения',
        },
      },
      required: ['raw_message'],
    },
  },
  {
    name: 'goip_build_sip',
    description: 'Сгенерировать SIP-сообщение в формате GoIP (с правильными отпечатками: User-Agent dble, SDP DBL Session, o=userX)',
    inputSchema: {
      type: 'object',
      properties: {
        method: {
          type: 'string',
          description: 'SIP метод: REGISTER, INVITE, BYE, MESSAGE, OPTIONS, INFO',
        },
        from_user: { type: 'string', description: 'From username' },
        to_user: { type: 'string', description: 'To username / калледнамбер' },
        server_ip: { type: 'string', description: 'IP SIP-сервера' },
        server_port: { type: 'number', description: 'Порт SIP-сервера (default 5060)' },
        local_ip: { type: 'string', description: 'Локальный IP GoIP' },
        body: { type: 'string', description: 'Тело сообщения (текст SMS для MESSAGE)' },
        include_sdp: { type: 'boolean', description: 'Добавить GoIP-стиль SDP (для INVITE)' },
      },
      required: ['method', 'from_user', 'server_ip'],
    },
  },

  // ─── Шифрование ───
  {
    name: 'goip_encrypt',
    description: 'Зашифровать данные одним из 8 проприетарных методов GoIP (RC4, FAST, XOR, VOS, AVS, N2C, ECM, ET263)',
    inputSchema: {
      type: 'object',
      properties: {
        method: {
          type: 'string',
          description: 'Метод: RC4, FAST, XOR, VOS, AVS, N2C, ECM, ET263',
          enum: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
        },
        key: { type: 'string', description: 'Ключ шифрования' },
        data_hex: { type: 'string', description: 'Данные в hex для шифрования' },
      },
      required: ['method', 'key', 'data_hex'],
    },
  },
  {
    name: 'goip_decrypt',
    description: 'Расшифровать данные одним из 8 проприетарных методов GoIP (тот же вызов — шифрование симметричное)',
    inputSchema: {
      type: 'object',
      properties: {
        method: {
          type: 'string',
          description: 'Метод: RC4, FAST, XOR, VOS, AVS, N2C, ECM, ET263',
          enum: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
        },
        key: { type: 'string', description: 'Ключ шифрования' },
        data_hex: { type: 'string', description: 'Зашифрованные данные в hex' },
      },
      required: ['method', 'key', 'data_hex'],
    },
  },
  {
    name: 'goip_parse_xacrypt',
    description: 'Разобрать значение заголовка X-ACrypt (метод + ключ) и создать шифратор',
    inputSchema: {
      type: 'object',
      properties: {
        header_value: { type: 'string', description: 'Значение X-ACrypt заголовка, например "RC4:a1b2c3d4"' },
      },
      required: ['header_value'],
    },
  },
  {
    name: 'goip_generate_key',
    description: 'Сгенерировать cryptographically-secure ключ для X-ACrypt шифрования',
    inputSchema: {
      type: 'object',
      properties: {
        method: {
          type: 'string',
          description: 'Метод шифрования (для формирования X-ACrypt заголовка)',
          enum: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
        },
        length: { type: 'number', description: 'Длина ключа в байтах (по умолчанию 16)' },
      },
      required: ['method'],
    },
  },

  // ─── RTP ───
  {
    name: 'goip_parse_rtp',
    description: 'Разобрать RTP-пакет: версия, PT, sequence, timestamp, SSRC, payload. Определить DTMF (RFC 2833) если PT=101.',
    inputSchema: {
      type: 'object',
      properties: {
        packet_hex: { type: 'string', description: 'RTP пакет в hex' },
      },
      required: ['packet_hex'],
    },
  },
  {
    name: 'goip_decrypt_rtp',
    description: 'Расшифровать RTP payload (только payload, не заголовок) используя указанный метод GoIP шифрования',
    inputSchema: {
      type: 'object',
      properties: {
        packet_hex: { type: 'string', description: 'Полный RTP пакет в hex' },
        method: {
          type: 'string',
          description: 'Метод шифрования',
          enum: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
        },
        key: { type: 'string', description: 'Ключ' },
      },
      required: ['packet_hex', 'method', 'key'],
    },
  },

  // ─── Reference ───
  {
    name: 'goip_protocol_info',
    description: 'Справочная информация о протоколе GoIP: режимы работы, тайминги, fingerprint-признаки, CLI параметры sipcli, системные процессы',
    inputSchema: {
      type: 'object',
      properties: {
        topic: {
          type: 'string',
          description: 'Раздел: modes, timers, fingerprints, cli_params, processes, encryption, sip_flow, sdp, dtmf, nat',
        },
      },
      required: ['topic'],
    },
  },
];

// ═══════════════════════════════════════════════════════════════
// TOOL HANDLERS
// ═══════════════════════════════════════════════════════════════

const TOOL_HANDLERS = {
  // ─── Статус ───

  goip_status(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    return this.sipServer.getStatus();
  },

  goip_registrations(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    return this.sipServer.getStatus().registeredAccounts;
  },

  goip_calls(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    return this.sipServer.getStatus().activeCalls;
  },

  goip_events(args) {
    const limit = args.limit || 50;
    let events = this.eventLog;
    if (args.type) {
      events = events.filter(e => e.type === args.type);
    }
    return events.slice(-limit);
  },

  goip_call_history(args) {
    const limit = args.limit || 100;
    return this.callHistory.slice(-limit);
  },

  // ─── Аккаунты ───

  goip_add_account(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    this.sipServer.addAccount(args.username, args.password);
    return { ok: true, username: args.username, message: `Account ${args.username} added` };
  },

  goip_list_accounts(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    const list = [];
    for (const [username, account] of this.sipServer.accounts) {
      list.push({
        username,
        registered: account.registrations.length > 0,
        registrations: account.registrations.map(r => ({
          addr: r.addr,
          port: r.port,
          expires: r.expires,
          age: Math.floor((Date.now() - r.registeredAt) / 1000),
        })),
        hasFingerprint: !!account.fingerprint,
        fingerprint: account.fingerprint,
      });
    }
    return list;
  },

  // ─── Звонки ───

  goip_make_call(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    const callId = this.sipServer.sendInvite(
      args.target_user,
      args.called_number,
      args.caller_display || '',
      args.caller_number || ''
    );
    if (callId) {
      this.callHistory.push({
        callId,
        direction: 'outgoing',
        from: args.caller_number || 'server',
        to: args.called_number,
        targetGoip: args.target_user,
        time: new Date().toISOString(),
        state: 'calling',
      });
      return { ok: true, callId, message: `INVITE sent to ${args.target_user} for ${args.called_number}` };
    }
    return { ok: false, error: `${args.target_user} not registered` };
  },

  goip_hangup(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    this.sipServer.sendBye(args.call_id);
    const hist = this.callHistory.find(c => c.callId === args.call_id);
    if (hist) hist.state = 'ended_by_server';
    return { ok: true, message: `BYE sent for ${args.call_id}` };
  },

  // ─── SMS ───

  goip_send_sms(args) {
    if (!this.sipServer) return { error: 'SIP server not started' };
    const sent = this.sipServer.sendMessage(args.target_user, args.text, args.from_number || '');
    return sent
      ? { ok: true, message: `SMS sent via ${args.target_user}: "${args.text.substring(0, 50)}..."` }
      : { ok: false, error: `${args.target_user} not registered` };
  },

  goip_sms_inbox(args) {
    const limit = args.limit || 50;
    return this.smsInbox.slice(-limit);
  },

  // ─── Анализ SIP ───

  goip_parse_sip(args) {
    const msg = SipMessage.parse(Buffer.from(args.raw_message));
    if (!msg) return { error: 'Failed to parse SIP message' };

    const result = {
      type: msg.isRequest ? 'request' : 'response',
      method: msg.method || undefined,
      statusCode: msg.statusCode || undefined,
      reasonPhrase: msg.reasonPhrase || undefined,
      requestUri: msg.requestUri || undefined,
      callId: msg.callId,
      cseq: msg.cseq,
      from: msg.from,
      to: msg.to,
      contact: msg.contact,
      via: msg.via,
      userAgent: msg.userAgent,
      contentType: msg.contentType,
      contentLength: msg.contentLength,
      expires: msg.expires,
      xACrypt: msg.xACrypt,
      maxForwards: msg.maxForwards,
    };

    // SDP
    if (msg.body && msg.contentType === 'application/sdp') {
      const sdp = SDP.parse(msg.body);
      result.sdp = {
        origin: sdp.origin,
        sessionName: sdp.sessionName,
        connection: sdp.connection,
        media: sdp.media.map(m => ({
          type: m.type,
          port: m.port,
          protocol: m.protocol,
          payloads: m.payloads,
          direction: m.direction,
          attributes: m.attributes,
        })),
        goipSigns: sdp.isGoIP(),
      };
    }

    // Fingerprint
    const fp = GoIPFingerprint.analyze(msg);
    result.fingerprint = fp;

    return result;
  },

  goip_fingerprint(args) {
    const msg = SipMessage.parse(Buffer.from(args.raw_message));
    if (!msg) return { error: 'Failed to parse SIP message' };

    const fp = GoIPFingerprint.analyze(msg);
    let sdpSigns = [];
    if (msg.body && msg.contentType === 'application/sdp') {
      sdpSigns = SDP.parse(msg.body).isGoIP();
    }

    return {
      isGoIP: fp.isGoIP,
      confidence: fp.confidence,
      vendor: fp.vendor,
      deviceType: fp.deviceType,
      signs: fp.signs,
      sdpSigns,
      userAgent: msg.userAgent,
      xACrypt: msg.xACrypt,
      details: {
        viaAnalysis: msg.via.length > 0 ? {
          branch: msg.via[0].branch,
          matchesOsipPattern: /^z9hG4bK\d{6,10}$/.test(msg.via[0].branch || ''),
        } : null,
      },
    };
  },

  goip_build_sip(args) {
    const method = (args.method || 'REGISTER').toUpperCase();
    const serverIp = args.server_ip;
    const serverPort = args.server_port || 5060;
    const localIp = args.local_ip || '192.168.1.100';
    const fromUser = args.from_user;
    const toUser = args.to_user || args.from_user;
    const branch = `z9hG4bK${Math.floor(Math.random() * 999999999)}`;
    const tag = crypto.randomBytes(6).toString('hex');
    const callId = `${Date.now()}@${localIp}`;

    const lines = [
      `${method} sip:${toUser}@${serverIp}:${serverPort} SIP/2.0`,
      `Via: SIP/2.0/UDP ${localIp}:5060;rport;branch=${branch}`,
      `From: <sip:${fromUser}@${serverIp}>;tag=${tag}`,
      `To: <sip:${toUser}@${serverIp}>`,
      `Call-ID: ${callId}`,
      `CSeq: 1 ${method}`,
      `Contact: <sip:${fromUser}@${localIp}:5060>`,
      `Max-Forwards: 70`,
      `User-Agent: dble`,
    ];

    if (method === 'REGISTER') {
      lines.push(`Expires: 120`);
    }

    if (method === 'MESSAGE' && args.body) {
      lines.push(`Content-Type: text/plain`);
      lines.push(`Content-Length: ${args.body.length}`);
      lines.push('');
      lines.push(args.body);
    } else if (method === 'INVITE' && args.include_sdp !== false) {
      const sdp = [
        'v=0',
        `o=userX 20000001 20000001 IN IP4 ${localIp}`,
        's=DBL Session',
        `c=IN IP4 ${localIp}`,
        't=0 0',
        'm=audio 21000 RTP/AVP 8 0 101',
        'a=rtpmap:8 PCMA/8000',
        'a=rtpmap:0 PCMU/8000',
        'a=rtpmap:101 telephone-event/8000',
        'a=fmtp:101 0-15',
        'a=ptime:20',
        'a=sendrecv',
        '',
      ].join('\r\n');
      lines.push(`Content-Type: application/sdp`);
      lines.push(`Content-Length: ${sdp.length}`);
      lines.push('');
      lines.push(sdp);
    } else {
      lines.push(`Content-Length:     0`);
      lines.push('');
      lines.push('');
    }

    return lines.join('\r\n');
  },

  // ─── Шифрование ───

  goip_encrypt(args) {
    const cipher = XACryptManager.createCipher(args.method, args.key);
    if (!cipher) return { error: `Unknown method: ${args.method}` };
    const data = Buffer.from(args.data_hex, 'hex');
    const encrypted = cipher.process(data);
    return {
      method: args.method,
      key: args.key,
      input_hex: args.data_hex,
      output_hex: encrypted.toString('hex'),
      xACryptHeader: XACryptManager.create(args.method, args.key),
    };
  },

  goip_decrypt(args) {
    // Симметричные шифры — то же самое что encrypt
    return TOOL_HANDLERS.goip_encrypt.call(this, args);
  },

  goip_parse_xacrypt(args) {
    const parsed = XACryptManager.parse(args.header_value);
    if (!parsed) return { error: 'Failed to parse X-ACrypt header' };
    return {
      method: parsed.method,
      key: parsed.key,
      supportedMethods: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'],
      isSupported: ['RC4', 'FAST', 'XOR', 'VOS', 'AVS', 'N2C', 'ECM', 'ET263'].includes(parsed.method),
    };
  },

  goip_generate_key(args) {
    const length = args.length || 16;
    const key = XACryptManager.generateKey(length);
    return {
      method: args.method,
      key,
      xACryptHeader: XACryptManager.create(args.method, key),
      keyLengthBytes: length,
    };
  },

  // ─── RTP ───

  goip_parse_rtp(args) {
    const buf = Buffer.from(args.packet_hex, 'hex');
    const parsed = RTPProcessor.parse(buf);
    if (!parsed) return { error: 'Failed to parse RTP packet' };

    const result = {
      version: parsed.version,
      padding: parsed.padding,
      extension: parsed.extension,
      csrcCount: parsed.csrcCount,
      marker: parsed.marker,
      payloadType: parsed.payloadType,
      sequenceNumber: parsed.sequenceNumber,
      timestamp: parsed.timestamp,
      ssrc: `0x${parsed.ssrc.toString(16)}`,
      headerLength: parsed.headerLength,
      payloadLength: parsed.payload.length,
      payloadHex: parsed.payload.toString('hex').substring(0, 200),
    };

    if (RTPProcessor.isDTMFEvent(parsed.payloadType)) {
      const dtmf = RTPProcessor.parseDTMFEvent(parsed.payload);
      if (dtmf) result.dtmf = dtmf;
    }

    return result;
  },

  goip_decrypt_rtp(args) {
    const buf = Buffer.from(args.packet_hex, 'hex');
    const cipher = XACryptManager.createCipher(args.method, args.key);
    if (!cipher) return { error: `Unknown method: ${args.method}` };

    const decrypted = RTPProcessor.decryptPayload(buf, cipher);
    const parsed = RTPProcessor.parse(decrypted);

    return {
      method: args.method,
      original_hex: args.packet_hex.substring(0, 100) + '...',
      decrypted_hex: decrypted.toString('hex').substring(0, 200) + '...',
      decryptedPayloadHex: parsed ? parsed.payload.toString('hex').substring(0, 200) : null,
      payloadType: parsed ? parsed.payloadType : null,
    };
  },

  // ─── Reference ───

  goip_protocol_info(args) {
    const topic = (args.topic || '').toLowerCase();
    return PROTOCOL_REFERENCE[topic] || {
      error: `Unknown topic: ${topic}`,
      available: Object.keys(PROTOCOL_REFERENCE),
    };
  },
};

// ═══════════════════════════════════════════════════════════════
// PROTOCOL REFERENCE DATA
// ═══════════════════════════════════════════════════════════════

const PROTOCOL_REFERENCE = {
  modes: {
    title: 'Режимы работы GoIP',
    modes: {
      SINGLE_MODE: {
        description: 'Один аккаунт для всех каналов. Все каналы регистрируются с одним SIP ID.',
        params: 'SIP_REGISTRAR, SIP_PROXY, SIP_AUTH_ID, SIP_AUTH_PASSWD, SIP_PHONE_NUMBER',
        aliases: 'SIP_PROXY → SIP_CONTACT8_PROXY, SIP_AUTH_ID → SIP_CONTACT8_AUTHID, etc.',
      },
      LINE_MODE: {
        description: 'Per-channel аккаунты (до 4 sub-accounts на канал для разных маршрутов).',
        params: 'SIP_CONTACT[1-4]_PROXY, SIP_CONTACT[1-4]_AUTHID, SIP_CONTACT[1-4]_PASSWD',
      },
      TRUNK_GW_MODE: {
        description: 'Прямой trunk. До 3 gateways. Регистрация опциональна.',
        params: 'SIP_TRUNK_GW[1-3], SIP_TRUNK_AUTH_ID, SIP_TRUNK_AUTH_PASSWD',
        note: 'Если SIP_TRUNK_REGISTER=1 — регистрация, иначе direct IP.',
      },
      GROUP_MODE: {
        description: 'Каналы объединены в группы, per-group регистрация.',
        params: 'Группы определяются в конфигурации устройства.',
      },
    },
  },

  timers: {
    title: 'Таймеры GoIP',
    timers: {
      REGISTRATION_PERIOD: { default: '120s', param: 'SIP_REGIST_PERIOD', description: 'Интервал REGISTER re-registration' },
      KEEPALIVE_INTERVAL: { default: '30s', param: 'SIP_KPALIVE_PERIOD', description: 'Интервал OPTIONS keepalive' },
      UNANSWER_TIMEOUT: { default: '180s', param: 'SIP_UNANSWER_EXP', description: 'Таймаут ответа на INVITE' },
      SESSION_TIMER: { default: '1800s', param: 'SIP_SESSION_EXP', description: 'Session timer (re-INVITE)' },
      T1: { default: '500ms', description: 'SIP retransmission T1' },
      DNS_SRV_TTL: { default: '3600s', description: 'Кэш DNS SRV записей' },
    },
  },

  fingerprints: {
    title: 'Признаки GoIP устройства',
    signs: [
      { sign: 'User-Agent: dble', confidence: 40, vendor: 'DBLTek' },
      { sign: 'User-Agent: HYBERTONE', confidence: 40, vendor: 'HYBERTONE' },
      { sign: 'User-Agent: pak', confidence: 30, vendor: 'DBLTek-PAK' },
      { sign: 'SDP s=DBL Session', confidence: 15, what: 'Session name' },
      { sign: 'SDP o=userX 20000001', confidence: 15, what: 'Origin' },
      { sign: 'Via branch z9hG4bK + digits', confidence: 10, what: 'oSIP uint32' },
      { sign: 'Content-Length:     0 (5 spaces)', confidence: 10, what: 'Padding' },
      { sign: 'X-ACrypt header', confidence: 30, what: 'Proprietary encryption' },
      { sign: '480 Remote Busy', confidence: 20, what: 'Non-standard reason phrase' },
    ],
  },

  cli_params: {
    title: 'Параметры sipcli',
    binary: '/usr/bin/sipcli (658,064 bytes, ARM OABI, uClibc)',
    key_params: [
      '-g mode (0=SINGLE, 1=LINE, 2=TRUNK_GW, 3=GROUP)',
      '-o addr — прокси-сервер',
      '-p port — порт SIP',
      '-u authid — SIP Auth ID',
      '-a passwd — SIP пароль',
      '-e phone_number — номер телефона',
      '-r registrar — SIP registrar',
      '-R regist_period — период регистрации',
      '-K kpalive_period — период keepalive',
      '-k kpalive_mode — режим keepalive (0=off, 1=OPTIONS, 2=REGISTER)',
      '-E encryption — шифрование (0=off, 1=RC4, 2=FAST, etc.)',
      '-y key — ключ шифрования',
      '-z nat_mode — NAT (0=off, 1=STUN, 2=rport)',
      '-Z stun_server — STUN сервер',
      '-I dtmf_mode — DTMF (0=RFC2833, 1=SIP INFO, 2=INBAND)',
      '-f codec — кодек (0=PCMU, 1=GSM, 2=PCMA, 3=G729, 4=G723)',
      '-D qos_tos — QoS TOS byte',
      '-J session_exp — session timer',
    ],
  },

  processes: {
    title: 'Системные процессы GoIP',
    processes: {
      sipcli: 'SIP User Agent (порт 5060, Unix: /tmp/.mg_cli0)',
      mg: 'Media Gateway (управление каналами, RTP)',
      fvdsp: 'DSP/RTP обработчик (7 потоков, /dev/aci, модуль fvaci.ko)',
      smb_module: 'SIM Bank клиент (UDP 56011, magic 0x43215678)',
      ioctl_tool: 'GPIO управление (REG, STA LED)',
    },
  },

  encryption: {
    title: '8 методов шифрования GoIP',
    methods: [
      { id: 1, name: 'RC4', description: 'Модифицированный RC4 с 13 дополнительными S-box swap' },
      { id: 2, name: 'FAST', description: 'Быстрый XOR с PRNG-генерированным 256-байтным паттерном' },
      { id: 3, name: 'XOR', description: 'Простой циклический XOR с ключом' },
      { id: 4, name: 'VOS', description: 'Voice Obfuscation Simple — S-box перестановка + XOR' },
      { id: 5, name: 'AVS', description: 'Advanced Voice Scrambling — двухраундовый XOR + ROL3' },
      { id: 6, name: 'N2C', description: 'XOR с каскадным carry' },
      { id: 7, name: 'ECM', description: 'Encrypted Communication — трёхраундовый S-box + XOR' },
      { id: 8, name: 'ET263', description: 'HYBERTONE-specific — RC4-like с 8 swap (не 13)' },
    ],
    header: 'X-ACrypt: <method>:<key>',
    sdp: 'RTP/SAVP (без a=crypto: строки)',
    rc4_extra_swaps: RC4_EXTRA_SWAPS,
  },

  sip_flow: {
    title: 'Типичные SIP-потоки GoIP',
    registration: [
      'GoIP → REGISTER',
      '   ← 401 Unauthorized (challenge)',
      'GoIP → REGISTER + Authorization',
      '   ← 200 OK',
      '(повтор каждые SIP_REGIST_PERIOD сек)',
    ],
    outgoing_call: [
      'GoIP → INVITE + SDP (GSM поступил звонок)',
      '   ← 100 Trying',
      '   ← 180 Ringing',
      '   ← 200 OK + SDP',
      'GoIP → ACK',
      '... RTP ...',
      'GoIP → BYE или ← BYE',
      '   ← 200 OK / → 200 OK',
    ],
    incoming_call: [
      '   → INVITE + SDP (хотим звонок через GSM)',
      'GoIP ← 100 Trying',
      'GoIP ← 180 Ringing (набирает GSM)',
      'GoIP ← 200 OK + SDP (ответили)',
      '   → ACK',
      '... RTP ...',
      '   → BYE или GoIP → BYE',
    ],
    sms_out: [
      '   → MESSAGE sip:user@goip (text/plain body)',
      'GoIP ← 200 OK',
      '(GoIP отправляет SMS через GSM)',
    ],
    sms_in: [
      'GoIP → MESSAGE (получена SMS из GSM)',
      '   ← 200 OK',
    ],
  },

  sdp: {
    title: 'SDP GoIP',
    template: [
      'v=0',
      'o=userX 20000001 20000001 IN IP4 <goip_ip>',
      's=DBL Session',
      'c=IN IP4 <goip_ip>',
      't=0 0',
      'm=audio <rtp_port> RTP/AVP 8 0 4 18 101',
      'a=rtpmap:8 PCMA/8000',
      'a=rtpmap:0 PCMU/8000',
      'a=rtpmap:4 G723/8000',
      'a=rtpmap:18 G729/8000',
      'a=rtpmap:101 telephone-event/8000',
      'a=fmtp:101 0-15',
      'a=ptime:20',
      'a=sendrecv',
    ],
    codecs: [
      { pt: 0, name: 'PCMU', rate: 8000, description: 'G.711 μ-law' },
      { pt: 4, name: 'G723', rate: 8000, description: 'G.723.1' },
      { pt: 8, name: 'PCMA', rate: 8000, description: 'G.711 A-law' },
      { pt: 18, name: 'G729', rate: 8000, description: 'G.729a' },
      { pt: 101, name: 'telephone-event', rate: 8000, description: 'RFC 2833 DTMF' },
    ],
    fingerprints: ['o=userX', 'sessionId=20000001', 's=DBL Session'],
  },

  dtmf: {
    title: 'Режимы DTMF GoIP',
    modes: {
      RFC2833: {
        id: 0,
        description: 'DTMF в RTP потоке (PT=101, telephone-event)',
        sdp: 'a=rtpmap:101 telephone-event/8000',
      },
      SIP_INFO: {
        id: 1,
        description: 'DTMF через SIP INFO',
        contentType: 'application/dtmf-relay',
        body: 'Signal=X\r\nDuration=160',
      },
      INBAND: {
        id: 2,
        description: 'DTMF внутри аудио потока (тональные сигналы)',
      },
    },
  },

  nat: {
    title: 'NAT traversal GoIP',
    modes: {
      OFF: { id: 0, description: 'Без NAT — прямой IP' },
      STUN: { id: 1, description: 'STUN клиент для определения внешнего IP', param: 'SIP_STUN_SERVER' },
      RPORT: { id: 2, description: 'Via: rport — сервер заполняет rport= и received=' },
    },
    note: 'GoIP всегда отправляет rport в Via. Сервер должен заполнить rport=<real_port> и received=<real_ip>.',
  },
};

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

const server = new McpServer();
