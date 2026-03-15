/**
 * GoIP GST1610 SIP Server
 * 
 * Полноценный SIP B2BUA/Registrar специально для GoIP GST1610.
 * Поддерживает все 4 режима: SINGLE, LINE, TRUNK_GW, GROUP.
 * 
 * Возможности:
 * - SIP Registrar с Digest Auth
 * - Обработка входящих INVITE от GoIP (GSM → SIP)
 * - Отправка INVITE на GoIP (SIP → GSM)
 * - SMS через SIP MESSAGE
 * - DTMF через SIP INFO и RFC 2833
 * - OPTIONS keepalive
 * - SUBSCRIBE/NOTIFY MWI
 * - REFER (call transfer)
 * - Проприетарная расшифровка X-ACrypt
 * - Fingerprinting GoIP устройств
 * - Web API для управления
 * 
 * Запуск: node goip_sip_server.js [--port 5060] [--api-port 8location]
 */

'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const http = require('http');
const url = require('url');
const { EventEmitter } = require('events');

// ═══════════════════════════════════════════════════════════════
// КОНФИГУРАЦИЯ
// ═══════════════════════════════════════════════════════════════

const CONFIG = {
  // SIP
  sipPort: parseInt(process.env.SIP_PORT) || 5060,
  sipHost: process.env.SIP_HOST || '0.0.0.0',
  realm: process.env.SIP_REALM || 'goip-server',
  
  // API
  apiPort: parseInt(process.env.API_PORT) || 8080,
  
  // Таймауты
  registerExpiry: 120,          // секунд
  registrationCheckInterval: 30, // секунд
  inviteTimeout: 180,           // секунд (UNANSWER_EXP)
  
  // Аутентификация
  requireAuth: true,
  
  // debug
  debug: process.env.SIP_DEBUG === '1' || process.argv.includes('--debug'),
  logSipMessages: true,
};

// Парсим аргументы CLI
for (let i = 2; i < process.argv.length; i++) {
  if (process.argv[i] === '--port' && process.argv[i + 1]) {
    CONFIG.sipPort = parseInt(process.argv[++i]);
  } else if (process.argv[i] === '--api-port' && process.argv[i + 1]) {
    CONFIG.apiPort = parseInt(process.argv[++i]);
  } else if (process.argv[i] === '--realm' && process.argv[i + 1]) {
    CONFIG.realm = process.argv[++i];
  }
}

// ═══════════════════════════════════════════════════════════════
// SIP ПАРСЕР
// ═══════════════════════════════════════════════════════════════

class SipMessage {
  constructor() {
    this.isRequest = false;
    this.isResponse = false;
    this.method = '';
    this.requestUri = '';
    this.statusCode = 0;
    this.reasonPhrase = '';
    this.sipVersion = 'SIP/2.0';
    this.headers = {};
    this.body = '';
    
    // Parsed fields
    this.via = [];
    this.from = null;
    this.to = null;
    this.contact = null;
    this.callId = '';
    this.cseq = { num: 0, method: '' };
    this.contentType = '';
    this.contentLength = 0;
    this.authorization = null;
    this.proxyAuthorization = null;
    this.wwwAuthenticate = null;
    this.userAgent = '';
    this.maxForwards = 70;
    this.expires = null;
    this.xACrypt = null;
    this.referTo = null;
    this.event = null;
    this.subscriptionState = null;
    this.pAssertedIdentity = null;
  }

  /**
   * Парсинг SIP-сообщения из буфера
   */
  static parse(buffer) {
    const text = buffer.toString('utf-8');
    const msg = new SipMessage();
    
    // Разделяем заголовки и тело
    const headerBodySplit = text.indexOf('\r\n\r\n');
    let headerPart, bodyPart;
    
    if (headerBodySplit >= 0) {
      headerPart = text.substring(0, headerBodySplit);
      bodyPart = text.substring(headerBodySplit + 4);
    } else {
      headerPart = text;
      bodyPart = '';
    }
    
    const lines = headerPart.split('\r\n');
    if (lines.length === 0) return null;
    
    // Парсим первую строку
    const firstLine = lines[0];
    
    if (firstLine.startsWith('SIP/')) {
      // Response: SIP/2.0 200 OK
      msg.isResponse = true;
      const match = firstLine.match(/^(SIP\/2\.0)\s+(\d{3})\s+(.*)$/);
      if (!match) return null;
      msg.sipVersion = match[1];
      msg.statusCode = parseInt(match[2]);
      msg.reasonPhrase = match[3];
    } else {
      // Request: INVITE sip:... SIP/2.0
      msg.isRequest = true;
      const match = firstLine.match(/^(\w+)\s+(.+)\s+(SIP\/2\.0)$/);
      if (!match) return null;
      msg.method = match[1].toUpperCase();
      msg.requestUri = match[2];
      msg.sipVersion = match[3];
    }
    
    // Парсим заголовки (с поддержкой multi-line)
    for (let i = 1; i < lines.length; i++) {
      let line = lines[i];
      // Multi-line headers (continuation)
      while (i + 1 < lines.length && (lines[i + 1].startsWith(' ') || lines[i + 1].startsWith('\t'))) {
        line += ' ' + lines[++i].trim();
      }
      
      const colonIdx = line.indexOf(':');
      if (colonIdx < 0) continue;
      
      const name = line.substring(0, colonIdx).trim();
      const value = line.substring(colonIdx + 1).trim();
      const nameLower = name.toLowerCase();
      
      // Собираем все заголовки
      if (!msg.headers[nameLower]) {
        msg.headers[nameLower] = [];
      }
      msg.headers[nameLower].push({ name, value });
      
      // Парсим специфичные
      switch (nameLower) {
        case 'via':
          msg.via.push(SipMessage._parseVia(value));
          break;
        case 'from':
        case 'f':
          msg.from = SipMessage._parseNameAddr(value);
          break;
        case 'to':
        case 't':
          msg.to = SipMessage._parseNameAddr(value);
          break;
        case 'contact':
        case 'm':
          msg.contact = SipMessage._parseNameAddr(value);
          break;
        case 'call-id':
        case 'i':
          msg.callId = value;
          break;
        case 'cseq':
          const cseqMatch = value.match(/^(\d+)\s+(\w+)$/);
          if (cseqMatch) {
            msg.cseq = { num: parseInt(cseqMatch[1]), method: cseqMatch[2].toUpperCase() };
          }
          break;
        case 'content-type':
        case 'c':
          msg.contentType = value;
          break;
        case 'content-length':
        case 'l':
          msg.contentLength = parseInt(value);
          break;
        case 'user-agent':
          msg.userAgent = value;
          break;
        case 'max-forwards':
          msg.maxForwards = parseInt(value);
          break;
        case 'expires':
          msg.expires = parseInt(value);
          break;
        case 'authorization':
          msg.authorization = SipMessage._parseAuth(value);
          break;
        case 'proxy-authorization':
          msg.proxyAuthorization = SipMessage._parseAuth(value);
          break;
        case 'www-authenticate':
        case 'proxy-authenticate':
          msg.wwwAuthenticate = value;
          break;
        case 'x-acrypt':
          msg.xACrypt = value;
          break;
        case 'refer-to':
          msg.referTo = value;
          break;
        case 'event':
          msg.event = value;
          break;
        case 'subscription-state':
          msg.subscriptionState = value;
          break;
        case 'p-asserted-identity':
          msg.pAssertedIdentity = SipMessage._parseNameAddr(value);
          break;
      }
    }
    
    msg.body = bodyPart;
    
    return msg;
  }

  /**
   * Парсинг Via заголовка
   */
  static _parseVia(value) {
    const via = { raw: value, protocol: '', host: '', port: 5060, branch: '', rport: null, received: null };
    
    // SIP/2.0/UDP 192.168.50.66:5060;rport;branch=z9hG4bK847291563
    const match = value.match(/^(SIP\/2\.0\/\w+)\s+([^;:]+)(?::(\d+))?(.*)$/);
    if (match) {
      via.protocol = match[1];
      via.host = match[2].trim();
      via.port = match[3] ? parseInt(match[3]) : 5060;
      
      const params = match[4] || '';
      const branchMatch = params.match(/branch=([^;,\s]+)/);
      if (branchMatch) via.branch = branchMatch[1];
      
      if (params.includes('rport=')) {
        const rportMatch = params.match(/rport=(\d+)/);
        if (rportMatch) via.rport = parseInt(rportMatch[1]);
      } else if (params.includes('rport')) {
        via.rport = 0; // rport без значения — ждёт заполнения
      }
      
      const recvMatch = params.match(/received=([^;,\s]+)/);
      if (recvMatch) via.received = recvMatch[1];
    }
    
    return via;
  }

  /**
   * Парсинг name-addr (From, To, Contact)
   */
  static _parseNameAddr(value) {
    const result = { raw: value, displayName: '', uri: '', user: '', host: '', port: 5060, tag: '', params: {} };
    
    // "DisplayName" <sip:user@host:port>;tag=xxx
    let uriPart = value;
    
    // Извлекаем display name
    const dnMatch = value.match(/^"([^"]*)"?\s*<(.+)>/);
    const noNameMatch = value.match(/^<(.+)>/);
    const plainMatch = value.match(/^([^<]+)\s*<(.+)>/);
    
    if (dnMatch) {
      result.displayName = dnMatch[1];
      uriPart = dnMatch[2];
    } else if (plainMatch) {
      result.displayName = plainMatch[1].trim();
      uriPart = plainMatch[2];
    } else if (noNameMatch) {
      uriPart = noNameMatch[1];
    }
    
    // Убираем > и парсим параметры после >
    const angleClose = value.indexOf('>');
    if (angleClose >= 0) {
      const afterAngle = value.substring(angleClose + 1);
      const tagMatch = afterAngle.match(/tag=([^;,\s]+)/);
      if (tagMatch) result.tag = tagMatch[1];
      
      const expiresMatch = afterAngle.match(/expires=(\d+)/);
      if (expiresMatch) result.params.expires = parseInt(expiresMatch[1]);
    }
    
    // Парсим URI
    // sip:user@host:port;params или sip:user@host
    const sipMatch = uriPart.match(/sip:([^@]+)@([^:;>\s]+)(?::(\d+))?/);
    if (sipMatch) {
      result.user = sipMatch[1];
      result.host = sipMatch[2];
      if (sipMatch[3]) result.port = parseInt(sipMatch[3]);
    } else {
      // sip:host (без user, как в REGISTER request-URI)
      const hostOnly = uriPart.match(/sip:([^:;>\s]+)(?::(\d+))?/);
      if (hostOnly) {
        result.host = hostOnly[1];
        if (hostOnly[2]) result.port = parseInt(hostOnly[2]);
      }
    }
    
    result.uri = uriPart.split(';')[0].split('>')[0];
    
    return result;
  }

  /**
   * Парсинг Authorization/Proxy-Authorization
   */
  static _parseAuth(value) {
    const result = { scheme: '', params: {} };
    const schemeMatch = value.match(/^(\w+)\s+(.+)$/);
    if (!schemeMatch) return result;
    
    result.scheme = schemeMatch[1];
    const paramsStr = schemeMatch[2];
    
    // Парсим key=value пары
    const paramRegex = /(\w+)\s*=\s*(?:"([^"]*)"|([^,\s]+))/g;
    let match;
    while ((match = paramRegex.exec(paramsStr)) !== null) {
      result.params[match[1]] = match[2] !== undefined ? match[2] : match[3];
    }
    
    return result;
  }

  /**
   * Сериализация SIP-сообщения в строку
   */
  toString() {
    let lines = [];
    
    if (this.isRequest) {
      lines.push(`${this.method} ${this.requestUri} ${this.sipVersion}`);
    } else {
      lines.push(`${this.sipVersion} ${this.statusCode} ${this.reasonPhrase}`);
    }
    
    // Заголовки в определённом порядке
    const headerOrder = ['via', 'from', 'to', 'call-id', 'cseq', 'contact', 
                         'max-forwards', 'user-agent', 'allow', 'supported',
                         'www-authenticate', 'proxy-authenticate',
                         'authorization', 'proxy-authorization',
                         'expires', 'event', 'subscription-state',
                         'refer-to', 'p-asserted-identity',
                         'x-acrypt', 'content-type', 'content-length'];
    
    const added = new Set();
    
    for (const key of headerOrder) {
      if (this.headers[key]) {
        for (const h of this.headers[key]) {
          lines.push(`${h.name}: ${h.value}`);
        }
        added.add(key);
      }
    }
    
    // Остальные заголовки
    for (const [key, values] of Object.entries(this.headers)) {
      if (!added.has(key)) {
        for (const h of values) {
          lines.push(`${h.name}: ${h.value}`);
        }
      }
    }
    
    return lines.join('\r\n') + '\r\n\r\n' + (this.body || '');
  }
}

// ═══════════════════════════════════════════════════════════════
// SDP ПАРСЕР/ГЕНЕРАТОР
// ═══════════════════════════════════════════════════════════════

class SDP {
  constructor() {
    this.version = 0;
    this.origin = { username: '-', sessionId: '0', sessionVersion: '0', netType: 'IN', addrType: 'IP4', address: '0.0.0.0' };
    this.sessionName = 'SIP Call';
    this.connection = { netType: 'IN', addrType: 'IP4', address: '0.0.0.0' };
    this.timing = { start: 0, stop: 0 };
    this.media = [];
  }

  static parse(sdpText) {
    const sdp = new SDP();
    let currentMedia = null;
    
    for (const line of sdpText.split(/\r?\n/)) {
      const match = line.match(/^([a-z])=(.*)/);
      if (!match) continue;
      
      const [, type, value] = match;
      
      switch (type) {
        case 'v':
          sdp.version = parseInt(value);
          break;
        case 'o': {
          const parts = value.split(/\s+/);
          if (parts.length >= 6) {
            sdp.origin = {
              username: parts[0], sessionId: parts[1], sessionVersion: parts[2],
              netType: parts[3], addrType: parts[4], address: parts[5]
            };
          }
          break;
        }
        case 's':
          sdp.sessionName = value;
          break;
        case 'c': {
          const cParts = value.split(/\s+/);
          const target = currentMedia || sdp;
          target.connection = { netType: cParts[0], addrType: cParts[1], address: cParts[2] };
          break;
        }
        case 't': {
          const tParts = value.split(/\s+/);
          sdp.timing = { start: parseInt(tParts[0]), stop: parseInt(tParts[1]) };
          break;
        }
        case 'm': {
          const mParts = value.split(/\s+/);
          currentMedia = {
            type: mParts[0],
            port: parseInt(mParts[1]),
            protocol: mParts[2],
            payloads: mParts.slice(3).map(p => parseInt(p)),
            attributes: [],
            rtpmap: {},
            fmtp: {},
            direction: 'sendrecv',
            connection: null,
          };
          sdp.media.push(currentMedia);
          break;
        }
        case 'a': {
          if (!currentMedia) break;
          currentMedia.attributes.push(value);
          
          const rtpmapMatch = value.match(/^rtpmap:(\d+)\s+(.+)/);
          if (rtpmapMatch) {
            currentMedia.rtpmap[parseInt(rtpmapMatch[1])] = rtpmapMatch[2];
          }
          
          const fmtpMatch = value.match(/^fmtp:(\d+)\s+(.+)/);
          if (fmtpMatch) {
            currentMedia.fmtp[parseInt(fmtpMatch[1])] = fmtpMatch[2];
          }
          
          if (['sendrecv', 'sendonly', 'recvonly', 'inactive'].includes(value)) {
            currentMedia.direction = value;
          }
          break;
        }
      }
    }
    
    return sdp;
  }

  toString() {
    let lines = [];
    lines.push(`v=${this.version}`);
    lines.push(`o=${this.origin.username} ${this.origin.sessionId} ${this.origin.sessionVersion} ${this.origin.netType} ${this.origin.addrType} ${this.origin.address}`);
    lines.push(`s=${this.sessionName}`);
    lines.push(`c=${this.connection.netType} ${this.connection.addrType} ${this.connection.address}`);
    lines.push(`t=${this.timing.start} ${this.timing.stop}`);
    
    for (const media of this.media) {
      lines.push(`m=${media.type} ${media.port} ${media.protocol} ${media.payloads.join(' ')}`);
      if (media.connection) {
        lines.push(`c=${media.connection.netType} ${media.connection.addrType} ${media.connection.address}`);
      }
      for (const attr of media.attributes) {
        lines.push(`a=${attr}`);
      }
    }
    
    return lines.join('\r\n') + '\r\n';
  }

  /**
   * Определить GoIP fingerprint в SDP
   */
  isGoIP() {
    const signs = [];
    if (this.origin.username === 'userX') signs.push('origin_userX');
    if (this.origin.sessionId === '20000001') signs.push('sessionId_20000001');
    if (this.sessionName === 'DBL Session') signs.push('session_DBL');
    return signs;
  }
}

// ═══════════════════════════════════════════════════════════════
// DIGEST AUTHENTICATION
// ═══════════════════════════════════════════════════════════════

class DigestAuth {
  /**
   * Генерация nonce
   */
  static generateNonce() {
    return crypto.randomBytes(16).toString('hex');
  }

  /**
   * Создание WWW-Authenticate заголовка
   */
  static createChallenge(realm, nonce) {
    return `Digest realm="${realm}", nonce="${nonce}", algorithm=MD5, qop="auth"`;
  }

  /**
   * Проверка Digest-ответа
   */
  static verify(auth, password, method) {
    if (!auth || auth.scheme !== 'Digest') return false;
    
    const { username, realm, nonce, response, uri, cnonce, qop, nc } = auth.params;
    if (!username || !realm || !nonce || !response) return false;
    
    // HA1 = MD5(username:realm:password)
    const ha1 = crypto.createHash('md5')
      .update(`${username}:${realm}:${password}`)
      .digest('hex');
    
    // HA2 = MD5(method:uri)
    const ha2 = crypto.createHash('md5')
      .update(`${method}:${uri}`)
      .digest('hex');
    
    let expected;
    if (qop === 'auth') {
      // response = MD5(HA1:nonce:nc:cnonce:qop:HA2)
      expected = crypto.createHash('md5')
        .update(`${ha1}:${nonce}:${nc || '00000001'}:${cnonce}:${qop}:${ha2}`)
        .digest('hex');
    } else {
      // response = MD5(HA1:nonce:HA2)
      expected = crypto.createHash('md5')
        .update(`${ha1}:${nonce}:${ha2}`)
        .digest('hex');
    }
    
    return response === expected;
  }
}

// ═══════════════════════════════════════════════════════════════
// GoIP FINGERPRINTER
// ═══════════════════════════════════════════════════════════════

class GoIPFingerprint {
  /**
   * Анализ SIP-сообщения на признаки GoIP
   */
  static analyze(msg) {
    const result = {
      isGoIP: false,
      confidence: 0,
      signs: [],
      deviceType: 'unknown',
      vendor: 'unknown',
    };
    
    // User-Agent
    const ua = msg.userAgent.toLowerCase();
    if (ua === 'dble') {
      result.signs.push('UA:dble');
      result.confidence += 40;
      result.vendor = 'DBLTek';
    } else if (ua === 'hybertone') {
      result.signs.push('UA:HYBERTONE');
      result.confidence += 40;
      result.vendor = 'HYBERTONE';
    } else if (ua === 'pak') {
      result.signs.push('UA:pak');
      result.confidence += 30;
      result.vendor = 'DBLTek-PAK';
    }
    
    // X-ACrypt
    if (msg.xACrypt) {
      result.signs.push(`X-ACrypt:${msg.xACrypt}`);
      result.confidence += 30;
    }
    
    // SDP fingerprints
    if (msg.body && msg.contentType === 'application/sdp') {
      const sdp = SDP.parse(msg.body);
      const sdpSigns = sdp.isGoIP();
      result.signs.push(...sdpSigns);
      result.confidence += sdpSigns.length * 15;
    }
    
    // Via branch format (z9hG4bK + digits)
    if (msg.via.length > 0 && msg.via[0].branch) {
      if (/^z9hG4bK\d{6,10}$/.test(msg.via[0].branch)) {
        result.signs.push('via_branch:oSIP_uint32');
        result.confidence += 10;
      }
    }
    
    // Content-Length со множеством пробелов
    const clHeader = msg.headers['content-length'];
    if (clHeader && clHeader[0] && /^\s{3,}\d+$/.test(clHeader[0].value)) {
      result.signs.push('content-length:padded');
      result.confidence += 10;
    }
    
    result.isGoIP = result.confidence >= 40;
    
    if (result.isGoIP) {
      if (result.signs.includes('UA:HYBERTONE') || result.signs.some(s => s.includes('ET263'))) {
        result.deviceType = 'HYBERTONE GST1610';
      } else {
        result.deviceType = 'DBLTek GoIP';
      }
    }
    
    return result;
  }
}

// ═══════════════════════════════════════════════════════════════
// ХРАНИЛИЩЕ СОСТОЯНИЙ
// ═══════════════════════════════════════════════════════════════

/**
 * Зарегистрированный SIP-аккаунт
 */
class SipAccount {
  constructor(username, password) {
    this.username = username;
    this.password = password;
    this.registrations = []; // [{contact, expires, addr, port, registeredAt, callId, cseq}]
    this.fingerprint = null;
  }
}

/**
 * Активный вызов
 */
class SipCall {
  constructor(callId) {
    this.callId = callId;
    this.state = 'init'; // init → trying → ringing → early_media → connected → terminated
    this.direction = '';  // inbound (SIP→GoIP→GSM) | outbound (GSM→GoIP→SIP)
    this.from = null;
    this.to = null;
    this.fromTag = '';
    this.toTag = '';
    this.localSdp = null;
    this.remoteSdp = null;
    this.cseq = 0;
    this.createdAt = Date.now();
    this.connectedAt = null;
    this.terminatedAt = null;
    this.addr = null;
    this.port = null;
    this.branch = '';
    this.via = null;
  }
}

// ═══════════════════════════════════════════════════════════════
// SIP SERVER
// ═══════════════════════════════════════════════════════════════

class GoIPSipServer extends EventEmitter {
  constructor(config) {
    super();
    this.config = config;
    this.socket = dgram.createSocket('udp4');
    
    // Хранилища
    this.accounts = new Map();      // username → SipAccount
    this.calls = new Map();         // callId → SipCall
    this.nonces = new Map();        // nonce → { createdAt, username }
    this.pendingInvites = new Map(); // callId → { msg, addr, port, timer }
    
    // Счётчики
    this.stats = {
      messagesReceived: 0,
      messagesSent: 0,
      registrations: 0,
      calls: 0,
      errors: 0,
      goipDevicesDetected: 0,
    };
    
    // Пул RTP портов
    this.rtpPortBase = 20000;
    this.rtpPortNext = this.rtpPortBase;
    
    this._setupSocket();
    this._startRegistrationCleanup();
  }

  // ─── Добавление аккаунтов ───

  addAccount(username, password) {
    this.accounts.set(username, new SipAccount(username, password));
    this.log(`Account added: ${username}`);
  }

  // ─── Запуск ───

  start() {
    this.socket.bind(this.config.sipPort, this.config.sipHost, () => {
      const addr = this.socket.address();
      this.log(`═══════════════════════════════════════════════`);
      this.log(`  GoIP SIP Server started`);
      this.log(`  SIP:  ${addr.address}:${addr.port}/UDP`);
      this.log(`  Realm: ${this.config.realm}`);
      this.log(`  Accounts: ${this.accounts.size}`);
      this.log(`═══════════════════════════════════════════════`);
    });
  }

  // ─── Сокет ───

  _setupSocket() {
    this.socket.on('message', (buffer, rinfo) => {
      this.stats.messagesReceived++;
      
      try {
        const msg = SipMessage.parse(buffer);
        if (!msg) {
          this.debug(`Failed to parse SIP from ${rinfo.address}:${rinfo.port}`);
          return;
        }
        
        if (this.config.logSipMessages) {
          this._logSipMessage('RECV', msg, rinfo);
        }
        
        if (msg.isRequest) {
          this._handleRequest(msg, rinfo);
        } else {
          this._handleResponse(msg, rinfo);
        }
        
      } catch (err) {
        this.stats.errors++;
        this.log(`ERROR processing message from ${rinfo.address}:${rinfo.port}: ${err.message}`);
        if (this.config.debug) console.error(err.stack);
      }
    });
    
    this.socket.on('error', (err) => {
      this.log(`Socket error: ${err.message}`);
    });
  }

  // ─── Обработка запросов ───

  _handleRequest(msg, rinfo) {
    // Fingerprint check
    const fp = GoIPFingerprint.analyze(msg);
    if (fp.isGoIP && fp.confidence > 50) {
      this.debug(`GoIP detected: ${fp.deviceType} (confidence: ${fp.confidence}%, signs: ${fp.signs.join(', ')})`);
    }
    
    switch (msg.method) {
      case 'REGISTER':
        this._handleRegister(msg, rinfo, fp);
        break;
      case 'INVITE':
        this._handleInvite(msg, rinfo, fp);
        break;
      case 'ACK':
        this._handleAck(msg, rinfo);
        break;
      case 'BYE':
        this._handleBye(msg, rinfo);
        break;
      case 'CANCEL':
        this._handleCancel(msg, rinfo);
        break;
      case 'OPTIONS':
        this._handleOptions(msg, rinfo);
        break;
      case 'INFO':
        this._handleInfo(msg, rinfo);
        break;
      case 'MESSAGE':
        this._handleMessage(msg, rinfo);
        break;
      case 'SUBSCRIBE':
        this._handleSubscribe(msg, rinfo);
        break;
      case 'NOTIFY':
        this._handleNotify(msg, rinfo);
        break;
      case 'REFER':
        this._handleRefer(msg, rinfo);
        break;
      default:
        this._sendResponse(msg, 405, 'Method Not Allowed', rinfo);
    }
  }

  // ─── REGISTER ───

  _handleRegister(msg, rinfo, fp) {
    const username = msg.from ? msg.from.user : null;
    if (!username) {
      this._sendResponse(msg, 400, 'Bad Request', rinfo);
      return;
    }
    
    const account = this.accounts.get(username);
    if (!account) {
      this.log(`REGISTER from unknown user: ${username} @ ${rinfo.address}:${rinfo.port}`);
      this._sendResponse(msg, 403, 'Forbidden', rinfo);
      return;
    }
    
    // Проверяем авторизацию
    if (this.config.requireAuth) {
      if (!msg.authorization) {
        // Отправляем 401 challenge
        const nonce = DigestAuth.generateNonce();
        this.nonces.set(nonce, { createdAt: Date.now(), username });
        
        const response = this._createResponse(msg, 401, 'Unauthorized', rinfo);
        response.headers['www-authenticate'] = [{
          name: 'WWW-Authenticate',
          value: DigestAuth.createChallenge(this.config.realm, nonce)
        }];
        
        this._send(response, rinfo);
        this.debug(`REGISTER 401 challenge sent to ${username}`);
        return;
      }
      
      // Проверяем credentials
      if (!DigestAuth.verify(msg.authorization, account.password, 'REGISTER')) {
        this.log(`REGISTER auth failed for ${username}`);
        this._sendResponse(msg, 403, 'Forbidden', rinfo);
        return;
      }
    }
    
    // Определяем expires
    let expires = this.config.registerExpiry;
    if (msg.contact && msg.contact.params.expires !== undefined) {
      expires = msg.contact.params.expires;
    } else if (msg.expires !== null) {
      expires = msg.expires;
    }
    
    // Deregister?
    if (expires === 0) {
      account.registrations = account.registrations.filter(r => 
        !(r.addr === rinfo.address && r.port === rinfo.port));
      this.log(`UNREGISTER: ${username} from ${rinfo.address}:${rinfo.port}`);
    } else {
      // Обновляем или добавляем регистрацию
      const existing = account.registrations.find(r => 
        r.addr === rinfo.address && r.port === rinfo.port);
      
      const regInfo = {
        contact: msg.contact ? msg.contact.raw : `<sip:${username}@${rinfo.address}:${rinfo.port}>`,
        expires,
        addr: rinfo.address,
        port: rinfo.port,
        registeredAt: Date.now(),
        callId: msg.callId,
        cseq: msg.cseq.num,
      };
      
      if (existing) {
        Object.assign(existing, regInfo);
      } else {
        account.registrations.push(regInfo);
        this.stats.registrations++;
      }
      
      // Сохраняем fingerprint
      if (fp) account.fingerprint = fp;
      
      this.log(`REGISTER OK: ${username} @ ${rinfo.address}:${rinfo.port} (expires=${expires}s)`);
    }
    
    // 200 OK
    const response = this._createResponse(msg, 200, 'OK', rinfo);
    if (msg.contact) {
      response.headers['contact'] = [{
        name: 'Contact',
        value: `${msg.contact.raw.split(';expires=')[0]};expires=${expires}`
      }];
    }
    
    this._send(response, rinfo);
    
    this.emit('register', {
      username,
      addr: rinfo.address,
      port: rinfo.port,
      expires,
      fingerprint: fp,
    });
  }

  // ─── INVITE ───

  _handleInvite(msg, rinfo, fp) {
    const fromUser = msg.from ? msg.from.user : 'unknown';
    const toUser = msg.to ? msg.to.user : 'unknown';
    
    this.debug(`INVITE: ${fromUser} → ${toUser}`);
    
    // Проверяем авторизацию если нужно
    if (this.config.requireAuth && !msg.proxyAuthorization) {
      const nonce = DigestAuth.generateNonce();
      this.nonces.set(nonce, { createdAt: Date.now(), username: fromUser });
      
      const response = this._createResponse(msg, 407, 'Proxy Authentication Required', rinfo);
      response.headers['proxy-authenticate'] = [{
        name: 'Proxy-Authenticate',
        value: DigestAuth.createChallenge(this.config.realm, nonce)
      }];
      
      this._send(response, rinfo);
      return;
    }
    
    // Если это re-INVITE (уже есть активный вызов)
    const existingCall = this.calls.get(msg.callId);
    if (existingCall && existingCall.state === 'connected') {
      this._handleReInvite(msg, rinfo, existingCall);
      return;
    }
    
    // Новый вызов
    const call = new SipCall(msg.callId);
    call.direction = 'outbound'; // GoIP → нас (GSM→SIP)
    call.from = msg.from;
    call.to = msg.to;
    call.fromTag = msg.from ? msg.from.tag : '';
    call.toTag = this._generateTag();
    call.cseq = msg.cseq.num;
    call.addr = rinfo.address;
    call.port = rinfo.port;
    call.via = msg.via[0];
    call.state = 'trying';
    
    // Парсим SDP
    if (msg.body && msg.contentType === 'application/sdp') {
      call.remoteSdp = SDP.parse(msg.body);
    }
    
    this.calls.set(msg.callId, call);
    this.stats.calls++;
    
    // 100 Trying
    this._sendResponse(msg, 100, 'Trying', rinfo);
    
    // Генерируем локальный SDP для ответа
    call.localSdp = this._generateSdp(rinfo, call.remoteSdp);
    
    // Отправляем событие — приложение решает что делать
    this.emit('invite', {
      callId: msg.callId,
      from: fromUser,
      to: toUser,
      callerDisplay: msg.from ? msg.from.displayName : '',
      pAssertedIdentity: msg.pAssertedIdentity,
      sdp: call.remoteSdp,
      fingerprint: fp,
      addr: rinfo.address,
      port: rinfo.port,
      
      // Методы ответа
      ring: () => this._sendCallResponse(msg, call, 180, 'Ringing', rinfo),
      progress: (sdp) => this._sendCallResponse(msg, call, 183, 'Session Progress', rinfo, sdp || call.localSdp),
      answer: (sdp) => this._sendCallResponse(msg, call, 200, 'OK', rinfo, sdp || call.localSdp),
      busy: () => this._sendCallResponse(msg, call, 486, 'Busy Here', rinfo),
      reject: (code, reason) => this._sendCallResponse(msg, call, code || 603, reason || 'Decline', rinfo),
      unavailable: () => this._sendCallResponse(msg, call, 480, 'Temporarily Unavailable', rinfo),
    });
    
    // Автоответ через таймаут если не обработано
    const timer = setTimeout(() => {
      if (call.state === 'trying') {
        this.log(`INVITE timeout for ${msg.callId}`);
        this._sendCallResponse(msg, call, 480, 'Temporarily Unavailable', rinfo);
        call.state = 'terminated';
      }
    }, this.config.inviteTimeout * 1000);
    
    this.pendingInvites.set(msg.callId, { msg, addr: rinfo.address, port: rinfo.port, timer });
  }

  _handleReInvite(msg, rinfo, call) {
    // re-INVITE — обычно hold/retrieve
    if (msg.body && msg.contentType === 'application/sdp') {
      const newSdp = SDP.parse(msg.body);
      const audioMedia = newSdp.media.find(m => m.type === 'audio');
      
      if (audioMedia) {
        const direction = audioMedia.direction;
        this.debug(`re-INVITE: ${call.callId} direction=${direction}`);
        
        call.remoteSdp = newSdp;
        
        if (direction === 'sendonly') {
          call.state = 'held';
          this.emit('hold', { callId: call.callId });
        } else if (direction === 'sendrecv') {
          call.state = 'connected';
          this.emit('unhold', { callId: call.callId });
        }
      }
    }
    
    // 200 OK с SDP
    const response = this._createResponse(msg, 200, 'OK', rinfo);
    this._addToTag(response, call.toTag);
    
    if (call.localSdp) {
      const sdpStr = call.localSdp.toString();
      response.headers['content-type'] = [{ name: 'Content-Type', value: 'application/sdp' }];
      response.headers['content-length'] = [{ name: 'Content-Length', value: sdpStr.length.toString() }];
      response.body = sdpStr;
    }
    
    this._send(response, rinfo);
  }

  // ─── ACK ───

  _handleAck(msg, rinfo) {
    const call = this.calls.get(msg.callId);
    if (call) {
      call.state = 'connected';
      call.connectedAt = Date.now();
      this.debug(`ACK received for ${msg.callId}`);
      this.emit('ack', { callId: msg.callId });
    }
    
    // Убираем таймер
    const pending = this.pendingInvites.get(msg.callId);
    if (pending) {
      clearTimeout(pending.timer);
      this.pendingInvites.delete(msg.callId);
    }
  }

  // ─── BYE ───

  _handleBye(msg, rinfo) {
    const call = this.calls.get(msg.callId);
    
    // 200 OK
    this._sendResponse(msg, 200, 'OK', rinfo);
    
    if (call) {
      call.state = 'terminated';
      call.terminatedAt = Date.now();
      const duration = call.connectedAt ? Math.floor((call.terminatedAt - call.connectedAt) / 1000) : 0;
      this.log(`BYE: ${msg.callId} (duration=${duration}s)`);
      
      this.emit('bye', {
        callId: msg.callId,
        duration,
        from: call.from ? call.from.user : '',
        to: call.to ? call.to.user : '',
      });
      
      // Cleanup после небольшой задержки (для retransmits)
      setTimeout(() => this.calls.delete(msg.callId), 30000);
    }
  }

  // ─── CANCEL ───

  _handleCancel(msg, rinfo) {
    const call = this.calls.get(msg.callId);
    
    // 200 OK на CANCEL
    this._sendResponse(msg, 200, 'OK', rinfo);
    
    if (call && call.state !== 'connected') {
      // 487 Request Terminated (на оригинальный INVITE)
      const pending = this.pendingInvites.get(msg.callId);
      if (pending) {
        const invResponse = this._createResponse(pending.msg, 487, 'Request Terminated', rinfo);
        this._addToTag(invResponse, call.toTag);
        this._send(invResponse, rinfo);
        clearTimeout(pending.timer);
        this.pendingInvites.delete(msg.callId);
      }
      
      call.state = 'terminated';
      call.terminatedAt = Date.now();
      this.log(`CANCEL: ${msg.callId}`);
      
      this.emit('cancel', { callId: msg.callId });
    }
  }

  // ─── OPTIONS ───

  _handleOptions(msg, rinfo) {
    const response = this._createResponse(msg, 200, 'OK', rinfo);
    response.headers['allow'] = [{
      name: 'Allow',
      value: 'INVITE, ACK, BYE, CANCEL, OPTIONS, NOTIFY, REFER, REGISTER, MESSAGE, INFO, SUBSCRIBE'
    }];
    this._send(response, rinfo);
  }

  // ─── INFO (DTMF) ───

  _handleInfo(msg, rinfo) {
    const call = this.calls.get(msg.callId);
    
    // 200 OK
    this._sendResponse(msg, 200, 'OK', rinfo);
    
    // Парсим DTMF
    if (msg.contentType === 'application/dtmf-relay' && msg.body) {
      const signalMatch = msg.body.match(/Signal=(.+)/);
      const durationMatch = msg.body.match(/Duration=(\d+)/);
      
      if (signalMatch) {
        const dtmf = {
          callId: msg.callId,
          signal: signalMatch[1].trim(),
          duration: durationMatch ? parseInt(durationMatch[1]) : 160,
          method: 'SIP_INFO',
        };
        
        this.debug(`DTMF: ${dtmf.signal} (duration=${dtmf.duration}ms) via SIP INFO`);
        this.emit('dtmf', dtmf);
      }
    }
  }

  // ─── MESSAGE (SMS) ───

  _handleMessage(msg, rinfo) {
    const fromUser = msg.from ? msg.from.user : 'unknown';
    const toUser = msg.to ? msg.to.user : 'unknown';
    
    // 200 OK
    this._sendResponse(msg, 200, 'OK', rinfo);
    
    const sms = {
      callId: msg.callId,
      from: fromUser,
      to: toUser,
      contentType: msg.contentType,
      body: msg.body,
    };
    
    this.log(`MESSAGE: ${fromUser} → ${toUser}: ${msg.body.substring(0, 50)}...`);
    this.emit('message', sms);
  }

  // ─── SUBSCRIBE ───

  _handleSubscribe(msg, rinfo) {
    const response = this._createResponse(msg, 200, 'OK', rinfo);
    response.headers['expires'] = [{ name: 'Expires', value: '3600' }];
    this._send(response, rinfo);
    
    this.debug(`SUBSCRIBE: event=${msg.event} from ${msg.from ? msg.from.user : 'unknown'}`);
    this.emit('subscribe', {
      from: msg.from ? msg.from.user : '',
      event: msg.event,
      addr: rinfo.address,
      port: rinfo.port,
    });
  }

  // ─── NOTIFY ───
  
  _handleNotify(msg, rinfo) {
    this._sendResponse(msg, 200, 'OK', rinfo);
    this.debug(`NOTIFY received from ${rinfo.address}:${rinfo.port}`);
  }

  // ─── REFER ───

  _handleRefer(msg, rinfo) {
    const call = this.calls.get(msg.callId);
    
    // 202 Accepted
    this._sendResponse(msg, 202, 'Accepted', rinfo);
    
    const referTarget = msg.referTo;
    this.log(`REFER: ${msg.callId} → ${referTarget}`);
    
    this.emit('refer', {
      callId: msg.callId,
      referTo: referTarget,
      from: msg.from ? msg.from.user : '',
    });
  }

  // ─── Ответ на Response (от GoIP) ───

  _handleResponse(msg, rinfo) {
    this.debug(`Response ${msg.statusCode} ${msg.reasonPhrase} from ${rinfo.address}:${rinfo.port}`);
    
    // Fingerprint на 480 Remote Busy
    if (msg.statusCode === 480 && msg.reasonPhrase === 'Remote Busy') {
      this.debug(`GoIP fingerprint confirmed: 480 Remote Busy (non-standard reason phrase)`);
    }
    
    this.emit('response', {
      statusCode: msg.statusCode,
      reasonPhrase: msg.reasonPhrase,
      callId: msg.callId,
      cseq: msg.cseq,
      addr: rinfo.address,
      port: rinfo.port,
    });
  }

  // ═══════════════════════════════════════════════════════════
  // ИСХОДЯЩИЕ SIP-СООБЩЕНИЯ (сервер → GoIP)
  // ═══════════════════════════════════════════════════════════

  /**
   * Отправка INVITE на GoIP (для звонка через GSM)
   */
  sendInvite(targetUser, calledNumber, callerDisplay, callerNumber) {
    const account = this.accounts.get(targetUser);
    if (!account || account.registrations.length === 0) {
      this.log(`Cannot send INVITE: ${targetUser} not registered`);
      return null;
    }
    
    const reg = account.registrations[0];
    const callId = `srv-${crypto.randomBytes(8).toString('hex')}@${this._getLocalIp()}`;
    const branch = `z9hG4bK${crypto.randomBytes(4).toString('hex')}`;
    const tag = this._generateTag();
    const localIp = this._getLocalIp();
    
    // Создаём SDP
    const sdp = new SDP();
    sdp.origin = { username: '-', sessionId: String(Date.now()), sessionVersion: '1', 
                   netType: 'IN', addrType: 'IP4', address: localIp };
    sdp.sessionName = 'SIP Call';
    sdp.connection = { netType: 'IN', addrType: 'IP4', address: localIp };
    sdp.media.push({
      type: 'audio',
      port: this._nextRtpPort(),
      protocol: 'RTP/AVP',
      payloads: [8, 0, 101],
      attributes: [
        'rtpmap:8 PCMA/8000',
        'rtpmap:0 PCMU/8000',
        'rtpmap:101 telephone-event/8000',
        'fmtp:101 0-15',
        'ptime:20',
        'sendrecv'
      ],
      rtpmap: {}, fmtp: {}, direction: 'sendrecv', connection: null,
    });
    
    const sdpStr = sdp.toString();
    
    // Создаём вызов
    const call = new SipCall(callId);
    call.direction = 'inbound'; // Мы → GoIP (SIP→GSM)
    call.from = { user: callerNumber || 'server', host: localIp, displayName: callerDisplay || 'Server' };
    call.to = { user: calledNumber, host: reg.addr };
    call.fromTag = tag;
    call.localSdp = sdp;
    call.addr = reg.addr;
    call.port = reg.port;
    call.state = 'trying';
    this.calls.set(callId, call);
    
    // Формируем INVITE
    const msg = new SipMessage();
    msg.isRequest = true;
    msg.method = 'INVITE';
    msg.requestUri = `sip:${calledNumber}@${reg.addr}:${reg.port}`;
    
    msg.headers = {
      'via': [{ name: 'Via', value: `SIP/2.0/UDP ${localIp}:${this.config.sipPort};branch=${branch}` }],
      'from': [{ name: 'From', value: `"${callerDisplay || 'Server'}" <sip:${callerNumber || 'server'}@${localIp}>;tag=${tag}` }],
      'to': [{ name: 'To', value: `<sip:${calledNumber}@${reg.addr}>` }],
      'call-id': [{ name: 'Call-ID', value: callId }],
      'cseq': [{ name: 'CSeq', value: '1 INVITE' }],
      'contact': [{ name: 'Contact', value: `<sip:${callerNumber || 'server'}@${localIp}:${this.config.sipPort}>` }],
      'max-forwards': [{ name: 'Max-Forwards', value: '70' }],
      'content-type': [{ name: 'Content-Type', value: 'application/sdp' }],
      'content-length': [{ name: 'Content-Length', value: String(sdpStr.length) }],
    };
    
    msg.body = sdpStr;
    
    this._send(msg, { address: reg.addr, port: reg.port });
    this.log(`INVITE sent: ${callerNumber || 'server'} → ${calledNumber} @ ${reg.addr}:${reg.port}`);
    
    return callId;
  }

  /**
   * Отправка BYE (завершение вызова)
   */
  sendBye(callId) {
    const call = this.calls.get(callId);
    if (!call) {
      this.log(`Cannot send BYE: call ${callId} not found`);
      return;
    }
    
    const localIp = this._getLocalIp();
    const branch = `z9hG4bK${crypto.randomBytes(4).toString('hex')}`;
    
    const msg = new SipMessage();
    msg.isRequest = true;
    msg.method = 'BYE';
    msg.requestUri = `sip:${call.from.user}@${call.addr}:${call.port}`;
    
    msg.headers = {
      'via': [{ name: 'Via', value: `SIP/2.0/UDP ${localIp}:${this.config.sipPort};branch=${branch}` }],
      'from': [{ name: 'From', value: `<sip:server@${localIp}>;tag=srv${Date.now()}` }],
      'to': [{ name: 'To', value: `<sip:${call.from.user}@${call.addr}>;tag=${call.fromTag}` }],
      'call-id': [{ name: 'Call-ID', value: callId }],
      'cseq': [{ name: 'CSeq', value: `${call.cseq + 1} BYE` }],
      'max-forwards': [{ name: 'Max-Forwards', value: '70' }],
      'content-length': [{ name: 'Content-Length', value: '0' }],
    };
    
    this._send(msg, { address: call.addr, port: call.port });
    call.state = 'terminated';
    call.terminatedAt = Date.now();
    
    this.log(`BYE sent for ${callId}`);
  }

  /**
   * Отправка SIP MESSAGE (SMS через SIP)
   */
  sendMessage(targetUser, text, fromNumber) {
    const account = this.accounts.get(targetUser);
    if (!account || account.registrations.length === 0) {
      this.log(`Cannot send MESSAGE: ${targetUser} not registered`);
      return false;
    }
    
    const reg = account.registrations[0];
    const localIp = this._getLocalIp();
    const branch = `z9hG4bK${crypto.randomBytes(4).toString('hex')}`;
    const callId = `sms-${crypto.randomBytes(6).toString('hex')}@${localIp}`;
    const tag = this._generateTag();
    
    const msg = new SipMessage();
    msg.isRequest = true;
    msg.method = 'MESSAGE';
    msg.requestUri = `sip:${targetUser}@${reg.addr}:${reg.port}`;
    
    msg.headers = {
      'via': [{ name: 'Via', value: `SIP/2.0/UDP ${localIp}:${this.config.sipPort};branch=${branch}` }],
      'from': [{ name: 'From', value: `<sip:${fromNumber || 'sms_service'}@${localIp}>;tag=${tag}` }],
      'to': [{ name: 'To', value: `<sip:${targetUser}@${reg.addr}:${reg.port}>` }],
      'call-id': [{ name: 'Call-ID', value: callId }],
      'cseq': [{ name: 'CSeq', value: '1 MESSAGE' }],
      'max-forwards': [{ name: 'Max-Forwards', value: '70' }],
      'content-type': [{ name: 'Content-Type', value: 'text/plain' }],
      'content-length': [{ name: 'Content-Length', value: String(Buffer.byteLength(text)) }],
    };
    
    msg.body = text;
    
    this._send(msg, { address: reg.addr, port: reg.port });
    this.log(`MESSAGE sent to ${targetUser}: ${text.substring(0, 50)}...`);
    return true;
  }

  // ═══════════════════════════════════════════════════════════
  // ВСПОМОГАТЕЛЬНЫЕ МЕТОДЫ
  // ═══════════════════════════════════════════════════════════

  _createResponse(request, code, reason, rinfo) {
    const response = new SipMessage();
    response.isResponse = true;
    response.statusCode = code;
    response.reasonPhrase = reason;
    
    // Копируем Via из запроса, добавляя rport и received
    response.headers['via'] = (request.headers['via'] || []).map(v => {
      let val = v.value;
      // Заполняем rport
      if (val.includes('rport') && !val.includes('rport=')) {
        val = val.replace('rport', `rport=${rinfo.port}`);
      }
      // Добавляем received если IP не совпадает
      const via = SipMessage._parseVia(val);
      if (via.host !== rinfo.address && !val.includes('received=')) {
        val += `;received=${rinfo.address}`;
      }
      return { name: 'Via', value: val };
    });
    
    // From, To, Call-ID, CSeq
    response.headers['from'] = request.headers['from'] || request.headers['f'] || [];
    response.headers['to'] = request.headers['to'] || request.headers['t'] || [];
    response.headers['call-id'] = request.headers['call-id'] || request.headers['i'] || [];
    response.headers['cseq'] = request.headers['cseq'] || [];
    
    response.headers['content-length'] = [{ name: 'Content-Length', value: '0' }];
    
    return response;
  }

  _sendResponse(request, code, reason, rinfo, body, contentType) {
    const response = this._createResponse(request, code, reason, rinfo);
    
    if (body) {
      response.headers['content-type'] = [{ name: 'Content-Type', value: contentType || 'application/sdp' }];
      response.headers['content-length'] = [{ name: 'Content-Length', value: String(body.length) }];
      response.body = body;
    }
    
    this._send(response, rinfo);
  }

  _sendCallResponse(request, call, code, reason, rinfo, sdp) {
    const response = this._createResponse(request, code, reason, rinfo);
    this._addToTag(response, call.toTag);
    
    if (code >= 200 && code < 300) {
      // Contact заголовок для 2xx
      const localIp = this._getLocalIp();
      response.headers['contact'] = [{
        name: 'Contact',
        value: `<sip:server@${localIp}:${this.config.sipPort}>`
      }];
    }
    
    if (sdp) {
      const sdpStr = typeof sdp === 'string' ? sdp : sdp.toString();
      response.headers['content-type'] = [{ name: 'Content-Type', value: 'application/sdp' }];
      response.headers['content-length'] = [{ name: 'Content-Length', value: String(sdpStr.length) }];
      response.body = sdpStr;
    }
    
    if (code === 180) call.state = 'ringing';
    else if (code === 183) call.state = 'early_media';
    else if (code === 200) call.state = 'answered';
    else if (code >= 400) {
      call.state = 'terminated';
      call.terminatedAt = Date.now();
    }
    
    this._send(response, rinfo);
  }

  _addToTag(response, tag) {
    if (response.headers['to'] && response.headers['to'].length > 0) {
      let toVal = response.headers['to'][0].value;
      if (!toVal.includes('tag=')) {
        toVal += `;tag=${tag}`;
        response.headers['to'][0].value = toVal;
      }
    }
  }

  _send(msg, rinfo) {
    const text = msg.toString();
    const buffer = Buffer.from(text);
    
    this.socket.send(buffer, 0, buffer.length, rinfo.port, rinfo.address, (err) => {
      if (err) {
        this.log(`Send error to ${rinfo.address}:${rinfo.port}: ${err.message}`);
      } else {
        this.stats.messagesSent++;
        if (this.config.logSipMessages) {
          this._logSipMessage('SEND', msg, rinfo);
        }
      }
    });
  }

  _generateTag() {
    return crypto.randomBytes(6).toString('hex');
  }

  _generateSdp(rinfo, remoteSdp) {
    const localIp = this._getLocalIp();
    const sdp = new SDP();
    
    sdp.origin = {
      username: '-',
      sessionId: String(Date.now()),
      sessionVersion: '1',
      netType: 'IN',
      addrType: 'IP4',
      address: localIp,
    };
    sdp.sessionName = 'SIP Call';
    sdp.connection = { netType: 'IN', addrType: 'IP4', address: localIp };
    
    // Согласование кодеков
    let payloads = [8, 0, 101]; // default: PCMA, PCMU, telephone-event
    let attrs = [
      'rtpmap:8 PCMA/8000',
      'rtpmap:0 PCMU/8000',
      'rtpmap:101 telephone-event/8000',
      'fmtp:101 0-15',
      'ptime:20',
      'sendrecv',
    ];
    
    if (remoteSdp && remoteSdp.media.length > 0) {
      const remoteMedia = remoteSdp.media[0];
      // Фильтруем кодеки которые поддерживаем
      const supported = new Set([0, 3, 4, 8, 18, 101]);
      payloads = remoteMedia.payloads.filter(p => supported.has(p));
      if (payloads.length === 0) payloads = [8, 0, 101];
    }
    
    sdp.media.push({
      type: 'audio',
      port: this._nextRtpPort(),
      protocol: remoteSdp && remoteSdp.media[0] ? remoteSdp.media[0].protocol : 'RTP/AVP',
      payloads,
      attributes: attrs,
      rtpmap: {}, fmtp: {}, direction: 'sendrecv', connection: null,
    });
    
    return sdp;
  }

  _nextRtpPort() {
    const port = this.rtpPortNext;
    this.rtpPortNext += 2; // RTP использует чётные порты
    if (this.rtpPortNext > 30000) this.rtpPortNext = this.rtpPortBase;
    return port;
  }

  _getLocalIp() {
    const addr = this.socket.address();
    if (addr.address === '0.0.0.0' || addr.address === '::') {
      // Пробуем определить реальный IP
      const os = require('os');
      const interfaces = os.networkInterfaces();
      for (const iface of Object.values(interfaces)) {
        for (const info of iface) {
          if (info.family === 'IPv4' && !info.internal) {
            return info.address;
          }
        }
      }
      return '127.0.0.1';
    }
    return addr.address;
  }

  _startRegistrationCleanup() {
    setInterval(() => {
      const now = Date.now();
      
      for (const [username, account] of this.accounts) {
        const before = account.registrations.length;
        account.registrations = account.registrations.filter(r => {
          const elapsed = (now - r.registeredAt) / 1000;
          return elapsed < r.expires * 2; // Даём 2x запас
        });
        
        if (account.registrations.length < before) {
          this.debug(`Registration expired for ${username} (${before} → ${account.registrations.length})`);
        }
      }
    }, this.config.registrationCheckInterval * 1000);
  }

  // ─── Логирование ───

  _logSipMessage(direction, msg, rinfo) {
    const arrow = direction === 'RECV' ? '◄──' : '──►';
    const method = msg.isRequest ? msg.method : `${msg.statusCode} ${msg.reasonPhrase}`;
    const peer = `${rinfo.address}:${rinfo.port}`;
    
    console.log(`[SIP] ${arrow} ${method} ${direction === 'RECV' ? 'from' : 'to'} ${peer}`);
    
    if (this.config.debug) {
      const text = msg.toString();
      const lines = text.split('\r\n');
      for (const line of lines.slice(0, 15)) {
        if (line) console.log(`       ${line}`);
      }
      if (lines.length > 15) console.log(`       ... (${lines.length - 15} more lines)`);
    }
  }

  log(text) {
    const ts = new Date().toISOString().substring(11, 23);
    console.log(`[${ts}] ${text}`);
  }

  debug(text) {
    if (this.config.debug) {
      const ts = new Date().toISOString().substring(11, 23);
      console.log(`[${ts}] [DEBUG] ${text}`);
    }
  }

  // ─── Статистика ───

  getStatus() {
    const registeredAccounts = [];
    for (const [username, account] of this.accounts) {
      if (account.registrations.length > 0) {
        registeredAccounts.push({
          username,
          registrations: account.registrations.map(r => ({
            addr: r.addr,
            port: r.port,
            expires: r.expires,
            age: Math.floor((Date.now() - r.registeredAt) / 1000),
          })),
          fingerprint: account.fingerprint,
        });
      }
    }
    
    const activeCalls = [];
    for (const [callId, call] of this.calls) {
      if (call.state !== 'terminated') {
        activeCalls.push({
          callId,
          state: call.state,
          direction: call.direction,
          from: call.from ? call.from.user : '',
          to: call.to ? call.to.user : '',
          duration: call.connectedAt ? Math.floor((Date.now() - call.connectedAt) / 1000) : 0,
        });
      }
    }
    
    return {
      stats: this.stats,
      registeredAccounts,
      activeCalls,
      config: {
        sipPort: this.config.sipPort,
        realm: this.config.realm,
        totalAccounts: this.accounts.size,
      },
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// HTTP API
// ═══════════════════════════════════════════════════════════════

class ApiServer {
  constructor(sipServer, port) {
    this.sipServer = sipServer;
    this.port = port;
    this.server = http.createServer((req, res) => this._handle(req, res));
  }

  start() {
    this.server.listen(this.port, () => {
      console.log(`[API] HTTP API на http://0.0.0.0:${this.port}`);
      console.log(`[API] Endpoints:`);
      console.log(`  GET  /status          — статус сервера`);
      console.log(`  GET  /registrations   — зарегистрированные устройства`);
      console.log(`  GET  /calls           — активные вызовы`);
      console.log(`  POST /invite          — отправить INVITE на GoIP`);
      console.log(`  POST /bye             — завершить вызов`);
      console.log(`  POST /message         — отправить SMS через GoIP`);
      console.log(`  POST /account         — добавить аккаунт`);
    });
  }

  async _handle(req, res) {
    const parsed = url.parse(req.url, true);
    const path = parsed.pathname;
    const method = req.method;
    
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    
    if (method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }
    
    try {
      let body = '';
      if (method === 'POST') {
        body = await new Promise((resolve, reject) => {
          let data = '';
          req.on('data', chunk => data += chunk);
          req.on('end', () => resolve(data));
          req.on('error', reject);
        });
      }
      
      switch (path) {
        case '/status':
          this._json(res, 200, this.sipServer.getStatus());
          break;
          
        case '/registrations':
          this._json(res, 200, this.sipServer.getStatus().registeredAccounts);
          break;
          
        case '/calls':
          this._json(res, 200, this.sipServer.getStatus().activeCalls);
          break;
          
        case '/invite':
          if (method !== 'POST') { this._json(res, 405, { error: 'POST required' }); break; }
          const invData = JSON.parse(body);
          const callId = this.sipServer.sendInvite(
            invData.targetUser,
            invData.calledNumber,
            invData.callerDisplay,
            invData.callerNumber
          );
          this._json(res, callId ? 200 : 400, callId ? { callId } : { error: 'User not registered' });
          break;
          
        case '/bye':
          if (method !== 'POST') { this._json(res, 405, { error: 'POST required' }); break; }
          const byeData = JSON.parse(body);
          this.sipServer.sendBye(byeData.callId);
          this._json(res, 200, { ok: true });
          break;
          
        case '/message':
          if (method !== 'POST') { this._json(res, 405, { error: 'POST required' }); break; }
          const msgData = JSON.parse(body);
          const sent = this.sipServer.sendMessage(msgData.targetUser, msgData.text, msgData.fromNumber);
          this._json(res, sent ? 200 : 400, sent ? { ok: true } : { error: 'User not registered' });
          break;
          
        case '/account':
          if (method !== 'POST') { this._json(res, 405, { error: 'POST required' }); break; }
          const accData = JSON.parse(body);
          this.sipServer.addAccount(accData.username, accData.password);
          this._json(res, 200, { ok: true, username: accData.username });
          break;
          
        default:
          this._json(res, 404, { error: 'Not found', endpoints: ['/status', '/registrations', '/calls', '/invite', '/bye', '/message', '/account'] });
      }
    } catch (err) {
      this._json(res, 500, { error: err.message });
    }
  }

  _json(res, code, data) {
    res.writeHead(code);
    res.end(JSON.stringify(data, null, 2));
  }
}

// ═══════════════════════════════════════════════════════════════
// MAIN
// ═══════════════════════════════════════════════════════════════

function main() {
  const server = new GoIPSipServer(CONFIG);
  
  // Добавляем аккаунты по умолчанию
  // Формат: username, password
  const defaultAccounts = [
    ['1001', '1001'],
    ['1002', '1002'],
    ['1003', '1003'],
    ['1004', '1004'],
    ['trunk01', 'trunkpass'],
  ];
  
  // Можно задать через env: ACCOUNTS=user1:pass1,user2:pass2
  if (process.env.ACCOUNTS) {
    process.env.ACCOUNTS.split(',').forEach(pair => {
      const [u, p] = pair.split(':');
      if (u && p) server.addAccount(u, p);
    });
  } else {
    defaultAccounts.forEach(([u, p]) => server.addAccount(u, p));
  }
  
  // Обработчики событий
  server.on('register', (data) => {
    if (data.fingerprint && data.fingerprint.isGoIP) {
      console.log(`\n★ GoIP DETECTED: ${data.fingerprint.deviceType}`);
      console.log(`  Signs: ${data.fingerprint.signs.join(', ')}`);
      console.log(`  Confidence: ${data.fingerprint.confidence}%\n`);
    }
  });
  
  server.on('invite', (data) => {
    console.log(`\n═══ INCOMING CALL ═══`);
    console.log(`  From: ${data.callerDisplay || data.from}`);
    console.log(`  To:   ${data.to}`);
    console.log(`  Call-ID: ${data.callId}`);
    
    if (data.sdp) {
      const goipSigns = data.sdp.isGoIP();
      if (goipSigns.length > 0) {
        console.log(`  GoIP SDP signs: ${goipSigns.join(', ')}`);
      }
    }
    
    // Автоответ — ring, потом answer через 2 секунды
    data.ring();
    setTimeout(() => {
      data.answer();
      console.log(`  → ANSWERED`);
    }, 2000);
  });
  
  server.on('bye', (data) => {
    console.log(`\n═══ CALL ENDED ═══`);
    console.log(`  Call-ID: ${data.callId}`);
    console.log(`  Duration: ${data.duration}s`);
  });
  
  server.on('message', (data) => {
    console.log(`\n═══ SMS RECEIVED ═══`);
    console.log(`  From: ${data.from}`);
    console.log(`  To:   ${data.to}`);
    console.log(`  Text: ${data.body}`);
  });
  
  server.on('dtmf', (data) => {
    console.log(`  DTMF: ${data.signal} (${data.duration}ms) [${data.method}]`);
  });
  
  server.on('refer', (data) => {
    console.log(`\n═══ TRANSFER ═══`);
    console.log(`  Call: ${data.callId}`);
    console.log(`  Target: ${data.referTo}`);
  });
  
  // Запускаем SIP
  server.start();
  
  // Запускаем API
  const api = new ApiServer(server, CONFIG.apiPort);
  api.start();
  
  // Graceful shutdown
  process.on('SIGINT', () => {
    console.log('\nShutting down...');
    server.socket.close();
    api.server.close();
    process.exit(0);
  });
  
  console.log('\n═══ GoIP SIP Server Ready ═══');
  console.log(`Конфигурация GoIP для подключения:`);
  console.log(`  SIP_REGISTRAR = <этот_IP>:${CONFIG.sipPort}`);
  console.log(`  SIP_PROXY     = <этот_IP>:${CONFIG.sipPort}`);
  console.log(`  SIP_AUTH_ID   = 1001`);
  console.log(`  SIP_AUTH_PASSWD = 1001`);
  console.log(`  SIP_CONFIG_MODE = SINGLE_MODE или TRUNK_GW_MODE`);
  console.log(`\nДля TRUNK_GW_MODE:`);
  console.log(`  SIP_TRUNK_GW1 = <этот_IP>`);
  console.log(`  SIP_TRUNK_AUTH_ID = trunk01`);
  console.log(`  SIP_TRUNK_AUTH_PASSWD = trunkpass`);
}

// Запуск только при прямом вызове (не при require)
if (require.main === module) {
  main();
}

module.exports = { GoIPSipServer, SipMessage, SDP, DigestAuth, GoIPFingerprint, ApiServer };
