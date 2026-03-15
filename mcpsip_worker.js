/**
 * GoIP MCP SIP Worker — Cloudflare Worker
 * 
 * MCP-сервер на Cloudflare Workers с полным GoIP функционалом:
 *   - SIP парсинг и fingerprinting
 *   - 8 проприетарных шифрований (RC4, FAST, XOR, VOS, AVS, N2C, ECM, ET263)
 *   - RTP анализ и расшифровка
 *   - GoIP protocol reference
 *   - Event log (Durable Object)
 * 
 * Endpoints:
 *   POST /mcp       — MCP JSON-RPC 2.0
 *   GET  /sse       — SSE stream
 *   GET  /health    — health check
 *   GET  /          — info
 * 
 * Deploy: cd C:\goip && npx wrangler deploy
 */

// ═══════════════════════════════════════════════════════════════
// CRYPTO MODULE (all 8 GoIP encryption methods)
// ═══════════════════════════════════════════════════════════════

const RC4_EXTRA_SWAPS = [
  [1, 5], [4, 56], [10, 47], [15, 185], [23, 74], [28, 129], [33, 42],
  [44, 66], [55, 73], [77, 99], [88, 124], [111, 250], [200, 220]
];

class GoIPRC4 {
  constructor(key) {
    this.S = new Uint8Array(256);
    this.i = 0;
    this.j = 0;
    const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    for (let i = 0; i < 256; i++) this.S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.S[i] + keyBytes[i % keyBytes.length]) & 0xFF;
      [this.S[i], this.S[j]] = [this.S[j], this.S[i]];
    }
    for (const [a, b] of RC4_EXTRA_SWAPS) {
      [this.S[a], this.S[b]] = [this.S[b], this.S[a]];
    }
  }
  process(data) {
    const S = this.S;
    let { i, j } = this;
    const output = new Uint8Array(data.length);
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 0xFF;
      j = (j + S[i]) & 0xFF;
      [S[i], S[j]] = [S[j], S[i]];
      output[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF];
    }
    this.i = i;
    this.j = j;
    return output;
  }
}

class GoIPXOR {
  constructor(key) { this.keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key; }
  process(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) output[i] = data[i] ^ this.keyBytes[i % this.keyBytes.length];
    return output;
  }
}

class GoIPFAST {
  constructor(key) {
    const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    this.pattern = new Uint8Array(256);
    let seed = 0;
    for (let i = 0; i < keyBytes.length; i++) seed = (seed * 31 + keyBytes[i]) & 0xFFFF;
    for (let i = 0; i < 256; i++) { seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF; this.pattern[i] = (seed >> 16) & 0xFF; }
  }
  process(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) output[i] = data[i] ^ this.pattern[i & 0xFF];
    return output;
  }
}

class GoIPVOS {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    this.permTable = new Uint8Array(256);
    for (let i = 0; i < 256; i++) this.permTable[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.permTable[i] + this.keyBytes[i % this.keyBytes.length] + 7) & 0xFF;
      [this.permTable[i], this.permTable[j]] = [this.permTable[j], this.permTable[i]];
    }
  }
  process(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) output[i] = this.permTable[data[i]] ^ this.keyBytes[i % this.keyBytes.length];
    return output;
  }
}

class GoIPAVS {
  constructor(key) { this.keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key; }
  process(data) {
    const output = new Uint8Array(data.length);
    const kl = this.keyBytes.length;
    for (let i = 0; i < data.length; i++) {
      let b = data[i] ^ this.keyBytes[i % kl] ^ this.keyBytes[(i + Math.floor(kl / 2)) % kl];
      output[i] = ((b << 3) | (b >> 5)) & 0xFF;
    }
    return output;
  }
}

class GoIPN2C {
  constructor(key) { this.keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key; }
  process(data) {
    const output = new Uint8Array(data.length);
    let carry = 0;
    for (let i = 0; i < data.length; i++) {
      const kb = this.keyBytes[i % this.keyBytes.length];
      output[i] = (data[i] ^ kb ^ carry) & 0xFF;
      carry = (carry + kb + data[i]) & 0xFF;
    }
    return output;
  }
}

class GoIPECM {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    this.sbox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) this.sbox[i] = i;
    let j = 0;
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 256; i++) {
        j = (j + this.sbox[i] + this.keyBytes[i % this.keyBytes.length] + round * 17) & 0xFF;
        [this.sbox[i], this.sbox[j]] = [this.sbox[j], this.sbox[i]];
      }
    }
  }
  process(data) {
    const output = new Uint8Array(data.length);
    for (let i = 0; i < data.length; i++) output[i] = this.sbox[data[i] ^ this.keyBytes[i % this.keyBytes.length]];
    return output;
  }
}

class GoIPET263 {
  constructor(key) {
    const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
    this.S = new Uint8Array(256);
    for (let i = 0; i < 256; i++) this.S[i] = i;
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.S[i] + keyBytes[i % keyBytes.length]) & 0xFF;
      [this.S[i], this.S[j]] = [this.S[j], this.S[i]];
    }
    for (const [a, b] of [[0,128],[32,192],[64,224],[96,160],[48,176],[80,208],[112,240],[16,144]]) {
      [this.S[a], this.S[b]] = [this.S[b], this.S[a]];
    }
  }
  process(data) {
    const S = this.S;
    const output = new Uint8Array(data.length);
    let i = 0, j = 0;
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 0xFF; j = (j + S[i]) & 0xFF;
      [S[i], S[j]] = [S[j], S[i]];
      output[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF];
    }
    return output;
  }
}

function createCipher(method, key) {
  switch (method.toUpperCase()) {
    case 'RC4':   return new GoIPRC4(key);
    case 'FAST':  return new GoIPFAST(key);
    case 'XOR':   return new GoIPXOR(key);
    case 'VOS':   return new GoIPVOS(key);
    case 'AVS':   return new GoIPAVS(key);
    case 'N2C':   return new GoIPN2C(key);
    case 'ECM':   return new GoIPECM(key);
    case 'ET263': return new GoIPET263(key);
    default:      return null;
  }
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function generateKey(length = 16) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

// ═══════════════════════════════════════════════════════════════
// SIP PARSER
// ═══════════════════════════════════════════════════════════════

function parseSipMessage(text) {
  const msg = {
    isRequest: false, isResponse: false, method: '', requestUri: '', statusCode: 0, reasonPhrase: '',
    headers: {}, via: [], from: null, to: null, contact: null, callId: '', cseq: { num: 0, method: '' },
    contentType: '', contentLength: 0, userAgent: '', maxForwards: 70, expires: null, xACrypt: null, body: '',
  };

  const split = text.indexOf('\r\n\r\n');
  const headerPart = split >= 0 ? text.substring(0, split) : text;
  msg.body = split >= 0 ? text.substring(split + 4) : '';

  const lines = headerPart.split('\r\n');
  if (!lines.length) return null;

  const first = lines[0];
  if (first.startsWith('SIP/')) {
    msg.isResponse = true;
    const m = first.match(/^(SIP\/2\.0)\s+(\d{3})\s+(.*)$/);
    if (!m) return null;
    msg.statusCode = parseInt(m[2]); msg.reasonPhrase = m[3];
  } else {
    msg.isRequest = true;
    const m = first.match(/^(\w+)\s+(.+)\s+(SIP\/2\.0)$/);
    if (!m) return null;
    msg.method = m[1].toUpperCase(); msg.requestUri = m[2];
  }

  for (let i = 1; i < lines.length; i++) {
    let line = lines[i];
    while (i + 1 < lines.length && (lines[i + 1].startsWith(' ') || lines[i + 1].startsWith('\t'))) {
      line += ' ' + lines[++i].trim();
    }
    const ci = line.indexOf(':');
    if (ci < 0) continue;
    const name = line.substring(0, ci).trim();
    const value = line.substring(ci + 1).trim();
    const nl = name.toLowerCase();
    if (!msg.headers[nl]) msg.headers[nl] = [];
    msg.headers[nl].push({ name, value });

    switch (nl) {
      case 'via': msg.via.push(parseVia(value)); break;
      case 'from': case 'f': msg.from = parseNameAddr(value); break;
      case 'to': case 't': msg.to = parseNameAddr(value); break;
      case 'contact': case 'm': msg.contact = parseNameAddr(value); break;
      case 'call-id': case 'i': msg.callId = value; break;
      case 'cseq': { const cm = value.match(/^(\d+)\s+(\w+)$/); if (cm) msg.cseq = { num: parseInt(cm[1]), method: cm[2].toUpperCase() }; break; }
      case 'content-type': case 'c': msg.contentType = value; break;
      case 'content-length': case 'l': msg.contentLength = parseInt(value); break;
      case 'user-agent': msg.userAgent = value; break;
      case 'max-forwards': msg.maxForwards = parseInt(value); break;
      case 'expires': msg.expires = parseInt(value); break;
      case 'x-acrypt': msg.xACrypt = value; break;
    }
  }
  return msg;
}

function parseVia(value) {
  const via = { raw: value, protocol: '', host: '', port: 5060, branch: '', rport: null, received: null };
  const m = value.match(/^(SIP\/2\.0\/\w+)\s+([^;:]+)(?::(\d+))?(.*)$/);
  if (m) {
    via.protocol = m[1]; via.host = m[2].trim(); via.port = m[3] ? parseInt(m[3]) : 5060;
    const p = m[4] || '';
    const bm = p.match(/branch=([^;,\s]+)/); if (bm) via.branch = bm[1];
    if (p.includes('rport=')) { const rm = p.match(/rport=(\d+)/); if (rm) via.rport = parseInt(rm[1]); }
    else if (p.includes('rport')) via.rport = 0;
    const rcm = p.match(/received=([^;,\s]+)/); if (rcm) via.received = rcm[1];
  }
  return via;
}

function parseNameAddr(value) {
  const r = { raw: value, displayName: '', uri: '', user: '', host: '', port: 5060, tag: '' };
  const dnm = value.match(/^"([^"]*)"?\s*<(.+)>/);
  const nnm = value.match(/^<(.+)>/);
  const pm = value.match(/^([^<]+)\s*<(.+)>/);
  let uriPart = value;
  if (dnm) { r.displayName = dnm[1]; uriPart = dnm[2]; }
  else if (pm) { r.displayName = pm[1].trim(); uriPart = pm[2]; }
  else if (nnm) { uriPart = nnm[1]; }
  const ac = value.indexOf('>');
  if (ac >= 0) { const tm = value.substring(ac + 1).match(/tag=([^;,\s]+)/); if (tm) r.tag = tm[1]; }
  const sm = uriPart.match(/sip:([^@]+)@([^:;>\s]+)(?::(\d+))?/);
  if (sm) { r.user = sm[1]; r.host = sm[2]; if (sm[3]) r.port = parseInt(sm[3]); }
  r.uri = uriPart.split(';')[0].split('>')[0];
  return r;
}

// SDP parser
function parseSDP(text) {
  const sdp = { version: 0, origin: {}, sessionName: '', connection: {}, media: [] };
  let curMedia = null;
  for (const line of text.split(/\r?\n/)) {
    const m = line.match(/^([a-z])=(.*)/);
    if (!m) continue;
    const [, type, val] = m;
    switch (type) {
      case 'v': sdp.version = parseInt(val); break;
      case 'o': { const p = val.split(/\s+/); sdp.origin = { username: p[0], sessionId: p[1], sessionVersion: p[2], netType: p[3], addrType: p[4], address: p[5] }; break; }
      case 's': sdp.sessionName = val; break;
      case 'c': { const p = val.split(/\s+/); (curMedia || sdp).connection = { netType: p[0], addrType: p[1], address: p[2] }; break; }
      case 'm': { const p = val.split(/\s+/); curMedia = { type: p[0], port: parseInt(p[1]), protocol: p[2], payloads: p.slice(3).map(Number), attributes: [], direction: 'sendrecv' }; sdp.media.push(curMedia); break; }
      case 'a': if (curMedia) { curMedia.attributes.push(val); if (['sendrecv','sendonly','recvonly','inactive'].includes(val)) curMedia.direction = val; } break;
    }
  }
  return sdp;
}

function sdpGoIPSigns(sdp) {
  const signs = [];
  if (sdp.origin?.username === 'userX') signs.push('origin_userX');
  if (sdp.origin?.sessionId === '20000001') signs.push('sessionId_20000001');
  if (sdp.sessionName === 'DBL Session') signs.push('session_DBL');
  return signs;
}

// GoIP fingerprint
function analyzeFingerprint(msg) {
  const r = { isGoIP: false, confidence: 0, signs: [], deviceType: 'unknown', vendor: 'unknown' };
  const ua = (msg.userAgent || '').toLowerCase();
  if (ua === 'dble') { r.signs.push('UA:dble'); r.confidence += 40; r.vendor = 'DBLTek'; }
  else if (ua === 'hybertone') { r.signs.push('UA:HYBERTONE'); r.confidence += 40; r.vendor = 'HYBERTONE'; }
  else if (ua === 'pak') { r.signs.push('UA:pak'); r.confidence += 30; r.vendor = 'DBLTek-PAK'; }
  if (msg.xACrypt) { r.signs.push(`X-ACrypt:${msg.xACrypt}`); r.confidence += 30; }
  if (msg.body && msg.contentType === 'application/sdp') {
    const sdp = parseSDP(msg.body);
    const ss = sdpGoIPSigns(sdp);
    r.signs.push(...ss); r.confidence += ss.length * 15;
  }
  if (msg.via.length > 0 && msg.via[0].branch && /^z9hG4bK\d{6,10}$/.test(msg.via[0].branch)) {
    r.signs.push('via_branch:oSIP_uint32'); r.confidence += 10;
  }
  const clh = msg.headers['content-length'];
  if (clh?.[0] && /^\s{3,}\d+$/.test(clh[0].value)) { r.signs.push('content-length:padded'); r.confidence += 10; }
  r.isGoIP = r.confidence >= 40;
  if (r.isGoIP) {
    r.deviceType = (r.signs.includes('UA:HYBERTONE') || r.signs.some(s => s.includes('ET263'))) ? 'HYBERTONE GST1610' : 'DBLTek GoIP';
  }
  return r;
}

// RTP parser
function parseRTP(hex) {
  const buf = hexToBytes(hex);
  if (buf.length < 12) return null;
  const csrcCount = buf[0] & 0x0F;
  const headerLength = 12 + csrcCount * 4;
  return {
    version: (buf[0] >> 6) & 3, padding: (buf[0] >> 5) & 1, extension: (buf[0] >> 4) & 1, csrcCount,
    marker: (buf[1] >> 7) & 1, payloadType: buf[1] & 0x7F,
    sequenceNumber: (buf[2] << 8) | buf[3], timestamp: (buf[4] << 24) | (buf[5] << 16) | (buf[6] << 8) | buf[7],
    ssrc: ((buf[8] << 24) | (buf[9] << 16) | (buf[10] << 8) | buf[11]) >>> 0,
    headerLength, payloadHex: bytesToHex(buf.slice(headerLength)).substring(0, 200),
    payloadLength: buf.length - headerLength,
  };
}

function parseDTMFEvent(payloadHex) {
  const p = hexToBytes(payloadHex);
  if (p.length < 4) return null;
  const chars = '0123456789*#ABCD';
  return { event: p[0], char: p[0] < chars.length ? chars[p[0]] : '?', end: !!((p[1] >> 7) & 1), volume: p[1] & 0x3F, duration: (p[2] << 8) | p[3] };
}

// ═══════════════════════════════════════════════════════════════
// PROTOCOL REFERENCE
// ═══════════════════════════════════════════════════════════════

const PROTOCOL_REFERENCE = {
  modes: {
    title: 'Режимы работы GoIP',
    modes: {
      SINGLE_MODE: { description: 'Один аккаунт для всех каналов', params: 'SIP_REGISTRAR, SIP_PROXY, SIP_AUTH_ID, SIP_AUTH_PASSWD, SIP_PHONE_NUMBER' },
      LINE_MODE: { description: 'Per-channel аккаунты (до 4 sub-accounts)', params: 'SIP_CONTACT[1-4]_PROXY, SIP_CONTACT[1-4]_AUTHID' },
      TRUNK_GW_MODE: { description: 'Прямой trunk, до 3 gateways', params: 'SIP_TRUNK_GW[1-3], SIP_TRUNK_AUTH_ID' },
      GROUP_MODE: { description: 'Каналы в группы, per-group регистрация', params: 'Группы в конфигурации устройства' },
    },
  },
  timers: {
    title: 'Таймеры GoIP',
    timers: {
      REGISTRATION_PERIOD: { default: '120s', param: 'SIP_REGIST_PERIOD' },
      KEEPALIVE_INTERVAL: { default: '30s', param: 'SIP_KPALIVE_PERIOD' },
      UNANSWER_TIMEOUT: { default: '180s', param: 'SIP_UNANSWER_EXP' },
      SESSION_TIMER: { default: '1800s', param: 'SIP_SESSION_EXP' },
    },
  },
  fingerprints: {
    title: 'Признаки GoIP устройства',
    signs: [
      { sign: 'User-Agent: dble', confidence: 40, vendor: 'DBLTek' },
      { sign: 'User-Agent: HYBERTONE', confidence: 40, vendor: 'HYBERTONE' },
      { sign: 'SDP s=DBL Session', confidence: 15 },
      { sign: 'SDP o=userX 20000001', confidence: 15 },
      { sign: 'Via branch z9hG4bK + digits', confidence: 10 },
      { sign: 'Content-Length with padding', confidence: 10 },
      { sign: 'X-ACrypt header', confidence: 30 },
    ],
  },
  cli_params: {
    title: 'Параметры sipcli',
    binary: '/usr/bin/sipcli (658,064 bytes, ARM OABI, uClibc)',
    key_params: [
      '-g mode (0=SINGLE, 1=LINE, 2=TRUNK_GW, 3=GROUP)',
      '-o addr — прокси', '-p port — SIP порт', '-u authid', '-a passwd',
      '-e phone_number', '-r registrar', '-R regist_period', '-K kpalive_period',
      '-E encryption (0=off, 1=RC4, 2=FAST...)', '-y key', '-z nat_mode', '-I dtmf_mode',
      '-f codec (0=PCMU, 1=GSM, 2=PCMA, 3=G729, 4=G723)',
    ],
  },
  processes: { title: 'Системные процессы GoIP', processes: { sipcli: 'SIP UA (5060)', mg: 'Media Gateway', fvdsp: 'DSP/RTP', smb_module: 'SIM Bank (UDP 56011)', ioctl_tool: 'GPIO' } },
  encryption: {
    title: '8 методов шифрования GoIP',
    methods: [
      { id: 1, name: 'RC4', description: 'Модифицированный RC4, 13 доп. S-box swap' },
      { id: 2, name: 'FAST', description: 'XOR с PRNG 256-байт паттерном' },
      { id: 3, name: 'XOR', description: 'Циклический XOR' },
      { id: 4, name: 'VOS', description: 'S-box перестановка + XOR' },
      { id: 5, name: 'AVS', description: 'Двухраундовый XOR + ROL3' },
      { id: 6, name: 'N2C', description: 'XOR с carry' },
      { id: 7, name: 'ECM', description: 'Трёхраундовый S-box + XOR' },
      { id: 8, name: 'ET263', description: 'HYBERTONE RC4-like, 8 swap' },
    ],
    header: 'X-ACrypt: <method>:<key>',
    rc4_extra_swaps: RC4_EXTRA_SWAPS,
  },
  sip_flow: {
    title: 'SIP-потоки GoIP',
    registration: ['GoIP→REGISTER', '←401 Unauthorized', 'GoIP→REGISTER+Auth', '←200 OK'],
    outgoing_call: ['GoIP→INVITE+SDP', '←100 Trying', '←180 Ringing', '←200 OK+SDP', 'GoIP→ACK', '…RTP…', 'BYE'],
    incoming_call: ['→INVITE+SDP', 'GoIP←100 Trying', 'GoIP←180 Ringing', 'GoIP←200 OK+SDP', '→ACK', '…RTP…', 'BYE'],
    sms_out: ['→MESSAGE text/plain', 'GoIP←200 OK'],
    sms_in: ['GoIP→MESSAGE', '←200 OK'],
  },
  sdp: {
    title: 'SDP GoIP',
    template: ['v=0', 'o=userX 20000001 20000001 IN IP4 <ip>', 's=DBL Session', 'c=IN IP4 <ip>', 't=0 0', 'm=audio <port> RTP/AVP 8 0 101'],
    codecs: [{ pt: 0, name: 'PCMU' }, { pt: 8, name: 'PCMA' }, { pt: 4, name: 'G723' }, { pt: 18, name: 'G729' }, { pt: 101, name: 'telephone-event' }],
  },
  dtmf: { title: 'DTMF GoIP', modes: { RFC2833: { id: 0, sdp: 'a=rtpmap:101 telephone-event/8000' }, SIP_INFO: { id: 1, contentType: 'application/dtmf-relay' }, INBAND: { id: 2 } } },
  nat: { title: 'NAT traversal', modes: { OFF: { id: 0 }, STUN: { id: 1, param: 'SIP_STUN_SERVER' }, RPORT: { id: 2 } } },
};

// ═══════════════════════════════════════════════════════════════
// MCP TOOLS DEFINITIONS
// ═══════════════════════════════════════════════════════════════

const TOOLS = [
  { name: 'goip_parse_sip', description: 'Парсинг SIP-сообщения: заголовки, SDP, GoIP fingerprint, X-ACrypt', inputSchema: { type: 'object', properties: { raw_message: { type: 'string', description: 'Сырой текст SIP' } }, required: ['raw_message'] } },
  { name: 'goip_fingerprint', description: 'Определить GoIP устройство по SIP-сообщению', inputSchema: { type: 'object', properties: { raw_message: { type: 'string', description: 'SIP-сообщение' } }, required: ['raw_message'] } },
  { name: 'goip_build_sip', description: 'Сгенерировать SIP в формате GoIP (User-Agent dble, SDP DBL Session)', inputSchema: { type: 'object', properties: { method: { type: 'string', description: 'REGISTER, INVITE, BYE, MESSAGE, OPTIONS' }, from_user: { type: 'string' }, to_user: { type: 'string' }, server_ip: { type: 'string' }, server_port: { type: 'number' }, local_ip: { type: 'string' }, body: { type: 'string' }, include_sdp: { type: 'boolean' } }, required: ['method', 'from_user', 'server_ip'] } },
  { name: 'goip_encrypt', description: 'Зашифровать данные одним из 8 методов GoIP', inputSchema: { type: 'object', properties: { method: { type: 'string', enum: ['RC4','FAST','XOR','VOS','AVS','N2C','ECM','ET263'] }, key: { type: 'string' }, data_hex: { type: 'string' } }, required: ['method', 'key', 'data_hex'] } },
  { name: 'goip_decrypt', description: 'Расшифровать данные (симметричные шифры)', inputSchema: { type: 'object', properties: { method: { type: 'string', enum: ['RC4','FAST','XOR','VOS','AVS','N2C','ECM','ET263'] }, key: { type: 'string' }, data_hex: { type: 'string' } }, required: ['method', 'key', 'data_hex'] } },
  { name: 'goip_parse_xacrypt', description: 'Разобрать X-ACrypt заголовок', inputSchema: { type: 'object', properties: { header_value: { type: 'string', description: 'Например RC4:a1b2c3d4' } }, required: ['header_value'] } },
  { name: 'goip_generate_key', description: 'Сгенерировать ключ для X-ACrypt', inputSchema: { type: 'object', properties: { method: { type: 'string' }, length: { type: 'number' } } } },
  { name: 'goip_parse_rtp', description: 'Разобрать RTP-пакет (hex)', inputSchema: { type: 'object', properties: { packet_hex: { type: 'string' } }, required: ['packet_hex'] } },
  { name: 'goip_decrypt_rtp', description: 'Расшифровать RTP payload', inputSchema: { type: 'object', properties: { packet_hex: { type: 'string' }, method: { type: 'string', enum: ['RC4','FAST','XOR','VOS','AVS','N2C','ECM','ET263'] }, key: { type: 'string' } }, required: ['packet_hex', 'method', 'key'] } },
  { name: 'goip_protocol_info', description: 'Справка по протоколу GoIP', inputSchema: { type: 'object', properties: { topic: { type: 'string', description: 'modes, timers, fingerprints, cli_params, processes, encryption, sip_flow, sdp, dtmf, nat' } }, required: ['topic'] } },
  { name: 'goip_events', description: 'Лог событий', inputSchema: { type: 'object', properties: { limit: { type: 'number' }, type: { type: 'string' } } } },
];

// ═══════════════════════════════════════════════════════════════
// TOOL HANDLERS
// ═══════════════════════════════════════════════════════════════

function handleTool(name, args, state) {
  switch (name) {
    case 'goip_parse_sip': {
      const msg = parseSipMessage(args.raw_message);
      if (!msg) return { error: 'Failed to parse' };
      const result = {
        type: msg.isRequest ? 'request' : 'response', method: msg.method || undefined,
        statusCode: msg.statusCode || undefined, requestUri: msg.requestUri || undefined,
        callId: msg.callId, cseq: msg.cseq, from: msg.from, to: msg.to, contact: msg.contact,
        via: msg.via, userAgent: msg.userAgent, contentType: msg.contentType, expires: msg.expires, xACrypt: msg.xACrypt,
      };
      if (msg.body && msg.contentType === 'application/sdp') {
        const sdp = parseSDP(msg.body);
        result.sdp = { origin: sdp.origin, sessionName: sdp.sessionName, connection: sdp.connection, media: sdp.media, goipSigns: sdpGoIPSigns(sdp) };
      }
      result.fingerprint = analyzeFingerprint(msg);
      return result;
    }
    case 'goip_fingerprint': {
      const msg = parseSipMessage(args.raw_message);
      if (!msg) return { error: 'Failed to parse' };
      const fp = analyzeFingerprint(msg);
      let sdpSigns = [];
      if (msg.body && msg.contentType === 'application/sdp') sdpSigns = sdpGoIPSigns(parseSDP(msg.body));
      return { ...fp, sdpSigns, userAgent: msg.userAgent, xACrypt: msg.xACrypt };
    }
    case 'goip_build_sip': {
      const method = (args.method || 'REGISTER').toUpperCase();
      const sip = args.server_ip;
      const sp = args.server_port || 5060;
      const lip = args.local_ip || '192.168.1.100';
      const fu = args.from_user;
      const tu = args.to_user || fu;
      const branch = `z9hG4bK${Math.floor(Math.random() * 999999999)}`;
      const tag = bytesToHex(crypto.getRandomValues(new Uint8Array(6)));
      const callId = `${Date.now()}@${lip}`;
      const lines = [
        `${method} sip:${tu}@${sip}:${sp} SIP/2.0`,
        `Via: SIP/2.0/UDP ${lip}:5060;rport;branch=${branch}`,
        `From: <sip:${fu}@${sip}>;tag=${tag}`, `To: <sip:${tu}@${sip}>`,
        `Call-ID: ${callId}`, `CSeq: 1 ${method}`,
        `Contact: <sip:${fu}@${lip}:5060>`, `Max-Forwards: 70`, `User-Agent: dble`,
      ];
      if (method === 'REGISTER') lines.push('Expires: 120');
      if (method === 'MESSAGE' && args.body) {
        lines.push(`Content-Type: text/plain`, `Content-Length: ${args.body.length}`, '', args.body);
      } else if (method === 'INVITE' && args.include_sdp !== false) {
        const sdp = ['v=0', `o=userX 20000001 20000001 IN IP4 ${lip}`, 's=DBL Session', `c=IN IP4 ${lip}`, 't=0 0',
          'm=audio 21000 RTP/AVP 8 0 101', 'a=rtpmap:8 PCMA/8000', 'a=rtpmap:0 PCMU/8000',
          'a=rtpmap:101 telephone-event/8000', 'a=fmtp:101 0-15', 'a=ptime:20', 'a=sendrecv', ''].join('\r\n');
        lines.push(`Content-Type: application/sdp`, `Content-Length: ${sdp.length}`, '', sdp);
      } else {
        lines.push('Content-Length:     0', '', '');
      }
      return lines.join('\r\n');
    }
    case 'goip_encrypt':
    case 'goip_decrypt': {
      const cipher = createCipher(args.method, args.key);
      if (!cipher) return { error: `Unknown method: ${args.method}` };
      const data = hexToBytes(args.data_hex);
      const out = cipher.process(data);
      return { method: args.method, key: args.key, input_hex: args.data_hex, output_hex: bytesToHex(out), xACryptHeader: `${args.method}:${args.key}` };
    }
    case 'goip_parse_xacrypt': {
      const ci = args.header_value.indexOf(':');
      if (ci < 0) return { method: args.header_value.trim().toUpperCase(), key: '', isSupported: false };
      const method = args.header_value.substring(0, ci).trim().toUpperCase();
      const key = args.header_value.substring(ci + 1).trim();
      return { method, key, supportedMethods: ['RC4','FAST','XOR','VOS','AVS','N2C','ECM','ET263'], isSupported: ['RC4','FAST','XOR','VOS','AVS','N2C','ECM','ET263'].includes(method) };
    }
    case 'goip_generate_key': {
      const len = args.length || 16;
      const key = generateKey(len);
      return { method: args.method, key, xACryptHeader: `${args.method || 'RC4'}:${key}`, keyLengthBytes: len };
    }
    case 'goip_parse_rtp': {
      const parsed = parseRTP(args.packet_hex);
      if (!parsed) return { error: 'Failed to parse RTP' };
      if (parsed.payloadType === 101) {
        const dtmf = parseDTMFEvent(parsed.payloadHex);
        if (dtmf) parsed.dtmf = dtmf;
      }
      parsed.ssrc = `0x${parsed.ssrc.toString(16)}`;
      return parsed;
    }
    case 'goip_decrypt_rtp': {
      const buf = hexToBytes(args.packet_hex);
      if (buf.length < 12) return { error: 'Too short' };
      const csrc = buf[0] & 0x0F;
      const hdrLen = 12 + csrc * 4;
      const cipher = createCipher(args.method, args.key);
      if (!cipher) return { error: `Unknown method: ${args.method}` };
      const payload = buf.slice(hdrLen);
      const dec = cipher.process(payload);
      const result = new Uint8Array(buf.length);
      result.set(buf.slice(0, hdrLen));
      result.set(dec, hdrLen);
      return { method: args.method, decrypted_hex: bytesToHex(result).substring(0, 200), decryptedPayloadHex: bytesToHex(dec).substring(0, 200), payloadType: buf[1] & 0x7F };
    }
    case 'goip_protocol_info': {
      const topic = (args.topic || '').toLowerCase();
      return PROTOCOL_REFERENCE[topic] || { error: `Unknown topic`, available: Object.keys(PROTOCOL_REFERENCE) };
    }
    case 'goip_events': {
      const limit = args.limit || 50;
      let events = state.events || [];
      if (args.type) events = events.filter(e => e.type === args.type);
      return events.slice(-limit);
    }
    default:
      return { error: `Unknown tool: ${name}` };
  }
}

// ═══════════════════════════════════════════════════════════════
// MCP PROTOCOL
// ═══════════════════════════════════════════════════════════════

const PROTOCOL_VERSION = '2024-11-05';
const SERVER_INFO = { name: 'goip-gateway', version: '1.0.0' };

function handleMcpRequest(msg, state) {
  switch (msg.method) {
    case 'initialize':
      return { jsonrpc: '2.0', id: msg.id, result: { protocolVersion: PROTOCOL_VERSION, capabilities: { tools: {}, resources: {} }, serverInfo: SERVER_INFO } };
    case 'initialized':
      return null; // notification, no response
    case 'tools/list':
      return { jsonrpc: '2.0', id: msg.id, result: { tools: TOOLS } };
    case 'tools/call': {
      const { name, arguments: args } = msg.params;
      try {
        const result = handleTool(name, args || {}, state);
        return { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: typeof result === 'string' ? result : JSON.stringify(result, null, 2) }] } };
      } catch (e) {
        return { jsonrpc: '2.0', id: msg.id, result: { content: [{ type: 'text', text: `Error: ${e.message}` }], isError: true } };
      }
    }
    case 'resources/list':
      return { jsonrpc: '2.0', id: msg.id, result: { resources: [
        { uri: 'goip://protocol/encryption', name: 'GoIP Encryption Reference', description: '8 методов шифрования DBLTek/HYBERTONE', mimeType: 'text/markdown' },
        { uri: 'goip://server/events', name: 'GoIP Event Log', description: 'Лог событий', mimeType: 'application/json' },
      ] } };
    case 'resources/read': {
      const { uri } = msg.params;
      if (uri === 'goip://protocol/encryption') {
        return { jsonrpc: '2.0', id: msg.id, result: { contents: [{ uri, mimeType: 'text/markdown', text: JSON.stringify(PROTOCOL_REFERENCE.encryption, null, 2) }] } };
      }
      if (uri === 'goip://server/events') {
        return { jsonrpc: '2.0', id: msg.id, result: { contents: [{ uri, mimeType: 'application/json', text: JSON.stringify(state.events || [], null, 2) }] } };
      }
      return { jsonrpc: '2.0', id: msg.id, error: { code: -32602, message: `Unknown resource: ${uri}` } };
    }
    case 'ping':
      return { jsonrpc: '2.0', id: msg.id, result: {} };
    default:
      if (msg.id !== undefined) {
        return { jsonrpc: '2.0', id: msg.id, error: { code: -32601, message: `Method not found: ${msg.method}` } };
      }
      return null;
  }
}

// ═══════════════════════════════════════════════════════════════
// DURABLE OBJECT — persistent state
// ═══════════════════════════════════════════════════════════════

export class McpState {
  constructor(state, env) {
    this.state = state;
    this.events = [];
    this.sseClients = new Set();

    state.blockConcurrencyWhile(async () => {
      this.events = (await state.storage.get('events')) || [];
    });
  }

  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === 'POST' && (url.pathname === '/mcp' || url.pathname === '/')) {
      const body = await request.json();
      const result = handleMcpRequest(body, { events: this.events });
      if (result) {
        return new Response(JSON.stringify(result), { headers: { 'Content-Type': 'application/json' } });
      }
      return new Response(JSON.stringify({ status: 'accepted' }), { status: 202 });
    }

    if (request.method === 'GET' && url.pathname === '/sse') {
      const { readable, writable } = new TransformStream();
      const writer = writable.getWriter();
      const enc = new TextEncoder();
      writer.write(enc.encode(`data: ${JSON.stringify({ type: 'connected', time: new Date().toISOString() })}\n\n`));
      this.sseClients.add(writer);
      request.signal.addEventListener('abort', () => {
        this.sseClients.delete(writer);
        writer.close().catch(() => {});
      });
      return new Response(readable, { headers: { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' } });
    }

    return new Response('Not found', { status: 404 });
  }

  async pushEvent(type, data) {
    this.events.push({ type, time: new Date().toISOString(), data });
    if (this.events.length > 500) this.events = this.events.slice(-500);
    await this.state.storage.put('events', this.events);
    const msg = JSON.stringify({ type, time: new Date().toISOString(), data });
    const enc = new TextEncoder();
    for (const writer of this.sseClients) {
      writer.write(enc.encode(`data: ${msg}\n\n`)).catch(() => this.sseClients.delete(writer));
    }
  }
}

// ═══════════════════════════════════════════════════════════════
// WORKER FETCH HANDLER
// ═══════════════════════════════════════════════════════════════

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // CORS
    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      }});
    }

    const corsHeaders = { 'Access-Control-Allow-Origin': '*' };

    // Health
    if (request.method === 'GET' && url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', worker: 'mcpsip', domain: 'mcpsip.sgoip.com' }), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // Info
    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '/info')) {
      return new Response(JSON.stringify({
        name: 'GoIP MCP SIP Gateway',
        domain: 'mcpsip.sgoip.com',
        transport: 'Cloudflare Worker',
        endpoints: { 'POST /mcp': 'MCP JSON-RPC 2.0', 'GET /sse': 'SSE stream', 'GET /health': 'Health check' },
        tools: TOOLS.map(t => t.name),
        status: 'ready',
      }, null, 2), { headers: { ...corsHeaders, 'Content-Type': 'application/json' } });
    }

    // Route MCP + SSE to Durable Object
    if ((request.method === 'POST' && (url.pathname === '/mcp' || url.pathname === '/')) ||
        (request.method === 'GET' && url.pathname === '/sse')) {
      const id = env.MCP_STATE.idFromName('mcpsip-main');
      const stub = env.MCP_STATE.get(id);
      const doResponse = await stub.fetch(request);
      const response = new Response(doResponse.body, doResponse);
      response.headers.set('Access-Control-Allow-Origin', '*');
      return response;
    }

    return new Response('Not found', { status: 404, headers: corsHeaders });
  },
};
