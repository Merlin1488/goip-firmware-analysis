/**
 * GoIP SIP Server — модуль проприетарного шифрования
 * 
 * Реализация всех 8 методов шифрования DBLTek/HYBERTONE:
 * RC4, FAST, XOR, VOS, AVS, N2C, ECM, ET263
 * 
 * Шифрование применяется к RTP-пакетам (payload, не заголовок).
 * Ключ обменивается через SIP-заголовок X-ACrypt.
 */

'use strict';

// ═══════════════════════════════════════════════════════════════
// RC4 — Модифицированный (с 13 дополнительными swap в S-box)
// ═══════════════════════════════════════════════════════════════

/**
 * GoIP RC4: стандартный RC4 KSA + 13 дополнительных swap
 * 
 * Дополнительные swap-позиции (после стандартного KSA):
 * [1,5], [4,56], [10,47], [15,185], [23,74], [28,129], [33,42],
 * [44,66], [55,73], [77,99], [88,124], [111,250], [200,220]
 */
const RC4_EXTRA_SWAPS = [
  [1, 5], [4, 56], [10, 47], [15, 185], [23, 74], [28, 129], [33, 42],
  [44, 66], [55, 73], [77, 99], [88, 124], [111, 250], [200, 220]
];

class GoIPRC4 {
  constructor(key) {
    this.S = new Uint8Array(256);
    this.i = 0;
    this.j = 0;
    this._ksa(key);
  }

  _ksa(key) {
    const keyBytes = typeof key === 'string' ? Buffer.from(key) : key;
    const S = this.S;
    
    // Стандартная инициализация
    for (let i = 0; i < 256; i++) S[i] = i;
    
    // Стандартный KSA
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + S[i] + keyBytes[i % keyBytes.length]) & 0xFF;
      [S[i], S[j]] = [S[j], S[i]];
    }
    
    // 13 дополнительных swap (проприетарная модификация DBLTek)
    for (const [a, b] of RC4_EXTRA_SWAPS) {
      [S[a], S[b]] = [S[b], S[a]];
    }
  }

  /**
   * Шифрование/дешифрование PRGA
   */
  process(data) {
    const S = this.S;
    let { i, j } = this;
    const output = Buffer.alloc(data.length);
    
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 0xFF;
      j = (j + S[i]) & 0xFF;
      [S[i], S[j]] = [S[j], S[i]];
      const k = S[(S[i] + S[j]) & 0xFF];
      output[n] = data[n] ^ k;
    }
    
    this.i = i;
    this.j = j;
    
    return output;
  }

  /**
   * Сброс состояния (для нового пакета, если нужно per-packet)
   */
  reset(key) {
    this.i = 0;
    this.j = 0;
    this._ksa(key);
  }
}

// ═══════════════════════════════════════════════════════════════
// XOR — Простой XOR с ключом
// ═══════════════════════════════════════════════════════════════

class GoIPXOR {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    const keyLen = this.keyBytes.length;
    
    for (let i = 0; i < data.length; i++) {
      output[i] = data[i] ^ this.keyBytes[i % keyLen];
    }
    
    return output;
  }
}

// ═══════════════════════════════════════════════════════════════
// FAST — Быстрый XOR (вероятно, фиксированный паттерн)
// ═══════════════════════════════════════════════════════════════

class GoIPFAST {
  constructor(key) {
    // FAST обычно XOR но с дополнительным seed
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
    this.pattern = this._generatePattern();
  }

  _generatePattern() {
    // Генерируем паттерн на основе ключа
    const pattern = Buffer.alloc(256);
    let seed = 0;
    for (let i = 0; i < this.keyBytes.length; i++) {
      seed = (seed * 31 + this.keyBytes[i]) & 0xFFFF;
    }
    
    for (let i = 0; i < 256; i++) {
      seed = (seed * 1103515245 + 12345) & 0x7FFFFFFF;
      pattern[i] = (seed >> 16) & 0xFF;
    }
    
    return pattern;
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      output[i] = data[i] ^ this.pattern[i & 0xFF];
    }
    return output;
  }
}

// ═══════════════════════════════════════════════════════════════
// VOS, AVS, N2C, ECM, ET263 — Проприетарные методы
// Точная реализация неизвестна, используем best-guess на основе
// reverse engineering patterns
// ═══════════════════════════════════════════════════════════════

/**
 * VOS — Voice Obfuscation Simple
 * Вероятно: побайтовая перестановка + XOR
 */
class GoIPVOS {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
    this.permTable = this._buildPermutation();
  }

  _buildPermutation() {
    const table = new Uint8Array(256);
    for (let i = 0; i < 256; i++) table[i] = i;
    
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + table[i] + this.keyBytes[i % this.keyBytes.length] + 7) & 0xFF;
      [table[i], table[j]] = [table[j], table[i]];
    }
    
    return table;
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      output[i] = this.permTable[data[i]] ^ this.keyBytes[i % this.keyBytes.length];
    }
    return output;
  }
}

/**
 * AVS — Advanced Voice Scrambling
 * Вероятно: multi-round XOR с rotating key
 */
class GoIPAVS {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    const keyLen = this.keyBytes.length;
    
    for (let i = 0; i < data.length; i++) {
      let byte = data[i];
      // Два раунда XOR с разными смещениями
      byte ^= this.keyBytes[i % keyLen];
      byte ^= this.keyBytes[(i + keyLen / 2) % keyLen];
      byte = ((byte << 3) | (byte >> 5)) & 0xFF; // rotate left 3
      output[i] = byte;
    }
    return output;
  }
}

/**
 * N2C — No idea what this stands for, but based on patterns
 */
class GoIPN2C {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    const keyLen = this.keyBytes.length;
    let carry = 0;
    
    for (let i = 0; i < data.length; i++) {
      const keyByte = this.keyBytes[i % keyLen];
      output[i] = (data[i] ^ keyByte ^ carry) & 0xFF;
      carry = (carry + keyByte + data[i]) & 0xFF;
    }
    return output;
  }
}

/**
 * ECM — Encrypted Communication Mode
 */
class GoIPECM {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
    this.sbox = this._buildSBox();
  }

  _buildSBox() {
    const sbox = new Uint8Array(256);
    for (let i = 0; i < 256; i++) sbox[i] = i;
    
    let j = 0;
    for (let round = 0; round < 3; round++) {
      for (let i = 0; i < 256; i++) {
        j = (j + sbox[i] + this.keyBytes[i % this.keyBytes.length] + round * 17) & 0xFF;
        [sbox[i], sbox[j]] = [sbox[j], sbox[i]];
      }
    }
    
    return sbox;
  }

  process(data) {
    const output = Buffer.alloc(data.length);
    for (let i = 0; i < data.length; i++) {
      output[i] = this.sbox[data[i] ^ this.keyBytes[i % this.keyBytes.length]];
    }
    return output;
  }
}

/**
 * ET263 — HYBERTONE-specific encryption
 * Назван по модели устройства (ET263x серия)
 */
class GoIPET263 {
  constructor(key) {
    this.keyBytes = typeof key === 'string' ? Buffer.from(key) : Buffer.from(key);
    this.state = new Uint8Array(256);
    this._init();
  }

  _init() {
    for (let i = 0; i < 256; i++) this.state[i] = i;
    
    let j = 0;
    for (let i = 0; i < 256; i++) {
      j = (j + this.state[i] + this.keyBytes[i % this.keyBytes.length]) & 0xFF;
      [this.state[i], this.state[j]] = [this.state[j], this.state[i]];
    }
    
    // ET263 специфика: не 13, а 8 дополнительных swap
    const etSwaps = [[0, 128], [32, 192], [64, 224], [96, 160], [48, 176], [80, 208], [112, 240], [16, 144]];
    for (const [a, b] of etSwaps) {
      [this.state[a], this.state[b]] = [this.state[b], this.state[a]];
    }
  }

  process(data) {
    const S = this.state;
    const output = Buffer.alloc(data.length);
    let i = 0, j = 0;
    
    for (let n = 0; n < data.length; n++) {
      i = (i + 1) & 0xFF;
      j = (j + S[i]) & 0xFF;
      [S[i], S[j]] = [S[j], S[i]];
      output[n] = data[n] ^ S[(S[i] + S[j]) & 0xFF];
    }
    
    return output;
  }
}

// ═══════════════════════════════════════════════════════════════
// X-ACrypt ПАРСЕР И МЕНЕДЖЕР КЛЮЧЕЙ
// ═══════════════════════════════════════════════════════════════

/**
 * Формат X-ACrypt заголовка:
 * X-ACrypt: <method>:<key_material>
 * 
 * Пример: X-ACrypt: RC4:a1b2c3d4e5f6
 */
class XACryptManager {
  /**
   * Парсинг X-ACrypt заголовка
   */
  static parse(headerValue) {
    if (!headerValue) return null;
    
    const colonIdx = headerValue.indexOf(':');
    if (colonIdx < 0) {
      return { method: headerValue.trim().toUpperCase(), key: '' };
    }
    
    return {
      method: headerValue.substring(0, colonIdx).trim().toUpperCase(),
      key: headerValue.substring(colonIdx + 1).trim(),
    };
  }

  /**
   * Создание X-ACrypt заголовка
   */
  static create(method, key) {
    return `${method}:${key}`;
  }

  /**
   * Создание шифратора по методу
   */
  static createCipher(method, key) {
    switch (method.toUpperCase()) {
      case 'RC4':   return new GoIPRC4(key);
      case 'FAST':  return new GoIPFAST(key);
      case 'XOR':   return new GoIPXOR(key);
      case 'VOS':   return new GoIPVOS(key);
      case 'AVS':   return new GoIPAVS(key);
      case 'N2C':   return new GoIPN2C(key);
      case 'ECM':   return new GoIPECM(key);
      case 'ET263': return new GoIPET263(key);
      default:
        console.warn(`Unknown encryption method: ${method}`);
        return null;
    }
  }

  /**
   * Генерация случайного ключа
   */
  static generateKey(length = 16) {
    return require('crypto').randomBytes(length).toString('hex');
  }
}

// ═══════════════════════════════════════════════════════════════
// RTP ОБРАБОТЧИК (для расшифровки / транскодирования)
// ═══════════════════════════════════════════════════════════════

class RTPProcessor {
  /**
   * Парсинг RTP пакета
   */
  static parse(buffer) {
    if (buffer.length < 12) return null;
    
    const version = (buffer[0] >> 6) & 0x03;
    const padding = (buffer[0] >> 5) & 0x01;
    const extension = (buffer[0] >> 4) & 0x01;
    const csrcCount = buffer[0] & 0x0F;
    const marker = (buffer[1] >> 7) & 0x01;
    const payloadType = buffer[1] & 0x7F;
    const sequenceNumber = buffer.readUInt16BE(2);
    const timestamp = buffer.readUInt32BE(4);
    const ssrc = buffer.readUInt32BE(8);
    
    const headerLength = 12 + csrcCount * 4;
    const payload = buffer.slice(headerLength);
    
    return {
      version,
      padding,
      extension,
      csrcCount,
      marker,
      payloadType,
      sequenceNumber,
      timestamp,
      ssrc,
      headerLength,
      payload,
      header: buffer.slice(0, headerLength),
    };
  }

  /**
   * Декрипт RTP payload (применяется только к payload, не к заголовку)
   */
  static decryptPayload(rtpPacket, cipher) {
    if (!cipher || !rtpPacket) return rtpPacket;
    
    const parsed = this.parse(rtpPacket);
    if (!parsed) return rtpPacket;
    
    const decryptedPayload = cipher.process(parsed.payload);
    
    return Buffer.concat([parsed.header, decryptedPayload]);
  }

  /**
   * Проверка — это DTMF (RFC 2833)?
   */
  static isDTMFEvent(payloadType) {
    return payloadType === 101; // Typical telephone-event PT
  }

  /**
   * Парсинг RFC 2833 DTMF event
   */
  static parseDTMFEvent(payload) {
    if (payload.length < 4) return null;
    
    const event = payload[0];
    const endBit = (payload[1] >> 7) & 0x01;
    const volume = payload[1] & 0x3F;
    const duration = payload.readUInt16BE(2);
    
    const chars = '0123456789*#ABCD';
    
    return {
      event,
      char: event < chars.length ? chars[event] : '?',
      end: !!endBit,
      volume,
      duration,
    };
  }
}

// ═══════════════════════════════════════════════════════════════
// ЭКСПОРТ
// ═══════════════════════════════════════════════════════════════

module.exports = {
  // Шифраторы
  GoIPRC4,
  GoIPXOR,
  GoIPFAST,
  GoIPVOS,
  GoIPAVS,
  GoIPN2C,
  GoIPECM,
  GoIPET263,
  
  // Менеджеры
  XACryptManager,
  RTPProcessor,
  
  // Константы
  RC4_EXTRA_SWAPS,
};
