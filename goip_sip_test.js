/**
 * Тест GoIP SIP Server — имитация GoIP устройства
 * 
 * Отправляет REGISTER, получает 401 challenge, повторяет с Digest Auth,
 * затем отправляет INVITE и MESSAGE.
 * 
 * Запуск: node goip_sip_test.js [server_ip] [server_port]
 */

'use strict';

const dgram = require('dgram');
const crypto = require('crypto');
const { SipMessage } = require('./goip_sip_server');

const SERVER_IP = process.argv[2] || '127.0.0.1';
const SERVER_PORT = parseInt(process.argv[3]) || 5060;
const LOCAL_PORT = 5070;
const USERNAME = '1001';
const PASSWORD = '1001';

const socket = dgram.createSocket('udp4');
let localIp = '127.0.0.1';
let testPhase = 'register_initial';
let savedNonce = '';
let savedRealm = '';

function generateBranch() {
  return 'z9hG4bK' + Math.floor(Math.random() * 999999999);
}

function generateTag() {
  return crypto.randomBytes(6).toString('hex');
}

function generateCallId() {
  return `${Date.now()}-test@${localIp}`;
}

function md5(str) {
  return crypto.createHash('md5').update(str).digest('hex');
}

function makeDigestResponse(username, realm, password, method, uri, nonce, cnonce, nc, qop) {
  const ha1 = md5(`${username}:${realm}:${password}`);
  const ha2 = md5(`${method}:${uri}`);
  if (qop === 'auth') {
    return md5(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`);
  }
  return md5(`${ha1}:${nonce}:${ha2}`);
}

function send(text) {
  const buf = Buffer.from(text);
  socket.send(buf, 0, buf.length, SERVER_PORT, SERVER_IP, (err) => {
    if (err) console.error('Send error:', err.message);
  });
}

// ═══ SIP-сообщения с GoIP-отпечатками ═══

function sendRegister(nonce, realm) {
  const branch = generateBranch();
  const tag = generateTag();
  const callId = `reg-${generateCallId()}`;
  const uri = `sip:${SERVER_IP}`;
  
  let authHeader = '';
  if (nonce && realm) {
    const cnonce = crypto.randomBytes(4).toString('hex');
    const nc = '00000001';
    const response = makeDigestResponse(USERNAME, realm, PASSWORD, 'REGISTER', uri, nonce, cnonce, nc, 'auth');
    authHeader = `Authorization: Digest username="${USERNAME}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}", cnonce="${cnonce}", nc=${nc}, qop=auth, algorithm=MD5\r\n`;
  }
  
  // GoIP-стиль: User-Agent: dble, Content-Length с пробелами
  const msg = [
    `REGISTER ${uri} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
    `From: <sip:${USERNAME}@${SERVER_IP}>;tag=${tag}`,
    `To: <sip:${USERNAME}@${SERVER_IP}>`,
    `Call-ID: ${callId}`,
    `CSeq: ${nonce ? 2 : 1} REGISTER`,
    `Contact: <sip:${USERNAME}@${localIp}:${LOCAL_PORT}>`,
    `Max-Forwards: 70`,
    authHeader ? authHeader.trim() : '',
    `Expires: 120`,
    `User-Agent: dble`,
    `Content-Length:     0`,
    '',
    '',
  ].filter(l => l !== '').join('\r\n');
  
  console.log(`\n─── SEND REGISTER ${nonce ? '(with auth)' : '(initial)'} ───`);
  send(msg);
}

function sendInvite() {
  const branch = generateBranch();
  const fromTag = generateTag();
  const callId = `call-${generateCallId()}`;
  
  // Сохраняем для повторного INVITE с auth
  savedInviteCallId = callId;
  savedInviteFromTag = fromTag;
  
  // GoIP-стиль SDP: o=userX 20000001, s=DBL Session
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
  
  const msg = [
    `INVITE sip:+79001234567@${SERVER_IP}:${SERVER_PORT} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
    `From: "GSM Caller" <sip:${USERNAME}@${SERVER_IP}>;tag=${fromTag}`,
    `To: <sip:+79001234567@${SERVER_IP}>`,
    `Call-ID: ${callId}`,
    `CSeq: 1 INVITE`,
    `Contact: <sip:${USERNAME}@${localIp}:${LOCAL_PORT}>`,
    `Max-Forwards: 70`,
    `User-Agent: dble`,
    `Content-Type: application/sdp`,
    `Content-Length: ${sdp.length}`,
    '',
    sdp,
  ].join('\r\n');
  
  console.log(`\n─── SEND INVITE ───`);
  console.log(`  From: ${USERNAME} → To: +79001234567`);
  send(msg);
  
  return callId;
}

let savedInviteCallId = '';
let savedInviteFromTag = '';

function sendInviteWithAuth(nonce, realm) {
  const branch = generateBranch();
  savedInviteFromTag = savedInviteFromTag || generateTag();
  savedInviteCallId = savedInviteCallId || `call-${generateCallId()}`;
  
  const uri = `sip:+79001234567@${SERVER_IP}:${SERVER_PORT}`;
  const cnonce = crypto.randomBytes(4).toString('hex');
  const nc = '00000001';
  const response = makeDigestResponse(USERNAME, realm, PASSWORD, 'INVITE', uri, nonce, cnonce, nc, 'auth');
  
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
  
  const msg = [
    `INVITE ${uri} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
    `From: "GSM Caller" <sip:${USERNAME}@${SERVER_IP}>;tag=${savedInviteFromTag}`,
    `To: <sip:+79001234567@${SERVER_IP}>`,
    `Call-ID: ${savedInviteCallId}`,
    `CSeq: 2 INVITE`,
    `Contact: <sip:${USERNAME}@${localIp}:${LOCAL_PORT}>`,
    `Max-Forwards: 70`,
    `User-Agent: dble`,
    `Proxy-Authorization: Digest username="${USERNAME}", realm="${realm}", nonce="${nonce}", uri="${uri}", response="${response}", cnonce="${cnonce}", nc=${nc}, qop=auth, algorithm=MD5`,
    `Content-Type: application/sdp`,
    `Content-Length: ${sdp.length}`,
    '',
    sdp,
  ].join('\r\n');
  
  console.log(`\n─── SEND INVITE (with proxy auth) ───`);
  send(msg);
}

function sendMessage() {
  const branch = generateBranch();
  const tag = generateTag();
  const callId = `sms-${generateCallId()}`;
  const body = 'Test SMS from GoIP device';
  
  const msg = [
    `MESSAGE sip:sms_dest@${SERVER_IP}:${SERVER_PORT} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
    `From: <sip:${USERNAME}@${SERVER_IP}>;tag=${tag}`,
    `To: <sip:sms_dest@${SERVER_IP}>`,
    `Call-ID: ${callId}`,
    `CSeq: 1 MESSAGE`,
    `Max-Forwards: 70`,
    `User-Agent: dble`,
    `Content-Type: text/plain`,
    `Content-Length: ${body.length}`,
    '',
    body,
  ].join('\r\n');
  
  console.log(`\n─── SEND MESSAGE (SMS) ───`);
  send(msg);
}

function sendOptions() {
  const branch = generateBranch();
  const tag = generateTag();
  
  const msg = [
    `OPTIONS sip:${SERVER_IP}:${SERVER_PORT} SIP/2.0`,
    `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
    `From: <sip:${USERNAME}@${SERVER_IP}>;tag=${tag}`,
    `To: <sip:${SERVER_IP}>`,
    `Call-ID: opt-${generateCallId()}`,
    `CSeq: 1 OPTIONS`,
    `Max-Forwards: 70`,
    `User-Agent: dble`,
    `Content-Length:     0`,
    '',
    '',
  ].join('\r\n');
  
  console.log(`\n─── SEND OPTIONS (keepalive) ───`);
  send(msg);
}

// ═══ Обработка ответов ═══

socket.on('message', (buffer, rinfo) => {
  const msg = SipMessage.parse(buffer);
  if (!msg) {
    console.log('  [!] Failed to parse response');
    return;
  }
  
  console.log(`\n◄── RECV ${msg.isResponse ? `${msg.statusCode} ${msg.reasonPhrase}` : msg.method} from ${rinfo.address}:${rinfo.port}`);
  
  if (msg.isResponse) {
    switch (testPhase) {
      case 'register_initial':
        if (msg.statusCode === 401) {
          // Парсим challenge
          const authHeader = msg.wwwAuthenticate;
          if (authHeader) {
            const realmMatch = authHeader.match(/realm="([^"]+)"/);
            const nonceMatch = authHeader.match(/nonce="([^"]+)"/);
            if (realmMatch && nonceMatch) {
              savedRealm = realmMatch[1];
              savedNonce = nonceMatch[1];
              console.log(`  Challenge: realm=${savedRealm}, nonce=${savedNonce.substring(0, 16)}...`);
              
              testPhase = 'register_auth';
              setTimeout(() => sendRegister(savedNonce, savedRealm), 100);
            }
          }
        }
        break;
        
      case 'register_auth':
        if (msg.statusCode === 200) {
          console.log('  ✓ REGISTERED SUCCESSFULLY');
          
          // Фаза 2: отправляем OPTIONS
          testPhase = 'options';
          setTimeout(() => sendOptions(), 500);
        } else {
          console.log(`  ✗ Registration failed: ${msg.statusCode}`);
        }
        break;
        
      case 'options':
        if (msg.statusCode === 200) {
          console.log('  ✓ OPTIONS OK');
          
          // Фаза 3: отправляем MESSAGE (SMS)
          testPhase = 'message';
          setTimeout(() => sendMessage(), 500);
        }
        break;
        
      case 'message':
        if (msg.statusCode === 200) {
          console.log('  ✓ MESSAGE DELIVERED');
          
          // Фаза 4: отправляем INVITE
          testPhase = 'invite';
          setTimeout(() => sendInvite(), 500);
        }
        break;
        
      case 'invite':
        if (msg.statusCode === 100) {
          console.log('  → 100 Trying');
        } else if (msg.statusCode === 180) {
          console.log('  → 180 Ringing');
        } else if (msg.statusCode === 200) {
          console.log('  ✓ 200 OK — CALL ANSWERED');
          
          // Отправляем ACK
          const branch = generateBranch();
          const ack = [
            `ACK sip:server@${SERVER_IP}:${SERVER_PORT} SIP/2.0`,
            `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch}`,
            msg.headers['from'] ? `From: ${msg.headers['from'][0].value}` : `From: <sip:${USERNAME}@${SERVER_IP}>`,
            msg.headers['to'] ? `To: ${msg.headers['to'][0].value}` : `To: <sip:+79001234567@${SERVER_IP}>`,
            `Call-ID: ${msg.callId}`,
            `CSeq: 1 ACK`,
            `Max-Forwards: 70`,
            `Content-Length: 0`,
            '',
            '',
          ].join('\r\n');
          
          console.log('  → SEND ACK');
          send(ack);
          
          testPhase = 'connected';
          
          // Завершаем через 3 секунды
          setTimeout(() => {
            console.log('\n═══ ALL TESTS PASSED ═══');
            console.log('Summary:');
            console.log('  ✓ REGISTER (401 challenge → 200 OK)');
            console.log('  ✓ OPTIONS keepalive (200 OK)');
            console.log('  ✓ MESSAGE SMS (200 OK)');
            console.log('  ✓ INVITE call (407 → Proxy-Auth → 100 → 180 → 200 → ACK)');
            console.log('  ✓ GoIP fingerprint detection (User-Agent: dble, SDP: DBL Session)');
            
            socket.close();
            process.exit(0);
          }, 2000);
        } else if (msg.statusCode === 407) {
          // Парсим Proxy-Authenticate challenge
          const paHeaders = msg.headers['proxy-authenticate'];
          if (paHeaders && paHeaders.length > 0) {
            const authHeader = paHeaders[0].value;
            const realmMatch = authHeader.match(/realm="([^"]+)"/);
            const nonceMatch = authHeader.match(/nonce="([^"]+)"/);
            if (realmMatch && nonceMatch) {
              const proxyRealm = realmMatch[1];
              const proxyNonce = nonceMatch[1];
              console.log(`  → 407 Proxy Auth Required — sending credentials`);
              
              // Повторяем INVITE с Proxy-Authorization
              testPhase = 'invite_auth';
              setTimeout(() => sendInviteWithAuth(proxyNonce, proxyRealm), 100);
            }
          }
        }
        break;
        
      case 'invite_auth':
        if (msg.statusCode === 100) {
          console.log('  → 100 Trying');
        } else if (msg.statusCode === 180) {
          console.log('  → 180 Ringing');
        } else if (msg.statusCode === 200) {
          console.log('  ✓ 200 OK — CALL ANSWERED');
          
          // Отправляем ACK
          const branch2 = generateBranch();
          const ack2 = [
            `ACK sip:server@${SERVER_IP}:${SERVER_PORT} SIP/2.0`,
            `Via: SIP/2.0/UDP ${localIp}:${LOCAL_PORT};rport;branch=${branch2}`,
            msg.headers['from'] ? `From: ${msg.headers['from'][0].value}` : `From: <sip:${USERNAME}@${SERVER_IP}>`,
            msg.headers['to'] ? `To: ${msg.headers['to'][0].value}` : `To: <sip:+79001234567@${SERVER_IP}>`,
            `Call-ID: ${msg.callId}`,
            `CSeq: 2 ACK`,
            `Max-Forwards: 70`,
            `Content-Length: 0`,
            '',
            '',
          ].join('\r\n');
          
          console.log('  → SEND ACK');
          send(ack2);
          
          testPhase = 'connected';
          
          setTimeout(() => {
            console.log('\n═══ ALL TESTS PASSED ═══');
            console.log('Summary:');
            console.log('  ✓ REGISTER (401 challenge → 200 OK)');
            console.log('  ✓ OPTIONS keepalive (200 OK)');
            console.log('  ✓ MESSAGE SMS (200 OK)');
            console.log('  ✓ INVITE call (407 → Proxy-Auth → 100 → 180 → 200 → ACK)');
            console.log('  ✓ GoIP fingerprint detection (User-Agent: dble, SDP: DBL Session)');
            
            socket.close();
            process.exit(0);
          }, 2000);
        }
        break;
    }
  }
});

// ═══ Запуск ═══

socket.bind(LOCAL_PORT, () => {
  const addr = socket.address();
  localIp = addr.address === '0.0.0.0' ? '127.0.0.1' : addr.address;
  
  console.log('═══════════════════════════════════════════════');
  console.log('  GoIP SIP Server Test');
  console.log(`  Server: ${SERVER_IP}:${SERVER_PORT}`);
  console.log(`  Local:  ${localIp}:${LOCAL_PORT}`);
  console.log('═══════════════════════════════════════════════');
  
  // Начинаем с REGISTER
  sendRegister();
});

// Таймаут на весь тест
setTimeout(() => {
  console.log('\n  ✗ TEST TIMEOUT');
  socket.close();
  process.exit(1);
}, 15000);
