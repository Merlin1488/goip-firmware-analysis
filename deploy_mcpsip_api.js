#!/usr/bin/env node
/**
 * GoIP MCP SIP — Direct Cloudflare API Deployer
 * Деплоит Worker напрямую через REST API (не нужен wrangler).
 * 
 * Запуск: node deploy_mcpsip_api.js
 * Или: deploy_mcpsip.bat
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const readline = require('readline');

const WORKER_NAME = 'mcpsip';
const WORKER_FILE = path.join(__dirname, 'mcpsip_worker.js');

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q) => new Promise(r => rl.question(q, r));

function cfRequest(method, path, token, body, contentType) {
  return new Promise((resolve, reject) => {
    const headers = { 'Authorization': `Bearer ${token}` };
    if (contentType) headers['Content-Type'] = contentType;
    
    const opts = { hostname: 'api.cloudflare.com', path, method, headers };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

function cfMultipart(method, apiPath, token, parts) {
  return new Promise((resolve, reject) => {
    const boundary = '----CFWorkerDeploy' + Date.now();
    let body = '';
    for (const p of parts) {
      body += `--${boundary}\r\n`;
      body += `Content-Disposition: form-data; name="${p.name}"`;
      if (p.filename) body += `; filename="${p.filename}"`;
      body += `\r\n`;
      if (p.type) body += `Content-Type: ${p.type}\r\n`;
      body += `\r\n${p.data}\r\n`;
    }
    body += `--${boundary}--\r\n`;

    const opts = {
      hostname: 'api.cloudflare.com', path: apiPath, method,
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, (res) => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, data }); }
      });
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

async function main() {
  console.log('==========================================');
  console.log(' GoIP MCP SIP — Cloudflare Worker Deploy');
  console.log(' Domain: mcpsip.sgoip.com');
  console.log('==========================================\n');

  // Token
  let token = process.env.CLOUDFLARE_API_TOKEN || '';
  if (!token) {
    console.log('Нужен API Token. Создай на:');
    console.log('  https://dash.cloudflare.com/profile/api-tokens');
    console.log('  -> Create Token -> "Edit Cloudflare Workers" template\n');
    token = await ask('API Token: ');
    token = token.trim();
  }
  if (!token) { console.log('Token не указан. Выход.'); process.exit(1); }

  // Verify token & get account
  console.log('\n[*] Проверка токена...');
  const verify = await cfRequest('GET', '/client/v4/user/tokens/verify', token);
  if (verify.data?.success !== true) {
    console.log('[ERROR] Невалидный токен:', JSON.stringify(verify.data?.errors || verify.data));
    process.exit(1);
  }
  console.log('[OK] Токен валиден.');

  // Get accounts
  console.log('[*] Получение аккаунта...');
  const accts = await cfRequest('GET', '/client/v4/accounts?page=1&per_page=5', token);
  if (!accts.data?.result?.length) {
    console.log('[ERROR] Не найдены аккаунты:', JSON.stringify(accts.data?.errors));
    process.exit(1);
  }
  const accountId = accts.data.result[0].id;
  const accountName = accts.data.result[0].name;
  console.log(`[OK] Аккаунт: ${accountName} (${accountId})`);

  // Read worker script
  console.log('[*] Чтение worker скрипта...');
  const workerCode = fs.readFileSync(WORKER_FILE, 'utf-8');
  console.log(`[OK] ${WORKER_FILE} (${workerCode.length} bytes)`);

  // Metadata for Durable Objects
  const metadata = {
    main_module: 'mcpsip_worker.js',
    compatibility_date: '2024-09-23',
    compatibility_flags: ['nodejs_compat'],
    durable_objects: {
      bindings: [{ name: 'MCP_STATE', class_name: 'McpState' }],
    },
    migrations: {
      new_tag: 'v1',
      steps: [{ new_classes: ['McpState'] }],
    },
  };

  // Deploy worker (multipart with module)
  console.log(`[*] Деплой worker "${WORKER_NAME}"...`);
  const deployResult = await cfMultipart(
    'PUT',
    `/client/v4/accounts/${accountId}/workers/scripts/${WORKER_NAME}`,
    token,
    [
      { name: 'metadata', data: JSON.stringify(metadata), type: 'application/json' },
      { name: 'mcpsip_worker.js', filename: 'mcpsip_worker.js', data: workerCode, type: 'application/javascript+module' },
    ]
  );

  if (deployResult.data?.success) {
    console.log('[OK] Worker задеплоен!');
  } else {
    console.log('[ERROR] Деплой не удался:');
    console.log(JSON.stringify(deployResult.data?.errors || deployResult.data, null, 2));

    // Fallback: try as service worker (no modules)
    console.log('\n[*] Пробую альтернативный формат (service worker)...');
    const fallback = await cfRequest(
      'PUT',
      `/client/v4/accounts/${accountId}/workers/scripts/${WORKER_NAME}`,
      token,
      workerCode,
      'application/javascript'
    );
    if (fallback.data?.success) {
      console.log('[OK] Worker задеплоен (service worker mode)!');
    } else {
      console.log('[ERROR]:', JSON.stringify(fallback.data?.errors || fallback.data, null, 2));
      console.log('\nПопробуй вручную: cd C:\\goip && npx wrangler deploy');
      rl.close();
      process.exit(1);
    }
  }

  // Enable worker route on workers.dev
  console.log('[*] Включение workers.dev subdomain...');
  const subdomainResult = await cfRequest(
    'POST',
    `/client/v4/accounts/${accountId}/workers/scripts/${WORKER_NAME}/subdomain`,
    token,
    JSON.stringify({ enabled: true }),
    'application/json'
  );
  if (subdomainResult.data?.success) {
    console.log('[OK] Доступен на: https://mcpsip.<account>.workers.dev');
  }

  // Try to set up custom domain
  console.log('[*] Настройка custom domain mcpsip.sgoip.com...');
  const domainResult = await cfRequest(
    'PUT',
    `/client/v4/accounts/${accountId}/workers/domains`,
    token,
    JSON.stringify({
      hostname: 'mcpsip.sgoip.com',
      service: WORKER_NAME,
      environment: 'production',
    }),
    'application/json'
  );
  if (domainResult.data?.success) {
    console.log('[OK] Custom domain настроен: mcpsip.sgoip.com');
  } else {
    console.log('[WARN] Custom domain:', JSON.stringify(domainResult.data?.errors?.[0]?.message || 'Настрой вручную в dashboard'));
    console.log('       Dashboard -> Workers & Pages -> mcpsip -> Settings -> Domains & Routes');
    console.log('       Добавь: mcpsip.sgoip.com');
  }

  console.log('\n==========================================');
  console.log(' ГОТОВО!');
  console.log('');
  console.log(' Worker URL: https://mcpsip.<account>.workers.dev');
  console.log(' Custom:     https://mcpsip.sgoip.com');
  console.log('');
  console.log(' Endpoints:');
  console.log('   POST /mcp    — MCP JSON-RPC 2.0');
  console.log('   GET  /sse    — SSE stream');
  console.log('   GET  /health — Health check');
  console.log('   GET  /       — Info');
  console.log('==========================================');

  // Save token for future use
  const tokenFile = path.join(__dirname, '.cf_token');
  fs.writeFileSync(tokenFile, token);
  console.log(`\nТокен сохранён в ${tokenFile}`);

  rl.close();
}

main().catch(e => { console.error('Fatal:', e.message); process.exit(1); });
