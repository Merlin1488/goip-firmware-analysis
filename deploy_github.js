#!/usr/bin/env node
/**
 * Деплой проекта GoIP на GitHub через REST API
 * Использование: node deploy_github.js <GITHUB_TOKEN> [repo_name]
 * 
 * Создаёт репо (если нет), пушит все файлы.
 * Не требует git/gh CLI.
 */

const https = require('https');
const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

const TOKEN = process.argv[2] || process.env.GITHUB_TOKEN;
const REPO_NAME = process.argv[3] || 'goip-firmware-analysis';
const PROJECT_DIR = __dirname;

if (!TOKEN) {
  console.error('Usage: node deploy_github.js <GITHUB_PAT_TOKEN> [repo_name]');
  console.error('Create token: https://github.com/settings/tokens → Generate → scope: repo');
  process.exit(1);
}

// ─── Файлы для деплоя ───
const DEPLOY_FILES = [
  // Документация
  'DOC_GOIP_CLIENT_PROTOCOL.md',
  'DOC_GST1610_SIP_EXAMPLES.md',
  'DOC_SIP_FILES_INVENTORY.md',
  'DOC_SIPCLI_ANALYSIS.md',
  
  // MCP серверы
  'goip_mcp_server.js',
  'goip_analysis_mcp.js',
  'goip_sip_server.js',
  'goip_crypto.js',
  'goip_sip_test.js',
  
  // CF Worker
  'mcpsip_worker.js',
  'deploy_mcpsip_api.js',
  'deploy_mcpsip.bat',
  'wrangler.toml',
  
  // Конфиги
  '.vscode/mcp.json',
  'package.json',
  
  // Анализ скрипты
  'analyze_ata_proto.py',
  'analyze_ata_sim.py',
  'analyze_ata_sim2.py',
  'analyze_fvaci.py',
  'analyze_fvaci2.py',
  'analyze_fvaci3.py',
  'analyze_fvaci4.py',
  'analyze_fvdsp.py',
  'analyze_gpio.py',
  'analyze_libtdi.py',
  'analyze_libtdi2.py',
  'analyze_pkg.py',
  'analyze_pkg2.py',

  // Этот скрипт
  'deploy_github.js',
];

// ─── GitHub API helpers ───
function api(method, path, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const opts = {
      hostname: 'api.github.com',
      path,
      method,
      headers: {
        'Authorization': `Bearer ${TOKEN}`,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'goip-deployer/1.0',
        'X-GitHub-Api-Version': '2022-11-28',
      },
    };
    if (data) {
      opts.headers['Content-Type'] = 'application/json';
      opts.headers['Content-Length'] = Buffer.byteLength(data);
    }

    const req = https.request(opts, (res) => {
      let body = '';
      res.on('data', d => body += d);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, data: JSON.parse(body || '{}') }); }
        catch { resolve({ status: res.statusCode, data: body }); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

async function getUser() {
  const r = await api('GET', '/user');
  if (r.status !== 200) throw new Error(`Auth failed (${r.status}): ${JSON.stringify(r.data)}`);
  return r.data.login;
}

async function createRepo(owner) {
  // Проверяем существует ли
  const check = await api('GET', `/repos/${owner}/${REPO_NAME}`);
  if (check.status === 200) {
    console.log(`✓ Repo ${owner}/${REPO_NAME} уже существует`);
    return check.data;
  }

  console.log(`→ Создаю репо ${REPO_NAME}...`);
  const r = await api('POST', '/user/repos', {
    name: REPO_NAME,
    description: 'GoIP GST1610 firmware analysis, MCP servers, SIP/crypto implementation',
    private: false,
    auto_init: true,
    has_issues: true,
    has_wiki: false,
  });
  if (r.status !== 201) throw new Error(`Create repo failed (${r.status}): ${JSON.stringify(r.data)}`);
  console.log(`✓ Repo создан: ${r.data.html_url}`);
  return r.data;
}

async function getOrCreateTree(owner, files) {
  const tree = [];
  for (const filePath of files) {
    const fullPath = path.join(PROJECT_DIR, filePath);
    if (!fs.existsSync(fullPath)) {
      console.log(`  ⊘ skip: ${filePath} (not found)`);
      continue;
    }

    const stat = fs.statSync(fullPath);
    if (stat.size > 10_000_000) {
      console.log(`  ⊘ skip: ${filePath} (too large: ${(stat.size/1024/1024).toFixed(1)}MB)`);
      continue;
    }

    const content = fs.readFileSync(fullPath);
    // Создаём blob
    const blob = await api('POST', `/repos/${owner}/${REPO_NAME}/git/blobs`, {
      content: content.toString('base64'),
      encoding: 'base64',
    });
    if (blob.status !== 201) {
      console.log(`  ✗ blob failed: ${filePath} (${blob.status})`);
      continue;
    }
    tree.push({
      path: filePath,
      mode: '100644',
      type: 'blob',
      sha: blob.data.sha,
    });
    console.log(`  ✓ ${filePath} (${(stat.size/1024).toFixed(1)}KB)`);
  }
  return tree;
}

async function main() {
  try {
    console.log('=== GoIP GitHub Deploy ===\n');
    
    // 1. Auth
    const owner = await getUser();
    console.log(`✓ Авторизован как: ${owner}\n`);

    // 2. Repo
    const repo = await createRepo(owner);
    
    // 3. Получаем текущий main branch ref
    let baseSha = null;
    const refRes = await api('GET', `/repos/${owner}/${REPO_NAME}/git/ref/heads/main`);
    if (refRes.status === 200) {
      baseSha = refRes.data.object.sha;
    } else {
      // Может быть master
      const refRes2 = await api('GET', `/repos/${owner}/${REPO_NAME}/git/ref/heads/master`);
      if (refRes2.status === 200) baseSha = refRes2.data.object.sha;
    }

    // 4. Создаём blobs + tree
    console.log('\n→ Загружаю файлы...');
    const treeItems = await getOrCreateTree(owner, DEPLOY_FILES);
    console.log(`\n✓ Загружено ${treeItems.length} файлов`);

    // 5. Создаём tree
    const treePayload = { tree: treeItems };
    if (baseSha) {
      // Получаем tree SHA от базового коммита
      const commitRes = await api('GET', `/repos/${owner}/${REPO_NAME}/git/commits/${baseSha}`);
      if (commitRes.status === 200) treePayload.base_tree = commitRes.data.tree.sha;
    }
    
    const treeRes = await api('POST', `/repos/${owner}/${REPO_NAME}/git/trees`, treePayload);
    if (treeRes.status !== 201) throw new Error(`Tree failed: ${JSON.stringify(treeRes.data)}`);

    // 6. Коммит
    const commitPayload = {
      message: 'GoIP GST1610: firmware analysis, MCP servers, SIP/crypto implementation\n\n' +
        '- goip_sip_server.js — SIP Registrar/B2BUA\n' +
        '- goip_crypto.js — 8 proprietary encryption methods\n' +
        '- goip_mcp_server.js — MCP server (21 tools)\n' +
        '- goip_analysis_mcp.js — Firmware binary analysis MCP (22 tools)\n' +
        '- DOC_GOIP_CLIENT_PROTOCOL.md — Full client protocol documentation\n' +
        '- mcpsip_worker.js — Cloudflare Worker MCP',
      tree: treeRes.data.sha,
    };
    if (baseSha) commitPayload.parents = [baseSha];

    const commitRes = await api('POST', `/repos/${owner}/${REPO_NAME}/git/commits`, commitPayload);
    if (commitRes.status !== 201) throw new Error(`Commit failed: ${JSON.stringify(commitRes.data)}`);

    // 7. Обновляем ref
    const branch = refRes.status === 200 ? 'main' : 'master';
    const updateRef = await api('PATCH', `/repos/${owner}/${REPO_NAME}/git/refs/heads/${branch}`, {
      sha: commitRes.data.sha,
      force: true,
    });
    
    if (updateRef.status !== 200) {
      // Создаём ref если не существует
      await api('POST', `/repos/${owner}/${REPO_NAME}/git/refs`, {
        ref: 'refs/heads/main',
        sha: commitRes.data.sha,
      });
    }

    console.log(`\n${'='.repeat(50)}`);
    console.log(`✓ ГОТОВО! Repo: https://github.com/${owner}/${REPO_NAME}`);
    console.log(`  Коммит: ${commitRes.data.sha.substring(0, 7)}`);
    console.log(`  Файлов: ${treeItems.length}`);
    console.log(`${'='.repeat(50)}`);
    console.log(`\nДля доступа с мака: git clone https://github.com/${owner}/${REPO_NAME}.git`);

  } catch (err) {
    console.error(`\n✗ ОШИБКА: ${err.message}`);
    process.exit(1);
  }
}

main();
