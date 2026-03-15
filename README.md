# GoIP GST1610 — Firmware Analysis & Server Implementation

Полный реверс-инжиниринг прошивки VoIP GSM шлюза GoIP GST1610 (DBLTek/HYBERTONE).

## Что внутри

### MCP Серверы
- **goip_mcp_server.js** — MCP сервер управления GoIP (21 tool: SIP, звонки, SMS, шифрование)
- **goip_analysis_mcp.js** — MCP сервер анализа прошивки (22 tools: strings, ELF, hex, протоколы)
- **mcpsip_worker.js** — Cloudflare Worker MCP (HTTP/SSE транспорт)

### Серверные реализации
- **goip_sip_server.js** — SIP Registrar/B2BUA (~1900 строк, Digest Auth, GoIP fingerprinting)
- **goip_crypto.js** — 8 проприетарных методов шифрования (RC4, XOR, FAST, VOS, AVS, N2C, ECM, ET263)

### Документация
- **DOC_GOIP_CLIENT_PROTOCOL.md** — Полная документация клиентского протокола
- **DOC_GST1610_SIP_EXAMPLES.md** — Примеры SIP трафика
- **DOC_SIP_FILES_INVENTORY.md** — Инвентаризация SIP файлов
- **DOC_SIPCLI_ANALYSIS.md** — Анализ sipcli

### Анализ бинарей
- `analyze_*.py` — Python скрипты анализа компонентов прошивки
- Целевые бинари: sipcli, ata, mg, fvdsp, smb_module, radmcli, smpp_smsc

## Прошивка
- **Модель**: GoIP GST1610 (16-port GSM Gateway)
- **Версия**: GHSFVT-1.1-68-11
- **Архитектура**: ARM OABI, Linux 2.6.17, uClibc 0.9.29
- **Компоненты**: 38 бинарей, 62 kernel модуля, 8 .def конфигов

## MCP Usage

### VS Code
Добавь в `.vscode/mcp.json`:
```json
{
  "servers": {
    "goip-analysis": {
      "type": "stdio",
      "command": "node",
      "args": ["goip_analysis_mcp.js"]
    }
  }
}
```

### Copilot CLI
```json
{
  "servers": {
    "goip-analysis": {
      "type": "stdio", 
      "command": "node",
      "args": ["path/to/goip_analysis_mcp.js"]
    }
  }
}
```

## License
Research purposes only.
