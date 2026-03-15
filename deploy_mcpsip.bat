@echo off
echo ============================================
echo  Deploy GoIP MCP SIP to Cloudflare Workers
echo  Domain: mcpsip.sgoip.com
echo ============================================
echo.

cd /d "C:\goip"

REM Check node
where node >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Node.js not found! Install from https://nodejs.org
    pause
    exit /b 1
)

REM Method 1: Direct API deploy (no wrangler needed)
if exist ".cf_token" (
    echo [*] Found saved token, deploying via API...
    set /p CLOUDFLARE_API_TOKEN=<.cf_token
    node deploy_mcpsip_api.js
    if %ERRORLEVEL% EQU 0 goto :done
)

echo [*] Deploying via Cloudflare REST API...
echo     (wrangler не нужен, только API token)
echo.
node deploy_mcpsip_api.js
if %ERRORLEVEL% EQU 0 goto :done

REM Method 2: Fallback to wrangler
echo.
echo [*] Fallback: trying wrangler...
where npx >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] npx not found.
    pause
    exit /b 1
)
npx wrangler login && npx wrangler deploy
if %ERRORLEVEL% EQU 0 goto :done

echo [ERROR] Deploy failed.
pause
exit /b 1

:done
echo.
echo ============================================
echo  MCP Server: https://mcpsip.sgoip.com
echo  Health:     https://mcpsip.sgoip.com/health
echo  MCP:        POST https://mcpsip.sgoip.com/mcp
echo  SSE:        GET  https://mcpsip.sgoip.com/sse
echo ============================================
pause
