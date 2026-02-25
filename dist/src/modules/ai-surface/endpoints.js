'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const http = require('http');
const https = require('https');
const { execSync } = require('child_process');
const INFERENCE_PORTS = [
    { port: 11434, name: 'Ollama', apiPath: '/api/tags' },
    { port: 1234, name: 'LM Studio', apiPath: '/v1/models' },
    { port: 4891, name: 'GPT4All', apiPath: '/v1/models' },
    { port: 8080, name: 'Generic OpenAI-compat', apiPath: '/v1/models' },
    { port: 8000, name: 'Generic', apiPath: '/v1/models' },
    { port: 5000, name: 'Generic', apiPath: '/' },
    { port: 3000, name: 'Generic', apiPath: '/' },
];
function httpGet(url, timeoutMs = 3000) {
    return new Promise((resolve) => {
        const timer = setTimeout(() => resolve({ err: 'timeout', statusCode: null, body: '', headers: {} }), timeoutMs);
        try {
            const lib = url.startsWith('https') ? https : http;
            const req = lib.get(url, { timeout: timeoutMs - 200 }, (res) => {
                let body = '';
                res.on('data', chunk => { body += chunk; if (body.length > 8192)
                    res.destroy(); });
                res.on('end', () => { clearTimeout(timer); resolve({ err: null, statusCode: res.statusCode, body, headers: res.headers }); });
            });
            req.on('error', (e) => { clearTimeout(timer); resolve({ err: e.message, statusCode: null, body: '', headers: {} }); });
        }
        catch (e) {
            clearTimeout(timer);
            resolve({ err: e.message, statusCode: null, body: '', headers: {} });
        }
    });
}
function getBindingInfo(port) {
    try {
        if (process.platform === 'win32') {
            const out = execSync(`netstat -an | findstr ":${port}"`, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
            return out.includes('0.0.0.0') ? '0.0.0.0' : (out.trim() ? '127.0.0.1' : null);
        }
        const out = execSync(`lsof -iTCP:${port} -sTCP:LISTEN -nP 2>/dev/null || ss -tlnp 2>/dev/null | grep :${port}`, { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
        if (!out.trim())
            return null;
        if (out.includes('0.0.0.0') || out.includes('*:'))
            return '0.0.0.0';
        if (out.includes('127.0.0.1') || out.includes('localhost') || out.includes('::1'))
            return '127.0.0.1';
        return 'unknown';
    }
    catch {
        return null;
    }
}
function extractModelName(body) {
    try {
        const json = JSON.parse(body);
        if (json.models?.length > 0)
            return json.models.map(m => m.name || m.id).filter(Boolean).slice(0, 3).join(', ');
        if (json.data?.length > 0)
            return json.data.map(m => m.id).filter(Boolean).slice(0, 3).join(', ');
        if (json.model)
            return json.model;
    }
    catch { /* ignore */ }
    return 'unknown';
}
function isCorsPermissive(headers) {
    return headers['access-control-allow-origin'] === '*';
}
async function scan() {
    const findings = [];
    for (const { port, name, apiPath } of INFERENCE_PORTS) {
        const binding = getBindingInfo(port);
        if (!binding)
            continue;
        const url = `http://localhost:${port}${apiPath}`;
        const resp = await httpGet(url);
        const connectionRefused = resp.err && resp.err.includes('ECONNREFUSED');
        if (connectionRefused)
            continue;
        const isPublic = binding === '0.0.0.0';
        const reachable = resp.statusCode !== null;
        const noAuth = reachable && resp.statusCode !== 401 && resp.statusCode !== 403;
        const corsPermissive = isCorsPermissive(resp.headers);
        const modelName = reachable && resp.body ? extractModelName(resp.body) : 'unknown';
        if (isPublic) {
            findings.push({
                title: `${name} inference endpoint publicly exposed on 0.0.0.0:${port}`,
                severity: 'critical',
                location: `0.0.0.0:${port}`,
                detail: `${name} is listening on ALL network interfaces. Model: ${modelName}. Auth: ${noAuth ? 'NONE' : 'present'}.`,
                recommendation: `Immediately bind ${name} to 127.0.0.1 only. For Ollama: set OLLAMA_HOST=127.0.0.1. Add authentication before any external exposure.`,
                tags: ['endpoint', 'public-exposure'],
                metadata: { port, binding, authStatus: noAuth ? 'missing' : 'configured', model: modelName, corsPermissive },
            });
        }
        if (!isPublic && noAuth && reachable) {
            findings.push({
                title: `${name} on port ${port} accepts unauthenticated requests`,
                severity: 'high',
                location: `localhost:${port}`,
                detail: `${name} responded to unauthenticated request with HTTP ${resp.statusCode}. Model: ${modelName}.`,
                recommendation: 'Add API key authentication to the inference server configuration to prevent unauthorized model access.',
                tags: ['endpoint', 'missing-auth'],
                metadata: { port, binding, authStatus: 'missing', model: modelName, corsPermissive },
            });
        }
        if (corsPermissive) {
            findings.push({
                title: `${name} on port ${port} has permissive CORS (Access-Control-Allow-Origin: *)`,
                severity: 'medium',
                location: `localhost:${port}`,
                detail: 'Wildcard CORS allows any webpage to send requests to this inference server — enables cross-site model access attacks.',
                recommendation: 'Restrict CORS to specific trusted origins. Remove the wildcard Access-Control-Allow-Origin header.',
                tags: ['endpoint', 'cors-permissive'],
                metadata: { port, binding, authStatus: noAuth ? 'missing' : 'configured', model: modelName, corsPermissive: true },
            });
        }
        if (!isPublic && !noAuth) {
            findings.push({
                title: `${name} running on port ${port} — secured`,
                severity: 'info',
                location: `localhost:${port}`,
                detail: `${name} is running (localhost only). Authentication is configured. Model: ${modelName}.`,
                recommendation: 'Continue to keep bound to localhost. Periodically rotate access credentials.',
                tags: ['endpoint'],
                metadata: { port, binding, authStatus: 'configured', model: modelName, corsPermissive },
            });
        }
    }
    return findings;
}
module.exports = { scan };
