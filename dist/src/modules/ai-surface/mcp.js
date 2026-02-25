'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const net = require('net');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { execSync } = require('child_process');
const { globSync } = require('glob');
const HOME = os.homedir();
const CONFIG_PATHS = [
    path.join(HOME, '.cursor', 'mcp.json'),
    path.join(HOME, '.claude', 'mcp.json'),
    path.join(process.cwd(), 'mcp.json'),
];
const RISKY_TOOL_KEYWORDS = ['filesystem', 'shell', 'database', 'sql', 'exec'];
function safeJson(filePath) {
    try {
        return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    }
    catch {
        return null;
    }
}
function normalizeServers(config) {
    if (!config || typeof config !== 'object')
        return [];
    if (Array.isArray(config.servers)) {
        return config.servers.map((server, idx) => ({
            name: server.name || `server-${idx + 1}`,
            endpoint: server.endpoint || server.url || server.host || '',
            auth: server.auth || server.apiKey || server.token || server.headers,
            tools: server.tools || [],
        }));
    }
    if (config.mcpServers && typeof config.mcpServers === 'object') {
        return Object.entries(config.mcpServers).map(([name, server]) => ({
            name,
            endpoint: server.url || server.endpoint || server.host || '',
            auth: server.auth || server.apiKey || server.token || server.headers,
            tools: server.tools || [],
        }));
    }
    return [];
}
function parseEndpoint(endpoint) {
    const normalized = String(endpoint || '').trim();
    if (!normalized)
        return { host: '', port: null, protocol: '' };
    try {
        const hasProto = normalized.startsWith('http://') || normalized.startsWith('https://');
        const url = new URL(hasProto ? normalized : `http://${normalized}`);
        return { host: url.hostname, port: Number(url.port || 80), protocol: url.protocol.replace(':', '') };
    }
    catch {
        return { host: '', port: null, protocol: '' };
    }
}
function isPublicHost(host) {
    if (!host)
        return false;
    return !['127.0.0.1', 'localhost', '::1'].includes(host);
}
function hasAuth(server) {
    return Boolean(server.auth);
}
function riskFromTools(tools) {
    const normalized = Array.isArray(tools) ? tools.map((t) => String(t).toLowerCase()) : [];
    const risky = normalized.filter((tool) => RISKY_TOOL_KEYWORDS.some((keyword) => tool.includes(keyword)));
    if (risky.length > 0)
        return { risk: 'high', riskyTools: risky };
    return { risk: 'low', riskyTools: [] };
}
function processList() {
    try {
        return execSync('ps -ewwo pid,args 2>/dev/null || ps aux 2>/dev/null', {
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
        }).toString().toLowerCase();
    }
    catch {
        return '';
    }
}
function checkPortOpen(port, host = '127.0.0.1') {
    return new Promise((resolve) => {
        if (!port)
            return resolve(false);
        const sock = new net.Socket();
        sock.setTimeout(700);
        sock.on('connect', () => {
            sock.destroy();
            resolve(true);
        });
        sock.on('error', () => {
            sock.destroy();
            resolve(false);
        });
        sock.on('timeout', () => {
            sock.destroy();
            resolve(false);
        });
        sock.connect(port, host);
    });
}
function findPublicListeners() {
    try {
        const output = execSync('ss -tulpen 2>/dev/null || netstat -tulpen 2>/dev/null', {
            stdio: ['ignore', 'pipe', 'ignore'],
            timeout: 8000,
        }).toString();
        return output
            .split('\n')
            .filter((line) => line.includes('0.0.0.0') && line.toLowerCase().includes('mcp'))
            .map((line) => line.trim());
    }
    catch {
        return [];
    }
}
function loadConfigFiles() {
    const files = new Set(CONFIG_PATHS.filter((p) => fs.existsSync(p)));
    const mcpConfigRoot = path.join(HOME, '.config', 'mcp');
    if (fs.existsSync(mcpConfigRoot)) {
        const configGlob = globSync('**/*', {
            cwd: mcpConfigRoot,
            absolute: true,
            nodir: true,
            maxDepth: 3,
        });
        for (const cfg of configGlob)
            files.add(cfg);
    }
    return [...files];
}
async function scan() {
    const findings = [];
    const procs = processList();
    const configFiles = loadConfigFiles();
    for (const configPath of configFiles) {
        const config = safeJson(configPath);
        const servers = normalizeServers(config);
        for (const server of servers) {
            const endpoint = parseEndpoint(server.endpoint);
            const running = endpoint.port ? await checkPortOpen(endpoint.port, ['127.0.0.1', 'localhost'].includes(endpoint.host) ? '127.0.0.1' : endpoint.host) : false;
            const processMatched = procs.includes(server.name.toLowerCase()) || (server.endpoint && procs.includes(String(server.endpoint).toLowerCase()));
            const authConfigured = hasAuth(server);
            const exposure = isPublicHost(endpoint.host) || endpoint.host === '0.0.0.0' ? 'public' : 'localhost';
            const toolRisk = riskFromTools(server.tools);
            const severity = endpoint.host === '0.0.0.0'
                ? 'critical'
                : (toolRisk.risk === 'high' || !authConfigured || exposure === 'public')
                    ? 'high'
                    : 'low';
            findings.push({
                title: `MCP server: ${server.name}`,
                severity,
                location: `${server.endpoint || 'unknown-endpoint'} (${configPath})`,
                detail: `running=${running || processMatched}, endpointScope=${exposure}, auth=${authConfigured ? 'configured' : 'missing'}, riskyTools=${toolRisk.riskyTools.join(', ') || 'none'}`,
                recommendation: authConfigured
                    ? 'Keep endpoint local-only and minimize high-risk tools.'
                    : 'Enable authentication and avoid public bindings for MCP servers.',
                tags: ['mcp', 'server-security'],
                metadata: {
                    name: server.name,
                    endpoint: server.endpoint,
                    authConfigured,
                    toolExposure: toolRisk.risk,
                    running: running || processMatched,
                },
            });
        }
    }
    for (const line of findPublicListeners()) {
        findings.push({
            title: 'MCP server listening on 0.0.0.0',
            severity: 'critical',
            location: line,
            detail: 'Detected MCP-related listener bound to all network interfaces.',
            recommendation: 'Bind to localhost only and place behind authenticated gateway if remote access is required.',
            tags: ['mcp', 'public-exposure'],
        });
    }
    if (!findings.length) {
        findings.push({
            title: 'No MCP server findings',
            severity: 'low',
            location: 'MCP config paths',
            detail: 'No active MCP server risks detected in known config and listener locations.',
            recommendation: 'Continue periodic MCP configuration review.',
            tags: ['mcp'],
        });
    }
    for (const configPath of configFiles) {
        if (safeJson(configPath) === null) {
            findings.push({
                title: 'Unreadable MCP config file',
                severity: 'medium',
                location: configPath,
                detail: 'MCP config exists but could not be parsed as JSON.',
                recommendation: 'Validate JSON format and ensure expected MCP schema.',
                tags: ['mcp', 'config-issue'],
            });
        }
    }
    return { findings };
}
module.exports = { scan };
