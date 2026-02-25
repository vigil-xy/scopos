'use strict';

const net  = require('net');
const path = require('path');
const fs   = require('fs');
const os   = require('os');

const MCP_PORTS    = [3000, 3001, 8811, 8080, 11434];
const MCP_SOCKETS  = [
  path.join(os.homedir(), '.mcp', 'server.sock'),
  '/tmp/mcp.sock',
  '/tmp/mcp-server.sock',
];

function checkPort(port) {
  return new Promise((resolve) => {
    const sock = new net.Socket();
    sock.setTimeout(500);
    sock.on('connect', () => { sock.destroy(); resolve(true);  });
    sock.on('error',   () => { sock.destroy(); resolve(false); });
    sock.on('timeout', () => { sock.destroy(); resolve(false); });
    sock.connect(port, '127.0.0.1');
  });
}

async function scan() {
  const findings = [];

  for (const port of MCP_PORTS) {
    const open = await checkPort(port);
    if (open) {
      findings.push({
        severity: 'high',
        message:  `MCP server port ${port} is open on localhost`,
        detail:   'Verify this is intentional and access-controlled',
      });
    }
  }

  for (const sock of MCP_SOCKETS) {
    if (fs.existsSync(sock)) {
      findings.push({
        severity: 'medium',
        message:  `MCP Unix socket found: ${sock}`,
        detail:   'Ensure socket permissions are restricted',
      });
    }
  }

  return { findings };
}

module.exports = { scan };