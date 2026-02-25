'use strict';

const { execSync } = require('child_process');
const os = require('os');
const path = require('path');

const HOME = os.homedir();

const AGENT_KEYWORDS = [
  { name: 'LangChain',      keyword: 'langchain'   },
  { name: 'AutoGPT',        keyword: 'autogpt'     },
  { name: 'CrewAI',         keyword: 'crewai'      },
  { name: 'AgentGPT',       keyword: 'agentgpt'    },
  { name: 'BabyAGI',        keyword: 'babyagi'     },
  { name: 'OpenDevin',      keyword: 'opendevin'   },
  { name: 'Aider',          keyword: 'aider'       },
  { name: 'Claude Desktop', keyword: 'claude'      },
  { name: 'Cursor',         keyword: 'cursor'      },
  { name: 'Continue',       keyword: 'continue'    },
  { name: 'Cline',          keyword: 'cline'       },
  { name: 'Goose',          keyword: 'goose'       },
];

const SENSITIVE_DIRS = [
  path.join(HOME, '.ssh'),
  '/etc',
  path.join(HOME, '.config'),
  path.join(HOME, '.aws'),
  path.join(HOME, '.kube'),
  '/var/lib/postgresql',
  '/var/lib/mysql',
  '/var/lib/mongodb',
];

function getFullProcessList() {
  try {
    if (process.platform === 'win32') {
      return execSync('tasklist /v /fo csv 2>nul', { stdio: ['ignore', 'pipe', 'ignore'], timeout: 8000 }).toString();
    }
    return execSync('ps -ewwo pid,user,args 2>/dev/null || ps aux 2>/dev/null',
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 8000 }).toString();
  } catch { return ''; }
}

function parseProcessList(output) {
  return output.split('\n').slice(1).map(line => {
    const parts = line.trim().split(/\s+/);
    if (parts.length < 3) return null;
    return { pid: parts[0], user: parts[1], cmd: parts.slice(2).join(' ') };
  }).filter(Boolean);
}

function isElevated(user) {
  if (!user) return false;
  return user === 'root' || user === 'SYSTEM' || user === 'Administrator';
}

function hasNetworkConnections(pid) {
  try {
    const out = execSync(`lsof -p ${pid} -i -n -P 2>/dev/null | grep -v LISTEN`,
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
    return out.trim().length > 0;
  } catch { return false; }
}

function hasSensitiveDirAccess(pid) {
  try {
    const out = execSync(`lsof -p ${pid} 2>/dev/null`,
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
    return SENSITIVE_DIRS.some(d => out.includes(d));
  } catch { return false; }
}

function isRunningFromTemp(cmd) {
  return ['/tmp/', '/var/tmp/', '/temp/', os.tmpdir()].some(t => cmd.includes(t));
}

function parseWorkingDir(pid) {
  try {
    return require('fs').readlinkSync(`/proc/${pid}/cwd`);
  } catch {
    return '';
  }
}

function hasFilesystemAccessBeyondWorkingDir(pid, cwd) {
  try {
    const out = execSync(`lsof -p ${pid} 2>/dev/null`,
      { stdio: ['ignore', 'pipe', 'ignore'], timeout: 5000 }).toString();
    const lines = out.split('\n').slice(1);
    return lines.some((line) => {
      const parts = line.trim().split(/\s+/);
      const filePath = parts[parts.length - 1] || '';
      if (!filePath.startsWith('/')) return false;
      if (!cwd) return true;
      return !filePath.startsWith(cwd);
    });
  } catch {
    return false;
  }
}

async function scan() {
  const findings = [];
  const processes = parseProcessList(getFullProcessList());

  for (const { name, keyword } of AGENT_KEYWORDS) {
    const matching = processes.filter(p => p.cmd.toLowerCase().includes(keyword.toLowerCase()));

    for (const proc of matching) {
      const elevated  = isElevated(proc.user);
      const fromTemp  = isRunningFromTemp(proc.cmd);
      let hasNet      = false;
      let hasSensitive = false;
      let broadFsAccess = false;
      const cwd = parseWorkingDir(proc.pid);

      try {
        hasNet       = hasNetworkConnections(proc.pid);
        hasSensitive = hasSensitiveDirAccess(proc.pid);
        broadFsAccess = hasFilesystemAccessBeyondWorkingDir(proc.pid, cwd);
      } catch { /* lsof unavailable */ }

      if (elevated) {
        findings.push({
          title: `${name} agent running as root/elevated user`,
          severity: 'critical',
          location: `PID ${proc.pid} (user: ${proc.user})`,
          detail: `Process: ${proc.cmd.slice(0, 120)}`,
          recommendation: `Stop ${name} and restart as a non-privileged user. AI agents must never run as root.`,
          tags: ['agent', 'elevated-privilege', 'unauthorized-ai-process'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      }

      if (hasNet && hasSensitive) {
        findings.push({
          title: `${name} agent has both network AND sensitive filesystem access`,
          severity: 'critical',
          location: `PID ${proc.pid}`,
          detail: `Outbound network connections detected AND open file handles to sensitive directories. Highest-risk configuration for data exfiltration.`,
          recommendation: `Sandbox ${name} with firejail or Docker to restrict filesystem and network access.`,
          tags: ['agent', 'network', 'filesystem', 'exfiltration-risk'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      } else if (hasSensitive) {
        findings.push({
          title: `${name} agent has access to sensitive directories`,
          severity: 'high',
          location: `PID ${proc.pid}`,
          detail: `Open file handles to sensitive directories (~/.ssh, /etc, or database paths).`,
          recommendation: `Restrict ${name}'s working directory. Run in a container or chroot.`,
          tags: ['agent', 'filesystem-access'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      } else if (hasNet) {
        findings.push({
          title: `${name} agent has active outbound network connections`,
          severity: 'medium',
          location: `PID ${proc.pid}`,
          detail: `Outbound network connections active. Ensure only approved API endpoints are reachable.`,
          recommendation: 'Use a network policy or proxy to restrict which endpoints this agent can reach.',
          tags: ['agent', 'network-access'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      }

      if (hasNet && broadFsAccess) {
        findings.push({
          title: `${name} agent has network + broad filesystem access beyond working directory`,
          severity: 'critical',
          location: `PID ${proc.pid}`,
          detail: `This agent can access files beyond ${cwd || 'its cwd'} while maintaining outbound connectivity.`,
          recommendation: 'Constrain filesystem mounts and egress for this process.',
          tags: ['agent', 'network', 'filesystem', 'beyond-working-dir'],
          metadata: { process: proc.cmd, pid: proc.pid, workingDirectory: cwd || null },
        });
      }

      if (fromTemp) {
        findings.push({
          title: `${name} agent running from a temp directory`,
          severity: 'high',
          location: `PID ${proc.pid}`,
          detail: `Running from: ${proc.cmd.slice(0, 100)}. May indicate a downloaded-and-run attack.`,
          recommendation: 'Investigate origin. Legitimate AI agents do not run from temp directories.',
          tags: ['agent', 'temp-execution'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      }

      if (!elevated && !hasNet && !hasSensitive && !fromTemp) {
        findings.push({
          title: `${name} agent process detected`,
          severity: 'low',
          location: `PID ${proc.pid} (user: ${proc.user})`,
          detail: 'Running normally. No elevated risk factors detected.',
          recommendation: 'Continue monitoring. Ensure this agent is approved for use.',
          tags: ['agent'],
          metadata: { process: proc.cmd, pid: proc.pid, user: proc.user },
        });
      }
    }
  }

  return findings;
}

module.exports = { scan };
export {};
