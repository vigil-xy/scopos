# 🔍 scopos

**AI attack surface scanner** — audits your environment for exposed LLM keys, running AI agents, MCP servers, local models, inference endpoints, shadow IT, and governance violations.

## Install

```bash
git clone https://github.com/vigil-xy/scopos.git
cd scopos && npm install
```

## Usage

```bash
# Full scan
node bin/scopos.js scan

# Export JSON report
node bin/scopos.js scan -o report.json

# Verify tamper-evident audit chain
node bin/scopos.js audit
```

## What it scans

| Module | Checks |
|--------|--------|
| `api-keys` | Leaked LLM keys in env, dotfiles, shell history |
| `agents` | Running/installed AI agent frameworks |
| `mcp` | Exposed MCP server ports and Unix sockets |
| `models` | Local model files missing checksums |
| `endpoints` | Inference endpoints exposed without auth |
| `governance/shadowIT` | Unapproved AI tools and packages |
| `governance/policyEnforcer` | PII in LLM proxy logs |
| `governance/auditAgent` | Tamper-evident audit chain integrity |

## Severity levels

| Icon | Level | Meaning |
|------|-------|---------|
| 🔴 | `critical` | Immediate action required |
| 🟠 | `high` | Should be addressed soon |
| 🟡 | `medium` | Review recommended |
| 🔵 | `low` | Informational risk |

## Audit chain

Every scan is recorded in a tamper-evident HMAC-SHA256 chain at `~/.scopos/audit-chain.json`. Run `node bin/scopos.js audit` to verify integrity at any time.

Set `SCOPOS_SECRET` env var to use a custom HMAC signing key.

## License

MIT