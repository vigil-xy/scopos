# Scopos

Scopos is the first security scanner built for AI infrastructure.

Scopos (`vigil-scopos`) is the AI-specific companion to `vigil-scan` in the Vigil security suite. It focuses exclusively on AI attack surface discovery, governance controls, and cryptographically signed reports.

## Install

```bash
npm install -g vigil-scopos
```

## Quick start

```bash
scopos scan
```

## What Scopos scans

1. **LLM API Key Exposure**
   - `.env` and shell profile secret leakage
   - Config files and `~/.config/**` scanning
   - Git history secret exposure checks (last 20 commits)

2. **MCP Server Security**
   - MCP config discovery (`~/.cursor/mcp.json`, `~/.claude/mcp.json`, `~/.config/mcp/**`, local `mcp.json`)
   - Endpoint scope (localhost vs public), auth status, and risky tool exposure
   - Public listener detection on `0.0.0.0`

3. **AI Agent Processes**
   - Detection of known agent frameworks and assistant runtimes
   - Elevated privilege checks, sensitive filesystem access, and outbound network behavior
   - Temp-directory execution detection

4. **Model File Integrity**
   - Local model inventory across common model directories
   - Verification checks for checksum presence
   - Source heuristics and suspicious network URL indicators in model binaries

5. **Inference Endpoint Exposure**
   - Common local inference server port scanning
   - Binding checks (`localhost` vs `0.0.0.0`)
   - Unauthenticated access tests, model identification, and permissive CORS checks

## Governance skills system

Scopos supports pluggable governance skills.

- Built-in skills:
  - Shadow IT Detector
  - Policy Enforcer (`scopos govern --watch`)
  - Automated Audit Agent (`scopos govern --audit-daemon`)
- Community skills:
  - Drop a `.js` file into `skills/`
  - Skills are auto-discovered and loaded
  - See `skills/README.md` and `skills/template.skill.js`

## Commands

```bash
scopos scan                          # Full AI security scan
scopos scan --json -o report.json    # JSON output to file
scopos scan --module apikeys         # Run single module only
scopos verify <report.json>          # Verify report signature
scopos keys --generate               # Generate new key pair
scopos keys --show-public            # Show public key
scopos govern --shadow-it            # Run Shadow IT scan
scopos govern --watch                # Start PII policy monitor
scopos govern --audit-daemon         # Start automated audit daemon
scopos audit --score                 # Show today's readiness score
scopos audit --history               # Show score history + trend
scopos skills --list                 # List all loaded governance skills
scopos skills --contribute           # Show instructions for contributing a skill
```

## Cryptographic signing

Every report is tamper-evident.

- Algorithm: Ed25519
- Key location:
  - `~/.scopos/keys/private.pem`
  - `~/.scopos/keys/public.pem`
- First run auto-generates keys if missing
- Report payload is hashed with SHA-256 before signing
- JSON reports embed hash, signature, algorithm, timestamp, and public key

Use verification:

```bash
scopos verify report.json
```

## Contributing a governance skill

1. Copy `skills/template.skill.js`
2. Rename it to your skill (for example `skills/my-team-policy.skill.js`)
3. Export: `{ name, description, version, run() }`
4. Return standardized findings from `run()`
5. Run `scopos skills --list` to confirm auto-loading

## Vigil suite

Scopos is part of the Vigil security suite. Use it alongside `vigil-scan` for complete host + AI surface coverage.

## Release

For publish steps and preflight checks, see `RELEASE.md`.

Quick preflight:

```bash
npm run release:check
```

## Development

Scopos is now TypeScript-first and compiles to `dist/`.

```bash
npm install
npm run typecheck
npm test
npm run build
node dist/bin/scopos.js --help
```
