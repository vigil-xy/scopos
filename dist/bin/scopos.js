#!/usr/bin/env node
'use strict';
Object.defineProperty(exports, "__esModule", { value: true });
const fs = require('fs');
const path = require('path');
const { Command } = require('commander');
const scanner = require('../src/modules/core/scanner');
const reporter = require('../src/modules/core/reporter');
const cryptoModule = require('../src/modules/core/crypto');
const governance = require('../src/modules/governance');
const auditAgent = require('../src/modules/governance/auditAgent');
const policyEnforcer = require('../src/modules/governance/policyEnforcer');
const program = new Command();
function writeJsonOut(payload, outputFile) {
    const json = JSON.stringify(payload, null, 2);
    if (outputFile) {
        fs.writeFileSync(path.resolve(outputFile), json, 'utf8');
        process.stdout.write(`Saved JSON report to ${path.resolve(outputFile)}\n`);
        return;
    }
    process.stdout.write(`${json}\n`);
}
async function handleScan(options) {
    process.stdout.write('🔍 Starting Scopos AI Security Scan...\n\n');
    const result = await scanner.runScan({ module: options.module || null });
    const signed = reporter.signReport(result);
    if (options.json) {
        writeJsonOut(signed, options.output);
        return;
    }
    process.stdout.write('✅ Report cryptographically signed\n\n');
    process.stdout.write(`${reporter.renderTextReport(signed)}\n`);
    if (options.output) {
        fs.writeFileSync(path.resolve(options.output), JSON.stringify(signed, null, 2), 'utf8');
        process.stdout.write(`\nSaved JSON report to ${path.resolve(options.output)}\n`);
    }
}
async function handleVerify(reportFile) {
    const resolved = path.resolve(reportFile);
    const verify = cryptoModule.verifyReportFile(resolved);
    if (!verify.ok) {
        process.stderr.write(`✖ Signature verification failed: ${verify.reason}\n`);
        process.exitCode = 1;
        return;
    }
    process.stdout.write('✔ Signature verification passed\n');
    process.stdout.write(`Report timestamp: ${verify.signature.timestamp}\n`);
    process.stdout.write(`Hash: ${verify.signature.hash}\n`);
}
async function handleKeys(options) {
    if (options.generate) {
        const keyInfo = cryptoModule.generateKeyPair(true);
        process.stdout.write(`Generated Ed25519 key pair\nPublic key: ${keyInfo.publicKeyPath}\n`);
        return;
    }
    if (options.showPublic) {
        const keyInfo = cryptoModule.ensureKeyPair();
        const publicPem = fs.readFileSync(keyInfo.publicKeyPath, 'utf8');
        process.stdout.write(`${publicPem}\n`);
        return;
    }
    process.stdout.write('Use --generate or --show-public\n');
}
async function handleGovern(options) {
    if (options.shadowIt) {
        const result = await governance.runShadowIT();
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        return;
    }
    if (options.watch) {
        process.stdout.write('Starting policy watch monitor. Press Ctrl+C to stop.\n');
        await policyEnforcer.startWatchMode();
        return;
    }
    if (options.auditDaemon) {
        process.stdout.write('Starting audit daemon. Scheduled daily at 06:00. Press Ctrl+C to stop.\n');
        await auditAgent.startDaemon();
        return;
    }
    const governanceReport = await governance.runGovernanceScan();
    process.stdout.write(`${JSON.stringify(governanceReport, null, 2)}\n`);
}
async function handleAudit(options) {
    if (options.score) {
        const score = await auditAgent.getTodayScore(true);
        process.stdout.write(`${JSON.stringify(score, null, 2)}\n`);
        return;
    }
    if (options.history) {
        const history = auditAgent.getHistory();
        process.stdout.write(`${JSON.stringify(history, null, 2)}\n`);
        return;
    }
    const score = await auditAgent.getTodayScore(false);
    process.stdout.write(`${JSON.stringify(score, null, 2)}\n`);
}
async function handleSkills(options) {
    if (options.list) {
        const loaded = governance.listSkills();
        process.stdout.write(`${JSON.stringify(loaded, null, 2)}\n`);
        return;
    }
    if (options.contribute) {
        const skillsReadme = path.join(process.cwd(), 'skills', 'README.md');
        process.stdout.write(`Contribute a skill by following: ${skillsReadme}\n`);
        return;
    }
    process.stdout.write('Use --list or --contribute\n');
}
program
    .name('scopos')
    .description('Scopos AI infrastructure security scanner')
    .version('0.1.0');
program
    .command('scan')
    .description('Full AI security scan')
    .option('--json', 'Emit JSON report')
    .option('-o, --output <file>', 'Write JSON report to file')
    .option('--module <name>', 'Run a single module (apikeys|mcp|agents|models|endpoints)')
    .action((options) => {
    handleScan(options).catch((err) => {
        process.stderr.write(`Scan failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
program
    .command('verify <reportFile>')
    .description('Verify report signature')
    .action((reportFile) => {
    handleVerify(reportFile).catch((err) => {
        process.stderr.write(`Verify failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
program
    .command('keys')
    .description('Manage Ed25519 keys')
    .option('--generate', 'Generate new key pair')
    .option('--show-public', 'Show public key')
    .action((options) => {
    handleKeys(options).catch((err) => {
        process.stderr.write(`Keys command failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
program
    .command('govern')
    .description('Governance module operations')
    .option('--shadow-it', 'Run Shadow IT scan')
    .option('--watch', 'Start PII policy monitor')
    .option('--audit-daemon', 'Start audit daemon')
    .action((options) => {
    handleGovern(options).catch((err) => {
        process.stderr.write(`Govern command failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
program
    .command('audit')
    .description('Readiness score and audit history')
    .option('--score', 'Show today\'s score')
    .option('--history', 'Show score history')
    .action((options) => {
    handleAudit(options).catch((err) => {
        process.stderr.write(`Audit command failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
program
    .command('skills')
    .description('Governance skills management')
    .option('--list', 'List loaded governance skills')
    .option('--contribute', 'Show contribution instructions')
    .action((options) => {
    handleSkills(options).catch((err) => {
        process.stderr.write(`Skills command failed: ${err.message}\n`);
        process.exitCode = 1;
    });
});
if (!process.argv.slice(2).length) {
    program.help();
}
program.parseAsync(process.argv);
