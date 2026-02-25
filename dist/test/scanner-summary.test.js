"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const strict_1 = __importDefault(require("node:assert/strict"));
const reporter = require('../src/modules/core/reporter.js');
const scanner = require('../src/modules/core/scanner.js');
(0, node_test_1.test)('computeSummary prioritizes critical over other severities', () => {
    const summary = reporter.computeSummary([
        { severity: 'medium' },
        { severity: 'high' },
        { severity: 'critical' },
        { severity: 'low' },
    ]);
    strict_1.default.equal(summary.riskLevel, 'critical');
    strict_1.default.equal(summary.totalIssues, 4);
    strict_1.default.equal(summary.counts.critical, 1);
    strict_1.default.equal(summary.counts.high, 1);
    strict_1.default.equal(summary.counts.medium, 1);
    strict_1.default.equal(summary.counts.low, 1);
});
(0, node_test_1.test)('runScan throws for unknown module names', async () => {
    await strict_1.default.rejects(async () => {
        await scanner.runScan({ module: 'unknown-module' });
    }, /Unknown module/);
});
