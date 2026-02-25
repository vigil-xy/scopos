"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const node_test_1 = require("node:test");
const strict_1 = __importDefault(require("node:assert/strict"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_os_1 = __importDefault(require("node:os"));
const node_path_1 = __importDefault(require("node:path"));
function withTempHome(fn) {
    const tempHome = node_fs_1.default.mkdtempSync(node_path_1.default.join(node_os_1.default.tmpdir(), 'scopos-home-'));
    const originalHome = process.env.HOME;
    process.env.HOME = tempHome;
    try {
        return fn();
    }
    finally {
        if (originalHome) {
            process.env.HOME = originalHome;
        }
        else {
            delete process.env.HOME;
        }
        node_fs_1.default.rmSync(tempHome, { recursive: true, force: true });
    }
}
(0, node_test_1.test)('signs and verifies a report payload with Ed25519', () => {
    withTempHome(() => {
        const cryptoModule = require('../src/modules/core/crypto.js');
        const reportPayload = {
            metadata: { timestamp: new Date().toISOString(), hostname: 'test-host' },
            summary: { riskLevel: 'low', totalIssues: 0, counts: { critical: 0, high: 0, medium: 0, low: 0 } },
            modules: {},
            governance: { title: 'GOVERNANCE MODULES', findings: [] },
        };
        const signature = cryptoModule.signReportPayload(reportPayload);
        const verify = cryptoModule.verifySignedReport({ report: reportPayload, signature });
        strict_1.default.equal(signature.algorithm, 'Ed25519');
        strict_1.default.equal(typeof signature.hash, 'string');
        strict_1.default.equal(typeof signature.signature, 'string');
        strict_1.default.equal(verify.ok, true);
    });
});
