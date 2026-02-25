'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const BASE_DIR = path.join(os.homedir(), '.scopos');
const KEY_DIR = path.join(BASE_DIR, 'keys');
const PRIVATE_KEY_PATH = path.join(KEY_DIR, 'private.pem');
const PUBLIC_KEY_PATH = path.join(KEY_DIR, 'public.pem');

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) fs.mkdirSync(dirPath, { recursive: true });
}

function stableStringify(input) {
  if (input === null || input === undefined) return JSON.stringify(input);
  if (typeof input !== 'object') return JSON.stringify(input);
  if (Array.isArray(input)) return `[${input.map(stableStringify).join(',')}]`;
  const keys = Object.keys(input).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${stableStringify(input[k])}`).join(',')}}`;
}

function sha256Hex(payload) {
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function generateKeyPair(force = false) {
  ensureDir(KEY_DIR);
  if (!force && fs.existsSync(PRIVATE_KEY_PATH) && fs.existsSync(PUBLIC_KEY_PATH)) {
    return { privateKeyPath: PRIVATE_KEY_PATH, publicKeyPath: PUBLIC_KEY_PATH };
  }

  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(PRIVATE_KEY_PATH, privateKey.export({ format: 'pem', type: 'pkcs8' }), 'utf8');
  fs.writeFileSync(PUBLIC_KEY_PATH, publicKey.export({ format: 'pem', type: 'spki' }), 'utf8');
  return { privateKeyPath: PRIVATE_KEY_PATH, publicKeyPath: PUBLIC_KEY_PATH };
}

function ensureKeyPair() {
  if (!fs.existsSync(PRIVATE_KEY_PATH) || !fs.existsSync(PUBLIC_KEY_PATH)) {
    return generateKeyPair(false);
  }
  return { privateKeyPath: PRIVATE_KEY_PATH, publicKeyPath: PUBLIC_KEY_PATH };
}

function signReportPayload(reportPayload) {
  const keyInfo = ensureKeyPair();
  const privateKey = fs.readFileSync(keyInfo.privateKeyPath, 'utf8');
  const publicKey = fs.readFileSync(keyInfo.publicKeyPath, 'utf8');

  const canonicalPayload = stableStringify(reportPayload);
  const hash = sha256Hex(canonicalPayload);
  const signature = crypto.sign(null, Buffer.from(hash, 'utf8'), privateKey).toString('base64');

  return {
    algorithm: 'Ed25519',
    hash,
    signature,
    publicKey,
    publicKeyLocation: PUBLIC_KEY_PATH,
    timestamp: new Date().toISOString(),
  };
}

function verifySignedReport(signedReport) {
  if (!signedReport || typeof signedReport !== 'object') {
    return { ok: false, reason: 'Invalid report format' };
  }

  if (!signedReport.report || !signedReport.signature) {
    return { ok: false, reason: 'Missing report or signature field' };
  }

  const canonicalPayload = stableStringify(signedReport.report);
  const hash = sha256Hex(canonicalPayload);
  if (hash !== signedReport.signature.hash) {
    return { ok: false, reason: 'SHA-256 hash mismatch', signature: signedReport.signature };
  }

  const publicKey = signedReport.signature.publicKey || fs.readFileSync(PUBLIC_KEY_PATH, 'utf8');
  const signatureBuffer = Buffer.from(signedReport.signature.signature, 'base64');
  const isValid = crypto.verify(null, Buffer.from(hash, 'utf8'), publicKey, signatureBuffer);

  if (!isValid) {
    return { ok: false, reason: 'Ed25519 signature mismatch', signature: signedReport.signature };
  }

  return { ok: true, signature: signedReport.signature };
}

function verifyReportFile(reportPath) {
  const raw = fs.readFileSync(reportPath, 'utf8');
  const parsed = JSON.parse(raw);
  return verifySignedReport(parsed);
}

module.exports = {
  BASE_DIR,
  KEY_DIR,
  PRIVATE_KEY_PATH,
  PUBLIC_KEY_PATH,
  ensureKeyPair,
  generateKeyPair,
  signReportPayload,
  verifySignedReport,
  verifyReportFile,
};
