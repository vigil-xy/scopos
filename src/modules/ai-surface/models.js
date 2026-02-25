'use strict';

const fs = require('fs');
const path = require('path');
const os = require('os');
const { glob } = require('glob');

const HOME = os.homedir();

const MODEL_SEARCH_DIRS = [
  path.join(HOME, '.ollama', 'models'),
  path.join(HOME, '.cache', 'huggingface'),
  path.join(HOME, 'models'),
  path.join(process.cwd(), 'models'),
  '/opt/models',
];

const MODEL_EXTENSIONS = ['.gguf', '.ggml', '.bin', '.safetensors', '.pt', '.pth', '.onnx', '.pkl', '.h5'];
const CHECKSUM_EXTENSIONS = ['.sha256', '.md5', '.sha512'];

const UNOFFICIAL_INDICATORS = [
  '/tmp/', '/temp/', '/downloads/', '/desktop/',
  'thebloke', 'uncensored', 'jailbreak', 'unfiltered',
];

const OFFICIAL_SOURCES = [
  '.ollama', 'huggingface', '.cache/huggingface', 'ollama',
];

function formatSize(bytes) {
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  return `${(bytes / 1e3).toFixed(1)} KB`;
}

function hasChecksumFile(filePath) {
  return CHECKSUM_EXTENSIONS.some(ext => fs.existsSync(filePath + ext));
}

function scanModelBinaryForUrls(filePath) {
  try {
    const fd = fs.openSync(filePath, 'r');
    const buf = Buffer.alloc(65536);
    const bytesRead = fs.readSync(fd, buf, 0, 65536, 0);
    fs.closeSync(fd);
    const content = buf.slice(0, bytesRead).toString('latin1');
    const urlPattern = /https?:\/\/(?!huggingface\.co|ollama\.ai|github\.com|pytorch\.org)[a-z0-9.\-]{4,50}\/[^\s"'<>]{0,100}/gi;
    return [...new Set(content.match(urlPattern) || [])].slice(0, 5);
  } catch { return []; }
}

function isLikelyUnofficial(filePath) {
  const lower = filePath.toLowerCase();
  return UNOFFICIAL_INDICATORS.some(i => lower.includes(i));
}

function isLikelyOfficial(filePath) {
  const lower = filePath.toLowerCase();
  return OFFICIAL_SOURCES.some(s => lower.includes(s));
}

async function scan() {
  const findings = [];
  let totalModels = 0;

  for (const dir of MODEL_SEARCH_DIRS) {
    if (!fs.existsSync(dir)) continue;

    let files;
    try {
      files = await glob(`**/*{${MODEL_EXTENSIONS.join(',')}}`, {
        cwd: dir,
        absolute: true,
        nodir: true,
        ignore: ['**/node_modules/**'],
      });
    } catch { continue; }

    for (const filePath of files) {
      let stat;
      try { stat = fs.statSync(filePath); } catch { continue; }

      totalModels++;
      const modelName = path.basename(filePath);
      const verified = hasChecksumFile(filePath);
      const unofficial = isLikelyUnofficial(filePath);
      const official = isLikelyOfficial(filePath);
      const size = formatSize(stat.size);

      let suspiciousUrls = [];
      if (stat.size < 200 * 1024 * 1024) {
        suspiciousUrls = scanModelBinaryForUrls(filePath);
      }

      if (suspiciousUrls.length > 0) {
        findings.push({
          title: `Model file contains suspicious embedded URLs: ${modelName}`,
          severity: 'high',
          location: filePath,
          detail: `Found ${suspiciousUrls.length} unexpected URL(s) in model binary: ${suspiciousUrls.slice(0, 3).join(', ')}`,
          recommendation: 'Do not load this model. Download it again from an official source and report the suspicious URLs.',
          tags: ['model', 'network-indicator'],
          metadata: { modelName, size, verificationStatus: verified ? 'verified' : 'unverified', source: official ? 'official' : 'unknown' },
        });
      }

      if (!verified && unofficial) {
        findings.push({
          title: `Unsigned model from unofficial source: ${modelName}`,
          severity: 'high',
          location: filePath,
          detail: `Model size: ${size}. No checksum file found. Path suggests unofficial/user download origin.`,
          recommendation: 'Verify this model against official checksums. Download from HuggingFace or Ollama official registry.',
          tags: ['model', 'unverified', 'unofficial-source'],
          metadata: { modelName, size, verificationStatus: 'unverified', source: 'non-official' },
        });
        continue;
      }

      if (!verified) {
        findings.push({
          title: `Model file has no checksum: ${modelName}`,
          severity: 'medium',
          location: filePath,
          detail: `Model size: ${size}. No .sha256, .md5, or .sha512 file found alongside this model.`,
          recommendation: `Download the official checksum for ${modelName} and create a .sha256 file next to the model.`,
          tags: ['model', 'unverified'],
          metadata: { modelName, size, verificationStatus: 'unverified', source: official ? 'official' : 'unknown' },
        });
        continue;
      }

      findings.push({
        title: `Model file verified: ${modelName}`,
        severity: 'low',
        location: filePath,
        detail: `Size: ${size}. Checksum present. Source: ${official ? 'official cache' : 'user directory'}.`,
        recommendation: 'Periodically re-verify checksums to detect corruption or tampering.',
        tags: ['model', 'verified'],
        metadata: { modelName, size, verificationStatus: 'verified', source: official ? 'official' : 'unknown' },
      });
    }
  }

  if (totalModels === 0) {
    findings.push({
      title: 'No local AI model files found',
      severity: 'low',
      location: MODEL_SEARCH_DIRS.join(', '),
      detail: 'No .gguf, .safetensors, .onnx, or other model files found in standard locations.',
      recommendation: 'No action needed.',
      tags: ['model'],
    });
  }

  return findings;
}

module.exports = { scan };