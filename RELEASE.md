# Scopos Release Checklist

This checklist is for publishing `vigil-scopos` to npm.

## 1) Preflight

- Ensure you are on `main` and up to date.
- Ensure working tree is clean.
- Ensure npm auth is valid (`npm whoami`).
- Ensure package name/version in `package.json` are correct.

## 2) Local sanity checks

```bash
npm ci
npm run release:check
node bin/scopos.js scan --module apikeys --json > /tmp/scopos-smoke.json
node bin/scopos.js verify /tmp/scopos-smoke.json
```

## 3) Inspect npm package contents

```bash
npm run pack:check
```

Optional full tarball creation:

```bash
npm pack
```

## 4) Version bump

Choose one:

```bash
npm version patch
npm version minor
npm version major
```

## 5) Publish

```bash
npm publish --access public
```

## 6) Post-publish validation

```bash
npm view vigil-scopos version
npm view vigil-scopos dist-tags
```

Quick install test:

```bash
npm install -g vigil-scopos
scopos --help
```

## 7) Optional GitHub release notes

Include:
- New/updated scan coverage
- Governance skill updates
- Signature/report format changes
- Breaking changes (if any)
