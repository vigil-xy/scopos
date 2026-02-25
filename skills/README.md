# Scopos Governance Skills

A governance skill is a single `.js` file dropped into this `skills/` directory.

Scopos auto-discovers every `.js` file in this folder and runs valid skills during governance scans.

## Skill contract

Your skill must export:

```js
module.exports = {
  name: 'Your Skill Name',
  description: 'What this skill checks',
  version: '0.1.0',
  async run(context) {
    return {
      findings: [
        {
          title: 'Finding title',
          severity: 'low', // critical|high|medium|low
          location: 'where-it-was-found',
          detail: 'what happened',
          recommendation: 'what to do next',
          tags: ['governance', 'custom-skill'],
          metadata: {}
        }
      ]
    };
  }
};
```

## Required export fields

- `name` (string)
- `description` (string)
- `version` (string)
- `run(context)` (function)

`run()` should return a standardized findings array through either:
- `{ findings: [...] }`, or
- `[...]`

## How skills are used

- Skills are loaded automatically by `scopos govern` and full `scopos scan` governance phase.
- Skill findings are included in governance output and report signatures.
- Skill findings can influence readiness score if your organization maps them into policy.

## Start quickly

Use [template.skill.js](template.skill.js) as a starter, then run:

```bash
scopos skills --list
scopos govern
```
