'use strict';

module.exports = {
  name: 'Template Governance Skill',
  description: 'Starter skill example for Scopos governance contributions',
  version: '0.1.0',
  async run() {
    return {
      findings: [
        {
          title: 'Template skill executed',
          severity: 'low',
          location: 'skills/template.skill.js',
          detail: 'Replace this with your own checks.',
          recommendation: 'Customize this skill for your governance controls.',
          tags: ['governance', 'custom-skill'],
          metadata: { template: true },
        },
      ],
    };
  },
};
