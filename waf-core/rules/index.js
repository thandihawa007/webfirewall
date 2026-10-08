/**
 * Combines all detection rule sets and tags each with its category (SQLi/XSS/PathTraversal).
 */

const sqlInjectionRules = require('./sqlInjection');
const xssRules = require('./xss');
const pathTraversalRules = require('./pathTraversal');

const allRules = [
  ...sqlInjectionRules.map(rule => ({ ...rule, category: 'SQLi' })),
  ...xssRules.map(rule => ({ ...rule, category: 'XSS' })),
  ...pathTraversalRules.map(rule => ({ ...rule, category: 'PathTraversal' }))
];

module.exports = allRules;
