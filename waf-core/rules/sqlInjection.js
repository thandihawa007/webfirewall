/**
 * SQL Injection Detection Rules
 * Contains realistic patterns for:
 * 1. Quote / comment injection
 * 2. UNION-based injection
 * 3. OR-condition authentication bypass (e.g. ' OR '1'='1)
 * 4. Stacked query injection
 */

const sqlInjectionRules = [
  {
    pattern: /(?:'|%27|")(?:[\s\+;]*)(?:--|#|\/\*)/i,
    label: 'Quote and Comment Injection'
  },
  {
    pattern: /\bunion\s+(?:all\s+)?select\b/i,
    label: 'UNION-Based Injection'
  },
  {
    pattern: /(?:'|%27|")?\s*\b(?:or|and)\b\s+(?:'[^']*'?|"[^"]*"?|\d+)\s*=\s*(?:'[^']*'?|"[^"]*"?|\d+)/i,
    label: 'OR-Condition Bypass'
  },
  {
    pattern: /;\s*(?:select|insert|update|delete|drop|truncate|alter|create|exec|execute|grant)\b/i,
    label: 'Stacked Query Injection'
  }
];

module.exports = sqlInjectionRules;
