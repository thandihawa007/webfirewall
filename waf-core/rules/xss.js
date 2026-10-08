/**
 * Cross-Site Scripting (XSS) Detection Rules
 * Contains realistic patterns for:
 * 1. Script tag injection
 * 2. javascript: protocol usage
 * 3. Inline event handlers (onerror=, onload=, etc.)
 * 4. Iframe injection
 */

const xssRules = [
  {
    pattern: /<script\b[^>]*>(?:[\s\S]*?<\/script>)?/i,
    label: 'Script Tag Injection'
  },
  {
    pattern: /(?:javascript|vbscript|data)\s*:[^\s"']*/i,
    label: 'JavaScript Protocol Usage'
  },
  {
    pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|change|keydown|keyup)\s*=\s*(?:'[^']*'|"[^"]*"|[^\s>]+)/i,
    label: 'Inline Event Handler'
  },
  {
    pattern: /<iframe\b[^>]*>(?:[\s\S]*?<\/iframe>)?/i,
    label: 'Iframe Injection'
  }
];

module.exports = xssRules;
