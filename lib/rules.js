/**
 * Droplet WAF Detection Rules
 * Clean array of { type, name, regex }
 */

const rules = [
  // ---------------------------------------------------------------------------
  // 1. SQL Injection (SQLi)
  // ---------------------------------------------------------------------------
  {
    type: 'SQLi',
    name: 'Boolean / Auth Bypass',
    regex: /(?:'|%27|")?\s*\b(?:or|and)\b\s+(?:'[^']*'?|"[^"]*"?|\d+)\s*=\s*(?:'[^']*'?|"[^"]*"?|\d+)/i
  },
  {
    type: 'SQLi',
    name: 'Quote and Comment Termination',
    regex: /(?:'|%27|")\s*(?:--|#|\/\*)/i
  },
  {
    type: 'SQLi',
    name: 'UNION SELECT Injection',
    regex: /\bunion\s+(?:all\s+)?select\b/i
  },
  {
    type: 'SQLi',
    name: 'Comment-Obfuscated UNION SELECT',
    regex: /\bun(?:\/\*[\s\S]*?\*\/)*ion\s+(?:all\s+)?(?:sel(?:\/\*[\s\S]*?\*\/)*ect)\b/i
  },
  {
    type: 'SQLi',
    name: 'Hex or Char Encoding Injection',
    regex: /(?:0x[0-9a-f]{2,}|\bchar\s*\(\s*\d+(?:\s*,\s*\d+)*\s*\)|\bconcat\s*\(|\bunhex\s*\()/i
  },
  {
    type: 'SQLi',
    name: 'Stacked Query Injection',
    regex: /;\s*(?:select|insert|update|delete|drop|truncate|alter|create|exec|execute|grant)\b/i
  },
  {
    type: 'SQLi',
    name: 'Time-Based or Benchmark Injection',
    regex: /\b(?:sleep\s*\(\s*\d+\s*\)|benchmark\s*\(\s*\d+\s*,|waitfor\s+delay\b|pg_sleep\s*\()/i
  },
  {
    type: 'SQLi',
    name: 'Database Metadata Access',
    regex: /\b(?:information_schema|sqlite_master|sys\.tables|sys\.objects)\b/i
  },

  // ---------------------------------------------------------------------------
  // 2. Cross-Site Scripting (XSS)
  // ---------------------------------------------------------------------------
  {
    type: 'XSS',
    name: 'Script Tag Injection',
    regex: /<\s*script\b[^>]*>(?:[\s\S]*?<\s*\/\s*script\s*>)?/i
  },
  {
    type: 'XSS',
    name: 'SVG / Tag Onload or Onerror Event',
    regex: /<\s*(?:svg|img|body|input|video|audio|object|embed|details)\b[^>]*\bon(?:error|load|click|mouseover|focus|blur|mouseenter)\s*=/i
  },
  {
    type: 'XSS',
    name: 'Inline Event Handler Injection',
    regex: /\bon(?:error|load|click|mouseover|focus|blur|submit|change|keydown|keyup|animationend)\s*=/i
  },
  {
    type: 'XSS',
    name: 'JavaScript / VBScript Pseudo-Protocol',
    regex: /(?:javascript|vbscript)\s*:[^\s"']*/i
  },
  {
    type: 'XSS',
    name: 'Dangerous Data URI',
    regex: /data\s*:\s*(?:text\/(?:html|javascript)|application\/(?:javascript|x-javascript))[^\s"']*/i
  },
  {
    type: 'XSS',
    name: 'Iframe or Embed Injection',
    regex: /<\s*(?:iframe|embed|object|applet)\b[^>]*>/i
  },

  // ---------------------------------------------------------------------------
  // 3. Path Traversal
  // ---------------------------------------------------------------------------
  {
    type: 'PathTraversal',
    name: 'Directory Traversal (../ or ..\\)',
    regex: /(?:\.\.[\/\\])/
  },
  {
    type: 'PathTraversal',
    name: 'URL-Encoded Traversal (%2e%2e)',
    regex: /(?:%2e|\.){2}(?:%2f|%5c|\/|\\)/i
  },
  {
    type: 'PathTraversal',
    name: 'Double-Encoded Traversal (%252e%252e)',
    regex: /(?:%252e){2}(?:%252f|%255c|%2f|%5c|\/|\\)/i
  },
  {
    type: 'PathTraversal',
    name: 'Backslash Variant Traversal',
    regex: /(?:\.\.\\|\.\.%5c|%2e%2e%5c)/i
  },
  {
    type: 'PathTraversal',
    name: 'Sensitive System Target',
    regex: /(?:\/etc\/(?:passwd|shadow|hosts|group)|\/proc\/self\/|\b(?:windows|winnt)[\/\\]system32|\/win\.ini|\/boot\.ini)/i
  },

  // ---------------------------------------------------------------------------
  // 4. Scanner Bots
  // ---------------------------------------------------------------------------
  {
    type: 'Bot',
    name: 'Known Malicious Scanner User-Agent',
    regex: /(?:sqlmap|nikto|dirbuster|nmap|masscan|wpscan|gobuster|hydra|acunetix|havij|zaproxy|arachni|netsparker|censys|shodan|badbot|morfeus|paros|webscarab)/i
  }
];

module.exports = rules;
