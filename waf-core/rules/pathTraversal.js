/**
 * Path Traversal Detection Rules
 * Contains realistic patterns for:
 * 1. Directory climb using ../ or ..\
 * 2. URL-encoded variants like %2e%2e/
 * 3. Known sensitive file targets like /etc/passwd or windows/system32
 */

const pathTraversalRules = [
  {
    pattern: /(?:\.\.[\/\\])/,
    label: 'Directory Climb (../)'
  },
  {
    pattern: /(?:%2e|\.){2}(?:%2f|%5c|\/|\\)/i,
    label: 'URL-Encoded Traversal Sequence (%2e%2e/)'
  },
  {
    pattern: /(?:\/etc\/(?:passwd|shadow|hosts|group)|\/proc\/self\/|\bwindows[\/\\]system32|\/windows\/win\.ini|\/boot\.ini)/i,
    label: 'Sensitive System File Target'
  }
];

module.exports = pathTraversalRules;
