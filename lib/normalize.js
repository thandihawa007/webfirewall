/**
 * WAF Normalization & Evasion Handling
 * Normalizes values against common WAF evasion techniques prior to rule matching.
 */

function decodeHtmlEntities(str) {
  if (!str || typeof str !== 'string') return '';
  return str
    .replace(/&#x([0-9a-f]+);?/gi, (_, hex) => {
      try { return String.fromCharCode(parseInt(hex, 16)); } catch (_) { return ''; }
    })
    .replace(/&#([0-9]+);?/g, (_, dec) => {
      try { return String.fromCharCode(parseInt(dec, 10)); } catch (_) { return ''; }
    })
    .replace(/&quot;/gi, '"')
    .replace(/&apos;/gi, "'")
    .replace(/&#39;/g, "'")
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&amp;/gi, '&');
}

/**
 * Normalizes an inspected string:
 * 1. Convert + to space in query strings
 * 2. Remove null bytes
 * 3. Decode percent-encoding repeatedly (max 3 passes)
 * 4. Decode HTML entities
 * 5. Normalize unicode (NFKC)
 * 6. Strip SQL comments (/* *\/, --, #)
 * 7. Lowercase
 * 8. Collapse whitespace
 */
function normalizeValue(val, isQuery = false) {
  if (val === null || val === undefined) return '';
  let s = String(val);

  // 1. Convert + to space if in query strings
  if (isQuery) {
    s = s.replace(/\+/g, ' ');
  }

  // 2. Remove null bytes
  s = s.replace(/\0|%00/gi, '');

  // 3. Decode percent-encoding repeatedly (max 3 passes)
  for (let i = 0; i < 3; i++) {
    try {
      const decoded = decodeURIComponent(s);
      if (decoded === s) break;
      s = decoded;
    } catch (_) {
      break;
    }
  }

  // 4. Decode HTML entities
  s = decodeHtmlEntities(s);

  // 5. Normalize unicode (NFKC)
  try {
    s = s.normalize('NFKC');
  } catch (_) {}

  // 6. Strip SQL comments (/* ... */, --, #)
  s = s.replace(/\/\*[\s\S]*?\*\//g, ' ');
  s = s.replace(/--[^\r\n]*/g, ' ');
  s = s.replace(/#[^\r\n]*/g, ' ');

  // 7. Lowercase
  s = s.toLowerCase();

  // 8. Collapse whitespace
  s = s.replace(/\s+/g, ' ').trim();

  return s;
}

/**
 * Recursively inspects a value (string, array, or object) against the rule set.
 * Tests BOTH raw and normalized representations.
 */
function scanValue(val, rules, isQuery = false, visited = new WeakSet()) {
  if (val === null || val === undefined) return null;

  if (typeof val === 'string') {
    // 1. Match against raw value
    for (const rule of rules) {
      if (rule.regex.test(val)) return rule;
    }

    // 2. Match against normalized representation
    const normalized = normalizeValue(val, isQuery);
    if (normalized && normalized !== val) {
      for (const rule of rules) {
        if (rule.regex.test(normalized)) return rule;
      }
    }

    return null;
  }

  if (typeof val === 'object') {
    if (visited.has(val)) return null;
    visited.add(val);

    if (Array.isArray(val)) {
      for (const item of val) {
        const match = scanValue(item, rules, isQuery, visited);
        if (match) return match;
      }
      return null;
    }

    for (const key of Object.keys(val)) {
      const keyMatch = scanValue(key, rules, isQuery, visited);
      if (keyMatch) return keyMatch;
      const valMatch = scanValue(val[key], rules, isQuery, visited);
      if (valMatch) return valMatch;
    }
  }

  return null;
}

module.exports = {
  normalizeValue,
  decodeHtmlEntities,
  scanValue
};
