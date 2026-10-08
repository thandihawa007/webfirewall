const allRules = require('./rules');
const { logBlockedRequest } = require('./logger');

/**
 * Recursively scans data structures (objects, arrays, strings)
 * against all compiled WAF security rules.
 *
 * @param {any} target - Data object, array, or primitive to scan
 * @param {Array} rules - Array of { pattern, label, category }
 * @param {WeakSet} [visited] - Guard against circular references
 * @returns {{ rule: string, category: string, payload: string } | null}
 */
function scanForViolations(target, rules, visited = new WeakSet()) {
  if (target === null || target === undefined) {
    return null;
  }

  // Check strings
  if (typeof target === 'string') {
    // 1. Direct regex test
    for (const rule of rules) {
      if (rule.pattern.test(target)) {
        return {
          rule: rule.label,
          category: rule.category,
          payload: target
        };
      }
    }

    // 2. Test URL-decoded string if it differs from raw
    try {
      const decoded = decodeURIComponent(target);
      if (decoded !== target) {
        for (const rule of rules) {
          if (rule.pattern.test(decoded)) {
            return {
              rule: rule.label,
              category: rule.category,
              payload: target
            };
          }
        }
      }
    } catch (_) {
      // Ignore invalid URL-encoding errors and proceed
    }

    return null;
  }

  // Handle nested objects and arrays
  if (typeof target === 'object') {
    if (visited.has(target)) {
      return null;
    }
    visited.add(target);

    // Recursively check array items
    if (Array.isArray(target)) {
      for (const item of target) {
        const match = scanForViolations(item, rules, visited);
        if (match) return match;
      }
      return null;
    }

    // Recursively check object keys and values
    for (const key of Object.keys(target)) {
      const keyMatch = scanForViolations(key, rules, visited);
      if (keyMatch) return keyMatch;

      const valMatch = scanForViolations(target[key], rules, visited);
      if (valMatch) return valMatch;
    }
  }

  return null;
}

/**
 * Express middleware function for WAF protection.
 * Fails open if an internal error occurs.
 */
const wafMiddleware = async (req, res, next) => {
  try {
    const locationsToInspect = [
      { name: 'body', data: req.body },
      { name: 'query', data: req.query },
      { name: 'params', data: req.params }
    ];

    let violation = null;

    for (const loc of locationsToInspect) {
      if (loc.data) {
        violation = scanForViolations(loc.data, allRules);
        if (violation) break;
      }
    }

    if (violation) {
      const clientIp =
        req.ip ||
        req.headers?.['x-forwarded-for'] ||
        (req.socket && req.socket.remoteAddress) ||
        '127.0.0.1';

      const requestPath = req.path || req.originalUrl || '/';

      // Log blocked attempt to MongoDB
      await logBlockedRequest({
        ip: String(clientIp),
        timestamp: new Date(),
        ruleTriggered: violation.rule,
        category: violation.category,
        path: requestPath,
        payload: String(violation.payload)
      });

      // Respond with 403 Forbidden - do NOT call next()
      return res.status(403).json({
        error: 'Request blocked by WAF',
        rule: violation.rule,
        category: violation.category
      });
    }

    // No rules matched: proceed normally
    return next();
  } catch (error) {
    // Fail open: log the error and allow the request to proceed
    console.error('[WAF Engine Error] Inspection failed, failing open:', error);
    return next();
  }
};

module.exports = wafMiddleware;
