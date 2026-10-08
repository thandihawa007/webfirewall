const mongoose = require('mongoose');

/**
 * Saves a blocked request event into MongoDB via Mongoose.
 *
 * @param {Object} details
 * @param {string} details.ip - Client IP address
 * @param {Date} [details.timestamp] - Event timestamp
 * @param {string} details.ruleTriggered - Triggered rule label
 * @param {string} details.category - Threat category (SQLi, XSS, PathTraversal)
 * @param {string} details.path - Request path
 * @param {string} details.payload - Actual malicious string that was caught
 */
async function logBlockedRequest(details) {
  try {
    const BlockedRequest =
      mongoose.models.BlockedRequest || require('../demo-app/models/BlockedRequest');

    const blockedEntry = new BlockedRequest({
      ip: details.ip,
      timestamp: details.timestamp || new Date(),
      ruleTriggered: details.ruleTriggered,
      category: details.category,
      path: details.path,
      payload: String(details.payload)
    });

    return await blockedEntry.save();
  } catch (error) {
    console.error('[WAF Logger] Failed to persist blocked request to MongoDB:', error.message);
  }
}

module.exports = {
  logBlockedRequest
};
