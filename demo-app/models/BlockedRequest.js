const mongoose = require('mongoose');

const blockedRequestSchema = new mongoose.Schema(
  {
    ip: {
      type: String,
      required: true,
      index: true
    },
    timestamp: {
      type: Date,
      default: Date.now,
      index: true
    },
    ruleTriggered: {
      type: String,
      required: true
    },
    category: {
      type: String,
      required: true,
      index: true
    },
    path: {
      type: String,
      required: true
    },
    payload: {
      type: String,
      required: true
    }
  },
  {
    versionKey: false
  }
);

module.exports = mongoose.model('BlockedRequest', blockedRequestSchema);
