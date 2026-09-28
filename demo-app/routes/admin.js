const express = require('express');
const router = express.Router();
const BlockedRequest = require('../models/BlockedRequest');

/**
 * GET /admin/blocked-requests
 * Returns the 50 most recent BlockedRequest documents from MongoDB, sorted newest first.
 */
router.get('/blocked-requests', async (req, res) => {
  try {
    const blockedRequests = await BlockedRequest.find()
      .sort({ timestamp: -1 })
      .limit(50)
      .lean();

    return res.status(200).json({
      success: true,
      count: blockedRequests.length,
      data: blockedRequests
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

/**
 * GET /admin/stats
 * Computes analytics using proper MongoDB aggregation pipelines:
 * Returns {
 *   totalBlocked: number,
 *   attackTypeBreakdown: { SQLi: number, XSS: number, PathTraversal: number },
 *   topAttackingIPs: [{ ip: string, count: number }]
 * }
 */
router.get('/stats', async (req, res) => {
  try {
    const [aggregated] = await BlockedRequest.aggregate([
      {
        $facet: {
          totalCount: [
            { $count: 'total' }
          ],
          attackTypeBreakdown: [
            {
              $group: {
                _id: '$category',
                count: { $sum: 1 }
              }
            }
          ],
          topAttackingIPs: [
            {
              $group: {
                _id: '$ip',
                count: { $sum: 1 }
              }
            },
            {
              $sort: { count: -1 }
            },
            {
              $limit: 10
            },
            {
              $project: {
                _id: 0,
                ip: '$_id',
                count: 1
              }
            }
          ]
        }
      }
    ]);

    const totalBlocked = aggregated?.totalCount?.[0]?.total || 0;

    // Structured breakdown object with default zeros
    const attackTypeBreakdown = {
      SQLi: 0,
      XSS: 0,
      PathTraversal: 0
    };

    if (Array.isArray(aggregated?.attackTypeBreakdown)) {
      for (const item of aggregated.attackTypeBreakdown) {
        if (Object.prototype.hasOwnProperty.call(attackTypeBreakdown, item._id)) {
          attackTypeBreakdown[item._id] = item.count;
        }
      }
    }

    const topAttackingIPs = aggregated?.topAttackingIPs || [];

    return res.status(200).json({
      totalBlocked,
      attackTypeBreakdown,
      topAttackingIPs
    });
  } catch (error) {
    return res.status(500).json({
      success: false,
      error: error.message
    });
  }
});

module.exports = router;
