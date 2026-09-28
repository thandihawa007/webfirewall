const express = require('express');
const router = express.Router();

/**
 * POST /demo/login
 * Bait endpoint for testing SQL injection attacks.
 * Accepts { username, password } and validates that both are non-empty strings.
 */
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};

  if (
    typeof username !== 'string' ||
    username.trim() === '' ||
    typeof password !== 'string' ||
    password.trim() === ''
  ) {
    return res.status(400).json({
      success: false,
      message: 'Both username and password must be non-empty strings.'
    });
  }

  // Simulated authentication check (for legitimate requests)
  if (username === 'admin' && password === 'secret123') {
    return res.status(200).json({
      success: true,
      message: 'Authentication successful. Welcome, admin!',
      user: {
        username: 'admin',
        role: 'administrator'
      }
    });
  }

  return res.status(401).json({
    success: false,
    message: 'Invalid username or password.'
  });
});

/**
 * POST /demo/comment
 * Bait endpoint for testing XSS attacks.
 * Accepts { comment } and echoes it back in the JSON response.
 */
router.post('/comment', (req, res) => {
  const { comment } = req.body || {};

  if (typeof comment !== 'string' || comment.trim() === '') {
    return res.status(400).json({
      success: false,
      message: 'Comment must be a non-empty string.'
    });
  }

  return res.status(200).json({
    success: true,
    comment: comment
  });
});

/**
 * ALL /demo/file
 * Bait endpoint for testing Path Traversal attacks.
 * Accepts ?path=... query parameter or POST body { path }.
 */
router.all('/file', (req, res) => {
  const filePath = req.query.path || (req.body && req.body.path);

  if (!filePath || typeof filePath !== 'string' || filePath.trim() === '') {
    return res.status(400).json({
      success: false,
      message: 'File path parameter is required.'
    });
  }

  // Simulated safe file response (for legitimate requests)
  return res.status(200).json({
    success: true,
    message: 'File retrieved successfully.',
    path: filePath,
    content: 'Simulated file stream: Document content rendered safely.'
  });
});

module.exports = router;

