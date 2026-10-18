require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const rateLimit = require('express-rate-limit');
const { createProxyMiddleware } = require('http-proxy-middleware');

const {
  db,
  getUserByUsername,
  getUserByEmail,
  getUserById,
  registerUser,
  listUsers,
  setUserActive,
  createSite,
  getSites,
  getSiteById,
  updateSite,
  deleteSite,
  recordSiteRequest,
  recordAttackLog,
  recordLoginAttempt,
  getOverviewStats,
  getTimeseriesStats,
  getAttackTypesStats,
  getTopIpsStats,
  getLogs,
  getAllLogsForExport
} = require('./db');

const { validateTargetUrl } = require('./lib/ssrf');

const app = express();
const PORT = process.env.PORT || 3000;
const IS_PROD = process.env.NODE_ENV === 'production';

// JWT Secret validation: required and must be at least 32 characters long
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('[Fatal Error] JWT_SECRET environment variable is required and must be at least 32 characters long.');
  process.exit(1);
}

// Trust proxy so req.ip reflects real client IP behind reverse proxies (Render / Railway / Docker)
app.set('trust proxy', 1);

// Standard Cookie configurations
const COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: IS_PROD,
  maxAge: 8 * 60 * 60 * 1000
};

const CLEAR_COOKIE_OPTIONS = {
  httpOnly: true,
  sameSite: 'lax',
  secure: IS_PROD
};

// Health check endpoint for Render / Railway / orchestrators
app.get('/healthz', (req, res) => {
  return res.json({ ok: true });
});

// -----------------------------------------------------------------------------
// 1. Core Security & Middleware
// -----------------------------------------------------------------------------

// Helmet headers (allowing inline animations on public frontend)
app.use(helmet({
  contentSecurityPolicy: false
}));

// CORS restricted to same-origin
app.use(cors({
  origin: true,
  credentials: true
}));

app.use(cookieParser());

// Body Parsers (support up to 10mb for WAF inspection & monitor mode; size limits enforced by Droplet WAF)
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// -----------------------------------------------------------------------------
// 2. WAF Detection Engine (SQLi, XSS, Path Traversal, Bot, DDoS, Oversized Body)
// -----------------------------------------------------------------------------

const WAF_RULES = require('./lib/rules');
const { scanValue } = require('./lib/normalize');

const ACTIVE_RULES_COUNT = WAF_RULES.length + 2; // Rules + DDoS limiter + Oversized Body policy

// DDoS Tracker: sliding 60-second window per site+IP
const ipRateLimitWindow = new Map();

function checkDDoS(siteKey, ip) {
  const key = `${siteKey}:${ip}`;
  const now = Date.now();
  const windowMs = 60 * 1000;
  const limit = 100; // max 100 req/min per IP
  let timestamps = ipRateLimitWindow.get(key) || [];
  timestamps = timestamps.filter(t => now - t < windowMs);
  timestamps.push(now);
  ipRateLimitWindow.set(key, timestamps);
  return timestamps.length > limit;
}

function getCleanIp(req) {
  const rawIp = req.ip || req.socket?.remoteAddress || '127.0.0.1';
  return String(rawIp).replace(/^::ffff:/, '').trim();
}

function getBodySize(req) {
  const headerLen = req.headers['content-length'];
  if (headerLen) {
    const parsed = parseInt(headerLen, 10);
    if (!isNaN(parsed) && parsed > 0) return parsed;
  }
  if (req.body) {
    if (Buffer.isBuffer(req.body)) return req.body.length;
    if (typeof req.body === 'string') return Buffer.byteLength(req.body);
    if (typeof req.body === 'object' && Object.keys(req.body).length > 0) {
      return Buffer.byteLength(JSON.stringify(req.body));
    }
  }
  return 0;
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// -----------------------------------------------------------------------------
// 3. Reverse Proxy Route (/p/:siteId and /p/:siteId/*)
// -----------------------------------------------------------------------------

app.all(['/p/:siteId', '/p/:siteId/*'], async (req, res, next) => {
  const siteId = Number(req.params.siteId);
  if (!siteId) {
    return res.status(404).send('Invalid site identifier.');
  }

  const site = getSiteById(siteId);
  if (!site) {
    return res.status(404).send('Site not found or not configured.');
  }

  if (site.owner_active === 0) {
    return res.status(403).send('Site owner account is disabled.');
  }

  const clientIp = getCleanIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const reqPath = req.originalUrl || req.url;
  const isBlockMode = site.mode === 'Block';

  // 1. SSRF Re-check on every proxied request
  const ssrfCheck = await validateTargetUrl(site.target_url);
  if (!ssrfCheck.valid) {
    return res.status(403).send(`
      <!DOCTYPE html>
      <html><head><title>Blocked by Droplet</title></head>
      <body style="background:#020509;color:#fff;font-family:monospace;padding:50px;text-align:center;">
        <h1 style="color:#C8FF3C;">Blocked by Droplet</h1>
        <p>Target destination is unreachable or violates internal network policies (SSRF Protection).</p>
      </body></html>
    `);
  }

  // 2. Per-Site Rate Limiting (DDoS: > 100 requests/min per IP)
  if (checkDDoS(site.id, clientIp)) {
    recordAttackLog({
      site_id: site.id,
      user_id: site.user_id,
      ip: clientIp,
      type: 'DDoS',
      path: reqPath,
      method: req.method,
      user_agent: userAgent,
      status: 'BLOCKED'
    });
    return res.status(403).send(`
      <!DOCTYPE html>
      <html><head><title>Blocked by Droplet</title></head>
      <body style="background:#020509;color:#fff;font-family:monospace;padding:50px;text-align:center;">
        <h1 style="color:#C8FF3C;">Blocked by Droplet</h1>
        <p>Request rate limit exceeded for this site (DDoS protection triggered).</p>
      </body></html>
    `);
  }

  // 3. Body Size Enforcement (Max 10KB = 10,240 bytes)
  const bodySize = getBodySize(req);
  if (bodySize > 10 * 1024) {
    if (isBlockMode) {
      recordAttackLog({
        site_id: site.id,
        user_id: site.user_id,
        ip: clientIp,
        type: 'Oversized Body',
        path: reqPath,
        method: req.method,
        user_agent: userAgent,
        status: 'BLOCKED'
      });

      return res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Blocked by Droplet</title></head>
        <body style="background:#020509;color:#ffffff;font-family:ui-monospace,monospace;display:flex;height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box;">
          <div style="background:rgba(10,14,20,0.85);border:1px solid #C8FF3C;border-radius:14px;padding:36px;max-width:460px;width:100%;text-align:center;box-shadow:0 0 40px rgba(200,255,60,0.2);">
            <div style="font-size:2.2rem;margin-bottom:12px;">🛡️</div>
            <h1 style="color:#C8FF3C;margin:0 0 10px;font-size:1.6rem;letter-spacing:0.06em;text-transform:uppercase;">BLOCKED BY DROPLET</h1>
            <p style="opacity:0.8;font-size:0.88rem;line-height:1.6;margin:0 0 20px;">Request payload exceeds the maximum allowed body size of 10KB.</p>
            <div style="margin:20px 0;padding:12px;background:rgba(200,255,60,0.08);color:#C8FF3C;font-size:0.82rem;border-radius:6px;font-weight:700;border:1px solid rgba(200,255,60,0.25);">
              Threat Category: Oversized Body (Payload > 10KB)
            </div>
            <p style="opacity:0.5;font-size:0.75rem;margin:20px 0 0;">Droplet Protected Reverse Proxy &bull; Real-time Threat Shield</p>
          </div>
        </body>
        </html>
      `);
    } else {
      recordAttackLog({
        site_id: site.id,
        user_id: site.user_id,
        ip: clientIp,
        type: 'Oversized Body',
        path: reqPath,
        method: req.method,
        user_agent: userAgent,
        status: 'MONITORED'
      });
    }
  }

  // 4. Inspect for Bot User-Agent
  let violation = null;
  const botRule = WAF_RULES.find(r => r.type === 'Bot');
  if (botRule && botRule.regex.test(userAgent)) {
    violation = botRule;
  }

  // 5. Inspect payload (URL, Query, Body, Headers) with WAF rules & evasion handling
  if (!violation) {
    violation = scanValue(reqPath, WAF_RULES, false);
  }
  if (!violation && req.query) {
    violation = scanValue(req.query, WAF_RULES, true);
  }
  if (!violation && req.body) {
    violation = scanValue(req.body, WAF_RULES, false);
  }

  // 6. Action upon inspection result
  if (violation) {
    if (isBlockMode) {
      recordAttackLog({
        site_id: site.id,
        user_id: site.user_id,
        ip: clientIp,
        type: violation.type,
        path: reqPath,
        method: req.method,
        user_agent: userAgent,
        status: 'BLOCKED'
      });

      return res.status(403).send(`
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>Blocked by Droplet</title>
        </head>
        <body style="background:#020509;color:#ffffff;font-family:ui-monospace,monospace;display:flex;height:100vh;align-items:center;justify-content:center;margin:0;padding:20px;box-sizing:border-box;">
          <div style="background:rgba(10,14,20,0.85);border:1px solid #C8FF3C;border-radius:14px;padding:36px;max-width:460px;width:100%;text-align:center;box-shadow:0 0 40px rgba(200,255,60,0.2);">
            <div style="font-size:2.2rem;margin-bottom:12px;">🛡️</div>
            <h1 style="color:#C8FF3C;margin:0 0 10px;font-size:1.6rem;letter-spacing:0.06em;text-transform:uppercase;">BLOCKED BY DROPLET</h1>
            <p style="opacity:0.8;font-size:0.88rem;line-height:1.6;margin:0 0 20px;">This request was inspected by Droplet and blocked before reaching the origin server.</p>
            <div style="margin:20px 0;padding:12px;background:rgba(200,255,60,0.08);color:#C8FF3C;font-size:0.82rem;border-radius:6px;font-weight:700;border:1px solid rgba(200,255,60,0.25);">
              Threat Category: ${escapeHtml(violation.type)} (${escapeHtml(violation.name)})
            </div>
            <p style="opacity:0.5;font-size:0.75rem;margin:20px 0 0;">Droplet Protected Reverse Proxy &bull; Real-time Threat Shield</p>
          </div>
        </body>
        </html>
      `);
    } else {
      // Monitor Mode: Log threat, but allow through
      recordAttackLog({
        site_id: site.id,
        user_id: site.user_id,
        ip: clientIp,
        type: violation.type,
        path: reqPath,
        method: req.method,
        user_agent: userAgent,
        status: 'MONITORED'
      });
    }
  } else {
    // Clean request: record allowed traffic
    recordSiteRequest(site.id, site.user_id, 'ALLOWED');
  }

  // 7. Forward clean / monitored request to target_url
  const prefixRegex = new RegExp(`^/p/${site.id}`);
  const proxy = createProxyMiddleware({
    target: site.target_url,
    changeOrigin: true,
    followRedirects: false, // Prevent SSRF redirect bypass
    pathRewrite: (pathStr) => {
      const rewritten = pathStr.replace(prefixRegex, '') || '/';
      return rewritten;
    },
    on: {
      proxyReq: (proxyReq, reqObj) => {
        // Forward client identification headers to destination
        proxyReq.setHeader('X-Forwarded-For', clientIp);
        proxyReq.setHeader('X-Forwarded-Host', reqObj.get('host') || '');
        proxyReq.setHeader('X-Forwarded-Proto', reqObj.protocol);
        proxyReq.setHeader('X-Real-IP', clientIp);

        // Re-stream parsed body if present
        if (reqObj.body && Object.keys(reqObj.body).length > 0) {
          const contentType = reqObj.headers['content-type'] || 'application/json';
          let bodyData;
          if (typeof reqObj.body === 'string' || Buffer.isBuffer(reqObj.body)) {
            bodyData = reqObj.body;
          } else if (contentType.includes('application/json')) {
            bodyData = JSON.stringify(reqObj.body);
          } else if (contentType.includes('application/x-www-form-urlencoded')) {
            bodyData = new URLSearchParams(reqObj.body).toString();
          } else {
            bodyData = JSON.stringify(reqObj.body);
          }
          if (bodyData) {
            proxyReq.setHeader('Content-Length', Buffer.byteLength(bodyData));
            proxyReq.write(bodyData);
          }
        }
      },
      error: (err, reqObj, resObj) => {
        console.error('[Droplet Proxy Error]', err.message);
        if (!resObj.headersSent) {
          resObj.status(502).send('Bad Gateway: Unable to connect to destination server.');
        }
      }
    }
  });

  return proxy(req, res, next);
});

// -----------------------------------------------------------------------------
// 4. Global Droplet Middleware (For Non-Proxy Traffic & Direct Tests)
// -----------------------------------------------------------------------------

function dropletGlobalWaf(req, res, next) {
  // Skip health check and static assets
  if (req.path === '/healthz' || req.path === '/chart.umd.js' || req.path.startsWith('/public/')) {
    return next();
  }

  const clientIp = getCleanIp(req);
  const userAgent = req.headers['user-agent'] || 'Unknown';
  const reqPath = req.originalUrl || req.path;

  // 1. Global Rate Limiting (DDoS: > 100 requests/min per IP on public/traffic routes)
  if (!req.path.startsWith('/api/') && checkDDoS('global', clientIp)) {
    recordAttackLog({
      site_id: null,
      user_id: null,
      ip: clientIp,
      type: 'DDoS',
      path: reqPath,
      method: req.method,
      user_agent: userAgent,
      status: 'BLOCKED'
    });
    return res.status(403).json({
      ok: false,
      error: 'Request rate limit exceeded (DDoS protection triggered)',
      type: 'DDoS'
    });
  }

  // 2. Check body size (Max 10KB)
  if (getBodySize(req) > 10 * 1024) {
    recordAttackLog({
      site_id: null,
      user_id: null,
      ip: clientIp,
      type: 'Oversized Body',
      path: reqPath,
      method: req.method,
      user_agent: userAgent,
      status: 'BLOCKED'
    });
    return res.status(403).json({
      ok: false,
      error: 'Request blocked by Droplet',
      type: 'Oversized Body',
      rule: 'Body size exceeds 10KB limit'
    });
  }

  // 3. Inspect for Bot User-Agent
  let violation = null;
  const botRule = WAF_RULES.find(r => r.type === 'Bot');
  if (botRule && botRule.regex.test(userAgent)) {
    violation = botRule;
  }

  // 4. Inspect payload (URL, Query, Body) with WAF rules & evasion handling
  if (!violation) violation = scanValue(reqPath, WAF_RULES, false);
  if (!violation && req.query) violation = scanValue(req.query, WAF_RULES, true);
  if (!violation && req.body) violation = scanValue(req.body, WAF_RULES, false);

  if (violation) {
    recordAttackLog({
      site_id: null,
      user_id: null,
      ip: clientIp,
      type: violation.type,
      path: reqPath,
      method: req.method,
      user_agent: userAgent,
      status: 'BLOCKED'
    });
    return res.status(403).json({
      ok: false,
      error: 'Request blocked by Droplet',
      type: violation.type,
      rule: violation.name
    });
  }

  next();
}

app.use(dropletGlobalWaf);

// Serve static frontend files from /public
app.use(express.static(path.join(__dirname, 'public')));

// -----------------------------------------------------------------------------
// 5. Auth Middleware
// -----------------------------------------------------------------------------

function requireAuth(req, res, next) {
  const token = req.cookies?.token;
  if (!token) {
    return res.status(401).json({ ok: false, error: 'Authentication required' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const user = getUserById(decoded.id);

    if (!user || user.active === 0) {
      res.clearCookie('token', CLEAR_COOKIE_OPTIONS);
      return res.status(401).json({ ok: false, error: 'User session expired or account disabled' });
    }

    req.user = user;
    next();
  } catch (_) {
    return res.status(401).json({ ok: false, error: 'Invalid or expired session' });
  }
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ ok: false, error: 'Administrator access required' });
  }
  next();
}

// Rate Limiter for Login & Registration
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { ok: false, error: 'Too many attempts, try again later' }
});

// -----------------------------------------------------------------------------
// 6. User Authentication & Registration APIs
// -----------------------------------------------------------------------------

// POST /api/register
app.post('/api/register', authLimiter, (req, res) => {
  const { username, email, password } = req.body || {};

  if (!username || typeof username !== 'string' || username.trim().length < 3) {
    return res.status(400).json({ ok: false, error: 'Username must be at least 3 characters' });
  }

  if (!email || typeof email !== 'string' || !email.includes('@') || !email.includes('.')) {
    return res.status(400).json({ ok: false, error: 'Valid email address is required' });
  }

  if (!password || typeof password !== 'string' || password.length < 8) {
    return res.status(400).json({ ok: false, error: 'Password must be at least 8 characters' });
  }

  const cleanUser = username.trim();
  const cleanEmail = email.trim().toLowerCase();

  if (getUserByUsername(cleanUser)) {
    return res.status(400).json({ ok: false, error: 'Username is already taken' });
  }

  if (getUserByEmail(cleanEmail)) {
    return res.status(400).json({ ok: false, error: 'Email is already registered' });
  }

  try {
    const passwordHash = bcrypt.hashSync(password, 12);
    const newUser = registerUser({
      username: cleanUser,
      email: cleanEmail,
      passwordHash,
      role: 'user'
    });

    // Auto-login newly registered user
    const token = jwt.sign(
      { id: newUser.id, username: newUser.username, role: newUser.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.cookie('token', token, COOKIE_OPTIONS);

    return res.status(201).json({
      ok: true,
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: 'Registration failed: ' + err.message });
  }
});

// POST /api/login
app.post('/api/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  const clientIp = getCleanIp(req);

  if (!username || !password || typeof username !== 'string' || typeof password !== 'string') {
    recordLoginAttempt({ username: username || null, ip: clientIp, success: false });
    return res.status(401).json({ ok: false, error: 'Invalid credentials' });
  }

  try {
    const user = getUserByUsername(username.trim());

    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      recordLoginAttempt({ username, ip: clientIp, success: false });
      return res.status(401).json({ ok: false, error: 'Invalid credentials' });
    }

    if (user.active === 0) {
      recordLoginAttempt({ username, ip: clientIp, success: false });
      return res.status(401).json({ ok: false, error: 'Account disabled. Contact administrator.' });
    }

    recordLoginAttempt({ username, ip: clientIp, success: true });

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.cookie('token', token, COOKIE_OPTIONS);

    return res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role
      }
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: 'Login error: ' + err.message });
  }
});

// POST /api/logout
app.post('/api/logout', (req, res) => {
  res.clearCookie('token', CLEAR_COOKIE_OPTIONS);
  return res.json({ ok: true, message: 'Logged out successfully' });
});

// GET /api/me
app.get('/api/me', requireAuth, (req, res) => {
  return res.json({
    ok: true,
    user: {
      id: req.user.id,
      username: req.user.username,
      email: req.user.email,
      role: req.user.role
    }
  });
});

// -----------------------------------------------------------------------------
// 7. Sites Management APIs
// -----------------------------------------------------------------------------

// GET /api/sites
app.get('/api/sites', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const sites = getSites(req.user.id, isAdmin);
  const host = req.get('host');
  const protocol = req.protocol;

  const sitesWithUrl = sites.map(s => ({
    ...s,
    protected_url: `${protocol}://${host}/p/${s.id}/`
  }));

  return res.json({ ok: true, sites: sitesWithUrl });
});

// POST /api/sites
app.post('/api/sites', requireAuth, async (req, res) => {
  const { name, target_url, mode } = req.body || {};

  if (!name || typeof name !== 'string' || !name.trim()) {
    return res.status(400).json({ ok: false, error: 'Site name is required' });
  }

  // Enforce mandatory SSRF Protection
  const ssrfValidation = await validateTargetUrl(target_url);
  if (!ssrfValidation.valid) {
    return res.status(400).json({ ok: false, error: ssrfValidation.error });
  }

  const validMode = mode === 'Monitor' ? 'Monitor' : 'Block';

  try {
    const site = createSite({
      user_id: req.user.id,
      name: name.trim(),
      target_url: target_url.trim(),
      mode: validMode
    });

    const host = req.get('host');
    const protocol = req.protocol;

    return res.status(201).json({
      ok: true,
      site: {
        ...site,
        protected_url: `${protocol}://${host}/p/${site.id}/`
      }
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: 'Failed to create site: ' + err.message });
  }
});

// PATCH /api/sites/:id
app.patch('/api/sites/:id', requireAuth, async (req, res) => {
  const siteId = Number(req.params.id);
  const site = getSiteById(siteId);

  if (!site) {
    return res.status(404).json({ ok: false, error: 'Site not found' });
  }

  if (req.user.role !== 'admin' && site.user_id !== req.user.id) {
    return res.status(404).json({ ok: false, error: 'Site not found' });
  }

  const { name, target_url, mode } = req.body || {};

  if (target_url) {
    const ssrfValidation = await validateTargetUrl(target_url);
    if (!ssrfValidation.valid) {
      return res.status(400).json({ ok: false, error: ssrfValidation.error });
    }
  }

  const validMode = mode ? (mode === 'Monitor' ? 'Monitor' : 'Block') : site.mode;

  try {
    const updated = updateSite(siteId, {
      name: name ? name.trim() : site.name,
      target_url: target_url ? target_url.trim() : site.target_url,
      mode: validMode
    });

    const host = req.get('host');
    const protocol = req.protocol;

    return res.json({
      ok: true,
      site: {
        ...updated,
        protected_url: `${protocol}://${host}/p/${updated.id}/`
      }
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: err.message });
  }
});

// DELETE /api/sites/:id
app.delete('/api/sites/:id', requireAuth, (req, res) => {
  const siteId = Number(req.params.id);
  const site = getSiteById(siteId);

  if (!site) {
    return res.status(404).json({ ok: false, error: 'Site not found' });
  }

  if (req.user.role !== 'admin' && site.user_id !== req.user.id) {
    return res.status(404).json({ ok: false, error: 'Site not found' });
  }

  deleteSite(siteId);
  return res.json({ ok: true, message: 'Site deleted successfully' });
});

// -----------------------------------------------------------------------------
// 8. Analytics & Log APIs
// -----------------------------------------------------------------------------

// GET /api/stats/overview?site=
app.get('/api/stats/overview', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const siteId = req.query.site ? Number(req.query.site) : null;

  if (siteId && !isAdmin) {
    const site = getSiteById(siteId);
    if (!site || site.user_id !== req.user.id) {
      return res.status(404).json({ ok: false, error: 'Site not found' });
    }
  }

  const stats = getOverviewStats(req.user.id, isAdmin, siteId);
  return res.json({ ok: true, data: stats });
});

// GET /api/stats/timeseries?site=
app.get('/api/stats/timeseries', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const siteId = req.query.site ? Number(req.query.site) : null;

  if (siteId && !isAdmin) {
    const site = getSiteById(siteId);
    if (!site || site.user_id !== req.user.id) {
      return res.status(404).json({ ok: false, error: 'Site not found' });
    }
  }

  const timeseries = getTimeseriesStats(req.user.id, isAdmin, siteId);
  return res.json({ ok: true, data: timeseries });
});

// GET /api/stats/types?site=&range=
app.get('/api/stats/types', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const siteId = req.query.site ? Number(req.query.site) : null;
  const range = req.query.range || null;

  if (siteId && !isAdmin) {
    const site = getSiteById(siteId);
    if (!site || site.user_id !== req.user.id) {
      return res.status(404).json({ ok: false, error: 'Site not found' });
    }
  }

  const typesData = getAttackTypesStats(req.user.id, isAdmin, siteId, range);
  return res.json({ ok: true, data: typesData });
});

// GET /api/stats/top-ips?site=
app.get('/api/stats/top-ips', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const siteId = req.query.site ? Number(req.query.site) : null;

  if (siteId && !isAdmin) {
    const site = getSiteById(siteId);
    if (!site || site.user_id !== req.user.id) {
      return res.status(404).json({ ok: false, error: 'Site not found' });
    }
  }

  const topIps = getTopIpsStats(req.user.id, isAdmin, siteId);
  return res.json({ ok: true, data: topIps });
});

// GET /api/logs?site=&type=&status=&search=&from=&to=&page=&limit=
app.get('/api/logs', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const { site, type, status, search, from, to, page, limit } = req.query;

  const siteId = site ? Number(site) : null;
  if (siteId && !isAdmin) {
    const s = getSiteById(siteId);
    if (!s || s.user_id !== req.user.id) {
      return res.status(404).json({ ok: false, error: 'Site not found' });
    }
  }

  const result = getLogs(req.user.id, isAdmin, {
    site_id: siteId,
    type,
    status,
    search,
    from,
    to,
    page,
    limit
  });

  return res.json({ ok: true, ...result });
});

// GET /api/logs/export.csv
app.get('/api/logs/export.csv', requireAuth, (req, res) => {
  const isAdmin = req.user.role === 'admin';
  const { site, type, status, search, from, to } = req.query;

  const siteId = site ? Number(site) : null;
  if (siteId && !isAdmin) {
    const s = getSiteById(siteId);
    if (!s || s.user_id !== req.user.id) {
      return res.status(404).send('Site not found');
    }
  }

  const logs = getAllLogsForExport(req.user.id, isAdmin, {
    site_id: siteId,
    type,
    status,
    search,
    from,
    to
  });

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="droplet-attack-logs.csv"');

  const header = ['ID', 'Time', 'Site', 'IP', 'Method', 'Type', 'Path', 'Status', 'User Agent'];
  const rows = [header.join(',')];

  logs.forEach(l => {
    const values = [
      l.id,
      `"${l.time}"`,
      `"${(l.site_name || 'Direct/Global').replace(/"/g, '""')}"`,
      `"${l.ip}"`,
      `"${l.method || 'GET'}"`,
      `"${l.type}"`,
      `"${(l.path || '').replace(/"/g, '""')}"`,
      `"${l.status}"`,
      `"${(l.user_agent || '').replace(/"/g, '""')}"`
    ];
    rows.push(values.join(','));
  });

  return res.send(rows.join('\n'));
});

// -----------------------------------------------------------------------------
// 9. Admin User Management APIs
// -----------------------------------------------------------------------------

// GET /api/users (Admin only)
app.get('/api/users', requireAuth, requireAdmin, (req, res) => {
  const users = listUsers();
  return res.json({ ok: true, users });
});

// PATCH /api/users/:id (Admin only)
app.patch('/api/users/:id', requireAuth, requireAdmin, (req, res) => {
  const targetId = Number(req.params.id);
  const targetUser = getUserById(targetId);

  if (!targetUser) {
    return res.status(404).json({ ok: false, error: 'User not found' });
  }

  // Prevent disabling self
  if (targetId === req.user.id && req.body.active === false) {
    return res.status(400).json({ ok: false, error: 'Cannot deactivate your own administrative account' });
  }

  if (req.body.active !== undefined) {
    setUserActive(targetId, !!req.body.active);
  }

  const updatedUser = getUserById(targetId);
  return res.json({ ok: true, user: updatedUser });
});

// -----------------------------------------------------------------------------
// 10. Start Server
// -----------------------------------------------------------------------------

app.use((req, res) => {
  res.status(404).json({ ok: false, error: 'Not found' });
});

app.listen(PORT, () => {
  console.log(`[Droplet] Server listening on http://localhost:${PORT}`);
  console.log(`[Droplet] Protected with ${ACTIVE_RULES_COUNT} active security rules`);
});
