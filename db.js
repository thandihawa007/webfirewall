require('dotenv').config();
const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const dbFile = process.env.DB_PATH || path.join(__dirname, 'droplet.db');
const db = new Database(dbFile);

// Enable WAL mode for high concurrency
db.pragma('journal_mode = WAL');

// 1. Initialize Tables
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    active INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    target_url TEXT NOT NULL,
    mode TEXT NOT NULL DEFAULT 'Block',
    total_requests INTEGER NOT NULL DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER,
    user_id INTEGER,
    time TEXT NOT NULL,
    ip TEXT NOT NULL,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    method TEXT NOT NULL DEFAULT 'GET',
    user_agent TEXT,
    status TEXT NOT NULL DEFAULT 'BLOCKED',
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS site_traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    time TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'ALLOWED',
    FOREIGN KEY (site_id) REFERENCES sites(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    ip TEXT,
    success INTEGER NOT NULL,
    time TEXT NOT NULL
  );

  CREATE TABLE IF NOT EXISTS request_counter (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    total_requests INTEGER NOT NULL DEFAULT 0
  );
`);

// Migration helpers for pre-existing tables
function ensureColumn(table, column, definition) {
  try {
    const info = db.prepare(`PRAGMA table_info(${table})`).all();
    const hasCol = info.some(c => c.name.toLowerCase() === column.toLowerCase());
    if (!hasCol) {
      db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
  } catch (_) {}
}

ensureColumn('users', 'email', "TEXT DEFAULT 'user@droplet.local'");
ensureColumn('users', 'active', 'INTEGER DEFAULT 1');
ensureColumn('attack_logs', 'site_id', 'INTEGER');
ensureColumn('attack_logs', 'user_id', 'INTEGER');
ensureColumn('attack_logs', 'method', "TEXT DEFAULT 'GET'");
ensureColumn('attack_logs', 'user_agent', 'TEXT');

// Ensure request counter exists
const counterRow = db.prepare('SELECT total_requests FROM request_counter WHERE id = 1').get();
if (!counterRow) {
  db.prepare('INSERT INTO request_counter (id, total_requests) VALUES (1, 0)').run();
}

// 2. Seed Default Admin
function seedAdmin() {
  const adminUsername = process.env.ADMIN_USERNAME || 'admin';
  const existingAdmin = db.prepare('SELECT id, role, active, email FROM users WHERE username = ? COLLATE NOCASE').get(adminUsername);
  if (!existingAdmin) {
    let password = process.env.ADMIN_PASSWORD;
    let isGenerated = false;

    if (!password) {
      const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
      const bytes = crypto.randomBytes(16);
      password = '';
      for (let i = 0; i < 16; i++) {
        password += chars[bytes[i] % chars.length];
      }
      isGenerated = true;
    }

    const saltRounds = 12;
    const passwordHash = bcrypt.hashSync(password, saltRounds);

    db.prepare(`
      INSERT INTO users (username, email, password_hash, role, active)
      VALUES (?, ?, ?, ?, ?)
    `).run(adminUsername, `${adminUsername}@droplet.local`, passwordHash, 'admin', 1);

    if (isGenerated) {
      console.log('\n========================================================');
      console.log(' 🔑 [Droplet] Initial Admin Account Created');
      console.log(`    Username: ${adminUsername}`);
      console.log(`    Generated Password: ${password}`);
      console.log('    (Save this password! It will not be shown again.)');
      console.log('========================================================\n');
    } else {
      console.log(`[Database] Seeded initial admin user (username: "${adminUsername}").`);
    }
  } else {
    // Ensure admin user has role admin and active 1
    db.prepare("UPDATE users SET role = 'admin', active = 1 WHERE id = ?").run(existingAdmin.id);
  }
}
seedAdmin();

// -----------------------------------------------------------------------------
// Database Query Helpers
// -----------------------------------------------------------------------------

// Users
const stmtFindUserByUsername = db.prepare('SELECT * FROM users WHERE username = ? COLLATE NOCASE');
const stmtFindUserByEmail = db.prepare('SELECT * FROM users WHERE email = ? COLLATE NOCASE');
const stmtFindUserById = db.prepare('SELECT id, username, email, role, active, created_at FROM users WHERE id = ?');
const stmtInsertUser = db.prepare(`
  INSERT INTO users (username, email, password_hash, role, active)
  VALUES (?, ?, ?, ?, 1)
`);
const stmtListAllUsers = db.prepare(`
  SELECT u.id, u.username, u.email, u.role, u.active, u.created_at,
         COUNT(s.id) as sites_count
  FROM users u
  LEFT JOIN sites s ON s.user_id = u.id
  GROUP BY u.id
  ORDER BY u.id ASC
`);
const stmtUpdateUserStatus = db.prepare('UPDATE users SET active = ? WHERE id = ?');

function getUserByUsername(username) {
  return stmtFindUserByUsername.get(username);
}

function getUserByEmail(email) {
  return stmtFindUserByEmail.get(email);
}

function getUserById(id) {
  return stmtFindUserById.get(id);
}

function registerUser({ username, email, passwordHash, role = 'user' }) {
  const res = stmtInsertUser.run(username, email, passwordHash, role);
  return { id: res.lastInsertRowid, username, email, role, active: 1 };
}

function listUsers() {
  return stmtListAllUsers.all();
}

function setUserActive(id, active) {
  stmtUpdateUserStatus.run(active ? 1 : 0, id);
}

// Sites
const stmtInsertSite = db.prepare(`
  INSERT INTO sites (user_id, name, target_url, mode)
  VALUES (?, ?, ?, ?)
`);
const stmtGetSitesByUser = db.prepare(`
  SELECT s.*, u.username as owner_username
  FROM sites s
  JOIN users u ON u.id = s.user_id
  WHERE s.user_id = ?
  ORDER BY s.id DESC
`);
const stmtGetAllSitesAdmin = db.prepare(`
  SELECT s.*, u.username as owner_username
  FROM sites s
  JOIN users u ON u.id = s.user_id
  ORDER BY s.id DESC
`);
const stmtGetSiteById = db.prepare(`
  SELECT s.*, u.username as owner_username, u.active as owner_active
  FROM sites s
  JOIN users u ON u.id = s.user_id
  WHERE s.id = ?
`);
const stmtUpdateSite = db.prepare(`
  UPDATE sites
  SET name = COALESCE(?, name),
      target_url = COALESCE(?, target_url),
      mode = COALESCE(?, mode)
  WHERE id = ?
`);
const stmtDeleteSite = db.prepare('DELETE FROM sites WHERE id = ?');
const stmtIncrementSiteReq = db.prepare('UPDATE sites SET total_requests = total_requests + 1 WHERE id = ?');
const stmtIncrementGlobalReq = db.prepare('UPDATE request_counter SET total_requests = total_requests + 1 WHERE id = 1');

function createSite({ user_id, name, target_url, mode = 'Block' }) {
  const res = stmtInsertSite.run(user_id, name, target_url, mode);
  return getSiteById(res.lastInsertRowid);
}

function getSites(user_id, isAdmin = false) {
  if (isAdmin) {
    return stmtGetAllSitesAdmin.all();
  }
  return stmtGetSitesByUser.all(user_id);
}

function getSiteById(id) {
  return stmtGetSiteById.get(id);
}

function updateSite(id, { name, target_url, mode }) {
  stmtUpdateSite.run(name || null, target_url || null, mode || null, id);
  return getSiteById(id);
}

function deleteSite(id) {
  stmtDeleteSite.run(id);
}

function recordSiteRequest(siteId, userId, status = 'ALLOWED') {
  stmtIncrementGlobalReq.run();
  if (siteId) {
    stmtIncrementSiteReq.run(siteId);
    if (status === 'ALLOWED') {
      const time = new Date().toISOString();
      db.prepare('INSERT INTO site_traffic (site_id, user_id, time, status) VALUES (?, ?, ?, ?)').run(
        siteId,
        userId,
        time,
        status
      );
    }
  }
}

// Attack Logs
const stmtInsertAttackLog = db.prepare(`
  INSERT INTO attack_logs (site_id, user_id, time, ip, type, path, method, user_agent, status)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

function recordAttackLog({ site_id = null, user_id = null, ip, type, path: reqPath, method = 'GET', user_agent = null, status = 'BLOCKED' }) {
  const time = new Date().toISOString();
  stmtInsertAttackLog.run(site_id, user_id, time, ip, type, reqPath, method, user_agent, status);
  if (site_id) {
    stmtIncrementSiteReq.run(site_id);
  }
  stmtIncrementGlobalReq.run();
}

// Login attempts
const stmtInsertLoginAttempt = db.prepare(`
  INSERT INTO login_attempts (username, ip, success, time)
  VALUES (?, ?, ?, ?)
`);

function recordLoginAttempt({ username, ip, success }) {
  const time = new Date().toISOString();
  stmtInsertLoginAttempt.run(username || null, ip, success ? 1 : 0, time);
}

// -----------------------------------------------------------------------------
// Analytics & Statistics Helpers
// -----------------------------------------------------------------------------

function buildScopeFilter(user_id, isAdmin, site_id, tableAlias = '') {
  const prefix = tableAlias ? `${tableAlias}.` : '';
  const clauses = [];
  const params = [];

  if (!isAdmin) {
    clauses.push(`${prefix}user_id = ?`);
    params.push(user_id);
  }

  if (site_id) {
    clauses.push(`${prefix}site_id = ?`);
    params.push(Number(site_id));
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
  return { whereSql, params };
}

function getOverviewStats(user_id, isAdmin = false, site_id = null) {
  // 1. Calculate total requests
  let totalRequests = 0;
  if (site_id) {
    const site = getSiteById(site_id);
    totalRequests = site ? site.total_requests : 0;
  } else if (!isAdmin) {
    const row = db.prepare('SELECT COALESCE(SUM(total_requests), 0) as total FROM sites WHERE user_id = ?').get(user_id);
    totalRequests = row ? row.total : 0;
  } else {
    const row = db.prepare('SELECT total_requests FROM request_counter WHERE id = 1').get();
    totalRequests = row ? row.total_requests : 0;
  }

  // 2. Threats blocked and unique attacker IPs
  const scope = buildScopeFilter(user_id, isAdmin, site_id);
  const threatWhere = scope.whereSql
    ? `${scope.whereSql} AND status = 'BLOCKED'`
    : "WHERE status = 'BLOCKED'";

  const threatsRow = db.prepare(`SELECT COUNT(*) as count FROM attack_logs ${threatWhere}`).get(...scope.params);
  const threatsBlocked = threatsRow ? threatsRow.count : 0;

  const ipsRow = db.prepare(`SELECT COUNT(DISTINCT ip) as count FROM attack_logs ${scope.whereSql}`).get(...scope.params);
  const uniqueAttackerIps = ipsRow ? ipsRow.count : 0;

  // 3. Block Rate %
  const totalConsidered = Math.max(totalRequests, threatsBlocked);
  const blockRate = totalConsidered > 0 ? ((threatsBlocked / totalConsidered) * 100).toFixed(1) : '0.0';

  return {
    totalRequests: Math.max(totalRequests, threatsBlocked),
    threatsBlocked,
    blockRate: `${blockRate}%`,
    uniqueAttackerIps
  };
}

function getTimeseriesStats(user_id, isAdmin = false, site_id = null) {
  const scope = buildScopeFilter(user_id, isAdmin, site_id);
  const now = new Date();
  const past24h = new Date(now.getTime() - 24 * 60 * 60 * 1000).toISOString();

  const timeFilter = scope.whereSql
    ? `${scope.whereSql} AND time >= ?`
    : 'WHERE time >= ?';
  const params = [...scope.params, past24h];

  const rows = db.prepare(`
    SELECT strftime('%Y-%m-%d %H:00', time) as hour_bucket, COUNT(*) as count
    FROM attack_logs
    ${timeFilter}
    GROUP BY hour_bucket
    ORDER BY hour_bucket ASC
  `).all(...params);

  // Generate continuous 24-hour labels
  const bucketsMap = new Map();
  rows.forEach(r => bucketsMap.set(r.hour_bucket, r.count));

  const labels = [];
  const data = [];

  for (let i = 23; i >= 0; i--) {
    const d = new Date(now.getTime() - i * 60 * 60 * 1000);
    const hourLabel = `${String(d.getHours()).padStart(2, '0')}:00`;
    const bucketKey = `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ${String(d.getHours()).padStart(2, '0')}:00`;
    labels.push(hourLabel);
    data.push(bucketsMap.get(bucketKey) || 0);
  }

  return { labels, data };
}

function getAttackTypesStats(user_id, isAdmin = false, site_id = null, range = null) {
  const scope = buildScopeFilter(user_id, isAdmin, site_id);
  let timeClause = '';
  const extraParams = [];

  if (range) {
    let cutoffDate = null;
    const now = Date.now();
    if (range === '24h' || range === '1d') {
      cutoffDate = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    } else if (range === '7d') {
      cutoffDate = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    } else if (range === '30d') {
      cutoffDate = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    } else {
      const parsed = new Date(range);
      if (!isNaN(parsed.getTime())) {
        cutoffDate = parsed.toISOString();
      }
    }

    if (cutoffDate) {
      timeClause = scope.whereSql ? ' AND time >= ?' : 'WHERE time >= ?';
      extraParams.push(cutoffDate);
    }
  }

  const whereSql = (scope.whereSql || '') + timeClause;
  const params = [...scope.params, ...extraParams];

  const rows = db.prepare(`
    SELECT type, COUNT(*) as count
    FROM attack_logs
    ${whereSql}
    GROUP BY type
    ORDER BY count DESC
  `).all(...params);

  const defaultTypes = ['SQLi', 'XSS', 'PathTraversal', 'Bot', 'DDoS', 'Oversized Body'];
  const countsMap = new Map();
  rows.forEach(r => countsMap.set(r.type, r.count));

  const activeTypes = rows.map(r => r.type);
  const combinedTypes = Array.from(new Set([...activeTypes, ...defaultTypes]));
  const labels = [];
  const data = [];

  combinedTypes.forEach(t => {
    labels.push(t);
    data.push(countsMap.get(t) || 0);
  });

  return { labels, data, counts: Object.fromEntries(countsMap) };
}

function getTopIpsStats(user_id, isAdmin = false, site_id = null) {
  const scope = buildScopeFilter(user_id, isAdmin, site_id);
  const rows = db.prepare(`
    SELECT ip, COUNT(*) as count
    FROM attack_logs
    ${scope.whereSql}
    GROUP BY ip
    ORDER BY count DESC
    LIMIT 5
  `).all(...scope.params);

  return {
    labels: rows.map(r => r.ip),
    data: rows.map(r => r.count)
  };
}

function getLogs(user_id, isAdmin = false, { site_id, type, status, search, from, to, page = 1, limit = 20 }) {
  const clauses = [];
  const params = [];

  if (!isAdmin) {
    clauses.push('l.user_id = ?');
    params.push(user_id);
  }

  if (site_id) {
    clauses.push('l.site_id = ?');
    params.push(Number(site_id));
  }

  if (type && type !== 'ALL') {
    clauses.push('l.type = ?');
    params.push(type);
  }

  if (status && status !== 'ALL') {
    clauses.push('l.status = ?');
    params.push(status);
  }

  if (search && search.trim()) {
    clauses.push('(l.ip LIKE ? OR l.path LIKE ?)');
    params.push(`%${search.trim()}%`, `%${search.trim()}%`);
  }

  if (from) {
    clauses.push('l.time >= ?');
    params.push(from);
  }

  if (to) {
    clauses.push('l.time <= ?');
    params.push(to);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';

  // Count total matching logs
  const countRow = db.prepare(`SELECT COUNT(*) as total FROM attack_logs l ${whereSql}`).get(...params);
  const total = countRow ? countRow.total : 0;

  const validLimit = Math.max(1, Math.min(Number(limit) || 20, 100));
  const validPage = Math.max(1, Number(page) || 1);
  const offset = (validPage - 1) * validLimit;

  const rows = db.prepare(`
    SELECT l.id, l.time, l.site_id, s.name as site_name, l.ip, l.type, l.path, l.method, l.status, l.user_agent
    FROM attack_logs l
    LEFT JOIN sites s ON s.id = l.site_id
    ${whereSql}
    ORDER BY l.id DESC
    LIMIT ? OFFSET ?
  `).all(...params, validLimit, offset);

  return {
    logs: rows,
    total,
    page: validPage,
    totalPages: Math.max(1, Math.ceil(total / validLimit))
  };
}

function getAllLogsForExport(user_id, isAdmin = false, { site_id, type, status, search, from, to }) {
  const clauses = [];
  const params = [];

  if (!isAdmin) {
    clauses.push('l.user_id = ?');
    params.push(user_id);
  }

  if (site_id) {
    clauses.push('l.site_id = ?');
    params.push(Number(site_id));
  }

  if (type && type !== 'ALL') {
    clauses.push('l.type = ?');
    params.push(type);
  }

  if (status && status !== 'ALL') {
    clauses.push('l.status = ?');
    params.push(status);
  }

  if (search && search.trim()) {
    clauses.push('(l.ip LIKE ? OR l.path LIKE ?)');
    params.push(`%${search.trim()}%`, `%${search.trim()}%`);
  }

  if (from) {
    clauses.push('l.time >= ?');
    params.push(from);
  }

  if (to) {
    clauses.push('l.time <= ?');
    params.push(to);
  }

  const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';

  return db.prepare(`
    SELECT l.id, l.time, s.name as site_name, l.ip, l.method, l.type, l.path, l.status, l.user_agent
    FROM attack_logs l
    LEFT JOIN sites s ON s.id = l.site_id
    ${whereSql}
    ORDER BY l.id DESC
    LIMIT 5000
  `).all(...params);
}

module.exports = {
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
};
