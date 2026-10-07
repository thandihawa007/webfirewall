const Database = require('better-sqlite3');
const path = require('path');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const dbPath = path.join(__dirname, 'data.db');
const db = new Database(dbPath);

// Enable WAL mode for better concurrency and reliability
db.pragma('journal_mode = WAL');

// 1. Create tables as specified
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS attack_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    time TEXT NOT NULL,
    ip TEXT NOT NULL,
    type TEXT NOT NULL,
    path TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'BLOCKED'
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

// Initialize request counter if not present
const counterRow = db.prepare('SELECT total_requests FROM request_counter WHERE id = 1').get();
if (!counterRow) {
  db.prepare('INSERT INTO request_counter (id, total_requests) VALUES (1, 0)').run();
}

// 2. Seed initial admin user if not exists
function seedAdmin() {
  const existingAdmin = db.prepare('SELECT id FROM users WHERE username = ?').get('admin');
  if (!existingAdmin) {
    let password = process.env.ADMIN_PASSWORD;
    let isGenerated = false;

    if (!password) {
      password = crypto.randomBytes(8).toString('hex');
      isGenerated = true;
    }

    const saltRounds = 12;
    const passwordHash = bcrypt.hashSync(password, saltRounds);

    db.prepare(`
      INSERT INTO users (username, password_hash, role)
      VALUES (?, ?, ?)
    `).run('admin', passwordHash, 'admin');

    console.log('[Database] Seeded initial admin user (username: "admin").');
    if (isGenerated) {
      console.log(`[Database] Generated random admin password: ${password}`);
    } else {
      console.log('[Database] Admin password initialized from ADMIN_PASSWORD environment variable.');
    }
  }
}

seedAdmin();

// Helper functions for application queries
const stmtIncrementRequests = db.prepare('UPDATE request_counter SET total_requests = total_requests + 1 WHERE id = 1');
const stmtGetRequests = db.prepare('SELECT total_requests FROM request_counter WHERE id = 1');

function incrementRequestCount() {
  stmtIncrementRequests.run();
}

function getRequestCount() {
  const row = stmtGetRequests.get();
  return row ? row.total_requests : 0;
}

const stmtInsertAttackLog = db.prepare(`
  INSERT INTO attack_logs (time, ip, type, path, status)
  VALUES (?, ?, ?, ?, ?)
`);

function recordAttackLog({ ip, type, path, status = 'BLOCKED' }) {
  const time = new Date().toISOString();
  stmtInsertAttackLog.run(time, ip, type, path, status);
}

const stmtInsertLoginAttempt = db.prepare(`
  INSERT INTO login_attempts (username, ip, success, time)
  VALUES (?, ?, ?, ?)
`);

function recordLoginAttempt({ username, ip, success }) {
  const time = new Date().toISOString();
  stmtInsertLoginAttempt.run(username || null, ip, success ? 1 : 0, time);
}

const stmtCountThreats = db.prepare('SELECT COUNT(*) as count FROM attack_logs');
const stmtCountBlockedIps = db.prepare('SELECT COUNT(DISTINCT ip) as count FROM attack_logs');
const stmtGetRecentLogs = db.prepare(`
  SELECT id, time, ip, type, path, status
  FROM attack_logs
  ORDER BY id DESC
  LIMIT ?
`);

function getStats(activeRulesCount = 12) {
  const totalRequests = getRequestCount();
  const blockedThreats = stmtCountThreats.get().count;
  const blockedIps = stmtCountBlockedIps.get().count;

  return {
    totalRequests,
    blockedThreats,
    activeRules: activeRulesCount,
    blockedIps
  };
}

function getRecentLogs(limit = 5) {
  return stmtGetRecentLogs.all(limit);
}

module.exports = {
  db,
  incrementRequestCount,
  getRequestCount,
  recordAttackLog,
  recordLoginAttempt,
  getStats,
  getRecentLogs
};
