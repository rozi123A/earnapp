express    from 'express';
import cors       from 'cors';
import helmet     from 'helmet';
import rateLimit  from 'express-rate-limit';
import Database   from 'better-sqlite3';
import crypto     from 'crypto';
import path       from 'path';
import { fileURLToPath } from 'url';
import { verifyTelegramInitData, extractUser } from './auth.js';
import { mountAdminRoutes, requireAdmin } from './admin.js';
import {
  initWithdrawalSchema,
  validateWithdrawal,
  notifyAdmin,
  sendStarsToUser,
  createWithdrawalAtomic,
  pointsToStars,
  MIN_WITHDRAWAL_PTS,
  MAX_WITHDRAWAL_PTS,
  MIN_STARS,
  MAX_STARS,
  WITHDRAWAL_COOLDOWN,
} from './withdrawal.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ════════════════════════════════════════
// CONFIG  (all values come from .env)
// ════════════════════════════════════════
const PORT              = process.env.PORT              || 3000;
const BOT_TOKEN         = process.env.BOT_TOKEN         || '';
const ADMOB_SSV_KEY_URL = process.env.ADMOB_SSV_KEY_URL || 'https://www.gstatic.com/admob/reward/verifier-keys.json';
const REWARD_HMAC_KEY   = process.env.REWARD_HMAC_KEY   || '';   // 32+ random bytes, hex-encoded
const COOLDOWN_MS       = parseInt(process.env.COOLDOWN_MS  || '30000');  // 30 s between ads
const DAILY_LIMIT       = parseInt(process.env.DAILY_LIMIT  || '50');
const PTS_PER_AD        = parseInt(process.env.PTS_PER_AD   || '1');
const ALLOWED_ORIGIN    = process.env.ALLOWED_ORIGIN    || '';   // must be set in prod
const INITDATA_MAX_AGE  = parseInt(process.env.INITDATA_MAX_AGE || '86400'); // 24 h
const ADMIN_CHAT_ID     = process.env.ADMIN_CHAT_ID     || '';   // Chat ID of the admin — REQUIRED for withdrawal notifications

// Fail fast on missing secrets
for (const [k, v] of [
  ['BOT_TOKEN',       BOT_TOKEN],
  ['REWARD_HMAC_KEY', REWARD_HMAC_KEY],
]) {
  if (!v) { console.error(`[FATAL] ${k} environment variable is not set.`); process.exit(1); }
}

if (!ALLOWED_ORIGIN) {
  console.warn('[WARN] ALLOWED_ORIGIN is not set — defaulting to * (insecure for production)');
}

// ════════════════════════════════════════
// DATABASE
// ════════════════════════════════════════
const db = new Database(path.join(__dirname, 'earnapp.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    telegram_id   TEXT PRIMARY KEY,
    username      TEXT,
    first_name    TEXT,
    balance       INTEGER NOT NULL DEFAULT 0,
    ads_watched   INTEGER NOT NULL DEFAULT 0,
    pts_today     INTEGER NOT NULL DEFAULT 0,
    last_date     TEXT    NOT NULL DEFAULT '',
    last_reward   INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reward_log (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    telegram_id    TEXT    NOT NULL,
    pts            INTEGER NOT NULL,
    ssv_token_hash TEXT,                          -- SHA-256 of the used SSV token (deduplication)
    rewarded_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (telegram_id) REFERENCES users(telegram_id)
  );

  CREATE TABLE IF NOT EXISTS suspicious_log (
    id            INTEGER PRIMARY KEY
