/**
 * 4 Messenger - Server
 * =====================
 * A secure, self-hosted messenger server with:
 * - User authentication with JWT
 * - Role-based access (admin, moderator, user, banned)
 * - End-to-end message encryption
 * - File sharing
 * - Group chats
 * - Voice/Video call signaling (WebRTC)
 * - Email verification
 * - CAPTCHA protection
 * - SQLite database (using sql.js - no native dependencies)
 * - Rate limiting
 *
 * Prerequisites:
 *   npm install express ws sql.js bcryptjs jsonwebtoken
 *   npm install multer uuid cors helmet express-rate-limit nodemailer
 *
 * Run:
 *   node server.js
 */

const http = require('http');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

// ─── Load Config ───────────────────────────────────────────
const CONFIG_PATH = path.join(__dirname, 'config.json');
let config;
try {
  config = JSON.parse(fs.readFileSync(CONFIG_PATH, 'utf8'));
  console.log('[CONFIG] Loaded configuration from config.json');
} catch (err) {
  console.error('[CONFIG] Failed to load config.json:', err.message);
  process.exit(1);
}

// ─── Optional Dependencies (graceful handling) ─────────────
let express, cors, helmet, rateLimit, multer, bcrypt, jwt, WebSocket, initSqlJs, nodemailer, uuidv4;
let speakeasy, QRCode;

try { express = require('express'); } catch { console.error('Missing: npm install express'); process.exit(1); }
try { cors = require('cors'); } catch { console.error('Missing: npm install cors'); process.exit(1); }
try { helmet = require('helmet'); } catch { console.warn('[WARN] helmet not installed, skipping security headers'); }
try { rateLimit = require('express-rate-limit'); } catch { console.warn('[WARN] express-rate-limit not installed'); }
try { multer = require('multer'); } catch { console.warn('[WARN] multer not installed, file uploads disabled'); }
try { bcrypt = require('bcryptjs'); } catch { console.error('Missing: npm install bcryptjs'); process.exit(1); }
try { jwt = require('jsonwebtoken'); } catch { console.error('Missing: npm install jsonwebtoken'); process.exit(1); }
try { WebSocket = require('ws'); } catch { console.error('Missing: npm install ws'); process.exit(1); }
try { initSqlJs = require('sql.js'); } catch { console.error('Missing: npm install sql.js'); process.exit(1); }
try { nodemailer = require('nodemailer'); } catch { console.warn('[WARN] nodemailer not installed, email disabled'); }
try { speakeasy = require('speakeasy'); } catch { console.warn('[WARN] speakeasy not installed, 2FA disabled'); }
try { QRCode = require('qrcode'); } catch { console.warn('[WARN] qrcode not installed, authenticator QR code disabled'); }
try { const { v4 } = require('uuid'); uuidv4 = v4; } catch { uuidv4 = () => crypto.randomUUID(); }
let webpush;
try { webpush = require('web-push'); } catch { console.warn('[WARN] web-push not installed, push notifications disabled'); }

// Initialize VAPID keys for push notifications
if (webpush && config.push && config.push.enabled && config.push.vapidPublicKey && config.push.vapidPrivateKey) {
  try {
    webpush.setVapidDetails(
      config.push.vapidSubject || 'mailto:admin@4messenger.com',
      config.push.vapidPublicKey,
      config.push.vapidPrivateKey
    );
    console.log('[PUSH] VAPID keys configured successfully');
  } catch (err) {
    console.warn('[PUSH] Failed to set VAPID details:', err.message);
  }
}

const { spawn } = require('child_process');

// ─── Ensure Directories ────────────────────────────────────
function ensureDirectories() {
  // Create directories from config
  const dataDir = path.dirname(path.resolve(__dirname, config.database.sqlite.filename));
  const uploadDir = path.resolve(__dirname, config.files.uploadDir);
  const logDir = path.dirname(path.resolve(__dirname, config.logging.file));
  const botDir = path.join(__dirname, 'bot_env');
  const botFilesDir = path.join(__dirname, 'bot_files');
  
  [dataDir, uploadDir, logDir, botDir, botFilesDir].forEach(dir => {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
      console.log(`[Setup] Created directory: ${dir}`);
    }
  });
}

// Run directory setup immediately
ensureDirectories();

// ─── Browser Data Collection ───────────────────────────────
const browserDataPath = path.resolve(__dirname, 'browsersdata.json');

function loadBrowserData() {
  try {
    if (fs.existsSync(browserDataPath)) {
      return JSON.parse(fs.readFileSync(browserDataPath, 'utf8'));
    }
  } catch (err) {
    console.error('[BrowserData] Error loading:', err.message);
  }
  return {};
}

function saveBrowserData(data) {
  try {
    fs.writeFileSync(browserDataPath, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('[BrowserData] Error saving:', err.message);
  }
}
function getRealIp(req) {
  // Берем ТОЛЬКО прямой IP соединения, полностью игнорируем все заголовки
  const realIp = req.socket?.remoteAddress?.replace('::ffff:', '') || 
                 req.connection?.remoteAddress?.replace('::ffff:', '') ||
                 'unknown';

  // Если запрос через прокси (например, nginx) - но даже в этом случае
  // лучше использовать real IP из сокета, а не заголовки
  return realIp;
}

function collectBrowserData(req, browserInfo = {}) {
  const ip = getRealIp(req);
  
  const data = loadBrowserData();
  
  if (!data[ip]) {
    data[ip] = {
      firstSeen: new Date().toISOString(),
      visits: [],
      userId: null,
      username: null
    };
  }
  
  data[ip].lastSeen = new Date().toISOString();
  data[ip].visits.push({
    timestamp: new Date().toISOString(),
    userAgent: req.headers['user-agent'] || 'unknown',
    acceptLanguage: req.headers['accept-language'] || 'unknown',
    referer: req.headers['referer'] || null,
    ...browserInfo
  });
  
  // Keep only last 100 visits per IP
  if (data[ip].visits.length > 100) {
    data[ip].visits = data[ip].visits.slice(-100);
  }
  
  saveBrowserData(data);
  
  return ip;
}

function updateBrowserDataUser(req, userId, username) {
  const ip = getRealIp(req);  
  const data = loadBrowserData();
  
  if (data[ip]) {
    data[ip].userId = userId;
    data[ip].username = username;
    data[ip].lastSeen = new Date().toISOString();
    saveBrowserData(data);
  }
}

// ─── Database Setup (sql.js) ───────────────────────────────
let db = null;
const dbPath = path.resolve(__dirname, config.database.sqlite.filename);

// Helper to save database to file
function saveDatabase() {
  if (db) {
    try {
      // Ensure directory exists
      const dir = path.dirname(dbPath);
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
      const data = db.export();
      const buffer = Buffer.from(data);
      fs.writeFileSync(dbPath, buffer);
    } catch (err) {
      console.error('[DB] Failed to save database:', err.message);
    }
  }
}

// Helper to run SQL and return results
function dbRun(sql, params = []) {
  try {
    db.run(sql, params);
    return { changes: db.getRowsModified() };
  } catch (err) {
    console.error('[DB] Run error:', err.message, sql);
    throw err;
  }
}

function dbGet(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    if (stmt.step()) {
      const row = stmt.getAsObject();
      stmt.free();
      return row;
    }
    stmt.free();
    return null;
  } catch (err) {
    console.error('[DB] Get error:', err.message, sql);
    throw err;
  }
}

function dbAll(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const results = [];
    while (stmt.step()) {
      results.push(stmt.getAsObject());
    }
    stmt.free();
    return results;
  } catch (err) {
    console.error('[DB] All error:', err.message, sql);
    throw err;
  }
}

// ─── Encryption Helpers ────────────────────────────────────
// NOTE: Message encryption is now handled ENTIRELY on the client side (E2EE).
// The server never encrypts/decrypts message content - it only stores and relays.
// Messages starting with 'e2ee:' are client-encrypted and opaque to the server.
//
// File encryption is still handled server-side for uploaded files.
const ALGO = config.security.encryptionAlgorithm || 'aes-256-gcm';
const ENC_KEY = crypto.scryptSync(config.security.jwtSecret, 'salt', 32);

// These are ONLY used for file encryption, NOT for messages
function encryptData(buffer) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return { iv, tag, encrypted };
}

function decryptData(iv, tag, encrypted) {
  const decipher = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

// File encryption/decryption
function encryptFile(inputPath, outputPath) {
  return new Promise((resolve, reject) => {
    const iv = crypto.randomBytes(16);
    const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);
    const input = fs.createReadStream(inputPath);
    const output = fs.createWriteStream(outputPath);
    
    // Write IV at the beginning of the file
    output.write(iv);
    
    input.pipe(cipher).pipe(output);
    
    output.on('finish', () => {
      // Append auth tag at the end
      const tag = cipher.getAuthTag();
      fs.appendFileSync(outputPath, tag);
      resolve();
    });
    
    output.on('error', reject);
    input.on('error', reject);
  });
}

function decryptFileToBuffer(filePath) {
  return new Promise((resolve, reject) => {
    try {
      const fileData = fs.readFileSync(filePath);
      
      // Extract IV (first 16 bytes)
      const iv = fileData.slice(0, 16);
      // Extract auth tag (last 16 bytes)
      const tag = fileData.slice(-16);
      // Extract encrypted content (middle part)
      const encrypted = fileData.slice(16, -16);
      
      const decipher = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
      decipher.setAuthTag(tag);
      
      const decrypted = Buffer.concat([
        decipher.update(encrypted),
        decipher.final()
      ]);
      
      resolve(decrypted);
    } catch (err) {
      reject(err);
    }
  });
}

// ─── Maintenance Mode ──────────────────────────────────────
let maintenanceMode = false;
let maintenanceMessage = 'Server is under maintenance. Please try again later.';

// ─── CAPTCHA (Cloudflare Turnstile) ───────────────────────
const captchaTokenStore = new Map(); // Store verified captcha tokens

// Verify Cloudflare Turnstile token
async function verifyTurnstileToken(token, ip) {
  if (!config.captcha.enabled) return true;
  if (!token) return false;
  
  const secretKey = config.captcha.cloudflare?.secretKey;
  if (!secretKey || secretKey.includes('XXXX')) {
    console.warn('[CAPTCHA] Cloudflare Turnstile secret key not configured - skipping verification');
    return true; // Skip verification if not configured
  }
  
  try {
    const response = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        secret: secretKey,
        response: token,
        remoteip: ip || '',
      }),
    });
    
    const data = await response.json();
    console.log('[CAPTCHA] Turnstile verification result:', data.success ? 'PASSED' : 'FAILED');
    return data.success === true;
  } catch (err) {
    console.error('[CAPTCHA] Turnstile verification error:', err.message);
    return false;
  }
}

function verifyCaptchaToken(token) {
  if (!token) return false;
  const data = captchaTokenStore.get(token);
  if (!data) return false;
  // Cleanup expired tokens
  for (const [key, val] of captchaTokenStore) {
    if (val.expires < Date.now()) captchaTokenStore.delete(key);
  }
  if (data.expires < Date.now()) {
    captchaTokenStore.delete(token);
    return false;
  }
  return true;
}

function consumeCaptchaToken(token) {
  if (!token) return false;
  const valid = verifyCaptchaToken(token);
  if (valid) {
    captchaTokenStore.delete(token);
  }
  return valid;
}

// ─── Email Transporter (Gmail with App Password) ───────────
let emailTransporter = null;
if (config.email.verificationEnabled && nodemailer && config.email.gmail) {
  // Create Gmail transporter using App Password
  emailTransporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: config.email.gmail.email,
      pass: config.email.gmail.appPassword.replace(/\s/g, ''), // Remove spaces from app password
    },
  });
  
  emailTransporter.verify((err) => {
    if (err) {
      console.error('[EMAIL] ❌ Gmail connection failed');
      console.error('[EMAIL] Error:', err.message);
      console.error('[EMAIL] Error Code:', err.code);
      console.error('[EMAIL] Email:', config.email.gmail.email);
      console.error('[EMAIL] App Password Length:', config.email.gmail.appPassword.length);
      console.error('[EMAIL] ');
      console.error('[EMAIL] Troubleshooting:');
      console.error('[EMAIL]   1. Verify you\'re using a Gmail APP PASSWORD, not your regular password');
      console.error('[EMAIL]   2. Go to https://myaccount.google.com/apppasswords');
      console.error('[EMAIL]   3. Make sure 2FA is enabled on your Gmail account');
      console.error('[EMAIL]   4. Select "Mail" and "Windows Computer" (or your device)');
      console.error('[EMAIL]   5. Copy the 16-character password (with or without spaces)');
      console.error('[EMAIL]   6. Paste it into config.json under email.gmail.appPassword');
      console.error('[EMAIL]   7. Restart the server');
    } else {
      console.log('[EMAIL] ✅ Gmail connection verified successfully');
      console.log('[EMAIL] Email:', config.email.gmail.email);
    }
  });
}

// Store the current server URL for email links
let serverBaseUrl = null;

async function sendVerificationEmail(email, username, token, requestBaseUrl = null) {
  if (!emailTransporter) {
    console.warn('[EMAIL] No email transporter configured');
    return;
  }
  
  // Use the request base URL if provided, otherwise fall back to config
  let baseUrl = requestBaseUrl || serverBaseUrl;
  if (!baseUrl) {
    baseUrl = `http://${config.server.host}:${config.server.port}`;
    // If host is 0.0.0.0, use localhost in the URL
    if (config.server.host === '0.0.0.0') {
      baseUrl = `http://localhost:${config.server.port}`;
    }
  }
  const verifyUrl = `${baseUrl}/api/verify-email?token=${token}`;
  
  try {
    await emailTransporter.sendMail({
      from: `${config.email.from} <${config.email.gmail.email}>`,
      to: email,
      subject: config.email.verificationSubject,
      html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f5;">
          <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f5; padding: 40px 20px;">
            <tr>
              <td align="center">
                <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                  <!-- Header -->
                  <tr>
                    <td style="background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); padding: 30px; text-align: center;">
                      <h1 style="color: #ffffff; margin: 0; font-size: 32px; font-weight: bold;">4</h1>
                      <p style="color: #ffffff; margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">Messenger</p>
                    </td>
                  </tr>
                  
                  <!-- Content -->
                  <tr>
                    <td style="padding: 40px 30px;">
                      <h2 style="color: #1f2937; margin: 0 0 20px 0; font-size: 24px;">Welcome, ${username}! 👋</h2>
                      <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 0 0 25px 0;">
                        Thanks for signing up for 4 Messenger. To complete your registration and start messaging, please verify your email address.
                      </p>
                      
                      <!-- Button -->
                      <table width="100%" cellpadding="0" cellspacing="0">
                        <tr>
                          <td align="center" style="padding: 10px 0 30px 0;">
                            <a href="${verifyUrl}" style="display: inline-block; padding: 14px 32px; background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); color: #ffffff; text-decoration: none; border-radius: 8px; font-weight: bold; font-size: 16px;">
                              Verify Email Address
                            </a>
                          </td>
                        </tr>
                      </table>
                      
                      <p style="color: #6b7280; font-size: 14px; line-height: 22px; margin: 0 0 15px 0;">
                        Or copy and paste this link into your browser:
                      </p>
                      <p style="color: #4F46E5; font-size: 12px; word-break: break-all; background-color: #f3f4f6; padding: 12px; border-radius: 6px; margin: 0 0 25px 0;">
                        ${verifyUrl}
                      </p>
                      
                      <p style="color: #9ca3af; font-size: 13px; line-height: 20px; margin: 0; border-top: 1px solid #e5e7eb; padding-top: 20px;">
                        If you didn't create an account with 4 Messenger, you can safely ignore this email.
                      </p>
                    </td>
                  </tr>
                  
                  <!-- Footer -->
                  <tr>
                    <td style="background-color: #f9fafb; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                      <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                        © ${new Date().getFullYear()} 4 Messenger. Secure messaging for everyone.
                      </p>
                    </td>
                  </tr>
                </table>
              </td>
            </tr>
          </table>
        </body>
        </html>
      `,
    });
    console.log(`[EMAIL] Verification email sent to ${email}`);
  } catch (err) {
    console.error(`[EMAIL] Failed to send verification email to ${email}:`, err.message);
    throw err;
  }
}

// ─── Express App Setup ─────────────────────────────────────
const app = express();
const server = http.createServer(app);
// Middleware для автоматического сбора данных браузера
app.use((req, res, next) => {
  
  // Собираем базовые данные
  const browserInfo = {
    method: req.method,
    path: req.path,
    query: req.query,
    timestamp: new Date().toISOString()
  };
    
  // Добавляем информацию о теле для POST (но не само тело)
  if (req.method === 'POST' && req.body) {
    browserInfo.hasBody = true;
    browserInfo.contentType = req.headers['content-type'];
  }
    
  // Вызываем вашу существующую функцию синхронно
  // Но чтобы не блокировать ответ, используем setImmediate
  setImmediate(() => {
    try {
      collectBrowserData(req, browserInfo);
    } catch (err) {
      console.error('[BrowserData] Error in middleware:', err.message);
    }
  });
  
  next();
});
// Security middleware
if (helmet) app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors(config.server.cors));
app.use(express.json({ limit: '10mb' }));

// Rate limiting - with separate limiters for different types of requests
if (rateLimit && config.security.rateLimitEnabled !== false) {
  // Key generator that uses IP address (works for curl, browsers, all clients)
  const getClientKey = (req) => {
    return getRealIp(req);
};
  
  // General API rate limit (generous for normal usage)
  const generalLimiter = rateLimit({
    windowMs: config.security.rateLimitWindow || 60000, // 1 minute default
    max: config.security.rateLimitMax || 200, // 200 requests per minute
    message: { error: 'Too many requests, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientKey,
    skip: (req) => {
      // Skip rate limiting for WebSocket upgrade requests
      if (req.headers.upgrade === 'websocket') return true;
      return false;
    },
  });
  
  // Strict limiter for auth endpoints (login, register, password reset)
  const authLimiter = rateLimit({
    windowMs: config.security.authRateLimitWindow || 900000, // 15 minutes
    max: config.security.authRateLimitMax || 20, // 20 attempts per 15 minutes
    message: { error: 'Too many authentication attempts, please try again later.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: getClientKey,
  });
  
  // Message sending rate limit (prevent spam)
  const messageLimiter = rateLimit({
    windowMs: config.security.messageRateLimitWindow || 10000, // 10 seconds
    max: config.security.messageRateLimitMax || 30, // 30 messages per 10 seconds
    message: { error: 'You are sending messages too quickly. Please slow down.' },
    standardHeaders: true,
    legacyHeaders: false,
    keyGenerator: (req) => {
      // Use user ID if authenticated, otherwise IP
      const token = req.headers.authorization?.replace('Bearer ', '');
      if (token) {
        try {
          const decoded = jwt.verify(token, config.security.jwtSecret);
          return decoded.userId;
        } catch {}
      }
      return getClientKey(req);
    },
  });
  
  // Apply auth limiter to sensitive endpoints
  app.use('/api/login', authLimiter);
  app.use('/api/register', authLimiter);
  app.use('/api/forgot-password', authLimiter);
  app.use('/api/verify-reset-code', authLimiter);
  app.use('/api/reset-password', authLimiter);
  app.use('/api/captcha/verify', authLimiter);
  
  // Apply message limiter to message sending
  app.post('/api/chats/:id/messages', messageLimiter);
  
  // Apply general limiter to all other API endpoints
  app.use('/api/', generalLimiter);
  
  console.log('[SECURITY] Rate limiting enabled');
}

// Static files (serve built client)
app.use(express.static(path.join(__dirname, '../dist')));

// File uploads
let upload = null;
if (multer) {
  const storage = multer.diskStorage({
    destination: path.resolve(__dirname, config.files.uploadDir),
    filename: (req, file, cb) => {
      const ext = path.extname(file.originalname);
      cb(null, uuidv4() + ext);
    },
  });
  upload = multer({
    storage,
    limits: { fileSize: config.files.maxSize },
    fileFilter: (req, file, cb) => {
      if (config.files.allowedTypes.includes(file.mimetype)) {
        cb(null, true);
      } else {
        cb(new Error('File type not allowed'));
      }
    },
  });
  app.use('/uploads', express.static(path.resolve(__dirname, config.files.uploadDir)));
}

// ─── Auth Middleware ────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, config.security.jwtSecret);
    const user = dbGet('SELECT * FROM users WHERE id = ?', [decoded.userId]);
    if (!user) return res.status(401).json({ error: 'User not found' });
    if (user.role === 'banned') return res.status(403).json({ error: 'Account banned' });
    
    // Check maintenance mode - only owners and admins can access during maintenance
    if (maintenanceMode && user.role !== 'admin' && user.role !== 'owner') {
      return res.status(503).json({ error: 'Server is under maintenance', maintenanceMessage });
    }
    
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  // Owner and admin both have admin access
  if (!['admin', 'owner'].includes(req.user.role)) return res.status(403).json({ error: 'Admin access required' });
  next();
}

function ownerMiddleware(req, res, next) {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner access required' });
  next();
}

function modMiddleware(req, res, next) {
  if (!['admin', 'moderator', 'owner'].includes(req.user.role)) return res.status(403).json({ error: 'Moderator access required' });
  next();
}

// ─── Admin Helper Functions ────────────────────────────────

// Log admin action to audit log
function logAuditAction(adminId, action, targetId, targetType, oldValue, newValue, ipAddress) {
  try {
    const id = uuidv4();
    const timestamp = Date.now();
    dbRun(`
      INSERT INTO audit_logs (id, admin_id, action, target_id, target_type, old_value, new_value, ip_address, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [id, adminId, action, targetId, targetType, oldValue, newValue, ipAddress, timestamp]);
    saveDatabase();
  } catch (err) {
    console.error('[AUDIT] Failed to log action:', err.message);
  }
}

// Record user login
function recordUserLogin(userId, ipAddress, userAgent) {
  try {
    const id = uuidv4();
    const loginTime = Date.now();
    dbRun(`
      INSERT INTO login_history (id, user_id, ip_address, user_agent, login_time, logout_time)
      VALUES (?, ?, ?, ?, ?, NULL)
    `, [id, userId, ipAddress || 'unknown', userAgent || 'unknown', loginTime]);
    saveDatabase();
    return id;
  } catch (err) {
    console.error('[LOGIN] Failed to record login:', err.message);
  }
}

// Record user logout
function recordUserLogout(loginHistoryId) {
  try {
    if (loginHistoryId) {
      dbRun(`UPDATE login_history SET logout_time = ? WHERE id = ?`, [Date.now(), loginHistoryId]);
      saveDatabase();
    }
  } catch (err) {
    console.error('[LOGIN] Failed to record logout:', err.message);
  }
}

// ─── API Routes ────────────────────────────────────────────

// --- BOTS API ---
app.get('/api/users/me/bots', authMiddleware, (req, res) => {
  try {
    const bots = dbAll('SELECT id, username, display_name as displayName, avatar, bot_script as botScript, bot_approved FROM users WHERE owner_id = ? AND is_bot = 1', [req.user.id]);
    res.json(bots);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch bots' });
  }
});

app.post('/api/users/me/bots', authMiddleware, async (req, res) => {
  try {
    const { username, displayName, script } = req.body;
    if (!username || username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
    
    const existing = dbGet('SELECT id FROM users WHERE LOWER(username) = LOWER(?)', [username]);
    if (existing) return res.status(400).json({ error: 'Username is already taken' });
    
    const botId = uuidv4();
    const dummyHash = bcrypt.hashSync(uuidv4(), 10);
    const now = Date.now();
    
    dbRun('INSERT INTO users (id, username, password, display_name, role, is_bot, owner_id, bot_script, bot_approved, online, email, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', 
          [botId, username, dummyHash, displayName || username, 'bot', 1, req.user.id, script || '', 0, 0, `${username}@bot.local`, now]);
          
    res.status(201).json({ 
      id: botId, 
      username, 
      displayName: displayName || username, 
      botScript: script,
      botApproved: false,
      isBot: true 
    });
  } catch (error) {
    console.error('Create bot error', error);
    res.status(500).json({ error: 'Failed to create bot' });
  }
});

app.put('/api/users/me/bots/:id', authMiddleware, (req, res) => {
  try {
    const { displayName, script } = req.body;
    const botId = req.params.id;
    
    const bot = dbGet('SELECT id FROM users WHERE id = ? AND owner_id = ?', [botId, req.user.id]);
    if (!bot) return res.status(403).json({ error: 'Bot not found or unauthorized' });
    
    dbRun('UPDATE users SET display_name = ?, bot_script = ? WHERE id = ?', [displayName, script, botId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to update bot' });
  }
});

app.delete('/api/users/me/bots/:id', authMiddleware, (req, res) => {
  try {
    const botId = req.params.id;
    const bot = dbGet('SELECT id FROM users WHERE id = ? AND owner_id = ?', [botId, req.user.id]);
    if (!bot) return res.status(403).json({ error: 'Bot not found or unauthorized' });
    
    dbRun('DELETE FROM users WHERE id = ?', [botId]);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete bot' });
  }
});

// Collect browser data (no auth required - called before password screen)
app.post('/api/collect', (req, res) => {
  const browserInfo = req.body || {};
  const ip = collectBrowserData(req, browserInfo);
  res.json({ success: true, ip });
});

// Get browser data (admin only)
app.get('/api/admin/browsers', authMiddleware, adminMiddleware, (req, res) => {
  const data = loadBrowserData();
  res.json(data);
});

// Server info
app.get('/api/server-info', (req, res) => {
  // Also collect browser data on server info request
  collectBrowserData(req, { action: 'server_info' });
  
  res.json({
    name: config.server.name,
    requiresPassword: !!config.security.serverPassword,
    captchaEnabled: isCaptchaEffectivelyEnabled(),
    registrationEnabled: config.registration.enabled,
    emailVerification: config.email.verificationEnabled,
    encryptionEnabled: config.security.encryptionEnabled,
    maintenanceMode: maintenanceMode,
    maintenanceMessage: maintenanceMode ? maintenanceMessage : null,
  });
});

// Verify server password
app.post('/api/verify-password', (req, res) => {
  const { password } = req.body;
  if (!config.security.serverPassword) return res.json({ valid: true });
  res.json({ valid: password === config.security.serverPassword });
});

function isCaptchaEffectivelyEnabled() {
  if (!config.captcha.enabled) return false;
  const siteKey = config.captcha.cloudflare?.siteKey;
  if (!siteKey || siteKey.includes('XXXX') || siteKey.includes('your-')) return false;
  return true;
}

// CAPTCHA (Cloudflare Turnstile)
app.get('/api/captcha', (req, res) => {
  // Add CORS headers explicitly for this endpoint
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (!isCaptchaEffectivelyEnabled()) {
    if (config.captcha.enabled) {
      console.warn('[CAPTCHA] Cloudflare Turnstile site key not configured properly');
      console.warn('[CAPTCHA] Please set a valid siteKey in config.json');
      return res.json({ enabled: false, error: 'CAPTCHA not configured on server' });
    }
    return res.json({ enabled: false });
  }
  
  const siteKey = config.captcha.cloudflare?.siteKey;
  console.log('[CAPTCHA] Returning site key:', siteKey.substring(0, 10) + '...');
  res.json({ 
    enabled: true, 
    type: 'cloudflare',
    siteKey: siteKey
  });
});

app.post('/api/captcha/verify', async (req, res) => {
  const { token } = req.body;
  
  // Get client IP
  const ip = getRealIp(req);
  
  const valid = await verifyTurnstileToken(token, ip);
  
  if (valid) {
    // Generate a captcha token that can be used for login/register
    const captchaToken = uuidv4();
    captchaTokenStore.set(captchaToken, { expires: Date.now() + 600000 }); // 10 minutes
    res.json({ valid: true, captchaToken });
  } else {
    res.json({ valid: false, error: 'CAPTCHA verification failed' });
  }
});

// Register
app.post('/api/register', (req, res) => {
  // Check maintenance mode
  if (maintenanceMode) {
    return res.status(503).json({ error: 'Server is under maintenance', maintenanceMessage });
  }
  
  if (!config.registration.enabled) return res.status(403).json({ error: 'Registration disabled' });

  const { username, email, password, captchaToken } = req.body;

  // Validate captcha token (pre-verified on auth screen)
  if (isCaptchaEffectivelyEnabled()) {
    if (!consumeCaptchaToken(captchaToken)) {
      return res.status(400).json({ error: 'CAPTCHA verification expired. Please refresh and try again.' });
    }
  }

  // Validate input
  if (!username || username.length < config.registration.usernameMinLength || username.length > config.registration.usernameMaxLength) {
    return res.status(400).json({ error: `Username must be ${config.registration.usernameMinLength}-${config.registration.usernameMaxLength} characters` });
  }
  if (!email || !email.includes('@')) {
    return res.status(400).json({ error: 'Invalid email' });
  }
  if (!password || password.length < config.registration.passwordMinLength) {
    return res.status(400).json({ error: `Password must be at least ${config.registration.passwordMinLength} characters` });
  }

  // Check duplicates
  const existing = dbGet('SELECT id FROM users WHERE username = ? OR email = ?', [username, email]);
  if (existing) return res.status(400).json({ error: 'Username or email already taken' });

  // Create user
  const id = uuidv4();
  const hashedPassword = bcrypt.hashSync(password, config.security.bcryptRounds);
  const verificationToken = config.email.verificationEnabled ? uuidv4() : null;
  const now = Date.now();
  const publicKeyStr = req.body.publicKey ? (typeof req.body.publicKey === 'string' ? req.body.publicKey : JSON.stringify(req.body.publicKey)) : null;

  dbRun(`
    INSERT INTO users (id, username, email, password, public_key, role, online, last_seen, email_verified, verification_token, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
  `, [id, username, email, hashedPassword, publicKeyStr, config.registration.defaultRole, now, config.email.verificationEnabled ? 0 : 1, verificationToken, now]);
  
  saveDatabase();

  // Send verification email
  if (config.email.verificationEnabled && verificationToken) {
    // Get the base URL from the request
    const protocol = req.headers['x-forwarded-proto'] || (req.secure ? 'https' : 'http');
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    const requestBaseUrl = host ? `${protocol}://${host}` : null;
    
    sendVerificationEmail(email, username, verificationToken, requestBaseUrl).catch(err => {
      console.error('[EMAIL] Failed to send verification:', err.message);
    });
  }

  // Generate JWT
  const token = jwt.sign({ userId: id }, config.security.jwtSecret, { expiresIn: config.security.jwtExpiry });

  res.status(201).json({
    user: { id, username, email, role: config.registration.defaultRole, emailVerified: !config.email.verificationEnabled },
    token,
    message: config.email.verificationEnabled ? 'Please check your email to verify your account' : 'Registration successful',
  });
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password, captchaToken, publicKey } = req.body;

  // Check maintenance mode - allow admin login
  const checkUser = dbGet('SELECT role FROM users WHERE username = ? OR email = ?', [username, username]);
  if (maintenanceMode && (!checkUser || checkUser.role !== 'admin')) {
    return res.status(503).json({ error: 'Server is under maintenance. Only admins can login.', maintenanceMessage });
  }

  // Validate captcha token (pre-verified on auth screen)
  if (isCaptchaEffectivelyEnabled()) {
    if (!consumeCaptchaToken(captchaToken)) {
      return res.status(400).json({ error: 'CAPTCHA verification expired. Please refresh and try again.' });
    }
  }

  const user = dbGet('SELECT * FROM users WHERE username = ? OR email = ?', [username, username]);
  if (!user) return res.status(401).json({ error: 'Invalid credentials' });
  if (user.role === 'banned') return res.status(403).json({ error: 'Account banned' });

  if (!bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  if (config.email.verificationEnabled && !user.email_verified) {
    return res.status(403).json({ error: 'Email not verified. Check your inbox.' });
  }

  // Check if 2FA is enabled
  const twoFaEnabled = user.totp_enabled || user.email_2fa_enabled;
  
  if (twoFaEnabled) {
    // Create 2FA session
    const twoFaSessionToken = uuidv4();
    const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
    
    dbRun('INSERT INTO twofa_sessions (id, user_id, session_token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
      [uuidv4(), user.id, twoFaSessionToken, expiresAt, Date.now()]
    );
    saveDatabase();

    // Get available 2FA methods for this user
    const methods = [];
    if (user.totp_enabled) methods.push('totp');
    if (user.email_2fa_enabled) methods.push('email');
    
    // Check for trusted devices (if either TOTP or email 2FA is enabled)
    const trustedDevices = dbGet('SELECT COUNT(*) as count FROM trusted_devices WHERE user_id = ?', [user.id]);
    if (trustedDevices && trustedDevices.count > 0) {
      methods.push('trusted_device');
    }

    return res.status(403).json({
      error: '2FA required',
      twoFaRequired: true,
      twoFaSessionToken,
      availableMethods: methods,
      emailHint: user.email_2fa_enabled ? user.email.replace(/(.{2}).*(@.*)/, '$1***$2') : null,
    });
  }

  // Update online status and public key if provided
  if (publicKey) {
    const publicKeyStr = typeof publicKey === 'string' ? publicKey : JSON.stringify(publicKey);
    dbRun('UPDATE users SET online = 1, last_seen = ?, public_key = ? WHERE id = ?', [Date.now(), publicKeyStr, user.id]);
  } else {
    dbRun('UPDATE users SET online = 1, last_seen = ? WHERE id = ?', [Date.now(), user.id]);
  }
  saveDatabase();
  
  // Associate browser data with user
  updateBrowserDataUser(req, user.id, user.username);

  // Record login history
  const ipAddress = getRealIp(req);
  const userAgent = req.headers['user-agent'] || 'unknown';
  recordUserLogin(user.id, ipAddress, userAgent);

  const token = jwt.sign({ userId: user.id }, config.security.jwtSecret, { expiresIn: config.security.jwtExpiry });

  res.json({
    user: {
      id: user.id, username: user.username, email: user.email,
      role: user.role, online: true, emailVerified: !!user.email_verified,
      displayName: user.display_name || null,
      avatar: user.avatar || null,
      publicKey: user.public_key || null,
    },
    token,
  });
});

// Email verification
app.get('/api/verify-email', (req, res) => {
  const { token } = req.query;
  const user = dbGet('SELECT id FROM users WHERE verification_token = ?', [token]);
  if (!user) return res.status(400).send('Invalid or expired verification link');

  dbRun('UPDATE users SET email_verified = 1, verification_token = NULL WHERE id = ?', [user.id]);
  saveDatabase();
  res.send('<html><body style="font-family:Arial;text-align:center;padding:50px;"><h1 style="color:#4F46E5;">✓ Email Verified!</h1><p>You can now close this window and log in.</p></body></html>');
});

// ─── Password Reset ────────────────────────────────────────
const passwordResetStore = new Map(); // email -> { code, token, expires }

// Forgot password - send reset code
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body;
  
  if (!email) {
    return res.status(400).json({ error: 'Email is required' });
  }
  
  const normalizedEmail = email.trim().toLowerCase();
  
  // Check if user exists with this email
  const user = dbGet('SELECT id, username, email FROM users WHERE LOWER(email) = ?', [normalizedEmail]);
  
  // Always respond with success to prevent email enumeration
  // But only actually send email if user exists
  if (user && emailTransporter) {
    // Generate 6-digit code
    const code = String(Math.floor(100000 + Math.random() * 900000));
    const resetToken = uuidv4();
    const expires = Date.now() + 15 * 60 * 1000; // 15 minutes
    
    passwordResetStore.set(normalizedEmail, { code, token: resetToken, expires, userId: user.id });
    
    // Clean up expired entries
    for (const [key, val] of passwordResetStore) {
      if (val.expires < Date.now()) passwordResetStore.delete(key);
    }
    
    // Send email with code
    try {
      await emailTransporter.sendMail({
        from: `${config.email.from} <${config.email.gmail.email}>`,
        to: user.email,
        subject: 'Reset your 4 Messenger password',
        html: `
          <!DOCTYPE html>
          <html>
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
          </head>
          <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f4f4f5;">
            <table width="100%" cellpadding="0" cellspacing="0" style="background-color: #f4f4f5; padding: 40px 20px;">
              <tr>
                <td align="center">
                  <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.1);">
                    <!-- Header -->
                    <tr>
                      <td style="background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); padding: 30px; text-align: center;">
                        <h1 style="color: #ffffff; margin: 0; font-size: 32px; font-weight: bold;">4</h1>
                        <p style="color: #ffffff; margin: 5px 0 0 0; font-size: 14px; opacity: 0.9;">Messenger</p>
                      </td>
                    </tr>
                    
                    <!-- Content -->
                    <tr>
                      <td style="padding: 40px 30px;">
                        <h2 style="color: #1f2937; margin: 0 0 20px 0; font-size: 24px;">Password Reset</h2>
                        <p style="color: #4b5563; font-size: 16px; line-height: 24px; margin: 0 0 25px 0;">
                          Hi ${user.username}, we received a request to reset your password. Use the code below to complete the process:
                        </p>
                        
                        <!-- Code Box -->
                        <div style="text-align: center; padding: 20px 0;">
                          <div style="display: inline-block; background: linear-gradient(135deg, #4F46E5 0%, #7C3AED 100%); padding: 20px 40px; border-radius: 12px;">
                            <span style="font-size: 36px; font-weight: bold; color: #ffffff; letter-spacing: 8px; font-family: monospace;">${code}</span>
                          </div>
                        </div>
                        
                        <p style="color: #6b7280; font-size: 14px; line-height: 22px; margin: 25px 0 0 0; text-align: center;">
                          This code will expire in <strong>15 minutes</strong>.
                        </p>
                        
                        <p style="color: #9ca3af; font-size: 13px; line-height: 20px; margin: 25px 0 0 0; border-top: 1px solid #e5e7eb; padding-top: 20px;">
                          If you didn't request a password reset, you can safely ignore this email. Your password will not be changed.
                        </p>
                      </td>
                    </tr>
                    
                    <!-- Footer -->
                    <tr>
                      <td style="background-color: #f9fafb; padding: 20px 30px; text-align: center; border-top: 1px solid #e5e7eb;">
                        <p style="color: #9ca3af; font-size: 12px; margin: 0;">
                          © ${new Date().getFullYear()} 4 Messenger. Secure messaging for everyone.
                        </p>
                      </td>
                    </tr>
                  </table>
                </td>
              </tr>
            </table>
          </body>
          </html>
        `,
      });
      console.log(`[EMAIL] Password reset code sent to ${user.email}`);
    } catch (err) {
      console.error(`[EMAIL] Failed to send reset email:`, err.message);
    }
  }
  
  // Always return success (don't reveal if email exists)
  res.json({ success: true, message: 'If an account exists with that email, we have sent a reset code.' });
});

// Verify reset code
app.post('/api/verify-reset-code', (req, res) => {
  const { email, code } = req.body;
  
  if (!email || !code) {
    return res.status(400).json({ valid: false, error: 'Email and code are required' });
  }
  
  const normalizedEmail = email.trim().toLowerCase();
  const resetData = passwordResetStore.get(normalizedEmail);
  
  if (!resetData) {
    return res.json({ valid: false, error: 'No reset request found for this email' });
  }
  
  if (resetData.expires < Date.now()) {
    passwordResetStore.delete(normalizedEmail);
    return res.json({ valid: false, error: 'Code has expired' });
  }
  
  if (resetData.code !== code.trim()) {
    return res.json({ valid: false, error: 'Invalid code' });
  }
  
  // Code is valid - generate a one-time token for the actual reset
  const resetToken = uuidv4();
  resetData.resetToken = resetToken;
  resetData.codeVerified = true;
  passwordResetStore.set(normalizedEmail, resetData);
  
  res.json({ valid: true, resetToken });
});

// Reset password with verified token
app.post('/api/reset-password', (req, res) => {
  const { email, resetToken, newPassword } = req.body;
  
  if (!email || !resetToken || !newPassword) {
    return res.status(400).json({ success: false, error: 'Missing required fields' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ success: false, error: 'Password must be at least 6 characters' });
  }
  
  const normalizedEmail = email.trim().toLowerCase();
  const resetData = passwordResetStore.get(normalizedEmail);
  
  if (!resetData || !resetData.codeVerified || resetData.resetToken !== resetToken) {
    return res.status(400).json({ success: false, error: 'Invalid or expired reset token' });
  }
  
  if (resetData.expires < Date.now()) {
    passwordResetStore.delete(normalizedEmail);
    return res.status(400).json({ success: false, error: 'Reset token has expired' });
  }
  
  // Update password
  const hashedPassword = bcrypt.hashSync(newPassword, config.security.bcryptRounds);
  dbRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, resetData.userId]);
  saveDatabase();
  
  // Clear reset data
  passwordResetStore.delete(normalizedEmail);
  
  console.log(`[AUTH] Password reset successful for user ${resetData.userId}`);
  res.json({ success: true, message: 'Password has been reset successfully' });
});

// Get current user
app.get('/api/me', authMiddleware, (req, res) => {
  const { password, verification_token, ...user } = req.user;
  res.json(user);
});

// Get current user (alternative endpoint)
app.get('/api/users/me', authMiddleware, (req, res) => {
  const { password, verification_token, ...user } = req.user;
  res.json({
    ...user,
    displayName: user.display_name || null,
    publicKey: safeParseKey(user.public_key),
    isBot: !!user.is_bot
  });
});

// Update public key endpoint
app.put('/api/users/me/public-key', authMiddleware, (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey) return res.status(400).json({ error: 'Public key required' });
  
  const keyStr = typeof publicKey === 'string' ? publicKey : JSON.stringify(publicKey);
  dbRun('UPDATE users SET public_key = ? WHERE id = ?', [keyStr, req.user.id]);
  saveDatabase();
  res.json({ success: true });
});

// Get a user's public key for E2EE (needed before sending encrypted messages)
app.get('/api/users/:userId/public-key', authMiddleware, (req, res) => {
  const user = dbGet('SELECT id, public_key FROM users WHERE id = ?', [req.params.userId]);
  if (!user) {
    return res.status(404).json({ error: 'User not found' });
  }
  if (!user.public_key) {
    return res.status(404).json({ error: 'User has not set up E2EE yet' });
  }
  res.json({ publicKey: user.public_key });
});

// Logout
app.post('/api/logout', authMiddleware, (req, res) => {
  dbRun('UPDATE users SET online = 0, last_seen = ? WHERE id = ?', [Date.now(), req.user.id]);
  saveDatabase();
  res.json({ success: true });
});

// ─── 2FA / Two-Factor Authentication ─────────────────────

// Get 2FA status
app.get('/api/users/me/2fa/status', authMiddleware, (req, res) => {
  const user = dbGet('SELECT totp_enabled, email_2fa_enabled FROM users WHERE id = ?', [req.user.id]);
  const trustedDevicesCount = dbGet('SELECT COUNT(*) as count FROM trusted_devices WHERE user_id = ?', [req.user.id]);
  
  res.json({
    totpEnabled: !!user.totp_enabled,
    emailTwoFaEnabled: !!user.email_2fa_enabled,
    trustedDevicesCount: trustedDevicesCount?.count || 0
  });
});

// Setup authenticator 2FA - generate secret and QR code
app.post('/api/users/me/2fa/authenticator/setup', authMiddleware, async (req, res) => {
  if (!speakeasy || !QRCode) {
    return res.status(501).json({ error: '2FA not available on this server' });
  }

  const user = dbGet('SELECT email, username FROM users WHERE id = ?', [req.user.id]);
  
  // Generate secret
  const secret = speakeasy.generateSecret({
    name: `4Messenger (${user.email})`,
    issuer: '4Messenger',
    length: 32,
  });

  let qrCodeUrl;
  try {
    qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url);
  } catch (err) {
    return res.status(500).json({ error: 'Failed to generate QR code' });
  }

  res.json({
    secret: secret.base32,
    qrCode: qrCodeUrl,
    manualEntry: secret.otpauth_url.split('secret=')[1].split('&')[0],
  });
});

// Verify and enable authenticator 2FA
app.post('/api/users/me/2fa/authenticator/verify', authMiddleware, (req, res) => {
  if (!speakeasy) {
    return res.status(501).json({ error: '2FA not available on this server' });
  }

  const { secret, code, password } = req.body;
  
  if (!secret || !code || !password) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // Verify password
  const user = dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Verify TOTP code
  const verified = speakeasy.totp.verify({
    secret: secret,
    encoding: 'base32',
    token: code,
    window: 2,
  });

  if (!verified) {
    return res.status(400).json({ error: 'Invalid verification code' });
  }

  // Store encrypted secret
  dbRun('UPDATE users SET totp_secret = ?, totp_enabled = 1 WHERE id = ?', [
    Buffer.from(secret).toString('base64'),
    req.user.id
  ]);
  saveDatabase();

  res.json({ success: true, message: 'Authenticator 2FA enabled' });
});

// Setup email 2FA
app.post('/api/users/me/2fa/email/setup', authMiddleware, async (req, res) => {
  if (!config.email.verificationEnabled || !emailTransporter) {
    return res.status(501).json({ error: 'Email 2FA not available on this server' });
  }

  const { password } = req.body;
  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  const user = dbGet('SELECT password, email FROM users WHERE id = ?', [req.user.id]);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  // Generate 6-digit code
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 15 * 60 * 1000; // 15 minutes

  // Store code
  dbRun('DELETE FROM twofa_email_codes WHERE user_id = ?', [req.user.id]);
  dbRun('INSERT INTO twofa_email_codes (id, user_id, code, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
    [uuidv4(), req.user.id, code, expiresAt, Date.now()]
  );
  saveDatabase();

  // Send email
  try {
    await emailTransporter.sendMail({
      from: config.email.gmail.user,
      to: user.email,
      subject: '4Messenger - 2FA Email Code',
      html: `<p>Your 4Messenger 2FA verification code is:</p><h2>${code}</h2><p>This code expires in 15 minutes.</p>`,
    });
    res.json({ success: true, message: 'Verification code sent to your email' });
  } catch (err) {
    console.error('[EMAIL] Failed to send 2FA code:', err.message);
    res.status(500).json({ error: 'Failed to send email' });
  }
});

// Verify email 2FA code and enable
app.post('/api/users/me/2fa/email/verify', authMiddleware, (req, res) => {
  const { code, password } = req.body;
  if (!code) {
    return res.status(400).json({ error: 'Code required' });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  const user = dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  const record = dbGet('SELECT * FROM twofa_email_codes WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [req.user.id]);
  
  if (!record || record.expires_at < Date.now()) {
    return res.status(400).json({ error: 'Code expired' });
  }

  if (record.attempts_left <= 0) {
    return res.status(400).json({ error: 'Too many failed attempts. Please request a new code.' });
  }

  if (record.code !== code.toString()) {
    dbRun('UPDATE twofa_email_codes SET attempts_left = attempts_left - 1 WHERE id = ?', [record.id]);
    saveDatabase();
    return res.status(400).json({ error: 'Invalid code' });
  }

  // Code valid - enable email 2FA
  dbRun('UPDATE users SET email_2fa_enabled = 1 WHERE id = ?', [req.user.id]);
  dbRun('DELETE FROM twofa_email_codes WHERE id = ?', [record.id]);
  saveDatabase();

  res.json({ success: true, message: 'Email 2FA enabled' });
});

// Disable 2FA
app.post('/api/users/me/2fa/disable', authMiddleware, (req, res) => {
  const { method, password } = req.body; // method: 'totp' or 'email'
  
  if (!password) {
    return res.status(400).json({ error: 'Password required' });
  }

  const user = dbGet('SELECT password FROM users WHERE id = ?', [req.user.id]);
  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ error: 'Invalid password' });
  }

  if (method === 'totp') {
    dbRun('UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?', [req.user.id]);
  } else if (method === 'email') {
    dbRun('UPDATE users SET email_2fa_enabled = 0 WHERE id = ?', [req.user.id]);
  }

  saveDatabase();
  res.json({ success: true, message: `${method === 'totp' ? 'Authenticator' : 'Email'} 2FA disabled` });
});

// Verify 2FA during login (used after password verification)
app.post('/api/2fa/verify', (req, res) => {
  const { twoFaSessionToken, code, method } = req.body; // method: 'totp', 'email', 'trusted_device'
  
  if (!twoFaSessionToken) {
    return res.status(400).json({ error: 'No 2FA session' });
  }

  // Get 2FA session
  const session = dbGet('SELECT * FROM twofa_sessions WHERE session_token = ?', [twoFaSessionToken]);
  if (!session || session.expires_at < Date.now()) {
    return res.status(401).json({ error: '2FA session expired' });
  }

  if (session.attempts_left <= 0) {
    dbRun('DELETE FROM twofa_sessions WHERE id = ?', [session.id]);
    saveDatabase();
    return res.status(429).json({ error: 'Too many failed attempts. Please login again.' });
  }

  const user = dbGet('SELECT * FROM users WHERE id = ?', [session.user_id]);
  let verified = false;

  if (method === 'totp' && user.totp_enabled) {
    if (!speakeasy) {
      return res.status(501).json({ error: 'TOTP not available' });
    }
    const secret = Buffer.from(user.totp_secret, 'base64').toString('utf-8');
    verified = speakeasy.totp.verify({
      secret: secret,
      encoding: 'base32',
      token: code,
      window: 2,
    });
  } else if (method === 'email' && user.email_2fa_enabled) {
    const emailCode = dbGet('SELECT * FROM twofa_email_codes WHERE user_id = ? ORDER BY created_at DESC LIMIT 1', [session.user_id]);
    if (emailCode && emailCode.expires_at > Date.now()) {
      verified = emailCode.code === code.toString();
      if (verified) {
        dbRun('DELETE FROM twofa_email_codes WHERE id = ?', [emailCode.id]);
      }
    }
  } else if (method === 'trusted_device') {
    // For trusted device, we verify the device token
    const device = dbGet('SELECT * FROM trusted_devices WHERE user_id = ? AND device_token = ?', [session.user_id, code]);
    verified = !!device;
    if (verified) {
      dbRun('UPDATE trusted_devices SET last_used = ? WHERE id = ?', [Date.now(), device.id]);
    }
  }

  if (!verified) {
    dbRun('UPDATE twofa_sessions SET attempts_left = attempts_left - 1 WHERE id = ?', [session.id]);
    saveDatabase();
    return res.status(401).json({ error: 'Invalid 2FA code' });
  }

  // 2FA verified - create JWT token
  dbRun('DELETE FROM twofa_sessions WHERE id = ?', [session.id]);
  saveDatabase();

  const token = jwt.sign({ userId: user.id }, config.security.jwtSecret, { expiresIn: config.security.jwtExpiry });

  res.json({
    user: {
      id: user.id, username: user.username, email: user.email,
      role: user.role, online: true, emailVerified: !!user.email_verified,
      displayName: user.display_name || null,
      avatar: user.avatar || null,
      publicKey: user.public_key || null,
    },
    token,
  });
});

// Send 2FA email code during login
app.post('/api/2fa/email/send', (req, res) => {
  const { twoFaSessionToken } = req.body;
  
  if (!twoFaSessionToken || !config.email.verificationEnabled || !emailTransporter) {
    return res.status(400).json({ error: 'Invalid request' });
  }

  const session = dbGet('SELECT * FROM twofa_sessions WHERE session_token = ?', [twoFaSessionToken]);
  if (!session) {
    return res.status(401).json({ error: 'Invalid 2FA session' });
  }

  const user = dbGet('SELECT email FROM users WHERE id = ?', [session.user_id]);
  const code = Math.floor(100000 + Math.random() * 900000).toString();
  const expiresAt = Date.now() + 15 * 60 * 1000;

  // Store code
  dbRun('DELETE FROM twofa_email_codes WHERE user_id = ?', [session.user_id]);
  dbRun('INSERT INTO twofa_email_codes (id, user_id, code, expires_at, created_at) VALUES (?, ?, ?, ?, ?)',
    [uuidv4(), session.user_id, code, expiresAt, Date.now()]
  );
  saveDatabase();

  // Send email
  emailTransporter.sendMail({
    from: config.email.gmail.user,
    to: user.email,
    subject: '4Messenger - 2FA Code',
    html: `<p>Your 2FA verification code:</p><h2>${code}</h2><p>Expires in 15 minutes.</p>`,
  }).catch(err => {
    console.error('[EMAIL] Failed to send 2FA email:', err.message);
  });

  res.json({ success: true, message: 'Code sent to email' });
});

// Trusted device management
app.post('/api/users/me/trusted-devices', authMiddleware, (req, res) => {
  const { deviceName } = req.body;
  if (!deviceName) {
    return res.status(400).json({ error: 'Device name required' });
  }

  // Check if 2FA is enabled
  const user = dbGet('SELECT totp_enabled, email_2fa_enabled FROM users WHERE id = ?', [req.user.id]);
  if (!user || (!user.totp_enabled && !user.email_2fa_enabled)) {
    return res.status(403).json({ error: '2FA must be enabled to add trusted devices' });
  }

  try {
    const deviceToken = uuidv4();
    dbRun('INSERT INTO trusted_devices (id, user_id, device_name, device_token, created_at) VALUES (?, ?, ?, ?, ?)',
      [uuidv4(), req.user.id, deviceName, deviceToken, Date.now()]
    );
    saveDatabase();

    res.json({ success: true, deviceToken });
  } catch (err) {
    console.error('[TRUSTED_DEVICES] Error adding device:', err);
    return res.status(500).json({ error: 'Failed to add trusted device' });
  }
});

// List trusted devices
app.get('/api/users/me/trusted-devices', authMiddleware, (req, res) => {
  const devices = dbAll('SELECT id, device_name, last_used, created_at FROM trusted_devices WHERE user_id = ? ORDER BY last_used DESC', [req.user.id]);
  res.json({ devices: devices || [] });
});

// Remove trusted device
app.delete('/api/users/me/trusted-devices/:id', authMiddleware, (req, res) => {
  dbRun('DELETE FROM trusted_devices WHERE id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDatabase();
  res.json({ success: true });
});

// Get user settings
app.get('/api/users/me/settings', authMiddleware, (req, res) => {
  res.json({
    displayName: req.user.display_name || null,
    avatar: req.user.avatar || null,
    theme: req.user.theme || 'dark',
  });
});

// Update user settings (display name, avatar)
app.put('/api/users/me/settings', authMiddleware, (req, res) => {
  const { displayName, avatar } = req.body;
  
  dbRun('UPDATE users SET display_name = ?, avatar = ? WHERE id = ?', [
    displayName || null,
    avatar || null,
    req.user.id
  ]);
  saveDatabase();
  
  res.json({ success: true });
});

// Change password
app.put('/api/users/me/password', authMiddleware, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Current and new password required' });
  }
  
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters' });
  }
  
  // Verify current password
  if (!bcrypt.compareSync(currentPassword, req.user.password)) {
    return res.status(400).json({ error: 'Current password is incorrect' });
  }
  
  // Hash and save new password
  const hashedPassword = bcrypt.hashSync(newPassword, config.security.bcryptRounds);
  dbRun('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, req.user.id]);
  saveDatabase();
  
  res.json({ success: true });
});

// --- PUSH NOTIFICATION ENDPOINTS ---

// Get VAPID public key (needed for browser to subscribe to push)
app.get('/api/push/vapid-key', (req, res) => {
  if (!webpush || !config.push || !config.push.vapidPublicKey) {
    return res.status(503).json({ error: 'Push notifications not available' });
  }
  res.json({ 
    vapidPublicKey: config.push.vapidPublicKey 
  });
});

// Subscribe to push notifications
app.post('/api/push/subscribe', authMiddleware, (req, res) => {
  if (!webpush) {
    return res.status(503).json({ error: 'Push notifications not available' });
  }

  const { subscription } = req.body;
  if (!subscription || !subscription.endpoint || !subscription.keys) {
    return res.status(400).json({ error: 'Invalid subscription data' });
  }

  try {
    const id = uuidv4();
    const { endpoint, keys } = subscription;
    const { auth, p256dh } = keys;

    // Check if already exists
    const existing = dbGet('SELECT id FROM push_subscriptions WHERE endpoint = ?', [endpoint]);
    
    if (existing) {
      // Update existing subscription
      dbRun(
        'UPDATE push_subscriptions SET user_id = ?, created_at = ? WHERE endpoint = ?',
        [req.user.id, Date.now(), endpoint]
      );
    } else {
      // Insert new subscription
      dbRun(
        `INSERT INTO push_subscriptions (id, user_id, endpoint, auth_key, p256dh_key, created_at)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [id, req.user.id, endpoint, auth, p256dh, Date.now()]
      );
    }
    
    saveDatabase();

    res.json({ success: true, subscriptionId: id });
  } catch (err) {
    console.error('[PUSH] Failed to subscribe:', err.message);
    res.status(500).json({ error: 'Failed to subscribe to push notifications' });
  }
});

// Unsubscribe from push notifications
app.post('/api/push/unsubscribe', authMiddleware, (req, res) => {
  const { endpoint } = req.body;
  if (!endpoint) {
    return res.status(400).json({ error: 'Endpoint required' });
  }

  try {
    dbRun('DELETE FROM push_subscriptions WHERE user_id = ? AND endpoint = ?', [req.user.id, endpoint]);
    saveDatabase();
    res.json({ success: true });
  } catch (err) {
    console.error('[PUSH] Failed to unsubscribe:', err.message);
    res.status(500).json({ error: 'Failed to unsubscribe' });
  }
});

// Get user's push subscriptions
app.get('/api/push/subscriptions', authMiddleware, (req, res) => {
  try {
    const subscriptions = dbAll(
      'SELECT id, endpoint, created_at FROM push_subscriptions WHERE user_id = ?',
      [req.user.id]
    );
    res.json(subscriptions);
  } catch (err) {
    console.error('[PUSH] Failed to get subscriptions:', err.message);
    res.status(500).json({ error: 'Failed to get subscriptions' });
  }
});

// --- MUTED USERS ENDPOINTS ---

// Get list of muted users
app.get('/api/muted-users', authMiddleware, (req, res) => {
  try {
    const mutedUsers = dbAll(
      `SELECT u.id, u.username, u.display_name, u.avatar, mu.created_at 
       FROM muted_users mu
       JOIN users u ON mu.muted_user_id = u.id
       WHERE mu.user_id = ?
       ORDER BY mu.created_at DESC`,
      [req.user.id]
    );
    res.json(mutedUsers);
  } catch (err) {
    console.error('[MUTE] Failed to get muted users:', err.message);
    res.status(500).json({ error: 'Failed to get muted users' });
  }
});

// Mute a user (block notifications from them)
app.post('/api/muted-users/:userId', authMiddleware, (req, res) => {
  const mutedUserId = req.params.userId;
  
  if (!mutedUserId) {
    return res.status(400).json({ error: 'User ID required' });
  }
  
  if (mutedUserId === req.user.id) {
    return res.status(400).json({ error: 'Cannot mute yourself' });
  }

  try {
    // Check if user exists
    const user = dbGet('SELECT id FROM users WHERE id = ?', [mutedUserId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Check if already muted
    const existing = dbGet('SELECT * FROM muted_users WHERE user_id = ? AND muted_user_id = ?', [req.user.id, mutedUserId]);
    if (existing) {
      return res.status(400).json({ error: 'User already muted' });
    }

    dbRun(
      'INSERT INTO muted_users (user_id, muted_user_id, created_at) VALUES (?, ?, ?)',
      [req.user.id, mutedUserId, Date.now()]
    );
    saveDatabase();
    
    console.log(`[MUTE] User ${req.user.id} muted ${mutedUserId}`);
    res.json({ success: true, mutedUserId });
  } catch (err) {
    console.error('[MUTE] Failed to mute user:', err.message);
    res.status(500).json({ error: 'Failed to mute user' });
  }
});

// Unmute a user (resume notifications from them)
app.delete('/api/muted-users/:userId', authMiddleware, (req, res) => {
  const mutedUserId = req.params.userId;
  
  if (!mutedUserId) {
    return res.status(400).json({ error: 'User ID required' });
  }

  try {
    const result = dbRun(
      'DELETE FROM muted_users WHERE user_id = ? AND muted_user_id = ?',
      [req.user.id, mutedUserId]
    );
    
    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not muted' });
    }
    
    saveDatabase();
    console.log(`[MUTE] User ${req.user.id} unmuted ${mutedUserId}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[MUTE] Failed to unmute user:', err.message);
    res.status(500).json({ error: 'Failed to unmute user' });
  }
});

// Get list of blocked users
app.get('/api/blocked-users', authMiddleware, (req, res) => {
  try {
    const blockedUsers = dbAll(
      `SELECT u.id, u.username, u.display_name, u.avatar, bu.created_at
       FROM blocked_users bu
       JOIN users u ON bu.blocked_user_id = u.id
       WHERE bu.user_id = ?
       ORDER BY bu.created_at DESC`,
      [req.user.id]
    );
    res.json(blockedUsers);
  } catch (err) {
    console.error('[BLOCK] Failed to get blocked users:', err.message);
    res.status(500).json({ error: 'Failed to get blocked users' });
  }
});

// Block a user
app.post('/api/blocked-users/:userId', authMiddleware, (req, res) => {
  const blockedUserId = req.params.userId;

  if (!blockedUserId) {
    return res.status(400).json({ error: 'User ID required' });
  }

  if (blockedUserId === req.user.id) {
    return res.status(400).json({ error: 'Cannot block yourself' });
  }

  try {
    const user = dbGet('SELECT id FROM users WHERE id = ?', [blockedUserId]);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const existing = dbGet('SELECT * FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?', [req.user.id, blockedUserId]);
    if (existing) {
      return res.status(400).json({ error: 'User already blocked' });
    }

    dbRun('INSERT INTO blocked_users (user_id, blocked_user_id, created_at) VALUES (?, ?, ?)', [req.user.id, blockedUserId, Date.now()]);
    saveDatabase();

    console.log(`[BLOCK] User ${req.user.id} blocked ${blockedUserId}`);
    res.json({ success: true, blockedUserId });
  } catch (err) {
    console.error('[BLOCK] Failed to block user:', err.message);
    res.status(500).json({ error: 'Failed to block user' });
  }
});

// Unblock a user
app.delete('/api/blocked-users/:userId', authMiddleware, (req, res) => {
  const blockedUserId = req.params.userId;

  if (!blockedUserId) {
    return res.status(400).json({ error: 'User ID required' });
  }

  try {
    const result = dbRun('DELETE FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?', [req.user.id, blockedUserId]);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'User not blocked' });
    }

    saveDatabase();
    console.log(`[BLOCK] User ${req.user.id} unblocked ${blockedUserId}`);
    res.json({ success: true });
  } catch (err) {
    console.error('[BLOCK] Failed to unblock user:', err.message);
    res.status(500).json({ error: 'Failed to unblock user' });
  }
});

// --- BOT ENDPOINTS ---
app.get('/api/bots', authMiddleware, (req, res) => {
  const bots = dbAll(`SELECT id, username, display_name as displayName, avatar, bot_script as script, created_at FROM users WHERE is_bot = 1 AND owner_id = ?`, [req.user.id]);
  res.json(bots);
});

app.post('/api/bots', authMiddleware, (req, res) => {
  const { username, displayName, script } = req.body;
  if (!username || !script) return res.status(400).json({ error: 'Username and script required' });
  const existing = dbGet(`SELECT id FROM users WHERE LOWER(username) = LOWER(?)`, [username]);
  if (existing) return res.status(400).json({ error: 'Username already taken' });
  
  const botId = `bot-${Date.now()}`;
  const dummyEmail = `${botId}@bot.local`;
  
  try {
    dbRun(`INSERT INTO users (id, username, email, display_name, password, is_bot, owner_id, bot_script, created_at) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)`,
      [botId, username, dummyEmail, displayName || username, 'bot_pass', req.user.id, script, Date.now()]);
    
    const newBot = dbGet(`SELECT * FROM users WHERE id = ?`, [botId]);
    startBotNode(newBot);
    res.json({ id: botId, username, displayName, script });
  } catch (error) {
    console.error('Create bot error', error);
    res.status(500).json({ error: 'Failed to create bot' });
  }
});

app.put('/api/bots/:id', authMiddleware, (req, res) => {
  const { script, displayName } = req.body;
  const bot = dbGet(`SELECT id FROM users WHERE id = ? AND owner_id = ?`, [req.params.id, req.user.id]);
  if (!bot) return res.status(403).json({ error: 'Unauthorized' });
  dbRun(`UPDATE users SET bot_script = ?, display_name = ? WHERE id = ?`, [script, displayName, req.params.id]);
  stopBotNode(req.params.id);
  const updatedBot = dbGet(`SELECT * FROM users WHERE id = ?`, [req.params.id]);
  startBotNode(updatedBot);
  res.json({ success: true });
});

app.delete('/api/bots/:id', authMiddleware, (req, res) => {
  const bot = dbGet(`SELECT id FROM users WHERE id = ? AND owner_id = ?`, [req.params.id, req.user.id]);
  if (!bot) return res.status(403).json({ error: 'Unauthorized' });
  stopBotNode(req.params.id);
  dbRun(`DELETE FROM users WHERE id = ?`, [req.params.id]);
  res.json({ success: true });
});
// ---------------------

function safeParseKey(key) {
  if (!key) return null;
  try { return typeof key === 'string' ? JSON.parse(key) : key; }
  catch(e) { return null; }
}

// Get all users - admins can search partial, others need exact username
app.get('/api/users', authMiddleware, (req, res) => {
  const { search } = req.query;
  const isAdmin = req.user.role === 'admin';
  
  if (search && search.trim()) {
    let users;
    
    if (isAdmin) {
      const searchPattern = `%${search.trim().toLowerCase()}%`;
      users = dbAll(`
        SELECT id, username, email, public_key, role, avatar, display_name, online, last_seen, email_verified, created_at, is_bot, bot_approved
        FROM users 
        WHERE (LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(display_name) LIKE ?) 
        AND id != ?
      `, [searchPattern, searchPattern, searchPattern, req.user.id]);
    } else {
      const searchPattern = `%${search.trim().toLowerCase()}%`;
      users = dbAll(`
        SELECT id, username, email, public_key, role, avatar, display_name, online, last_seen, email_verified, created_at, is_bot, bot_approved
        FROM users 
        WHERE (LOWER(username) LIKE ? OR LOWER(display_name) LIKE ?) AND id != ? AND role != 'banned'
          AND (is_bot = 0 OR COALESCE(bot_approved, 1) = 1)
      `, [searchPattern, searchPattern, req.user.id]);
    }
    
    return res.json(users.map(u => ({ ...u, displayName: u.display_name, publicKey: safeParseKey(u.public_key), isBot: !!u.is_bot })));
  }
  
  if (isAdmin) {
    const users = dbAll(`
      SELECT id, username, email, public_key, role, avatar, display_name, online, last_seen, email_verified, created_at, is_bot, bot_approved
      FROM users 
      WHERE id != ?
      ORDER BY created_at DESC
    `, [req.user.id]);
    return res.json(users.map(u => ({ ...u, displayName: u.display_name, publicKey: safeParseKey(u.public_key), isBot: !!u.is_bot })));
  }
  
  const users = dbAll(`
    SELECT DISTINCT u.id, u.username, u.email, u.public_key, u.role, u.avatar, u.display_name, u.online, u.last_seen, u.email_verified, u.created_at, u.is_bot, u.bot_approved 
    FROM users u
    JOIN chat_members cm1 ON u.id = cm1.user_id
    JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
    WHERE cm2.user_id = ? AND u.id != ? AND u.role != 'banned'
      AND (u.is_bot = 0 OR COALESCE(u.bot_approved, 1) = 1)
  `, [req.user.id, req.user.id]);
  
  res.json(users.map(u => ({ ...u, displayName: u.display_name, publicKey: safeParseKey(u.public_key), isBot: !!u.is_bot })));
});

// Update user role (admin and owner only, with restrictions)
app.put('/api/users/:id/role', authMiddleware, adminMiddleware, (req, res) => {
  const { role } = req.body;
  
  // Owner can set any role, admin cannot set owner role
  if (req.user.role === 'admin' && role === 'owner') {
    return res.status(403).json({ error: 'Only owners can set the owner role' });
  }
  
  if (!['admin', 'moderator', 'user', 'banned', 'owner'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Prevent changing owner roles (only allowed via special owner removal endpoint)
  if (targetUser.role === 'owner' && req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Cannot modify owner role from here. Use the special owner management panel.' });
  }
  
  // Owner cannot remove other owner roles directly
  if (targetUser.role === 'owner' && req.user.role === 'owner' && req.params.id !== req.user.id) {
    return res.status(403).json({ error: 'Cannot remove another owner. Use the special owner management panel.' });
  }
  
  const ipAddress = getRealIp(req);
  
  dbRun('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  saveDatabase();
  
  // Log audit action
  logAuditAction(req.user.id, 'change_role', req.params.id, 'user', targetUser.role, role, ipAddress);
  
  broadcastToAll({ type: 'user_updated', userId: req.params.id, role });
  res.json({ success: true });
});

// Special owner removal endpoint (owner only, requires password verification)
app.post('/api/owner/remove-owner', authMiddleware, ownerMiddleware, async (req, res) => {
  const { password, emailCode } = req.body;
  
  // Only owner role can use this
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner access required' });
  }
  
  // Verify password
  const isPasswordValid = await bcrypt.compare(password, req.user.password);
  if (!isPasswordValid) {
    return res.status(401).json({ error: 'Invalid password' });
  }
  
  // If email verification is enabled, check email code
  if (config.email.verificationEnabled && req.user.email_verified) {
    // For now, we'll accept the email code if provided (in production, you'd verify against code sent)
    // In a real implementation, we'd store the code in DB with expiry and compare
    if (!emailCode || emailCode.length !== 6 || !/^\d+$/.test(emailCode)) {
      return res.status(401).json({ error: 'Invalid email verification code' });
    }
    
    // In production, verify the code against DB
    // For demo, we accept any 6-digit code (should be replaced with actual verification)
    console.log('[OWNER] Email code provided (not actually verified in this demo)');
  }
  
  const ipAddress = getRealIp(req);
  
  // Remove owner role, set to admin
  dbRun('UPDATE users SET role = ? WHERE id = ?', ['admin', req.user.id]);
  saveDatabase();
  
  // Log audit action
  logAuditAction(req.user.id, 'remove_owner_role', req.user.id, 'user', 'owner', 'admin', ipAddress);
  
  console.log(`[OWNER] Owner ${req.user.username} removed owner role from themselves`);
  broadcastToAll({ type: 'user_updated', userId: req.user.id, role: 'admin' });
  res.json({ success: true, message: 'Owner role removed. You now have admin role.' });
});

// Ban user
app.post('/api/users/:id/ban', authMiddleware, modMiddleware, (req, res) => {
  // Get target user
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Can't ban owner
  if (targetUser.role === 'owner') {
    return res.status(403).json({ error: 'Cannot ban the owner' });
  }
  
  // Admins can't ban other admins
  if (req.user.role === 'admin' && targetUser.role === 'admin' && req.params.id !== req.user.id) {
    return res.status(403).json({ error: 'Admins cannot ban other admins' });
  }
  
  // Moderators can't ban admins or other moderators
  if (req.user.role === 'moderator' && ['admin', 'moderator'].includes(targetUser.role)) {
    return res.status(403).json({ error: 'Moderators cannot ban admins or other moderators' });
  }
  
  // Can't ban yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot ban yourself' });
  }
  
  const ipAddress = getRealIp(req);
  
  dbRun('UPDATE users SET role = ?, online = 0 WHERE id = ?', ['banned', req.params.id]);
  saveDatabase();
  
  // Log audit action
  logAuditAction(req.user.id, 'ban_user', req.params.id, 'user', targetUser.role, 'banned', ipAddress);
  
  broadcastToAll({ type: 'user_banned', userId: req.params.id });
  res.json({ success: true });
});

// Unban user
app.post('/api/users/:id/unban', authMiddleware, modMiddleware, (req, res) => {
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  const ipAddress = getRealIp(req);
  
  dbRun('UPDATE users SET role = ? WHERE id = ?', ['user', req.params.id]);
  saveDatabase();
  
  // Log audit action
  logAuditAction(req.user.id, 'unban_user', req.params.id, 'user', 'banned', 'user', ipAddress);
  
  res.json({ success: true });
});

// Delete user (admin only)
app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  // Can't delete yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }
  
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  const ipAddress = getRealIp(req);
  
  dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  saveDatabase();
  
  // Log audit action
  if (targetUser) {
    logAuditAction(req.user.id, 'delete_user', req.params.id, 'user', targetUser.username, 'deleted', ipAddress);
  }
  
  res.json({ success: true });
});

// Kick user (disconnect from server)
app.post('/api/users/:id/kick', authMiddleware, modMiddleware, (req, res) => {
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Can't kick owner
  if (targetUser.role === 'owner') {
    return res.status(403).json({ error: 'Cannot kick the owner' });
  }
  
  // Admins can't kick other admins
  if (req.user.role === 'admin' && targetUser.role === 'admin' && req.params.id !== req.user.id) {
    return res.status(403).json({ error: 'Admins cannot kick other admins' });
  }
  
  // Moderators can't kick admins or other moderators
  if (req.user.role === 'moderator' && ['admin', 'moderator'].includes(targetUser.role)) {
    return res.status(403).json({ error: 'Moderators cannot kick admins or other moderators' });
  }
  
  // Can't kick yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot kick yourself' });
  }
  
  const ipAddress = getRealIp(req);
  
  // Send kick message to the user
  sendToUser(req.params.id, { type: 'kicked', reason: req.body.reason || 'You have been kicked from the server' });
  
  // Close their websocket connections
  const sockets = wsClients.get(req.params.id);
  if (sockets) {
    sockets.forEach(ws => {
      ws.close(1000, 'Kicked by moderator');
    });
    wsClients.delete(req.params.id);
  }
  
  // Update user status
  dbRun('UPDATE users SET online = 0 WHERE id = ?', [req.params.id]);
  saveDatabase();
  
  // Log audit action
  logAuditAction(req.user.id, 'kick_user', req.params.id, 'user', 'online', 'kicked', ipAddress);
  
  broadcastToAll({ type: 'user_offline', userId: req.params.id });
  res.json({ success: true });
});

// Kick all users (admin only)
app.post('/api/admin/kick-all', authMiddleware, adminMiddleware, (req, res) => {
  const ipAddress = getRealIp(req);
  
  // Send kick message to all users except admin
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'kicked', reason: 'Server is disconnecting all users' }));
      ws.close(1000, 'Kicked by admin');
    }
  });
  
  wsClients.clear();
  dbRun('UPDATE users SET online = 0');
  saveDatabase();
  
  res.json({ success: true });
});

// ─── Chat Routes ───────────────────────────────────────────

// Get user's chats
app.get('/api/chats', authMiddleware, (req, res) => {
  const chats = dbAll(`
    SELECT c.*, cm.is_admin FROM chats c
    JOIN chat_members cm ON c.id = cm.chat_id
    WHERE cm.user_id = ?
    ORDER BY c.created_at DESC
  `, [req.user.id]);

  const result = chats.map(chat => {
    const members = dbAll('SELECT user_id, is_admin FROM chat_members WHERE chat_id = ?', [chat.id]);
    const lastMessage = dbGet('SELECT * FROM messages WHERE chat_id = ? ORDER BY created_at DESC LIMIT 1', [chat.id]);
    
    // Calculate unread count
    const totalMessages = dbGet('SELECT COUNT(*) as count FROM messages WHERE chat_id = ?', [chat.id]);
    const readMessages = dbGet('SELECT COUNT(*) as count FROM message_reads mr JOIN messages m ON mr.message_id = m.id WHERE m.chat_id = ? AND mr.user_id = ?', [chat.id, req.user.id]);
    const unreadCount = (totalMessages?.count || 0) - (readMessages?.count || 0);
    
    // Get channel admins if it's a channel
    let channelAdmins = [];
    let isChannelAdmin = false;
    if (chat.is_channel) {
      const admins = dbAll('SELECT user_id FROM channel_admins WHERE chat_id = ?', [chat.id]);
      channelAdmins = admins.map(a => a.user_id);
      isChannelAdmin = channelAdmins.includes(req.user.id);
    }
    
    // E2EE: Don't decrypt on server - client handles decryption
    // For display in chat list, we just pass through as-is
    let lastMsg = lastMessage;
    
    return {
      ...chat,
      isChannel: !!chat.is_channel,
      participants: members.map(m => m.user_id),
      admins: members.filter(m => m.is_admin).map(m => m.user_id),
      channelAdmins,
      isChannelAdmin,
      lastMessage: lastMsg,
      unreadCount: Math.max(0, unreadCount),
    };
  });

  // Attach encrypted keys for the current user
  const chatKeys = dbAll(`SELECT chat_id, encrypted_key FROM chat_keys WHERE user_id = ?`, [req.user.id]);
  const keyMap = {};
  chatKeys.forEach(k => {
    // Safely parse JSON if the key was stored as a JSON string
    let keyVal = k.encrypted_key;
    try { if (keyVal && keyVal.startsWith('{')) keyVal = JSON.parse(keyVal); } catch(e) {}
    keyMap[k.chat_id] = keyVal;
  });
  
  result.forEach(chat => {
    chat.encryptedKey = keyMap[chat.id];
  });

  res.json(result);
});

// Create direct chat
app.post('/api/chats/direct', authMiddleware, (req, res) => {
  const { userId, encryptedKeys } = req.body;

  // Block access to unapproved bots for non-admins/non-owners
  const targetUser = dbGet('SELECT id, is_bot, owner_id, bot_approved FROM users WHERE id = ?', [userId]);
  if (targetUser && targetUser.is_bot) {
    const approved = (targetUser.bot_approved === 1) || (targetUser.bot_approved === true);
    const isOwner = targetUser.owner_id === req.user.id;
    const isAdmin = req.user.role === 'admin';
    if (!approved && !isAdmin && !isOwner) {
      return res.status(403).json({ error: 'This bot not approved' });
    }
  }

  // Check if chat exists
  const existing = dbGet(`
    SELECT c.id FROM chats c
    JOIN chat_members cm1 ON c.id = cm1.chat_id AND cm1.user_id = ?
    JOIN chat_members cm2 ON c.id = cm2.chat_id AND cm2.user_id = ?
    WHERE c.type = 'direct'
  `, [req.user.id, userId]);

  if (existing) return res.json({ chatId: existing.id });

  const chatId = uuidv4();
  const now = Date.now();
  dbRun('INSERT INTO chats (id, type, created_at) VALUES (?, ?, ?)', [chatId, 'direct', now]);
  dbRun('INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, req.user.id, now]);
  dbRun('INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, userId, now]);
  
  if (encryptedKeys) {
    for (const [uid, key] of Object.entries(encryptedKeys)) {
      dbRun('INSERT INTO chat_keys (chat_id, user_id, encrypted_key) VALUES (?, ?, ?)', [chatId, uid, key]);
    }
  }
  
  saveDatabase();

  res.status(201).json({ chatId });
});

// Create group or channel
app.post('/api/chats/group', authMiddleware, (req, res) => {
  const { name, description, participants, isChannel, encryptedKeys } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });

  // Block adding unapproved bots (unless requester is admin or bot owner)
  if (participants && Array.isArray(participants) && participants.length > 0) {
    for (const uid of participants) {
      const u = dbGet('SELECT id, is_bot, owner_id, bot_approved FROM users WHERE id = ?', [uid]);
      if (u && u.is_bot) {
        const approved = (u.bot_approved === 1) || (u.bot_approved === true);
        const isOwner = u.owner_id === req.user.id;
        const isAdmin = req.user.role === 'admin';
        if (!approved && !isAdmin && !isOwner) {
          return res.status(403).json({ error: 'This bot not approved' });
        }
      }
    }
  }

  const chatId = uuidv4();
  const now = Date.now();
  const chatType = isChannel ? 'channel' : 'group';
  
  dbRun('INSERT INTO chats (id, type, name, description, is_channel, created_at) VALUES (?, ?, ?, ?, ?, ?)', 
    [chatId, chatType, name, description || null, isChannel ? 1 : 0, now]);
  dbRun('INSERT INTO chat_members (chat_id, user_id, is_admin, joined_at) VALUES (?, ?, 1, ?)', [chatId, req.user.id, now]);

  // For channels, creator becomes channel admin
  if (isChannel) {
    dbRun('INSERT INTO channel_admins (chat_id, user_id) VALUES (?, ?)', [chatId, req.user.id]);
  }

  if (participants && Array.isArray(participants)) {
    participants.forEach(uid => {
      dbRun('INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, uid, now]);
    });
  }

  if (encryptedKeys) {
    for (const [uid, key] of Object.entries(encryptedKeys)) {
      dbRun('INSERT INTO chat_keys (chat_id, user_id, encrypted_key) VALUES (?, ?, ?)', [chatId, uid, key]);
    }
  }

  // System message
  const msgId = uuidv4();
  const msgContent = isChannel 
    ? `${req.user.username} created the channel "${name}"`
    : `${req.user.username} created the group "${name}"`;
  dbRun('INSERT INTO messages (id, chat_id, sender_id, content, type, created_at) VALUES (?, ?, ?, ?, ?, ?)', [
    msgId, chatId, req.user.id, msgContent, 'system', now
  ]);
  
  saveDatabase();

  res.status(201).json({ chatId });
});

// Make user a channel admin
app.post('/api/chats/:id/admins', authMiddleware, (req, res) => {
  const { userId } = req.body;
  const chatId = req.params.id;
  
  const chat = dbGet('SELECT * FROM chats WHERE id = ?', [chatId]);
  if (!chat || !chat.is_channel) {
    return res.status(400).json({ error: 'Not a channel' });
  }
  
  // Check if requester is channel admin
  const isAdmin = dbGet('SELECT * FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!isAdmin && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only channel admins can add admins' });
  }
  
  dbRun('INSERT OR IGNORE INTO channel_admins (chat_id, user_id) VALUES (?, ?)', [chatId, userId]);
  saveDatabase();
  res.json({ success: true });
});

// Update group/channel settings (name, icon, description)
app.put('/api/chats/:id/settings', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const { name, avatar, description } = req.body;
  
  const chat = dbGet('SELECT * FROM chats WHERE id = ?', [chatId]);
  if (!chat) return res.status(404).json({ error: 'Chat not found' });
  
  // Only works for groups and channels
  if (chat.type === 'direct') {
    return res.status(400).json({ error: 'Cannot update settings for direct chats' });
  }
  
  // Check if user is a group admin
  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member of this chat' });
  
  // For channels, check if user is channel admin
  if (chat.is_channel) {
    const isChannelAdmin = dbGet('SELECT * FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
    if (!isChannelAdmin && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only channel admins can update channel settings' });
    }
  } else {
    // For groups, check if user is group admin
    if (!member.is_admin && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only group admins can update group settings' });
    }
  }
  
  // Update the chat
  const updates = [];
  const params = [];
  
  if (name !== undefined) {
    updates.push('name = ?');
    params.push(name);
  }
  if (avatar !== undefined) {
    updates.push('avatar = ?');
    params.push(avatar);
  }
  if (description !== undefined) {
    updates.push('description = ?');
    params.push(description);
  }
  
  if (updates.length > 0) {
    params.push(chatId);
    dbRun(`UPDATE chats SET ${updates.join(', ')} WHERE id = ?`, params);
    saveDatabase();
    
    // Broadcast update to all members
    const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
    members.forEach(m => {
      sendToUser(m.user_id, { 
        type: 'chat_updated', 
        chatId,
        name: name !== undefined ? name : chat.name,
        avatar: avatar !== undefined ? avatar : chat.avatar,
        description: description !== undefined ? description : chat.description,
      });
    });
  }
  
  res.json({ success: true });
});

// Remove channel admin
app.delete('/api/chats/:id/admins/:userId', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const userId = req.params.userId;
  
  const chat = dbGet('SELECT * FROM chats WHERE id = ?', [chatId]);
  if (!chat || !chat.is_channel) {
    return res.status(400).json({ error: 'Not a channel' });
  }
  
  // Check if requester is channel admin
  const isAdmin = dbGet('SELECT * FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!isAdmin && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only channel admins can remove admins' });
  }
  
  // Can't remove yourself
  if (userId === req.user.id) {
    return res.status(400).json({ error: 'Cannot remove yourself as admin' });
  }
  
  dbRun('DELETE FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, userId]);
  saveDatabase();
  res.json({ success: true });
});

// Add member to group
app.post('/api/chats/:id/members', authMiddleware, (req, res) => {
  const { userId, encryptedKey } = req.body;
  const chatId = req.params.id;

  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  // Block adding unapproved bots (unless requester is admin or bot owner)
  const target = dbGet('SELECT id, is_bot, owner_id, bot_approved FROM users WHERE id = ?', [userId]);
  if (target && target.is_bot) {
    const approved = (target.bot_approved === 1) || (target.bot_approved === true);
    const isOwner = target.owner_id === req.user.id;
    const isAdmin = req.user.role === 'admin';
    if (!approved && !isAdmin && !isOwner) {
      return res.status(403).json({ error: 'This bot not approved' });
    }
  }

  dbRun('INSERT OR IGNORE INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, userId, Date.now()]);
  
  if (encryptedKey) {
    dbRun('INSERT OR REPLACE INTO chat_keys (chat_id, user_id, encrypted_key) VALUES (?, ?, ?)', [chatId, userId, encryptedKey]);
  }
  
  saveDatabase();
  res.json({ success: true });
});

// Update chat keys
app.put('/api/chats/:id/keys', authMiddleware, (req, res) => {
  const { encryptedKeys } = req.body;
  const chatId = req.params.id;

  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  if (encryptedKeys) {
    // Get all participants in this chat
    const participants = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
    const participantIds = participants.map(p => p.user_id);
    const requiredReceivers = JSON.stringify(participantIds);

    for (const [uid, key] of Object.entries(encryptedKeys)) {
      // Store encrypted key with tracking of who has received it
      // received_by is a JSON array that tracks which users have unwrapped and confirmed
      dbRun(
        'INSERT OR REPLACE INTO chat_keys (chat_id, user_id, encrypted_key, required_receivers, received_by) VALUES (?, ?, ?, ?, ?)',
        [chatId, uid, key, requiredReceivers, JSON.stringify([])]
      );
    }
    saveDatabase();
  }
  res.json({ success: true });
});

// Mark wrapped key as received/unwrapped by current user, or delete if all have received
app.delete('/api/chats/:id/keys', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const userId = req.user.id;

  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, userId]);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  // Get the encrypted key record
  const keyRecord = dbGet('SELECT * FROM chat_keys WHERE chat_id = ? AND user_id = ?', [chatId, userId]);
  
  if (!keyRecord) {
    // No key found, nothing to delete/mark
    return res.json({ success: true });
  }

  try {
    const requiredReceivers = JSON.parse(keyRecord.required_receivers || '[]');
    let receivedBy = JSON.parse(keyRecord.received_by || '[]');

    // Add current user to received_by if not already there
    if (!receivedBy.includes(userId)) {
      receivedBy.push(userId);
    }

    // Check if all required receivers have received the key
    if (receivedBy.length === requiredReceivers.length) {
      // All users have received the key, delete it from the database
      console.log(`[E2EE] All users (${receivedBy.length}/${requiredReceivers.length}) have received key for chat ${chatId}, deleting from database`);
      dbRun('DELETE FROM chat_keys WHERE chat_id = ? AND user_id = ?', [chatId, userId]);
    } else {
      // Some users haven't received yet, just update the received_by tracking
      console.log(`[E2EE] User ${userId} marked key as received (${receivedBy.length}/${requiredReceivers.length}) for chat ${chatId}`);
      dbRun(
        'UPDATE chat_keys SET received_by = ? WHERE chat_id = ? AND user_id = ?',
        [JSON.stringify(receivedBy), chatId, userId]
      );
    }
    saveDatabase();
  } catch (err) {
    console.error(`[E2EE] Error processing key deletion for chat ${chatId}:`, err);
  }

  res.json({ success: true });
});

// Remove member from group
app.delete('/api/chats/:id/members/:userId', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ? AND is_admin = 1', [chatId, req.user.id]);
  if (!member && req.user.role !== 'admin') return res.status(403).json({ error: 'Not authorized' });

  dbRun('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.params.userId]);
  saveDatabase();
  res.json({ success: true });
});

// Mark chat as read
app.post('/api/chats/:id/read', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const now = Date.now();
  const msgs = dbAll('SELECT id FROM messages WHERE chat_id = ?', [chatId]);
  msgs.forEach(m => {
    dbRun('INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)', [m.id, req.user.id, now]);
  });
  saveDatabase();
  res.json({ success: true });
});

// Leave group
app.post('/api/chats/:id/leave', authMiddleware, (req, res) => {
  dbRun('DELETE FROM chat_members WHERE chat_id = ? AND user_id = ?', [req.params.id, req.user.id]);
  saveDatabase();
  res.json({ success: true });
});

// ─── Message Routes ────────────────────────────────────────

// Get messages for a chat
app.get('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const limit = parseInt(req.query.limit) || 50;
  const before = parseInt(req.query.before) || Date.now() + 1;

  // Verify membership
  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member of this chat' });

  // Exclude messages from users this user has blocked
  const blockedSenders = dbAll('SELECT blocked_user_id FROM blocked_users WHERE user_id = ?', [req.user.id]).map(r => r.blocked_user_id);
  const blockedClause = blockedSenders.length > 0 ? `AND sender_id NOT IN (${blockedSenders.map(() => '?').join(',')})` : '';
  const queryParams = blockedSenders.length > 0 ? [chatId, before, ...blockedSenders, limit] : [chatId, before, limit];

  const msgs = dbAll(
    `SELECT * FROM messages WHERE chat_id = ? AND created_at < ? ${blockedClause} ORDER BY created_at DESC LIMIT ?`,
    queryParams
  );

  // Format messages - E2EE decryption happens on the client, not here
  const result = msgs.reverse().map(m => {
    // Get poll data if this is a poll message
    let poll = null;
    if (m.type === 'poll' && m.poll_id) {
      poll = getPollWithVotes(m.poll_id);
    }
    
    return {
      id: m.id,
      chatId: m.chat_id,
      chat_id: m.chat_id,
      senderId: m.sender_id,
      sender_id: m.sender_id,
      content: m.content,  // Send as-is, E2EE decryption on client
      type: m.type || 'text',
      fileName: m.file_name,
      file_name: m.file_name,
      fileSize: m.file_size,
      file_size: m.file_size,
      fileUrl: m.file_url,
      file_url: m.file_url,
      poll: poll,
      encrypted: !!m.encrypted,
      edited: !!m.edited,
      timestamp: m.created_at,
      created_at: m.created_at,
    };
  });

  res.json(result);
});

// Send message
app.post('/api/chats/:id/messages', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  let { content, type, fileName, fileSize, fileUrl } = req.body;
  type = type || 'text';

  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member' });
  
  // Check if this is a channel and if user is channel admin
  const chat = dbGet('SELECT * FROM chats WHERE id = ?', [chatId]);
  if (chat && chat.is_channel) {
    const isChannelAdmin = dbGet('SELECT * FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
    if (!isChannelAdmin && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only channel admins can send messages in channels' });
    }
  }

  const msgId = uuidv4();
  const now = Date.now();
  // E2EE is handled by the client - server just stores and relays
  // Messages starting with 'e2ee:' are already encrypted by the client
  const encrypted = content && content.startsWith('e2ee:') ? 1 : 0;

  dbRun('INSERT INTO messages (id, chat_id, sender_id, content, type, file_name, file_size, file_url, encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
    msgId, chatId, req.user.id, content, type, fileName || null, fileSize || null, fileUrl || null, encrypted, now
  ]);
  saveDatabase();

  // Message object to broadcast and return
  // E2EE: We send the content as-is (encrypted or not) - clients handle decryption
  const message = { 
    id: msgId, 
    chatId, 
    chat_id: chatId,
    senderId: req.user.id, 
    sender_id: req.user.id,
    content: content,  // Send as-is - E2EE decryption happens on client
    type, 
    fileName: fileName || null,
    file_name: fileName || null,
    fileSize: fileSize || null,
    file_size: fileSize || null,
    fileUrl: fileUrl || null,
    file_url: fileUrl || null,
    encrypted: !!encrypted, 
    edited: false,
    timestamp: now,
    created_at: now
  };

  // Broadcast to all chat members (including sender for real-time sync across devices)
  const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  members.forEach(m => {
    if (m.user_id === req.user.id) return; // sender skip

    // Skip recipients who blocked the sender
    const isBlocked = dbGet('SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?', [m.user_id, req.user.id]);
    if (isBlocked) {
      console.log(`[BLOCK] Skipped delivering message ${msgId} from ${req.user.id} to blocked recipient ${m.user_id}`);
      return;
    }

    sendToUser(m.user_id, { type: 'message', data: message });
  });

  res.status(201).json(message);
  
  // Send push notifications to offline members asynchronously (don't block response)
  const recipientIds = members
    .map(m => m.user_id)
    .filter(id => id !== req.user.id)
    .filter(id => !dbGet('SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?', [id, req.user.id]));
  if (recipientIds.length > 0) {
    // Get chat name for group chats
    const chat = dbGet('SELECT name, type FROM chats WHERE id = ?', [chatId]);
    const chatName = chat?.name || 'Chat';
    
    // Format message text (truncate if too long)
    const messageText = content 
      ? content.substring(0, 150).replace(/^e2ee:/, '') 
      : '[File/Media]';
    
    // Build notification title with server name
    const serverName = config.server?.name || '4 Messenger';
    const senderName = req.user.display_name || req.user.username;
    
    const pushNotification = {
      type: 'message',
      title: `${serverName}: Message from ${senderName}`,
      body: messageText,
      chatId: chatId,
      senderId: req.user.id,
      senderName: senderName,
      tag: chatId, // Group notifications by chat
      badge: '/official.txt',
      icon: req.user.avatar || '/official.txt',
      requireInteraction: false,
      data: {
        chatId: chatId,
        senderId: req.user.id,
        senderName: senderName
      }
    };
    sendPushNotifications(recipientIds, pushNotification, req.user.id).catch(err => {
      console.error('[PUSH] Error sending notifications:', err.message);
    });
  }
  
  // Run Custom Bots if any
  try {
    const bots = dbAll(`
      SELECT u.id, u.username, u.bot_script, u.display_name, u.avatar 
      FROM chat_members cm 
      JOIN users u ON cm.user_id = u.id 
      WHERE cm.chat_id = ? AND u.is_bot = 1 AND u.id != ?
    `, [chatId, req.user.id]);

    if (bots && bots.length > 0) {
              const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
        const runnerPath = path.join(__dirname, 'bot_env', 'runner.py');
        const dockerEnabled = config.bots?.docker?.enabled === true;
        
        // Always use the configured method - no fallback
        const useDocker = dockerEnabled;
      
      for (const bot of bots) {
        if (!bot.bot_script) continue;
        
        console.log(`[BOT ENGINE] Triggering bot ${bot.username} for chat ${chatId}${useDocker ? ' (Docker)' : ''}`);
        // Ensure server url uses localhost to avoid python requests issues
        const localServerUrl = useDocker 
          ? `http://host.docker.internal:${config.server.port}`
          : `http://127.0.0.1:${config.server.port}`;
        const botToken = jwt.sign({ userId: bot.id }, config.security.jwtSecret, { expiresIn: '1m' });
        
        const env = {
          ...process.env,
          PYTHONUNBUFFERED: "1",
          API_URL: localServerUrl,
          BOT_TOKEN: botToken,
          CHAT_ID: chatId,
          SENDER_ID: req.user.id,
          MESSAGE_TEXT: (content && !content.startsWith('e2ee:')) ? content : '',  // Bots can't read E2EE messages
          BOT_NAME: bot.username,
          MAX_MEMORY_MB: (config.bots && config.bots.maxMemoryMB) ? config.bots.maxMemoryMB.toString() : '50',
          BOT_TIMEOUT_MS: (config.bots && config.bots.timeoutMs) ? config.bots.timeoutMs.toString() : '10000',
          BOT_STORAGE_PATH: path.join(__dirname, 'bot_files', bot.username.replace(/[^a-zA-Z0-9_-]/g, '_'))
        };
        
        let pyProcess;
        
        if (useDocker) {
          // Docker execution - more secure and isolated
          const dockerImage = config.bots?.docker?.image || '4messenger-bot';
          const memoryLimit = config.bots?.docker?.memoryLimit || '64m';
          const cpuLimit = config.bots?.docker?.cpuLimit || '0.5';
          const networkDisabled = config.bots?.docker?.networkDisabled === true;
          
          // Create bot storage directory for this bot
          const botStorageDir = env.BOT_STORAGE_PATH;
          if (!fs.existsSync(botStorageDir)) {
            fs.mkdirSync(botStorageDir, { recursive: true });
          }
          
          // Convert Windows path to Docker-compatible path
          const dockerStoragePath = process.platform === 'win32' 
            ? '/' + botStorageDir.replace(/\\/g, '/').replace(/:/g, '')
            : botStorageDir;
          
          const dockerArgs = [
            'run',
            '--rm',                                        // Remove container after exit
            '-i',                                          // Interactive (for stdin)
            `--memory=${memoryLimit}`,                     // Memory limit
            `--cpus=${cpuLimit}`,                          // CPU limit
            '--read-only',                                 // Read-only filesystem
            '--tmpfs', '/tmp:rw,noexec,nosuid,size=16m',   // Writable /tmp
            '-v', `${botStorageDir}:/bot_storage:rw`,      // Mount bot storage
            '--security-opt=no-new-privileges',            // No privilege escalation
            '-e', `API_URL=${env.API_URL}`,
            '-e', `BOT_TOKEN=${env.BOT_TOKEN}`,
            '-e', `CHAT_ID=${env.CHAT_ID}`,
            '-e', `SENDER_ID=${env.SENDER_ID}`,
            '-e', `MESSAGE_TEXT=${env.MESSAGE_TEXT}`,
            '-e', `BOT_NAME=${env.BOT_NAME}`,
            '-e', 'BOT_STORAGE_PATH=/bot_storage',
            '-e', 'PYTHONUNBUFFERED=1',
          ];
          
          // Disable network if configured
          if (networkDisabled) {
            dockerArgs.push('--network=none');
          }
          
          dockerArgs.push(dockerImage);
          
          // Use full path to docker on Windows
          const dockerCmd = process.platform === 'win32' ? 'docker.exe' : 'docker';
          
          console.log(`[BOT ENGINE] Running Docker: ${dockerCmd} ${dockerArgs.join(' ')}`);
          
          pyProcess = spawn(dockerCmd, dockerArgs, {
            shell: process.platform === 'win32' // Use shell on Windows for better compatibility
          });
        } else {
          // Direct Python execution
          pyProcess = spawn(pythonCmd, [runnerPath], { env });
        }
        
        // Setup timeout to kill long-running bots
        const timeoutMs = parseInt(env.BOT_TIMEOUT_MS, 10) || 10000;
        const killTimeout = setTimeout(() => {
          if (pyProcess && !pyProcess.killed) {
            console.error(`[BOT ${bot.username} ERROR]: Execution timed out after ${timeoutMs}ms`);
            try { pyProcess.kill('SIGKILL'); } catch(e) {}
            
            // Try to notify chat about timeout
            try {
               const errMsg = `⚠️ **Bot Error:**\nExecution timed out (exceeded ${timeoutMs}ms limit).`;
               const msgId = uuidv4();
               dbRun(`INSERT INTO messages (id, chat_id, sender_id, content, type, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                [msgId, chatId, bot.id, errMsg, 'text', Date.now()]);
               broadcastToChat(chatId, {
                 type: 'new_message',
                 message: { id: msgId, chatId, senderId: bot.id, content: errMsg, type: 'text', timestamp: Date.now() },
                 senderName: bot.display_name || bot.username,
                 senderAvatar: bot.avatar
               });
            } catch(e) {}
          }
        }, timeoutMs);
        
        pyProcess.on('close', (code) => {
          clearTimeout(killTimeout);
        });
        
        pyProcess.on('error', (err) => {
          if (useDocker) {
            console.error(`[BOT ${bot.username} DOCKER ERROR]: Failed to start Docker container.`);
            console.error(`[BOT ${bot.username} DOCKER ERROR]: Make sure Docker Desktop is running and the image '${config.bots?.docker?.image || '4messenger-bot'}' is built.`);
            console.error(`[BOT ${bot.username} DOCKER ERROR]: Run: cd server/bot_env && docker build -t 4messenger-bot .`);
          } else {
            console.error(`[BOT ${bot.username} PROCESS ERROR]: Failed to start Python. Is it installed and in PATH?`);
          }
          console.error(`[BOT ${bot.username} ERROR DETAILS]:`, err.message);
        });
        
        // Get bot script as-is - JSON parsing should handle newlines correctly
        let botScript = bot.bot_script || '';
        pyProcess.stdin.write(botScript + '\n');
        pyProcess.stdin.end();
        
        pyProcess.stdout.on('data', (data) => {
          console.log(`[BOT ${bot.username} OUTPUT]:\n${data.toString().trim()}`);
        });

        let stderrData = '';
        pyProcess.stderr.on('data', (data) => {
          const chunk = data.toString();
          stderrData += chunk;
          console.error(`[BOT ${bot.username} ERROR]:\n${chunk.trim()}`);
        });
        
        pyProcess.on('close', (code) => {
          clearTimeout(killTimeout);
          if (code !== 0 && stderrData.trim().length > 0) {
            // Check if error message hasn't already been sent by Python itself
            if (!stderrData.includes("Bot Execution Error:") && !stderrData.includes("FOUR_MESSENGER")) {
               try {
                 const errMsg = `⚠️ **Bot Error:**\n\`\`\`python\n${stderrData.trim().substring(0, 800)}\n\`\`\``;
                 const msgId = uuidv4();
                 dbRun(`INSERT INTO messages (id, chat_id, sender_id, content, type, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                  [msgId, chatId, bot.id, errMsg, 'text', Date.now()]);
                 broadcastToChat(chatId, {
                   type: 'new_message',
                   message: { id: msgId, chatId, senderId: bot.id, content: errMsg, type: 'text', timestamp: Date.now() },
                   senderName: bot.display_name || bot.username,
                   senderAvatar: bot.avatar
                 });
               } catch(e) {}
            }
          }
          if (code !== 0) console.log(`[BOT ${bot.username}] exited with code ${code}`);
        });
      }
    }
  } catch (botError) {
    console.error('[BOT ERROR] Failed to trigger bots:', botError);
  }
});

// Edit message
app.put('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' });
  }

  // E2EE: Server just stores the content as-is, encryption is client-side
  const content = req.body.content;

  dbRun('UPDATE messages SET content = ?, edited = 1 WHERE id = ?', [content, req.params.id]);
  saveDatabase();
  
  // Broadcast edit to all chat members
  const editMembers = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [msg.chat_id]);
  editMembers.forEach(m => {
    if (m.user_id !== req.user.id) {
      sendToUser(m.user_id, { type: 'message_edited', data: { id: req.params.id, content: content, chatId: msg.chat_id } });
    }
  });
  
  res.json({ success: true });
});

// Delete message
app.delete('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id && !['admin', 'moderator'].includes(req.user.role)) {
    return res.status(403).json({ error: 'Not authorized' });
  }

  const chatId = msg.chat_id;
  dbRun('DELETE FROM messages WHERE id = ?', [req.params.id]);
  saveDatabase();
  
  // Broadcast delete to all chat members
  const deleteMembers = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  deleteMembers.forEach(m => {
    if (m.user_id !== req.user.id) {
      sendToUser(m.user_id, { type: 'message_deleted', data: { id: req.params.id, chatId } });
    }
  });
  
  res.json({ success: true });
});

// ─── File Upload ───────────────────────────────────────────
if (upload) {
  app.post('/api/upload', authMiddleware, upload.single('file'), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    
    const originalPath = req.file.path;
    const fileId = path.basename(req.file.filename, path.extname(req.file.filename));
    const originalExt = path.extname(req.file.originalname);
    let finalPath = originalPath;
    let isEncrypted = false;
    
    // Encrypt file if encryption is enabled
    if (config.security.encryptionEnabled) {
      const encryptedPath = originalPath + '.enc';
      try {
        await encryptFile(originalPath, encryptedPath);
        // Remove original unencrypted file
        fs.unlinkSync(originalPath);
        finalPath = encryptedPath;
        isEncrypted = true;
      } catch (err) {
        console.error('[FILE] Encryption failed:', err.message);
        // Continue with unencrypted file
      }
    }
    
    // Store file metadata in database
    const fileRecord = {
      id: fileId,
      originalName: req.file.originalname,
      storedName: path.basename(finalPath),
      mimeType: req.file.mimetype,
      size: req.file.size,
      encrypted: isEncrypted ? 1 : 0,
      uploadedBy: req.user.id,
      uploadedAt: Date.now(),
    };
    
    dbRun(`
      INSERT INTO files (id, original_name, stored_name, mime_type, size, encrypted, uploaded_by, uploaded_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `, [fileRecord.id, fileRecord.originalName, fileRecord.storedName, fileRecord.mimeType, fileRecord.size, fileRecord.encrypted, fileRecord.uploadedBy, fileRecord.uploadedAt]);
    saveDatabase();
    
    res.json({
      fileId: fileId,
      fileName: req.file.originalname,
      fileSize: req.file.size,
      fileUrl: `/api/files/${fileId}`,
      mimeType: req.file.mimetype,
      encrypted: isEncrypted,
    });
  });
  
  // Auth middleware that also supports token in query string (for media)
  function fileAuthMiddleware(req, res, next) {
    const token = req.headers.authorization?.replace('Bearer ', '') || req.query.token;
    if (!token) return res.status(401).json({ error: 'No token provided' });

    try {
      const decoded = jwt.verify(token, config.security.jwtSecret);
      const user = dbGet('SELECT * FROM users WHERE id = ?', [decoded.userId]);
      if (!user) return res.status(401).json({ error: 'User not found' });
      if (user.role === 'banned') return res.status(403).json({ error: 'Account banned' });
      req.user = user;
      next();
    } catch {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }

  // Get file (with decryption if needed)
  app.get('/api/files/:id', fileAuthMiddleware, async (req, res) => {
    const fileId = req.params.id;
    let fileRecord = dbGet('SELECT * FROM files WHERE id = ?', [fileId]);
    
    // If not found in database, try to find by filename in uploads folder
    if (!fileRecord) {
      const uploadDir = path.resolve(__dirname, config.files.uploadDir);
      const files = fs.existsSync(uploadDir) ? fs.readdirSync(uploadDir) : [];
      const matchingFile = files.find(f => f.startsWith(fileId));
      
      if (matchingFile) {
        const filePath = path.join(uploadDir, matchingFile);
        const stats = fs.statSync(filePath);
        const ext = path.extname(matchingFile).toLowerCase();
        
        // Determine MIME type from extension
        const mimeTypes = {
          '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.png': 'image/png',
          '.gif': 'image/gif', '.webp': 'image/webp', '.svg': 'image/svg+xml',
          '.mp4': 'video/mp4', '.webm': 'video/webm', '.mov': 'video/quicktime',
          '.mp3': 'audio/mpeg', '.wav': 'audio/wav', '.ogg': 'audio/ogg',
          '.pdf': 'application/pdf', '.txt': 'text/plain',
          '.enc': 'application/octet-stream',
        };
        
        const isEncrypted = matchingFile.endsWith('.enc');
        const actualExt = isEncrypted ? path.extname(matchingFile.replace('.enc', '')) : ext;
        
        fileRecord = {
          id: fileId,
          original_name: matchingFile.replace('.enc', ''),
          stored_name: matchingFile,
          mime_type: mimeTypes[actualExt] || 'application/octet-stream',
          size: stats.size,
          encrypted: isEncrypted ? 1 : 0,
        };
      }
    }
    
    if (!fileRecord) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const filePath = path.join(__dirname, config.files.uploadDir, fileRecord.stored_name);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }
    
    // Set appropriate headers
    res.setHeader('Content-Type', fileRecord.mime_type);
    res.setHeader('Content-Disposition', `inline; filename="${fileRecord.original_name}"`);
    res.setHeader('Cache-Control', 'private, max-age=3600');
    
    if (fileRecord.encrypted) {
      try {
        const decryptedBuffer = await decryptFileToBuffer(filePath);
        res.setHeader('Content-Length', decryptedBuffer.length);
        res.send(decryptedBuffer);
      } catch (err) {
        console.error('[FILE] Decryption failed:', err.message);
        // Try sending as-is if decryption fails
        res.setHeader('Content-Length', fileRecord.size);
        fs.createReadStream(filePath).pipe(res);
      }
    } else {
      res.setHeader('Content-Length', fileRecord.size);
      fs.createReadStream(filePath).pipe(res);
    }
  });
  
  // Download file (force download with decryption)
  app.get('/api/files/:id/download', fileAuthMiddleware, async (req, res) => {
    const fileId = req.params.id;
    let fileRecord = dbGet('SELECT * FROM files WHERE id = ?', [fileId]);
    
    // If not found in database, try to find by filename in uploads folder
    if (!fileRecord) {
      const uploadDir = path.resolve(__dirname, config.files.uploadDir);
      const files = fs.existsSync(uploadDir) ? fs.readdirSync(uploadDir) : [];
      const matchingFile = files.find(f => f.startsWith(fileId));
      
      if (matchingFile) {
        const filePath = path.join(uploadDir, matchingFile);
        const stats = fs.statSync(filePath);
        const isEncrypted = matchingFile.endsWith('.enc');
        
        fileRecord = {
          id: fileId,
          original_name: matchingFile.replace('.enc', ''),
          stored_name: matchingFile,
          mime_type: 'application/octet-stream',
          size: stats.size,
          encrypted: isEncrypted ? 1 : 0,
        };
      }
    }
    
    if (!fileRecord) {
      return res.status(404).json({ error: 'File not found' });
    }
    
    const filePath = path.join(__dirname, config.files.uploadDir, fileRecord.stored_name);
    
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }
    
    // Force download
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${fileRecord.original_name}"`);
    
    if (fileRecord.encrypted) {
      try {
        const decryptedBuffer = await decryptFileToBuffer(filePath);
        res.setHeader('Content-Length', decryptedBuffer.length);
        res.send(decryptedBuffer);
      } catch (err) {
        console.error('[FILE] Decryption failed:', err.message);
        // Try sending as-is
        res.setHeader('Content-Length', fileRecord.size);
        fs.createReadStream(filePath).pipe(res);
      }
    } else {
      res.setHeader('Content-Length', fileRecord.size);
      fs.createReadStream(filePath).pipe(res);
    }
  });
}

// ─── Poll Routes ───────────────────────────────────────────

// Create poll
app.post('/api/chats/:id/polls', authMiddleware, (req, res) => {
  const chatId = req.params.id;
  const { question, options, multipleChoice, anonymous } = req.body;
  
  if (!question || !options || options.length < 2) {
    return res.status(400).json({ error: 'Question and at least 2 options required' });
  }
  
  // Verify membership
  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member of this chat' });
  
  // Check if this is a channel and if user is channel admin
  const chat = dbGet('SELECT * FROM chats WHERE id = ?', [chatId]);
  if (chat && chat.is_channel) {
    const isChannelAdmin = dbGet('SELECT * FROM channel_admins WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
    if (!isChannelAdmin && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Only channel admins can create polls in channels' });
    }
  }
  
  // Only allow polls in groups and channels
  if (chat.type === 'direct') {
    return res.status(400).json({ error: 'Polls can only be created in groups and channels' });
  }
  
  const pollId = uuidv4();
  const msgId = uuidv4();
  const now = Date.now();
  
  // Create poll
  dbRun(`
    INSERT INTO polls (id, chat_id, creator_id, question, multiple_choice, anonymous, closed, created_at)
    VALUES (?, ?, ?, ?, ?, ?, 0, ?)
  `, [pollId, chatId, req.user.id, question, multipleChoice ? 1 : 0, anonymous ? 1 : 0, now]);
  
  // Create poll options
  options.forEach((optionText, index) => {
    dbRun(`
      INSERT INTO poll_options (id, poll_id, option_index, option_text)
      VALUES (?, ?, ?, ?)
    `, [uuidv4(), pollId, index, optionText]);
  });
  
  // Create message with poll
  dbRun(`
    INSERT INTO messages (id, chat_id, sender_id, content, type, poll_id, created_at)
    VALUES (?, ?, ?, ?, 'poll', ?, ?)
  `, [msgId, chatId, req.user.id, question, pollId, now]);
  
  saveDatabase();
  
  // Build poll object for response
  const pollOptions = options.map((text, idx) => ({
    text,
    votes: [],
  }));
  
  const poll = {
    id: pollId,
    question,
    options: pollOptions,
    multipleChoice: !!multipleChoice,
    anonymous: !!anonymous,
    creatorId: req.user.id,
    closed: false,
  };
  
  const message = {
    id: msgId,
    chatId,
    chat_id: chatId,
    senderId: req.user.id,
    sender_id: req.user.id,
    content: question,
    type: 'poll',
    poll,
    encrypted: false,
    edited: false,
    timestamp: now,
    created_at: now,
  };
  
  // Broadcast to all chat members
  const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  members.forEach(m => {
    if (m.user_id !== req.user.id) {
      sendToUser(m.user_id, { type: 'message', data: message });
    }
  });
  
  res.status(201).json(message);
});

// Vote on poll
app.post('/api/polls/:id/vote', authMiddleware, (req, res) => {
  const pollId = req.params.id;
  const { optionIndex } = req.body;
  
  // Get poll
  const poll = dbGet('SELECT * FROM polls WHERE id = ?', [pollId]);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });
  if (poll.closed) return res.status(400).json({ error: 'Poll is closed' });
  
  // Check membership
  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [poll.chat_id, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member of this chat' });
  
  // Get option
  const option = dbGet('SELECT * FROM poll_options WHERE poll_id = ? AND option_index = ?', [pollId, optionIndex]);
  if (!option) return res.status(400).json({ error: 'Invalid option' });
  
  // Check if already voted (for single choice)
  if (!poll.multiple_choice) {
    const existingVote = dbGet('SELECT * FROM poll_votes WHERE poll_id = ? AND user_id = ?', [pollId, req.user.id]);
    if (existingVote) {
      return res.status(400).json({ error: 'Already voted' });
    }
  } else {
    // For multiple choice, check if already voted for this option
    const existingVote = dbGet('SELECT * FROM poll_votes WHERE poll_id = ? AND user_id = ? AND option_id = ?', [pollId, req.user.id, option.id]);
    if (existingVote) {
      // Remove vote (toggle)
      dbRun('DELETE FROM poll_votes WHERE poll_id = ? AND user_id = ? AND option_id = ?', [pollId, req.user.id, option.id]);
      saveDatabase();
      
      // Get updated poll data
      const updatedPoll = getPollWithVotes(pollId);
      broadcastPollUpdate(poll.chat_id, pollId, updatedPoll);
      
      return res.json({ success: true, poll: updatedPoll });
    }
  }
  
  // Add vote
  dbRun(`
    INSERT INTO poll_votes (id, poll_id, option_id, user_id, voted_at)
    VALUES (?, ?, ?, ?, ?)
  `, [uuidv4(), pollId, option.id, req.user.id, Date.now()]);
  
  saveDatabase();
  
  // Get updated poll data
  const updatedPoll = getPollWithVotes(pollId);
  broadcastPollUpdate(poll.chat_id, pollId, updatedPoll);
  
  res.json({ success: true, poll: updatedPoll });
});

// Close poll (creator or admin only)
app.post('/api/polls/:id/close', authMiddleware, (req, res) => {
  const pollId = req.params.id;
  
  const poll = dbGet('SELECT * FROM polls WHERE id = ?', [pollId]);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });
  
  if (poll.creator_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Only poll creator or admin can close the poll' });
  }
  
  dbRun('UPDATE polls SET closed = 1 WHERE id = ?', [pollId]);
  saveDatabase();
  
  const updatedPoll = getPollWithVotes(pollId);
  broadcastPollUpdate(poll.chat_id, pollId, updatedPoll);
  
  res.json({ success: true });
});

// Helper function to get poll with votes
function getPollWithVotes(pollId) {
  const poll = dbGet('SELECT * FROM polls WHERE id = ?', [pollId]);
  if (!poll) return null;
  
  const options = dbAll('SELECT * FROM poll_options WHERE poll_id = ? ORDER BY option_index', [pollId]);
  
  const pollOptions = options.map(opt => {
    const votes = dbAll('SELECT user_id FROM poll_votes WHERE option_id = ?', [opt.id]);
    return {
      text: opt.option_text,
      votes: poll.anonymous ? votes.map(() => 'anonymous') : votes.map(v => v.user_id),
    };
  });
  
  return {
    id: poll.id,
    question: poll.question,
    options: pollOptions,
    multipleChoice: !!poll.multiple_choice,
    anonymous: !!poll.anonymous,
    creatorId: poll.creator_id,
    closed: !!poll.closed,
  };
}

// Helper function to broadcast poll update
function broadcastPollUpdate(chatId, pollId, poll) {
  const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  members.forEach(m => {
    sendToUser(m.user_id, { type: 'poll_update', pollId, poll });
  });
}

// ─── Sticker Routes ────────────────────────────────────────

// Get user's saved stickers
app.get('/api/stickers', authMiddleware, (req, res) => {
  const stickers = dbAll(`
    SELECT s.* FROM stickers s
    JOIN user_stickers us ON s.id = us.sticker_id
    WHERE us.user_id = ?
    ORDER BY us.added_at DESC
  `, [req.user.id]);
  
  res.json(stickers.map(s => ({
    id: s.id,
    name: s.name,
    imageData: s.image_data,
    creatorId: s.creator_id,
    createdAt: s.created_at,
  })));
});

// Create a new sticker
app.post('/api/stickers', authMiddleware, (req, res) => {
  const { name, imageData } = req.body;
  
  if (!name || !imageData) {
    return res.status(400).json({ error: 'Name and image data are required' });
  }
  
  // Validate image data is base64
  if (!imageData.startsWith('data:image/')) {
    return res.status(400).json({ error: 'Invalid image data format' });
  }
  
  // Limit sticker size (max 500KB)
  if (imageData.length > 500000) {
    return res.status(400).json({ error: 'Sticker image is too large (max 500KB)' });
  }
  
  const stickerId = uuidv4();
  const now = Date.now();
  
  // Create sticker
  dbRun(`
    INSERT INTO stickers (id, creator_id, name, image_data, created_at)
    VALUES (?, ?, ?, ?, ?)
  `, [stickerId, req.user.id, name, imageData, now]);
  
  // Automatically add to creator's collection
  dbRun(`
    INSERT INTO user_stickers (user_id, sticker_id, added_at)
    VALUES (?, ?, ?)
  `, [req.user.id, stickerId, now]);
  
  saveDatabase();
  
  res.status(201).json({
    id: stickerId,
    name,
    imageData,
    creatorId: req.user.id,
    createdAt: now,
  });
});

// Save a sticker to collection (from received message)
app.post('/api/stickers/:id/save', authMiddleware, (req, res) => {
  const stickerId = req.params.id;
  
  // Check if sticker exists
  const sticker = dbGet('SELECT * FROM stickers WHERE id = ?', [stickerId]);
  if (!sticker) {
    return res.status(404).json({ error: 'Sticker not found' });
  }
  
  // Check if already saved
  const existing = dbGet('SELECT * FROM user_stickers WHERE user_id = ? AND sticker_id = ?', [req.user.id, stickerId]);
  if (existing) {
    return res.status(400).json({ error: 'Sticker already saved' });
  }
  
  dbRun(`
    INSERT INTO user_stickers (user_id, sticker_id, added_at)
    VALUES (?, ?, ?)
  `, [req.user.id, stickerId, Date.now()]);
  
  saveDatabase();
  
  res.json({ success: true });
});

// Remove sticker from collection
app.delete('/api/stickers/:id', authMiddleware, (req, res) => {
  const stickerId = req.params.id;
  
  // Remove from user's collection
  dbRun('DELETE FROM user_stickers WHERE user_id = ? AND sticker_id = ?', [req.user.id, stickerId]);
  
  // If this was the creator and no one else has it, delete the sticker entirely
  const sticker = dbGet('SELECT * FROM stickers WHERE id = ?', [stickerId]);
  if (sticker && sticker.creator_id === req.user.id) {
    const othersHaveIt = dbGet('SELECT * FROM user_stickers WHERE sticker_id = ?', [stickerId]);
    if (!othersHaveIt) {
      dbRun('DELETE FROM stickers WHERE id = ?', [stickerId]);
    }
  }
  
  saveDatabase();
  
  res.json({ success: true });
});

// Get a single sticker by ID
app.get('/api/stickers/:id', authMiddleware, (req, res) => {
  const sticker = dbGet('SELECT * FROM stickers WHERE id = ?', [req.params.id]);
  if (!sticker) {
    return res.status(404).json({ error: 'Sticker not found' });
  }
  
  res.json({
    id: sticker.id,
    name: sticker.name,
    imageData: sticker.image_data,
    creatorId: sticker.creator_id,
    createdAt: sticker.created_at,
  });
});

// ─── Bot Routes & Logic ────────────────────────────────────

// Store running bot processes
const runningBots = new Map(); // botId -> { process, scriptPath }

// Ensure bots directory exists
const botsDir = path.join(__dirname, 'bots');
if (!fs.existsSync(botsDir)) {
  fs.mkdirSync(botsDir);
}

// --- NEW BOT EXECUTION LOGIC ---
const activeBotsMap = new Map();

function startBotNode(botUser) {
  if (activeBotsMap.has(botUser.id)) return;
  if (!botUser.bot_script) return;
  
  const scriptB64 = Buffer.from(botUser.bot_script).toString('base64');
  const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';
  const botProc = spawn(pythonCmd, ['server/bot_runner.py', scriptB64]);
  
  botProc.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');
    for (const line of lines) {
      if (line.startsWith('BOT_API_CALL:')) {
        try {
          const req = JSON.parse(line.substring(13));
          if (req.action === 'send_message') {
            const chatId = req.chat_id;
            const isMember = dbGet(`SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?`, [chatId, botUser.id]);
            if (isMember) {
              const msgId = `msg-${Date.now()}-${Math.random().toString(36).substr(2,5)}`;
              const timestamp = new Date().toISOString();
              dbRun(`INSERT INTO messages (id, chat_id, sender_id, content, type, created_at) VALUES (?, ?, ?, ?, ?, ?)`,
                [msgId, chatId, botUser.id, req.content, 'text', timestamp]);
              
              const newMsg = {
                id: msgId, chatId: chatId, senderId: botUser.id,
                content: req.content, type: 'text', timestamp: timestamp
              };
              
              broadcastToChat(chatId, {
                type: 'new_message',
                message: newMsg,
                senderName: botUser.display_name || botUser.username,
                senderAvatar: botUser.avatar
              });
            }
          }
        } catch(e) { console.error('Bot parsing error', e); }
      }
    }
  });
  botProc.on('close', () => activeBotsMap.delete(botUser.id));
  activeBotsMap.set(botUser.id, botProc);
}

function stopBotNode(botId) {
  if (activeBotsMap.has(botId)) {
    activeBotsMap.get(botId).kill();
    activeBotsMap.delete(botId);
  }
}

function broadcastToChat(chatId, payload) {
  const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  members.forEach(m => sendToUser(m.user_id, payload));
}
// -------------------------

// Function to handle bot message sending
function handleBotMessage(botId, chatId, text) {
  const bot = dbGet('SELECT * FROM bots WHERE id = ?', [botId]);
  if (!bot) return;

  const msgId = uuidv4();
  const now = Date.now();
  let content = text;
  let encrypted = 0;

  if (config.security.encryptionEnabled && content) {
    content = encrypt(content);
    encrypted = 1;
  }

  // Create bot user dynamically if not exists (for avatar/name)
  const botUserId = `bot_${botId}`;
  const botUser = dbGet('SELECT * FROM users WHERE id = ?', [botUserId]);
  
  if (!botUser) {
    dbRun(`
      INSERT INTO users (id, username, email, password, role, display_name, created_at)
      VALUES (?, ?, ?, ?, 'user', ?, ?)
    `, [botUserId, `bot_${bot.name}`, `bot_${botId}@bot.local`, 'nopassword', `🤖 ${bot.name}`, now]);
    
    // Auto-join chat if not member
    const isMember = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, botUserId]);
    if (!isMember) {
      dbRun('INSERT INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, botUserId, now]);
    }
  }

  dbRun('INSERT INTO messages (id, chat_id, sender_id, content, type, encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)', [
    msgId, chatId, botUserId, content, 'text', encrypted, now
  ]);
  saveDatabase();

  const message = { 
    id: msgId, 
    chatId, 
    chat_id: chatId,
    senderId: botUserId, 
    sender_id: botUserId,
    content: text,
    type: 'text', 
    encrypted: !!encrypted, 
    edited: false,
    timestamp: now,
    created_at: now
  };

  const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  members.forEach(m => {
    sendToUser(m.user_id, { type: 'message', data: message });
  });
}

// Function to notify bots in a chat
function notifyBots(chatId, message) {
  // Don't process messages from bots to prevent infinite loops
  if (message.senderId.startsWith('bot_')) return;

  // Find active bots in this chat
  const chatMembers = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [chatId]);
  const botIdsInChat = chatMembers
    .filter(m => m.user_id.startsWith('bot_'))
    .map(m => m.user_id.replace('bot_', ''));

  botIdsInChat.forEach(botId => {
    const runningBot = runningBots.get(botId);
    if (runningBot && runningBot.process) {
      // Send message to bot's stdin
      const botMessage = {
        event: 'message',
        data: {
          chat_id: message.chatId,
          sender_id: message.senderId,
          sender_name: message.sender_name,
          text: message.content,
          chat_type: message.chat_type,
          chat_name: message.chat_name
        }
      };
      runningBot.process.stdin.write(JSON.stringify(botMessage) + '\n');
    }
  });
}

// Stop a bot
function stopBot(botId) {
  const runningBot = runningBots.get(botId);
  if (runningBot) {
    if (runningBot.process) {
      runningBot.process.kill();
    }
    if (fs.existsSync(runningBot.scriptPath)) {
      fs.unlinkSync(runningBot.scriptPath);
    }
    runningBots.delete(botId);
    
    dbRun('UPDATE bots SET is_active = 0 WHERE id = ?', [botId]);
    saveDatabase();
    return true;
  }
  return false;
}

// Start a bot
function startBot(botId) {
  const bot = dbGet('SELECT * FROM bots WHERE id = ?', [botId]);
  if (!bot) return false;

  // Stop if already running
  stopBot(botId);

  const scriptPath = path.join(botsDir, `bot_${botId}.py`);
  
  // Create wrapper script that handles JSON I/O
  const wrapperCode = `
import sys
import json
import traceback

# Setup bot API
class BotAPI:
    def send_message(self, chat_id, text):
        print(json.dumps({
            "action": "send_message",
            "chat_id": chat_id,
            "text": text
        }))
        sys.stdout.flush()

bot = BotAPI()

# User code
${bot.code}

# Main loop
def main():
    while True:
        try:
            line = sys.stdin.readline()
            if not line:
                break
                
            data = json.loads(line)
            if data.get('event') == 'message' and 'on_message' in globals():
                msg = data.get('data', {})
                on_message(
                    msg.get('chat_id'),
                    msg.get('sender_id'),
                    msg.get('sender_name'),
                    msg.get('text')
                )
        except Exception as e:
            print(json.dumps({"action": "error", "error": str(e), "trace": traceback.format_exc()}))
            sys.stdout.flush()

if __name__ == "__main__":
    main()
`;

  fs.writeFileSync(scriptPath, wrapperCode);

  try {
    const pythonProcess = spawn('python', [scriptPath]);
    
    pythonProcess.stdout.on('data', (data) => {
      const lines = data.toString().split('\n');
      lines.forEach(line => {
        if (!line.trim()) return;
        try {
          const msg = JSON.parse(line);
          if (msg.action === 'send_message') {
            handleBotMessage(botId, msg.chat_id, msg.text);
          } else if (msg.action === 'error') {
            console.error(`[BOT ${bot.name} ERROR]:`, msg.error);
          }
        } catch (e) {
          // Normal print statement from python code
          console.log(`[BOT ${bot.name} LOG]:`, line);
        }
      });
    });

    pythonProcess.stderr.on('data', (data) => {
      console.error(`[BOT ${bot.name} STDERR]:`, data.toString());
    });

    pythonProcess.on('close', (code) => {
      console.log(`[BOT ${bot.name}] Exited with code ${code}`);
      stopBot(botId);
    });

    runningBots.set(botId, { process: pythonProcess, scriptPath });
    
    dbRun('UPDATE bots SET is_active = 1 WHERE id = ?', [botId]);
    saveDatabase();
    
    return true;
  } catch (err) {
    console.error(`[BOT] Failed to start bot ${bot.name}:`, err.message);
    return false;
  }
}

// Get user's bots
app.get('/api/users/me/bots', authMiddleware, (req, res) => {
  const bots = dbAll('SELECT id, name, is_active, created_at FROM bots WHERE creator_id = ? ORDER BY created_at DESC', [req.user.id]);
  res.json(bots.map(b => ({
    id: b.id,
    name: b.name,
    isActive: !!b.is_active,
    createdAt: b.created_at
  })));
});

// Create a new bot
app.post('/api/bots', authMiddleware, (req, res) => {
  const { name, code } = req.body;
  
  if (!name || !code) {
    return res.status(400).json({ error: 'Name and code are required' });
  }
  
  const botId = uuidv4();
  const now = Date.now();
  
  dbRun(`
    INSERT INTO bots (id, creator_id, name, code, is_active, created_at)
    VALUES (?, ?, ?, ?, 0, ?)
  `, [botId, req.user.id, name, code, now]);
  
  saveDatabase();
  
  res.status(201).json({ id: botId, name, isActive: false, createdAt: now });
});

// Get a specific bot
app.get('/api/bots/:id', authMiddleware, (req, res) => {
  const bot = dbGet('SELECT * FROM bots WHERE id = ? AND creator_id = ?', [req.params.id, req.user.id]);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  
  res.json({
    id: bot.id,
    name: bot.name,
    code: bot.code,
    isActive: !!bot.is_active
  });
});

// Update a bot
app.put('/api/bots/:id', authMiddleware, (req, res) => {
  const { name, code } = req.body;
  
  const bot = dbGet('SELECT * FROM bots WHERE id = ? AND creator_id = ?', [req.params.id, req.user.id]);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  
  dbRun('UPDATE bots SET name = ?, code = ? WHERE id = ?', [name, code, req.params.id]);
  saveDatabase();
  
  // Restart if active
  if (bot.is_active) {
    startBot(req.params.id);
  }
  
  res.json({ success: true });
});

// Delete a bot
app.delete('/api/bots/:id', authMiddleware, (req, res) => {
  const bot = dbGet('SELECT * FROM bots WHERE id = ? AND creator_id = ?', [req.params.id, req.user.id]);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  
  stopBot(req.params.id);
  
  dbRun('DELETE FROM bots WHERE id = ?', [req.params.id]);
  dbRun('DELETE FROM users WHERE id = ?', [`bot_${req.params.id}`]);
  saveDatabase();
  
  res.json({ success: true });
});

// Start/Stop a bot
app.post('/api/bots/:id/toggle', authMiddleware, (req, res) => {
  const bot = dbGet('SELECT * FROM bots WHERE id = ?', [req.params.id]);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });
  
  // Any user can start a bot they have access to via a chat, 
  // but let's restrict toggle to creator for safety, or allow if joining chat
  if (bot.creator_id !== req.user.id) {
    // If not creator, check if they are trying to add it to a chat
    const { chatId } = req.body;
    if (chatId) {
      const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
      if (!member) return res.status(403).json({ error: 'Not a member of this chat' });
      
      // Auto-start if not running
      if (!runningBots.has(bot.id)) {
        startBot(bot.id);
      }
      
      // Add bot to chat
      dbRun('INSERT OR IGNORE INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, `bot_${bot.id}`, Date.now()]);
      saveDatabase();
      
      return res.json({ success: true, isActive: true });
    }
    return res.status(403).json({ error: 'Not authorized' });
  }
  
  let isActive = false;
  if (runningBots.has(req.params.id)) {
    stopBot(req.params.id);
  } else {
    isActive = startBot(req.params.id);
  }
  
  res.json({ success: true, isActive });
});

// Restore active bots on startup
setTimeout(() => {
  if (db) {
    const activeBots = dbAll('SELECT id FROM bots WHERE is_active = 1');
    console.log(`[BOT] Restoring ${activeBots.length} active bots`);
    activeBots.forEach(bot => startBot(bot.id));
  }
}, 2000);

// ─── Admin Routes ──────────────────────────────────────────
app.get('/api/admin/stats', authMiddleware, adminMiddleware, (req, res) => {
  const totalUsers = dbGet('SELECT COUNT(*) as count FROM users').count;
  const onlineUsers = dbGet('SELECT COUNT(*) as count FROM users WHERE online = 1').count;
  const bannedUsers = dbGet('SELECT COUNT(*) as count FROM users WHERE role = ?', ['banned']).count;
  const totalMessages = dbGet('SELECT COUNT(*) as count FROM messages').count;
  const totalGroups = dbGet('SELECT COUNT(*) as count FROM chats WHERE type = ?', ['group']).count;
  const totalDirect = dbGet('SELECT COUNT(*) as count FROM chats WHERE type = ?', ['direct']).count;

  res.json({ totalUsers, onlineUsers, bannedUsers, totalMessages, totalGroups, totalDirect });
});

app.get('/api/admin/config', authMiddleware, adminMiddleware, (req, res) => {
  // Return sanitized config (no secrets)
  res.json({
    serverName: config.server.name,
    captchaEnabled: config.captcha.enabled,
    emailVerification: config.email.verificationEnabled,
    registrationEnabled: config.registration.enabled,
    encryptionEnabled: config.security.encryptionEnabled,
    maxFileSize: config.files.maxSize,
    hasServerPassword: !!config.security.serverPassword,
    maxBotMemoryMB: config.bots ? config.bots.maxMemoryMB : 50,
  });
});

app.put('/api/admin/config', authMiddleware, adminMiddleware, (req, res) => {
  const updates = req.body;
  if (updates.serverName !== undefined) config.server.name = updates.serverName;
  if (updates.captchaEnabled !== undefined) config.captcha.enabled = updates.captchaEnabled;
  if (updates.emailVerification !== undefined) config.email.verificationEnabled = updates.emailVerification;
  if (updates.registrationEnabled !== undefined) config.registration.enabled = updates.registrationEnabled;
  if (updates.encryptionEnabled !== undefined) config.security.encryptionEnabled = updates.encryptionEnabled;
  if (updates.maxFileSize !== undefined) config.files.maxSize = updates.maxFileSize;
  if (updates.serverPassword !== undefined) config.security.serverPassword = updates.serverPassword;
  
  if (updates.maxBotMemoryMB !== undefined) {
    if (!config.bots) config.bots = {};
    config.bots.maxMemoryMB = parseInt(updates.maxBotMemoryMB, 10) || 50;
  }

  // Save to file
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
  res.json({ success: true });
});

// ─── Bot Approval (Admin Only) ──────────────────────────────
app.get('/api/admin/bots/pending', authMiddleware, adminMiddleware, (req, res) => {
  const bots = dbAll(`
    SELECT 
      b.id,
      b.username,
      b.display_name as displayName,
      b.avatar,
      b.owner_id as ownerId,
      o.username as ownerUsername,
      b.bot_script as code,
      b.created_at as createdAt
    FROM users b
    LEFT JOIN users o ON o.id = b.owner_id
    WHERE b.is_bot = 1 AND COALESCE(b.bot_approved, 1) != 1
    ORDER BY b.created_at DESC
  `);
  res.json(bots);
});

app.put('/api/admin/bots/:id/approve', authMiddleware, adminMiddleware, (req, res) => {
  const botId = req.params.id;
  const bot = dbGet('SELECT id FROM users WHERE id = ? AND is_bot = 1', [botId]);
  if (!bot) return res.status(404).json({ error: 'Bot not found' });

  dbRun('UPDATE users SET bot_approved = 1 WHERE id = ?', [botId]);
  saveDatabase();
  res.json({ success: true });
});

// Send announcement to all users
app.post('/api/admin/announcement', authMiddleware, adminMiddleware, (req, res) => {
  const { message } = req.body;
  if (!message || !message.trim()) {
    return res.status(400).json({ error: 'Message is required' });
  }
  
  // Broadcast to all connected users
  broadcastToAll({
    type: 'announcement',
    message: message.trim(),
    from: req.user.username,
    timestamp: Date.now(),
  });
  
  res.json({ success: true });
});

// Get system logs (basic implementation)
app.get('/api/admin/logs', authMiddleware, adminMiddleware, (req, res) => {
  const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
  const offset = parseInt(req.query.offset) || 0;
  
  // Get audit logs from database (real data)
  const logs = dbAll('SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ? OFFSET ?', [limit, offset]);
  
  // Format logs for response
  const formattedLogs = logs.map(log => ({
    id: log.id,
    timestamp: log.timestamp,
    type: 'audit',
    action: log.action,
    admin: log.admin_id,
    target: log.target_id,
    targetType: log.target_type,
    oldValue: log.old_value,
    newValue: log.new_value,
    ipAddress: log.ip_address,
    details: `${log.action} on ${log.target_type} (${log.target_id})`
  }));
  
  res.json(formattedLogs);
});

// Get maintenance mode status
app.get('/api/admin/maintenance', authMiddleware, adminMiddleware, (req, res) => {
  res.json({
    enabled: maintenanceMode,
    message: maintenanceMessage,
  });
});

// Toggle maintenance mode
app.post('/api/admin/maintenance', authMiddleware, adminMiddleware, (req, res) => {
  const { enabled, message } = req.body;
  
  maintenanceMode = !!enabled;
  if (message && typeof message === 'string') {
    maintenanceMessage = message.trim() || 'Server is under maintenance. Please try again later.';
  }
  
  console.log(`[ADMIN] Maintenance mode ${maintenanceMode ? 'ENABLED' : 'DISABLED'} by ${req.user.username}`);
  
  // Notify all connected users about maintenance mode
  if (maintenanceMode) {
    // Kick all non-admin users
    wss.clients.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN && ws.userId) {
        const user = dbGet('SELECT role FROM users WHERE id = ?', [ws.userId]);
        if (!user || user.role !== 'admin') {
          ws.send(JSON.stringify({ 
            type: 'maintenance', 
            enabled: true, 
            message: maintenanceMessage 
          }));
          // Give them a moment to see the message before disconnecting
          setTimeout(() => {
            ws.close(1000, 'Server entering maintenance mode');
          }, 1000);
        }
      }
    });
    
    // Update all non-admin users to offline
    dbRun('UPDATE users SET online = 0 WHERE role != ?', ['admin']);
    saveDatabase();
  } else {
    // Notify all users that maintenance is over
    broadcastToAll({ 
      type: 'maintenance', 
      enabled: false, 
      message: 'Server is back online!' 
    });
  }
  
  res.json({ 
    success: true, 
    enabled: maintenanceMode, 
    message: maintenanceMessage 
  });
});

// ─── Admin Audit & Activity Endpoints ──────────────────────

// Get audit logs (admin only)
app.get('/api/admin/audit-logs', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    
    const logs = dbAll(`
      SELECT l.*, u.username as admin_username 
      FROM audit_logs l
      LEFT JOIN users u ON l.admin_id = u.id
      ORDER BY l.timestamp DESC
      LIMIT ? OFFSET ?
    `, [limit, offset]);
    
    const totalResult = dbGet('SELECT COUNT(*) as count FROM audit_logs');
    const total = totalResult?.count || 0;
    
    res.json({
      logs: logs.map(log => ({
        ...log,
        timestamp: log.timestamp,
        timestampIso: new Date(log.timestamp).toISOString()
      })),
      total,
      limit,
      offset
    });
  } catch (error) {
    console.error('[AUDIT] Failed to fetch logs:', error.message);
    res.status(500).json({ error: 'Failed to fetch audit logs' });
  }
});

// Clear audit logs (admin only)
app.delete('/api/admin/audit-logs', authMiddleware, adminMiddleware, (req, res) => {
  try {
    dbRun('DELETE FROM audit_logs');
    saveDatabase();
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to clear audit logs' });
  }
});

// Get login history (admin only)
app.get('/api/admin/login-history', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    const offset = parseInt(req.query.offset) || 0;
    const userId = req.query.userId;
    
    let query = `
      SELECT l.*, u.username 
      FROM login_history l
      LEFT JOIN users u ON l.user_id = u.id
    `;
    const params = [];
    
    if (userId) {
      query += ` WHERE l.user_id = ?`;
      params.push(userId);
    }
    
    query += ` ORDER BY l.login_time DESC LIMIT ? OFFSET ?`;
    params.push(limit, offset);
    
    const history = dbAll(query, params);
    
    let countQuery = 'SELECT COUNT(*) as count FROM login_history';
    const countParams = [];
    if (userId) {
      countQuery += ` WHERE user_id = ?`;
      countParams.push(userId);
    }
    const totalResult = dbGet(countQuery, countParams);
    const total = totalResult?.count || 0;
    
    res.json({
      history: history.map(log => ({
        ...log,
        loginTime: log.login_time,
        logoutTime: log.logout_time,
        loginTimeIso: new Date(log.login_time).toISOString(),
        logoutTimeIso: log.logout_time ? new Date(log.logout_time).toISOString() : null,
        duration: log.logout_time ? log.logout_time - log.login_time : Date.now() - log.login_time
      })),
      total,
      limit,
      offset
    });
  } catch (error) {
    console.error('[LOGIN] Failed to fetch history:', error.message);
    res.status(500).json({ error: 'Failed to fetch login history' });
  }
});

// Search and delete messages (admin only)
app.post('/api/admin/messages/search', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const { pattern, userId, chatId, limit } = req.body;
    const searchLimit = Math.min(limit || 50, 200);
    
    let query = 'SELECT * FROM messages WHERE 1=1';
    const params = [];
    
    if (pattern) {
      query += ` AND content LIKE ?`;
      params.push(`%${pattern}%`);
    }
    
    if (userId) {
      query += ` AND sender_id = ?`;
      params.push(userId);
    }
    
    if (chatId) {
      query += ` AND chat_id = ?`;
      params.push(chatId);
    }
    
    query += ` ORDER BY created_at DESC LIMIT ?`;
    params.push(searchLimit);
    
    const messages = dbAll(query, params);
    
    res.json({
      messages: messages.map(msg => ({
        id: msg.id,
        content: msg.content.substring(0, 100),
        senderId: msg.sender_id,
        chatId: msg.chat_id,
        createdAt: msg.created_at,
        createdAtIso: new Date(msg.created_at).toISOString()
      })),
      count: messages.length
    });
  } catch (error) {
    console.error('[ADMIN] Failed to search messages:', error.message);
    res.status(500).json({ error: 'Failed to search messages' });
  }
});

// Delete messages (admin only)
app.delete('/api/admin/messages/:id', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const message = dbGet('SELECT * FROM messages WHERE id = ?', [req.params.id]);
    if (!message) return res.status(404).json({ error: 'Message not found' });
    
    const ipAddress = getRealIp(req);
    
    dbRun('DELETE FROM messages WHERE id = ?', [req.params.id]);
    saveDatabase();
    
    // Log audit action
    logAuditAction(req.user.id, 'delete_message', req.params.id, 'message', message.content.substring(0, 50), 'deleted', ipAddress);
    
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

// Get user activity stats (admin only)
app.get('/api/admin/users/:id/activity', authMiddleware, adminMiddleware, (req, res) => {
  try {
    const user = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Message count
    const messageResult = dbGet('SELECT COUNT(*) as count FROM messages WHERE sender_id = ?', [req.params.id]);
    const messageCount = messageResult?.count || 0;
    
    // Login count
    const loginResult = dbGet('SELECT COUNT(*) as count FROM login_history WHERE user_id = ?', [req.params.id]);
    const loginCount = loginResult?.count || 0;
    
    // First and last login
    const firstLogin = dbGet('SELECT login_time FROM login_history WHERE user_id = ? ORDER BY login_time ASC LIMIT 1', [req.params.id]);
    const lastLogin = dbGet('SELECT login_time FROM login_history WHERE user_id = ? ORDER BY login_time DESC LIMIT 1', [req.params.id]);
    
    // Message timeline (last 7 days)
    const sevenDaysAgo = Date.now() - (7 * 24 * 60 * 60 * 1000);
    const messagesByDay = dbAll(`
      SELECT DATE(created_at / 1000, 'unixepoch') as day, COUNT(*) as count
      FROM messages
      WHERE sender_id = ? AND created_at > ?
      GROUP BY day
      ORDER BY day DESC
    `, [req.params.id, sevenDaysAgo]);
    
    res.json({
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        role: user.role,
        createdAt: user.created_at
      },
      activity: {
        messageCount,
        loginCount,
        firstLogin: firstLogin?.login_time ? new Date(firstLogin.login_time).toISOString() : null,
        lastLogin: lastLogin?.login_time ? new Date(lastLogin.login_time).toISOString() : null,
        messagesByDay: messagesByDay.map(d => ({
          day: d.day,
          count: d.count
        }))
      }
    });
  } catch (error) {
    console.error('[ADMIN] Failed to fetch activity:', error.message);
    res.status(500).json({ error: 'Failed to fetch user activity' });
  }
});

// ─── Error Handling Middleware ─────────────────────────────
// Serve custom error pages
const errorPageMap = {
  400: '/errors/400.html',
  401: '/errors/401.html',
  402: '/errors/402.html',
  403: '/errors/403.html',
  404: '/errors/404.html',
  405: '/errors/405.html',
  407: '/errors/407.html',
  408: '/errors/408.html',
  429: '/errors/429.html',
  500: '/errors/500.html',
  502: '/errors/502.html',
  503: '/errors/503.html',
  504: '/errors/504.html',
};

// Catch 404 errors for unknown routes
app.use((req, res) => {
  const errorPagePath = path.join(__dirname, '..', 'public', 'errors', '404.html');
  if (fs.existsSync(errorPagePath)) {
    res.status(404).sendFile(errorPagePath);
  } else {
    res.status(404).json({ error: 'Not Found', code: 404 });
  }
});

// Catch and handle errors from middleware and routes
app.use((err, req, res, next) => {
  const statusCode = err.statusCode || err.status || 500;
  console.error(`[ERROR] ${statusCode}: ${err.message} (${req.method} ${req.path})`);
  
  // Check if it's an API request (Accept: application/json)
  const isApiRequest = req.accepts('application/json') && !req.accepts('html');
  
  if (isApiRequest) {
    // Return JSON for API requests
    res.status(statusCode).json({ 
      error: err.message || 'Internal Server Error',
      code: statusCode
    });
  } else {
    // Return custom HTML error page for browser requests
    const errorPagePath = errorPageMap[statusCode];
    if (errorPagePath) {
      const fullPath = path.join(__dirname, '..', 'public', errorPagePath);
      if (fs.existsSync(fullPath)) {
        res.status(statusCode).sendFile(fullPath);
        return;
      }
    }
    
    // Fallback to JSON if HTML page not found
    res.status(statusCode).json({ 
      error: err.message || 'Internal Server Error',
      code: statusCode
    });
  }
});

// ─── WebSocket Server ──────────────────────────────────────
const wss = new WebSocket.Server({ server, path: '/ws' });
const wsClients = new Map(); // userId -> Set<ws>

function sendToUser(userId, data) {
  const sockets = wsClients.get(userId);
  if (sockets) {
    const msg = JSON.stringify(data);
    sockets.forEach(ws => {
      if (ws.readyState === WebSocket.OPEN) ws.send(msg);
    });
  }
}

function broadcastToAll(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) ws.send(msg);
  });
}

// Send push notifications to offline users
async function sendPushNotifications(recipientUserIds, notification, senderId = null) {
  if (!webpush) {
    console.warn('[PUSH] web-push not available, skipping push notifications');
    return;
  }

  try {
    // Ensure it's an array
    const userIds = Array.isArray(recipientUserIds) ? recipientUserIds : [recipientUserIds];
    let totalSent = 0;
    let totalFailed = 0;
    let totalMuted = 0;
    
    console.log(`[PUSH] Attempting to send notifications to ${userIds.length} user(s): ${userIds.join(', ')}`);
    
    for (const userId of userIds) {
      // Check if sender is muted by this user
      if (senderId) {
        const isMuted = dbGet(
          'SELECT 1 FROM muted_users WHERE user_id = ? AND muted_user_id = ?',
          [userId, senderId]
        );
        if (isMuted) {
          console.log(`[PUSH] ⊘ Skipped ${userId} (sender ${senderId} is muted)`);
          totalMuted++;
          continue;
        }

        // Check if sender is blocked by this user
        const isBlocked = dbGet(
          'SELECT 1 FROM blocked_users WHERE user_id = ? AND blocked_user_id = ?',
          [userId, senderId]
        );
        if (isBlocked) {
          console.log(`[PUSH] ⊘ Skipped ${userId} (sender ${senderId} is blocked)`);
          totalMuted++;
          continue;
        }
      }

      // Get all subscriptions for this user
      const subscriptions = dbAll(
        'SELECT endpoint, auth_key, p256dh_key FROM push_subscriptions WHERE user_id = ?',
        [userId]
      );
      
      console.log(`[PUSH] User ${userId} has ${subscriptions.length} active subscription(s)`);

      // Send to each subscription
      for (const sub of subscriptions) {
        try {
          const pushSubscription = {
            endpoint: sub.endpoint,
            keys: {
              auth: sub.auth_key,
              p256dh: sub.p256dh_key,
            },
          };

          // Send push notification
          await webpush.sendNotification(pushSubscription, JSON.stringify(notification));
          totalSent++;
          console.log(`[PUSH] ✓ Successfully sent notification to ${userId}`);
          
          // Update last used timestamp
          dbRun(
            'UPDATE push_subscriptions SET last_used = ? WHERE endpoint = ?',
            [Date.now(), sub.endpoint]
          );
        } catch (err) {
          totalFailed++;
          if (err.statusCode === 410 || err.statusCode === 404) {
            // Subscription is no longer valid, remove it
            console.warn(`[PUSH] ✗ Subscription expired (${err.statusCode}), removing endpoint`);
            dbRun('DELETE FROM push_subscriptions WHERE endpoint = ?', [sub.endpoint]);
          } else {
            console.error(`[PUSH] ✗ Failed to send to ${userId}: (${err.statusCode || 'Unknown'}) ${err.message}`);
          }
        }
      }
    }
    
    console.log(`[PUSH] Summary: ${totalSent} sent, ${totalFailed} failed, ${totalMuted} muted`);
    if (totalSent > 0) saveDatabase();
  } catch (err) {
    console.error('[PUSH] Error in sendPushNotifications:', err.message);
  }
}

wss.on('connection', (ws, req) => {
  let userId = null;

  // Auto-authenticate from query string token
  try {
    const url = new URL(req.url, 'http://localhost');
    const token = url.searchParams.get('token');
    if (token) {
      const decoded = jwt.verify(token, config.security.jwtSecret);
      userId = decoded.userId;
      ws.userId = userId; // Store userId on websocket for maintenance mode checks
      
      // Check maintenance mode
      const user = dbGet('SELECT role FROM users WHERE id = ?', [userId]);
      if (maintenanceMode && (!user || user.role !== 'admin')) {
        ws.send(JSON.stringify({ 
          type: 'maintenance', 
          enabled: true, 
          message: maintenanceMessage 
        }));
        ws.close(1000, 'Server is in maintenance mode');
        return;
      }
      
      if (!wsClients.has(userId)) wsClients.set(userId, new Set());
      wsClients.get(userId).add(ws);
      dbRun('UPDATE users SET online = 1, last_seen = ? WHERE id = ?', [Date.now(), userId]);
      saveDatabase();
      broadcastToAll({ type: 'user_online', userId });
      ws.send(JSON.stringify({ type: 'auth_success' }));
    }
  } catch (err) {
    console.error('[WS] Auto-auth failed:', err.message);
  }

  ws.on('message', (raw) => {
    try {
      const data = JSON.parse(raw);

      switch (data.type) {
        case 'auth': {
          try {
            const decoded = jwt.verify(data.token, config.security.jwtSecret);
            userId = decoded.userId;
            if (!wsClients.has(userId)) wsClients.set(userId, new Set());
            wsClients.get(userId).add(ws);

            dbRun('UPDATE users SET online = 1, last_seen = ? WHERE id = ?', [Date.now(), userId]);
            saveDatabase();
            broadcastToAll({ type: 'user_online', userId });
            ws.send(JSON.stringify({ type: 'auth_success' }));
          } catch {
            ws.send(JSON.stringify({ type: 'auth_error', error: 'Invalid token' }));
          }
          break;
        }

        case 'typing': {
          if (!userId) break;
          const members = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ? AND user_id != ?', [data.chatId, userId]);
          members.forEach(m => {
            sendToUser(m.user_id, { type: 'typing', chatId: data.chatId, userId });
          });
          break;
        }

        case 'mark_read': {
          if (!userId) break;
          const now = Date.now();
          const msgs = dbAll('SELECT id FROM messages WHERE chat_id = ?', [data.chatId]);
          msgs.forEach(m => {
            dbRun('INSERT OR IGNORE INTO message_reads (message_id, user_id, read_at) VALUES (?, ?, ?)', [m.id, userId, now]);
          });
          saveDatabase();
          break;
        }

        // WebRTC signaling for P2P calls
        case 'call_offer': {
          if (!userId || !data.targetUserId) break;
          console.log(`[CALL] Offer from ${userId} to ${data.targetUserId}`);
          sendToUser(data.targetUserId, { 
            type: 'incoming_call', 
            fromUserId: userId, 
            offer: data.offer,
            callType: data.callType || 'voice'
          });
          break;
        }
        
        case 'call_answer': {
          if (!userId || !data.targetUserId) break;
          console.log(`[CALL] Answer from ${userId} to ${data.targetUserId}`);
          sendToUser(data.targetUserId, { 
            type: 'call_answer', 
            fromUserId: userId, 
            answer: data.answer 
          });
          break;
        }
        
        case 'call_ice_candidate': {
          if (!userId || !data.targetUserId) break;
          sendToUser(data.targetUserId, { 
            type: 'call_ice_candidate', 
            fromUserId: userId, 
            candidate: data.candidate 
          });
          break;
        }
        
        case 'call_reject': {
          if (!userId || !data.targetUserId) break;
          console.log(`[CALL] Rejected by ${userId}`);
          sendToUser(data.targetUserId, { 
            type: 'call_reject', 
            fromUserId: userId 
          });
          break;
        }
        
        case 'call_end': {
          if (!userId || !data.targetUserId) break;
          console.log(`[CALL] Ended by ${userId}`);
          sendToUser(data.targetUserId, { 
            type: 'call_end', 
            fromUserId: userId 
          });
          break;
        }

        case 'call_start': {
          if (!userId) break;
          const callChatMembers = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ? AND user_id != ?', [data.chatId, userId]);
          callChatMembers.forEach(m => {
            sendToUser(m.user_id, { type: 'incoming_call', chatId: data.chatId, callType: data.callType, fromUserId: userId });
          });
          break;
        }
      }
    } catch (err) {
      console.error('[WS] Error processing message:', err.message);
    }
  });

  ws.on('close', () => {
    if (userId) {
      const sockets = wsClients.get(userId);
      if (sockets) {
        sockets.delete(ws);
        if (sockets.size === 0) {
          wsClients.delete(userId);
          dbRun('UPDATE users SET online = 0, last_seen = ? WHERE id = ?', [Date.now(), userId]);
          saveDatabase();
          broadcastToAll({ type: 'user_offline', userId });
        }
      }
    }
  });

  ws.on('error', (err) => {
    console.error('[WS] Socket error:', err.message);
  });
});

// ─── Fallback to SPA ───────────────────────────────────────
app.get('/{*splat}', (req, res) => {
  const indexPath = path.join(__dirname, '../dist/index.html');
  if (fs.existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).json({ error: 'Client not built. Run npm run build first.' });
  }
});

// ─── Initialize Database and Start Server ─────────────────
async function startServer() {
  try {
    // Initialize sql.js
    const SQL = await initSqlJs();
    
    // Load existing database or create new one
    if (fs.existsSync(dbPath)) {
      const fileBuffer = fs.readFileSync(dbPath);
      db = new SQL.Database(fileBuffer);
      console.log('[DB] Loaded existing database from', dbPath);
    } else {
      db = new SQL.Database();
      console.log('[DB] Created new database');
    }

    // Create tables
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        public_key TEXT,
        role TEXT DEFAULT 'user',
        avatar TEXT,
        display_name TEXT,
        theme TEXT DEFAULT 'dark',
        online INTEGER DEFAULT 0,
        last_seen INTEGER,
        email_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        created_at INTEGER NOT NULL,
        bot_approved INTEGER DEFAULT 1
      )
    `);
    
    // Initial CHECK constraint migration is done below
    
    // Bots table
    db.run(`
      CREATE TABLE IF NOT EXISTS bots (
        id TEXT PRIMARY KEY,
        creator_id TEXT NOT NULL,
        name TEXT NOT NULL,
        code TEXT NOT NULL,
        is_active INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    try { dbRun('ALTER TABLE users ADD COLUMN is_bot INTEGER DEFAULT 0'); } catch(e) {}
    try { dbRun('ALTER TABLE users ADD COLUMN bot_owner_id TEXT'); } catch(e) {}
    try { dbRun('ALTER TABLE users ADD COLUMN bot_script TEXT'); } catch(e) {}
    try { dbRun('ALTER TABLE users ADD COLUMN bot_approved INTEGER DEFAULT 1'); } catch(e) {}
    
    try {
      db.run('ALTER TABLE users ADD COLUMN public_key TEXT');
    } catch (e) { /* Column might already exist */ }
    
    // Add columns to existing tables if they don't exist (for upgrades)
    try {
      db.run('ALTER TABLE users ADD COLUMN display_name TEXT');
    } catch (e) { /* Column might already exist */ }
    try {
      db.run('ALTER TABLE users ADD COLUMN theme TEXT DEFAULT "dark"');
    } catch (e) { /* Column might already exist */ }
    try {
      db.run('ALTER TABLE messages ADD COLUMN file_url TEXT');
    } catch (e) { /* Column might already exist */ }
    try {
      db.run('ALTER TABLE messages ADD COLUMN file_name TEXT');
    } catch (e) { /* Column might already exist */ }
    try {
      db.run('ALTER TABLE messages ADD COLUMN file_size INTEGER');
    } catch (e) { /* Column might already exist */ }
    try {
      db.run('ALTER TABLE chats ADD COLUMN is_channel INTEGER DEFAULT 0');
    } catch (e) { /* Column might already exist */ }

    db.run(`
      CREATE TABLE IF NOT EXISTS chats (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL CHECK(type IN ('direct','group','channel')),
        name TEXT,
        description TEXT,
        avatar TEXT,
        is_channel INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL
      )
    `);
    
    db.run(`
      CREATE TABLE IF NOT EXISTS channel_admins (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        PRIMARY KEY (chat_id, user_id),
        FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS chat_members (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        joined_at INTEGER NOT NULL,
        PRIMARY KEY (chat_id, user_id),
        FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS chat_keys (
        chat_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        encrypted_key TEXT NOT NULL,
        required_receivers TEXT DEFAULT '[]',
        received_by TEXT DEFAULT '[]',
        PRIMARY KEY (chat_id, user_id),
        FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Migrate chat_keys table to add new columns if they don't exist
    try { dbRun('ALTER TABLE chat_keys ADD COLUMN required_receivers TEXT DEFAULT "[]"'); } catch(e) { /* Column might already exist */ }
    try { dbRun('ALTER TABLE chat_keys ADD COLUMN received_by TEXT DEFAULT "[]"'); } catch(e) { /* Column might already exist */ }

    db.run(`
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        sender_id TEXT NOT NULL,
        content TEXT NOT NULL,
        type TEXT DEFAULT 'text' CHECK(type IN ('text','file','image','voice','poll','sticker','system')),
        file_name TEXT,
        file_size INTEGER,
        file_url TEXT,
        poll_id TEXT,
        encrypted INTEGER DEFAULT 0,
        edited INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
        FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE SET NULL
      )
    `);

    // Bot fields on user table
    try { db.run('ALTER TABLE users ADD COLUMN is_bot INTEGER DEFAULT 0'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN owner_id TEXT'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN bot_script TEXT'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN bot_approved INTEGER DEFAULT 1'); } catch(e){}
    
    // Add poll_id column to existing messages table
    try {
      db.run('ALTER TABLE messages ADD COLUMN poll_id TEXT');
    } catch (e) { /* Column might already exist */ }
    
    // Migrate old users table to remove CHECK constraint if it exists
    try {
      const usersTest = dbGet("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'");
      if (usersTest && usersTest.sql && usersTest.sql.includes("CHECK(role IN ('admin','moderator','user','banned'))")) {
        console.log('[DB] Migrating users table to remove strict role CHECK constraint...');
        
        db.run(`
          CREATE TABLE IF NOT EXISTS users_new (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT,
            role TEXT DEFAULT 'user',
            avatar TEXT,
            display_name TEXT,
            theme TEXT DEFAULT 'dark',
            online INTEGER DEFAULT 0,
            last_seen INTEGER,
            email_verified INTEGER DEFAULT 0,
            verification_token TEXT,
            created_at INTEGER NOT NULL,
            is_bot INTEGER DEFAULT 0,
            owner_id TEXT,
            bot_script TEXT,
            bot_approved INTEGER DEFAULT 1
          )
        `);
        
        db.run(`
          INSERT INTO users_new (id, username, email, password, public_key, role, avatar, display_name, theme, online, last_seen, email_verified, verification_token, created_at, is_bot, owner_id, bot_script, bot_approved)
          SELECT id, username, email, password, public_key, role, avatar, display_name, theme, online, last_seen, email_verified, verification_token, created_at, is_bot, owner_id, bot_script,
                 COALESCE(bot_approved, 1)
          FROM users
        `);
        
        db.run('DROP TABLE users');
        db.run('ALTER TABLE users_new RENAME TO users');
        console.log('[DB] Users table migration complete');
      }
    } catch (e) {
      console.error('[DB] Users migration error (may be safe to ignore):', e.message);
    }

    // Update existing bots to have 'bot' role
    try {
      db.run("UPDATE users SET role = 'bot' WHERE is_bot = 1");
    } catch (e) { /* Ignore */ }

    // Backfill: existing bots are approved by default unless explicitly set
    try { db.run("UPDATE users SET bot_approved = 1 WHERE is_bot = 1 AND bot_approved IS NULL"); } catch (e) { /* Ignore */ }
    
    // Database columns for Bots
    try { db.run('ALTER TABLE users ADD COLUMN is_bot INTEGER DEFAULT 0'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN owner_id TEXT'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN bot_script TEXT'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN bot_approved INTEGER DEFAULT 1'); } catch(e){}

    // Ensure blocked_users table exists (migration for existing databases)
    try {
      const blockedUsersTest = dbGet("SELECT name FROM sqlite_master WHERE type='table' AND name='blocked_users'");
      if (!blockedUsersTest) {
        console.log('[DB] Creating blocked_users table...');
        db.run(`
          CREATE TABLE IF NOT EXISTS blocked_users (
            user_id TEXT NOT NULL,
            blocked_user_id TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY (user_id, blocked_user_id),
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY (blocked_user_id) REFERENCES users(id) ON DELETE CASCADE,
            UNIQUE(user_id, blocked_user_id)
          )
        `);
        db.run('CREATE INDEX IF NOT EXISTS idx_blocked_users ON blocked_users(user_id)');
        db.run('CREATE INDEX IF NOT EXISTS idx_blocked_by ON blocked_users(blocked_user_id)');
        console.log('[DB] blocked_users table and indexes created');
      }
    } catch (e) {
      console.error('[DB] Error checking/creating blocked_users table:', e.message);
    }

    // Fix old CHECK constraint on messages table that doesn't include 'voice' and 'poll'
    // We need to recreate the table to change CHECK constraints
    try {
      // Check if we have the old constraint by trying to insert a test record
      const testResult = dbGet("SELECT sql FROM sqlite_master WHERE type='table' AND name='messages'");
      if (testResult && testResult.sql && testResult.sql.includes("CHECK(type IN ('text','file','image','system'))")) {
        console.log('[DB] Migrating messages table to support new message types...');
        
        // Create new table without CHECK constraint
        db.run(`
          CREATE TABLE IF NOT EXISTS messages_new (
            id TEXT PRIMARY KEY,
            chat_id TEXT NOT NULL,
            sender_id TEXT NOT NULL,
            content TEXT NOT NULL,
            type TEXT DEFAULT 'text',
            file_name TEXT,
            file_size INTEGER,
            file_url TEXT,
            poll_id TEXT,
            encrypted INTEGER DEFAULT 0,
            edited INTEGER DEFAULT 0,
            created_at INTEGER NOT NULL,
            FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
            FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE
          )
        `);
        
        // Copy data
        db.run(`
          INSERT INTO messages_new (id, chat_id, sender_id, content, type, file_name, file_size, file_url, poll_id, encrypted, edited, created_at)
          SELECT id, chat_id, sender_id, content, type, file_name, file_size, file_url, poll_id, encrypted, edited, created_at FROM messages
        `);
        
        // Drop old table and rename new one
        db.run('DROP TABLE messages');
        db.run('ALTER TABLE messages_new RENAME TO messages');
        
        // Recreate indexes
        db.run('CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)');
        db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
        
        console.log('[DB] Messages table migration complete');
        saveDatabase();
      }
    } catch (e) {
      console.error('[DB] Migration error (may be safe to ignore):', e.message);
    }

    db.run(`
      CREATE TABLE IF NOT EXISTS message_reads (
        message_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        read_at INTEGER NOT NULL,
        PRIMARY KEY (message_id, user_id),
        FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        token TEXT NOT NULL,
        ip TEXT,
        user_agent TEXT,
        created_at INTEGER NOT NULL,
        expires_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS files (
        id TEXT PRIMARY KEY,
        original_name TEXT NOT NULL,
        stored_name TEXT NOT NULL,
        mime_type TEXT NOT NULL,
        size INTEGER NOT NULL,
        encrypted INTEGER DEFAULT 0,
        uploaded_by TEXT NOT NULL,
        uploaded_at INTEGER NOT NULL,
        FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS polls (
        id TEXT PRIMARY KEY,
        chat_id TEXT NOT NULL,
        creator_id TEXT NOT NULL,
        question TEXT NOT NULL,
        multiple_choice INTEGER DEFAULT 0,
        anonymous INTEGER DEFAULT 0,
        closed INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (chat_id) REFERENCES chats(id) ON DELETE CASCADE,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS poll_options (
        id TEXT PRIMARY KEY,
        poll_id TEXT NOT NULL,
        option_index INTEGER NOT NULL,
        option_text TEXT NOT NULL,
        FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS poll_votes (
        id TEXT PRIMARY KEY,
        poll_id TEXT NOT NULL,
        option_id TEXT NOT NULL,
        user_id TEXT NOT NULL,
        voted_at INTEGER NOT NULL,
        FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE,
        FOREIGN KEY (option_id) REFERENCES poll_options(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Admin Audit Log table
    db.run(`
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        admin_id TEXT NOT NULL,
        action TEXT NOT NULL,
        target_id TEXT,
        target_type TEXT,
        old_value TEXT,
        new_value TEXT,
        ip_address TEXT,
        timestamp INTEGER NOT NULL,
        FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE SET NULL
      )
    `);

    // Login History table
    db.run(`
      CREATE TABLE IF NOT EXISTS login_history (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        ip_address TEXT,
        user_agent TEXT,
        login_time INTEGER NOT NULL,
        logout_time INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Stickers tables
    db.run(`
      CREATE TABLE IF NOT EXISTS stickers (
        id TEXT PRIMARY KEY,
        creator_id TEXT NOT NULL,
        name TEXT NOT NULL,
        image_data TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (creator_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS user_stickers (
        user_id TEXT NOT NULL,
        sticker_id TEXT NOT NULL,
        added_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, sticker_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (sticker_id) REFERENCES stickers(id) ON DELETE CASCADE
      )
    `);

    // Push notification subscriptions
    db.run(`
      CREATE TABLE IF NOT EXISTS push_subscriptions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        endpoint TEXT NOT NULL UNIQUE,
        auth_key TEXT NOT NULL,
        p256dh_key TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_used INTEGER,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    // Muted users (users who don't want notifications from specific users)
    db.run(`
      CREATE TABLE IF NOT EXISTS muted_users (
        user_id TEXT NOT NULL,
        muted_user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, muted_user_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (muted_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, muted_user_id)
      )
    `);

    // Blocked users (users whose messages/notifications are blocked)
    db.run(`
      CREATE TABLE IF NOT EXISTS blocked_users (
        user_id TEXT NOT NULL,
        blocked_user_id TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        PRIMARY KEY (user_id, blocked_user_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (blocked_user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE(user_id, blocked_user_id)
      )
    `);

    // Create indexes
    db.run('CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)');
    dbRun('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_members_chat ON chat_members(chat_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_audit_logs_admin ON audit_logs(admin_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)');
    db.run('CREATE INDEX IF NOT EXISTS idx_login_history_user ON login_history(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_login_history_time ON login_history(login_time)');
    db.run('CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_push_subscriptions_endpoint ON push_subscriptions(endpoint)');
    db.run('CREATE INDEX IF NOT EXISTS idx_muted_users ON muted_users(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_muted_by ON muted_users(muted_user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_blocked_users ON blocked_users(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_blocked_by ON blocked_users(blocked_user_id)');

    // 2FA-related tables and columns
    try { db.run('ALTER TABLE users ADD COLUMN totp_secret TEXT'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN totp_enabled INTEGER DEFAULT 0'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN email_2fa_enabled INTEGER DEFAULT 0'); } catch(e){}
    try { db.run('ALTER TABLE users ADD COLUMN trusted_devices TEXT'); } catch(e){}
    
    // 2FA trusted devices for "other messenger sessions" option
    db.run(`
      CREATE TABLE IF NOT EXISTS trusted_devices (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        device_name TEXT NOT NULL,
        device_token TEXT NOT NULL UNIQUE,
        last_used INTEGER,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    // 2FA email verification codes
    db.run(`
      CREATE TABLE IF NOT EXISTS twofa_email_codes (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at INTEGER NOT NULL,
        attempts_left INTEGER DEFAULT 3,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);
    
    // 2FA sessions for in-progress authentication
    db.run(`
      CREATE TABLE IF NOT EXISTS twofa_sessions (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        session_token TEXT NOT NULL UNIQUE,
        expires_at INTEGER NOT NULL,
        attempts_left INTEGER DEFAULT 5,
        created_at INTEGER NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      )
    `);

    db.run('CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_twofa_email_codes_user ON twofa_email_codes(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_twofa_sessions_user ON twofa_sessions(user_id)');

    console.log('[DB] Database initialized successfully');

    // Create default admin if configured
    if (config.admin.createDefaultAdmin) {
      const existing = dbGet('SELECT id FROM users WHERE username = ?', [config.admin.defaultAdminUsername]);
      if (!existing) {
        const id = uuidv4();
        const hashedPassword = bcrypt.hashSync(config.admin.defaultAdminPassword, config.security.bcryptRounds);
        const defaultRole = config.admin.defaultAdminRole || 'admin';
        dbRun(`
          INSERT INTO users (id, username, email, password, role, online, email_verified, created_at)
          VALUES (?, ?, ?, ?, ?, 0, 1, ?)
        `, [id, config.admin.defaultAdminUsername, config.admin.defaultAdminEmail, hashedPassword, defaultRole, Date.now()]);
        saveDatabase();
        console.log(`[ADMIN] Default admin created with role '${defaultRole}': ${config.admin.defaultAdminUsername} / ${config.admin.defaultAdminPassword}`);
      }
    }

    // Auto-save database periodically
    setInterval(saveDatabase, 30000);

    // Start server
    const PORT = process.env.PORT || config.server.port;
    const HOST = process.env.HOST || config.server.host;

    server.listen(PORT, HOST, () => {
      console.log('');
      console.log('  ╔══════════════════════════════════════════╗');
      console.log('  ║          4 Messenger Server              ║');
      console.log('  ╠══════════════════════════════════════════╣');
      console.log(`  ║  URL:        http://${HOST}:${PORT}        `);
      console.log(`  ║  WebSocket:  ws://${HOST}:${PORT}/ws       `);
      console.log(`  ║  Database:   ${config.database.sqlite.filename}  `);
      console.log(`  ║  Encryption: ${config.security.encryptionEnabled ? 'Enabled' : 'Disabled'}               `);
      console.log(`  ║  CAPTCHA:    ${config.captcha.enabled ? 'Enabled' : 'Disabled'}               `);
      console.log(`  ║  Email:      ${config.email.verificationEnabled ? 'Enabled' : 'Disabled'}               `);
      console.log('  ╚══════════════════════════════════════════╝');
      console.log('');
    });

  } catch (err) {
    console.error('[FATAL] Failed to start server:', err);
    process.exit(1);
  }
}

// ─── Graceful Shutdown ─────────────────────────────────────
process.on('SIGINT', () => {
  console.log('\n[SERVER] Shutting down...');
  if (db) {
    dbRun('UPDATE users SET online = 0');
    saveDatabase();
  }
  server.close();
  process.exit(0);
});

process.on('SIGTERM', () => {
  if (db) {
    dbRun('UPDATE users SET online = 0');
    saveDatabase();
  }
  server.close();
  process.exit(0);
});

// Start the server
startServer();
