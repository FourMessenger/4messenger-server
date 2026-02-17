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
try { const { v4 } = require('uuid'); uuidv4 = v4; } catch { uuidv4 = () => crypto.randomUUID(); }

// ─── Ensure Directories ────────────────────────────────────
function ensureDirectories() {
  // Create directories from config
  const dataDir = path.dirname(path.resolve(__dirname, config.database.sqlite.filename));
  const uploadDir = path.resolve(__dirname, config.files.uploadDir);
  const logDir = path.dirname(path.resolve(__dirname, config.logging.file));
  
  [dataDir, uploadDir, logDir].forEach(dir => {
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

function collectBrowserData(req, browserInfo = {}) {
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || 
             req.socket?.remoteAddress?.replace('::ffff:', '') || 
             req.ip?.replace('::ffff:', '') || 
             'unknown';
  
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
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || 
             req.socket?.remoteAddress?.replace('::ffff:', '') || 
             req.ip?.replace('::ffff:', '') || 
             'unknown';
  
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
const ALGO = config.security.encryptionAlgorithm || 'aes-256-gcm';
const ENC_KEY = crypto.scryptSync(config.security.jwtSecret, 'salt', 32);

function encrypt(text) {
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv(ALGO, ENC_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const tag = cipher.getAuthTag().toString('hex');
  return iv.toString('hex') + ':' + tag + ':' + encrypted;
}

function decrypt(data) {
  try {
    const [ivHex, tagHex, encrypted] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const tag = Buffer.from(tagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGO, ENC_KEY, iv);
    decipher.setAuthTag(tag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch {
    return data;
  }
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
      console.warn('[EMAIL] Gmail connection failed:', err.message);
      console.warn('[EMAIL] Make sure you are using a valid Gmail App Password');
      console.warn('[EMAIL] To create an App Password:');
      console.warn('[EMAIL]   1. Go to https://myaccount.google.com/apppasswords');
      console.warn('[EMAIL]   2. Select "Mail" and your device');
      console.warn('[EMAIL]   3. Copy the 16-character password to config.json');
    } else {
      console.log('[EMAIL] Gmail connection verified');
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

// Security middleware
if (helmet) app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors(config.server.cors));
app.use(express.json({ limit: '10mb' }));

// Rate limiting
if (rateLimit) {
  const limiter = rateLimit({
    windowMs: config.security.rateLimitWindow,
    max: config.security.rateLimitMax,
    message: { error: 'Too many requests, please try again later.' },
  });
  app.use('/api/', limiter);
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
    
    // Check maintenance mode - only admins can access during maintenance
    if (maintenanceMode && user.role !== 'admin') {
      return res.status(503).json({ error: 'Server is under maintenance', maintenanceMessage });
    }
    
    req.user = user;
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

function adminMiddleware(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin access required' });
  next();
}

function modMiddleware(req, res, next) {
  if (!['admin', 'moderator'].includes(req.user.role)) return res.status(403).json({ error: 'Moderator access required' });
  next();
}

// ─── API Routes ────────────────────────────────────────────

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
    captchaEnabled: config.captcha.enabled,
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

// CAPTCHA (Cloudflare Turnstile)
app.get('/api/captcha', (req, res) => {
  // Add CORS headers explicitly for this endpoint
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
  
  if (!config.captcha.enabled) {
    return res.json({ enabled: false });
  }
  
  // Return Cloudflare Turnstile site key
  const siteKey = config.captcha.cloudflare?.siteKey;
  if (!siteKey || siteKey.includes('XXXX') || siteKey.includes('your-')) {
    console.warn('[CAPTCHA] Cloudflare Turnstile site key not configured properly');
    console.warn('[CAPTCHA] Please set a valid siteKey in config.json');
    // Return disabled when not configured to avoid errors
    return res.json({ enabled: false, error: 'CAPTCHA not configured on server' });
  }
  
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
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
             req.headers['x-real-ip'] || 
             req.socket?.remoteAddress?.replace('::ffff:', '') || 
             req.ip?.replace('::ffff:', '') || 
             '';
  
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
  if (config.captcha.enabled) {
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

  dbRun(`
    INSERT INTO users (id, username, email, password, role, online, last_seen, email_verified, verification_token, created_at)
    VALUES (?, ?, ?, ?, ?, 0, ?, ?, ?, ?)
  `, [id, username, email, hashedPassword, config.registration.defaultRole, now, config.email.verificationEnabled ? 0 : 1, verificationToken, now]);
  
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
  const { username, password, captchaToken } = req.body;

  // Check maintenance mode - allow admin login
  const checkUser = dbGet('SELECT role FROM users WHERE username = ? OR email = ?', [username, username]);
  if (maintenanceMode && (!checkUser || checkUser.role !== 'admin')) {
    return res.status(503).json({ error: 'Server is under maintenance. Only admins can login.', maintenanceMessage });
  }

  // Validate captcha token (pre-verified on auth screen)
  if (config.captcha.enabled) {
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

  // Update online status
  dbRun('UPDATE users SET online = 1, last_seen = ? WHERE id = ?', [Date.now(), user.id]);
  saveDatabase();
  
  // Associate browser data with user
  updateBrowserDataUser(req, user.id, user.username);

  const token = jwt.sign({ userId: user.id }, config.security.jwtSecret, { expiresIn: config.security.jwtExpiry });

  res.json({
    user: {
      id: user.id, username: user.username, email: user.email,
      role: user.role, online: true, emailVerified: !!user.email_verified,
      displayName: user.display_name || null,
      avatar: user.avatar || null,
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
  });
});

// Logout
app.post('/api/logout', authMiddleware, (req, res) => {
  dbRun('UPDATE users SET online = 0, last_seen = ? WHERE id = ?', [Date.now(), req.user.id]);
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

// Get all users - admins can search partial, others need exact username
app.get('/api/users', authMiddleware, (req, res) => {
  const { search } = req.query;
  const isAdmin = req.user.role === 'admin';
  
  if (search && search.trim()) {
    let users;
    
    if (isAdmin) {
      // Admins can search by partial username or email (case-insensitive)
      const searchPattern = `%${search.trim().toLowerCase()}%`;
      users = dbAll(`
        SELECT id, username, email, role, avatar, display_name, online, last_seen, email_verified, created_at 
        FROM users 
        WHERE (LOWER(username) LIKE ? OR LOWER(email) LIKE ? OR LOWER(display_name) LIKE ?) 
        AND id != ?
      `, [searchPattern, searchPattern, searchPattern, req.user.id]);
    } else {
      // Moderators and users need exact username match (case-insensitive)
      users = dbAll(`
        SELECT id, username, email, role, avatar, display_name, online, last_seen, email_verified, created_at 
        FROM users 
        WHERE LOWER(username) = LOWER(?) AND id != ? AND role != 'banned'
      `, [search.trim(), req.user.id]);
    }
    
    // Map display_name to displayName
    return res.json(users.map(u => ({ ...u, displayName: u.display_name })));
  }
  
  // No search query
  if (isAdmin) {
    // Admins can see all users
    const users = dbAll(`
      SELECT id, username, email, role, avatar, display_name, online, last_seen, email_verified, created_at 
      FROM users 
      WHERE id != ?
      ORDER BY created_at DESC
    `, [req.user.id]);
    return res.json(users.map(u => ({ ...u, displayName: u.display_name })));
  }
  
  // Return users who share a chat with current user
  const users = dbAll(`
    SELECT DISTINCT u.id, u.username, u.email, u.role, u.avatar, u.display_name, u.online, u.last_seen, u.email_verified, u.created_at 
    FROM users u
    JOIN chat_members cm1 ON u.id = cm1.user_id
    JOIN chat_members cm2 ON cm1.chat_id = cm2.chat_id
    WHERE cm2.user_id = ? AND u.id != ? AND u.role != 'banned'
  `, [req.user.id, req.user.id]);
  
  // Map display_name to displayName
  res.json(users.map(u => ({ ...u, displayName: u.display_name })));
});

// Update user role (admin only)
app.put('/api/users/:id/role', authMiddleware, adminMiddleware, (req, res) => {
  const { role } = req.body;
  if (!['admin', 'moderator', 'user', 'banned'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role' });
  }
  dbRun('UPDATE users SET role = ? WHERE id = ?', [role, req.params.id]);
  saveDatabase();
  broadcastToAll({ type: 'user_updated', userId: req.params.id, role });
  res.json({ success: true });
});

// Ban user
app.post('/api/users/:id/ban', authMiddleware, modMiddleware, (req, res) => {
  // Get target user
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Moderators can't ban admins or other moderators
  if (req.user.role === 'moderator' && ['admin', 'moderator'].includes(targetUser.role)) {
    return res.status(403).json({ error: 'Moderators cannot ban admins or other moderators' });
  }
  
  // Can't ban yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot ban yourself' });
  }
  
  dbRun('UPDATE users SET role = ?, online = 0 WHERE id = ?', ['banned', req.params.id]);
  saveDatabase();
  broadcastToAll({ type: 'user_banned', userId: req.params.id });
  res.json({ success: true });
});

// Unban user
app.post('/api/users/:id/unban', authMiddleware, modMiddleware, (req, res) => {
  dbRun('UPDATE users SET role = ? WHERE id = ?', ['user', req.params.id]);
  saveDatabase();
  res.json({ success: true });
});

// Delete user (admin only)
app.delete('/api/users/:id', authMiddleware, adminMiddleware, (req, res) => {
  // Can't delete yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete yourself' });
  }
  dbRun('DELETE FROM users WHERE id = ?', [req.params.id]);
  saveDatabase();
  res.json({ success: true });
});

// Kick user (disconnect from server)
app.post('/api/users/:id/kick', authMiddleware, modMiddleware, (req, res) => {
  const targetUser = dbGet('SELECT * FROM users WHERE id = ?', [req.params.id]);
  if (!targetUser) return res.status(404).json({ error: 'User not found' });
  
  // Moderators can't kick admins or other moderators
  if (req.user.role === 'moderator' && ['admin', 'moderator'].includes(targetUser.role)) {
    return res.status(403).json({ error: 'Moderators cannot kick admins or other moderators' });
  }
  
  // Can't kick yourself
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot kick yourself' });
  }
  
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
  
  broadcastToAll({ type: 'user_offline', userId: req.params.id });
  res.json({ success: true });
});

// Kick all users (admin only)
app.post('/api/admin/kick-all', authMiddleware, adminMiddleware, (req, res) => {
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
    
    // Decrypt last message content if needed
    let lastMsg = lastMessage;
    if (lastMessage && lastMessage.encrypted && config.security.encryptionEnabled && lastMessage.type === 'text') {
      lastMsg = { ...lastMessage, content: decrypt(lastMessage.content) };
    }
    
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

  res.json(result);
});

// Create direct chat
app.post('/api/chats/direct', authMiddleware, (req, res) => {
  const { userId } = req.body;

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
  saveDatabase();

  res.status(201).json({ chatId });
});

// Create group or channel
app.post('/api/chats/group', authMiddleware, (req, res) => {
  const { name, description, participants, isChannel } = req.body;
  if (!name) return res.status(400).json({ error: 'Group name required' });

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
  const { userId } = req.body;
  const chatId = req.params.id;

  const member = dbGet('SELECT * FROM chat_members WHERE chat_id = ? AND user_id = ?', [chatId, req.user.id]);
  if (!member) return res.status(403).json({ error: 'Not a member' });

  dbRun('INSERT OR IGNORE INTO chat_members (chat_id, user_id, joined_at) VALUES (?, ?, ?)', [chatId, userId, Date.now()]);
  saveDatabase();
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

  const msgs = dbAll('SELECT * FROM messages WHERE chat_id = ? AND created_at < ? ORDER BY created_at DESC LIMIT ?', [chatId, before, limit]);

  // Decrypt and format messages
  const result = msgs.reverse().map(m => {
    let content = m.content;
    if (m.encrypted && config.security.encryptionEnabled && m.type === 'text') {
      content = decrypt(m.content);
    }
    
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
      content: content,
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
  let encrypted = 0;
  const originalContent = content;

  // Only encrypt text messages, not file messages
  if (config.security.encryptionEnabled && type === 'text' && content) {
    content = encrypt(content);
    encrypted = 1;
  }

  dbRun('INSERT INTO messages (id, chat_id, sender_id, content, type, file_name, file_size, file_url, encrypted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)', [
    msgId, chatId, req.user.id, content, type, fileName || null, fileSize || null, fileUrl || null, encrypted, now
  ]);
  saveDatabase();

  // Message object to broadcast and return
  const message = { 
    id: msgId, 
    chatId, 
    chat_id: chatId,
    senderId: req.user.id, 
    sender_id: req.user.id,
    content: originalContent,  // Send original (decrypted) content to clients
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
    // Send to all members except the sender (they already have it optimistically)
    if (m.user_id !== req.user.id) {
      sendToUser(m.user_id, { type: 'message', data: message });
    }
  });

  res.status(201).json(message);
});

// Edit message
app.put('/api/messages/:id', authMiddleware, (req, res) => {
  const msg = dbGet('SELECT * FROM messages WHERE id = ?', [req.params.id]);
  if (!msg) return res.status(404).json({ error: 'Message not found' });
  if (msg.sender_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Not authorized' });
  }

  let content = req.body.content;
  const originalContent = req.body.content;
  if (config.security.encryptionEnabled) content = encrypt(content);

  dbRun('UPDATE messages SET content = ?, edited = 1 WHERE id = ?', [content, req.params.id]);
  saveDatabase();
  
  // Broadcast edit to all chat members
  const editMembers = dbAll('SELECT user_id FROM chat_members WHERE chat_id = ?', [msg.chat_id]);
  editMembers.forEach(m => {
    if (m.user_id !== req.user.id) {
      sendToUser(m.user_id, { type: 'message_edited', data: { id: req.params.id, content: originalContent, chatId: msg.chat_id } });
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

  // Save to file
  fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));
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
  // In a real app, you'd read from a log file or database
  const logs = [
    { id: '1', timestamp: Date.now(), type: 'info', action: 'Server started', details: `Port ${config.server.port}` },
  ];
  res.json(logs);
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
        role TEXT DEFAULT 'user' CHECK(role IN ('admin','moderator','user','banned')),
        avatar TEXT,
        display_name TEXT,
        theme TEXT DEFAULT 'dark',
        online INTEGER DEFAULT 0,
        last_seen INTEGER,
        email_verified INTEGER DEFAULT 0,
        verification_token TEXT,
        created_at INTEGER NOT NULL
      )
    `);
    
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
    
    // Add poll_id column to existing messages table
    try {
      db.run('ALTER TABLE messages ADD COLUMN poll_id TEXT');
    } catch (e) { /* Column might already exist */ }
    
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

    // Create indexes
    db.run('CREATE INDEX IF NOT EXISTS idx_messages_chat ON messages(chat_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_members_user ON chat_members(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_chat_members_chat ON chat_members(chat_id)');

    console.log('[DB] Database initialized successfully');

    // Create default admin if configured
    if (config.admin.createDefaultAdmin) {
      const existing = dbGet('SELECT id FROM users WHERE username = ?', [config.admin.defaultAdminUsername]);
      if (!existing) {
        const id = uuidv4();
        const hashedPassword = bcrypt.hashSync(config.admin.defaultAdminPassword, config.security.bcryptRounds);
        dbRun(`
          INSERT INTO users (id, username, email, password, role, online, email_verified, created_at)
          VALUES (?, ?, ?, ?, 'admin', 0, 1, ?)
        `, [id, config.admin.defaultAdminUsername, config.admin.defaultAdminEmail, hashedPassword, Date.now()]);
        saveDatabase();
        console.log(`[ADMIN] Default admin created: ${config.admin.defaultAdminUsername} / ${config.admin.defaultAdminPassword}`);
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
