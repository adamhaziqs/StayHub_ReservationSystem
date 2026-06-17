require('dotenv').config();
const fs = require('fs');
const path = require('path');
const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const session = require('express-session');
const csurf = require('csurf');
const crypto = require('crypto');
const https = require('https');
const multer = require('multer');

console.log('🚀 Starting secure server...');

const app = express();
const DATA_FILE = path.join(__dirname, 'data.json');
// Store uploaded files outside the immediate application web root
const UPLOAD_DIR = path.join(__dirname, '..', 'secure_storage', 'uploads');
const TEMP_UPLOAD_DIR = path.join(__dirname, '..', 'secure_storage', 'temp');

// Configuration Validation
const isProduction = process.env.NODE_ENV === 'production';
const SESSION_SECRET = process.env.SESSION_SECRET;

if (isProduction) {
  if (!SESSION_SECRET || SESSION_SECRET === 'change-this-in-production') {
    console.error('❌ CRITICAL SECURITY ERROR: SESSION_SECRET must be set to a strong, unique value in production.');
    process.exit(1);
  }
  if (!process.env.ADMIN_PASSWORD || process.env.ADMIN_PASSWORD === 'Admin123!') {
    console.warn('⚠️  WARNING: Using default or missing ADMIN_PASSWORD in production is highly discouraged.');
  }
}

// Ensure upload directories exist and are secure
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true, mode: 0o755 });
}
if (!fs.existsSync(TEMP_UPLOAD_DIR)) {
  fs.mkdirSync(TEMP_UPLOAD_DIR, { recursive: true, mode: 0o755 });
}

// File Upload Security Configuration
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const ALLOWED_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.webp', '.gif'];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB
const MAX_FILES = 3;

function isValidMimeType(mimeType) {
  return ALLOWED_MIME_TYPES.includes(mimeType);
}

function isValidFileExtension(filename) {
  const ext = path.extname(filename).toLowerCase();
  return ALLOWED_EXTENSIONS.includes(ext);
}

function getRandomFileName(originalName) {
  const ext = path.extname(originalName);
  // Use standard UUID for unique, unpredictable filenames
  return `${crypto.randomUUID()}${ext}`;
}

// Multer storage configuration - uses temp directory first
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, TEMP_UPLOAD_DIR);
  },
  filename: (req, file, cb) => {
    const randomName = getRandomFileName(file.originalname);
    cb(null, randomName);
  }
});

// File filter for multer
const fileFilter = (req, file, cb) => {
  // Validate MIME type
  if (!isValidMimeType(file.mimetype)) {
    return cb(new Error('Invalid file type. Only JPEG, PNG, WebP, and GIF allowed.'));
  }
  
  // Validate file extension
  if (!isValidFileExtension(file.originalname)) {
    return cb(new Error('Invalid file extension.'));
  }
  
  cb(null, true);
};

// Multer upload middleware with security
const upload = multer({
  storage,
  fileFilter,
  limits: {
    fileSize: MAX_FILE_SIZE,
    files: MAX_FILES
  }
});
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Admin123!';
const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID || null;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET || null;
const GOOGLE_AUTH_ENABLED = Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET);

if (GOOGLE_AUTH_ENABLED) {
  console.log('📝 Google OAuth credentials found. Google login is enabled.');
} else {
  console.log('📝 Google OAuth credentials not found. Only local login/register will be available.');
}

// PKCE helper functions
function generateCodeVerifier() {
  return crypto.randomBytes(32).toString('hex');
}

function generateCodeChallenge(codeVerifier) {
  return crypto
    .createHash('sha256')
    .update(codeVerifier)
    .digest('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=/g, '');
}

function generateId() {
  return crypto.randomBytes(10).toString('hex');
}

// Enhanced password hashing with OWASP-compliant PBKDF2 parameters
// (Consider using bcrypt for production: npm install bcrypt)
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(32).toString('hex');
  // OWASP recommendation: 310,000+ iterations, SHA-512
  const iterations = 310000;
  const derivedKey = crypto.pbkdf2Sync(password, salt, iterations, 64, 'sha512').toString('hex');
  return `${iterations}:${salt}:${derivedKey}`;
}

function verifyPassword(password, stored) {
  if (!stored || typeof stored !== 'string') return false;
  const parts = stored.split(':');
  let iterations;
  let salt;
  let derivedKey;

  if (parts.length === 3) {
    [iterations, salt, derivedKey] = parts;
  } else if (parts.length === 2) {
    iterations = 310000;
    [salt, derivedKey] = parts;
  } else {
    return false;
  }

  if (!salt || !derivedKey || !iterations) return false;
  const hashed = crypto.pbkdf2Sync(password, salt, parseInt(iterations, 10), 64, 'sha512').toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hashed, 'hex'), Buffer.from(derivedKey, 'hex'));
}

function verifyAndUpgradePassword(user, password) {
  if (!verifyPassword(password, user.passwordHash)) return false;
  const parts = String(user.passwordHash).split(':');
  if (parts.length === 2) {
    user.passwordHash = hashPassword(password);
    writeData(data);
  }
  return true;
}

// Password reset token management
function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function findUserByResetToken(token) {
  return data.users.find((user) => user.resetToken === token && user.resetTokenExpiry && new Date(user.resetTokenExpiry) > new Date());
}

function setResetToken(user) {
  const token = generateResetToken();
  user.resetToken = token;
  user.resetTokenExpiry = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour expiry
  writeData(data);
  return token;
}

function clearResetToken(user) {
  delete user.resetToken;
  delete user.resetTokenExpiry;
  writeData(data);
}

function writeData(data) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function loadData() {
  if (!fs.existsSync(DATA_FILE)) {
    const defaultAdmin = {
      id: generateId(),
      displayName: 'Administrator',
      email: 'admin@example.com',
      passwordHash: hashPassword(ADMIN_PASSWORD),
      role: 'admin',
      provider: 'local',
      createdAt: new Date().toISOString()
    };
    const initial = { users: [defaultAdmin], properties: [], bookings: [], auditLogs: [] };
    writeData(initial);
    return initial;
  }

  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.users) parsed.users = [];
    if (!parsed.properties) parsed.properties = [];
    if (!parsed.bookings) parsed.bookings = [];
    if (!parsed.auditLogs) parsed.auditLogs = [];
    if (!parsed.users.some((user) => user.role === 'admin')) {
      const defaultAdmin = {
        id: generateId(),
        displayName: 'Administrator',
        email: 'admin@example.com',
        passwordHash: hashPassword(ADMIN_PASSWORD),
        role: 'admin',
        provider: 'local',
        createdAt: new Date().toISOString()
      };
      parsed.users.unshift(defaultAdmin);
    }
    return parsed;
  } catch (err) {
    console.error('❌ Failed to load data.json:', err);
    process.exit(1);
  }
}

const data = loadData();

function findUserByEmail(email) {
  return data.users.find((user) => user.email.toLowerCase() === String(email).toLowerCase());
}

function findUserByGoogleId(googleId) {
  return data.users.find((user) => user.googleId === googleId);
}

// Audit logging with redacted sensitive data (OWASP A6 - Sensitive Data Protection)
function audit(type, message, req, userId) {
  // Redact email addresses and sensitive info from audit logs
  const redactedMessage = message
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]')
    .replace(/password/gi, '[REDACTED]')
    .replace(/token/gi, '[REDACTED]')
    .replace(/secret/gi, '[REDACTED]');
  
  const entry = {
    id: generateId(),
    timestamp: new Date().toISOString(),
    type,
    message: redactedMessage,
    ip: req.ip || req.connection?.remoteAddress || 'unknown',
    userId: userId || (req.user && req.user.id) || null
  };
  data.auditLogs.unshift(entry);
  if (data.auditLogs.length > 200) data.auditLogs.pop();
  writeData(data);
}

function currentUser(req) {
  if (req.user) return req.user;
  if (req.session?.localUser) return req.session.localUser;
  return null;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function ensureAuthenticated(req, res, next) {
  if (currentUser(req)) {
    req.user = currentUser(req);
    return next();
  }
  return res.redirect('/login');
}

function ensureAdmin(req, res, next) {
  const user = currentUser(req);
  if (user && user.role === 'admin') return next();
  return res.status(403).send('<h1>403 Forbidden</h1><p>You do not have permission to access this page.</p>');
}

function isAdmin(req) {
  const user = currentUser(req);
  return user && user.role === 'admin';
}

function getRoutePrefix(req) {
  return isAdmin(req) ? '/admin' : '/user';
}

function findOrCreateGoogleUser(profile) {
  let user = findUserByGoogleId(profile.id) || findUserByEmail(profile.emails?.[0]?.value);

  if (!user) {
    user = {
      id: generateId(),
      displayName: profile.displayName || profile.username || 'Google User',
      email: profile.emails?.[0]?.value || `user-${profile.id}@google.local`,
      role: 'user',
      provider: 'google',
      googleId: profile.id,
      createdAt: new Date().toISOString()
    };
    data.users.push(user);
    writeData(data);
    audit('user_created', `Google user registered: [REDACTED_EMAIL]`, { ip: 'system' }, user.id);
  } else if (!user.googleId) {
    user.googleId = profile.id;
    writeData(data);
  }

  return user;
}

if (GOOGLE_AUTH_ENABLED) {
  passport.use(new GoogleStrategy({
      clientID: GOOGLE_CLIENT_ID,
      clientSecret: GOOGLE_CLIENT_SECRET,
      callbackURL: '/auth/google/callback'
    },
    function(accessToken, refreshToken, profile, done) {
      const user = findOrCreateGoogleUser(profile);
      audit('login_success', `Google login succeeded`, { ip: 'system' }, user.id);
      return done(null, user);
    }
  ));
}

passport.serializeUser(function(user, done) {
  done(null, user);
});

passport.deserializeUser(function(user, done) {
  done(null, user);
});

// Security Headers and HTTPS Enforcement (OWASP A6)
app.use((req, res, next) => {
  // Enforce HTTPS in production
  if (process.env.NODE_ENV === 'production' && !req.secure && req.get('x-forwarded-proto') !== 'https') {
    return res.redirect('https://' + req.get('host') + req.url);
  }
  
  // Security headers
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; img-src 'self' https:; font-src 'self' https://cdnjs.cloudflare.com");
  
  next();
});

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
const sessionSecure = process.env.HTTPS === 'true' || process.env.NODE_ENV === 'production';
const SESSION_TIMEOUT = (parseInt(process.env.SESSION_TIMEOUT_MINS, 10) || 30) * 60 * 1000; // minutes -> ms

app.use(session({ 
  secret: SESSION_SECRET || 'change-this-in-production', 
  resave: false, 
  saveUninitialized: false,
  rolling: true,
  cookie: { secure: sessionSecure, httpOnly: true, sameSite: 'lax', maxAge: SESSION_TIMEOUT }
}));
app.use(passport.initialize());
app.use(passport.session());
app.use((req, res, next) => {
  if (!req.user && req.session?.localUser) {
    req.user = req.session.localUser;
  }
  next();
});

// CSRF protection: protects all state-changing routes. Tokens will be injected into forms below.
const csrfProtection = csurf();
app.use(csrfProtection);

app.get('/', (req, res) => {
  const user = currentUser(req);
  if (!user) {
    // Landing page for non-authenticated users
    res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>StayHub - Book Your Perfect Stay</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          
          .navbar { background: white; padding: 16px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
          .navbar-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
          .logo { font-size: 1.8rem; font-weight: bold; color: #e74c3c; }
          .nav-links { display: flex; gap: 20px; }
          .nav-links a { text-decoration: none; color: #333; font-weight: 500; }
          .nav-links a:hover { color: #e74c3c; }
          .auth-buttons { display: flex; gap: 12px; }
          .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; }
          .btn-primary { background: #e74c3c; color: white; }
          .btn-outline { background: transparent; color: #e74c3c; border: 2px solid #e74c3c; }
          .btn:hover { opacity: 0.9; }
          
          .hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 80px 20px; text-align: center; }
          .hero h1 { font-size: 3.5rem; margin-bottom: 20px; }
          .hero p { font-size: 1.3rem; margin-bottom: 40px; opacity: 0.9; }
          
          .search-container { max-width: 900px; margin: -50px auto 0; position: relative; z-index: 10; padding: 0 20px; }
          .search-box { background: white; padding: 30px; border-radius: 16px; box-shadow: 0 20px 50px rgba(0,0,0,0.15); }
          .search-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
          .search-field { display: flex; flex-direction: column; }
          .search-field label { font-size: 0.9rem; color: #666; margin-bottom: 8px; font-weight: 600; }
          .search-field input { padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; }
          .search-btn { background: #e74c3c; color: white; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1rem; width: 100%; }
          
          .featured { max-width: 1200px; margin: 80px auto; padding: 0 20px; }
          .section-title { font-size: 2.2rem; margin-bottom: 10px; color: #333; }
          .section-subtitle { color: #666; margin-bottom: 40px; }
          
          .properties-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; }
          .property-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s; cursor: pointer; }
          .property-card:hover { transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.15); }
          .property-image { height: 200px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 3rem; }
          .property-content { padding: 20px; }
          .property-name { font-size: 1.2rem; font-weight: bold; color: #333; margin-bottom: 8px; }
          .property-location { color: #666; margin-bottom: 12px; }
          .property-rating { color: #f39c12; margin-bottom: 12px; }
          .property-price { font-size: 1.5rem; font-weight: bold; color: #e74c3c; }
          
          .footer { background: #2c3e50; color: white; padding: 40px 20px; text-align: center; margin-top: 60px; }
          
          @media (max-width: 768px) {
            .hero h1 { font-size: 2rem; }
            .search-grid { grid-template-columns: 1fr; }
          }
        </style>
      </head>
      <body>
        <nav class="navbar">
          <div class="navbar-content">
            <div class="logo"><i class="fas fa-home"></i> StayHub</div>
            <div class="nav-links">
              <a href="/">Homes</a>
              <a href="#about">Become a Host</a>
              <a href="#contact">Help</a>
            </div>
            <div class="auth-buttons">
              <a href="/login" class="btn btn-outline">Sign In</a>
              <a href="/register" class="btn btn-primary">Sign Up</a>
            </div>
          </div>
        </nav>

        <div class="hero" style="background: linear-gradient(rgba(0,0,0,0.3), rgba(0,0,0,0.3)), url('https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=1200&h=400&fit=crop') center/cover; min-height: 500px;">
          <h1>Find Your Perfect Stay</h1>
          <p>Discover unique properties and book your next adventure</p>
        </div>

        <div class="search-container">
          <div class="search-box">
            <form method="GET" action="/search">
              <div class="search-grid">
                <div class="search-field">
                  <label for="location">Where to?</label>
                  <input type="text" id="location" name="location" placeholder="City or location">
                </div>
                <div class="search-field">
                  <label for="checkin">Check In</label>
                  <input type="date" id="checkin" name="checkin">
                </div>
                <div class="search-field">
                  <label for="checkout">Check Out</label>
                  <input type="date" id="checkout" name="checkout">
                </div>
              </div>
              <button type="submit" class="search-btn"><i class="fas fa-search"></i> Search Stays</button>
            </form>
          </div>
        </div>

        <div class="featured">
          <h2 class="section-title">Featured Properties</h2>
          <p class="section-subtitle">Discover hand-picked properties from our trusted hosts</p>
          <div class="properties-grid">
            <div class="property-card">
              <div class="property-image"><i class="fas fa-tree"></i></div>
              <div class="property-content">
                <div class="property-name">Mountain Cabin Retreat</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> Colorado, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 4.9 (234 reviews)</div>
                <div class="property-price">$299 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
            <div class="property-card">
              <div class="property-image"><i class="fas fa-city"></i></div>
              <div class="property-content">
                <div class="property-name">Urban Loft</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> New York, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 4.8 (512 reviews)</div>
                <div class="property-price">$199 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
            <div class="property-card">
              <div class="property-image"><i class="fas fa-water"></i></div>
              <div class="property-content">
                <div class="property-name">Beach Villa</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> Malibu, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 5.0 (189 reviews)</div>
                <div class="property-price">$499 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
          </div>
        </div>

        <div class="footer">
          <p>&copy; 2024 StayHub. All rights reserved. | <a href="#" style="color: #3498db;">Privacy</a> | <a href="#" style="color: #3498db;">Terms</a></p>
        </div>
      </body>
      </html>
    `);
  } else {
    return res.redirect(user.role === 'admin' ? '/admin' : '/user');
  }
});

app.get('/admin', ensureAuthenticated, ensureAdmin, (req, res) => {
  const user = currentUser(req);
  const properties = (data.properties || []);
  const bookings = (data.bookings || []);
  const activeBookings = bookings.filter((b) => !b.completed).length;
  const recentLogs = data.auditLogs.slice(0, 5);

  res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Admin Dashboard - StayHub</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          
          .navbar { background: white; padding: 16px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
          .navbar-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
          .logo { font-size: 1.8rem; font-weight: bold; color: #e74c3c; }
          .nav-links { display: flex; gap: 20px; }
          .nav-links a { text-decoration: none; color: #333; font-weight: 500; }
          .nav-links a:hover { color: #e74c3c; }
          .auth-buttons { display: flex; gap: 12px; align-items: center; }
          .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; }
          .btn-primary { background: #e74c3c; color: white; }
          .btn-outline { background: transparent; color: #e74c3c; border: 2px solid #e74c3c; }
          .btn:hover { opacity: 0.9; }
          .user-avatar { width: 40px; height: 40px; border-radius: 50%; background: #e74c3c; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
          
          .hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 80px 20px; text-align: center; }
          .hero h1 { font-size: 3.5rem; margin-bottom: 20px; }
          .hero p { font-size: 1.3rem; margin-bottom: 40px; opacity: 0.9; }
          
          .search-container { max-width: 900px; margin: -50px auto 0; position: relative; z-index: 10; padding: 0 20px; }
          .search-box { background: white; padding: 30px; border-radius: 16px; box-shadow: 0 20px 50px rgba(0,0,0,0.15); }
          .search-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
          .search-field { display: flex; flex-direction: column; }
          .search-field label { font-size: 0.9rem; color: #666; margin-bottom: 8px; font-weight: 600; }
          .search-field input { padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; }
          .search-btn { background: #e74c3c; color: white; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1rem; width: 100%; }
          
          .featured { max-width: 1200px; margin: 80px auto; padding: 0 20px; }
          .section-title { font-size: 2.2rem; margin-bottom: 10px; color: #333; }
          .section-subtitle { color: #666; margin-bottom: 40px; }
          
          .properties-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; }
          .property-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s; cursor: pointer; }
          .property-card:hover { transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.15); }
          .property-image { height: 200px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 3rem; }
          .property-content { padding: 20px; }
          .property-name { font-size: 1.2rem; font-weight: bold; color: #333; margin-bottom: 8px; }
          .property-location { color: #666; margin-bottom: 12px; }
          .property-rating { color: #f39c12; margin-bottom: 12px; }
          .property-price { font-size: 1.5rem; font-weight: bold; color: #e74c3c; }
          
          .footer { background: #2c3e50; color: white; padding: 40px 20px; text-align: center; margin-top: 60px; }
          
          @media (max-width: 768px) {
            .hero h1 { font-size: 2rem; }
            .search-grid { grid-template-columns: 1fr; }
            .navbar-content { flex-wrap: wrap; }
            .nav-links { width: 100%; justify-content: center; }
          }
        </style>
      </head>
      <body>
        <nav class="navbar">
          <div class="navbar-content">
            <div class="logo"><i class="fas fa-home"></i> StayHub Admin</div>
            <div class="nav-links">
              <a href="/admin"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
              <a href="/admin/properties"><i class="fas fa-building"></i> Properties</a>
              <a href="/admin/bookings"><i class="fas fa-calendar-check"></i> Bookings</a>
              <a href="/admin/audit"><i class="fas fa-clipboard-list"></i> Audit Log</a>
            </div>
            <div class="auth-buttons">
              <div class="user-avatar">${user.displayName.charAt(0).toUpperCase()}</div>
              <a href="/profile" class="btn btn-outline"><i class="fas fa-user"></i></a>
              <a href="/logout" class="btn btn-primary">Logout</a>
            </div>
          </div>
        </nav>

        <div class="hero" style="background: linear-gradient(rgba(0,0,0,0.3), rgba(0,0,0,0.3)), url('https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=1200&h=400&fit=crop') center/cover; min-height: 500px;">
          <h1>Admin Dashboard</h1>
          <p>Welcome back, ${escapeHtml(user.displayName)}! Manage your properties and bookings</p>
        </div>

        <div class="search-container">
          <div class="search-box">
            <form method="GET" action="/admin/search">
              <div class="search-grid">
                <div class="search-field">
                  <label for="location">Filter by Location</label>
                  <input type="text" id="location" name="location" placeholder="City or location">
                </div>
                <div class="search-field">
                  <label for="checkin">From Date</label>
                  <input type="date" id="checkin" name="checkin">
                </div>
                <div class="search-field">
                  <label for="checkout">To Date</label>
                  <input type="date" id="checkout" name="checkout">
                </div>
              </div>
              <button type="submit" class="search-btn"><i class="fas fa-search"></i> Search Properties</button>
            </form>
          </div>
        </div>

        <div class="featured">
          <h2 class="section-title">Your Properties</h2>
          <p class="section-subtitle">Manage your ${properties.length} listed properties</p>
          <div class="properties-grid">
            ${properties.length > 0 ? properties.map((prop) => `
              <div class="property-card">
                <div class="property-image"><i class="fas fa-building"></i></div>
                <div class="property-content">
                  <div class="property-name">${escapeHtml(prop.name)}</div>
                  <div class="property-location"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(prop.location)}</div>
                  <div class="property-rating"><i class="fas fa-home"></i> Type: ${escapeHtml(prop.type)}</div>
                  <div class="property-price">$${prop.pricePerNight} <span style="font-size: 0.9rem; color: #666;">/night</span></div>
                </div>
              </div>
            `).join('') : '<p style="grid-column: 1/-1; text-align: center; color: #666; padding: 40px;">No properties listed yet. <a href="/admin/properties" style="color: #e74c3c; text-decoration: none;">Add your first property</a></p>'}
          </div>
        </div>

        <div class="footer">
          <p>&copy; 2024 StayHub Admin. All rights reserved.</p>
        </div>
      </body>
      </html>
    `);
});

app.get('/user', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const bookings = (data.bookings || []).filter((b) => b.guestId === user.id);
  const activeBookings = bookings.filter((b) => !b.completed).length;

  res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>My Bookings - StayHub</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          
          .navbar { background: white; padding: 16px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.1); position: sticky; top: 0; z-index: 100; }
          .navbar-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
          .logo { font-size: 1.8rem; font-weight: bold; color: #e74c3c; }
          .nav-links { display: flex; gap: 20px; }
          .nav-links a { text-decoration: none; color: #333; font-weight: 500; }
          .nav-links a:hover { color: #e74c3c; }
          .auth-buttons { display: flex; gap: 12px; align-items: center; }
          .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; }
          .btn-primary { background: #e74c3c; color: white; }
          .btn-outline { background: transparent; color: #e74c3c; border: 2px solid #e74c3c; }
          .btn:hover { opacity: 0.9; }
          .user-avatar { width: 40px; height: 40px; border-radius: 50%; background: #e74c3c; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; }
          
          .hero { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 80px 20px; text-align: center; }
          .hero h1 { font-size: 3.5rem; margin-bottom: 20px; }
          .hero p { font-size: 1.3rem; margin-bottom: 40px; opacity: 0.9; }
          
          .search-container { max-width: 900px; margin: -50px auto 0; position: relative; z-index: 10; padding: 0 20px; }
          .search-box { background: white; padding: 30px; border-radius: 16px; box-shadow: 0 20px 50px rgba(0,0,0,0.15); }
          .search-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 20px; }
          .search-field { display: flex; flex-direction: column; }
          .search-field label { font-size: 0.9rem; color: #666; margin-bottom: 8px; font-weight: 600; }
          .search-field input { padding: 12px; border: 1px solid #ddd; border-radius: 8px; font-size: 1rem; }
          .search-btn { background: #e74c3c; color: white; padding: 12px 30px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 1rem; width: 100%; }
          
          .featured { max-width: 1200px; margin: 80px auto; padding: 0 20px; }
          .section-title { font-size: 2.2rem; margin-bottom: 10px; color: #333; }
          .section-subtitle { color: #666; margin-bottom: 40px; }
          
          .properties-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 30px; }
          .property-card { background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 5px 20px rgba(0,0,0,0.1); transition: transform 0.3s, box-shadow 0.3s; cursor: pointer; }
          .property-card:hover { transform: translateY(-5px); box-shadow: 0 15px 40px rgba(0,0,0,0.15); }
          .property-image { height: 200px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); display: flex; align-items: center; justify-content: center; color: white; font-size: 3rem; }
          .property-content { padding: 20px; }
          .property-name { font-size: 1.2rem; font-weight: bold; color: #333; margin-bottom: 8px; }
          .property-location { color: #666; margin-bottom: 12px; }
          .property-rating { color: #f39c12; margin-bottom: 12px; }
          .property-price { font-size: 1.5rem; font-weight: bold; color: #e74c3c; }
          
          .footer { background: #2c3e50; color: white; padding: 40px 20px; text-align: center; margin-top: 60px; }
          
          @media (max-width: 768px) {
            .hero h1 { font-size: 2rem; }
            .search-grid { grid-template-columns: 1fr; }
            .navbar-content { flex-wrap: wrap; }
            .nav-links { width: 100%; justify-content: center; }
          }
        </style>
      </head>
      <body>
        <nav class="navbar">
          <div class="navbar-content">
            <div class="logo"><i class="fas fa-home"></i> StayHub</div>
            <div class="nav-links">
              <a href="/user"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
              <a href="/properties"><i class="fas fa-bed"></i> Browse Stays</a>
              <a href="/user/bookings"><i class="fas fa-calendar-check"></i> My Bookings</a>
            </div>
            <div class="auth-buttons">
              <div class="user-avatar">${user.displayName.charAt(0).toUpperCase()}</div>
              <a href="/profile" class="btn btn-outline"><i class="fas fa-user"></i></a>
              <a href="/logout" class="btn btn-primary">Logout</a>
            </div>
          </div>
        </nav>

        <div class="hero" style="background: linear-gradient(rgba(0,0,0,0.3), rgba(0,0,0,0.3)), url('https://images.unsplash.com/photo-1631049307264-da0ec9d70304?w=1200&h=400&fit=crop') center/cover; min-height: 500px;">
          <h1>Explore Amazing Stays</h1>
          <p>Welcome back, ${escapeHtml(user.displayName)}! Find your next perfect destination</p>
        </div>

        <div class="search-container">
          <div class="search-box">
            <form method="GET" action="/search">
              <div class="search-grid">
                <div class="search-field">
                  <label for="location">Where to?</label>
                  <input type="text" id="location" name="location" placeholder="City or location">
                </div>
                <div class="search-field">
                  <label for="checkin">Check In</label>
                  <input type="date" id="checkin" name="checkin">
                </div>
                <div class="search-field">
                  <label for="checkout">Check Out</label>
                  <input type="date" id="checkout" name="checkout">
                </div>
              </div>
              <button type="submit" class="search-btn"><i class="fas fa-search"></i> Search Stays</button>
            </form>
          </div>
        </div>

        <div class="featured">
          <h2 class="section-title">Featured Properties</h2>
          <p class="section-subtitle">Discover hand-picked properties from our trusted hosts</p>
          <div class="properties-grid">
            <div class="property-card">
              <div class="property-image"><i class="fas fa-tree"></i></div>
              <div class="property-content">
                <div class="property-name">Mountain Cabin Retreat</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> Colorado, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 4.9 (234 reviews)</div>
                <div class="property-price">$299 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
            <div class="property-card">
              <div class="property-image"><i class="fas fa-city"></i></div>
              <div class="property-content">
                <div class="property-name">Urban Loft</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> New York, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 4.8 (512 reviews)</div>
                <div class="property-price">$199 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
            <div class="property-card">
              <div class="property-image"><i class="fas fa-water"></i></div>
              <div class="property-content">
                <div class="property-name">Beach Villa</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> Malibu, USA</div>
                <div class="property-rating"><i class="fas fa-star"></i> 5.0 (189 reviews)</div>
                <div class="property-price">$499 <span style="font-size: 0.9rem; color: #666;">/night</span></div>
              </div>
            </div>
          </div>
        </div>

        <div class="footer">
          <p>&copy; 2024 StayHub. All rights reserved.</p>
        </div>
      </body>
      </html>
    `);
});

app.get('/login', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  const error = escapeHtml(req.query.error || '');
  const success = escapeHtml(req.query.success || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Sign In - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: linear-gradient(135deg, rgba(102, 126, 234, 0.95) 0%, rgba(118, 75, 162, 0.95) 100%), url('https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800&fit=crop') center/cover; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 2.5rem 2.2rem; width: 100%; max-width: 420px; }
        .login-header { text-align: center; margin-bottom: 1.8rem; }
        .login-logo { font-size: 2.5rem; color: #e74c3c; margin-bottom: 10px; }
        .login-header h1 { margin: 0 0 0.5rem 0; font-size: 1.8rem; color: #333; }
        .login-header p { color: #666; margin: 0; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px 14px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; }
        .btn-primary { width: 100%; background: #e74c3c; color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .btn-primary:hover { background: #c0392b; }
        .google-btn { display: inline-flex; align-items: center; justify-content: center; gap: 10px; width: 100%; padding: 12px; border-radius: 8px; background: #4285f4; color: white; text-decoration: none; margin-top: 1rem; font-weight: 600; }
        .google-btn:hover { background: #357ae8; }
        .error { color: #c82333; margin-bottom: 1rem; text-align: center; padding: 12px; background: #f8d7da; border-radius: 8px; }
        .success { color: #155724; margin-bottom: 1rem; text-align: center; padding: 12px; background: #d4edda; border-radius: 8px; }
        .footer { text-align: center; margin-top: 1.4rem; color: #666; }
        .footer a { color: #e74c3c; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="login-header">
          <div class="login-logo"><i class="fas fa-home"></i></div>
          <h1>Welcome to StayHub</h1>
          <p>Sign in to your account</p>
        </div>
        ${success ? `<div class="success"><i class="fas fa-check-circle"></i> ${success}</div>` : ''}
        ${error ? `<div class="error"><i class="fas fa-exclamation-circle"></i> ${error}</div>` : ''}
        <form method="POST" action="/login">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">
          <div class="form-group"><label for="email">Email Address</label><input type="email" id="email" name="email" required></div>
          <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
          <button type="submit" class="btn-primary">Sign In (User)</button>
        </form>
        <div class="footer"><a href="/forgot-password">Forgot Password?</a> | Admin? <a href="/admin/login" style="color:#e74c3c; font-weight:700;">Admin login</a></div>
        
        ${GOOGLE_AUTH_ENABLED ? `<a href="/auth/google" class="google-btn"><i class="fab fa-google"></i> Continue with Google</a>` : ''}
        <div class="footer">Don't have an account? <a href="/register">Create one</a></div>
      </div>
    </body>
    </html>
  `);
});

app.get('/admin/login', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  const error = escapeHtml(req.query.error || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Admin Sign In - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: linear-gradient(135deg, rgba(102, 126, 234, 0.95) 0%, rgba(118, 75, 162, 0.95) 100%), url('https://images.unsplash.com/photo-1522708323590-d24dbb6b0267?w=800&fit=crop') center/cover; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .login-container { background: white; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,0.3); padding: 2.5rem 2.2rem; width: 100%; max-width: 420px; }
        .login-header { text-align: center; margin-bottom: 1.8rem; }
        .login-logo { font-size: 2.5rem; color: #e74c3c; margin-bottom: 10px; }
        .login-header h1 { margin: 0 0 0.5rem 0; font-size: 1.8rem; color: #333; }
        .login-header p { color: #666; margin: 0; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px 14px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; }
        .btn-primary { width: 100%; background: #e74c3c; color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .btn-primary:hover { background: #c0392b; }
        .error { color: #c82333; margin-bottom: 1rem; text-align: center; padding: 12px; background: #f8d7da; border-radius: 8px; }
        .footer { text-align: center; margin-top: 1.4rem; color: #666; }
        .footer a { color: #e74c3c; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="login-container">
        <div class="login-header">
          <div class="login-logo"><i class="fas fa-shield-alt"></i></div>
          <h1>Admin Sign In</h1>
          <p>Access the admin dashboard</p>
        </div>
        ${error ? `<div class="error"><i class="fas fa-exclamation-circle"></i> ${error}</div>` : ''}
        <form method="POST" action="/admin/login">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">
          <div class="form-group"><label for="email">Email Address</label><input type="email" id="email" name="email" required></div>
          <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
          <button type="submit" class="btn-primary">Sign In (Admin)</button>
        </form>
        <div class="footer">Back to <a href="/login">user login</a></div>
      </div>
    </body>
    </html>
  `);
});

app.post('/login', (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);

  if (!user || !verifyAndUpgradePassword(user, password)) {
    audit('login_failed', `Local login failed`, req, user?.id || null);
    return res.redirect('/login?error=Invalid email or password.');
  }

  // If an admin tries to use the normal user login, block it.
  if (user.role === 'admin') {
    audit('login_failed', `Admin attempted to log in via /login`, req, user.id);
    return res.redirect('/login?error=Use the admin dashboard login instead.');
  }

  req.session.localUser = user;
  req.user = user;
  audit('login_success', `Local login succeeded`, req, user.id);
  res.redirect('/');
});

// Admin login uses the same login page, but posts to /admin/login
app.post('/admin/login', (req, res) => {
  const { email, password } = req.body;
  const user = findUserByEmail(email);

  if (!user || !verifyAndUpgradePassword(user, password) || user.role !== 'admin') {
    audit('login_failed', `Admin login failed`, req, user?.id || null);
    return res.redirect('/login?error=Invalid admin email or password.');
  }

  req.session.localUser = user;
  req.user = user;
  audit('login_success', `Admin local login succeeded`, req, user.id);
  res.redirect('/admin');
});

app.get('/register', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  const error = escapeHtml(req.query.error || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Create Account - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: linear-gradient(135deg, rgba(247, 247, 247, 0.95) 0%, rgba(227, 234, 252, 0.95) 100%), url('https://images.unsplash.com/photo-1566073771259-6a8506099945?w=800&fit=crop') center/cover; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .register-container { width: 100%; max-width: 460px; background: white; border-radius: 16px; padding: 2.5rem; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
        .register-header { margin-bottom: 1.8rem; }
        .register-logo { font-size: 2.5rem; color: #e74c3c; text-align: center; margin-bottom: 10px; }
        .register-header h1 { font-size: 1.8rem; color: #333; margin: 0 0 0.5rem 0; }
        .register-header p { color: #666; margin: 0; }
        .form-group { margin-bottom: 1.1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px 14px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; }
        .btn-primary { width: 100%; background: #e74c3c; color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .btn-primary:hover { background: #c0392b; }
        .error { color: #c82333; margin-bottom: 1rem; padding: 12px; background: #f8d7da; border-radius: 8px; text-align: center; }
        .footer { text-align: center; margin-top: 1.4rem; color: #666; }
        .footer a { color: #e74c3c; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="register-container">
        <div class="register-header">
          <div class="register-logo"><i class="fas fa-home"></i></div>
          <h1>Join StayHub</h1>
          <p>Create your account to start exploring amazing stays</p>
        </div>
        ${error ? `<div class="error"><i class="fas fa-exclamation-circle"></i> ${error}</div>` : ''}
        <form method="POST" action="/register">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">
          <div class="form-group"><label for="displayName">Full Name</label><input type="text" id="displayName" name="displayName" required></div>
          <div class="form-group"><label for="email">Email Address</label><input type="email" id="email" name="email" required></div>
          <div class="form-group"><label for="password">Password</label><input type="password" id="password" name="password" required></div>
          <button type="submit" class="btn-primary">Create Account</button>
        </form>
        <div class="footer">Already have an account? <a href="/login">Sign In</a></div>
      </div>
    </body>
    </html>
  `);
});

app.post('/register', (req, res) => {
  const { displayName, email, password } = req.body;
  if (!displayName || !email || !password) {
    return res.redirect('/register?error=Please complete all fields.');
  }

  if (findUserByEmail(email)) {
    return res.redirect('/register?error=Email is already registered.');
  }

  // Password strength policy: minimum 12 chars, at least one upper, one lower, one digit, one special
  const passwordPolicy = /^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).*$/;
  if (!passwordPolicy.test(password)) {
    return res.redirect('/register?error=Password must be at least 12 characters and include upper, lower, number, and symbol.');
  }

  const user = {
    id: generateId(),
    displayName: displayName.trim(),
    email: email.trim().toLowerCase(),
    passwordHash: hashPassword(password),
    role: 'user',
    provider: 'local',
    createdAt: new Date().toISOString()
  };

  data.users.push(user);
  writeData(data);
  req.session.localUser = user;
  req.user = user;
  audit('user_created', `Local user registered`, req, user.id);
  res.redirect('/');
});

// Forgot Password Route
app.get('/forgot-password', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  const error = escapeHtml(req.query.error || '');
  const success = escapeHtml(req.query.success || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Forgot Password - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: linear-gradient(135deg, rgba(247, 247, 247, 0.95) 0%, rgba(227, 234, 252, 0.95) 100%), url('https://images.unsplash.com/photo-1566073771259-6a8506099945?w=800&fit=crop') center/cover; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .reset-container { width: 100%; max-width: 460px; background: white; border-radius: 16px; padding: 2.5rem; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
        .reset-header { margin-bottom: 1.8rem; }
        .reset-logo { font-size: 2.5rem; color: #e74c3c; text-align: center; margin-bottom: 10px; }
        .reset-header h1 { font-size: 1.8rem; color: #333; margin: 0 0 0.5rem 0; }
        .reset-header p { color: #666; margin: 0; }
        .form-group { margin-bottom: 1.1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px 14px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; }
        .btn-primary { width: 100%; background: #e74c3c; color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; }
        .btn-primary:hover { background: #c0392b; }
        .error { color: #c82333; margin-bottom: 1rem; padding: 12px; background: #f8d7da; border-radius: 8px; text-align: center; }
        .success { color: #155724; margin-bottom: 1rem; padding: 12px; background: #d4edda; border-radius: 8px; text-align: center; }
        .footer { text-align: center; margin-top: 1.4rem; color: #666; }
        .footer a { color: #e74c3c; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="reset-container">
        <div class="reset-header">
          <div class="reset-logo"><i class="fas fa-key"></i></div>
          <h1>Forgot Password</h1>
          <p>Enter your email to receive a password reset link</p>
        </div>
        ${error ? '<div class="error"><i class="fas fa-exclamation-circle"></i> ' + error + '</div>' : ''}
        ${success ? '<div class="success"><i class="fas fa-check-circle"></i> ' + success + '</div>' : ''}
        <form method="POST" action="/forgot-password">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">
          <div class="form-group"><label for="email">Email Address</label><input type="email" id="email" name="email" required></div>
          <button type="submit" class="btn-primary">Send Reset Link</button>
        </form>
        <div class="footer">Remember your password? <a href="/login">Sign in</a></div>
      </div>
    </body>
    </html>
  `);
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;
  if (!email) {
    return res.redirect('/forgot-password?error=Please enter your email address.');
  }

  const user = findUserByEmail(email);
  if (!user) {
    // For security, don't reveal if email exists or not
    return res.redirect('/forgot-password?success=If an account exists with this email, a reset link has been sent.');
  }

  // Only allow password reset for local users (not Google OAuth users)
  if (user.provider === 'google') {
    return res.redirect('/forgot-password?error=This account uses Google login. Please use the Google login option.');
  }

  const resetToken = setResetToken(user);
  const resetLink = `http://localhost:3000/reset-password?token=${resetToken}`;
  
  audit('password_reset_requested', `Password reset requested for user`, req, user.id);
  console.log(`📧 Password reset link for ${user.email}: ${resetLink}`);
  
  // In production, send this link via email. For demo purposes, we log it.
  res.redirect('/forgot-password?success=If an account exists with this email, a reset link has been sent.');
});

// Reset Password Route
app.get('/reset-password', (req, res) => {
  if (currentUser(req)) return res.redirect('/');
  
  const { token } = req.query;
  if (!token) {
    return res.redirect('/login?error=Invalid or expired reset link.');
  }

  const user = findUserByResetToken(token);
  if (!user) {
    return res.redirect('/login?error=Invalid or expired reset link.');
  }

  const error = escapeHtml(req.query.error || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Reset Password - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: linear-gradient(135deg, rgba(247, 247, 247, 0.95) 0%, rgba(227, 234, 252, 0.95) 100%), url('https://images.unsplash.com/photo-1566073771259-6a8506099945?w=800&fit=crop') center/cover; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; min-height: 100vh; display: flex; align-items: center; justify-content: center; }
        .reset-container { width: 100%; max-width: 460px; background: white; border-radius: 16px; padding: 2.5rem; box-shadow: 0 20px 60px rgba(0,0,0,0.15); }
        .reset-header { margin-bottom: 1.8rem; }
        .reset-logo { font-size: 2.5rem; color: #e74c3c; text-align: center; margin-bottom: 10px; }
        .reset-header h1 { font-size: 1.8rem; color: #333; margin: 0 0 0.5rem 0; }
        .reset-header p { color: #666; margin: 0; font-size: 0.95rem; }
        .form-group { margin-bottom: 1.1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; color: #555; font-weight: 500; }
        .form-group input { width: 100%; padding: 12px 14px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; }
        .password-hint { font-size: 0.85rem; color: #6b7280; margin-top: 6px; }
        .btn-primary { width: 100%; background: #e74c3c; color: white; border: none; padding: 14px; border-radius: 8px; cursor: pointer; font-size: 1rem; font-weight: 600; margin-top: 12px; }
        .btn-primary:hover { background: #c0392b; }
        .error { color: #c82333; margin-bottom: 1rem; padding: 12px; background: #f8d7da; border-radius: 8px; text-align: center; }
        .footer { text-align: center; margin-top: 1.4rem; color: #666; }
        .footer a { color: #e74c3c; text-decoration: none; font-weight: 600; }
      </style>
    </head>
    <body>
      <div class="reset-container">
        <div class="reset-header">
          <div class="reset-logo"><i class="fas fa-lock"></i></div>
          <h1>Reset Password</h1>
          <p>Enter your new password below</p>
        </div>
        ${error ? '<div class="error"><i class="fas fa-exclamation-circle"></i> ' + error + '</div>' : ''}
        <form method="POST" action="/reset-password">
          <input type="hidden" name="_csrf" value="${req.csrfToken()}">
          <input type="hidden" name="token" value="${escapeHtml(token)}">
          <div class="form-group">
            <label for="password">New Password</label>
            <input type="password" id="password" name="password" required>
            <div class="password-hint">At least 12 characters with uppercase, lowercase, number, and special character</div>
          </div>
          <div class="form-group">
            <label for="confirmPassword">Confirm Password</label>
            <input type="password" id="confirmPassword" name="confirmPassword" required>
          </div>
          <button type="submit" class="btn-primary">Reset Password</button>
        </form>
        <div class="footer">Back to <a href="/login">login</a></div>
      </div>
    </body>
    </html>
  `);
});

app.post('/reset-password', (req, res) => {
  const { token, password, confirmPassword } = req.body;
  
  if (!token) {
    return res.redirect('/login?error=Invalid reset link.');
  }

  const user = findUserByResetToken(token);
  if (!user) {
    return res.redirect('/login?error=Invalid or expired reset link.');
  }

  if (!password || !confirmPassword) {
    return res.redirect(`/reset-password?token=${token}&error=Please fill in all password fields.`);
  }

  if (password !== confirmPassword) {
    return res.redirect(`/reset-password?token=${token}&error=Passwords do not match.`);
  }

  // Password strength policy: minimum 12 chars, at least one upper, one lower, one digit, one special
  const passwordPolicy = /^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).*$/;
  if (!passwordPolicy.test(password)) {
    return res.redirect(`/reset-password?token=${token}&error=Password must be at least 12 characters and include upper, lower, number, and symbol.`);
  }

  user.passwordHash = hashPassword(password);
  clearResetToken(user);
  
  audit('password_reset_success', `Password reset completed`, req, user.id);
  res.redirect('/login?success=Password has been reset successfully. Please sign in with your new password.');
});

if (GOOGLE_AUTH_ENABLED) {
  app.get('/auth/google', function(req, res, next) {
    const codeVerifier = generateCodeVerifier();
    const codeChallenge = generateCodeChallenge(codeVerifier);
    req.session.pkce = { codeVerifier, codeChallenge };
    passport.authenticate('google', { 
      scope: ['profile', 'email'],
      state: codeChallenge
    })(req, res, next);
  });

  app.get('/auth/google/callback',
    function(req, res, next) {
      if (!req.session.pkce || req.query.state !== req.session.pkce.codeChallenge) {
        return res.status(400).send('PKCE verification failed');
      }
      delete req.session.pkce;
      next();
    },
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      req.session.localUser = req.user;
      res.redirect('/');
    }
  );
} else {
  app.get('/auth/google', (req, res) => res.redirect('/login'));
}

app.get('/tasks', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  return res.redirect(user.role === 'admin' ? '/admin/properties' : '/user/bookings');
});

app.get('/admin/properties', ensureAuthenticated, ensureAdmin, (req, res) => {
  const user = currentUser(req);
  const properties = data.properties || [];
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Properties - StayHub Admin</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; }
        .page { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2rem; color: #333; }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 20px; border-radius: 8px; border: none; background: #e74c3c; color: white; text-decoration: none; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #c0392b; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 16px; text-align: left; border-bottom: 1px solid #e9ecef; }
        th { background: #f8f9fa; color: #555; font-weight: 600; }
        td { color: #333; }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; background: #e7f1ff; color: #084298; }
        .actions a { margin-right: 12px; color: #e74c3c; text-decoration: none; font-weight: 500; }
        .actions a:hover { text-decoration: underline; }
        .empty { padding: 40px; text-align: center; color: #666; }
      </style>
    </head>
    <body>
      <div class="page">
        <div class="header">
          <div>
            <h1><i class="fas fa-building"></i> Property Management</h1>
            <p style="color:#666; margin-top:6px;">Manage all properties in the system.</p>
          </div>
          <div>
            <a href="/admin/properties/new" class="btn"><i class="fas fa-plus"></i> Add Property</a>
            <a href="/admin" class="btn" style="background:#6c757d;"><i class="fas fa-home"></i> Dashboard</a>
          </div>
        </div>
        <div class="card">
          <table>
            <thead>
              <tr><th>Property Name</th><th>Location</th><th>Price/Night</th><th>Status</th><th>Created</th><th>Actions</th></tr>
            </thead>
            <tbody>
              ${properties.length === 0 ? '<tr><td colspan="6" class="empty"><i class="fas fa-inbox"></i> No properties yet. <a href="/admin/properties/new" style="color: #e74c3c;">Create one</a></td></tr>' : properties.map((prop) => `
                <tr>
                  <td><strong>${escapeHtml(prop.name)}</strong></td>
                  <td>${escapeHtml(prop.location)}</td>
                  <td>$${prop.price}</td>
                  <td><span class="badge">${prop.active ? 'Active' : 'Inactive'}</span></td>
                  <td>${new Date(prop.createdAt).toLocaleDateString()}</td>
                  <td class="actions">
                    <a href="/admin/properties/${prop.id}/edit">Edit</a>
                    <form method="POST" action="/admin/properties/${prop.id}/delete" style="display:inline; margin:0; padding:0;">
                      <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                      <button type="submit" style="background:none;border:none;color:#dc3545;cursor:pointer;font:inherit;padding:0;text-decoration:underline;">Delete</button>
                    </form>
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/admin/bookings', ensureAuthenticated, ensureAdmin, (req, res) => {
  const user = currentUser(req);
  const bookings = data.bookings || [];
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Bookings - StayHub Admin</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; }
        .page { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2rem; color: #333; }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 20px; border-radius: 8px; border: none; background: #e74c3c; color: white; text-decoration: none; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #c0392b; }
        .card { background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        table { width: 100%; border-collapse: collapse; }
        th, td { padding: 16px; text-align: left; border-bottom: 1px solid #e9ecef; }
        th { background: #f8f9fa; color: #555; font-weight: 600; }
        td { color: #333; }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; }
        .badge.active { background: #d4edda; color: #155724; }
        .badge.completed { background: #cfe2ff; color: #084298; }
        .empty { padding: 40px; text-align: center; color: #666; }
      </style>
    </head>
    <body>
      <div class="page">
        <div class="header">
          <div>
            <h1><i class="fas fa-calendar-check"></i> All Bookings</h1>
            <p style="color:#666; margin-top:6px;">Monitor and manage guest bookings.</p>
          </div>
          <a href="/admin" class="btn" style="background:#6c757d;"><i class="fas fa-home"></i> Dashboard</a>
        </div>
        <div class="card">
          <table>
            <thead>
              <tr><th>Guest</th><th>Property</th><th>Check In</th><th>Check Out</th><th>Status</th><th>Total</th></tr>
            </thead>
            <tbody>
              ${bookings.length === 0 ? '<tr><td colspan="6" class="empty"><i class="fas fa-inbox"></i> No bookings yet</td></tr>' : bookings.map((booking) => `
                <tr>
                  <td>${escapeHtml(booking.guestName)}</td>
                  <td>${escapeHtml(booking.propertyName)}</td>
                  <td>${new Date(booking.checkIn).toLocaleDateString()}</td>
                  <td>${new Date(booking.checkOut).toLocaleDateString()}</td>
                  <td><span class="badge ${booking.completed ? 'completed' : 'active'}">${booking.completed ? 'Completed' : 'Active'}</span></td>
                  <td>$${booking.totalPrice}</td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/user/bookings', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const bookings = (data.bookings || []).filter((b) => b.guestId === user.id);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>My Bookings - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; }
        .page { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2rem; color: #333; }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 20px; border-radius: 8px; border: none; background: #e74c3c; color: white; text-decoration: none; font-weight: 600; cursor: pointer; }
        .btn:hover { background: #c0392b; }
        .bookings-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px; }
        .booking-card { background: white; border-radius: 12px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); overflow: hidden; }
        .booking-header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; }
        .booking-title { font-size: 1.3rem; font-weight: bold; margin: 0; }
        .booking-subtitle { opacity: 0.9; margin: 5px 0 0 0; }
        .booking-body { padding: 20px; }
        .booking-detail { display: flex; justify-content: space-between; align-items: center; margin-bottom: 15px; padding-bottom: 15px; border-bottom: 1px solid #e9ecef; }
        .booking-detail:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
        .detail-label { color: #666; font-size: 0.9rem; }
        .detail-value { font-weight: 600; color: #333; }
        .status-badge { display: inline-block; padding: 6px 12px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; }
        .status-active { background: #d4edda; color: #155724; }
        .status-completed { background: #cfe2ff; color: #084298; }
        .empty { padding: 60px 20px; text-align: center; color: #666; }
      </style>
    </head>
    <body>
      <div class="page">
        <div class="header">
          <div>
            <h1><i class="fas fa-calendar-check"></i> My Bookings</h1>
            <p style="color:#666; margin-top:6px;">View and manage your reservations.</p>
          </div>
          <a href="/user" class="btn" style="background:#6c757d;"><i class="fas fa-home"></i> Back to Dashboard</a>
        </div>
        <div class="bookings-grid">
          ${bookings.length === 0 ? '<div style="grid-column: 1/-1; text-align: center; padding: 60px 20px; color: #666;"><i class="fas fa-inbox" style="font-size: 3rem; margin-bottom: 20px; opacity: 0.5;"></i><p>You don\'t have any bookings yet.</p></div>' : bookings.map((booking) => `
            <div class="booking-card">
              <div class="booking-header">
                <h3 class="booking-title">${escapeHtml(booking.propertyName)}</h3>
                <p class="booking-subtitle"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(booking.propertyLocation)}</p>
              </div>
              <div class="booking-body">
                <div class="booking-detail">
                  <span class="detail-label"><i class="fas fa-calendar-alt"></i> Check In</span>
                  <span class="detail-value">${new Date(booking.checkIn).toLocaleDateString()}</span>
                </div>
                <div class="booking-detail">
                  <span class="detail-label"><i class="fas fa-calendar-alt"></i> Check Out</span>
                  <span class="detail-value">${new Date(booking.checkOut).toLocaleDateString()}</span>
                </div>
                <div class="booking-detail">
                  <span class="detail-label"><i class="fas fa-user"></i> Guests</span>
                  <span class="detail-value">${booking.guests}</span>
                </div>
                <div class="booking-detail">
                  <span class="detail-label"><i class="fas fa-dollar-sign"></i> Total</span>
                  <span class="detail-value">$${booking.totalPrice}</span>
                </div>
                <div class="booking-detail">
                  <span class="detail-label">Status</span>
                  <span class="status-badge ${booking.completed ? 'status-completed' : 'status-active'}">${booking.completed ? 'Completed' : 'Confirmed'}</span>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/properties', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const searchQuery = (req.query.location || '').trim().toLowerCase();
  const properties = (data.properties || []).filter((property) => {
    if (!property.active) return false;
    if (!searchQuery) return true;
    return property.location.toLowerCase().includes(searchQuery) || property.name.toLowerCase().includes(searchQuery);
  });

  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Browse Stays - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f6f8; }
        .navbar { background: white; padding: 16px 0; box-shadow: 0 2px 8px rgba(0,0,0,0.08); position: sticky; top: 0; z-index: 100; }
        .navbar-content { max-width: 1200px; margin: 0 auto; padding: 0 20px; display: flex; justify-content: space-between; align-items: center; }
        .logo { font-size: 1.8rem; font-weight: bold; color: #e74c3c; }
        .nav-links { display: flex; gap: 20px; }
        .nav-links a { text-decoration: none; color: #333; font-weight: 500; }
        .nav-links a:hover { color: #e74c3c; }
        .auth-buttons { display: flex; gap: 12px; align-items: center; }
        .btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; }
        .btn-primary { background: #e74c3c; color: white; }
        .btn-outline { background: transparent; color: #e74c3c; border: 2px solid #e74c3c; }
        .page { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .hero { display: flex; justify-content: space-between; flex-wrap: wrap; gap: 20px; margin-bottom: 30px; }
        .hero h1 { font-size: 2.4rem; color: #333; }
        .hero p { color: #555; margin-top: 8px; max-width: 640px; }
        .search-form { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
        .search-form input { padding: 12px 14px; border-radius: 10px; border: 1px solid #ddd; width: 220px; }
        .cards-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; }
        .property-card { background: white; border-radius: 18px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.08); transition: transform 0.25s ease, box-shadow 0.25s ease; }
        .property-card:hover { transform: translateY(-4px); box-shadow: 0 18px 40px rgba(0,0,0,0.12); }
        .property-image { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; height: 180px; display: flex; align-items: center; justify-content: center; font-size: 2.2rem; }
        .property-body { padding: 22px; }
        .property-title { font-size: 1.3rem; font-weight: 700; margin-bottom: 10px; color: #222; }
        .property-location { color: #6b7280; margin-bottom: 14px; }
        .property-description { color: #555; margin-bottom: 16px; line-height: 1.6; }
        .property-footer { display: flex; align-items: center; justify-content: space-between; gap: 14px; }
        .property-price { color: #e74c3c; font-weight: 700; }
        .property-action { display: inline-flex; align-items: center; gap: 10px; background: #e74c3c; color: white; padding: 12px 18px; border-radius: 999px; text-decoration: none; font-weight: 700; }
        .empty-state { text-align: center; color: #6b7280; padding: 80px 20px; border: 1px dashed #d1d5db; border-radius: 16px; background: white; }
      </style>
    </head>
    <body>
      <nav class="navbar">
        <div class="navbar-content">
          <div class="logo"><i class="fas fa-home"></i> StayHub</div>
          <div class="nav-links">
            <a href="/user"><i class="fas fa-tachometer-alt"></i> Dashboard</a>
            <a href="/properties"><i class="fas fa-bed"></i> Browse Stays</a>
            <a href="/user/bookings"><i class="fas fa-calendar-check"></i> My Bookings</a>
          </div>
          <div class="auth-buttons">
            <div class="user-avatar">${user.displayName.charAt(0).toUpperCase()}</div>
            <a href="/logout" class="btn btn-primary">Logout</a>
          </div>
        </div>
      </nav>
      <div class="page">
        <div class="hero">
          <div>
            <h1>Browse available stays</h1>
            <p>Choose where you'd like to stay and complete your booking in just a few steps.</p>
          </div>
          <form class="search-form" method="GET" action="/properties">
            <input type="text" name="location" placeholder="Search by city or property" value="${escapeHtml(req.query.location || '')}">
            <button type="submit" class="btn btn-primary">Search</button>
          </form>
        </div>

        <div class="cards-grid">
          ${properties.length === 0 ? `
            <div class="empty-state">
              <h2>No stays found</h2>
              <p>Try a different search term or come back later when new properties are available.</p>
            </div>
          ` : properties.map((property) => `
            <div class="property-card">
              <div class="property-image">${escapeHtml(property.name.charAt(0).toUpperCase())}</div>
              <div class="property-body">
                <div class="property-title">${escapeHtml(property.name)}</div>
                <div class="property-location"><i class="fas fa-map-marker-alt"></i> ${escapeHtml(property.location)}</div>
                <div class="property-description">${escapeHtml(property.description || 'A relaxing stay for your next trip.')}</div>
                <div class="property-footer">
                  <div class="property-price">$${Number(property.price).toFixed(2)}/night</div>
                  <a href="/properties/${property.id}" class="property-action"><i class="fas fa-arrow-right"></i> Book Now</a>
                </div>
              </div>
            </div>
          `).join('')}
        </div>
      </div>
    </body>
    </html>
  `);
});

app.get('/properties/:id', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const property = (data.properties || []).find((item) => item.id === req.params.id && item.active);
  if (!property) return res.status(404).send('Property not found.');

  const error = escapeHtml(req.query.error || '');
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Book ${escapeHtml(property.name)} - StayHub</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
      <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f4f6f8; margin: 0; }
        .page { max-width: 900px; margin: 40px auto; padding: 0 20px; }
        .card { background: white; border-radius: 18px; padding: 32px; box-shadow: 0 12px 35px rgba(0,0,0,0.08); }
        .card h1 { margin-bottom: 12px; font-size: 2rem; }
        .card p { color: #555; margin-bottom: 24px; line-height: 1.7; }
        .detail { display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }
        .detail span { color: #444; font-weight: 600; }
        .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 24px; }
        .form-group { display: flex; flex-direction: column; gap: 8px; }
        .form-group label { font-weight: 600; color: #555; }
        .form-group input { padding: 14px 16px; border: 1px solid #ddd; border-radius: 12px; font-size: 1rem; }
        .btn-primary { display: inline-flex; align-items: center; gap: 10px; background: #e74c3c; color: white; padding: 14px 24px; border: none; border-radius: 12px; cursor: pointer; font-weight: 700; text-decoration: none; }
        .btn-secondary { display: inline-flex; align-items: center; gap: 10px; background: #6c757d; color: white; padding: 14px 24px; border: none; border-radius: 12px; cursor: pointer; text-decoration: none; }
        .error { margin-bottom: 24px; padding: 16px; background: #ffe3e3; color: #b02a37; border-radius: 12px; }
      </style>
    </head>
    <body>
      <div class="page">
        <a href="/properties" class="btn-secondary"><i class="fas fa-arrow-left"></i> Back to Listings</a>
        <div class="card">
          <h1>Book ${escapeHtml(property.name)}</h1>
          <p>${escapeHtml(property.description || 'Enjoy a comfortable stay in a beautifully appointed home.')}</p>
          <div class="detail">
            <span><i class="fas fa-map-marker-alt"></i> ${escapeHtml(property.location)}</span>
            <span><i class="fas fa-dollar-sign"></i> $${Number(property.price).toFixed(2)} per night</span>
          </div>
          ${error ? `<div class="error"><i class="fas fa-exclamation-circle"></i> ${error}</div>` : ''}
          <form method="POST" action="/properties/${property.id}/book">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <div class="form-grid">
              <div class="form-group"><label for="checkIn">Check In</label><input type="date" id="checkIn" name="checkIn" required></div>
              <div class="form-group"><label for="checkOut">Check Out</label><input type="date" id="checkOut" name="checkOut" required></div>
              <div class="form-group"><label for="guests">Guests</label><input type="number" id="guests" name="guests" min="1" value="1" required></div>
            </div>
            <button type="submit" class="btn-primary"><i class="fas fa-check"></i> Confirm Booking</button>
          </form>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.post('/properties/:id/book', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const property = (data.properties || []).find((item) => item.id === req.params.id && item.active);
  if (!property) return res.status(404).send('Property not found.');

  const { checkIn, checkOut, guests } = req.body;
  const numGuests = Number(guests);
  if (!checkIn || !checkOut || !guests || isNaN(numGuests) || numGuests < 1) {
    return res.redirect(`/properties/${property.id}?error=Please provide a valid check-in, check-out, and guest count.`);
  }

  const checkInDate = new Date(checkIn);
  const checkOutDate = new Date(checkOut);
  if (isNaN(checkInDate.getTime()) || isNaN(checkOutDate.getTime()) || checkOutDate <= checkInDate) {
    return res.redirect(`/properties/${property.id}?error=Check out must be after check in.`);
  }

  const nights = Math.ceil((checkOutDate - checkInDate) / (1000 * 60 * 60 * 24));
  if (nights <= 0) {
    return res.redirect(`/properties/${property.id}?error=Please select a valid stay duration.`);
  }

  const totalPrice = Number((Number(property.price) * nights).toFixed(2));
  const booking = {
    id: generateId(),
    guestId: user.id,
    guestName: user.displayName,
    guestEmail: user.email,
    propertyId: property.id,
    propertyName: property.name,
    propertyLocation: property.location,
    checkIn,
    checkOut,
    guests: numGuests,
    totalPrice,
    completed: false,
    createdAt: new Date().toISOString()
  };

  data.bookings.push(booking);
  writeData(data);
  audit('booking_created', `Booking created for property '${property.name}' by ${user.email}`, req, user.id);
  res.redirect('/user/bookings');
});

app.get('/admin/properties/new', ensureAuthenticated, ensureAdmin, (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Add Property - StayHub Admin</title>
      <style>
        body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; }
        .page { max-width: 600px; margin: 50px auto; padding: 0 20px; }
        .card { background: white; border-radius: 12px; padding: 30px; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        .card h1 { margin-top: 0; font-size: 2rem; color: #333; }
        .form-group { margin-bottom: 20px; }
        .form-group label { display: block; margin-bottom: 10px; color: #555; font-weight: 600; }
        .form-group input, .form-group textarea { width: 100%; padding: 12px; border-radius: 8px; border: 1px solid #ddd; font-size: 1rem; font-family: inherit; }
        .form-group textarea { min-height: 100px; resize: vertical; }
        .form-actions { display: flex; gap: 12px; flex-wrap: wrap; }
        .btn { border: none; border-radius: 8px; padding: 12px 20px; cursor: pointer; color: white; font-weight: 600; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; }
        .btn-primary { background: #e74c3c; }
        .btn-secondary { background: #6c757d; }
        .btn-primary:hover { background: #c0392b; }
        .btn-secondary:hover { background: #5a6268; }
      </style>
    </head>
    <body>
      <div class="page">
        <div class="card">
          <h1>Add New Property</h1>
          <form method="POST" action="/admin/properties/new">
            <input type="hidden" name="_csrf" value="${req.csrfToken()}">
            <div class="form-group"><label for="name">Property Name</label><input id="name" name="name" required></div>
            <div class="form-group"><label for="location">Location</label><input id="location" name="location" required></div>
            <div class="form-group"><label for="description">Description</label><textarea id="description" name="description"></textarea></div>
            <div class="form-group"><label for="price">Price per Night ($)</label><input id="price" name="price" type="number" step="0.01" required></div>
            <div class="form-group"><label><input type="checkbox" name="active" checked> Active</label></div>
            <div class="form-actions">
              <button type="submit" class="btn btn-primary">Create Property</button>
              <a href="/admin/properties" class="btn btn-secondary">Back</a>
            </div>
          </form>
        </div>
      </div>
    </body>
    </html>
  `);
});

app.post('/admin/properties/new', ensureAuthenticated, ensureAdmin, (req, res) => {
  const user = currentUser(req);
  const { name, location, description, price } = req.body;
  const active = Boolean(req.body.active);
  const property = {
    id: generateId(),
    name: name.trim(),
    location: location.trim(),
    description: description.trim(),
    price: parseFloat(price),
    active,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  if (!data.properties) data.properties = [];
  data.properties.push(property);
  writeData(data);
  audit('property_created', `Property '${property.name}' created in ${property.location}`, req, user.id);
  res.redirect('/admin/properties');
});

app.post('/admin/properties/:id/delete', ensureAuthenticated, ensureAdmin, (req, res) => {
  const user = currentUser(req);
  const index = (data.properties || []).findIndex((p) => p.id === req.params.id);
  if (index === -1) return res.status(404).send('Property not found');
  const property = data.properties[index];
  data.properties.splice(index, 1);
  writeData(data);
  audit('property_deleted', `Property '${property.name}' deleted`, req, user.id);
  res.redirect('/admin/properties');
});

app.get('/tasks/:id/edit', ensureAuthenticated, (req, res) => {
  res.redirect('/admin/properties');
});

app.post('/tasks/:id/edit', ensureAuthenticated, (req, res) => {
  res.redirect('/admin/properties');
});

app.post('/tasks/:id/delete', ensureAuthenticated, (req, res) => {
  res.redirect('/admin/properties');
});

app.get('/audit', ensureAuthenticated, ensureAdmin, (req, res) => {
  res.redirect('/admin/audit');
});

app.get('/admin/audit', ensureAuthenticated, ensureAdmin, (req, res) => {
  const logs = data.auditLogs.slice(0, 100);
  res.send(`
    <!DOCTYPE html>
    <html lang="en">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>Audit Log - StayHub Admin</title>
      <style>
        body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; }
        .page { max-width: 1200px; margin: 40px auto; padding: 0 20px; }
        .header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; }
        .header h1 { margin: 0; font-size: 2rem; color: #333; }
        .btn { display: inline-flex; align-items: center; justify-content: center; gap: 8px; padding: 12px 20px; border-radius: 8px; border: none; background: #6c757d; color: white; text-decoration: none; font-weight: 600; }
        .btn:hover { background: #5a6268; }
        .table { width: 100%; border-collapse: collapse; background: white; border-radius: 12px; overflow: hidden; box-shadow: 0 2px 8px rgba(0,0,0,0.1); }
        th, td { padding: 16px; border-bottom: 1px solid #e9ecef; }
        th { background: #f8f9fa; color: #555; text-transform: uppercase; font-size: 0.9rem; font-weight: 600; }
        td { color: #333; }
        tr:last-child td { border-bottom: none; }
        .badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 10px; border-radius: 20px; font-size: 0.85rem; background: #d4edda; color: #155724; }
      </style>
    </head>
    <body>
      <div class="page">
        <div class="header">
          <div>
            <h1><i class="fas fa-clipboard-list"></i> Audit Log</h1>
            <p style="color:#666;margin-top:6px;">System activity and security events.</p>
          </div>
          <a href="/admin" class="btn"><i class="fas fa-home"></i> Dashboard</a>
        </div>
        <table class="table">
          <thead>
            <tr><th>Timestamp</th><th>Type</th><th>Message</th><th>User</th><th>IP</th></tr>
          </thead>
          <tbody>
            ${logs.map((log) => `
              <tr>
                <td>${new Date(log.timestamp).toLocaleString()}</td>
                <td><span class="badge">${log.type.replace(/_/g, ' ')}</span></td>
                <td>${escapeHtml(log.message)}</td>
                <td>${escapeHtml(log.userId || 'system')}</td>
                <td>${escapeHtml(log.ip)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    </body>
    </html>
  `);
});

app.get('/profile', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  const email = user.email || (user.emails && user.emails.length > 0 ? user.emails[0].value : 'N/A');
  // Prioritize uploaded profile picture, then Google, then UI Avatars
  const profileImageSrc = user.profileImageFileName 
    ? `/uploads/${user.profileImageFileName}` 
    : (user.provider === 'google' && user.photos && user.photos.length > 0 ? user.photos[0].value : `https://ui-avatars.com/api/?name=${encodeURIComponent(user.displayName)}&background=e74c3c&color=fff`);

  const bookingsCount = (data.bookings || []).filter((b) => b.guestId === user.id).length;
  const error = escapeHtml(req.query.error || '');
  const success = escapeHtml(req.query.success || '');
  res.send(`
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Profile - StayHub</title>
        <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
        <style>
          body { background: #f8f9fa; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }
          .container { max-width: 680px; margin: 40px auto; background: white; border-radius: 16px; box-shadow: 0 2px 12px rgba(0,0,0,0.1); overflow: hidden; }
          .profile-banner { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); padding: 40px 30px; text-align: center; color: white; }
          .profile-banner h1 { margin: 0; font-size: 1.5rem; }
          .profile-banner p { margin: 5px 0 0 0; opacity: 0.9; }
          .profile-flex { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; padding: 40px 30px; }
          .profile-card { background: #ffffff; border-radius: 16px; padding: 24px; box-shadow: 0 1px 6px rgba(0,0,0,0.05); }
          .avatar { width: 120px; height: 120px; border-radius: 50%; object-fit: cover; box-shadow: 0 2px 12px rgba(0,0,0,0.08); background: #e9ecef; margin: -60px auto 20px; display: block; border: 4px solid white; }
          .profile-details { margin: 30px 0; }
          .detail-row { display: flex; align-items: center; margin-bottom: 18px; padding-bottom: 18px; border-bottom: 1px solid #e9ecef; }
          .detail-row:last-child { border-bottom: none; margin-bottom: 0; padding-bottom: 0; }
          .detail-row i { color: #e74c3c; margin-right: 15px; font-size: 1.2rem; width: 25px; }
          .detail-label { color: #888; min-width: 110px; font-size: 0.9rem; }
          .detail-value { color: #333; font-weight: 500; margin-left: auto; }
          .actions { text-align: center; margin-top: 30px; }
          .btn { padding: 12px 24px; border-radius: 8px; border: none; font-size: 1rem; font-weight: 600; cursor: pointer; text-decoration: none; margin: 0 8px; transition: all 0.2s; display: inline-block; }
          .btn-primary { background: #e74c3c; color: white; }
          .btn-primary:hover { background: #c0392b; }
          .btn-outline { background: transparent; color: #e74c3c; border: 2px solid #e74c3c; }
          .btn-outline:hover { background: #e74c3c; color: white; }
          .message { padding: 14px 18px; margin-bottom: 22px; border-radius: 12px; font-size: 0.95rem; }
          .message.error { background: #fdecea; color: #b02a37; border: 1px solid #f5c2c7; }
          .message.success { background: #e6ffed; color: #1d7a3d; border: 1px solid #b7eb8f; }
          .form-group { margin-bottom: 18px; }
          .form-group label { display: block; margin-bottom: 8px; color: #565656; font-size: 0.95rem; }
          .form-control { width: 100%; padding: 12px 14px; border-radius: 10px; border: 1px solid #dcdfe3; font-size: 0.95rem; }
          .form-control:focus { outline: none; border-color: #e74c3c; box-shadow: 0 0 0 2px rgba(231,76,60,0.12); }
          .section-title { font-size: 1.05rem; font-weight: 700; margin-bottom: 18px; }
          .section-note { font-size: 0.95rem; color: #6c757d; margin-top: 10px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="profile-banner">
            <h1>${escapeHtml(user.displayName)}</h1>
            <p>${user.role === 'admin' ? '<i class="fas fa-shield-alt"></i> Administrator' : '<i class="fas fa-user"></i> Guest'}</p>
          </div>
          <div class="profile-flex">
            <div class="profile-card">
              <img src="${profileImageSrc}" alt="Profile Picture" class="avatar">
              <div class="profile-details">
                <div class="detail-row"><i class="fas fa-envelope"></i><span class="detail-label">Email:</span> <span class="detail-value">${escapeHtml(email)}</span></div>
                <div class="detail-row"><i class="fas fa-key"></i><span class="detail-label">ID:</span> <span class="detail-value" style="font-size: 0.85rem; font-family: monospace;">${escapeHtml(user.id.substring(0, 12))}...</span></div>
                <div class="detail-row"><i class="fas fa-network-wired"></i><span class="detail-label">Provider:</span> <span class="detail-value">${user.provider ? user.provider.charAt(0).toUpperCase() + user.provider.slice(1) : 'Email'}</span></div>
                <div class="detail-row"><i class="fas fa-calendar-check"></i><span class="detail-label">Bookings:</span> <span class="detail-value">${bookingsCount}</span></div>
                <div class="detail-row"><i class="fas fa-calendar-alt"></i><span class="detail-label">Member Since:</span> <span class="detail-value">${new Date(user.createdAt).toLocaleDateString()}</span></div>
              </div>
              <div class="actions">
                <a href="${user.role === 'admin' ? '/admin' : '/user'}" class="btn btn-outline"><i class="fas fa-arrow-left"></i> Back</a>
                <a href="/logout" class="btn btn-primary"><i class="fas fa-sign-out-alt"></i> Logout</a>
              </div>
            </div>
            <div class="profile-card">
              ${error ? `<div class="message error">${error}</div>` : ''}
              <div class="section-title">Profile Picture</div>
              <form method="POST" action="/profile/upload-picture" enctype="multipart/form-data" style="margin-bottom: 20px;">
                <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                <div class="form-group">
                  <label for="profilePicture">Upload new picture</label>
                  <input type="file" id="profilePicture" name="profilePicture" accept="image/jpeg,image/png,image/webp,image/gif" class="form-control">
                  <p class="section-note">Max 5MB. Allowed: JPG, PNG, WebP, GIF.</p>
                </div>
                <button type="submit" class="btn btn-primary">Upload Picture</button>
              </form>
              ${user.profileImageFileName ? `
                <form method="POST" action="/profile/delete-picture">
                  <input type="hidden" name="_csrf" value="${req.csrfToken()}">
                  <button type="submit" class="btn btn-outline" style="background: #dc3545; color: white; border: none; margin-top: 10px;">Delete Picture</button>
                </form>
              ` : ''}

              <hr style="margin: 30px 0; border: 0; border-top: 1px solid #eee;">

              ${success ? `<div class="message success">${success}</div>` : ''}
              ${success ? `<div class="message success">${success}</div>` : ''}
              <div class="section-title">Change Password</div>
              ${user.provider === 'google' ? `
                <p class="section-note">This account uses Google login. Password changes are managed through Google, not this site.</p>
              ` : `
                <form method="POST" action="/profile/change-password">
                  <div class="form-group">
                    <label for="currentPassword">Current password</label>
                    <input id="currentPassword" name="currentPassword" type="password" class="form-control" required>
                  </div>
                  <div class="form-group">
                    <label for="newPassword">New password</label>
                    <input id="newPassword" name="newPassword" type="password" class="form-control" required>
                  </div>
                  <div class="form-group">
                    <label for="confirmPassword">Confirm new password</label>
                    <input id="confirmPassword" name="confirmPassword" type="password" class="form-control" required>
                  </div>
                  <button type="submit" class="btn btn-primary">Update password</button>
                  <p class="section-note">Password must be at least 12 characters and include uppercase, lowercase, number, and special character.</p>
                </form>
              `}
            </div>
          </div>
        </div>
      </body>
      </html>
    `);
});

app.post('/profile/change-password', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  if (!user) return res.redirect('/login');
  if (user.provider === 'google') {
    return res.redirect('/profile?error=Password changes are not available for Google login users.');
  }

  const { currentPassword, newPassword, confirmPassword } = req.body || {};
  if (!currentPassword || !newPassword || !confirmPassword) {
    return res.redirect('/profile?error=Please complete all password fields.');
  }

  if (newPassword !== confirmPassword) {
    return res.redirect('/profile?error=New passwords do not match.');
  }

  if (!verifyPassword(currentPassword, user.passwordHash)) {
    return res.redirect('/profile?error=Current password is incorrect.');
  }

  const passwordPolicy = /^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).*$/;
  if (!passwordPolicy.test(newPassword)) {
    return res.redirect('/profile?error=Password must be at least 12 characters and include lowercase, uppercase, number, and special character.');
  }

  user.passwordHash = hashPassword(newPassword);
  writeData(data);
  if (req.session) {
    req.session.localUser = user;
  }

  audit('password_change', `Password changed for user ${user.email}`, req, user.id);
  return res.redirect('/profile?success=Password changed successfully.');
});

app.get('/logout', (req, res, next) => {
  if (req.session) {
    req.session.localUser = null;
  }
  const finishLogout = () => {
    if (req.session) {
      req.session.destroy(() => {
        res.clearCookie('connect.sid', { path: '/' });
        return res.redirect('/login');
      });
    } else {
      res.clearCookie('connect.sid', { path: '/' });
      return res.redirect('/login');
    }
  };
  if (typeof req.logout === 'function') {
    req.logout((err) => {
      if (err) return next(err);
      finishLogout();
    });
  } else {
    finishLogout();
  }
});

// FILE UPLOAD SECURITY ROUTES
// Upload property images (admin only)
app.post('/admin/properties/:id/upload-image', ensureAuthenticated, ensureAdmin, upload.single('propertyImage'), (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const property = (data.properties || []).find((p) => p.id === req.params.id);
    if (!property) {
      fs.unlinkSync(req.file.path); // Clean up uploaded file
      return res.status(404).json({ error: 'Property not found' });
    }

    // Use the random UUID filename generated by Multer storage
    const finalFileName = req.file.filename;
    const finalPath = path.join(UPLOAD_DIR, finalFileName);
    fs.renameSync(req.file.path, finalPath);

    // Store file reference in property
    property.imageFileName = finalFileName;
    writeData(data);

    audit('file_uploaded', `Property image uploaded for '${property.name}'`, req, req.user.id);
    res.json({ success: true, message: 'Image uploaded successfully', fileName: finalFileName });
  } catch (err) {
    // Clean up temp file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error('File upload error:', err.message);
    audit('file_upload_failed', `File upload failed: ${err.message}`, req, req.user.id);
    res.status(500).json({ error: 'File upload failed' });
  }
});

// Download property image (authenticated users)
app.get('/uploads/:fileName', ensureAuthenticated, (req, res) => {
  try {
    // Validate filename - prevent path traversal
    const fileName = path.basename(req.params.fileName);
    if (!fileName || fileName.includes('..') || fileName.includes('/')) {
      return res.status(400).send('Invalid file name');
    }

    const filePath = path.join(UPLOAD_DIR, fileName);

    // Check file exists and is in upload directory
    const realPath = fs.realpathSync(filePath);
    const realUploadDir = fs.realpathSync(UPLOAD_DIR);
    if (!realPath.startsWith(realUploadDir)) {
      return res.status(403).send('Access denied');
    }

    if (!fs.existsSync(filePath)) {
      return res.status(404).send('File not found');
    }

    // Set secure headers for file download
    res.setHeader('Content-Disposition', 'inline; filename=' + fileName);
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');

    // Serve file
    const stream = fs.createReadStream(filePath);
    stream.on('error', (err) => {
      console.error('File stream error:', err);
      res.status(500).send('Error serving file');
    });
    stream.pipe(res);

    audit('file_downloaded', `File downloaded: ${fileName}`, req, req.user.id);
  } catch (err) {
    console.error('File access error:', err.message);
    res.status(500).send('Error accessing file');
  }
});

// Delete property image (admin only)
app.post('/admin/properties/:id/delete-image', ensureAuthenticated, ensureAdmin, (req, res) => {
  try {
    const property = (data.properties || []).find((p) => p.id === req.params.id);
    if (!property || !property.imageFileName) {
      return res.status(404).json({ error: 'Property or image not found' });
    }

    const filePath = path.join(UPLOAD_DIR, property.imageFileName);

    // Validate file path
    const realPath = fs.realpathSync(filePath);
    const realUploadDir = fs.realpathSync(UPLOAD_DIR);
    if (!realPath.startsWith(realUploadDir)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Delete file
    if (fs.existsSync(filePath)) {
      fs.unlinkSync(filePath);
    }

    // Remove reference from property
    delete property.imageFileName;
    delete property.imageUploadedAt;
    writeData(data);

    audit('file_deleted', `Property image deleted for '${property.name}'`, req, req.user.id);
    res.json({ success: true, message: 'Image deleted successfully' });
  } catch (err) {
    console.error('File deletion error:', err.message);
    audit('file_deletion_failed', `File deletion failed: ${err.message}`, req, req.user.id);
    res.status(500).json({ error: 'File deletion failed' });
  }
});

// NEW: Upload profile picture
app.post('/profile/upload-picture', ensureAuthenticated, upload.single('profilePicture'), (req, res) => {
  try {
    if (!req.file) {
      return res.redirect('/profile?error=No file uploaded or invalid file type/size.');
    }

    const user = currentUser(req);
    if (!user) { // Should not happen due to ensureAuthenticated, but good for safety
      fs.unlinkSync(req.file.path); // Clean up uploaded file
      return res.redirect('/profile?error=User not found.');
    }

    // Delete old profile picture if it exists
    if (user.profileImageFileName) {
      const oldFilePath = path.join(UPLOAD_DIR, user.profileImageFileName);
      // Ensure the old file is actually within the UPLOAD_DIR to prevent path traversal during deletion
      const realOldFilePath = fs.realpathSync(oldFilePath);
      const realUploadDir = fs.realpathSync(UPLOAD_DIR);
      if (realOldFilePath.startsWith(realUploadDir) && fs.existsSync(oldFilePath)) {
        fs.unlinkSync(oldFilePath);
      }
    }

    // Move file from temp to permanent storage
    const finalFileName = req.file.filename; // Multer already renamed it to UUID
    const finalPath = path.join(UPLOAD_DIR, finalFileName);
    fs.renameSync(req.file.path, finalPath);

    // Store file reference in user profile
    user.profileImageFileName = finalFileName;
    writeData(data);

    audit('profile_picture_uploaded', `Profile picture uploaded for user ${user.email}`, req, user.id);
    res.redirect('/profile?success=Profile picture uploaded successfully.');
  } catch (err) {
    // Clean up temp file on error
    if (req.file && fs.existsSync(req.file.path)) {
      fs.unlinkSync(req.file.path);
    }
    console.error('Profile picture upload error:', err.message);
    audit('profile_picture_upload_failed', `Profile picture upload failed: ${err.message}`, req, req.user.id);
    res.redirect(`/profile?error=Upload failed: ${err.message}`);
  }
});

// NEW: Delete profile picture
app.post('/profile/delete-picture', ensureAuthenticated, (req, res) => {
  const user = currentUser(req);
  if (!user || !user.profileImageFileName) {
    return res.redirect('/profile?error=No profile picture to delete.');
  }

  const filePath = path.join(UPLOAD_DIR, user.profileImageFileName);
  if (fs.existsSync(filePath)) { // No need for realpath check here as filename is system-generated UUID
    fs.unlinkSync(filePath);
  }
  delete user.profileImageFileName;
  writeData(data);
  audit('profile_picture_deleted', `Profile picture deleted for user ${user.email}`, req, user.id);
  res.redirect('/profile?success=Profile picture deleted successfully.');
});

// ERROR HANDLER - don't expose sensitive error details to users
app.use((err, req, res, next) => {
  // Handle multer errors
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: `File too large. Maximum size is ${MAX_FILE_SIZE / 1024 / 1024}MB` });
    }
    if (err.code === 'LIMIT_FILE_COUNT') {
      return res.status(413).json({ error: `Too many files. Maximum is ${MAX_FILES}` });
    }
    return res.status(400).json({ error: err.message });
  }

  // Handle custom multer validation errors
  if (err.message && err.message.includes('Invalid file')) {
    return res.status(400).json({ error: err.message });
  }

  // Log error securely (don't include stack trace in response)
  const errorId = generateId();
  console.error(`[${errorId}] Error:`, err.message);
  
  res.status(500).send(`
    <!DOCTYPE html>
    <html>
    <head><title>Error</title><style>
      body { font-family: Arial; text-align: center; padding: 40px; }
      .error-box { background: #f8d7da; padding: 20px; border-radius: 8px; max-width: 500px; margin: 0 auto; }
      h1 { color: #721c24; }
      p { color: #721c24; }
    </style></head>
    <body>
      <div class="error-box">
        <h1>500 - Internal Server Error</h1>
        <p>An error occurred while processing your request.</p>
        <p><small>Error ID: ${errorId}</small></p>
      </div>
    </body>
    </html>
  `);
});

const PORT = process.env.PORT || 3000;

// HTTPS Support (OWASP A6 - Use TLS for all connections)
const useHttps = process.env.HTTPS === 'true' || process.env.NODE_ENV === 'production';

let server;
if (useHttps) {
  try {
    const certPath = process.env.CERT_PATH || path.join(__dirname, 'cert.pem');
    const keyPath = process.env.KEY_PATH || path.join(__dirname, 'key.pem');
    
    if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
      const options = {
        cert: fs.readFileSync(certPath),
        key: fs.readFileSync(keyPath)
      };
      server = https.createServer(options, app);
      server.listen(PORT, () => {
        console.log(`\n✅ Secure server running on https://localhost:${PORT}`);
        console.log(`🔐 TLS/HTTPS enabled - OWASP A6 compliant`);
        console.log(`🔐 PBKDF2 password hashing with 310k+ iterations`);
        console.log(`🔐 Sensitive data redacted from logs`);
        console.log(`\n📖 Open browser and visit: https://localhost:${PORT}\n`);
      });
    } else {
      console.log('⚠️  HTTPS requested but certificates not found. Using HTTP.');
      console.log('To generate self-signed certificates, run:');
      console.log('openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365\n');
      server = app.listen(PORT);
    }
  } catch (e) {
    console.log('⚠️  HTTPS setup failed. Using HTTP.');
    server = app.listen(PORT);
  }
} else {
  server = app.listen(PORT);
}

if (!useHttps) {
  console.log(`\n✅ Server running on http://localhost:${PORT}`);
  console.log(`🔐 PBKDF2 password hashing with 310k+ iterations`);
  console.log(`🔐 Sensitive data redacted from logs`);
  console.log(`⚠️  Note: For production, enable HTTPS by setting HTTPS=true`);
  console.log(`\n📖 Open browser and visit: http://localhost:${PORT}\n`);
}

server.on('error', (err) => {
  if (err.code === 'EADDRINUSE') {
    console.error(`\n❌ Port ${PORT} is already in use!`);
    console.error(`Try: netstat -ano | findstr :${PORT}`);
    console.error(`Then: taskkill /PID <PID> /F\n`);
  } else {
    console.error('❌ Server error:', err.code);
  }
});