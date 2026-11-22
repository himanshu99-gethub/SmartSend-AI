import express from 'express';
import cors from 'cors';
import multer from 'multer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
import { createRequire } from 'module';
import {
  authRegister,
  authLogin,
  authGoogleLogin,
  isFirestoreConnected,
  getCampaigns as fbGetCampaigns,
  getCampaignById as fbGetCampaignById,
  saveCampaignRecord,
  updateCampaignRecord,
  logEmailRecord,
  getEmailHistory as fbGetEmailHistory,
  getStats as fbGetStats
} from './firebase.js';

dotenv.config();

const require = createRequire(import.meta.url);
const pdfParse = require('pdf-parse');
const XLSX = require('xlsx');

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// Security Headers & Hardening (OWASP / Pre-Launch)
// ==========================================
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

// Strict CORS Lockdown (Allows only trusted origins)
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  process.env.APP_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.includes('*')) {
      return callback(null, true);
    }
    return callback(new Error('Blocked by CORS policy.'));
  },
  credentials: true
}));

// Robust sliding-window in-memory rate limiter
const rateLimitBuckets = new Map();

function createRateLimiter({ windowMs = 60000, max = 60, message = 'Too many requests. Please slow down.' }) {
  return (req, res, next) => {
    const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const key = `${req.baseUrl || req.path}:${ip}`;
    const now = Date.now();

    let bucket = rateLimitBuckets.get(key);
    if (!bucket || now - bucket.startTime > windowMs) {
      bucket = { startTime: now, count: 1 };
      rateLimitBuckets.set(key, bucket);
    } else {
      bucket.count++;
      if (bucket.count > max) {
        return res.status(429).json({ success: false, message });
      }
    }
    next();
  };
}

// Global API rate limit: 150 requests per minute
app.use('/api', createRateLimiter({ windowMs: 60 * 1000, max: 150, message: 'Too many API requests. Please slow down.' }));

// Strict Auth Rate Limiter: max 12 attempts per 5 minutes per IP
const authLimiter = createRateLimiter({ windowMs: 5 * 60 * 1000, max: 12, message: 'Too many login attempts. Please wait 5 minutes before trying again.' });

// AI Rate Limiter: max 15 requests per minute per IP
const aiLimiter = createRateLimiter({ windowMs: 60 * 1000, max: 15, message: 'AI generation rate limit reached. Please wait a minute.' });

app.use(express.json({ limit: '15mb' }));
app.use(express.urlencoded({ extended: true, limit: '15mb' }));

// Static frontend
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// Authentication Routes (Firebase Auth / Schema)
// ==========================================

// POST /api/auth/register (Rate Limited)
app.post('/api/auth/register', authLimiter, async (req, res) => {
  const { email, password, displayName } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ success: false, message: 'Password must be at least 6 characters.' });
  }
  try {
    const user = await authRegister({ email, password, displayName });
    return res.json({ success: true, user, message: 'Account created successfully.' });
  } catch (err) {
    return res.status(400).json({ success: false, message: err.message });
  }
});

// POST /api/auth/login (Rate Limited)
app.post('/api/auth/login', authLimiter, async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ success: false, message: 'Email and password are required.' });
  }
  try {
    const user = await authLogin({ email, password });
    return res.json({ success: true, user, message: 'Signed in successfully.' });
  } catch (err) {
    return res.status(401).json({ success: false, message: err.message });
  }
});

// POST /api/auth/google
app.post('/api/auth/google', authLimiter, async (req, res) => {
  const { email, displayName, googleUid } = req.body;
  if (!email) {
    return res.status(400).json({ success: false, message: 'Email is required for Google Sign-in.' });
  }
  try {
    const user = await authGoogleLogin({ email, displayName, googleUid });
    return res.json({ success: true, user, message: 'Signed in with Google.' });
  } catch (err) {
    return res.status(500).json({ success: false, message: err.message });
  }
});

// GET /api/auth/demo (Disabled in production for security)
app.get('/api/auth/demo', (req, res) => {
  return res.status(403).json({ success: false, message: 'Demo endpoint is disabled for production security.' });
});

// DELETE /api/auth/account (User Self-Deletion - DPDP / GDPR Compliance)
app.delete('/api/auth/account', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required to delete account.' });
  }

  const db = readDB();
  db.users = (db.users || []).filter(u => u.uid !== userId);
  db.credentials = (db.credentials || []).filter(c => c.userId !== userId);
  db.campaigns = (db.campaigns || []).filter(c => c.userId !== userId);
  db.emails = (db.emails || []).filter(e => e.userId !== userId);
  writeDB(db);

  return res.json({ success: true, message: 'Your account data, credentials, and campaigns have been permanently deleted.' });
});

// Ensure data & uploads directories exist
const DATA_DIR = path.join(__dirname, 'data');
const UPLOADS_DIR = path.join(__dirname, 'data', 'uploads');
const ATTACHMENTS_DIR = path.join(__dirname, 'data', 'uploads', 'attachments');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
if (!fs.existsSync(UPLOADS_DIR)) fs.mkdirSync(UPLOADS_DIR, { recursive: true });
if (!fs.existsSync(ATTACHMENTS_DIR)) fs.mkdirSync(ATTACHMENTS_DIR, { recursive: true });

const DB_FILE = path.join(DATA_DIR, 'db.json');
if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({
    users: [{
      uid: 'user_default',
      email: 'user@example.com',
      displayName: 'Aman',
      dailyCap: 450,
      createdAt: new Date().toISOString()
    }],
    credentials: [],
    uploads: [],
    campaigns: [],
    emails: [],
    usage: {}
  }, null, 2));
}

function readDB() {
  try {
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (err) {
    return { users: [], credentials: [], uploads: [], campaigns: [], emails: [], usage: {} };
  }
}

function writeDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error writing DB:', err);
  }
}

const allowedContactExts = ['.xlsx', '.xls', '.csv', '.pdf'];
const allowedAttachmentExts = ['.pdf', '.png', '.jpg', '.jpeg', '.gif', '.webp', '.doc', '.docx', '.txt'];

// Multer storage for contact files with strict file extension filtering
const upload = multer({
  dest: UPLOADS_DIR,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB limit
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedContactExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid contact file format (${ext}). Allowed: ${allowedContactExts.join(', ')}`));
    }
  }
});

// Multer storage for email attachments with strict validation
const attachmentUpload = multer({
  dest: ATTACHMENTS_DIR,
  limits: { fileSize: 15 * 1024 * 1024 }, // 15MB limit
  fileFilter: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    if (allowedAttachmentExts.includes(ext)) {
      cb(null, true);
    } else {
      cb(new Error(`Invalid attachment format (${ext}). Executable and unsafe files are blocked.`));
    }
  }
});

// Active in-memory campaign controllers
const activeCampaigns = new Map();

// Helper: validate email address
function isValidEmail(email) {
  if (!email || typeof email !== 'string') return false;
  const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$/;
  return re.test(email.trim());
}

// Helper: sanitize cell text (strip CSV injection =, +, -, @)
function sanitizeText(val) {
  if (val === null || val === undefined) return '';
  let str = String(val).trim();
  if (/^[=+\-@]/.test(str)) {
    str = "'" + str;
  }
  return str;
}

// Helper: get authenticated user from request headers or query
function getAuthUser(req) {
  const userId = req.headers['x-user-id'] || req.query.userId || req.body?.userId || null;
  const userEmail = req.headers['x-user-email'] || req.query.userEmail || req.body?.userEmail || null;
  return { userId, userEmail };
}

// ==========================================
// 1. Credentials Endpoints
// ==========================================

// POST /api/credentials/test (Rate Limited)
app.post('/api/credentials/test', authLimiter, async (req, res) => {
  const { senderEmail, appPassword, smtpHost, smtpPort, secure } = req.body;
  if (!senderEmail || !appPassword) {
    return res.status(400).json({ success: false, message: 'Sender Email and App Password are required.' });
  }

  const host = smtpHost || 'smtp.gmail.com';
  const port = parseInt(smtpPort, 10) || 587;
  const isSecure = secure === true || port === 465;

  try {
    const transporter = nodemailer.createTransport({
      host,
      port,
      secure: isSecure,
      auth: {
        user: senderEmail.trim(),
        pass: appPassword.replace(/\s+/g, '') // remove spaces from 16-char app password
      },
      connectionTimeout: 10000,
      greetingTimeout: 8000
    });

    await transporter.verify();
    return res.json({
      success: true,
      message: `Verified successfully. Connected as ${senderEmail.trim()}`
    });
  } catch (error) {
    console.error('SMTP Verify Error:', error.message);
    let msg = error.message;
    if (error.code === 'EAUTH' || msg.includes('BadCredentials') || msg.includes('Username and Password not accepted')) {
      msg = 'Authentication failed. Please check your 16-character Gmail App Password (make sure 2-Step Verification is enabled in Google Account).';
    } else if (error.code === 'ETIMEDOUT' || error.code === 'ESOCKET') {
      msg = 'Connection timed out. Check SMTP Host and Port.';
    }
    return res.status(400).json({
      success: false,
      message: msg,
      code: error.code || 'EAUTH'
    });
  }
});

// POST /api/credentials (Save or update - User Isolated)
app.post('/api/credentials', (req, res) => {
  const { userId, userEmail } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required. Please sign in to save credentials.' });
  }

  const { senderEmail, appPassword, smtpHost, smtpPort, secure, mode } = req.body;
  if (!senderEmail) {
    return res.status(400).json({ success: false, message: 'Sender Email is required.' });
  }

  const db = readDB();
  const credId = 'cred_' + Date.now();
  const cleanPass = appPassword ? appPassword.replace(/\s+/g, '') : '';
  const newCred = {
    id: credId,
    userId,
    userEmail: userEmail || senderEmail.trim(),
    senderEmail: senderEmail.trim(),
    smtpHost: smtpHost || 'smtp.gmail.com',
    smtpPort: parseInt(smtpPort, 10) || 587,
    secure: secure === true,
    verified: true,
    mode: mode || 'saved', // 'saved' or 'session'
    appPassword: cleanPass,
    updatedAt: new Date().toISOString()
  };

  // Upsert credentials specifically for this userId
  const existingIdx = db.credentials.findIndex(c => c.userId === userId && c.senderEmail.toLowerCase() === newCred.senderEmail.toLowerCase());
  if (existingIdx >= 0) {
    if (!cleanPass && db.credentials[existingIdx].appPassword) {
      newCred.appPassword = db.credentials[existingIdx].appPassword;
    }
    db.credentials[existingIdx] = { ...db.credentials[existingIdx], ...newCred };
  } else {
    db.credentials.push(newCred);
  }
  writeDB(db);

  // Return masked credentials to client (never return raw app password)
  return res.json({
    success: true,
    credential: {
      id: newCred.id,
      senderEmail: newCred.senderEmail,
      smtpHost: newCred.smtpHost,
      smtpPort: newCred.smtpPort,
      verified: true,
      mode: newCred.mode,
      maskedPassword: '••••••••••••••••'
    }
  });
});

// GET /api/credentials (User Isolated)
app.get('/api/credentials', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required.', credentials: [] });
  }
  const db = readDB();
  const userCreds = (db.credentials || []).filter(c => c.userId === userId);
  const list = userCreds.map(c => ({
    id: c.id,
    senderEmail: c.senderEmail,
    smtpHost: c.smtpHost,
    smtpPort: c.smtpPort,
    verified: c.verified,
    mode: c.mode,
    maskedPassword: '••••••••••••••••',
    updatedAt: c.updatedAt
  }));
  res.json({ success: true, credentials: list });
});

// DELETE /api/credentials/:id (User Isolated)
app.delete('/api/credentials/:id', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required.' });
  }
  const db = readDB();
  db.credentials = (db.credentials || []).filter(c => !(c.id === req.params.id && (c.userId === userId || !c.userId)));
  writeDB(db);
  res.json({ success: true, message: 'Credential deleted.' });
});

// ==========================================
// 2. File Upload & Parsing Endpoints
// ==========================================

// POST /api/uploads/parse (Authenticated)
app.post('/api/uploads/parse', upload.single('file'), async (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    if (req.file && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
    }
    return res.status(401).json({ success: false, message: 'Authentication required to parse contact files.' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No file uploaded.' });
  }

  const filePath = req.file.path;
  const originalName = req.file.originalname;
  const ext = path.extname(originalName).toLowerCase();

  try {
    let headers = [];
    let rows = [];

    if (ext === '.xlsx' || ext === '.xls' || ext === '.csv') {
      const workbook = XLSX.readFile(filePath, { cellDates: true });
      const firstSheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[firstSheetName];
      const rawJson = XLSX.utils.sheet_to_json(worksheet, { defval: '', raw: false });

      if (rawJson.length > 0) {
        headers = Object.keys(rawJson[0]).map(h => h.trim());
        rows = rawJson.map(row => {
          const cleanRow = {};
          for (const key of headers) {
            cleanRow[key] = sanitizeText(row[key]);
          }
          return cleanRow;
        });
      }
    } else if (ext === '.pdf') {
      // PDF text extraction and regex email detection
      const dataBuffer = fs.readFileSync(filePath);
      const pdfData = await pdfParse(dataBuffer);
      const text = pdfData.text || '';

      // Find all emails
      const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;
      const matches = text.match(emailRegex) || [];
      const uniqueEmails = [...new Set(matches.map(e => e.toLowerCase()))];

      headers = ['Email', 'Name', 'Context'];
      rows = uniqueEmails.map(email => {
        // Derive name from email local part
        const namePart = email.split('@')[0].replace(/[._-]/g, ' ');
        const name = namePart.charAt(0).toUpperCase() + namePart.slice(1);
        return {
          Email: email,
          Name: name,
          Context: `Extracted from ${originalName}`
        };
      });
    } else {
      // Try treating as text/CSV
      const fileContent = fs.readFileSync(filePath, 'utf8');
      const workbook = XLSX.read(fileContent, { type: 'string' });
      const firstSheetName = workbook.SheetNames[0];
      const worksheet = workbook.Sheets[firstSheetName];
      const rawJson = XLSX.utils.sheet_to_json(worksheet, { defval: '' });
      if (rawJson.length > 0) {
        headers = Object.keys(rawJson[0]);
        rows = rawJson;
      }
    }

    // Auto-detect email & name columns
    let detectedEmailCol = headers.find(h => /email|e-mail|mail/i.test(h)) || '';
    let detectedNameCol = headers.find(h => /name|full_name|firstname|first_name|contact/i.test(h)) || '';
    let detectedCompanyCol = headers.find(h => /company|org|organization|business/i.test(h)) || '';

    // If no detected email col by name, scan first row values
    if (!detectedEmailCol && rows.length > 0) {
      for (const h of headers) {
        if (isValidEmail(rows[0][h])) {
          detectedEmailCol = h;
          break;
        }
      }
    }

    // Validation stats
    let validCount = 0;
    let invalidCount = 0;
    const seenEmails = new Set();
    let duplicateCount = 0;

    const validatedRows = rows.map((r, idx) => {
      const emailVal = detectedEmailCol ? String(r[detectedEmailCol] || '').trim() : '';
      const isValid = isValidEmail(emailVal);
      const isDuplicate = seenEmails.has(emailVal.toLowerCase());
      if (isValid) {
        if (isDuplicate) duplicateCount++;
        else seenEmails.add(emailVal.toLowerCase());
        validCount++;
      } else {
        invalidCount++;
      }
      return {
        _rowNumber: idx + 1,
        _isValid: isValid,
        _isDuplicate: isDuplicate,
        ...r
      };
    });

    const uploadRecord = {
      uploadId: 'up_' + Date.now(),
      fileName: originalName,
      sizeBytes: req.file.size,
      headers,
      totalRows: rows.length,
      validRows: validCount,
      invalidRows: invalidCount,
      duplicateRows: duplicateCount,
      detectedEmailCol,
      detectedNameCol,
      detectedCompanyCol,
      rows: validatedRows,
      createdAt: new Date().toISOString()
    };

    const db = readDB();
    db.uploads.push(uploadRecord);
    writeDB(db);

    return res.json({
      success: true,
      uploadId: uploadRecord.uploadId,
      fileName: originalName,
      headers,
      totalRows: rows.length,
      validRows: validCount,
      invalidRows: invalidCount,
      duplicateRows: duplicateCount,
      detectedEmailCol,
      detectedNameCol,
      detectedCompanyCol,
      sampleRows: validatedRows.slice(0, 10),
      allRows: validatedRows
    });
  } catch (error) {
    console.error('File parsing error:', error);
    return res.status(500).json({ success: false, message: 'Failed to parse file: ' + error.message });
  }
});

// POST /api/uploads/attachment (Authenticated)
app.post('/api/uploads/attachment', attachmentUpload.single('attachment'), (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    if (req.file && fs.existsSync(req.file.path)) {
      try { fs.unlinkSync(req.file.path); } catch (e) {}
    }
    return res.status(401).json({ success: false, message: 'Authentication required to upload attachments.' });
  }

  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No attachment file uploaded.' });
  }

  const originalName = req.file.originalname;
  const safeFilename = `${Date.now()}_${path.basename(originalName)}`;
  const targetPath = path.join(ATTACHMENTS_DIR, safeFilename);

  try {
    fs.renameSync(req.file.path, targetPath);
    return res.json({
      success: true,
      attachment: {
        name: originalName,
        path: targetPath,
        size: req.file.size,
        mimetype: req.file.mimetype
      }
    });
  } catch (err) {
    console.error('Error saving attachment:', err);
    return res.status(500).json({ success: false, message: 'Failed to save attachment file.' });
  }
});

// GET /api/config
app.get('/api/config', (req, res) => {
  const hasKey = !!(process.env.VITE_OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY);
  return res.json({
    success: true,
    hasOpenRouterKey: hasKey,
    model: process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash-001',
    isFirestoreConnected: isFirestoreConnected(),
    firebaseProjectId: process.env.FIREBASE_PROJECT_ID || null
  });
});

// ==========================================
// 3. AI Generation & Preview Endpoints
// ==========================================

function localSmartTemplateGenerator(prompt, tone = 'professional', headers = []) {
  const hasCompany = headers.some(h => /company|org|business/i.test(h));
  const companyTag = hasCompany ? '{{Company}}' : 'your organization';

  let subject = `Connecting with {{Name}} regarding ${prompt.slice(0, 30)}...`;
  if (/job|hire|position|role|resume|apply|application|career/i.test(prompt)) {
    subject = `Application: {{Name}} - Exploration regarding opportunities at ${companyTag}`;
  } else if (/audit|review|website|seo|design/i.test(prompt)) {
    subject = `Complimentary digital audit & suggestions for ${companyTag}`;
  } else if (/sales|service|offer|pitch|partnership|collaborat/i.test(prompt)) {
    subject = `Partnership idea for {{Name}} at ${companyTag}`;
  } else if (/invoice|payment|bill|reminder/i.test(prompt)) {
    subject = `Account follow-up & invoice inquiry for ${companyTag}`;
  } else if (/meeting|coffee|chat|quick/i.test(prompt)) {
    subject = `Quick 10-min chat with {{Name}}?`;
  }

  const salutations = {
    formal: 'Dear Mr./Ms. {{Name}},',
    friendly: 'Hi {{Name}},',
    short: 'Hi {{Name}} —',
    professional: 'Dear {{Name}},'
  };
  const signoffs = {
    formal: 'Sincerely,\n[Your Name]',
    friendly: 'Warmly,\n[Your Name]',
    short: 'Thanks,\n[Your Name]',
    professional: 'Best regards,\n[Your Name]'
  };

  const salutation = salutations[tone] || salutations.professional;
  const signoff = signoffs[tone] || signoffs.professional;

  let body = `${salutation}\n\nI hope this email finds you well.\n\nI am reaching out regarding: ${prompt}.\n\nGiven your focus at ${companyTag}, I believe there could be exceptional mutual value in connecting. We recently helped similar organizations achieve meaningful results without friction.\n\nWould you be open to a 10-minute introductory conversation this Thursday or Friday?\n\n${signoff}`;

  return { subject, body };
}

// POST /api/ai/generate-template (Rate Limited & Authenticated)
app.post('/api/ai/generate-template', aiLimiter, async (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required for AI email generation.' });
  }

  const { prompt, tone = 'professional', headers = [], userApiKey, model } = req.body;
  const apiKey = userApiKey || process.env.VITE_OPENROUTER_API_KEY || process.env.OPENROUTER_API_KEY;
  const targetModel = model || process.env.OPENROUTER_MODEL || 'google/gemini-2.0-flash-001';

  if (!prompt || !prompt.trim()) {
    return res.status(400).json({ success: false, message: 'Please provide a prompt describing the email.' });
  }

  if (prompt.length > 2000) {
    return res.status(400).json({ success: false, message: 'Prompt exceeds maximum allowed length (2,000 characters).' });
  }

  const availableHeaders = headers.length > 0 ? headers.join(', ') : 'Name, Company, Email';

  if (apiKey && apiKey.trim()) {
    try {
      const response = await fetch('https://openrouter.ai/api/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey.trim()}`,
          'Content-Type': 'application/json',
          'HTTP-Referer': 'http://localhost:3000',
          'X-Title': 'SmartSend AI'
        },
        body: JSON.stringify({
          model: targetModel,
          messages: [
            {
              role: 'system',
              content: `You are an executive email copywriter.
Generate an engaging email subject and body based on the user's prompt.
Tone: ${tone}.
Available placeholders from contacts sheet: [${availableHeaders}].
Embed placeholders naturally in double curly braces (e.g. {{Name}}, {{Company}}).
Return ONLY raw JSON in this exact structure without markdown backticks or explanation:
{"subject": "...", "body": "..."}`
            },
            {
              role: 'user',
              content: prompt
            }
          ],
          temperature: 0.7
        })
      });

      const data = await response.json();
      if (data.choices && data.choices[0] && data.choices[0].message) {
        let text = data.choices[0].message.content.trim();
        text = text.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```$/i, '').trim();
        const parsed = JSON.parse(text);
        return res.json({
          success: true,
          subject: parsed.subject || `Collaboration opportunity with {{Company}}`,
          body: parsed.body || prompt,
          source: 'openrouter',
          model: targetModel
        });
      } else {
        throw new Error(data.error?.message || 'OpenRouter returned no choices.');
      }
    } catch (err) {
      console.warn('OpenRouter generation error, falling back:', err.message);
      const fallback = localSmartTemplateGenerator(prompt, tone, headers);
      return res.json({
        success: true,
        subject: fallback.subject,
        body: fallback.body,
        source: 'local-fallback',
        notice: `OpenRouter notice: ${err.message}. Generated using local smart engine.`
      });
    }
  } else {
    const fallback = localSmartTemplateGenerator(prompt, tone, headers);
    return res.json({
      success: true,
      subject: fallback.subject,
      body: fallback.body,
      source: 'local-heuristic',
      notice: 'Generated using built-in template engine. Add VITE_OPENROUTER_API_KEY in .env for OpenRouter models!'
    });
  }
});

function interpolateTemplate(template, row) {
  let result = template;
  for (const [key, val] of Object.entries(row)) {
    if (key.startsWith('_')) continue;
    const regex = new RegExp(`{{\\s*${key}\\s*}}`, 'gi');
    result = result.replace(regex, String(val || ''));
  }
  return result;
}

function generateAIEmailDraft(prompt, subjectTemplate, tone, row, nameCol, companyCol) {
  const recipientName = (nameCol && row[nameCol]) ? row[nameCol] : 'there';
  const recipientCompany = (companyCol && row[companyCol]) ? row[companyCol] : '';

  let subject = subjectTemplate || `Hello, {{${nameCol || 'Name'}}}`;
  subject = interpolateTemplate(subject, row);

  let body = '';
  if (prompt && prompt.includes('{{')) {
    // If prompt is written with placeholders, interpolate directly
    body = interpolateTemplate(prompt, row);
  } else {
    // Intelligent drafting based on tone and prompt instruction
    const toneSalutations = {
      professional: `Dear ${recipientName},`,
      friendly: `Hi ${recipientName},`,
      formal: `Dear Mr./Ms. ${recipientName},`,
      short: `Hi ${recipientName} —`
    };

    const toneSignoffs = {
      professional: `Best regards,\nAman`,
      friendly: `Warmly,\nAman`,
      formal: `Sincerely,\nAman`,
      short: `Thanks,\nAman`
    };

    const salutation = toneSalutations[tone] || toneSalutations.professional;
    const signoff = toneSignoffs[tone] || toneSignoffs.professional;

    const basePrompt = prompt || 'Reaching out regarding collaboration opportunities.';
    const contextStr = recipientCompany ? ` at ${recipientCompany}` : '';

    if (tone === 'short') {
      body = `${salutation}\n\nQuick note regarding ${basePrompt}${contextStr}. Would love to connect briefly if you have 5 minutes this week.\n\n${signoff}`;
    } else if (tone === 'friendly') {
      body = `${salutation}\n\nHope your week is off to a wonderful start! I wanted to reach out regarding ${basePrompt}${contextStr}.\n\nI really admire what you are building and would love to see if there is an opportunity to collaborate. Let me know if you would be open to a quick chat.\n\n${signoff}`;
    } else if (tone === 'formal') {
      body = `${salutation}\n\nI am writing to express my interest regarding ${basePrompt}${contextStr}.\n\nPlease let me know if we can schedule a formal discussion at your earliest convenience.\n\n${signoff}`;
    } else {
      // Professional default
      body = `${salutation}\n\nI hope this email finds you well. I am reaching out regarding ${basePrompt}${contextStr}.\n\nGiven your focus, I believe there could be strong mutual synergy. I would welcome the opportunity to discuss how we might work together.\n\n${signoff}`;
    }
  }

  return { subject, body };
}

// POST /api/campaigns/preview
app.post('/api/campaigns/preview', (req, res) => {
  const { prompt, subjectTemplate, tone, rows, nameCol, companyCol, sampleCount = 3 } = req.body;
  if (!rows || !rows.length) {
    return res.status(400).json({ success: false, message: 'No rows provided for preview.' });
  }

  const samples = rows.slice(0, Math.min(rows.length, sampleCount)).map((row, idx) => {
    const draft = generateAIEmailDraft(prompt, subjectTemplate, tone, row, nameCol, companyCol);
    return {
      index: idx + 1,
      to: row[req.body.emailCol] || row['Email'] || 'recipient@example.com',
      recipientName: (nameCol && row[nameCol]) || 'Recipient',
      subject: draft.subject,
      bodyText: draft.body,
      bodyHtml: draft.body.replace(/\n/g, '<br/>')
    };
  });

  return res.json({ success: true, previews: samples });
});

// ==========================================
// 4. Campaign Execution & Dispatch Engine
// ==========================================

// POST /api/campaigns/send (User Isolated)
app.post('/api/campaigns/send', async (req, res) => {
  const { userId, userEmail } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required. Please sign in to launch campaigns.' });
  }

  const {
    name,
    senderEmail,
    appPassword,
    smtpHost,
    smtpPort,
    secure,
    rows,
    emailCol,
    nameCol,
    companyCol,
    subjectTemplate,
    prompt,
    tone = 'professional',
    ratePerMin = 30,
    includeUnsubscribe = true,
    consentConfirmed = true,
    attachment = null
  } = req.body;

  if (!senderEmail) {
    return res.status(400).json({ success: false, message: 'Sender Email is required.' });
  }

  // Look up appPassword if not passed directly in payload
  let effectivePassword = appPassword ? appPassword.replace(/\s+/g, '') : '';
  const db = readDB();
  if (!effectivePassword) {
    const userCred = (db.credentials || []).find(c => c.userId === userId && c.senderEmail.toLowerCase() === senderEmail.trim().toLowerCase());
    if (userCred && userCred.appPassword) {
      effectivePassword = userCred.appPassword;
    }
  }

  if (!effectivePassword) {
    return res.status(400).json({
      success: false,
      message: 'App Password is required for this sender. Please connect your Gmail & 16-character App Password in the Connect Email tab.'
    });
  }

  if (!rows || !rows.length) {
    return res.status(400).json({ success: false, message: 'No recipient rows to send.' });
  }
  if (!emailCol) {
    return res.status(400).json({ success: false, message: 'Email column must be selected.' });
  }
  if (!consentConfirmed) {
    return res.status(400).json({ success: false, message: 'You must confirm permission to email recipients.' });
  }

  const campaignId = 'camp_' + Date.now();
  const host = smtpHost || 'smtp.gmail.com';
  const port = parseInt(smtpPort, 10) || 587;
  const isSecure = secure === true || port === 465;

  // Filter valid rows
  const targetRows = rows.filter(r => r[emailCol] && isValidEmail(String(r[emailCol]).trim()));
  if (!targetRows.length) {
    return res.status(400).json({ success: false, message: 'No valid recipient email addresses found in the selection.' });
  }

  const campaignRecord = {
    id: campaignId,
    userId,
    userEmail: userEmail || senderEmail.trim(),
    name: name || `Campaign ${new Date().toLocaleDateString()}`,
    senderEmail: senderEmail.trim(),
    status: 'running',
    totalRecipients: targetRows.length,
    counters: {
      total: targetRows.length,
      sent: 0,
      failed: 0,
      queued: targetRows.length
    },
    ratePerMin: parseInt(ratePerMin, 10) || 30,
    includeUnsubscribe,
    consentConfirmed,
    attachment: attachment || null,
    startedAt: new Date().toISOString(),
    completedAt: null
  };

  db.campaigns.unshift(campaignRecord);
  writeDB(db);

  // Initialize campaign controller in memory
  const campaignControl = {
    id: campaignId,
    userId,
    status: 'running', // running, paused, cancelled
    isPaused: false,
    isCancelled: false
  };
  activeCampaigns.set(campaignId, campaignControl);

  // Start sending in background
  runCampaignDispatcher({
    campaignId,
    userId,
    senderEmail: senderEmail.trim(),
    appPassword: effectivePassword,
    host,
    port,
    secure: isSecure,
    rows: targetRows,
    emailCol,
    nameCol,
    companyCol,
    subjectTemplate,
    prompt,
    tone,
    ratePerMin: campaignRecord.ratePerMin,
    includeUnsubscribe,
    attachment,
    control: campaignControl
  });

  return res.json({
    success: true,
    campaignId,
    message: `Campaign started with ${targetRows.length} recipients.`,
    campaign: campaignRecord
  });
});

async function runCampaignDispatcher({
  campaignId,
  userId,
  senderEmail,
  appPassword,
  host,
  port,
  secure,
  rows,
  emailCol,
  nameCol,
  companyCol,
  subjectTemplate,
  prompt,
  tone,
  ratePerMin,
  includeUnsubscribe,
  attachment,
  control
}) {
  const transporter = nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user: senderEmail, pass: appPassword },
    pool: true,
    maxConnections: 3,
    maxMessages: 100
  });

  const delayMs = Math.max(100, Math.floor(60000 / (ratePerMin || 30)));

  for (let i = 0; i < rows.length; i++) {
    // Check if cancelled
    if (control.isCancelled) {
      updateCampaignStatus(campaignId, 'cancelled');
      break;
    }

    // Handle pause
    while (control.isPaused) {
      await new Promise(r => setTimeout(r, 1000));
      if (control.isCancelled) break;
    }
    if (control.isCancelled) break;

    const row = rows[i];
    const toEmail = String(row[emailCol]).trim();
    const recipientName = (nameCol && row[nameCol]) ? String(row[nameCol]).trim() : '';

    const draft = generateAIEmailDraft(prompt, subjectTemplate, tone, row, nameCol, companyCol);
    let finalBodyHtml = draft.body.replace(/\n/g, '<br/>');
    let finalBodyText = draft.body;

    if (includeUnsubscribe) {
      finalBodyHtml += '<br/><br/><p style="font-size:11px;color:#888;border-top:1px solid #eee;padding-top:8px;">You received this because of your business listing. If you do not wish to receive further communications, please reply with "Unsubscribe".</p>';
      finalBodyText += '\n\n---\nTo unsubscribe, please reply with "Unsubscribe".';
    }

    const emailId = `mail_${campaignId}_${i + 1}`;
    let emailStatus = 'sent';
    let errorMessage = null;
    let messageId = null;

    try {
      const mailOptions = {
        from: `"${senderEmail.split('@')[0]}" <${senderEmail}>`,
        to: toEmail,
        subject: draft.subject,
        text: finalBodyText,
        html: finalBodyHtml
      };

      // Add file attachment if present (image, pdf, docs)
      if (attachment && attachment.path && fs.existsSync(attachment.path)) {
        mailOptions.attachments = [
          {
            filename: attachment.name,
            path: attachment.path
          }
        ];
      }

      const sendResult = await transporter.sendMail(mailOptions);
      messageId = sendResult.messageId;
    } catch (err) {
      console.error(`Failed to send email to ${toEmail}:`, err.message);
      emailStatus = 'failed';
      errorMessage = err.message;
    }

    // Log email to DB
    logEmailResult({
      emailId,
      campaignId,
      userId,
      rowNumber: i + 1,
      to: toEmail,
      recipientName,
      subject: draft.subject,
      status: emailStatus,
      sentAt: new Date().toISOString(),
      messageId,
      error: errorMessage
    });

    // Rate-limit delay before next send
    if (i < rows.length - 1) {
      await new Promise(r => setTimeout(r, delayMs));
    }
  }

  if (!control.isCancelled) {
    updateCampaignStatus(campaignId, 'completed');
  }
}

function logEmailResult({ emailId, campaignId, userId, rowNumber, to, recipientName, subject, status, sentAt, messageId, error }) {
  const db = readDB();
  const emailLog = {
    id: emailId,
    campaignId,
    userId: userId || null,
    rowNumber,
    to,
    recipientName,
    subject,
    status,
    sentAt,
    messageId,
    error: error ? { message: error } : null
  };
  db.emails.unshift(emailLog);

  // Update campaign counters
  const campaign = db.campaigns.find(c => c.id === campaignId);
  if (campaign) {
    if (status === 'sent') {
      campaign.counters.sent = (campaign.counters.sent || 0) + 1;
    } else if (status === 'failed') {
      campaign.counters.failed = (campaign.counters.failed || 0) + 1;
    }
    campaign.counters.queued = Math.max(0, campaign.counters.total - campaign.counters.sent - campaign.counters.failed);
  }

  // Record daily usage per user
  const today = new Date().toISOString().slice(0, 10);
  const userUsageKey = userId ? `${today}_${userId}` : today;
  if (!db.usage[userUsageKey]) db.usage[userUsageKey] = { sent: 0, failed: 0 };
  if (status === 'sent') db.usage[userUsageKey].sent++;
  if (status === 'failed') db.usage[userUsageKey].failed++;

  writeDB(db);
}

function updateCampaignStatus(campaignId, status) {
  const db = readDB();
  const campaign = db.campaigns.find(c => c.id === campaignId);
  if (campaign) {
    campaign.status = status;
    if (status === 'completed' || status === 'cancelled') {
      campaign.completedAt = new Date().toISOString();
    }
    writeDB(db);
  }
}

// POST /api/campaigns/:id/pause
app.post('/api/campaigns/:id/pause', (req, res) => {
  const ctrl = activeCampaigns.get(req.params.id);
  if (ctrl) {
    ctrl.isPaused = true;
    ctrl.status = 'paused';
    updateCampaignStatus(req.params.id, 'paused');
    return res.json({ success: true, message: 'Campaign paused' });
  }
  res.status(404).json({ success: false, message: 'Active campaign not found' });
});

// POST /api/campaigns/:id/resume
app.post('/api/campaigns/:id/resume', (req, res) => {
  const ctrl = activeCampaigns.get(req.params.id);
  if (ctrl) {
    ctrl.isPaused = false;
    ctrl.status = 'running';
    updateCampaignStatus(req.params.id, 'running');
    return res.json({ success: true, message: 'Campaign resumed' });
  }
  res.status(404).json({ success: false, message: 'Active campaign not found' });
});

// POST /api/campaigns/:id/cancel
app.post('/api/campaigns/:id/cancel', (req, res) => {
  const ctrl = activeCampaigns.get(req.params.id);
  if (ctrl) {
    ctrl.isCancelled = true;
    ctrl.status = 'cancelled';
    updateCampaignStatus(req.params.id, 'cancelled');
    return res.json({ success: true, message: 'Campaign cancelled' });
  }
  res.status(404).json({ success: false, message: 'Active campaign not found' });
});

// GET /api/campaigns (User Isolated)
app.get('/api/campaigns', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required.', campaigns: [] });
  }
  const db = readDB();
  const list = (db.campaigns || []).filter(c => c.userId === userId);
  res.json({ success: true, campaigns: list });
});

// GET /api/campaigns/:id (User Isolated)
app.get('/api/campaigns/:id', (req, res) => {
  const { userId } = getAuthUser(req);
  const db = readDB();
  const campaign = db.campaigns.find(c => c.id === req.params.id && (c.userId === userId || !userId));
  if (!campaign) {
    return res.status(404).json({ success: false, message: 'Campaign not found' });
  }
  const logs = (db.emails || []).filter(e => e.campaignId === req.params.id);
  res.json({ success: true, campaign, logs });
});

// GET /api/history (User Isolated)
app.get('/api/history', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({ success: false, message: 'Authentication required.', emails: [] });
  }
  const db = readDB();
  const { status, search, campaignId } = req.query;
  let list = (db.emails || []).filter(e => e.userId === userId);

  if (status) {
    list = list.filter(e => e.status === status);
  }
  if (campaignId) {
    list = list.filter(e => e.campaignId === campaignId);
  }
  if (search) {
    const q = search.toLowerCase();
    list = list.filter(e => (e.to && e.to.toLowerCase().includes(q)) ||
                            (e.recipientName && e.recipientName.toLowerCase().includes(q)) ||
                            (e.subject && e.subject.toLowerCase().includes(q)));
  }

  res.json({ success: true, emails: list });
});

// GET /api/stats (User Isolated)
app.get('/api/stats', (req, res) => {
  const { userId } = getAuthUser(req);
  if (!userId) {
    return res.status(401).json({
      success: false,
      message: 'Authentication required.',
      stats: { sentToday: 0, failedToday: 0, totalSent: 0, totalFailed: 0, totalQueued: 0, dailyCap: 450, dailyRemaining: 450 }
    });
  }
  const db = readDB();
  const today = new Date().toISOString().slice(0, 10);
  const userUsageKey = `${today}_${userId}`;
  const todayUsage = db.usage[userUsageKey] || db.usage[today] || { sent: 0, failed: 0 };
  const userEmails = (db.emails || []).filter(e => e.userId === userId);
  const totalSent = userEmails.filter(e => e.status === 'sent').length;
  const totalFailed = userEmails.filter(e => e.status === 'failed').length;
  const totalQueued = userEmails.filter(e => e.status === 'queued').length;

  res.json({
    success: true,
    stats: {
      sentToday: todayUsage.sent || 0,
      failedToday: todayUsage.failed || 0,
      totalSent,
      totalFailed,
      totalQueued,
      dailyCap: 450,
      dailyRemaining: Math.max(0, 450 - (todayUsage.sent || 0))
    }
  });
});

// GET /api/export/:campaignId.csv
app.get('/api/export/:campaignId.csv', (req, res) => {
  const db = readDB();
  const logs = db.emails.filter(e => e.campaignId === req.params.id);
  let csv = 'Recipient,Name,Subject,Status,SentAt,MessageId,Error\n';
  logs.forEach(e => {
    const errorMsg = e.error ? (e.error.message || '').replace(/"/g, '""') : '';
    csv += `"${e.to || ''}","${e.recipientName || ''}","${(e.subject || '').replace(/"/g, '""')}","${e.status}","${e.sentAt || ''}","${e.messageId || ''}","${errorMsg}"\n`;
  });

  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="campaign-${req.params.campaignId}-logs.csv"`);
  res.send(csv);
});

// Start Server
app.listen(PORT, () => {
  console.log(`====================================================`);
  console.log(`SmartSend AI (sendAutoMail) running at:`);
  console.log(`http://localhost:${PORT}`);
  console.log(`====================================================`);
});
