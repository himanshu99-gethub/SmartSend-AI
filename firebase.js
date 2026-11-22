import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Data paths
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

// Firebase Admin initialization (conditional)
let firebaseApp = null;
let firestoreDb = null;
let isFirebaseActive = false;

async function initFirebaseAdmin() {
  const projectId = process.env.FIREBASE_PROJECT_ID || 'send-mail-f73f9';
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY
    ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n')
    : null;

  // Firebase Admin SDK requires service account credentials on backend
  if (projectId && clientEmail && privateKey) {
    try {
      const { initializeApp, cert, getApps } = await import('firebase-admin/app');
      const { getFirestore } = await import('firebase-admin/firestore');

      if (!getApps().length) {
        firebaseApp = initializeApp({
          credential: cert({ projectId, clientEmail, privateKey }),
          projectId
        });
      }
      firestoreDb = getFirestore();
      isFirebaseActive = true;
      console.log('>>> [Firebase Admin] Connected to Cloud Firestore project:', projectId);
    } catch (err) {
      console.warn('>>> [Firebase Admin] Service account notice:', err.message);
      isFirebaseActive = false;
    }
  } else {
    isFirebaseActive = false;
    console.log('>>> [Firebase] Project set to send-mail-f73f9. Web Client SDK active, backend running resilient local sync.');
  }
}

// Initial call
initFirebaseAdmin();

// Local DB Helpers
function readLocalDB() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      const initial = {
        users: [{
          uid: 'user_demo',
          email: 'demo@smartsend.ai',
          displayName: 'Aman (Demo)',
          plan: 'free',
          dailyCap: 450,
          createdAt: new Date().toISOString()
        }],
        credentials: [],
        uploads: [],
        campaigns: [],
        emails: [],
        usage: {}
      };
      fs.writeFileSync(DB_FILE, JSON.stringify(initial, null, 2));
      return initial;
    }
    return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (err) {
    return { users: [], credentials: [], uploads: [], campaigns: [], emails: [], usage: {} };
  }
}

function writeLocalDB(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  } catch (err) {
    console.error('Error writing local DB:', err);
  }
}

// Password hashing helper
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// ==========================================
// User Authentication & Profile
// ==========================================

export async function authRegister({ email, password, displayName }) {
  const db = readLocalDB();
  const normalizedEmail = email.trim().toLowerCase();

  const existing = db.users.find(u => u.email === normalizedEmail);
  if (existing) {
    throw new Error('An account with this email already exists.');
  }

  const uid = 'usr_' + Date.now();
  const newUser = {
    uid,
    email: normalizedEmail,
    displayName: displayName ? displayName.trim() : normalizedEmail.split('@')[0],
    passwordHash: hashPassword(password),
    plan: 'free',
    dailyCap: 450,
    createdAt: new Date().toISOString(),
    lastLoginAt: new Date().toISOString()
  };

  db.users.push(newUser);
  writeLocalDB(db);

  if (isFirebaseActive && firestoreDb) {
    try {
      await firestoreDb.collection('users').doc(uid).set({
        email: newUser.email,
        displayName: newUser.displayName,
        plan: newUser.plan,
        dailyCap: newUser.dailyCap,
        createdAt: newUser.createdAt
      });
    } catch (e) {
      console.error('Firestore saveUser error:', e);
    }
  }

  const { passwordHash, ...userClean } = newUser;
  return userClean;
}

export async function authLogin({ email, password }) {
  const db = readLocalDB();
  const normalizedEmail = email.trim().toLowerCase();
  const hashed = hashPassword(password);

  const user = db.users.find(u => u.email === normalizedEmail && u.passwordHash === hashed);
  if (!user) {
    throw new Error('Invalid email address or password.');
  }

  user.lastLoginAt = new Date().toISOString();
  writeLocalDB(db);

  const { passwordHash, ...userClean } = user;
  return userClean;
}

export async function authGoogleLogin({ email, displayName, googleUid }) {
  const db = readLocalDB();
  const normalizedEmail = email.trim().toLowerCase();

  let user = db.users.find(u => u.email === normalizedEmail);
  if (!user) {
    user = {
      uid: googleUid || 'usr_g_' + Date.now(),
      email: normalizedEmail,
      displayName: displayName || normalizedEmail.split('@')[0],
      provider: 'google',
      plan: 'free',
      dailyCap: 450,
      createdAt: new Date().toISOString(),
      lastLoginAt: new Date().toISOString()
    };
    db.users.push(user);
  } else {
    user.lastLoginAt = new Date().toISOString();
  }
  writeLocalDB(db);

  if (isFirebaseActive && firestoreDb) {
    try {
      await firestoreDb.collection('users').doc(user.uid).set(user, { merge: true });
    } catch (e) {
      console.error('Firestore googleLogin error:', e);
    }
  }

  const { passwordHash, ...userClean } = user;
  return userClean;
}

// ==========================================
// Database Operations (Matching 05_BACKEND_SCHEMA.md)
// ==========================================

export async function getCampaigns(uid) {
  const db = readLocalDB();
  let list = db.campaigns || [];
  if (uid) {
    list = list.filter(c => !c.uid || c.uid === uid);
  }
  return list;
}

export async function getCampaignById(campaignId) {
  const db = readLocalDB();
  const campaign = db.campaigns.find(c => c.id === campaignId);
  const logs = db.emails.filter(e => e.campaignId === campaignId);
  return { campaign, logs };
}

export async function saveCampaignRecord(campaign) {
  const db = readLocalDB();
  db.campaigns.unshift(campaign);
  writeLocalDB(db);

  if (isFirebaseActive && firestoreDb) {
    try {
      const uid = campaign.uid || 'default';
      await firestoreDb.collection('users').doc(uid).collection('campaigns').doc(campaign.id).set(campaign);
    } catch (e) {
      console.error('Firestore saveCampaign error:', e);
    }
  }
}

export async function updateCampaignRecord(campaignId, updates) {
  const db = readLocalDB();
  const c = db.campaigns.find(camp => camp.id === campaignId);
  if (c) {
    Object.assign(c, updates);
    writeLocalDB(db);
  }

  if (isFirebaseActive && firestoreDb && c) {
    try {
      const uid = c.uid || 'default';
      await firestoreDb.collection('users').doc(uid).collection('campaigns').doc(campaignId).update(updates);
    } catch (e) {
      console.error('Firestore updateCampaign error:', e);
    }
  }
}

export async function logEmailRecord(emailLog) {
  const db = readLocalDB();
  db.emails.unshift(emailLog);

  // Update campaign counters
  const campaign = db.campaigns.find(c => c.id === emailLog.campaignId);
  if (campaign) {
    if (emailLog.status === 'sent') campaign.counters.sent = (campaign.counters.sent || 0) + 1;
    if (emailLog.status === 'failed') campaign.counters.failed = (campaign.counters.failed || 0) + 1;
    campaign.counters.queued = Math.max(0, campaign.counters.total - campaign.counters.sent - campaign.counters.failed);
  }

  // Update daily usage
  const today = new Date().toISOString().slice(0, 10);
  if (!db.usage[today]) db.usage[today] = { sent: 0, failed: 0 };
  if (emailLog.status === 'sent') db.usage[today].sent++;
  if (emailLog.status === 'failed') db.usage[today].failed++;

  writeLocalDB(db);

  if (isFirebaseActive && firestoreDb) {
    try {
      const uid = campaign?.uid || 'default';
      await firestoreDb.collection('users').doc(uid)
        .collection('campaigns').doc(emailLog.campaignId)
        .collection('emails').doc(emailLog.id).set(emailLog);
    } catch (e) {
      console.error('Firestore logEmail error:', e);
    }
  }
}

export async function getEmailHistory({ uid, status, search, campaignId }) {
  const db = readLocalDB();
  let list = db.emails || [];

  if (status) list = list.filter(e => e.status === status);
  if (campaignId) list = list.filter(e => e.campaignId === campaignId);
  if (search) {
    const q = search.toLowerCase();
    list = list.filter(e =>
      (e.to && e.to.toLowerCase().includes(q)) ||
      (e.recipientName && e.recipientName.toLowerCase().includes(q)) ||
      (e.subject && e.subject.toLowerCase().includes(q))
    );
  }

  return list;
}

export async function getStats(uid) {
  const db = readLocalDB();
  const today = new Date().toISOString().slice(0, 10);
  const todayUsage = db.usage[today] || { sent: 0, failed: 0 };
  const allEmails = db.emails || [];

  const totalSent = allEmails.filter(e => e.status === 'sent').length;
  const totalFailed = allEmails.filter(e => e.status === 'failed').length;
  const totalQueued = allEmails.filter(e => e.status === 'queued').length;

  return {
    sentToday: todayUsage.sent,
    failedToday: todayUsage.failed,
    totalSent,
    totalFailed,
    totalQueued,
    dailyCap: 450,
    dailyRemaining: Math.max(0, 450 - todayUsage.sent),
    isFirebaseActive
  };
}

export function isFirestoreConnected() {
  return isFirebaseActive;
}
