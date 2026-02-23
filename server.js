const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const nacl = require("tweetnacl");
const multer = require("multer");
const { parse: parseCsv } = require("csv-parse/sync");
const nodemailer = require("nodemailer");
const PDFDocument = require("pdfkit");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 10000;

const TELNYX_API_BASE = "https://api.telnyx.com/v2";
const TELNYX_HTTP_TIMEOUT_MS = Math.max(2000, Number(process.env.TELNYX_HTTP_TIMEOUT_MS || 5000));
const IS_RENDER_RUNTIME = Boolean(process.env.RENDER || process.env.RENDER_SERVICE_ID);
const RENDER_PERSISTENT_ROOT = "/var/data";
const DEFAULT_RENDER_DATA_DIR = path.join(RENDER_PERSISTENT_ROOT, "telnyx-fax-office-app");
const DATA_DIR =
  process.env.DATA_DIR ||
  (IS_RENDER_RUNTIME && fs.existsSync(RENDER_PERSISTENT_ROOT)
    ? DEFAULT_RENDER_DATA_DIR
    : path.join(__dirname, "data"));
const PUBLIC_DIR = path.join(__dirname, "public");
const STORE_FILE = path.join(DATA_DIR, "faxes.json");
const FAX_ARCHIVE_FILE = path.join(DATA_DIR, "faxes_archive.json");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const CONTACTS_FILE = path.join(DATA_DIR, "contacts.json");
const BULK_JOBS_FILE = path.join(DATA_DIR, "bulk_jobs.json");
const LOCAL_SESSIONS_FILE = path.join(DATA_DIR, "sessions_local.json");
const TENANTS_FILE = path.join(DATA_DIR, "tenants.json");
const AUDIT_EVENTS_FILE = path.join(DATA_DIR, "audit_events.json");
const IDEMPOTENCY_FILE = path.join(DATA_DIR, "idempotency_keys.json");
const BILLING_FILE = path.join(DATA_DIR, "billing.json");
const UPLOADS_DIR = path.join(DATA_DIR, "uploads");
const MAX_CONTACTS = 3000;
const MAX_SEND_RECIPIENTS = 100;
const MAX_UPLOAD_BATCH_FILES = 5;
const FAX_HISTORY_VISIBLE_LIMIT = 50;
const DEFAULT_TENANT_ID = (process.env.DEFAULT_TENANT_ID || "default").trim() || "default";
const MULTI_TENANT_ENABLED = process.env.MULTI_TENANT_ENABLED !== "false";
const COMMERCIAL_ENFORCEMENTS_ENABLED = process.env.COMMERCIAL_ENFORCEMENTS_ENABLED !== "false";
const BILLING_MODE = (process.env.BILLING_MODE || "free").toString().trim().toLowerCase() === "paid"
  ? "paid"
  : "free";
const IDEMPOTENCY_TTL_SECONDS = Math.max(60, Number(process.env.IDEMPOTENCY_TTL_SECONDS || 24 * 60 * 60));
const PLAN_LIMITS = {
  free: {
    max_contacts: 3000,
    max_users: 25,
    max_recipients_per_send: 100
  },
  starter: {
    max_contacts: 3000,
    max_users: 10,
    max_recipients_per_send: 25
  },
  pro: {
    max_contacts: 10000,
    max_users: 50,
    max_recipients_per_send: 100
  },
  enterprise: {
    max_contacts: 50000,
    max_users: 500,
    max_recipients_per_send: 500
  }
};
const BILLING_SUPPORTED_PLANS = Object.keys(PLAN_LIMITS).filter((plan) => plan !== "free");
const CLOUDFLARE_API_BASE = "https://api.cloudflare.com/client/v4";
const D1_ACCOUNT_ID = (process.env.CLOUDFLARE_ACCOUNT_ID || "").trim();
const D1_DATABASE_ID = (process.env.CLOUDFLARE_D1_DATABASE_ID || "").trim();
const D1_API_TOKEN = (process.env.CLOUDFLARE_API_TOKEN || "").trim();
const D1_API_KEY = (process.env.CLOUDFLARE_API_KEY || "").trim();
const D1_EMAIL = (process.env.CLOUDFLARE_EMAIL || "").trim();
const D1_USERS_ENABLED = Boolean(
  D1_ACCOUNT_ID && D1_DATABASE_ID && (D1_API_TOKEN || (D1_API_KEY && D1_EMAIL))
);
const D1_APP_STORES_ENABLED = D1_USERS_ENABLED;
const TELNYX_WEBHOOK_PUBLIC_KEY = (process.env.TELNYX_WEBHOOK_PUBLIC_KEY || "").trim();
const WEBHOOK_SIGNATURE_REQUIRED =
  process.env.WEBHOOK_SIGNATURE_REQUIRED === "true" ||
  (process.env.WEBHOOK_SIGNATURE_REQUIRED === undefined && Boolean(TELNYX_WEBHOOK_PUBLIC_KEY));
const WEBHOOK_MAX_AGE_SECONDS = Math.max(30, Number(process.env.WEBHOOK_MAX_AGE_SECONDS || 300));
const MEDIA_URL_SIGNING_SECRET = (process.env.MEDIA_URL_SIGNING_SECRET || "").trim();
const MEDIA_URL_TTL_SECONDS = Math.max(60, Number(process.env.MEDIA_URL_TTL_SECONDS || 3600));
const UPLOAD_RETENTION_SECONDS = Math.max(
  MEDIA_URL_TTL_SECONDS,
  Number(process.env.UPLOAD_RETENTION_SECONDS || 2 * 24 * 60 * 60)
);
const AUTH_RATE_WINDOW_MS = Math.max(60_000, Number(process.env.AUTH_RATE_WINDOW_MS || 15 * 60 * 1000));
const AUTH_RATE_MAX_ATTEMPTS_PER_IP = Math.max(
  5,
  Number(process.env.AUTH_RATE_MAX_ATTEMPTS_PER_IP || 30)
);
const AUTH_LOCKOUT_THRESHOLD = Math.max(3, Number(process.env.AUTH_LOCKOUT_THRESHOLD || 8));
const AUTH_LOCKOUT_MS = Math.max(60_000, Number(process.env.AUTH_LOCKOUT_MS || 15 * 60 * 1000));
const BULK_WORKER_POLL_MS = Math.max(5_000, Number(process.env.BULK_WORKER_POLL_MS || 15_000));
const SESSION_MAX_AGE_MS = Math.max(60_000, Number(process.env.SESSION_MAX_AGE_MS || 12 * 60 * 60 * 1000));
const LOCAL_SESSION_STORE_ENABLED = process.env.LOCAL_SESSION_STORE_ENABLED !== "false";
const D1_SYNC_STORE_FILENAMES = new Set([
  "faxes.json",
  "faxes_archive.json",
  "config.json",
  "contacts.json",
  "bulk_jobs.json"
]);

let isBulkProcessorRunning = false;
let isD1AppStoreHydration = false;
let d1AppStoresReady = false;
let d1StoreSyncTimer = null;
const pendingD1StoreSync = new Map();
let bulkWorkerInterval = null;
let uploadCleanupInterval = null;
const authIpAttemptState = new Map();
const authUserAttemptState = new Map();

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.SESSION_SECRET) {
  console.warn("SESSION_SECRET not set. A temporary secret is being used for this process.");
}
const effectiveMediaUrlSigningSecret = MEDIA_URL_SIGNING_SECRET || sessionSecret;

function defaultTenantPlan() {
  return BILLING_MODE === "paid" ? "starter" : "free";
}

app.set("trust proxy", 1);
app.use(
  express.json({
    limit: "2mb",
    verify: (req, res, buffer) => {
      req.rawBody = buffer?.toString("utf8") || "";
    }
  })
);
app.use(express.urlencoded({ extended: true }));
app.use(express.static(PUBLIC_DIR));

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
}

function ensureUploadsDir() {
  if (!fs.existsSync(UPLOADS_DIR)) {
    fs.mkdirSync(UPLOADS_DIR, { recursive: true });
  }
}

function readJson(filePath, fallback) {
  ensureDataDir();
  if (!fs.existsSync(filePath)) {
    return fallback;
  }
  try {
    return JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch (error) {
    console.warn(`Invalid JSON in ${filePath}. Falling back to defaults.`);
    return fallback;
  }
}

function writeJson(filePath, value) {
  ensureDataDir();
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
  scheduleD1StoreSnapshot(filePath, value);
}

function normalizeE164(value) {
  if (!value) {
    return "";
  }
  return value.replace(/[^\d+]/g, "");
}

function isE164(value) {
  return /^\+[1-9]\d{7,14}$/.test(value || "");
}

function parseMediaUrlsInput(value) {
  if (Array.isArray(value)) {
    return Array.from(
      new Set(
        value
          .flatMap((item) => (item || "").toString().split(/[\n,]+/))
          .map((item) => item.trim())
          .filter(Boolean)
      )
    );
  }

  return Array.from(
    new Set(
      (value || "")
        .toString()
        .split(/[\n,]+/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function isHttpsMediaUrl(value) {
  try {
    const parsed = new URL((value || "").toString().trim());
    return parsed.protocol === "https:";
  } catch (error) {
    return false;
  }
}

function parseRecipientNumbersInput(value) {
  const tokens = parseRecipientTokensInput(value);
  return Array.from(new Set(tokens.map((item) => normalizeE164(item)).filter(Boolean)));
}

function parseRecipientTokensInput(value) {
  if (Array.isArray(value)) {
    return Array.from(
      new Set(
        value
          .flatMap((item) => (item || "").toString().split(/[\n,;]+/))
          .map((item) => item.trim())
          .filter(Boolean)
      )
    );
  }

  return Array.from(
    new Set(
      (value || "")
        .toString()
        .split(/[\n,;]+/)
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function normalizeUsername(value) {
  return (value || "").trim().toLowerCase();
}

function normalizeTenantId(value) {
  const tenant = (value || "").toString().trim().toLowerCase();
  if (!tenant) return DEFAULT_TENANT_ID;
  if (!/^[a-z0-9._-]{2,64}$/.test(tenant)) {
    return DEFAULT_TENANT_ID;
  }
  return tenant;
}

function getTenantIdFromRequest(req) {
  if (!MULTI_TENANT_ENABLED) {
    return DEFAULT_TENANT_ID;
  }
  if (req.session?.user?.tenant_id) {
    const sessionTenant = normalizeTenantId(req.session.user.tenant_id);
    return sessionTenant;
  }
  const headerTenant = normalizeTenantId(req.get("x-tenant-id"));
  if (headerTenant && headerTenant !== DEFAULT_TENANT_ID) {
    return headerTenant;
  }
  const bodyTenant = normalizeTenantId(req.body?.tenant_id);
  if (bodyTenant && bodyTenant !== DEFAULT_TENANT_ID) {
    return bodyTenant;
  }
  const queryTenant = normalizeTenantId(req.query?.tenant_id);
  if (queryTenant && queryTenant !== DEFAULT_TENANT_ID) {
    return queryTenant;
  }
  return DEFAULT_TENANT_ID;
}

function isEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test((value || "").trim());
}

function normalizeTags(input) {
  const asArray = Array.isArray(input)
    ? input
    : (input || "")
        .toString()
        .split(",");

  return Array.from(
    new Set(
      asArray
        .map((item) => item.toString().trim().toLowerCase())
        .filter(Boolean)
    )
  );
}

function safeBasename(value) {
  return path.basename((value || "").toString().trim());
}

function signMediaAccess({ filename, exp }) {
  return crypto
    .createHmac("sha256", effectiveMediaUrlSigningSecret)
    .update(`${filename}|${exp}`)
    .digest("base64url");
}

function buildSignedMediaUrl(req, filename, ttlSeconds = MEDIA_URL_TTL_SECONDS) {
  const safeName = safeBasename(filename);
  const exp = Math.floor(Date.now() / 1000) + Math.max(60, Number(ttlSeconds || MEDIA_URL_TTL_SECONDS));
  const sig = signMediaAccess({ filename: safeName, exp });
  return `${req.protocol}://${req.get("host")}/media/${encodeURIComponent(safeName)}?exp=${exp}&sig=${encodeURIComponent(sig)}`;
}

function verifySignedMediaAccess({ filename, exp, sig }) {
  const safeName = safeBasename(filename);
  const expNum = Number(exp);
  if (!safeName || !Number.isFinite(expNum) || expNum <= 0) {
    return false;
  }
  if (Math.floor(Date.now() / 1000) > expNum) {
    return false;
  }
  const expected = signMediaAccess({ filename: safeName, exp: expNum });
  const provided = (sig || "").toString();
  const expectedBuf = Buffer.from(expected);
  const providedBuf = Buffer.from(provided);
  if (!expectedBuf.length || expectedBuf.length !== providedBuf.length) {
    return false;
  }
  return crypto.timingSafeEqual(expectedBuf, providedBuf);
}

function getAuthClientIp(req) {
  return (req.ip || req.headers["x-forwarded-for"] || req.connection?.remoteAddress || "unknown")
    .toString()
    .split(",")[0]
    .trim();
}

function pruneAttemptMap(map, cutoffMs) {
  const now = Date.now();
  map.forEach((entry, key) => {
    if (!entry) {
      map.delete(key);
      return;
    }
    if ((entry.lastFailedAt || 0) < now - cutoffMs && (entry.lockedUntil || 0) < now) {
      map.delete(key);
    }
  });
}

function getAttemptState(map, key) {
  const k = (key || "").toString();
  if (!k) return null;
  const now = Date.now();
  const existing = map.get(k) || {
    count: 0,
    firstFailedAt: 0,
    lastFailedAt: 0,
    lockedUntil: 0
  };

  if (!existing.firstFailedAt || now - existing.firstFailedAt > AUTH_RATE_WINDOW_MS) {
    existing.count = 0;
    existing.firstFailedAt = now;
  }
  map.set(k, existing);
  return existing;
}

function registerFailedAuthAttempt({ ip, username }) {
  const now = Date.now();

  const ipState = getAttemptState(authIpAttemptState, ip);
  if (ipState) {
    ipState.count += 1;
    ipState.lastFailedAt = now;
    authIpAttemptState.set(ip, ipState);
  }

  const normalizedUsername = normalizeUsername(username);
  if (normalizedUsername) {
    const userState = getAttemptState(authUserAttemptState, normalizedUsername);
    if (userState) {
      userState.count += 1;
      userState.lastFailedAt = now;
      if (userState.count >= AUTH_LOCKOUT_THRESHOLD) {
        userState.lockedUntil = now + AUTH_LOCKOUT_MS;
      }
      authUserAttemptState.set(normalizedUsername, userState);
    }
  }

  pruneAttemptMap(authIpAttemptState, AUTH_RATE_WINDOW_MS * 2);
  pruneAttemptMap(authUserAttemptState, AUTH_LOCKOUT_MS * 2);
}

function clearAuthAttemptState({ ip, username }) {
  if (ip) {
    authIpAttemptState.delete(ip);
  }
  const normalizedUsername = normalizeUsername(username);
  if (normalizedUsername) {
    authUserAttemptState.delete(normalizedUsername);
  }
}

function getAuthProtectionStatus({ ip, username }) {
  const now = Date.now();
  const ipState = ip ? getAttemptState(authIpAttemptState, ip) : null;
  if (ipState && now - ipState.firstFailedAt <= AUTH_RATE_WINDOW_MS && ipState.count >= AUTH_RATE_MAX_ATTEMPTS_PER_IP) {
    return {
      blocked: true,
      status: 429,
      error: "Too many login attempts from this IP. Try again shortly."
    };
  }

  const normalizedUsername = normalizeUsername(username);
  const userState = normalizedUsername ? authUserAttemptState.get(normalizedUsername) : null;
  if (userState?.lockedUntil && userState.lockedUntil > now) {
    const retrySec = Math.ceil((userState.lockedUntil - now) / 1000);
    return {
      blocked: true,
      status: 429,
      error: `Account temporarily locked due to repeated failed logins. Retry in ${retrySec}s.`
    };
  }
  return { blocked: false };
}

function verifyTelnyxWebhookSignature(req) {
  if (!WEBHOOK_SIGNATURE_REQUIRED) {
    return { valid: true, reason: "disabled" };
  }
  if (!TELNYX_WEBHOOK_PUBLIC_KEY) {
    return { valid: false, reason: "missing_public_key" };
  }

  const signature = req.get("telnyx-signature-ed25519") || "";
  const timestamp = req.get("telnyx-timestamp") || "";
  const rawBody = req.rawBody || "";
  if (!signature || !timestamp || !rawBody) {
    return { valid: false, reason: "missing_signature_headers" };
  }

  const ts = Number(timestamp);
  if (!Number.isFinite(ts)) {
    return { valid: false, reason: "invalid_timestamp" };
  }
  const nowSec = Math.floor(Date.now() / 1000);
  if (Math.abs(nowSec - ts) > WEBHOOK_MAX_AGE_SECONDS) {
    return { valid: false, reason: "timestamp_out_of_range" };
  }

  let publicKey;
  let sigBytes;
  try {
    publicKey = Buffer.from(TELNYX_WEBHOOK_PUBLIC_KEY.replace(/\s+/g, ""), "base64");
    sigBytes = Buffer.from(signature.replace(/\s+/g, ""), "base64");
  } catch (error) {
    return { valid: false, reason: "signature_decode_failed" };
  }
  if (publicKey.length !== 32 || sigBytes.length !== 64) {
    return { valid: false, reason: "signature_length_invalid" };
  }

  const message = Buffer.from(`${timestamp}|${rawBody}`);
  const valid = nacl.sign.detached.verify(
    new Uint8Array(message),
    new Uint8Array(sigBytes),
    new Uint8Array(publicKey)
  );
  return { valid, reason: valid ? "ok" : "signature_invalid" };
}

function cleanExpiredUploads() {
  ensureUploadsDir();
  const files = fs.readdirSync(UPLOADS_DIR, { withFileTypes: true }).filter((item) => item.isFile());
  const cutoffMs = Date.now() - UPLOAD_RETENTION_SECONDS * 1000;
  for (const file of files) {
    const filePath = path.join(UPLOADS_DIR, file.name);
    try {
      const stat = fs.statSync(filePath);
      if (stat.mtimeMs < cutoffMs) {
        fs.unlinkSync(filePath);
      }
    } catch (error) {
      // non-blocking
    }
  }
}

function matchesTagFilter(tags, selectedTags, mode) {
  const normalizedTags = normalizeTags(tags);
  const filterTags = normalizeTags(selectedTags);

  if (!filterTags.length) {
    return true;
  }

  if ((mode || "any") === "all") {
    return filterTags.every((tag) => normalizedTags.includes(tag));
  }
  return filterTags.some((tag) => normalizedTags.includes(tag));
}

function mapEventTypeToStatus(eventType, fallbackStatus) {
  const map = {
    "fax.queued": "queued",
    "fax.media.processed": "media_processed",
    "fax.sending.started": "sending",
    "fax.delivered": "delivered",
    "fax.failed": "failed"
  };
  return map[eventType] || fallbackStatus || "unknown";
}

function ensureDataFiles() {
  ensureDataDir();
  ensureUploadsDir();

  if (!fs.existsSync(STORE_FILE)) {
    writeJson(STORE_FILE, { updated_at: new Date().toISOString(), items: {} });
  }
  if (!fs.existsSync(FAX_ARCHIVE_FILE)) {
    writeJson(FAX_ARCHIVE_FILE, { updated_at: new Date().toISOString(), items: {} });
  }

  if (!fs.existsSync(CONFIG_FILE)) {
    writeJson(CONFIG_FILE, {
      updated_at: new Date().toISOString(),
      telnyx_api_key: process.env.TELNYX_API_KEY || "",
      telnyx_connection_id: process.env.TELNYX_CONNECTION_ID || "",
      telnyx_from_number: process.env.TELNYX_FROM_NUMBER || "",
      telnyx_fax_application_id: process.env.TELNYX_FAX_APPLICATION_ID || "",
      outbound_copy_enabled:
        process.env.OUTBOUND_COPY_ENABLED === undefined
          ? true
          : process.env.OUTBOUND_COPY_ENABLED === "true",
      outbound_copy_email: process.env.OUTBOUND_COPY_EMAIL || "eyecarecenteroc@gmail.com",
      office_name: process.env.OFFICE_NAME || "Eyecare Care of Orange County",
      office_fax_number: process.env.OFFICE_FAX_NUMBER || "+17145580642",
      office_email: process.env.OFFICE_EMAIL || "eyecarecenteroc@gmail.com"
    });
  }

  if (!fs.existsSync(CONTACTS_FILE)) {
    writeJson(CONTACTS_FILE, { updated_at: new Date().toISOString(), items: {} });
  }

  if (!fs.existsSync(BULK_JOBS_FILE)) {
    writeJson(BULK_JOBS_FILE, { updated_at: new Date().toISOString(), items: {} });
  }
  if (!fs.existsSync(TENANTS_FILE)) {
    writeJson(TENANTS_FILE, {
      updated_at: new Date().toISOString(),
      items: {
        [DEFAULT_TENANT_ID]: {
          id: DEFAULT_TENANT_ID,
          name: "Default Tenant",
          plan: defaultTenantPlan(),
          active: true,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      }
    });
  }
  if (!fs.existsSync(AUDIT_EVENTS_FILE)) {
    writeJson(AUDIT_EVENTS_FILE, { updated_at: new Date().toISOString(), items: [] });
  }
  if (!fs.existsSync(IDEMPOTENCY_FILE)) {
    writeJson(IDEMPOTENCY_FILE, { updated_at: new Date().toISOString(), items: [] });
  }
  if (!fs.existsSync(BILLING_FILE)) {
    writeJson(BILLING_FILE, {
      updated_at: new Date().toISOString(),
      items: {
        [DEFAULT_TENANT_ID]: {
          tenant_id: DEFAULT_TENANT_ID,
          plan: defaultTenantPlan(),
          seats: 5,
          status: "active",
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString()
        }
      }
    });
  }
  const tenants = readTenantsStore();
  if (!tenants.items?.[DEFAULT_TENANT_ID]) {
    tenants.items = tenants.items || {};
    tenants.items[DEFAULT_TENANT_ID] = {
      id: DEFAULT_TENANT_ID,
      name: "Default Tenant",
      plan: defaultTenantPlan(),
      active: true,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString()
    };
    writeTenantsStore(tenants);
  }

  if (!fs.existsSync(USERS_FILE)) {
    const adminUsername = normalizeUsername(process.env.ADMIN_USERNAME || "admin");
    const generatedPassword = crypto.randomBytes(9).toString("base64url");
    const adminPassword = process.env.ADMIN_PASSWORD || generatedPassword;
    const now = new Date().toISOString();

    writeJson(USERS_FILE, {
      updated_at: now,
      items: [
        {
          id: crypto.randomUUID(),
          tenant_id: DEFAULT_TENANT_ID,
          username: adminUsername,
          role: "admin",
          password_hash: bcrypt.hashSync(adminPassword, 12),
          mfa_enabled: false,
          mfa_secret: "",
          last_media_url: "",
          created_at: now,
          updated_at: now
        }
      ]
    });

    if (!process.env.ADMIN_PASSWORD) {
      console.warn(
        `Bootstrap admin created: username "${adminUsername}" password "${generatedPassword}". Set ADMIN_PASSWORD in .env.`
      );
    }
  } else {
    const normalizedUsers = ensureAdminAccount(readUsers());
    writeUsers(normalizedUsers);
  }
}

function readStore() {
  return readJson(STORE_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeStore(store) {
  writeJson(STORE_FILE, store);
}

function readArchiveStore() {
  return readJson(FAX_ARCHIVE_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeArchiveStore(store) {
  writeJson(FAX_ARCHIVE_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function readTenantsStore() {
  return readJson(TENANTS_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeTenantsStore(store) {
  writeJson(TENANTS_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function getTenantById(tenantId) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readTenantsStore();
  return store.items?.[normalizedTenantId] || null;
}

function ensureTenantExists(tenantId) {
  const existing = getTenantById(tenantId);
  if (existing) {
    return existing;
  }
  return null;
}

function createTenantRecord({
  tenantId,
  name = "",
  plan = defaultTenantPlan(),
  active = true
}) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (normalizedTenantId === DEFAULT_TENANT_ID) {
    throw new Error("Default tenant already exists.");
  }
  if (getTenantById(normalizedTenantId)) {
    throw new Error("Tenant already exists.");
  }
  const planName = PLAN_LIMITS[(plan || "").toString().trim().toLowerCase()]
    ? (plan || "").toString().trim().toLowerCase()
    : defaultTenantPlan();
  const store = readTenantsStore();
  const now = new Date().toISOString();
  const tenant = {
    id: normalizedTenantId,
    name: (name || `Tenant ${normalizedTenantId}`).toString().trim(),
    plan: planName,
    active: active !== false,
    created_at: now,
    updated_at: now
  };
  store.items = store.items || {};
  store.items[normalizedTenantId] = tenant;
  writeTenantsStore(store);
  return tenant;
}

function readBillingStore() {
  return readJson(BILLING_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeBillingStore(store) {
  writeJson(BILLING_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function getTenantBilling(tenantId) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const tenants = readTenantsStore();
  const billingStore = readBillingStore();
  const tenant = tenants.items?.[normalizedTenantId] || null;
  if (!tenant) {
    return null;
  }
  if (BILLING_MODE !== "paid") {
    return {
      tenant_id: normalizedTenantId,
      plan: "free",
      seats: 9999,
      status: tenant.active === false ? "suspended" : "active",
      created_at: tenant.created_at || new Date().toISOString(),
      updated_at: tenant.updated_at || new Date().toISOString()
    };
  }
  const now = new Date().toISOString();
  const billing = billingStore.items?.[normalizedTenantId] || {
    tenant_id: normalizedTenantId,
    plan: tenant.plan || defaultTenantPlan(),
    seats: 5,
    status: tenant.active === false ? "suspended" : "active",
    created_at: now,
    updated_at: now
  };

  if (!billingStore.items?.[normalizedTenantId]) {
    billingStore.items = billingStore.items || {};
    billingStore.items[normalizedTenantId] = billing;
    writeBillingStore(billingStore);
  }

  return billing;
}

function updateTenantBilling(tenantId, patch = {}) {
  if (BILLING_MODE !== "paid") {
    throw new Error("Billing mode is set to free. Paid plan updates are disabled.");
  }
  const normalizedTenantId = normalizeTenantId(tenantId);
  const tenant = getTenantById(normalizedTenantId);
  if (!tenant) {
    throw new Error("Tenant not found.");
  }
  const billingStore = readBillingStore();
  const existing = getTenantBilling(normalizedTenantId);
  const nextPlan = (patch.plan || existing.plan || defaultTenantPlan()).toString().trim().toLowerCase();
  const plan = PLAN_LIMITS[nextPlan] && nextPlan !== "free" ? nextPlan : existing.plan || defaultTenantPlan();
  const next = {
    ...existing,
    plan,
    seats: Math.max(1, Number(patch.seats || existing.seats || 1)),
    status: (patch.status || existing.status || "active").toString().trim().toLowerCase(),
    updated_at: new Date().toISOString()
  };
  billingStore.items = billingStore.items || {};
  billingStore.items[normalizedTenantId] = next;
  writeBillingStore(billingStore);

  const tenants = readTenantsStore();
  tenants.items[normalizedTenantId] = {
    ...tenant,
    plan: next.plan,
    active: next.status !== "suspended",
    updated_at: new Date().toISOString()
  };
  writeTenantsStore(tenants);
  return next;
}

function getTenantPlanLimits(tenantId) {
  if (BILLING_MODE !== "paid") {
    return PLAN_LIMITS.free;
  }
  const billing = getTenantBilling(tenantId);
  const plan = (billing?.plan || defaultTenantPlan()).toLowerCase();
  return PLAN_LIMITS[plan] || PLAN_LIMITS.starter;
}

function readAuditStore() {
  return readJson(AUDIT_EVENTS_FILE, { updated_at: new Date().toISOString(), items: [] });
}

function writeAuditStore(store) {
  writeJson(AUDIT_EVENTS_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function appendAuditEvent({
  tenantId,
  actorUsername,
  actorRole,
  action,
  targetType = "",
  targetId = "",
  ipAddress = "",
  metadata = {}
}) {
  const store = readAuditStore();
  const event = {
    id: crypto.randomUUID(),
    tenant_id: normalizeTenantId(tenantId),
    actor_username: (actorUsername || "system").toString(),
    actor_role: (actorRole || "system").toString(),
    action: (action || "unknown").toString(),
    target_type: (targetType || "").toString(),
    target_id: (targetId || "").toString(),
    ip_address: (ipAddress || "").toString(),
    metadata: metadata && typeof metadata === "object" ? metadata : {},
    created_at: new Date().toISOString()
  };
  const items = Array.isArray(store.items) ? store.items : [];
  items.push(event);
  if (items.length > 100000) {
    items.splice(0, items.length - 100000);
  }
  store.items = items;
  writeAuditStore(store);
  return event;
}

function listAuditEvents({ tenantId, limit = 200, action = "" }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const max = Math.max(1, Math.min(Number(limit || 200), 2000));
  const actionFilter = (action || "").toString().trim().toLowerCase();
  const store = readAuditStore();
  const items = Array.isArray(store.items) ? store.items : [];
  return items
    .filter((item) => normalizeTenantId(item.tenant_id) === normalizedTenantId)
    .filter((item) => (actionFilter ? (item.action || "").toLowerCase() === actionFilter : true))
    .sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
    .slice(0, max);
}

function readIdempotencyStore() {
  return readJson(IDEMPOTENCY_FILE, { updated_at: new Date().toISOString(), items: [] });
}

function writeIdempotencyStore(store) {
  writeJson(IDEMPOTENCY_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function cleanupIdempotencyStore() {
  const store = readIdempotencyStore();
  const items = Array.isArray(store.items) ? store.items : [];
  const now = Date.now();
  const filtered = items.filter((item) => new Date(item.expires_at || 0).getTime() > now);
  if (filtered.length !== items.length) {
    store.items = filtered;
    writeIdempotencyStore(store);
  }
}

function getIdempotentResponse({ tenantId, key, method, path: requestPath }) {
  if (!key) return null;
  cleanupIdempotencyStore();
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readIdempotencyStore();
  const items = Array.isArray(store.items) ? store.items : [];
  return (
    items.find(
      (item) =>
        normalizeTenantId(item.tenant_id) === normalizedTenantId &&
        item.key === key &&
        item.method === method &&
        item.path === requestPath
    ) || null
  );
}

function saveIdempotentResponse({ tenantId, key, method, path: requestPath, statusCode, responseBody }) {
  if (!key) return;
  const normalizedTenantId = normalizeTenantId(tenantId);
  const now = new Date();
  const expiresAt = new Date(now.getTime() + IDEMPOTENCY_TTL_SECONDS * 1000);
  const store = readIdempotencyStore();
  const items = Array.isArray(store.items) ? store.items : [];
  const filtered = items.filter(
    (item) =>
      !(
        normalizeTenantId(item.tenant_id) === normalizedTenantId &&
        item.key === key &&
        item.method === method &&
        item.path === requestPath
      )
  );
  filtered.push({
    id: crypto.randomUUID(),
    tenant_id: normalizedTenantId,
    key,
    method,
    path: requestPath,
    status_code: Number(statusCode || 200),
    response_body: responseBody && typeof responseBody === "object" ? responseBody : {},
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString()
  });
  store.items = filtered;
  writeIdempotencyStore(store);
}

function normalizeUsersStore(rawUsers) {
  const rawItems = Array.isArray(rawUsers?.items)
    ? rawUsers.items
    : rawUsers?.items && typeof rawUsers.items === "object"
      ? Object.values(rawUsers.items)
      : [];

  const items = rawItems
    .filter(Boolean)
    .map((item) => ({
      ...item,
      tenant_id: normalizeTenantId(item.tenant_id),
      username: normalizeUsername(item.username),
      role: item.role === "admin" ? "admin" : "user",
      mfa_enabled: item.mfa_enabled === true,
      mfa_secret: (item.mfa_secret || "").toString(),
      last_media_url: item.last_media_url || ""
    }));

  return {
    updated_at: rawUsers?.updated_at || new Date().toISOString(),
    items
  };
}

function ensureAdminAccount(usersStore) {
  const users = normalizeUsersStore(usersStore);
  const hasAdmin = users.items.some(
    (item) => item.role === "admin" && normalizeTenantId(item.tenant_id) === DEFAULT_TENANT_ID
  );
  if (hasAdmin) {
    return users;
  }

  const adminUsername = normalizeUsername(process.env.ADMIN_USERNAME || "admin");
  const generatedPassword = crypto.randomBytes(9).toString("base64url");
  const adminPassword = process.env.ADMIN_PASSWORD || generatedPassword;
  const now = new Date().toISOString();
  users.items.push({
    id: crypto.randomUUID(),
    tenant_id: DEFAULT_TENANT_ID,
    username: adminUsername,
    role: "admin",
    password_hash: bcrypt.hashSync(adminPassword, 12),
    mfa_enabled: false,
    mfa_secret: "",
    last_media_url: "",
    created_at: now,
    updated_at: now
  });
  users.updated_at = now;

  if (!process.env.ADMIN_PASSWORD) {
    console.warn(
      `No admin account found. Created bootstrap admin "${adminUsername}" with generated password "${generatedPassword}".`
    );
  }
  return users;
}

function readUsers() {
  return normalizeUsersStore(readJson(USERS_FILE, { updated_at: new Date().toISOString(), items: [] }));
}

function writeUsers(users) {
  writeJson(USERS_FILE, normalizeUsersStore(users));
}

const TENANT_CONFIG_FIELDS = [
  "telnyx_api_key",
  "telnyx_connection_id",
  "telnyx_from_number",
  "telnyx_fax_application_id",
  "outbound_copy_enabled",
  "outbound_copy_email",
  "office_name",
  "office_fax_number",
  "office_email"
];

function readConfigStore() {
  const raw = readJson(CONFIG_FILE, { updated_at: new Date().toISOString(), tenants: {} });
  const tenants = raw?.tenants && typeof raw.tenants === "object" ? { ...raw.tenants } : {};
  if (!tenants[DEFAULT_TENANT_ID]) {
    const legacy = {};
    TENANT_CONFIG_FIELDS.forEach((field) => {
      if (raw[field] !== undefined) {
        legacy[field] = raw[field];
      }
    });
    if (Object.keys(legacy).length) {
      tenants[DEFAULT_TENANT_ID] = legacy;
    }
  }
  return {
    updated_at: raw?.updated_at || new Date().toISOString(),
    tenants
  };
}

function readConfig(tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const defaults = {
    updated_at: new Date().toISOString(),
    telnyx_api_key: process.env.TELNYX_API_KEY || "",
    telnyx_connection_id: process.env.TELNYX_CONNECTION_ID || "",
    telnyx_from_number: process.env.TELNYX_FROM_NUMBER || "",
    telnyx_fax_application_id: process.env.TELNYX_FAX_APPLICATION_ID || "",
    outbound_copy_enabled:
      process.env.OUTBOUND_COPY_ENABLED === undefined
        ? true
        : process.env.OUTBOUND_COPY_ENABLED === "true",
    outbound_copy_email: process.env.OUTBOUND_COPY_EMAIL || "eyecarecenteroc@gmail.com",
    office_name: process.env.OFFICE_NAME || "Eyecare Care of Orange County",
    office_fax_number: process.env.OFFICE_FAX_NUMBER || "+17145580642",
    office_email: process.env.OFFICE_EMAIL || "eyecarecenteroc@gmail.com"
  };
  const stored = readConfigStore();
  const tenantScoped =
    stored?.tenants && typeof stored.tenants === "object" ? stored.tenants[normalizedTenantId] || {} : {};
  return {
    ...defaults,
    ...tenantScoped,
    tenant_id: normalizedTenantId
  };
}

function writeConfig(config, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const existing = readConfigStore();
  const tenants = existing?.tenants && typeof existing.tenants === "object" ? { ...existing.tenants } : {};
  const now = new Date().toISOString();
  const nextTenantConfig = {
    ...readConfig(normalizedTenantId),
    ...config,
    updated_at: now,
    tenant_id: normalizedTenantId
  };
  tenants[normalizedTenantId] = nextTenantConfig;

  writeJson(CONFIG_FILE, {
    updated_at: now,
    tenants,
    migrated_at: now
  });
}

function readContactsStore() {
  return readJson(CONTACTS_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeContactsStore(store) {
  writeJson(CONTACTS_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function normalizeContactRecord(contact) {
  return {
    ...contact,
    usage_count: Number(contact?.usage_count || 0),
    last_used_at: contact?.last_used_at || null
  };
}

function contactCount(store) {
  return Object.keys(store?.items || {}).length;
}

function markContactsUsedByFaxNumbers(faxNumbers = [], tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const numbers = Array.from(new Set((faxNumbers || []).map((item) => normalizeE164(item)).filter(Boolean)));
  if (!numbers.length) {
    return;
  }

  const store = readContactsStore();
  const byFax = new Map(
    Object.values(store.items || {})
      .filter((contact) => normalizeTenantId(contact.tenant_id) === normalizedTenantId)
      .map((contact) => [normalizeE164(contact.fax_number), contact.id])
  );
  const now = new Date().toISOString();
  let changed = false;

  numbers.forEach((faxNumber) => {
    const contactId = byFax.get(faxNumber);
    if (!contactId || !store.items[contactId]) {
      return;
    }
    const existing = normalizeContactRecord(store.items[contactId]);
    store.items[contactId] = {
      ...existing,
      usage_count: existing.usage_count + 1,
      last_used_at: now,
      updated_at: now
    };
    changed = true;
  });

  if (changed) {
    writeContactsStore(store);
  }
}

function listFrequentContacts(limit = 5, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const max = Math.max(1, Math.min(Number(limit) || 5, 20));
  const store = readContactsStore();
  return Object.values(store.items || {})
    .map((contact) => normalizeContactRecord(contact))
    .filter((contact) => normalizeTenantId(contact.tenant_id) === normalizedTenantId)
    .filter((contact) => contact.usage_count > 0)
    .sort((a, b) => {
      if (b.usage_count !== a.usage_count) {
        return b.usage_count - a.usage_count;
      }
      return new Date(b.last_used_at || 0).getTime() - new Date(a.last_used_at || 0).getTime();
    })
    .slice(0, max);
}

function readBulkJobsStore() {
  return readJson(BULK_JOBS_FILE, { updated_at: new Date().toISOString(), items: {} });
}

function writeBulkJobsStore(store) {
  writeJson(BULK_JOBS_FILE, {
    ...store,
    updated_at: new Date().toISOString()
  });
}

function sanitizeUser(user) {
  return {
    id: user.id,
    tenant_id: normalizeTenantId(user.tenant_id),
    username: user.username,
    role: user.role,
    mfa_enabled: user.mfa_enabled === true,
    last_media_url: user.last_media_url || "",
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}

function getUserByUsername(username, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const users = readUsers();
  return (
    users.items.find(
      (item) =>
        item.username === normalizeUsername(username) &&
        normalizeTenantId(item.tenant_id) === normalizedTenantId
    ) || null
  );
}

function verifyUserPassword(user, password) {
  if (!user) return false;
  if (user.password_hash) {
    return bcrypt.compareSync(password, user.password_hash);
  }
  if (typeof user.password === "string") {
    return password === user.password;
  }
  return false;
}

function listUsersSafe(tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const users = readUsers();
  return users.items
    .filter((item) => normalizeTenantId(item.tenant_id) === normalizedTenantId)
    .map((item) => sanitizeUser(item));
}

function createUser({ username, password, role, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const normalizedUsername = normalizeUsername(username);
  if (!/^[a-z0-9._-]{3,64}$/.test(normalizedUsername)) {
    throw new Error("Username must be 3-64 chars and use letters, numbers, dot, underscore, or dash.");
  }
  if (!password || password.length < 10) {
    throw new Error("Password must be at least 10 characters.");
  }
  if (!["admin", "user"].includes(role)) {
    throw new Error("Role must be admin or user.");
  }

  const users = readUsers();
  const tenantUserCount = users.items.filter(
    (item) => normalizeTenantId(item.tenant_id) === normalizedTenantId
  ).length;
  const maxUsers = getTenantPlanLimits(normalizedTenantId).max_users;
  if (COMMERCIAL_ENFORCEMENTS_ENABLED && tenantUserCount >= maxUsers) {
    throw new Error(`User limit reached for current plan (${maxUsers}).`);
  }

  const exists = users.items.some(
    (item) =>
      item.username === normalizedUsername &&
      normalizeTenantId(item.tenant_id) === normalizedTenantId
  );
  if (exists) {
    throw new Error("Username already exists.");
  }

  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    tenant_id: normalizedTenantId,
    username: normalizedUsername,
    role,
    password_hash: bcrypt.hashSync(password, 12),
    mfa_enabled: false,
    mfa_secret: "",
    last_media_url: "",
    created_at: now,
    updated_at: now
  };

  users.items.push(user);
  users.updated_at = now;
  writeUsers(users);
  return sanitizeUser(user);
}

function updateUserPassword({ username, password, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!password || password.length < 10) {
    throw new Error("Password must be at least 10 characters.");
  }

  const users = readUsers();
  const index = users.items.findIndex(
    (item) =>
      item.username === normalizeUsername(username) &&
      normalizeTenantId(item.tenant_id) === normalizedTenantId
  );
  if (index < 0) {
    throw new Error("User not found.");
  }

  users.items[index] = {
    ...users.items[index],
    password_hash: bcrypt.hashSync(password, 12),
    updated_at: new Date().toISOString()
  };
  users.updated_at = new Date().toISOString();
  writeUsers(users);
  return sanitizeUser(users.items[index]);
}

function updateUserLastMediaUrl({ username, mediaUrl, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const users = readUsers();
  const index = users.items.findIndex(
    (item) =>
      item.username === normalizeUsername(username) &&
      normalizeTenantId(item.tenant_id) === normalizedTenantId
  );
  if (index < 0) {
    throw new Error("User not found.");
  }

  users.items[index] = {
    ...users.items[index],
    last_media_url: mediaUrl || "",
    updated_at: new Date().toISOString()
  };
  users.updated_at = new Date().toISOString();
  writeUsers(users);
  return sanitizeUser(users.items[index]);
}

function updateUserMfa({ username, enabled, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const users = readUsers();
  const index = users.items.findIndex(
    (item) =>
      item.username === normalizeUsername(username) &&
      normalizeTenantId(item.tenant_id) === normalizedTenantId
  );
  if (index < 0) {
    throw new Error("User not found.");
  }
  users.items[index] = {
    ...users.items[index],
    mfa_enabled: enabled === true,
    updated_at: new Date().toISOString()
  };
  users.updated_at = new Date().toISOString();
  writeUsers(users);
  return sanitizeUser(users.items[index]);
}

function d1AuthHeaders() {
  if (D1_API_TOKEN) {
    return {
      Authorization: `Bearer ${D1_API_TOKEN}`,
      "Content-Type": "application/json"
    };
  }
  if (D1_API_KEY && D1_EMAIL) {
    return {
      "X-Auth-Key": D1_API_KEY,
      "X-Auth-Email": D1_EMAIL,
      "Content-Type": "application/json"
    };
  }
  throw new Error("Cloudflare D1 auth not configured.");
}

async function d1Query(sql, params = []) {
  if (!D1_USERS_ENABLED) {
    throw new Error("Cloudflare D1 is not enabled.");
  }
  const response = await fetch(
    `${CLOUDFLARE_API_BASE}/accounts/${D1_ACCOUNT_ID}/d1/database/${D1_DATABASE_ID}/query`,
    {
      method: "POST",
      headers: d1AuthHeaders(),
      body: JSON.stringify({ sql, params })
    }
  );

  const json = await response.json().catch(() => ({}));
  if (!response.ok || !json?.success) {
    const detail = json?.errors?.[0]?.message || "Cloudflare D1 query failed.";
    throw new Error(detail);
  }
  const result = Array.isArray(json.result) ? json.result[0] : null;
  if (result && result.success === false) {
    throw new Error("Cloudflare D1 statement failed.");
  }
  return Array.isArray(result?.results) ? result.results : [];
}

async function ensureD1SessionsTable() {
  if (!D1_USERS_ENABLED) return;
  await d1Query(`CREATE TABLE IF NOT EXISTS sessions (
    sid TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
  )`);
}

class D1SessionStore extends session.Store {
  constructor() {
    super();
    this.ready = ensureD1SessionsTable();
  }

  get(sid, callback) {
    this.ready
      .then(async () => {
        const rows = await d1Query(
          "SELECT payload, expires_at FROM sessions WHERE sid = ? LIMIT 1",
          [sid]
        );
        const row = rows[0];
        if (!row) {
          callback(null, null);
          return;
        }

        const now = Date.now();
        const expiresAt = Number(row.expires_at || 0);
        if (expiresAt && expiresAt <= now) {
          await d1Query("DELETE FROM sessions WHERE sid = ?", [sid]).catch(() => {});
          callback(null, null);
          return;
        }

        let parsed = null;
        try {
          parsed = JSON.parse(row.payload || "{}");
        } catch (error) {
          parsed = null;
        }
        callback(null, parsed);
      })
      .catch((error) => callback(error));
  }

  set(sid, sess, callback) {
    this.ready
      .then(async () => {
        const expiresAt = sess?.cookie?.expires
          ? new Date(sess.cookie.expires).getTime()
          : Date.now() + SESSION_MAX_AGE_MS;
        await d1Query(
          `INSERT INTO sessions (sid, payload, expires_at, updated_at)
           VALUES (?, ?, ?, ?)
           ON CONFLICT(sid) DO UPDATE SET
             payload = excluded.payload,
             expires_at = excluded.expires_at,
             updated_at = excluded.updated_at`,
          [sid, JSON.stringify(sess || {}), Math.max(Date.now(), expiresAt), Date.now()]
        );
        callback(null);
      })
      .catch((error) => callback(error));
  }

  destroy(sid, callback) {
    this.ready
      .then(async () => {
        await d1Query("DELETE FROM sessions WHERE sid = ?", [sid]);
        callback(null);
      })
      .catch((error) => callback(error));
  }

  touch(sid, sess, callback) {
    this.ready
      .then(async () => {
        const expiresAt = sess?.cookie?.expires
          ? new Date(sess.cookie.expires).getTime()
          : Date.now() + SESSION_MAX_AGE_MS;
        await d1Query("UPDATE sessions SET expires_at = ?, updated_at = ? WHERE sid = ?", [
          Math.max(Date.now(), expiresAt),
          Date.now(),
          sid
        ]);
        callback(null);
      })
      .catch((error) => callback(error));
  }
}

function readLocalSessionStore() {
  return readJson(LOCAL_SESSIONS_FILE, {
    items: {},
    updated_at: new Date().toISOString()
  });
}

function writeLocalSessionStore(store) {
  writeJson(LOCAL_SESSIONS_FILE, {
    items: store?.items || {},
    updated_at: new Date().toISOString()
  });
}

function resolveSessionExpiresAt(sess) {
  if (sess?.cookie?.expires) {
    const expiresAt = new Date(sess.cookie.expires).getTime();
    if (Number.isFinite(expiresAt) && expiresAt > 0) {
      return expiresAt;
    }
  }
  return Date.now() + SESSION_MAX_AGE_MS;
}

function purgeExpiredLocalSessions(store) {
  const safeStore = store && typeof store === "object" ? store : { items: {} };
  const items = safeStore.items && typeof safeStore.items === "object" ? safeStore.items : {};
  const now = Date.now();
  let changed = false;
  for (const [sid, row] of Object.entries(items)) {
    const expiresAt = Number(row?.expires_at || 0);
    if (!expiresAt || expiresAt > now) {
      continue;
    }
    delete items[sid];
    changed = true;
  }
  safeStore.items = items;
  return { store: safeStore, changed };
}

class LocalFileSessionStore extends session.Store {
  get(sid, callback) {
    try {
      const purged = purgeExpiredLocalSessions(readLocalSessionStore());
      if (purged.changed) {
        writeLocalSessionStore(purged.store);
      }
      const row = purged.store.items[sid];
      if (!row) {
        callback(null, null);
        return;
      }
      let parsed = null;
      try {
        parsed = JSON.parse(row.payload || "{}");
      } catch (error) {
        parsed = null;
      }
      callback(null, parsed);
    } catch (error) {
      callback(error);
    }
  }

  set(sid, sess, callback) {
    try {
      const store = readLocalSessionStore();
      const items = store.items && typeof store.items === "object" ? store.items : {};
      const expiresAt = resolveSessionExpiresAt(sess);
      items[sid] = {
        payload: JSON.stringify(sess || {}),
        expires_at: Math.max(Date.now(), expiresAt),
        updated_at: Date.now()
      };
      store.items = items;
      writeLocalSessionStore(store);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  destroy(sid, callback) {
    try {
      const store = readLocalSessionStore();
      const items = store.items && typeof store.items === "object" ? store.items : {};
      if (items[sid]) {
        delete items[sid];
        store.items = items;
        writeLocalSessionStore(store);
      }
      callback(null);
    } catch (error) {
      callback(error);
    }
  }

  touch(sid, sess, callback) {
    try {
      const store = readLocalSessionStore();
      const items = store.items && typeof store.items === "object" ? store.items : {};
      const current = items[sid];
      if (!current) {
        callback(null);
        return;
      }
      current.expires_at = Math.max(Date.now(), resolveSessionExpiresAt(sess));
      current.updated_at = Date.now();
      items[sid] = current;
      store.items = items;
      writeLocalSessionStore(store);
      callback(null);
    } catch (error) {
      callback(error);
    }
  }
}

function getSessionStoreMode() {
  if (D1_USERS_ENABLED) return "d1";
  if (LOCAL_SESSION_STORE_ENABLED) return "local_file";
  return "memory";
}

const SESSION_STORE_MODE = getSessionStoreMode();

function createSessionStore() {
  if (SESSION_STORE_MODE === "d1") {
    return new D1SessionStore();
  }
  if (SESSION_STORE_MODE === "local_file") {
    return new LocalFileSessionStore();
  }
  return undefined;
}

app.use(
  session({
    name: "fax_app_session",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    store: createSessionStore(),
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: SESSION_MAX_AGE_MS
    }
  })
);

function d1NormalizeUserRow(row) {
  if (!row) return null;
  return {
    id: row.id,
    username: normalizeUsername(row.username),
    role: row.role === "admin" ? "admin" : "user",
    password_hash: row.password_hash || "",
    mfa_enabled: false,
    mfa_secret: "",
    last_media_url: row.last_media_url || "",
    created_at: row.created_at,
    updated_at: row.updated_at
  };
}

function d1StoreKeyForFile(filePath) {
  const filename = path.basename(filePath || "");
  if (!D1_SYNC_STORE_FILENAMES.has(filename)) {
    return null;
  }
  return filename;
}

async function ensureD1AppStoresTable() {
  if (!D1_APP_STORES_ENABLED) return;
  await d1Query(`CREATE TABLE IF NOT EXISTS app_store_snapshots (
    store_key TEXT PRIMARY KEY,
    payload TEXT NOT NULL,
    updated_at TEXT NOT NULL
  )`);
}

async function d1ReadStoreSnapshot(storeKey) {
  if (!D1_APP_STORES_ENABLED || !storeKey) {
    return null;
  }
  const rows = await d1Query(
    "SELECT store_key, payload, updated_at FROM app_store_snapshots WHERE store_key = ? LIMIT 1",
    [storeKey]
  );
  const row = rows[0];
  if (!row) {
    return null;
  }
  try {
    return {
      store_key: row.store_key,
      payload: JSON.parse(row.payload || "{}"),
      updated_at: row.updated_at || null
    };
  } catch (error) {
    return null;
  }
}

async function d1UpsertStoreSnapshot({ storeKey, payload }) {
  if (!D1_APP_STORES_ENABLED || !storeKey) return;
  await d1Query(
    `INSERT INTO app_store_snapshots (store_key, payload, updated_at)
     VALUES (?, ?, ?)
     ON CONFLICT(store_key) DO UPDATE SET
       payload = excluded.payload,
       updated_at = excluded.updated_at`,
    [storeKey, JSON.stringify(payload || {}), new Date().toISOString()]
  );
}

async function flushD1StoreSyncQueue() {
  if (!D1_APP_STORES_ENABLED || !d1AppStoresReady) {
    return;
  }
  const entries = Array.from(pendingD1StoreSync.entries());
  pendingD1StoreSync.clear();
  d1StoreSyncTimer = null;

  for (const [storeKey, payload] of entries) {
    try {
      await d1UpsertStoreSnapshot({ storeKey, payload });
    } catch (error) {
      console.warn(`D1 store sync failed for ${storeKey}: ${error.message || error}`);
    }
  }
}

function scheduleD1StoreSnapshot(filePath, payload) {
  if (!D1_APP_STORES_ENABLED || !d1AppStoresReady || isD1AppStoreHydration) {
    return;
  }
  const storeKey = d1StoreKeyForFile(filePath);
  if (!storeKey) {
    return;
  }
  pendingD1StoreSync.set(storeKey, payload);
  if (d1StoreSyncTimer) {
    return;
  }
  d1StoreSyncTimer = setTimeout(() => {
    flushD1StoreSyncQueue().catch((error) => {
      console.warn(`D1 store sync queue failed: ${error.message || error}`);
    });
  }, 250);
}

async function bootstrapD1AppStores() {
  if (!D1_APP_STORES_ENABLED) return;
  await ensureD1AppStoresTable();

  const storeFiles = [STORE_FILE, FAX_ARCHIVE_FILE, CONFIG_FILE, CONTACTS_FILE, BULK_JOBS_FILE];
  for (const storeFile of storeFiles) {
    const storeKey = d1StoreKeyForFile(storeFile);
    if (!storeKey) continue;

    const remote = await d1ReadStoreSnapshot(storeKey);
    if (remote?.payload && typeof remote.payload === "object") {
      isD1AppStoreHydration = true;
      try {
        writeJson(storeFile, remote.payload);
      } finally {
        isD1AppStoreHydration = false;
      }
      continue;
    }

    const local = readJson(storeFile, {});
    await d1UpsertStoreSnapshot({ storeKey, payload: local });
  }
  d1AppStoresReady = true;
}

async function ensureD1UsersTable() {
  if (!D1_USERS_ENABLED) return;
  await d1Query(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL,
    password_hash TEXT,
    last_media_url TEXT,
    created_at TEXT,
    updated_at TEXT
  )`);
}

async function getUserByUsernameStore(username, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return getUserByUsername(username, normalizedTenantId);
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  const rows = await d1Query("SELECT * FROM users WHERE username = ? LIMIT 1", [
    normalizeUsername(username)
  ]);
  const user = d1NormalizeUserRow(rows[0] || null);
  if (!user) return null;
  return {
    ...user,
    tenant_id: DEFAULT_TENANT_ID
  };
}

async function listUsersSafeStore(tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return listUsersSafe(normalizedTenantId);
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  const rows = await d1Query(
    "SELECT id, username, role, last_media_url, created_at, updated_at FROM users ORDER BY created_at DESC"
  );
  return rows.map((row) => sanitizeUser({ ...d1NormalizeUserRow(row), tenant_id: DEFAULT_TENANT_ID }));
}

async function createUserStore({ username, password, role, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return createUser({ username, password, role, tenantId: normalizedTenantId });
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  const normalizedUsername = normalizeUsername(username);
  if (!/^[a-z0-9._-]{3,64}$/.test(normalizedUsername)) {
    throw new Error("Username must be 3-64 chars and use letters, numbers, dot, underscore, or dash.");
  }
  if (!password || password.length < 10) {
    throw new Error("Password must be at least 10 characters.");
  }
  if (!["admin", "user"].includes(role)) {
    throw new Error("Role must be admin or user.");
  }

  const maxUsers = getTenantPlanLimits(DEFAULT_TENANT_ID).max_users;
  const countRows = await d1Query("SELECT COUNT(1) AS count FROM users");
  const totalUsers = Number(countRows[0]?.count || 0);
  if (COMMERCIAL_ENFORCEMENTS_ENABLED && totalUsers >= maxUsers) {
    throw new Error(`User limit reached for current plan (${maxUsers}).`);
  }

  const existing = await d1Query("SELECT id FROM users WHERE username = ? LIMIT 1", [normalizedUsername]);
  if (existing.length) {
    throw new Error("Username already exists.");
  }

  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    tenant_id: DEFAULT_TENANT_ID,
    username: normalizedUsername,
    role,
    password_hash: bcrypt.hashSync(password, 12),
    last_media_url: "",
    created_at: now,
    updated_at: now
  };

  await d1Query(
    "INSERT INTO users (id, username, role, password_hash, last_media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [user.id, user.username, user.role, user.password_hash, user.last_media_url, user.created_at, user.updated_at]
  );
  return sanitizeUser(user);
}

async function updateUserPasswordStore({ username, password, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return updateUserPassword({ username, password, tenantId: normalizedTenantId });
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  if (!password || password.length < 10) {
    throw new Error("Password must be at least 10 characters.");
  }

  const normalizedUsername = normalizeUsername(username);
  const existingRows = await d1Query("SELECT * FROM users WHERE username = ? LIMIT 1", [normalizedUsername]);
  const existing = d1NormalizeUserRow(existingRows[0] || null);
  if (!existing) {
    throw new Error("User not found.");
  }

  const now = new Date().toISOString();
  const passwordHash = bcrypt.hashSync(password, 12);
  await d1Query("UPDATE users SET password_hash = ?, updated_at = ? WHERE username = ?", [
    passwordHash,
    now,
    normalizedUsername
  ]);
  return sanitizeUser({
    ...existing,
    tenant_id: DEFAULT_TENANT_ID,
    password_hash: passwordHash,
    updated_at: now
  });
}

async function updateUserLastMediaUrlStore({ username, mediaUrl, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return updateUserLastMediaUrl({ username, mediaUrl, tenantId: normalizedTenantId });
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  const normalizedUsername = normalizeUsername(username);
  const existingRows = await d1Query("SELECT * FROM users WHERE username = ? LIMIT 1", [normalizedUsername]);
  const existing = d1NormalizeUserRow(existingRows[0] || null);
  if (!existing) {
    throw new Error("User not found.");
  }

  const now = new Date().toISOString();
  await d1Query("UPDATE users SET last_media_url = ?, updated_at = ? WHERE username = ?", [
    mediaUrl || "",
    now,
    normalizedUsername
  ]);
  return sanitizeUser({
    ...existing,
    tenant_id: DEFAULT_TENANT_ID,
    last_media_url: mediaUrl || "",
    updated_at: now
  });
}

async function updateUserMfaStore({ username, enabled, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  if (!D1_USERS_ENABLED) {
    return updateUserMfa({ username, enabled, tenantId: normalizedTenantId });
  }
  if (normalizedTenantId !== DEFAULT_TENANT_ID) {
    throw new Error("Tenant-scoped users with D1 are not enabled for this build.");
  }
  throw new Error("MFA settings in D1 user mode are not available in this build.");
}

async function ensureD1AdminUser() {
  if (!D1_USERS_ENABLED) return;
  const rows = await d1Query("SELECT id FROM users WHERE role = 'admin' LIMIT 1");
  if (rows.length) {
    return;
  }

  const adminUsername = normalizeUsername(process.env.ADMIN_USERNAME || "admin");
  const generatedPassword = crypto.randomBytes(9).toString("base64url");
  const adminPassword = process.env.ADMIN_PASSWORD || generatedPassword;
  const now = new Date().toISOString();
  await d1Query(
    "INSERT INTO users (id, username, role, password_hash, last_media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
    [
      crypto.randomUUID(),
      adminUsername,
      "admin",
      bcrypt.hashSync(adminPassword, 12),
      "",
      now,
      now
    ]
  );

  if (!process.env.ADMIN_PASSWORD) {
    console.warn(
      `D1 admin created: username "${adminUsername}" password "${generatedPassword}". Set ADMIN_PASSWORD in environment.`
    );
  }
}

async function syncLocalUsersToD1() {
  if (!D1_USERS_ENABLED) return;
  const localUsers = readUsers().items || [];
  if (!localUsers.length) {
    return;
  }
  const remoteRows = await d1Query("SELECT username FROM users");
  const remoteSet = new Set(remoteRows.map((row) => normalizeUsername(row.username)));

  for (const localUser of localUsers) {
    const tenantId = normalizeTenantId(localUser.tenant_id);
    if (tenantId !== DEFAULT_TENANT_ID) {
      continue;
    }
    const username = normalizeUsername(localUser.username);
    if (!username || remoteSet.has(username)) {
      continue;
    }
    const passwordHash =
      localUser.password_hash ||
      (typeof localUser.password === "string" && localUser.password
        ? bcrypt.hashSync(localUser.password, 12)
        : "");
    await d1Query(
      "INSERT INTO users (id, username, role, password_hash, last_media_url, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
      [
        localUser.id || crypto.randomUUID(),
        username,
        localUser.role === "admin" ? "admin" : "user",
        passwordHash,
        localUser.last_media_url || "",
        localUser.created_at || new Date().toISOString(),
        localUser.updated_at || new Date().toISOString()
      ]
    );
    remoteSet.add(username);
  }
}

function listContacts({ search = "", tag = "", tenantId = DEFAULT_TENANT_ID } = {}) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readContactsStore();
  const searchTerm = (search || "").toString().trim().toLowerCase();
  const selectedTag = (tag || "").toString().trim().toLowerCase();

  return Object.values(store.items)
    .map((contact) => normalizeContactRecord(contact))
    .filter((contact) => {
      if (normalizeTenantId(contact.tenant_id) !== normalizedTenantId) {
        return false;
      }
      if (selectedTag && !normalizeTags(contact.tags).includes(selectedTag)) {
        return false;
      }

      if (!searchTerm) {
        return true;
      }

      const haystack = [
        contact.name || "",
        contact.fax_number || "",
        (contact.tags || []).join(" "),
        contact.email || "",
        contact.notes || ""
      ]
        .join(" ")
        .toLowerCase();

      return haystack.includes(searchTerm);
    })
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
}

function listContactTags(tenantId = DEFAULT_TENANT_ID) {
  const contacts = listContacts({ tenantId });
  const tags = new Set();
  contacts.forEach((contact) => {
    normalizeTags(contact.tags).forEach((tag) => tags.add(tag));
  });
  return Array.from(tags).sort();
}

function createContact({ name, fax_number, tags, email, notes, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const faxNumber = normalizeE164(fax_number);
  if (!isE164(faxNumber)) {
    throw new Error("fax_number must be E.164 format, for example +17145551234.");
  }

  const store = readContactsStore();
  const tenantContacts = Object.values(store.items || {}).filter(
    (item) => normalizeTenantId(item.tenant_id) === normalizedTenantId
  );
  const maxContacts = getTenantPlanLimits(normalizedTenantId).max_contacts;
  if (COMMERCIAL_ENFORCEMENTS_ENABLED && tenantContacts.length >= maxContacts) {
    throw new Error(`Contact limit reached for current plan (${maxContacts}). Remove contacts before adding new ones.`);
  }
  const exists = tenantContacts.some((item) => item.fax_number === faxNumber);
  if (exists) {
    throw new Error("A contact with that fax number already exists.");
  }

  const now = new Date().toISOString();
  const contact = {
    id: crypto.randomUUID(),
    tenant_id: normalizedTenantId,
    name: (name || "").toString().trim() || faxNumber,
    fax_number: faxNumber,
    tags: normalizeTags(tags),
    email: (email || "").toString().trim(),
    notes: (notes || "").toString().trim(),
    usage_count: 0,
    last_used_at: null,
    created_at: now,
    updated_at: now
  };

  if (contact.email && !isEmail(contact.email)) {
    throw new Error("email must be a valid email address.");
  }

  store.items[contact.id] = contact;
  writeContactsStore(store);
  return contact;
}

function updateContact(contactId, patch, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readContactsStore();
  const existing = store.items[contactId];
  if (!existing || normalizeTenantId(existing.tenant_id) !== normalizedTenantId) {
    throw new Error("Contact not found.");
  }

  const next = { ...existing };
  if (patch.name !== undefined) {
    next.name = (patch.name || "").toString().trim() || existing.name;
  }
  if (patch.fax_number !== undefined) {
    const faxNumber = normalizeE164(patch.fax_number);
    if (!isE164(faxNumber)) {
      throw new Error("fax_number must be E.164 format.");
    }
    const duplicate = Object.values(store.items).some(
      (item) =>
        item.id !== contactId &&
        normalizeTenantId(item.tenant_id) === normalizedTenantId &&
        item.fax_number === faxNumber
    );
    if (duplicate) {
      throw new Error("Another contact already uses this fax number.");
    }
    next.fax_number = faxNumber;
  }
  if (patch.tags !== undefined) {
    next.tags = normalizeTags(patch.tags);
  }
  if (patch.email !== undefined) {
    const email = (patch.email || "").toString().trim();
    if (email && !isEmail(email)) {
      throw new Error("email must be a valid email address.");
    }
    next.email = email;
  }
  if (patch.notes !== undefined) {
    next.notes = (patch.notes || "").toString().trim();
  }

  next.updated_at = new Date().toISOString();
  store.items[contactId] = next;
  writeContactsStore(store);
  return next;
}

function deleteContact(contactId, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readContactsStore();
  if (!store.items[contactId] || normalizeTenantId(store.items[contactId].tenant_id) !== normalizedTenantId) {
    throw new Error("Contact not found.");
  }
  delete store.items[contactId];
  writeContactsStore(store);
}

function importContactsFromCsv(csvText, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const records = parseCsv(csvText, {
    columns: true,
    bom: true,
    skip_empty_lines: true,
    trim: true
  });

  const store = readContactsStore();
  const existingByFax = new Map(
    Object.values(store.items)
      .filter((item) => normalizeTenantId(item.tenant_id) === normalizedTenantId)
      .map((item) => [item.fax_number, item])
  );

  const result = {
    created: 0,
    updated: 0,
    skipped: 0,
    errors: []
  };

  records.forEach((row, index) => {
    const faxRaw = row.fax_number || row.fax || row.number || row.phone || "";
    const faxNumber = normalizeE164(faxRaw);
    if (!isE164(faxNumber)) {
      result.skipped += 1;
      result.errors.push(`Row ${index + 2}: invalid fax number "${faxRaw}".`);
      return;
    }

    const now = new Date().toISOString();
    const tags = normalizeTags(row.tags || "");
    const email = (row.email || "").toString().trim();
    if (email && !isEmail(email)) {
      result.skipped += 1;
      result.errors.push(`Row ${index + 2}: invalid email "${email}".`);
      return;
    }

    const existing = existingByFax.get(faxNumber);
    if (existing) {
      store.items[existing.id] = {
        ...existing,
        name: (row.name || row.full_name || existing.name || faxNumber).toString().trim(),
        fax_number: faxNumber,
        tags: tags.length ? tags : normalizeTags(existing.tags),
        email: email || existing.email || "",
        notes: (row.notes || existing.notes || "").toString().trim(),
        updated_at: now
      };
      existingByFax.set(faxNumber, store.items[existing.id]);
      result.updated += 1;
      return;
    }

    const tenantContactCount = Object.values(store.items || {}).filter(
      (item) => normalizeTenantId(item.tenant_id) === normalizedTenantId
    ).length;
    const maxContacts = getTenantPlanLimits(normalizedTenantId).max_contacts;
    if (COMMERCIAL_ENFORCEMENTS_ENABLED && tenantContactCount >= maxContacts) {
      result.skipped += 1;
      result.errors.push(`Row ${index + 2}: contact limit reached (${maxContacts}).`);
      return;
    }

    const contact = {
      id: crypto.randomUUID(),
      tenant_id: normalizedTenantId,
      name: (row.name || row.full_name || faxNumber).toString().trim(),
      fax_number: faxNumber,
      tags,
      email,
      notes: (row.notes || "").toString().trim(),
      usage_count: 0,
      last_used_at: null,
      created_at: now,
      updated_at: now
    };
    store.items[contact.id] = contact;
    existingByFax.set(faxNumber, contact);
    result.created += 1;
  });

  writeContactsStore(store);
  return result;
}

function createBulkJob({ created_by, media_url, tag_filters, tag_mode, contacts, tenantId = DEFAULT_TENANT_ID }) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readBulkJobsStore();
  const now = new Date().toISOString();
  const job = {
    id: crypto.randomUUID(),
    tenant_id: normalizedTenantId,
    created_by,
    media_url,
    tag_filters: normalizeTags(tag_filters),
    tag_mode: tag_mode === "all" ? "all" : "any",
    status: "queued",
    totals: {
      total: contacts.length,
      queued: 0,
      failed: 0
    },
    contacts: contacts.map((contact) => ({
      id: contact.id,
      name: contact.name,
      fax_number: contact.fax_number,
      tags: normalizeTags(contact.tags)
    })),
    results: [],
    created_at: now,
    updated_at: now,
    completed_at: null
  };

  store.items[job.id] = job;
  writeBulkJobsStore(store);
  return job;
}

function updateBulkJob(jobId, updater, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readBulkJobsStore();
  const existing = store.items[jobId];
  if (!existing || normalizeTenantId(existing.tenant_id) !== normalizedTenantId) {
    return null;
  }
  const next = updater({ ...existing });
  next.updated_at = new Date().toISOString();
  store.items[jobId] = next;
  writeBulkJobsStore(store);
  return next;
}

async function processQueuedBulkJobs() {
  if (isBulkProcessorRunning) {
    return;
  }

  isBulkProcessorRunning = true;
  try {
    while (true) {
      const jobsStore = readBulkJobsStore();
      const nextJob = Object.values(jobsStore.items)
        .filter((job) => job.status === "queued")
        .sort((a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime())[0];

      if (!nextJob) {
        break;
      }

      const tenantId = normalizeTenantId(nextJob.tenant_id);
      const cfg = getRuntimeConfig(tenantId);
      if (!cfg.telnyx_api_key || !cfg.telnyx_connection_id || !cfg.telnyx_from_number) {
        updateBulkJob(nextJob.id, (job) => ({
          ...job,
          status: "failed",
          completed_at: new Date().toISOString(),
          error: "Missing Telnyx settings."
        }), tenantId);
        continue;
      }

      updateBulkJob(nextJob.id, (job) => ({ ...job, status: "running", error: null }), tenantId);

      for (const contact of nextJob.contacts) {
        try {
          const fax = await telnyxSendFax({
            apiKey: cfg.telnyx_api_key,
            connectionId: cfg.telnyx_connection_id,
            from: cfg.telnyx_from_number,
            to: contact.fax_number,
            mediaUrls: [nextJob.media_url]
          });

          upsertFax(fax.id, {
            id: fax.id,
            direction: fax.direction,
            status: fax.status,
            from: fax.from,
            to: fax.to,
            media_url: fax.media_url,
            failure_reason: null,
            telnyx_updated_at: fax.updated_at,
            created_at: fax.created_at,
            contact_id: contact.id,
            contact_name: contact.name,
            contact_tags: normalizeTags(contact.tags),
            bulk_job_id: nextJob.id
          }, nextJob.tenant_id);
          appendEvent(fax.id, "fax.queued", fax, nextJob.tenant_id);

          let copyResult = { sent: false, reason: "not_attempted" };
          try {
            copyResult = await sendOutboundCopyEmail({
              cfg,
              fax,
              mediaUrl: nextJob.media_url,
              mediaUrls: [nextJob.media_url],
              requestedBy: nextJob.created_by,
              bulkJobId: nextJob.id
            });
          } catch (copyError) {
            copyResult = { sent: false, reason: copyError.message || "copy_email_failed" };
          }

          markContactsUsedByFaxNumbers([contact.fax_number], nextJob.tenant_id);

          updateBulkJob(nextJob.id, (job) => {
            const results = Array.isArray(job.results) ? job.results : [];
            results.push({
              contact_id: contact.id,
              contact_name: contact.name,
              fax_number: contact.fax_number,
              status: "queued",
              fax_id: fax.id,
              copy_email_sent: copyResult.sent,
              copy_email_reason: copyResult.reason,
              error: null,
              created_at: new Date().toISOString()
            });

            return {
              ...job,
              totals: {
                ...job.totals,
                queued: job.totals.queued + 1
              },
              results
            };
          }, tenantId);
        } catch (error) {
          updateBulkJob(nextJob.id, (job) => {
            const results = Array.isArray(job.results) ? job.results : [];
            results.push({
              contact_id: contact.id,
              contact_name: contact.name,
              fax_number: contact.fax_number,
              status: "failed",
              fax_id: null,
              error: error.message || "Failed to queue fax.",
              created_at: new Date().toISOString()
            });

            return {
              ...job,
              totals: {
                ...job.totals,
                failed: job.totals.failed + 1
              },
              results
            };
          }, tenantId);
        }
      }

      updateBulkJob(nextJob.id, (job) => ({
        ...job,
        status: "completed",
        completed_at: new Date().toISOString()
      }), tenantId);
    }
  } finally {
    isBulkProcessorRunning = false;
  }
}

function upsertFax(faxId, patch, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readStore();
  const existing = store.items[faxId] || { id: faxId, events: [] };
  store.items[faxId] = {
    ...existing,
    tenant_id: normalizedTenantId,
    ...patch,
    updated_at: new Date().toISOString()
  };
  store.updated_at = new Date().toISOString();
  writeStore(store);
  return store.items[faxId];
}

function getFaxTenantId(faxId, fallbackTenantId = DEFAULT_TENANT_ID) {
  if (!faxId) return normalizeTenantId(fallbackTenantId);
  const store = readStore();
  if (store.items?.[faxId]) {
    return normalizeTenantId(store.items[faxId].tenant_id);
  }
  const archive = readArchiveStore();
  if (archive.items?.[faxId]) {
    return normalizeTenantId(archive.items[faxId].tenant_id);
  }
  return normalizeTenantId(fallbackTenantId);
}

function appendEvent(faxId, eventType, payload, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const store = readStore();
  const existing = store.items[faxId] || { id: faxId, events: [] };
  const events = Array.isArray(existing.events) ? existing.events : [];
  events.push({
    event_type: eventType || "unknown",
    received_at: new Date().toISOString(),
    payload
  });
  store.items[faxId] = {
    ...existing,
    tenant_id: normalizedTenantId,
    events,
    updated_at: new Date().toISOString()
  };
  store.updated_at = new Date().toISOString();
  writeStore(store);
}

function sortFaxItemsDesc(items) {
  return [...(items || [])].sort((a, b) => {
    const aTs = new Date(a?.telnyx_updated_at || a?.updated_at || a?.created_at || 0).getTime();
    const bTs = new Date(b?.telnyx_updated_at || b?.updated_at || b?.created_at || 0).getTime();
    return bTs - aTs;
  });
}

function rotateFaxStoreToVisibleLimit(limit = FAX_HISTORY_VISIBLE_LIMIT, tenantId = DEFAULT_TENANT_ID) {
  const normalizedTenantId = normalizeTenantId(tenantId);
  const maxVisible = Math.max(1, Number(limit) || FAX_HISTORY_VISIBLE_LIMIT);
  const store = readStore();
  const sorted = sortFaxItemsDesc(
    Object.values(store.items || {}).filter(
      (item) => normalizeTenantId(item.tenant_id) === normalizedTenantId
    )
  );
  if (sorted.length <= maxVisible) {
    return;
  }

  const keep = sorted.slice(0, maxVisible);
  const overflow = sorted.slice(maxVisible);
  const archive = readArchiveStore();

  overflow.forEach((item) => {
    if (!item?.id) return;
    archive.items[item.id] = {
      ...(archive.items[item.id] || {}),
      ...item,
      tenant_id: normalizedTenantId,
      archived_at: new Date().toISOString()
    };
  });

  const keepIds = new Set(keep.map((item) => item.id));
  const nextItems = {};
  Object.entries(store.items || {}).forEach(([id, item]) => {
    if (normalizeTenantId(item.tenant_id) !== normalizedTenantId || keepIds.has(id)) {
      nextItems[id] = item;
    }
  });
  store.items = nextItems;
  store.updated_at = new Date().toISOString();

  writeStore(store);
  writeArchiveStore(archive);
}

function parseWebhook(reqBody) {
  const eventType = reqBody?.data?.event_type || reqBody?.event_type || reqBody?.type || "unknown";
  const payload = reqBody?.data?.payload || reqBody?.payload || reqBody?.data || reqBody || {};
  const faxId = payload?.id || payload?.fax_id || reqBody?.fax_id || null;
  const status = mapEventTypeToStatus(eventType, payload?.status);
  const failureReason = payload?.failure_reason || payload?.failure_code || null;
  return {
    eventType,
    faxId,
    status,
    payload,
    failureReason
  };
}

function getRuntimeConfig(tenantId = DEFAULT_TENANT_ID) {
  const cfg = readConfig(tenantId);
  return {
    telnyx_api_key: cfg.telnyx_api_key || "",
    telnyx_connection_id: cfg.telnyx_connection_id || "",
    telnyx_from_number: cfg.telnyx_from_number || "",
    telnyx_fax_application_id: cfg.telnyx_fax_application_id || "",
    outbound_copy_enabled: cfg.outbound_copy_enabled !== false,
    outbound_copy_email: cfg.outbound_copy_email || "eyecarecenteroc@gmail.com",
    office_name: cfg.office_name || "Eyecare Care of Orange County",
    office_fax_number: cfg.office_fax_number || "+17145580642",
    office_email: cfg.office_email || "eyecarecenteroc@gmail.com",
    smtp_host: process.env.SMTP_HOST || "",
    smtp_port: Number(process.env.SMTP_PORT || 587),
    smtp_secure: process.env.SMTP_SECURE === "true",
    smtp_user: process.env.SMTP_USER || "",
    smtp_pass: process.env.SMTP_PASS || "",
    smtp_from: process.env.SMTP_FROM || process.env.SMTP_USER || "",
    tenant_id: normalizeTenantId(tenantId)
  };
}

function requireConfig(res, tenantId = DEFAULT_TENANT_ID) {
  const cfg = getRuntimeConfig(tenantId);
  if (!cfg.telnyx_api_key || !cfg.telnyx_connection_id || !cfg.telnyx_from_number) {
    res.status(500).json({
      error:
        "Missing Telnyx settings. Admin must set API key, connection ID, and from number in Settings."
    });
    return null;
  }
  return cfg;
}

async function telnyxRequest({ apiKey, method, resourcePath, body, isForm = false }) {
  const headers = {
    Authorization: `Bearer ${apiKey}`
  };
  if (!isForm && body) {
    headers["Content-Type"] = "application/json";
  }
  if (isForm) {
    headers["Content-Type"] = "application/x-www-form-urlencoded";
  }

  const abortController = new AbortController();
  const timeoutHandle = setTimeout(() => {
    abortController.abort();
  }, TELNYX_HTTP_TIMEOUT_MS);

  let response;
  try {
    response = await fetch(`${TELNYX_API_BASE}${resourcePath}`, {
      method,
      headers,
      body: body ? (isForm ? body : JSON.stringify(body)) : undefined,
      signal: abortController.signal
    });
  } catch (error) {
    if (error?.name === "AbortError") {
      throw new Error(`Telnyx request timed out after ${TELNYX_HTTP_TIMEOUT_MS}ms.`);
    }
    throw error;
  } finally {
    clearTimeout(timeoutHandle);
  }

  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = json?.errors?.[0]?.detail || `Telnyx ${method} ${resourcePath} failed`;
    throw new Error(detail);
  }
  return json?.data;
}

async function telnyxSendFax({ apiKey, connectionId, from, to, mediaUrls }) {
  if (!Array.isArray(mediaUrls) || !mediaUrls.length) {
    throw new Error("At least one media URL is required.");
  }
  const body = {
    connection_id: connectionId,
    from,
    to,
    media_url: mediaUrls.length === 1 ? mediaUrls[0] : mediaUrls
  };
  return telnyxRequest({
    apiKey,
    method: "POST",
    resourcePath: "/faxes",
    body,
    isForm: false
  });
}

async function telnyxGetFax({ apiKey, faxId }) {
  return telnyxRequest({
    apiKey,
    method: "GET",
    resourcePath: `/faxes/${faxId}`
  });
}

async function telnyxListFaxes({ apiKey, pageSize = FAX_HISTORY_VISIBLE_LIMIT }) {
  const size = Math.max(1, Math.min(Number(pageSize) || FAX_HISTORY_VISIBLE_LIMIT, 100));
  return telnyxRequest({
    apiKey,
    method: "GET",
    resourcePath: `/faxes?page[size]=${size}`
  });
}

async function telnyxGetFaxApplication({ apiKey, faxApplicationId }) {
  return telnyxRequest({
    apiKey,
    method: "GET",
    resourcePath: `/fax_applications/${faxApplicationId}`
  });
}

async function telnyxPatchFaxApplication({ apiKey, faxApplicationId, payload }) {
  return telnyxRequest({
    apiKey,
    method: "PATCH",
    resourcePath: `/fax_applications/${faxApplicationId}`,
    body: payload
  });
}

function localAttachmentFromMediaUrl(mediaUrl) {
  try {
    const parsed = new URL(mediaUrl);
    if (!parsed.pathname.startsWith("/media/")) {
      return null;
    }
    const filename = safeBasename(parsed.pathname.replace("/media/", ""));
    const localPath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(localPath)) {
      return null;
    }
    return {
      filename,
      path: localPath
    };
  } catch (error) {
    return null;
  }
}

function localAttachmentsFromMediaUrls(mediaUrls) {
  return Array.from(
    new Map(
      (mediaUrls || [])
        .map((url) => localAttachmentFromMediaUrl(url))
        .filter(Boolean)
        .map((attachment) => [attachment.filename, attachment])
    ).values()
  );
}

function getPublicMediaUrl(req, filename) {
  return buildSignedMediaUrl(req, filename);
}

async function generateCoverPageMediaUrl({
  req,
  cfg,
  toNumber,
  subject,
  message,
  requestedBy
}) {
  ensureUploadsDir();
  const filename = `${Date.now()}-${crypto.randomBytes(8).toString("hex")}-cover.pdf`;
  const filePath = path.join(UPLOADS_DIR, filename);

  const doc = new PDFDocument({ size: "LETTER", margin: 50 });
  const out = fs.createWriteStream(filePath);
  doc.pipe(out);

  const now = new Date().toLocaleString();
  const officeName = cfg.office_name || "Eyecare Care of Orange County";
  const officeFax = cfg.office_fax_number || "+17145580642";
  const officeEmail = cfg.office_email || "eyecarecenteroc@gmail.com";
  const finalSubject = (subject || "Fax Transmission").toString().trim();
  const finalMessage = (message || "").toString().trim();

  doc.fontSize(18).text("FAX COVER SHEET", { align: "center" });
  doc.moveDown();
  doc.fontSize(11);
  doc.text(`Date: ${now}`);
  doc.text(`From: ${officeName}`);
  doc.text(`From Fax: ${officeFax}`);
  doc.text(`From Email: ${officeEmail}`);
  doc.text(`To Fax: ${toNumber}`);
  if (requestedBy) {
    doc.text(`Requested By: ${requestedBy}`);
  }
  doc.moveDown();
  doc.fontSize(12).text(`Subject: ${finalSubject}`);
  doc.moveDown(0.5);
  doc.fontSize(11).text("Message:");
  doc.rect(doc.x, doc.y, 500, 120).stroke();
  doc.text(finalMessage || "Please see attached fax documents.", doc.x + 8, doc.y + 8, {
    width: 484,
    height: 104
  });
  doc.moveDown(8);
  doc.fontSize(10).text(
    "HIPAA NOTICE: This facsimile may contain confidential healthcare information intended only for the recipient listed above. If you received this in error, please notify the sender immediately and destroy all copies."
  );

  doc.end();
  await new Promise((resolve, reject) => {
    out.on("finish", resolve);
    out.on("error", reject);
  });

  return getPublicMediaUrl(req, filename);
}

async function sendOutboundCopyEmail({
  cfg,
  fax,
  mediaUrl,
  mediaUrls,
  requestedBy,
  bulkJobId,
  enabledOverride
}) {
  const enabled = enabledOverride === undefined ? cfg.outbound_copy_enabled : Boolean(enabledOverride);
  if (!enabled) {
    return { sent: false, reason: "disabled" };
  }
  if (!cfg.outbound_copy_email || !isEmail(cfg.outbound_copy_email)) {
    return { sent: false, reason: "invalid_recipient" };
  }
  if (!cfg.smtp_host || !cfg.smtp_user || !cfg.smtp_pass || !cfg.smtp_from) {
    return { sent: false, reason: "smtp_not_configured" };
  }

  const transporter = nodemailer.createTransport({
    host: cfg.smtp_host,
    port: cfg.smtp_port,
    secure: cfg.smtp_secure,
    auth: {
      user: cfg.smtp_user,
      pass: cfg.smtp_pass
    }
  });

  const normalizedMediaUrls = Array.isArray(mediaUrls)
    ? mediaUrls
    : mediaUrl
      ? [mediaUrl]
      : [];
  const subject = `Fax queued: ${fax.to} (${fax.id})`;
  const lines = [
    `A fax was queued successfully.`,
    ``,
    `Fax ID: ${fax.id}`,
    `From: ${fax.from}`,
    `To: ${fax.to}`,
    `Status: ${fax.status}`,
    `Media URLs:`,
    ...normalizedMediaUrls.map((url) => `- ${url}`),
    requestedBy ? `Requested By: ${requestedBy}` : null,
    bulkJobId ? `Bulk Job ID: ${bulkJobId}` : null,
    `Attachments Included: no`,
    `Created At: ${fax.created_at || new Date().toISOString()}`
  ].filter(Boolean);

  const mail = {
    from: cfg.smtp_from,
    to: cfg.outbound_copy_email,
    subject,
    text: lines.join("\n")
  };

  await transporter.sendMail(mail);
  return { sent: true, reason: "ok" };
}

const uploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    ensureUploadsDir();
    cb(null, UPLOADS_DIR);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const safeExt = [".pdf", ".tif", ".tiff"].includes(ext) ? ext : ".pdf";
    cb(null, `${Date.now()}-${crypto.randomBytes(8).toString("hex")}${safeExt}`);
  }
});

function uploadFileFilter(req, file, cb) {
  const ext = path.extname(file.originalname || "").toLowerCase();
  const mime = (file.mimetype || "").toLowerCase();
  const allowedExt = [".pdf", ".tif", ".tiff"];
  const allowedMime = [
    "application/pdf",
    "image/tiff",
    "application/tiff",
    "application/octet-stream"
  ];

  if (!allowedExt.includes(ext)) {
    return cb(new Error("Only PDF/TIFF files are allowed."));
  }
  if (mime && !allowedMime.includes(mime)) {
    return cb(new Error("Unsupported file type."));
  }
  return cb(null, true);
}

const upload = multer({
  storage: uploadStorage,
  fileFilter: uploadFileFilter,
  limits: {
    fileSize: 50 * 1024 * 1024
  }
});

const importUpload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 10 * 1024 * 1024
  }
});

function requireAdmin(req, res, next) {
  if (!req.session.user || req.session.user.role !== "admin") {
    return res.status(403).json({ error: "Admin access required." });
  }
  if (normalizeTenantId(req.session.user.tenant_id) !== normalizeTenantId(req.tenant_id)) {
    return res.status(403).json({ error: "Admin access required for active tenant." });
  }
  return next();
}

app.use((req, res, next) => {
  req.tenant_id = getTenantIdFromRequest(req);
  if (D1_USERS_ENABLED && normalizeTenantId(req.tenant_id) !== DEFAULT_TENANT_ID) {
    return res.status(503).json({
      error: "Tenant-scoped auth with D1 is not enabled. Use local user store or default tenant."
    });
  }
  return next();
});

app.use("/api", (req, res, next) => {
  const openRoutes = new Set([
    "/health",
    "/auth/login",
    "/auth/logout",
    "/auth/me",
    "/webhooks/telnyx"
  ]);
  if (openRoutes.has(req.path)) {
    return next();
  }
  if (!getTenantById(req.tenant_id)) {
    return res.status(404).json({ error: "Tenant not found." });
  }
  if (!req.session.user) {
    return res.status(401).json({ error: "Login required." });
  }
  if (normalizeTenantId(req.session.user.tenant_id) !== normalizeTenantId(req.tenant_id)) {
    return res.status(403).json({ error: "Tenant mismatch." });
  }
  return next();
});

app.post("/api/auth/login", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const tenant = getTenantById(tenantId);
    if (!tenant) {
      return res.status(404).json({ error: "Tenant is not provisioned." });
    }
    if (tenant.active === false) {
      return res.status(403).json({ error: "Tenant is suspended." });
    }
    const username = normalizeUsername(req.body.username);
    const password = req.body.password || "";
    const clientIp = getAuthClientIp(req);
    const protectionStatus = getAuthProtectionStatus({ ip: clientIp, username });
    if (protectionStatus.blocked) {
      appendAuditEvent({
        tenantId,
        actorUsername: username || "unknown",
        actorRole: "anonymous",
        action: "auth.login.blocked",
        targetType: "user",
        targetId: username || "",
        ipAddress: clientIp,
        metadata: { reason: protectionStatus.error }
      });
      return res.status(protectionStatus.status || 429).json({ error: protectionStatus.error });
    }
    const user = await getUserByUsernameStore(username, tenantId);

    if (!user || !verifyUserPassword(user, password)) {
      registerFailedAuthAttempt({ ip: clientIp, username });
      appendAuditEvent({
        tenantId,
        actorUsername: username || "unknown",
        actorRole: "anonymous",
        action: "auth.login.failed",
        targetType: "user",
        targetId: username || "",
        ipAddress: clientIp,
        metadata: {}
      });
      return res.status(401).json({ error: "Invalid username or password." });
    }

    if (!user.password_hash && typeof user.password === "string") {
      try {
        await updateUserPasswordStore({ username: user.username, password, tenantId });
      } catch (error) {
        // keep login successful even if migration write fails
      }
    }

    req.session.user = sanitizeUser({ ...user, tenant_id: tenantId });
    clearAuthAttemptState({ ip: clientIp, username });
    appendAuditEvent({
      tenantId,
      actorUsername: user.username,
      actorRole: user.role,
      action: "auth.login.success",
      targetType: "user",
      targetId: user.id,
      ipAddress: clientIp,
      metadata: {}
    });
    return res.json({ user: req.session.user });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Login failed." });
  }
});

app.post("/api/auth/logout", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const actor = req.session.user;
  if (actor) {
    appendAuditEvent({
      tenantId,
      actorUsername: actor.username,
      actorRole: actor.role,
      action: "auth.logout",
      targetType: "user",
      targetId: actor.id,
      ipAddress: getAuthClientIp(req),
      metadata: {}
    });
  }
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  if (normalizeTenantId(req.session.user.tenant_id) !== normalizeTenantId(req.tenant_id)) {
    return res.json({ authenticated: false, tenant_mismatch: true });
  }
  return res.json({ authenticated: true, user: req.session.user });
});

app.patch("/api/me/last-media-url", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const username = req.session.user?.username;
    const mediaUrl = (req.body.media_url || "").trim();
    if (mediaUrl && !mediaUrl.startsWith("https://")) {
      return res.status(400).json({ error: "media_url must start with https://." });
    }

    const user = await updateUserLastMediaUrlStore({ username, mediaUrl, tenantId });
    req.session.user = user;
    return res.json({ user });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not save last media URL." });
  }
});

app.post("/api/auth/change-password", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const username = req.session.user?.username;
    const currentPassword = req.body.current_password || "";
    const newPassword = req.body.new_password || "";
    const user = await getUserByUsernameStore(username, tenantId);

    if (!user || !verifyUserPassword(user, currentPassword)) {
      return res.status(400).json({ error: "Current password is incorrect." });
    }

    await updateUserPasswordStore({ username, password: newPassword, tenantId });
    appendAuditEvent({
      tenantId,
      actorUsername: username,
      actorRole: req.session.user?.role || "user",
      action: "auth.password.changed",
      targetType: "user",
      targetId: user?.id || "",
      ipAddress: getAuthClientIp(req),
      metadata: {}
    });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not change password." });
  }
});

app.get("/api/health", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const cfg = getRuntimeConfig(tenantId);
  const isPersistentDataPath = DATA_DIR.startsWith(`${RENDER_PERSISTENT_ROOT}/`);
  res.json({
    ok: true,
    app: "telnyx-fax-office-app",
    configured: Boolean(cfg.telnyx_api_key && cfg.telnyx_connection_id && cfg.telnyx_from_number),
    has_api_key: Boolean(cfg.telnyx_api_key),
    has_connection_id: Boolean(cfg.telnyx_connection_id),
    has_from_number: Boolean(cfg.telnyx_from_number),
    has_fax_application_id: Boolean(cfg.telnyx_fax_application_id),
    d1_users_enabled: D1_USERS_ENABLED,
    d1_app_stores_enabled: D1_APP_STORES_ENABLED,
    webhook_signature_required: WEBHOOK_SIGNATURE_REQUIRED,
    webhook_public_key_configured: Boolean(TELNYX_WEBHOOK_PUBLIC_KEY),
    hosting: {
      is_render: IS_RENDER_RUNTIME,
      data_dir: DATA_DIR,
      persistent_data_path: isPersistentDataPath
    },
    auth: {
      rate_window_ms: AUTH_RATE_WINDOW_MS,
      max_attempts_per_ip: AUTH_RATE_MAX_ATTEMPTS_PER_IP,
      lockout_threshold: AUTH_LOCKOUT_THRESHOLD,
      lockout_ms: AUTH_LOCKOUT_MS
    },
    session_store_mode: SESSION_STORE_MODE,
    commercial: {
      multi_tenant_enabled: MULTI_TENANT_ENABLED,
      commercial_enforcements_enabled: COMMERCIAL_ENFORCEMENTS_ENABLED,
      billing_mode: BILLING_MODE,
      default_tenant_id: DEFAULT_TENANT_ID,
      active_tenant_id: tenantId,
      idempotency_ttl_seconds: IDEMPOTENCY_TTL_SECONDS
    }
  });
});

app.get("/api/settings", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const tenant = getTenantById(tenantId);
  if (!tenant) {
    return res.status(404).json({ error: "Tenant not found." });
  }
  const cfg = getRuntimeConfig(tenantId);
  const billing = getTenantBilling(tenantId);
  return res.json({
    tenant_id: tenantId,
    plan: billing.plan,
    outbound_copy_enabled: cfg.outbound_copy_enabled !== false,
    outbound_copy_email: cfg.outbound_copy_email || "eyecarecenteroc@gmail.com",
    office_name: cfg.office_name || "Eyecare Care of Orange County",
    office_fax_number: cfg.office_fax_number || "+17145580642",
    office_email: cfg.office_email || "eyecarecenteroc@gmail.com"
  });
});

app.get("/api/faxes", async (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const limit = Math.max(1, Math.min(Number(req.query.limit || FAX_HISTORY_VISIBLE_LIMIT), 100));
  let syncWarning = "";
  try {
    const cfg = getRuntimeConfig(tenantId);
    if (cfg.telnyx_api_key) {
      const remote = await telnyxListFaxes({ apiKey: cfg.telnyx_api_key, pageSize: limit });
      const remoteItems = Array.isArray(remote) ? remote : [];
      remoteItems.forEach((fax) => {
        if (!fax?.id) return;
        upsertFax(fax.id, {
          id: fax.id,
          direction: fax.direction,
          status: fax.status,
          from: fax.from,
          to: fax.to,
          media_url: Array.isArray(fax.media_url) ? fax.media_url.join("\n") : fax.media_url,
          media_urls: Array.isArray(fax.media_url) ? fax.media_url : parseMediaUrlsInput(fax.media_url || ""),
          failure_reason: fax.failure_reason || null,
          telnyx_updated_at: fax.updated_at,
          page_count: fax.page_count || null,
          created_at: fax.created_at
        }, tenantId);
      });
      rotateFaxStoreToVisibleLimit(FAX_HISTORY_VISIBLE_LIMIT, tenantId);
    }
  } catch (error) {
    // Non-blocking: return local store if Telnyx sync fails.
    syncWarning = error?.message || "Telnyx history sync failed.";
  }

  const store = readStore();
  const archive = readArchiveStore();
  const merged = sortFaxItemsDesc([
    ...Object.values(store.items || {}).filter((item) => normalizeTenantId(item.tenant_id) === tenantId),
    ...Object.values(archive.items || {}).filter((item) => normalizeTenantId(item.tenant_id) === tenantId)
  ]);
  const deduped = [];
  const seenIds = new Set();
  merged.forEach((item) => {
    const id = item?.id || crypto.randomUUID();
    if (seenIds.has(id)) {
      return;
    }
    seenIds.add(id);
    deduped.push(item);
  });
  const items = deduped.slice(0, limit);
  res.json({ items, updated_at: store.updated_at, limit, sync_warning: syncWarning });
});

app.get("/api/faxes/archive", requireAdmin, (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const limit = Math.max(1, Math.min(Number(req.query.limit || 500), 2000));
  const archive = readArchiveStore();
  const items = sortFaxItemsDesc(
    Object.values(archive.items || {}).filter((item) => normalizeTenantId(item.tenant_id) === tenantId)
  ).slice(0, limit);
  return res.json({ items, updated_at: archive.updated_at, limit });
});

app.post("/api/faxes", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const cfg = requireConfig(res, tenantId);
    if (!cfg) {
      return;
    }

    const recipientTokens = parseRecipientTokensInput(req.body.to_numbers || req.body.to || "");
    const toNumbers = parseRecipientNumbersInput(recipientTokens);
    const mediaUrls = parseMediaUrlsInput(req.body.media_urls || req.body.media_url || "");
    const includeCoverPage =
      req.body.include_cover_page === undefined
        ? true
        : req.body.include_cover_page === true || req.body.include_cover_page === "true";
    const coverSubject = (req.body.cover_subject || "").toString().trim();
    const coverMessage = (req.body.cover_message || "").toString().trim();

    if (!recipientTokens.length) {
      return res.status(400).json({
        error: "Provide at least one destination number in E.164 format, for example +17145551234."
      });
    }
    const invalidNumber = recipientTokens.find((value) => !isE164(normalizeE164(value)));
    if (invalidNumber) {
      return res.status(400).json({
        error: `Invalid destination number: ${invalidNumber}. Use E.164 format, for example +17145551234.`
      });
    }
    const maxRecipients = Math.min(
      MAX_SEND_RECIPIENTS,
      getTenantPlanLimits(tenantId).max_recipients_per_send
    );
    if (toNumbers.length > maxRecipients) {
      return res.status(400).json({
        error: `Too many recipients. Maximum is ${maxRecipients} per send request for your plan.`
      });
    }
    if (!mediaUrls.length) {
      return res
        .status(400)
        .json({ error: "Provide one or more public https media URLs (PDF/TIFF)." });
    }
    const invalidMediaUrl = mediaUrls.find((url) => !isHttpsMediaUrl(url));
    if (invalidMediaUrl) {
      return res.status(400).json({
        error: `Invalid media URL: ${invalidMediaUrl}. Media URLs must be public https links reachable by Telnyx.`
      });
    }

    const idempotencyKey = (req.get("Idempotency-Key") || "").toString().trim();
    if (idempotencyKey) {
      const cached = getIdempotentResponse({
        tenantId,
        key: idempotencyKey,
        method: req.method,
        path: req.path
      });
      if (cached) {
        return res.status(cached.status_code || 200).json({
          ...(cached.response_body || {}),
          idempotent_replay: true
        });
      }
    }

    const requestedBy = req.session.user?.username || "unknown";
    let sendCopyEmail = cfg.outbound_copy_enabled !== false;
    if (req.body.send_copy_email !== undefined) {
      sendCopyEmail =
        req.body.send_copy_email === true || req.body.send_copy_email === "true";
    }

    const results = [];
    const queuedRecipients = [];
    const faxIds = [];

    for (const to of toNumbers) {
      try {
        let finalMediaUrls = [...mediaUrls];
        let coverPageMediaUrl = null;
        if (includeCoverPage) {
          coverPageMediaUrl = await generateCoverPageMediaUrl({
            req,
            cfg,
            toNumber: to,
            subject: coverSubject,
            message: coverMessage,
            requestedBy
          });
          finalMediaUrls = [coverPageMediaUrl, ...finalMediaUrls];
        }

        const fax = await telnyxSendFax({
          apiKey: cfg.telnyx_api_key,
          connectionId: cfg.telnyx_connection_id,
          from: cfg.telnyx_from_number,
          to,
          mediaUrls: finalMediaUrls
        });

        upsertFax(fax.id, {
          id: fax.id,
          direction: fax.direction,
          status: fax.status,
          from: fax.from,
          to: fax.to,
          media_url: Array.isArray(fax.media_url) ? fax.media_url.join("\n") : fax.media_url,
          media_urls: finalMediaUrls,
          include_cover_page: includeCoverPage,
          cover_subject: coverSubject || "Fax Transmission",
          cover_message: coverMessage || "",
          failure_reason: null,
          telnyx_updated_at: fax.updated_at,
          created_at: fax.created_at
        }, tenantId);
        appendEvent(fax.id, "fax.queued", fax, tenantId);

        let copyResult = { sent: false, reason: "not_attempted" };
        try {
          copyResult = await sendOutboundCopyEmail({
            cfg,
            fax,
            mediaUrl: finalMediaUrls[0],
            mediaUrls: finalMediaUrls,
            requestedBy,
            bulkJobId: null,
            enabledOverride: sendCopyEmail
          });
        } catch (copyError) {
          copyResult = { sent: false, reason: copyError.message || "copy_email_failed" };
        }

        faxIds.push(fax.id);
        queuedRecipients.push(to);
        results.push({
          to,
          fax_id: fax.id,
          status: fax.status,
          queued: true,
          copy_email_sent: copyResult.sent,
          copy_email_reason: copyResult.reason,
          cover_page_added: Boolean(coverPageMediaUrl),
          error: null
        });
      } catch (recipientError) {
        results.push({
          to,
          fax_id: null,
          status: "failed",
          queued: false,
          copy_email_sent: false,
          copy_email_reason: "not_attempted",
          cover_page_added: false,
          error: recipientError.message || "Failed to queue fax."
        });
      }
    }

    if (!faxIds.length) {
      const firstError = results.find((item) => item.error)?.error || "Failed to send fax.";
      appendAuditEvent({
        tenantId,
        actorUsername: requestedBy,
        actorRole: req.session.user?.role || "user",
        action: "fax.send.failed",
        targetType: "fax",
        targetId: "",
        ipAddress: getAuthClientIp(req),
        metadata: { error: firstError, recipients: toNumbers.length }
      });
      return res.status(400).json({ error: firstError, results });
    }

    markContactsUsedByFaxNumbers(queuedRecipients, tenantId);

    try {
      const updatedUser = await updateUserLastMediaUrlStore({
        username: req.session.user?.username,
        mediaUrl: mediaUrls[0],
        tenantId
      });
      req.session.user = updatedUser;
    } catch (error) {
      // Non-blocking: fax send can still succeed if preference write fails.
    }
    const firstQueuedResult = results.find((item) => item.queued);
    const failedCount = results.filter((item) => !item.queued).length;
    const responseBody = {
      fax_id: firstQueuedResult?.fax_id || null,
      fax_ids: faxIds,
      queued_count: faxIds.length,
      failed_count: failedCount,
      total_recipients: toNumbers.length,
      status: firstQueuedResult?.status || "queued",
      cover_page_added: includeCoverPage,
      copy_email_sent: firstQueuedResult?.copy_email_sent || false,
      copy_email_reason: firstQueuedResult?.copy_email_reason || "not_attempted",
      results
    };
    if (idempotencyKey) {
      saveIdempotentResponse({
        tenantId,
        key: idempotencyKey,
        method: req.method,
        path: req.path,
        statusCode: 202,
        responseBody
      });
    }
    appendAuditEvent({
      tenantId,
      actorUsername: requestedBy,
      actorRole: req.session.user?.role || "user",
      action: "fax.send.queued",
      targetType: "fax",
      targetId: faxIds[0] || "",
      ipAddress: getAuthClientIp(req),
      metadata: { queued_count: faxIds.length, failed_count: failedCount }
    });
    return res.status(202).json(responseBody);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Failed to send fax." });
  }
});

app.get("/api/contacts", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const items = listContacts({
    search: req.query.search || "",
    tag: req.query.tag || "",
    tenantId
  });
  const maxContacts = getTenantPlanLimits(tenantId).max_contacts;
  return res.json({ items, total: items.length, max_contacts: maxContacts });
});

app.get("/api/contacts/tags", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  return res.json({ items: listContactTags(tenantId) });
});

app.get("/api/contacts/frequent", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const limit = Number(req.query.limit || 5);
  return res.json({ items: listFrequentContacts(limit, tenantId) });
});

app.post("/api/contacts", (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const created = createContact({
      name: req.body.name,
      fax_number: req.body.fax_number,
      tags: req.body.tags,
      email: req.body.email,
      notes: req.body.notes,
      tenantId
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "user",
      action: "contact.created",
      targetType: "contact",
      targetId: created.id,
      ipAddress: getAuthClientIp(req),
      metadata: { fax_number: created.fax_number }
    });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create contact." });
  }
});

app.patch("/api/contacts/:id", (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const updated = updateContact(req.params.id, {
      name: req.body.name,
      fax_number: req.body.fax_number,
      tags: req.body.tags,
      email: req.body.email,
      notes: req.body.notes
    }, tenantId);
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "user",
      action: "contact.updated",
      targetType: "contact",
      targetId: updated.id,
      ipAddress: getAuthClientIp(req),
      metadata: {}
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update contact." });
  }
});

app.delete("/api/contacts/:id", (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    deleteContact(req.params.id, tenantId);
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "user",
      action: "contact.deleted",
      targetType: "contact",
      targetId: req.params.id,
      ipAddress: getAuthClientIp(req),
      metadata: {}
    });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not delete contact." });
  }
});

app.post("/api/contacts/import", (req, res) => {
  importUpload.single("file")(req, res, (error) => {
    if (error instanceof multer.MulterError) {
      return res.status(400).json({ error: error.message || "Import upload failed." });
    }
    if (error) {
      return res.status(400).json({ error: error.message || "Import upload failed." });
    }
    if (!req.file) {
      return res.status(400).json({ error: "No CSV file uploaded." });
    }

    try {
      const tenantId = normalizeTenantId(req.tenant_id);
      const csvText = req.file.buffer.toString("utf8");
      const summary = importContactsFromCsv(csvText, tenantId);
      appendAuditEvent({
        tenantId,
        actorUsername: req.session.user?.username || "unknown",
        actorRole: req.session.user?.role || "user",
        action: "contact.imported",
        targetType: "contact",
        targetId: "",
        ipAddress: getAuthClientIp(req),
        metadata: summary
      });
      return res.json(summary);
    } catch (parseError) {
      return res.status(400).json({
        error:
          parseError.message ||
          "Could not parse CSV. Expected headers like name,fax_number,tags,email,notes."
      });
    }
  });
});

app.post("/api/faxes/bulk", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const cfg = requireConfig(res, tenantId);
    if (!cfg) {
      return;
    }

    const mediaUrl = (req.body.media_url || "").toString().trim();
    const tagFilters = normalizeTags(req.body.tag_filters || []);
    const tagMode = req.body.tag_mode === "all" ? "all" : "any";
    const contactIds = Array.isArray(req.body.contact_ids) ? req.body.contact_ids : [];
    const sendAll = req.body.send_all === true || req.body.send_all === "true";

    if (!mediaUrl.startsWith("https://")) {
      return res.status(400).json({ error: "media_url must be a public https URL." });
    }

    const allContacts = listContacts({ tenantId });
    let selectedContacts = [];
    if (contactIds.length) {
      const set = new Set(contactIds);
      selectedContacts = allContacts.filter((contact) => set.has(contact.id));
    } else if (sendAll) {
      selectedContacts = allContacts;
    } else {
      selectedContacts = allContacts.filter((contact) =>
        matchesTagFilter(contact.tags, tagFilters, tagMode)
      );
    }

    if (!selectedContacts.length) {
      return res.status(400).json({ error: "No contacts matched the selected filters." });
    }

    const job = createBulkJob({
      created_by: req.session.user?.username || "unknown",
      media_url: mediaUrl,
      tag_filters: tagFilters,
      tag_mode: tagMode,
      contacts: selectedContacts,
      tenantId
    });

    const updatedUser = await updateUserLastMediaUrlStore({
      username: req.session.user?.username,
      mediaUrl,
      tenantId
    });
    req.session.user = updatedUser;
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "user",
      action: "fax.bulk.queued",
      targetType: "bulk_job",
      targetId: job.id,
      ipAddress: getAuthClientIp(req),
      metadata: { total: job.totals?.total || 0 }
    });

    setImmediate(() => {
      processQueuedBulkJobs().catch(() => {
        // Errors are persisted inside job updates.
      });
    });

    return res.status(202).json(job);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create bulk fax job." });
  }
});

app.get("/api/faxes/bulk-jobs", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const store = readBulkJobsStore();
  const items = Object.values(store.items)
    .filter((job) => normalizeTenantId(job.tenant_id) === tenantId)
    .sort((a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime());
  return res.json({ items });
});

app.get("/api/faxes/bulk-jobs/:id", (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const store = readBulkJobsStore();
  const item = store.items[req.params.id];
  if (!item || normalizeTenantId(item.tenant_id) !== tenantId) {
    return res.status(404).json({ error: "Bulk job not found." });
  }
  return res.json(item);
});

app.post("/api/uploads", (req, res) => {
  upload.single("file")(req, res, async (error) => {
    if (error instanceof multer.MulterError) {
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ error: "File too large. Maximum size is 50MB." });
      }
      return res.status(400).json({ error: error.message || "Upload failed." });
    }
    if (error) {
      return res.status(400).json({ error: error.message || "Upload failed." });
    }
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded." });
    }

    const mediaUrl = getPublicMediaUrl(req, req.file.filename);
    try {
      const tenantId = normalizeTenantId(req.tenant_id);
      const updatedUser = await updateUserLastMediaUrlStore({
        username: req.session.user?.username,
        mediaUrl,
        tenantId
      });
      req.session.user = updatedUser;
    } catch (prefError) {
      // Do not fail upload when saving preference fails.
    }

    return res.status(201).json({
      media_url: mediaUrl,
      original_name: req.file.originalname,
      size: req.file.size
    });
  });
});

app.post("/api/uploads/batch", (req, res) => {
  upload.array("files", MAX_UPLOAD_BATCH_FILES)(req, res, async (error) => {
    if (error instanceof multer.MulterError) {
      if (error.code === "LIMIT_FILE_SIZE") {
        return res.status(400).json({ error: "A file is too large. Maximum size is 50MB." });
      }
      if (error.code === "LIMIT_UNEXPECTED_FILE") {
        return res.status(400).json({
          error: `Too many files. Maximum is ${MAX_UPLOAD_BATCH_FILES} files per fax send.`
        });
      }
      return res.status(400).json({ error: error.message || "Upload failed." });
    }
    if (error) {
      return res.status(400).json({ error: error.message || "Upload failed." });
    }
    const files = Array.isArray(req.files) ? req.files : [];
    if (!files.length) {
      return res.status(400).json({ error: "No files uploaded." });
    }

    const mediaUrls = files.map((file) => getPublicMediaUrl(req, file.filename));
    try {
      const tenantId = normalizeTenantId(req.tenant_id);
      const updatedUser = await updateUserLastMediaUrlStore({
        username: req.session.user?.username,
        mediaUrl: mediaUrls[0],
        tenantId
      });
      req.session.user = updatedUser;
    } catch (prefError) {
      // Non-blocking
    }

    return res.status(201).json({
      media_urls: mediaUrls,
      files: files.map((file, index) => ({
        media_url: mediaUrls[index],
        original_name: file.originalname,
        size: file.size
      }))
    });
  });
});

app.post("/api/faxes/:id/refresh", async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const store = readStore();
    const archive = readArchiveStore();
    const localFax = store.items?.[req.params.id] || archive.items?.[req.params.id] || null;
    if (!localFax || normalizeTenantId(localFax.tenant_id) !== tenantId) {
      return res.status(404).json({ error: "Fax not found for tenant." });
    }
    const cfg = requireConfig(res, tenantId);
    if (!cfg) {
      return;
    }
    const fax = await telnyxGetFax({ apiKey: cfg.telnyx_api_key, faxId: req.params.id });
    const saved = upsertFax(fax.id, {
      id: fax.id,
      direction: fax.direction,
      status: fax.status,
      from: fax.from,
      to: fax.to,
      media_url: fax.media_url,
      failure_reason: fax.failure_reason || null,
      telnyx_updated_at: fax.updated_at,
      page_count: fax.page_count || null,
      created_at: fax.created_at
    }, tenantId);
    return res.json(saved);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Failed to refresh fax status." });
  }
});

app.get("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const items = await listUsersSafeStore(tenantId);
    return res.json({ items });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not load users." });
  }
});

app.post("/api/admin/users", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const created = await createUserStore({
      username: req.body.username,
      password: req.body.password,
      role: req.body.role || "user",
      tenantId
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.user.created",
      targetType: "user",
      targetId: created.id,
      ipAddress: getAuthClientIp(req),
      metadata: { username: created.username, role: created.role }
    });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create user." });
  }
});

app.patch("/api/admin/users/:username/password", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const updated = await updateUserPasswordStore({
      username: req.params.username,
      password: req.body.password,
      tenantId
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.user.password_reset",
      targetType: "user",
      targetId: updated.id,
      ipAddress: getAuthClientIp(req),
      metadata: { username: updated.username }
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not reset password." });
  }
});

app.patch("/api/admin/users/:username/mfa", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const enabled = req.body.enabled === true || req.body.enabled === "true";
    const updated = await updateUserMfaStore({
      username: req.params.username,
      enabled,
      tenantId
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.user.mfa_updated",
      targetType: "user",
      targetId: updated.id,
      ipAddress: getAuthClientIp(req),
      metadata: { username: updated.username, mfa_enabled: updated.mfa_enabled }
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update user MFA setting." });
  }
});

app.get("/api/admin/audit-events", requireAdmin, (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const limit = Math.max(1, Math.min(Number(req.query.limit || 200), 2000));
  const action = (req.query.action || "").toString().trim();
  const items = listAuditEvents({ tenantId, limit, action });
  return res.json({ items, tenant_id: tenantId, limit });
});

app.get("/api/admin/billing", requireAdmin, (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const tenant = getTenantById(tenantId);
  if (!tenant) {
    return res.status(404).json({ error: "Tenant not found." });
  }
  const billing = getTenantBilling(tenantId);
  const limits = getTenantPlanLimits(tenantId);
  return res.json({
    tenant_id: tenantId,
    billing_mode: BILLING_MODE,
    billing,
    limits,
    supported_plans: BILLING_MODE === "paid" ? BILLING_SUPPORTED_PLANS : []
  });
});

app.patch("/api/admin/billing", requireAdmin, (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const next = updateTenantBilling(tenantId, {
      plan: req.body.plan,
      seats: req.body.seats,
      status: req.body.status
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.billing.updated",
      targetType: "billing",
      targetId: tenantId,
      ipAddress: getAuthClientIp(req),
      metadata: { plan: next.plan, seats: next.seats, status: next.status }
    });
    return res.json({
      tenant_id: tenantId,
      billing: next,
      limits: getTenantPlanLimits(tenantId)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update billing." });
  }
});

app.get("/api/admin/tenant", requireAdmin, (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const tenants = readTenantsStore();
  const tenant = tenants.items?.[tenantId] || null;
  if (!tenant) {
    return res.status(404).json({ error: "Tenant not found." });
  }
  return res.json({
    tenant_id: tenantId,
    tenant,
    billing: getTenantBilling(tenantId),
    limits: getTenantPlanLimits(tenantId)
  });
});

app.get("/api/admin/tenants", requireAdmin, (req, res) => {
  const currentTenantId = normalizeTenantId(req.tenant_id);
  const items = Object.values(readTenantsStore().items || {})
    .filter((tenant) =>
      currentTenantId === DEFAULT_TENANT_ID ? true : normalizeTenantId(tenant.id) === currentTenantId
    )
    .sort((a, b) => new Date(a.created_at || 0).getTime() - new Date(b.created_at || 0).getTime());
  return res.json({ items, billing_mode: BILLING_MODE });
});

app.post("/api/admin/tenants", requireAdmin, (req, res) => {
  try {
    const currentTenantId = normalizeTenantId(req.tenant_id);
    if (currentTenantId !== DEFAULT_TENANT_ID) {
      return res.status(403).json({ error: "Tenant provisioning is only allowed from the default tenant admin." });
    }
    const tenant = createTenantRecord({
      tenantId: req.body.tenant_id,
      name: req.body.name,
      plan: BILLING_MODE === "paid" ? req.body.plan : "free",
      active: req.body.active
    });
    appendAuditEvent({
      tenantId: DEFAULT_TENANT_ID,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.tenant.created",
      targetType: "tenant",
      targetId: tenant.id,
      ipAddress: getAuthClientIp(req),
      metadata: { name: tenant.name, plan: tenant.plan, active: tenant.active }
    });
    return res.status(201).json({ tenant, billing_mode: BILLING_MODE });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create tenant." });
  }
});

app.get("/api/admin/settings", requireAdmin, (req, res) => {
  const tenantId = normalizeTenantId(req.tenant_id);
  const cfg = getRuntimeConfig(tenantId);
  res.json({
    tenant_id: tenantId,
    telnyx_connection_id: cfg.telnyx_connection_id,
    telnyx_from_number: cfg.telnyx_from_number,
    telnyx_fax_application_id: cfg.telnyx_fax_application_id,
    outbound_copy_enabled: cfg.outbound_copy_enabled,
    outbound_copy_email: cfg.outbound_copy_email,
    office_name: cfg.office_name,
    office_fax_number: cfg.office_fax_number,
    office_email: cfg.office_email,
    has_telnyx_api_key: Boolean(cfg.telnyx_api_key)
  });
});

app.patch("/api/admin/settings", requireAdmin, (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const cfg = readConfig(tenantId);
    const next = { ...cfg };

    if (req.body.telnyx_api_key !== undefined) {
      next.telnyx_api_key = (req.body.telnyx_api_key || "").trim();
    }
    if (req.body.telnyx_connection_id !== undefined) {
      next.telnyx_connection_id = (req.body.telnyx_connection_id || "").trim();
    }
    if (req.body.telnyx_from_number !== undefined) {
      const value = normalizeE164(req.body.telnyx_from_number);
      if (value && !isE164(value)) {
        return res.status(400).json({ error: "TELNYX from number must be E.164 format." });
      }
      next.telnyx_from_number = value;
    }
    if (req.body.telnyx_fax_application_id !== undefined) {
      next.telnyx_fax_application_id = (req.body.telnyx_fax_application_id || "").trim();
    }
    if (req.body.outbound_copy_enabled !== undefined) {
      next.outbound_copy_enabled =
        req.body.outbound_copy_enabled === true || req.body.outbound_copy_enabled === "true";
    }
    if (req.body.outbound_copy_email !== undefined) {
      const email = (req.body.outbound_copy_email || "").trim();
      if (email && !isEmail(email)) {
        return res.status(400).json({ error: "outbound_copy_email must be a valid email address." });
      }
      next.outbound_copy_email = email;
    }
    if (req.body.office_name !== undefined) {
      next.office_name = (req.body.office_name || "").trim() || "Eyecare Care of Orange County";
    }
    if (req.body.office_fax_number !== undefined) {
      const value = normalizeE164(req.body.office_fax_number);
      if (value && !isE164(value)) {
        return res.status(400).json({ error: "office_fax_number must be E.164 format." });
      }
      next.office_fax_number = value || "+17145580642";
    }
    if (req.body.office_email !== undefined) {
      const email = (req.body.office_email || "").trim();
      if (email && !isEmail(email)) {
        return res.status(400).json({ error: "office_email must be a valid email address." });
      }
      next.office_email = email || "eyecarecenteroc@gmail.com";
    }

    writeConfig(next, tenantId);
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.settings.updated",
      targetType: "settings",
      targetId: tenantId,
      ipAddress: getAuthClientIp(req),
      metadata: {}
    });
    return res.json({
      ok: true,
      telnyx_connection_id: next.telnyx_connection_id,
      telnyx_from_number: next.telnyx_from_number,
      telnyx_fax_application_id: next.telnyx_fax_application_id,
      outbound_copy_enabled: next.outbound_copy_enabled !== false,
      outbound_copy_email: next.outbound_copy_email || "",
      office_name: next.office_name || "Eyecare Care of Orange County",
      office_fax_number: next.office_fax_number || "+17145580642",
      office_email: next.office_email || "eyecarecenteroc@gmail.com",
      has_telnyx_api_key: Boolean(next.telnyx_api_key)
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update settings." });
  }
});

app.get("/api/admin/telnyx/fax-application", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const cfg = requireConfig(res, tenantId);
    if (!cfg) {
      return;
    }
    if (!cfg.telnyx_fax_application_id) {
      return res.status(400).json({ error: "Set telnyx_fax_application_id in Admin Settings first." });
    }

    const data = await telnyxGetFaxApplication({
      apiKey: cfg.telnyx_api_key,
      faxApplicationId: cfg.telnyx_fax_application_id
    });

    return res.json({
      id: data.id,
      application_name: data.application_name,
      fax_email_recipient: data.fax_email_recipient || "",
      inbound_channel_limit: data?.inbound?.channel_limit ?? null,
      outbound_channel_limit: data?.outbound?.channel_limit ?? null,
      webhook_event_url: data.webhook_event_url || ""
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not fetch fax application." });
  }
});

app.patch("/api/admin/telnyx/fax-application", requireAdmin, async (req, res) => {
  try {
    const tenantId = normalizeTenantId(req.tenant_id);
    const cfg = requireConfig(res, tenantId);
    if (!cfg) {
      return;
    }
    if (!cfg.telnyx_fax_application_id) {
      return res.status(400).json({ error: "Set telnyx_fax_application_id in Admin Settings first." });
    }

    const payload = {};
    if (req.body.fax_email_recipient !== undefined) {
      const email = (req.body.fax_email_recipient || "").trim();
      if (email && !isEmail(email)) {
        return res.status(400).json({ error: "fax_email_recipient must be a valid email address." });
      }
      payload.fax_email_recipient = email;
    }
    if (req.body.inbound_channel_limit !== undefined && req.body.inbound_channel_limit !== "") {
      const inboundLimit = Number(req.body.inbound_channel_limit);
      if (!Number.isInteger(inboundLimit) || inboundLimit < 1) {
        return res.status(400).json({ error: "inbound_channel_limit must be an integer >= 1." });
      }
      payload.inbound = { channel_limit: inboundLimit };
    }
    if (req.body.outbound_channel_limit !== undefined && req.body.outbound_channel_limit !== "") {
      const outboundLimit = Number(req.body.outbound_channel_limit);
      if (!Number.isInteger(outboundLimit) || outboundLimit < 1) {
        return res.status(400).json({ error: "outbound_channel_limit must be an integer >= 1." });
      }
      payload.outbound = { channel_limit: outboundLimit };
    }

    if (!Object.keys(payload).length) {
      return res.status(400).json({ error: "No fax application fields provided." });
    }

    const data = await telnyxPatchFaxApplication({
      apiKey: cfg.telnyx_api_key,
      faxApplicationId: cfg.telnyx_fax_application_id,
      payload
    });
    appendAuditEvent({
      tenantId,
      actorUsername: req.session.user?.username || "unknown",
      actorRole: req.session.user?.role || "admin",
      action: "admin.telnyx.fax_application.updated",
      targetType: "telnyx_fax_application",
      targetId: cfg.telnyx_fax_application_id,
      ipAddress: getAuthClientIp(req),
      metadata: {
        fax_email_recipient: data.fax_email_recipient || "",
        inbound_channel_limit: data?.inbound?.channel_limit ?? null,
        outbound_channel_limit: data?.outbound?.channel_limit ?? null
      }
    });

    return res.json({
      ok: true,
      id: data.id,
      fax_email_recipient: data.fax_email_recipient || "",
      inbound_channel_limit: data?.inbound?.channel_limit ?? null,
      outbound_channel_limit: data?.outbound?.channel_limit ?? null
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update fax application." });
  }
});

app.post(["/api/webhooks/telnyx", "/telnyx/webhook"], (req, res) => {
  try {
    const fallbackTenantId = DEFAULT_TENANT_ID;
    const signature = verifyTelnyxWebhookSignature(req);
    if (!signature.valid) {
      return res.status(401).json({ error: `Webhook signature invalid (${signature.reason}).` });
    }
    const parsed = parseWebhook(req.body);
    if (parsed.faxId) {
      const tenantId = getFaxTenantId(parsed.faxId, fallbackTenantId);
      upsertFax(parsed.faxId, {
        id: parsed.faxId,
        status: parsed.status,
        failure_reason: parsed.failureReason
      }, tenantId);
      appendEvent(parsed.faxId, parsed.eventType, parsed.payload, tenantId);
      appendAuditEvent({
        tenantId,
        actorUsername: "telnyx-webhook",
        actorRole: "system",
        action: "fax.webhook.received",
        targetType: "fax",
        targetId: parsed.faxId,
        ipAddress: getAuthClientIp(req),
        metadata: { event_type: parsed.eventType, status: parsed.status }
      });
    }
    return res.status(200).json({ ok: true });
  } catch (error) {
    return res.status(200).json({ ok: true });
  }
});

app.get("/media/:filename", (req, res) => {
  try {
    const filename = safeBasename(req.params.filename || "");
    const exp = req.query.exp;
    const sig = req.query.sig;
    if (!filename || !verifySignedMediaAccess({ filename, exp, sig })) {
      return res.status(403).json({ error: "Invalid or expired media access link." });
    }

    const filePath = path.join(UPLOADS_DIR, filename);
    if (!fs.existsSync(filePath)) {
      return res.status(404).json({ error: "Media file not found." });
    }
    return res.sendFile(filePath);
  } catch (error) {
    return res.status(400).json({ error: "Could not access media file." });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(PUBLIC_DIR, "index.html"));
});

function startBackgroundWorkers() {
  if (!bulkWorkerInterval) {
    bulkWorkerInterval = setInterval(() => {
      processQueuedBulkJobs().catch((error) => {
        console.warn(`Bulk queue worker cycle failed: ${error.message || error}`);
      });
    }, BULK_WORKER_POLL_MS);
  }

  if (!uploadCleanupInterval) {
    uploadCleanupInterval = setInterval(() => {
      cleanExpiredUploads();
    }, Math.min(60 * 60 * 1000, Math.max(5 * 60 * 1000, MEDIA_URL_TTL_SECONDS * 1000)));
  }

  setTimeout(() => {
    processQueuedBulkJobs().catch(() => {});
    cleanExpiredUploads();
  }, 1000);
}

async function initializePersistence() {
  ensureDataFiles();
  if (!D1_USERS_ENABLED) {
    return;
  }
  await bootstrapD1AppStores();
  await ensureD1SessionsTable();
  await ensureD1UsersTable();
  await syncLocalUsersToD1();
  await ensureD1AdminUser();
}

initializePersistence()
  .then(() => {
    app.listen(port, () => {
      console.log(`Fax app running on port ${port}`);
      console.log(`Using data directory: ${DATA_DIR}`);
      if (D1_USERS_ENABLED) {
        console.log(`Cloudflare D1 users enabled (db: ${D1_DATABASE_ID}).`);
      } else {
        console.log("Cloudflare D1 users disabled. Using local file user store.");
      }
      if (D1_APP_STORES_ENABLED) {
        console.log("Cloudflare D1 app-store sync enabled for config/contacts/faxes.");
      } else {
        console.log("Cloudflare D1 app-store sync disabled. Using local JSON app stores.");
      }
      if (SESSION_STORE_MODE === "d1") {
        console.log("Session store mode: D1.");
      } else if (SESSION_STORE_MODE === "local_file") {
        console.log("Session store mode: local file.");
      } else {
        console.log("Session store mode: in-memory (non-persistent).");
      }
      if (!WEBHOOK_SIGNATURE_REQUIRED) {
        console.warn(
          "Telnyx webhook signature verification is disabled. Set TELNYX_WEBHOOK_PUBLIC_KEY and WEBHOOK_SIGNATURE_REQUIRED=true."
        );
      }
      if (IS_RENDER_RUNTIME && !DATA_DIR.startsWith(`${RENDER_PERSISTENT_ROOT}/`)) {
        console.warn(
          "Render persistent disk is not configured for DATA_DIR. Users/settings/history will reset after restart/deploy."
        );
      }
      if (IS_RENDER_RUNTIME) {
        console.warn(
          "Render free instances can sleep when idle. For always-on inbound fax webhooks, use a non-sleeping plan or external uptime pings."
        );
      }
      startBackgroundWorkers();
    });
  })
  .catch((error) => {
    console.error(`Startup failed: ${error.message || error}`);
    process.exit(1);
  });
