const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const { parse: parseCsv } = require("csv-parse/sync");
const nodemailer = require("nodemailer");
const PDFDocument = require("pdfkit");
require("dotenv").config();

const app = express();
const port = process.env.PORT || 10000;

const TELNYX_API_BASE = "https://api.telnyx.com/v2";
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, "data");
const STORE_FILE = path.join(DATA_DIR, "faxes.json");
const FAX_ARCHIVE_FILE = path.join(DATA_DIR, "faxes_archive.json");
const USERS_FILE = path.join(DATA_DIR, "users.json");
const CONFIG_FILE = path.join(DATA_DIR, "config.json");
const CONTACTS_FILE = path.join(DATA_DIR, "contacts.json");
const BULK_JOBS_FILE = path.join(DATA_DIR, "bulk_jobs.json");
const UPLOADS_DIR = path.join(__dirname, "public", "uploads");
const MAX_CONTACTS = 3000;
const MAX_SEND_RECIPIENTS = 100;
const MAX_UPLOAD_BATCH_FILES = 5;
const FAX_HISTORY_VISIBLE_LIMIT = 50;

let isBulkProcessorRunning = false;

const sessionSecret = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
if (!process.env.SESSION_SECRET) {
  console.warn("SESSION_SECRET not set. A temporary secret is being used for this process.");
}

app.set("trust proxy", 1);
app.use(express.json({ limit: "2mb" }));
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    name: "fax_app_session",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 12 * 60 * 60 * 1000
    }
  })
);
app.use(express.static(path.join(__dirname, "public")));

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
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function writeJson(filePath, value) {
  ensureDataDir();
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2));
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
          username: adminUsername,
          role: "admin",
          password_hash: bcrypt.hashSync(adminPassword, 12),
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

function readUsers() {
  return readJson(USERS_FILE, { updated_at: new Date().toISOString(), items: [] });
}

function writeUsers(users) {
  writeJson(USERS_FILE, users);
}

function readConfig() {
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
  const stored = readJson(CONFIG_FILE, defaults);
  return {
    ...defaults,
    ...stored
  };
}

function writeConfig(config) {
  writeJson(CONFIG_FILE, {
    ...config,
    updated_at: new Date().toISOString()
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

function markContactsUsedByFaxNumbers(faxNumbers = []) {
  const numbers = Array.from(new Set((faxNumbers || []).map((item) => normalizeE164(item)).filter(Boolean)));
  if (!numbers.length) {
    return;
  }

  const store = readContactsStore();
  const byFax = new Map(
    Object.values(store.items || {}).map((contact) => [normalizeE164(contact.fax_number), contact.id])
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

function listFrequentContacts(limit = 5) {
  const max = Math.max(1, Math.min(Number(limit) || 5, 20));
  const store = readContactsStore();
  return Object.values(store.items || {})
    .map((contact) => normalizeContactRecord(contact))
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
    username: user.username,
    role: user.role,
    last_media_url: user.last_media_url || "",
    created_at: user.created_at,
    updated_at: user.updated_at
  };
}

function getUserByUsername(username) {
  const users = readUsers();
  return users.items.find((item) => item.username === normalizeUsername(username)) || null;
}

function listUsersSafe() {
  const users = readUsers();
  return users.items.map((item) => sanitizeUser(item));
}

function createUser({ username, password, role }) {
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
  const exists = users.items.some((item) => item.username === normalizedUsername);
  if (exists) {
    throw new Error("Username already exists.");
  }

  const now = new Date().toISOString();
  const user = {
    id: crypto.randomUUID(),
    username: normalizedUsername,
    role,
    password_hash: bcrypt.hashSync(password, 12),
    last_media_url: "",
    created_at: now,
    updated_at: now
  };

  users.items.push(user);
  users.updated_at = now;
  writeUsers(users);
  return sanitizeUser(user);
}

function updateUserPassword({ username, password }) {
  if (!password || password.length < 10) {
    throw new Error("Password must be at least 10 characters.");
  }

  const users = readUsers();
  const index = users.items.findIndex((item) => item.username === normalizeUsername(username));
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

function updateUserLastMediaUrl({ username, mediaUrl }) {
  const users = readUsers();
  const index = users.items.findIndex((item) => item.username === normalizeUsername(username));
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

function listContacts({ search = "", tag = "" } = {}) {
  const store = readContactsStore();
  const searchTerm = (search || "").toString().trim().toLowerCase();
  const selectedTag = (tag || "").toString().trim().toLowerCase();

  return Object.values(store.items)
    .map((contact) => normalizeContactRecord(contact))
    .filter((contact) => {
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

function listContactTags() {
  const contacts = listContacts({});
  const tags = new Set();
  contacts.forEach((contact) => {
    normalizeTags(contact.tags).forEach((tag) => tags.add(tag));
  });
  return Array.from(tags).sort();
}

function createContact({ name, fax_number, tags, email, notes }) {
  const faxNumber = normalizeE164(fax_number);
  if (!isE164(faxNumber)) {
    throw new Error("fax_number must be E.164 format, for example +17145551234.");
  }

  const store = readContactsStore();
  if (contactCount(store) >= MAX_CONTACTS) {
    throw new Error(`Contact limit reached (${MAX_CONTACTS}). Remove contacts before adding new ones.`);
  }
  const exists = Object.values(store.items).some((item) => item.fax_number === faxNumber);
  if (exists) {
    throw new Error("A contact with that fax number already exists.");
  }

  const now = new Date().toISOString();
  const contact = {
    id: crypto.randomUUID(),
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

function updateContact(contactId, patch) {
  const store = readContactsStore();
  const existing = store.items[contactId];
  if (!existing) {
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
      (item) => item.id !== contactId && item.fax_number === faxNumber
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

function deleteContact(contactId) {
  const store = readContactsStore();
  if (!store.items[contactId]) {
    throw new Error("Contact not found.");
  }
  delete store.items[contactId];
  writeContactsStore(store);
}

function importContactsFromCsv(csvText) {
  const records = parseCsv(csvText, {
    columns: true,
    bom: true,
    skip_empty_lines: true,
    trim: true
  });

  const store = readContactsStore();
  const existingByFax = new Map(
    Object.values(store.items).map((item) => [item.fax_number, item])
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

    if (contactCount(store) >= MAX_CONTACTS) {
      result.skipped += 1;
      result.errors.push(`Row ${index + 2}: contact limit reached (${MAX_CONTACTS}).`);
      return;
    }

    const contact = {
      id: crypto.randomUUID(),
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

function createBulkJob({ created_by, media_url, tag_filters, tag_mode, contacts }) {
  const store = readBulkJobsStore();
  const now = new Date().toISOString();
  const job = {
    id: crypto.randomUUID(),
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

function updateBulkJob(jobId, updater) {
  const store = readBulkJobsStore();
  const existing = store.items[jobId];
  if (!existing) {
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

      const cfg = getRuntimeConfig();
      if (!cfg.telnyx_api_key || !cfg.telnyx_connection_id || !cfg.telnyx_from_number) {
        updateBulkJob(nextJob.id, (job) => ({
          ...job,
          status: "failed",
          completed_at: new Date().toISOString(),
          error: "Missing Telnyx settings."
        }));
        continue;
      }

      updateBulkJob(nextJob.id, (job) => ({ ...job, status: "running", error: null }));

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
          });
          appendEvent(fax.id, "fax.queued", fax);

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

          markContactsUsedByFaxNumbers([contact.fax_number]);

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
          });
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
          });
        }
      }

      updateBulkJob(nextJob.id, (job) => ({
        ...job,
        status: "completed",
        completed_at: new Date().toISOString()
      }));
    }
  } finally {
    isBulkProcessorRunning = false;
  }
}

function upsertFax(faxId, patch) {
  const store = readStore();
  const existing = store.items[faxId] || { id: faxId, events: [] };
  store.items[faxId] = {
    ...existing,
    ...patch,
    updated_at: new Date().toISOString()
  };
  store.updated_at = new Date().toISOString();
  writeStore(store);
  return store.items[faxId];
}

function appendEvent(faxId, eventType, payload) {
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

function rotateFaxStoreToVisibleLimit(limit = FAX_HISTORY_VISIBLE_LIMIT) {
  const maxVisible = Math.max(1, Number(limit) || FAX_HISTORY_VISIBLE_LIMIT);
  const store = readStore();
  const sorted = sortFaxItemsDesc(Object.values(store.items || {}));
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
      archived_at: new Date().toISOString()
    };
  });

  const keepIds = new Set(keep.map((item) => item.id));
  const nextItems = {};
  Object.entries(store.items || {}).forEach(([id, item]) => {
    if (keepIds.has(id)) {
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

function getRuntimeConfig() {
  const cfg = readConfig();
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
    smtp_from: process.env.SMTP_FROM || process.env.SMTP_USER || ""
  };
}

function requireConfig(res) {
  const cfg = getRuntimeConfig();
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

  const response = await fetch(`${TELNYX_API_BASE}${resourcePath}`, {
    method,
    headers,
    body: body ? (isForm ? body : JSON.stringify(body)) : undefined
  });

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
    if (!parsed.pathname.startsWith("/uploads/")) {
      return null;
    }
    const filename = path.basename(parsed.pathname);
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
  return `${req.protocol}://${req.get("host")}/uploads/${filename}`;
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
  return next();
}

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
  if (!req.session.user) {
    return res.status(401).json({ error: "Login required." });
  }
  return next();
});

app.post("/api/auth/login", (req, res) => {
  const username = normalizeUsername(req.body.username);
  const password = req.body.password || "";
  const user = getUserByUsername(username);

  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ error: "Invalid username or password." });
  }

  req.session.user = sanitizeUser(user);
  return res.json({ user: req.session.user });
});

app.post("/api/auth/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ ok: true });
  });
});

app.get("/api/auth/me", (req, res) => {
  if (!req.session.user) {
    return res.json({ authenticated: false });
  }
  return res.json({ authenticated: true, user: req.session.user });
});

app.patch("/api/me/last-media-url", (req, res) => {
  try {
    const username = req.session.user?.username;
    const mediaUrl = (req.body.media_url || "").trim();
    if (mediaUrl && !mediaUrl.startsWith("https://")) {
      return res.status(400).json({ error: "media_url must start with https://." });
    }

    const user = updateUserLastMediaUrl({ username, mediaUrl });
    req.session.user = user;
    return res.json({ user });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not save last media URL." });
  }
});

app.post("/api/auth/change-password", (req, res) => {
  try {
    const username = req.session.user?.username;
    const currentPassword = req.body.current_password || "";
    const newPassword = req.body.new_password || "";
    const user = getUserByUsername(username);

    if (!user || !bcrypt.compareSync(currentPassword, user.password_hash)) {
      return res.status(400).json({ error: "Current password is incorrect." });
    }

    updateUserPassword({ username, password: newPassword });
    return res.json({ ok: true });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not change password." });
  }
});

app.get("/api/health", (req, res) => {
  const cfg = getRuntimeConfig();
  res.json({
    ok: true,
    app: "telnyx-fax-office-app",
    configured: Boolean(cfg.telnyx_api_key && cfg.telnyx_connection_id && cfg.telnyx_from_number),
    has_api_key: Boolean(cfg.telnyx_api_key),
    has_connection_id: Boolean(cfg.telnyx_connection_id),
    has_from_number: Boolean(cfg.telnyx_from_number),
    has_fax_application_id: Boolean(cfg.telnyx_fax_application_id)
  });
});

app.get("/api/settings", (req, res) => {
  const cfg = getRuntimeConfig();
  return res.json({
    outbound_copy_enabled: cfg.outbound_copy_enabled !== false,
    outbound_copy_email: cfg.outbound_copy_email || "eyecarecenteroc@gmail.com",
    office_name: cfg.office_name || "Eyecare Care of Orange County",
    office_fax_number: cfg.office_fax_number || "+17145580642",
    office_email: cfg.office_email || "eyecarecenteroc@gmail.com"
  });
});

app.get("/api/faxes", async (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || FAX_HISTORY_VISIBLE_LIMIT), 100));
  try {
    const cfg = getRuntimeConfig();
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
        });
      });
      rotateFaxStoreToVisibleLimit(FAX_HISTORY_VISIBLE_LIMIT);
    }
  } catch (error) {
    // Non-blocking: return local store if Telnyx sync fails.
  }

  const store = readStore();
  const items = sortFaxItemsDesc(Object.values(store.items || {})).slice(0, limit);
  res.json({ items, updated_at: store.updated_at, limit });
});

app.get("/api/faxes/archive", requireAdmin, (req, res) => {
  const limit = Math.max(1, Math.min(Number(req.query.limit || 500), 2000));
  const archive = readArchiveStore();
  const items = sortFaxItemsDesc(Object.values(archive.items || {})).slice(0, limit);
  return res.json({ items, updated_at: archive.updated_at, limit });
});

app.post("/api/faxes", async (req, res) => {
  try {
    const cfg = requireConfig(res);
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
    if (toNumbers.length > MAX_SEND_RECIPIENTS) {
      return res.status(400).json({
        error: `Too many recipients. Maximum is ${MAX_SEND_RECIPIENTS} per send request.`
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
        });
        appendEvent(fax.id, "fax.queued", fax);

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
      return res.status(400).json({ error: firstError, results });
    }

    markContactsUsedByFaxNumbers(queuedRecipients);

    try {
      const updatedUser = updateUserLastMediaUrl({
        username: req.session.user?.username,
        mediaUrl: mediaUrls[0]
      });
      req.session.user = updatedUser;
    } catch (error) {
      // Non-blocking: fax send can still succeed if preference write fails.
    }
    const firstQueuedResult = results.find((item) => item.queued);
    const failedCount = results.filter((item) => !item.queued).length;
    return res.status(202).json({
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
    });
  } catch (error) {
    return res.status(400).json({ error: error.message || "Failed to send fax." });
  }
});

app.get("/api/contacts", (req, res) => {
  const items = listContacts({
    search: req.query.search || "",
    tag: req.query.tag || ""
  });
  return res.json({ items, total: items.length, max_contacts: MAX_CONTACTS });
});

app.get("/api/contacts/tags", (req, res) => {
  return res.json({ items: listContactTags() });
});

app.get("/api/contacts/frequent", (req, res) => {
  const limit = Number(req.query.limit || 5);
  return res.json({ items: listFrequentContacts(limit) });
});

app.post("/api/contacts", (req, res) => {
  try {
    const created = createContact({
      name: req.body.name,
      fax_number: req.body.fax_number,
      tags: req.body.tags,
      email: req.body.email,
      notes: req.body.notes
    });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create contact." });
  }
});

app.patch("/api/contacts/:id", (req, res) => {
  try {
    const updated = updateContact(req.params.id, {
      name: req.body.name,
      fax_number: req.body.fax_number,
      tags: req.body.tags,
      email: req.body.email,
      notes: req.body.notes
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not update contact." });
  }
});

app.delete("/api/contacts/:id", (req, res) => {
  try {
    deleteContact(req.params.id);
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
      const csvText = req.file.buffer.toString("utf8");
      const summary = importContactsFromCsv(csvText);
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
    const cfg = requireConfig(res);
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

    const allContacts = listContacts({});
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
      contacts: selectedContacts
    });

    const updatedUser = updateUserLastMediaUrl({
      username: req.session.user?.username,
      mediaUrl
    });
    req.session.user = updatedUser;

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
  const store = readBulkJobsStore();
  const items = Object.values(store.items).sort(
    (a, b) => new Date(b.updated_at).getTime() - new Date(a.updated_at).getTime()
  );
  return res.json({ items });
});

app.get("/api/faxes/bulk-jobs/:id", (req, res) => {
  const store = readBulkJobsStore();
  const item = store.items[req.params.id];
  if (!item) {
    return res.status(404).json({ error: "Bulk job not found." });
  }
  return res.json(item);
});

app.post("/api/uploads", (req, res) => {
  upload.single("file")(req, res, (error) => {
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
      const updatedUser = updateUserLastMediaUrl({
        username: req.session.user?.username,
        mediaUrl
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
  upload.array("files", MAX_UPLOAD_BATCH_FILES)(req, res, (error) => {
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
      const updatedUser = updateUserLastMediaUrl({
        username: req.session.user?.username,
        mediaUrl: mediaUrls[0]
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
    const cfg = requireConfig(res);
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
    });
    return res.json(saved);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Failed to refresh fax status." });
  }
});

app.get("/api/admin/users", requireAdmin, (req, res) => {
  res.json({ items: listUsersSafe() });
});

app.post("/api/admin/users", requireAdmin, (req, res) => {
  try {
    const created = createUser({
      username: req.body.username,
      password: req.body.password,
      role: req.body.role || "user"
    });
    return res.status(201).json(created);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not create user." });
  }
});

app.patch("/api/admin/users/:username/password", requireAdmin, (req, res) => {
  try {
    const updated = updateUserPassword({
      username: req.params.username,
      password: req.body.password
    });
    return res.json(updated);
  } catch (error) {
    return res.status(400).json({ error: error.message || "Could not reset password." });
  }
});

app.get("/api/admin/settings", requireAdmin, (req, res) => {
  const cfg = getRuntimeConfig();
  res.json({
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
    const cfg = readConfig();
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

    writeConfig(next);
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
    const cfg = requireConfig(res);
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
    const cfg = requireConfig(res);
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
    const parsed = parseWebhook(req.body);
    if (parsed.faxId) {
      upsertFax(parsed.faxId, {
        id: parsed.faxId,
        status: parsed.status,
        failure_reason: parsed.failureReason
      });
      appendEvent(parsed.faxId, parsed.eventType, parsed.payload);
    }
    return res.status(200).json({ ok: true });
  } catch (error) {
    return res.status(200).json({ ok: true });
  }
});

app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

ensureDataFiles();
app.listen(port, () => {
  console.log(`Fax app running on port ${port}`);
});
