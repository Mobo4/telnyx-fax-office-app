const loginPanel = document.getElementById("login-panel");
const appShell = document.getElementById("app-shell");
const adminPanel = document.getElementById("admin-panel");

const loginForm = document.getElementById("login-form");
const loginMessage = document.getElementById("login-message");
const tenantInput = document.getElementById("tenant_id");
const googleSigninBtn = document.getElementById("google-signin-btn");
const googleLoginHint = document.getElementById("google-login-hint");
const googleLinkBtn = document.getElementById("google-link-btn");
const logoutBtn = document.getElementById("logout-btn");
const settingsToggleBtn = document.getElementById("settings-toggle-btn");
const sessionLabel = document.getElementById("session-label");

const sendForm = document.getElementById("send-form");
const sendMessage = document.getElementById("send-message");
const sendFaxPrimaryBtn = document.getElementById("send-fax-primary-btn");
const toInput = document.getElementById("to");
const recipientNameSearchInput = document.getElementById("recipient_name_search");
const recipientSuggestions = document.getElementById("recipient-suggestions");
const mediaUrlInput = document.getElementById("media_url");
const sendFileInput = document.getElementById("send_file_input");
const selectedFilesList = document.getElementById("selected-files-list");
const fileSelectionMessage = document.getElementById("file-selection-message");
const lastUrlLabel = document.getElementById("last-url-label");
const sendCopyEmailInput = document.getElementById("send_copy_email");
const sendCopyLabel = document.getElementById("send-copy-label");
const includeCoverPageInput = document.getElementById("include_cover_page");
const coverSubjectInput = document.getElementById("cover_subject");
const coverMessageInput = document.getElementById("cover_message");
const officeNameDisplay = document.getElementById("office_name_display");
const officeFaxDisplay = document.getElementById("office_fax_display");
const officeEmailDisplay = document.getElementById("office_email_display");
const addressbookToggleBtn = document.getElementById("addressbook-toggle-btn");
const addressbookModal = document.getElementById("addressbook-modal");
const addressbookCloseBtn = document.getElementById("addressbook-close-btn");
const addressbookApplyBtn = document.getElementById("addressbook-apply-btn");
const addressbookTabContacts = document.getElementById("addressbook-tab-contacts");
const addressbookTabBulk = document.getElementById("addressbook-tab-bulk");
const addressbookContactsTab = document.getElementById("addressbook-contacts-tab");
const addressbookBulkTab = document.getElementById("addressbook-bulk-tab");
const addressbookSearchInput = document.getElementById("addressbook-search");
const addressbookList = document.getElementById("addressbook-list");
const recipientChips = document.getElementById("recipient-chips");
const frequentContacts = document.getElementById("frequent-contacts");
const tableBody = document.getElementById("fax-table-body");
const refreshAllButton = document.getElementById("refresh-all");
const historyTabSent = document.getElementById("history-tab-sent");
const historyTabReceived = document.getElementById("history-tab-received");

const contactForm = document.getElementById("contact-form");
const contactMessage = document.getElementById("contact-message");
const contactImportForm = document.getElementById("contact-import-form");
const contactImportMessage = document.getElementById("contact-import-message");
const contactSearchInput = document.getElementById("contact-search");
const contactTagFilter = document.getElementById("contact-tag-filter");
const contactRefreshBtn = document.getElementById("contact-refresh-btn");
const contactsTableBody = document.getElementById("contacts-table-body");

const bulkMediaUrlInput = document.getElementById("bulk_media_url");
const bulkTagModeSelect = document.getElementById("bulk_tag_mode");
const bulkSendAllInput = document.getElementById("bulk_send_all");
const bulkTagsList = document.getElementById("bulk-tags-list");
const bulkSendBtn = document.getElementById("bulk-send-btn");
const bulkRefreshBtn = document.getElementById("bulk-refresh-btn");
const bulkMessage = document.getElementById("bulk-message");
const bulkJobsBody = document.getElementById("bulk-jobs-body");

const settingsForm = document.getElementById("settings-form");
const settingsMessage = document.getElementById("settings-message");
const faxAppForm = document.getElementById("fax-app-form");
const faxAppMessage = document.getElementById("fax-app-message");
const loadFaxAppBtn = document.getElementById("load-fax-app");

const createUserForm = document.getElementById("create-user-form");
const usersMessage = document.getElementById("users-message");
const usersTableBody = document.getElementById("users-table-body");
const newAuthProviderSelect = document.getElementById("new_auth_provider");
const newUsernameInput = document.getElementById("new_username");
const newPasswordWrap = document.getElementById("new_password_wrap");
const newPasswordInput = document.getElementById("new_password");
const newGoogleEmailWrap = document.getElementById("new_google_email_wrap");
const newGoogleEmailInput = document.getElementById("new_google_email");
const sendConfirmModal = document.getElementById("send-confirm-modal");
const sendConfirmText = document.getElementById("send-confirm-text");
const sendConfirmDetails = document.getElementById("send-confirm-details");
const sendConfirmCloseBtn = document.getElementById("send-confirm-close-btn");
const sendConfirmOkBtn = document.getElementById("send-confirm-ok-btn");

const MAX_SEND_FILES = 5;
const MAX_SINGLE_FILE_BYTES = 50 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES = 50 * 1024 * 1024;
const ALLOWED_SEND_FILE_EXT = new Set([".pdf", ".tif", ".tiff"]);

let state = {
  user: null,
  tenantId: (window.localStorage.getItem("fax_app_tenant_id") || "default").toLowerCase(),
  selectedUploadFiles: [],
  faxes: [],
  historyFilter: "sent",
  adminSettingsOpen: false,
  recipients: [],
  recipientMeta: {},
  addressbookSelectedIds: [],
  frequentContacts: [],
  contacts: [],
  allContacts: [],
  tags: [],
  bulkJobs: [],
  pendingResetAfterSendConfirm: false,
  googleAuth: {
    enabled: false,
    configured: false,
    tenant_exists: false,
    tenant_active: false
  },
  appSettings: {
    outbound_copy_enabled: true,
    outbound_copy_email: "eyecarecenteroc@gmail.com",
    office_name: "Eyecare Care of Orange County",
    office_fax_number: "+17145580642",
    office_email: "eyecarecenteroc@gmail.com"
  }
};

function escapeHtml(text) {
  return (text || "")
    .toString()
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

function statusClass(status) {
  const value = (status || "").toLowerCase();
  if (value === "delivered") return "status ok";
  if (value === "failed") return "status fail";
  if (value === "sending" || value === "running") return "status sending";
  return "status pending";
}

function formatDate(value) {
  if (!value) return "-";
  const dt = new Date(value);
  if (Number.isNaN(dt.getTime())) return value;
  return dt.toLocaleString();
}

function parseTagsInput(value) {
  return Array.from(
    new Set(
      (value || "")
        .split(",")
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
    )
  );
}

function parseMediaUrls(value) {
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

function parseRecipientNumbers(value) {
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

function normalizePhoneInput(value) {
  const raw = (value || "").toString().trim();
  if (!raw) return "";

  const cleaned = raw.replace(/[^\d+]/g, "");
  if (!cleaned) return "";

  if (cleaned.startsWith("+")) {
    const digits = cleaned.slice(1).replace(/\D/g, "");
    const e164 = digits ? `+${digits}` : "";
    return isE164(e164) ? e164 : "";
  }

  const digits = cleaned.replace(/\D/g, "");
  if (digits.length === 10) {
    return `+1${digits}`;
  }
  if (digits.length === 11 && digits.startsWith("1")) {
    return `+${digits}`;
  }
  return "";
}

function isE164(value) {
  return /^\+[1-9]\d{7,14}$/.test((value || "").toString());
}

function isCompletePhoneToken(value) {
  const raw = (value || "").toString().trim();
  if (!raw) return false;

  if (raw.includes("+")) {
    const normalized = normalizePhoneInput(raw);
    return Boolean(normalized && isE164(normalized));
  }

  const digits = raw.replace(/\D/g, "");
  return digits.length === 10 || (digits.length === 11 && digits.startsWith("1"));
}

function formatPhoneForDisplay(value) {
  const normalized = normalizePhoneInput(value);
  if (/^\+1\d{10}$/.test(normalized)) {
    const local = normalized.slice(2);
    return `${local.slice(0, 3)}-${local.slice(3, 6)}-${local.slice(6)}`;
  }
  if (normalized) return normalized;
  return (value || "").toString().trim();
}

function parseRecipientsFromInput(value) {
  const tokens = parseRecipientNumbers(value);
  const valid = [];
  const invalid = [];

  tokens.forEach((token) => {
    const normalized = normalizePhoneInput(token);
    if (normalized && isE164(normalized)) {
      valid.push(normalized);
    } else {
      invalid.push(token);
    }
  });

  return {
    tokens,
    recipients: Array.from(new Set(valid)),
    invalidTokens: invalid
  };
}

function normalizeTenantId(value) {
  const tenant = (value || "").toString().trim().toLowerCase();
  if (!tenant) return "default";
  if (!/^[a-z0-9._-]{2,64}$/.test(tenant)) return "default";
  return tenant;
}

function normalizeAuthProvider(value) {
  return (value || "").toString().trim().toLowerCase() === "google" ? "google" : "local";
}

function consumeAuthQueryState() {
  const params = new URLSearchParams(window.location.search || "");
  const tenantFromQuery = normalizeTenantId(params.get("tenant_id") || "");
  if (tenantFromQuery) {
    state.tenantId = tenantFromQuery;
    window.localStorage.setItem("fax_app_tenant_id", tenantFromQuery);
    if (tenantInput) {
      tenantInput.value = tenantFromQuery;
    }
  }

  const authError = (params.get("auth_error") || "").toString().trim();
  const authSource = (params.get("auth_source") || "").toString().trim().toLowerCase();
  if (authError) {
    const prefix = authSource === "google" ? "Google sign-in error: " : "";
    setMessage(loginMessage, `${prefix}${authError}`);
  }

  if (params.has("tenant_id") || params.has("auth_error") || params.has("auth_source")) {
    window.history.replaceState({}, document.title, window.location.pathname || "/");
  }
}

async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  const tenantId = normalizeTenantId(state.tenantId || tenantInput?.value || "default");
  headers.set("X-Tenant-Id", tenantId);
  state.tenantId = tenantId;
  window.localStorage.setItem("fax_app_tenant_id", tenantId);
  const response = await fetch(path, {
    ...options,
    headers
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(body.error || "Request failed.");
    error.status = response.status;
    throw error;
  }
  return body;
}

function setMessage(el, text) {
  if (el) {
    el.textContent = text || "";
  }
}

function applyGoogleAuthUI() {
  if (!googleSigninBtn || !googleLoginHint) {
    return;
  }
  const auth = state.googleAuth || {};
  const featureEnabled = auth.enabled === true;
  const loginAvailable =
    featureEnabled &&
    auth.configured === true &&
    auth.tenant_exists === true &&
    auth.tenant_active === true;

  googleSigninBtn.classList.toggle("hidden", !featureEnabled);
  googleLoginHint.classList.toggle("hidden", !featureEnabled);
  googleSigninBtn.disabled = !loginAvailable;

  if (!featureEnabled) {
    googleLoginHint.textContent = "";
    return;
  }
  if (!auth.configured) {
    googleLoginHint.textContent = "Google sign-in is not configured on this server.";
    return;
  }
  if (!auth.tenant_exists) {
    googleLoginHint.textContent = "Tenant is not provisioned yet for Google sign-in.";
    return;
  }
  if (!auth.tenant_active) {
    googleLoginHint.textContent = "Tenant is currently suspended.";
    return;
  }
  googleLoginHint.textContent = "Use your Google account for this tenant workspace.";
}

function applyGoogleLinkButton() {
  if (!googleLinkBtn) return;
  const auth = state.googleAuth || {};
  const canUseGoogle = auth.enabled === true && auth.configured === true;
  const isAuthenticated = Boolean(state.user);
  const provider = normalizeAuthProvider(state.user?.auth_provider || "local");
  const linked = provider === "google";
  const showButton = isAuthenticated && canUseGoogle;
  googleLinkBtn.classList.toggle("hidden", !showButton);
  if (!showButton) {
    return;
  }
  googleLinkBtn.disabled = linked;
  googleLinkBtn.textContent = linked ? "Google Linked" : "Link Google Login";
}

async function loadGoogleAuthConfig({ silent = false } = {}) {
  const tenantId = normalizeTenantId(tenantInput?.value || state.tenantId || "default");
  state.tenantId = tenantId;
  window.localStorage.setItem("fax_app_tenant_id", tenantId);
  try {
    const body = await api(`/api/auth/google/config?tenant_id=${encodeURIComponent(tenantId)}`);
    state.googleAuth = body || {};
    applyGoogleAuthUI();
    applyGoogleLinkButton();
    return body;
  } catch (error) {
    state.googleAuth = {
      enabled: false,
      configured: false,
      tenant_exists: false,
      tenant_active: false
    };
    applyGoogleAuthUI();
    applyGoogleLinkButton();
    if (!silent) {
      setMessage(loginMessage, error.message);
    }
    return null;
  }
}

function applyCreateUserProviderUI() {
  if (!newAuthProviderSelect) return;
  const provider = normalizeAuthProvider(newAuthProviderSelect.value || "local");
  const isGoogle = provider === "google";

  if (newPasswordWrap) {
    newPasswordWrap.classList.toggle("hidden", isGoogle);
  }
  if (newGoogleEmailWrap) {
    newGoogleEmailWrap.classList.toggle("hidden", !isGoogle);
  }
  if (newPasswordInput) {
    newPasswordInput.required = !isGoogle;
    if (isGoogle) {
      newPasswordInput.value = "";
    }
  }
  if (newGoogleEmailInput) {
    newGoogleEmailInput.required = isGoogle;
  }
  if (newUsernameInput) {
    newUsernameInput.required = !isGoogle;
    newUsernameInput.placeholder = isGoogle
      ? "optional (auto-generated from Google email)"
      : "required username";
  }
}

function setLastUrlUI(url) {
  const value = (url || "").trim();
  if (value) {
    lastUrlLabel.textContent = `Last URL: ${value}`;
  } else {
    lastUrlLabel.textContent = "";
  }
}

function formatBytes(value) {
  const bytes = Number(value || 0);
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function fileExtension(name) {
  const value = (name || "").toString().toLowerCase();
  const dot = value.lastIndexOf(".");
  return dot >= 0 ? value.slice(dot) : "";
}

function fileFingerprint(file) {
  return `${file.name || ""}:${file.size || 0}:${file.lastModified || 0}`;
}

function validateSelectedUploadFiles(files) {
  const list = Array.isArray(files) ? files : [];
  if (list.length > MAX_SEND_FILES) {
    return `You can attach up to ${MAX_SEND_FILES} files per fax.`;
  }

  let totalBytes = 0;
  for (const file of list) {
    if (!file) continue;
    totalBytes += Number(file.size || 0);
    const ext = fileExtension(file.name);
    if (!ALLOWED_SEND_FILE_EXT.has(ext)) {
      return `Unsupported file: ${file.name}. Only PDF/TIFF files are allowed.`;
    }
    if (Number(file.size || 0) > MAX_SINGLE_FILE_BYTES) {
      return `File too large: ${file.name}. Max per file is ${formatBytes(MAX_SINGLE_FILE_BYTES)}.`;
    }
  }

  if (totalBytes > MAX_TOTAL_FILE_BYTES) {
    return `Total attachments are too large (${formatBytes(totalBytes)}). Max total is ${formatBytes(
      MAX_TOTAL_FILE_BYTES
    )}.`;
  }

  return "";
}

function renderSelectedUploadFiles() {
  const files = Array.isArray(state.selectedUploadFiles) ? state.selectedUploadFiles : [];
  if (!selectedFilesList) return;
  selectedFilesList.innerHTML = "";

  if (!files.length) {
    selectedFilesList.innerHTML = `<p class="helper-text">No files selected yet.</p>`;
    setMessage(fileSelectionMessage, "");
    return;
  }

  let totalBytes = 0;
  files.forEach((file, index) => {
    totalBytes += Number(file.size || 0);
    const row = document.createElement("div");
    row.className = "file-item";
    row.innerHTML = `
      <div class="file-item-meta">
        <strong class="file-item-name">${escapeHtml(file.name || `File ${index + 1}`)}</strong>
        <span class="file-item-size">${escapeHtml(formatBytes(file.size || 0))}</span>
      </div>
      <button type="button" class="file-remove-btn" data-remove-index="${index}" aria-label="Remove file">×</button>
    `;
    row.querySelector("button[data-remove-index]").addEventListener("click", () => {
      removeSelectedUploadFile(index);
    });
    selectedFilesList.appendChild(row);
  });

  setMessage(
    fileSelectionMessage,
    `${files.length}/${MAX_SEND_FILES} file(s) selected. Total size: ${formatBytes(totalBytes)}.`
  );
}

function setSelectedUploadFiles(files) {
  state.selectedUploadFiles = Array.isArray(files) ? files.filter(Boolean) : [];
  renderSelectedUploadFiles();
}

function removeSelectedUploadFile(index) {
  const files = Array.isArray(state.selectedUploadFiles) ? [...state.selectedUploadFiles] : [];
  files.splice(index, 1);
  setSelectedUploadFiles(files);
  setMessage(sendMessage, files.length ? "Updated attachment list." : "Attachment list cleared.");
}

function addFilesToSelection(files) {
  const incoming = Array.isArray(files) ? files : [];
  if (!incoming.length) return;

  const existing = Array.isArray(state.selectedUploadFiles) ? [...state.selectedUploadFiles] : [];
  const existingSet = new Set(existing.map(fileFingerprint));
  incoming.forEach((file) => {
    const key = fileFingerprint(file);
    if (!existingSet.has(key)) {
      existing.push(file);
      existingSet.add(key);
    }
  });

  const validationError = validateSelectedUploadFiles(existing);
  if (validationError) {
    throw new Error(validationError);
  }

  setSelectedUploadFiles(existing);
}

function clearSelectedUploadFiles() {
  state.selectedUploadFiles = [];
  if (sendFileInput) {
    sendFileInput.value = "";
  }
  renderSelectedUploadFiles();
}

function openSendConfirmationModal(details) {
  if (!sendConfirmModal) return;
  const queuedCount = Number(details?.queuedCount || 0);
  const failedCount = Number(details?.failedCount || 0);
  const faxIds = Array.isArray(details?.faxIds) ? details.faxIds.filter(Boolean) : [];
  const historyRecordedCount = Number(details?.historyRecordedCount || 0);

  sendConfirmText.textContent =
    failedCount > 0
      ? `Fax request processed. ${queuedCount} queued and ${failedCount} failed.`
      : `Fax sent to API successfully. ${queuedCount} fax(es) queued.`;

  sendConfirmDetails.innerHTML = "";
  const lines = [
    `Queued: ${queuedCount}`,
    `Failed: ${failedCount}`,
    `History records found: ${historyRecordedCount}/${faxIds.length || queuedCount || 0}`,
    faxIds.length ? `Fax ID(s): ${faxIds.join(", ")}` : ""
  ].filter(Boolean);

  lines.forEach((line) => {
    const li = document.createElement("li");
    li.textContent = line;
    sendConfirmDetails.appendChild(li);
  });

  sendConfirmModal.classList.remove("hidden");
}

function closeSendConfirmationModal() {
  if (!sendConfirmModal) return;
  sendConfirmModal.classList.add("hidden");
}

function resetSendFormForNextFaxJob() {
  sendForm.reset();
  state.recipients = [];
  state.recipientMeta = {};
  syncRecipientsInput();
  renderRecipientChips();
  recipientNameSearchInput.value = "";
  recipientSuggestions.innerHTML = "";
  recipientSuggestions.classList.add("hidden");
  mediaUrlInput.value = "";
  clearSelectedUploadFiles();
  applyAppSettingsToSendForm();
  toInput.focus();
}

function getContactByFaxNumber(number) {
  const normalized = normalizePhoneInput(number);
  return state.allContacts.find((contact) => normalizePhoneInput(contact.fax_number) === normalized) || null;
}

function recipientLabel(number) {
  const meta = state.recipientMeta[number];
  const displayNumber = formatPhoneForDisplay(number);
  if (meta?.name) {
    return `${meta.name} (${displayNumber})`;
  }
  return displayNumber;
}

function syncRecipientsInput({ trailingComma = false } = {}) {
  const formatted = state.recipients.map((number) => formatPhoneForDisplay(number)).join(", ");
  toInput.value = trailingComma && formatted ? `${formatted}, ` : formatted;
}

function syncRecipientMetaFromState() {
  const nextSet = new Set(state.recipients);
  state.recipientMeta = Object.fromEntries(
    Object.entries(state.recipientMeta).filter(([number]) => nextSet.has(number))
  );
  state.recipients.forEach((number) => {
    if (!state.recipientMeta[number]) {
      const contact = getContactByFaxNumber(number);
      if (contact) {
        state.recipientMeta[number] = { name: contact.name || "", contact_id: contact.id || "" };
      }
    }
  });
}

function renderRecipientChips() {
  recipientChips.innerHTML = "";
  if (!state.recipients.length) {
    recipientChips.innerHTML = `<span class="helper-text">No recipients selected yet.</span>`;
    return;
  }

  state.recipients.forEach((number) => {
    const chip = document.createElement("button");
    chip.type = "button";
    chip.className = "chip removable";
    chip.textContent = recipientLabel(number);
    chip.title = "Remove recipient";
    chip.addEventListener("click", () => {
      state.recipients = state.recipients.filter((item) => item !== number);
      delete state.recipientMeta[number];
      syncRecipientsInput();
      renderRecipientChips();
    });
    recipientChips.appendChild(chip);
  });
}

function setRecipientsFromInput(value, { syncInput = true } = {}) {
  const parsed = parseRecipientsFromInput(value);
  state.recipients = parsed.recipients;
  syncRecipientMetaFromState();
  if (syncInput) {
    syncRecipientsInput();
  }
  renderRecipientChips();
  return parsed;
}

function addRecipient(number, meta = null) {
  const normalized = normalizePhoneInput(number);
  if (!normalized || !isE164(normalized)) return;
  state.recipients = Array.from(new Set([...state.recipients, normalized]));
  if (meta?.name || meta?.contact_id) {
    state.recipientMeta[normalized] = {
      name: meta.name || "",
      contact_id: meta.contact_id || ""
    };
  } else if (!state.recipientMeta[normalized]) {
    const contact = getContactByFaxNumber(normalized);
    if (contact) {
      state.recipientMeta[normalized] = { name: contact.name || "", contact_id: contact.id || "" };
    }
  }
  syncRecipientsInput();
  renderRecipientChips();
}

function addRecipientContact(contact) {
  if (!contact?.fax_number) return;
  addRecipient(contact.fax_number, {
    name: contact.name || "",
    contact_id: contact.id || ""
  });
}

function applyAdminPanelVisibility() {
  const isAdmin = state.user?.role === "admin";
  settingsToggleBtn.classList.toggle("hidden", !isAdmin);
  if (!isAdmin) {
    state.adminSettingsOpen = false;
  }
  adminPanel.classList.toggle("hidden", !isAdmin || !state.adminSettingsOpen);
  if (isAdmin) {
    settingsToggleBtn.textContent = state.adminSettingsOpen ? "⚙ Close Settings" : "⚙ Settings";
  }
}

function setAuthenticatedView(user) {
  state.user = user || null;
  if (user?.tenant_id) {
    state.tenantId = normalizeTenantId(user.tenant_id);
    window.localStorage.setItem("fax_app_tenant_id", state.tenantId);
  }
  if (tenantInput) {
    tenantInput.value = normalizeTenantId(state.tenantId || "default");
  }
  const isAuthenticated = Boolean(user);
  document.body.classList.toggle("login-mode", !isAuthenticated);
  loginPanel.classList.toggle("hidden", isAuthenticated);
  appShell.classList.toggle("hidden", !isAuthenticated);

  if (isAuthenticated) {
    const provider = normalizeAuthProvider(user.auth_provider || "local");
    const providerText = provider === "google" ? "google sign-in" : "local login";
    sessionLabel.textContent = `Logged in as ${user.username} (${user.role}, ${providerText}) on tenant ${state.tenantId}`;
    mediaUrlInput.value = user.last_media_url || "";
    bulkMediaUrlInput.value = user.last_media_url || "";
    setLastUrlUI(user.last_media_url || "");
    state.recipientMeta = {};
    state.recipients = parseRecipientsFromInput(toInput.value).recipients;
    syncRecipientMetaFromState();
    syncRecipientsInput();
    renderRecipientChips();
    renderSelectedUploadFiles();
  } else {
    sessionLabel.textContent = "";
    mediaUrlInput.value = "";
    bulkMediaUrlInput.value = "";
    toInput.value = "";
    state.recipients = [];
    state.recipientMeta = {};
    state.pendingResetAfterSendConfirm = false;
    state.addressbookSelectedIds = [];
    recipientNameSearchInput.value = "";
    recipientSuggestions.innerHTML = "";
    recipientSuggestions.classList.add("hidden");
    renderRecipientChips();
    clearSelectedUploadFiles();
    addressbookModal.classList.add("hidden");
    closeSendConfirmationModal();
    setLastUrlUI("");
    loadGoogleAuthConfig({ silent: true }).catch(() => {});
  }
  applyAdminPanelVisibility();
  applyGoogleLinkButton();
}

function applyAppSettingsToSendForm() {
  const email = state.appSettings.outbound_copy_email || "eyecarecenteroc@gmail.com";
  const enabled = state.appSettings.outbound_copy_enabled !== false;
  const officeName = state.appSettings.office_name || "Eyecare Care of Orange County";
  const officeFax = state.appSettings.office_fax_number || "+17145580642";
  const officeEmail = state.appSettings.office_email || "eyecarecenteroc@gmail.com";
  sendCopyEmailInput.checked = enabled;
  sendCopyLabel.textContent = `Email us a copy (${email})`;
  officeNameDisplay.textContent = officeName;
  officeFaxDisplay.textContent = `Fax: ${officeFax}`;
  officeEmailDisplay.textContent = `Email: ${officeEmail}`;
  if (!coverSubjectInput.value.trim()) {
    coverSubjectInput.value = "Fax Transmission";
  }
  if (!coverMessageInput.value.trim()) {
    coverMessageInput.value = `Please see attached fax documents from ${officeName}.`;
  }
}

function renderFaxRow(item) {
  const mediaLinks = mediaUrlsFromFaxItem(item)
    .map(
      (url, index) =>
        `<a href="${escapeHtml(url)}" target="_blank" rel="noreferrer">File ${index + 1}</a>`
    )
    .join("<br />");
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td class="mono">${escapeHtml(item.id)}</td>
    <td>${escapeHtml(item.direction || "-")}</td>
    <td>${escapeHtml(item.from || "-")}</td>
    <td>${escapeHtml(item.to || "-")}</td>
    <td>${mediaLinks || "-"}</td>
    <td><span class="${statusClass(item.status)}">${escapeHtml(item.status || "unknown")}</span></td>
    <td>${escapeHtml(formatDate(item.telnyx_updated_at || item.updated_at))}</td>
    <td>${escapeHtml(item.failure_reason || "-")}</td>
    <td><button class="small-btn" data-id="${escapeHtml(item.id)}">Poll</button></td>
  `;

  tr.querySelector("button[data-id]").addEventListener("click", async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await api(`/api/faxes/${encodeURIComponent(item.id)}/refresh`, { method: "POST" });
      await loadFaxes();
    } catch (error) {
      alert(error.message);
    } finally {
      button.disabled = false;
    }
  });

  return tr;
}

function mediaUrlsFromFaxItem(item) {
  if (Array.isArray(item?.media_urls) && item.media_urls.length) {
    return item.media_urls.map((url) => (url || "").toString().trim()).filter(Boolean);
  }
  return parseMediaUrls(item?.media_url || "");
}

function faxDirectionBucket(item) {
  const direction = (item?.direction || "").toLowerCase();
  if (direction.includes("inbound") || direction.includes("received")) {
    return "received";
  }
  return "sent";
}

function renderFaxTable() {
  const items = state.faxes.filter((item) => faxDirectionBucket(item) === state.historyFilter);
  tableBody.innerHTML = "";

  if (!items.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="9">No ${state.historyFilter} faxes yet.</td>`;
    tableBody.appendChild(tr);
    return;
  }

  items.forEach((item) => tableBody.appendChild(renderFaxRow(item)));
}

function setHistoryFilter(filter) {
  state.historyFilter = filter === "received" ? "received" : "sent";
  historyTabSent.classList.toggle("active", state.historyFilter === "sent");
  historyTabReceived.classList.toggle("active", state.historyFilter === "received");
  renderFaxTable();
}

async function loadFaxes() {
  const body = await api("/api/faxes?limit=50");
  state.faxes = Array.isArray(body.items) ? body.items : [];
  if (body.sync_warning) {
    setMessage(sendMessage, `History sync warning: ${body.sync_warning}`);
  }
  renderFaxTable();
}

function renderContactRow(contact) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${escapeHtml(contact.name || "-")}</td>
    <td class="mono">${escapeHtml(contact.fax_number || "-")}</td>
    <td>${escapeHtml((contact.tags || []).join(", ") || "-")}</td>
    <td>${escapeHtml(contact.email || "-")}</td>
    <td class="row-actions">
      <button type="button" class="small-btn secondary" data-send="${escapeHtml(contact.fax_number)}">Use</button>
      <button type="button" class="small-btn secondary" data-delete="${escapeHtml(contact.id)}">Delete</button>
    </td>
  `;

  tr.querySelector("button[data-send]").addEventListener("click", () => {
    addRecipientContact(contact);
    window.scrollTo({ top: 0, behavior: "smooth" });
  });

  tr.querySelector("button[data-delete]").addEventListener("click", async () => {
    if (!window.confirm(`Delete contact "${contact.name}"?`)) {
      return;
    }
    try {
      await api(`/api/contacts/${encodeURIComponent(contact.id)}`, { method: "DELETE" });
      await Promise.all([loadContacts(), loadAllContactsForPicker(), loadContactTags()]);
      setMessage(contactMessage, "Contact deleted.");
    } catch (error) {
      setMessage(contactMessage, error.message);
    }
  });

  return tr;
}

async function loadContacts() {
  const params = new URLSearchParams();
  const search = (contactSearchInput.value || "").trim();
  const tag = (contactTagFilter.value || "").trim();
  if (search) params.set("search", search);
  if (tag) params.set("tag", tag);

  const body = await api(`/api/contacts?${params.toString()}`);
  state.contacts = Array.isArray(body.items) ? body.items : [];
  contactsTableBody.innerHTML = "";

  if (!state.contacts.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="5">No contacts found.</td>`;
    contactsTableBody.appendChild(tr);
    return;
  }

  state.contacts.forEach((contact) => contactsTableBody.appendChild(renderContactRow(contact)));
  renderAddressbookList();
}

function toggleAddressbookSelection(contactId) {
  const selected = new Set(state.addressbookSelectedIds);
  if (selected.has(contactId)) {
    selected.delete(contactId);
  } else {
    selected.add(contactId);
  }
  state.addressbookSelectedIds = Array.from(selected);
}

function renderAddressbookList() {
  const search = (addressbookSearchInput.value || "").trim().toLowerCase();
  const selected = new Set(state.addressbookSelectedIds);
  const filtered = state.allContacts.filter((contact) => {
    if (!search) return true;
    const haystack = [
      contact.name || "",
      contact.fax_number || "",
      (contact.tags || []).join(" "),
      contact.email || ""
    ]
      .join(" ")
      .toLowerCase();
    return haystack.includes(search);
  });

  addressbookList.innerHTML = "";
  if (!filtered.length) {
    addressbookList.innerHTML = `<p class="helper-text">No matching contacts.</p>`;
    return;
  }

  filtered.slice(0, 500).forEach((contact) => {
    const checked = selected.has(contact.id) ? "checked" : "";
    const row = document.createElement("label");
    row.className = "picker-row";
    row.innerHTML = `
      <input type="checkbox" value="${escapeHtml(contact.id || "")}" ${checked} />
      <div>
        <strong>${escapeHtml(contact.name || "Unnamed")}</strong>
        <div class="helper-text mono">${escapeHtml(contact.fax_number || "-")}</div>
      </div>
    `;
    row.querySelector("input").addEventListener("change", () => {
      toggleAddressbookSelection(contact.id);
      renderFrequentContacts();
    });
    addressbookList.appendChild(row);
  });
}

function renderFrequentContacts() {
  const selected = new Set(state.addressbookSelectedIds);
  frequentContacts.innerHTML = "";
  if (!state.frequentContacts.length) {
    frequentContacts.innerHTML = `<span class="helper-text">No frequent contacts yet.</span>`;
    return;
  }

  state.frequentContacts.forEach((contact) => {
    const isActive = selected.has(contact.id);
    const button = document.createElement("button");
    button.type = "button";
    button.className = `chip ${isActive ? "active" : ""}`;
    button.textContent = `${contact.name || contact.fax_number} (${contact.fax_number})`;
    button.addEventListener("click", () => {
      toggleAddressbookSelection(contact.id);
      renderFrequentContacts();
      renderAddressbookList();
    });
    frequentContacts.appendChild(button);
  });
}

function renderRecipientSuggestions() {
  const query = (recipientNameSearchInput.value || "").trim().toLowerCase();
  recipientSuggestions.innerHTML = "";
  if (!query) {
    recipientSuggestions.classList.add("hidden");
    return;
  }

  const matches = state.allContacts
    .filter((contact) => (contact.name || "").toLowerCase().includes(query))
    .slice(0, 8);
  if (!matches.length) {
    recipientSuggestions.classList.add("hidden");
    return;
  }

  matches.forEach((contact) => {
    const item = document.createElement("button");
    item.type = "button";
    item.className = "suggestion-item";
    item.innerHTML = `
      <span>${escapeHtml(contact.name || "Unnamed")}</span>
      <small class="mono">${escapeHtml(contact.fax_number || "-")}</small>
    `;
    item.addEventListener("click", () => {
      addRecipientContact(contact);
      recipientNameSearchInput.value = "";
      recipientSuggestions.classList.add("hidden");
      setMessage(sendMessage, `Added ${contact.name || contact.fax_number} to recipients.`);
    });
    recipientSuggestions.appendChild(item);
  });
  recipientSuggestions.classList.remove("hidden");
}

async function openAddressbookModal() {
  try {
    await Promise.all([loadAllContactsForPicker(), loadContacts(), loadContactTags(), loadFrequentContacts()]);
  } catch (error) {
    setMessage(sendMessage, error.message || "Failed to load address book.");
  }
  const selectedByFax = new Set(state.recipients);
  state.addressbookSelectedIds = state.allContacts
    .filter((contact) => selectedByFax.has(normalizePhoneInput(contact.fax_number || "")))
    .map((contact) => contact.id);
  addressbookSearchInput.value = "";
  renderFrequentContacts();
  renderAddressbookList();
  setAddressbookTab("contacts");
  addressbookModal.classList.remove("hidden");
}

function closeAddressbookModal() {
  addressbookModal.classList.add("hidden");
}

function applyAddressbookSelection() {
  const selected = new Set(state.addressbookSelectedIds);
  const chosen = state.allContacts.filter((contact) => selected.has(contact.id));
  if (!chosen.length) {
    closeAddressbookModal();
    return;
  }
  chosen.forEach((contact) => addRecipientContact(contact));
  closeAddressbookModal();
  setMessage(sendMessage, `Added ${chosen.length} contact(s) from Address Book.`);
}

function setAddressbookTab(tab) {
  const showBulk = tab === "bulk";
  addressbookContactsTab.classList.toggle("hidden", showBulk);
  addressbookBulkTab.classList.toggle("hidden", !showBulk);
  addressbookTabContacts.classList.toggle("active", !showBulk);
  addressbookTabBulk.classList.toggle("active", showBulk);
}

async function loadFrequentContacts() {
  const body = await api("/api/contacts/frequent?limit=5");
  state.frequentContacts = Array.isArray(body.items) ? body.items : [];
  renderFrequentContacts();
}

async function loadAllContactsForPicker() {
  const body = await api("/api/contacts");
  state.allContacts = Array.isArray(body.items) ? body.items : [];
  renderAddressbookList();
  renderRecipientSuggestions();
}

function renderBulkTagCheckboxes() {
  const selected = new Set(
    Array.from(
      bulkTagsList.querySelectorAll("input[type='checkbox']:checked")
    ).map((input) => input.value)
  );

  bulkTagsList.innerHTML = "";
  if (!state.tags.length) {
    bulkTagsList.innerHTML = `<p class="helper-text">No tags yet. Add contacts with tags first.</p>`;
    return;
  }

  state.tags.forEach((tag) => {
    const label = document.createElement("label");
    label.className = "tag-pill";
    label.innerHTML = `
      <input type="checkbox" value="${escapeHtml(tag)}" ${selected.has(tag) ? "checked" : ""} />
      <span>${escapeHtml(tag)}</span>
    `;
    bulkTagsList.appendChild(label);
  });
}

async function loadContactTags() {
  const body = await api("/api/contacts/tags");
  state.tags = Array.isArray(body.items) ? body.items : [];

  const selectedTag = contactTagFilter.value;
  contactTagFilter.innerHTML = `<option value="">All tags</option>`;
  state.tags.forEach((tag) => {
    const option = document.createElement("option");
    option.value = tag;
    option.textContent = tag;
    if (tag === selectedTag) option.selected = true;
    contactTagFilter.appendChild(option);
  });

  renderBulkTagCheckboxes();
}

function selectedBulkTags() {
  return Array.from(bulkTagsList.querySelectorAll("input[type='checkbox']:checked")).map(
    (input) => input.value
  );
}

function renderBulkJobRow(job) {
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td class="mono">${escapeHtml(job.id)}</td>
    <td><span class="${statusClass(job.status)}">${escapeHtml(job.status || "unknown")}</span></td>
    <td>${escapeHtml(String(job.totals?.total ?? 0))}</td>
    <td>${escapeHtml(String(job.totals?.queued ?? 0))}</td>
    <td>${escapeHtml(String(job.totals?.failed ?? 0))}</td>
    <td>${escapeHtml(formatDate(job.updated_at))}</td>
  `;
  return tr;
}

async function loadBulkJobs() {
  const body = await api("/api/faxes/bulk-jobs");
  state.bulkJobs = Array.isArray(body.items) ? body.items : [];
  bulkJobsBody.innerHTML = "";

  if (!state.bulkJobs.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6">No bulk jobs yet.</td>`;
    bulkJobsBody.appendChild(tr);
    return;
  }

  state.bulkJobs.forEach((job) => bulkJobsBody.appendChild(renderBulkJobRow(job)));
}

async function loadAppSettings() {
  const body = await api("/api/settings");
  state.appSettings = {
    outbound_copy_enabled: body.outbound_copy_enabled !== false,
    outbound_copy_email: body.outbound_copy_email || "eyecarecenteroc@gmail.com",
    office_name: body.office_name || "Eyecare Care of Orange County",
    office_fax_number: body.office_fax_number || "+17145580642",
    office_email: body.office_email || "eyecarecenteroc@gmail.com"
  };
  applyAppSettingsToSendForm();
}

async function loadAdminSettings() {
  const body = await api("/api/admin/settings");
  document.getElementById("setting_connection_id").value = body.telnyx_connection_id || "";
  document.getElementById("setting_from_number").value = body.telnyx_from_number || "";
  document.getElementById("setting_fax_app_id").value = body.telnyx_fax_application_id || "";
  document.getElementById("setting_outbound_copy_enabled").checked = body.outbound_copy_enabled !== false;
  document.getElementById("setting_outbound_copy_email").value =
    body.outbound_copy_email || "eyecarecenteroc@gmail.com";
  document.getElementById("setting_office_name").value =
    body.office_name || "Eyecare Care of Orange County";
  document.getElementById("setting_office_fax_number").value = body.office_fax_number || "+17145580642";
  document.getElementById("setting_office_email").value = body.office_email || "eyecarecenteroc@gmail.com";
}

async function loadFaxAppSettings() {
  const body = await api("/api/admin/telnyx/fax-application");
  document.getElementById("fax_email_recipient").value = body.fax_email_recipient || "";
  document.getElementById("inbound_channel_limit").value =
    body.inbound_channel_limit === null ? "" : String(body.inbound_channel_limit);
  document.getElementById("outbound_channel_limit").value =
    body.outbound_channel_limit === null ? "" : String(body.outbound_channel_limit);
}

function renderUserRow(item) {
  const provider = normalizeAuthProvider(item.auth_provider || "local");
  const canResetPassword = provider === "local";
  const resetCell = canResetPassword
    ? `
      <form class="inline-reset-form" data-user="${escapeHtml(item.username)}">
        <input type="password" name="password" placeholder="New password" minlength="10" required />
        <button type="submit" class="small-btn secondary">Reset</button>
      </form>
    `
    : `<span class="helper-text">Google user</span>`;
  const tr = document.createElement("tr");
  tr.innerHTML = `
    <td>${escapeHtml(item.username)}</td>
    <td>${escapeHtml(item.role)}</td>
    <td>${escapeHtml(provider)}</td>
    <td>${escapeHtml(item.email || "-")}</td>
    <td>${escapeHtml(formatDate(item.created_at))}</td>
    <td>${resetCell}</td>
  `;

  if (canResetPassword) {
    tr.querySelector(".inline-reset-form").addEventListener("submit", async (event) => {
      event.preventDefault();
      const password = event.target.password.value || "";
      try {
        await api(`/api/admin/users/${encodeURIComponent(item.username)}/password`, {
          method: "PATCH",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ password })
        });
        setMessage(usersMessage, `Password reset for ${item.username}.`);
        event.target.reset();
      } catch (error) {
        setMessage(usersMessage, error.message);
      }
    });
  }

  return tr;
}

async function loadUsers() {
  const body = await api("/api/admin/users");
  const items = Array.isArray(body.items) ? body.items : [];
  usersTableBody.innerHTML = "";

  if (!items.length) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6">No users.</td>`;
    usersTableBody.appendChild(tr);
    return;
  }

  items.forEach((item) => usersTableBody.appendChild(renderUserRow(item)));
}

async function initAfterLogin() {
  const baseLoaders = [
    { label: "fax history", run: () => loadFaxes() },
    { label: "contacts", run: () => loadContacts() },
    { label: "address book", run: () => loadAllContactsForPicker() },
    { label: "contact tags", run: () => loadContactTags() },
    { label: "bulk jobs", run: () => loadBulkJobs() },
    { label: "app settings", run: () => loadAppSettings() },
    { label: "frequent contacts", run: () => loadFrequentContacts() }
  ];
  const baseResults = await Promise.allSettled(baseLoaders.map((item) => item.run()));
  const baseFailed = baseResults
    .map((result, index) =>
      result.status === "rejected" ? `${baseLoaders[index].label}: ${result.reason?.message || "failed"}` : null
    )
    .filter(Boolean);
  if (baseFailed.length) {
    setMessage(sendMessage, `Loaded with warnings. ${baseFailed[0]}`);
  }

  setLastUrlUI(state.user?.last_media_url || "");
  if (state.user?.role === "admin") {
    const adminLoaders = [
      { label: "admin settings", run: () => loadAdminSettings() },
      { label: "users", run: () => loadUsers() }
    ];
    const adminResults = await Promise.allSettled(adminLoaders.map((item) => item.run()));
    const adminFailed = adminResults
      .map((result, index) =>
        result.status === "rejected" ? `${adminLoaders[index].label}: ${result.reason?.message || "failed"}` : null
      )
      .filter(Boolean);
    if (adminFailed.length) {
      setMessage(settingsMessage, `Loaded with warnings. ${adminFailed[0]}`);
    }
  }
}

async function saveLastMediaUrl(mediaUrl) {
  const body = await api("/api/me/last-media-url", {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ media_url: mediaUrl || "" })
  });
  state.user = body.user;
  setLastUrlUI(body.user?.last_media_url || "");
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(loginMessage, "");

  const formData = new FormData(loginForm);
  const tenantId = normalizeTenantId(formData.get("tenant_id") || state.tenantId || "default");
  state.tenantId = tenantId;
  window.localStorage.setItem("fax_app_tenant_id", tenantId);
  try {
    const body = await api("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        tenant_id: tenantId,
        username: formData.get("username"),
        password: formData.get("password")
      })
    });
    setAuthenticatedView(body.user);
    loginForm.reset();
    if (tenantInput) {
      tenantInput.value = tenantId;
    }
    await initAfterLogin();
  } catch (error) {
    setMessage(loginMessage, error.message);
  }
});

if (tenantInput) {
  tenantInput.addEventListener("change", () => {
    state.tenantId = normalizeTenantId(tenantInput.value || state.tenantId || "default");
    window.localStorage.setItem("fax_app_tenant_id", state.tenantId);
    loadGoogleAuthConfig({ silent: true }).catch(() => {});
  });
}

if (googleSigninBtn) {
  googleSigninBtn.addEventListener("click", async () => {
    setMessage(loginMessage, "");
    const tenantId = normalizeTenantId(tenantInput?.value || state.tenantId || "default");
    state.tenantId = tenantId;
    window.localStorage.setItem("fax_app_tenant_id", tenantId);

    const config = await loadGoogleAuthConfig({ silent: true });
    if (!config?.enabled) {
      setMessage(loginMessage, "Google sign-in is not enabled for this server.");
      return;
    }
    if (!config?.configured) {
      setMessage(loginMessage, "Google sign-in is not configured yet.");
      return;
    }
    if (!config?.tenant_exists) {
      setMessage(loginMessage, "Tenant is not provisioned.");
      return;
    }
    if (!config?.tenant_active) {
      setMessage(loginMessage, "Tenant is suspended.");
      return;
    }
    window.location.assign(`/api/auth/google/start?tenant_id=${encodeURIComponent(tenantId)}`);
  });
}

if (googleLinkBtn) {
  googleLinkBtn.addEventListener("click", async () => {
    if (!state.user) return;
    const tenantId = normalizeTenantId(state.tenantId || tenantInput?.value || "default");
    state.tenantId = tenantId;
    window.localStorage.setItem("fax_app_tenant_id", tenantId);
    const config = await loadGoogleAuthConfig({ silent: true });
    if (!config?.enabled || !config?.configured) {
      setMessage(sendMessage, "Google sign-in is not configured yet.");
      return;
    }
    window.location.assign(`/api/auth/google/link/start?tenant_id=${encodeURIComponent(tenantId)}`);
  });
}

logoutBtn.addEventListener("click", async () => {
  await api("/api/auth/logout", { method: "POST" }).catch(() => ({}));
  clearSelectedUploadFiles();
  setAuthenticatedView(null);
});

sendForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(sendMessage, "");
  const formData = new FormData(sendForm);
  const parsedRecipients = parseRecipientsFromInput(formData.get("to") || "");
  const recipientTokens = parsedRecipients.tokens;
  const recipients = parsedRecipients.recipients;
  const invalidRecipient = parsedRecipients.invalidTokens[0] || null;
  const liveSelectedFiles = sendFileInput.files ? Array.from(sendFileInput.files) : [];
  const selectedFiles = Array.isArray(state.selectedUploadFiles) && state.selectedUploadFiles.length
    ? state.selectedUploadFiles
    : liveSelectedFiles;
  setSelectedUploadFiles(selectedFiles);
  const fileValidationError = validateSelectedUploadFiles(selectedFiles);
  const uploadedMediaUrls = [];
  sendFaxPrimaryBtn.disabled = true;

  try {
    if (!recipientTokens.length || !recipients.length) {
      throw new Error("No recipient picked. Add at least one destination fax number.");
    }
    if (invalidRecipient) {
      throw new Error(
        `Invalid phone number format: ${invalidRecipient}. Use US 10-digit format (7145580642) or full E.164 international format (example: +17145551234, +442071838750).`
      );
    }
    if (fileValidationError) {
      throw new Error(fileValidationError);
    }
    if (!selectedFiles.length) {
      throw new Error("Attach at least one PDF/TIFF file before sending.");
    }

    setMessage(sendMessage, `Uploading ${selectedFiles.length} file(s)...`);
    const uploadData = new FormData();
    selectedFiles.forEach((file) => uploadData.append("files", file));
    const uploadResponse = await api("/api/uploads/batch", {
      method: "POST",
      body: uploadData
    });
    const urls = Array.isArray(uploadResponse.media_urls) ? uploadResponse.media_urls : [];
    if (urls.length !== selectedFiles.length) {
      throw new Error("Upload failed. One or more selected files were not uploaded.");
    }
    uploadedMediaUrls.push(...urls);

    const finalMediaUrls = Array.from(new Set(uploadedMediaUrls));
    const firstMediaUrl = finalMediaUrls[0] || "";
    if (!finalMediaUrls.length) {
      throw new Error("Upload failed. No PDF/TIFF media URL was created.");
    }

    const body = await api("/api/faxes", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        to_numbers: recipients,
        media_urls: finalMediaUrls,
        include_cover_page: includeCoverPageInput.checked,
        cover_subject: (formData.get("cover_subject") || "").toString().trim(),
        cover_message: (formData.get("cover_message") || "").toString().trim(),
        send_copy_email: sendCopyEmailInput.checked
      })
    });
    state.recipients = recipients;
    syncRecipientsInput();
    renderRecipientChips();
    mediaUrlInput.value = "";
    const coverNote = body.cover_page_added ? " Cover page added." : "";
    const uploadNote = uploadedMediaUrls.length ? ` Uploaded ${uploadedMediaUrls.length} file(s).` : "";
    const queuedCount = Number(body.queued_count || 0);
    const failedCount = Number(body.failed_count || 0);
    const faxIds = Array.isArray(body.fax_ids) ? body.fax_ids.filter(Boolean) : [];
    const queueNote =
      queuedCount > 1 ? `Queued ${queuedCount} faxes.` : `Fax queued. ID: ${body.fax_id || body.fax_ids?.[0]}.`;
    const failedNote = failedCount ? ` ${failedCount} recipient(s) failed.` : "";
    setMessage(sendMessage, `${queueNote}${uploadNote}${coverNote}${failedNote}`);
    if (firstMediaUrl) {
      await saveLastMediaUrl(firstMediaUrl);
      if (!bulkMediaUrlInput.value.trim()) {
        bulkMediaUrlInput.value = firstMediaUrl;
      }
    }
    await Promise.all([loadFaxes(), loadFrequentContacts()]);
    const historyIdSet = new Set(state.faxes.map((item) => item.id));
    const historyRecordedCount = faxIds.filter((id) => historyIdSet.has(id)).length;
    state.pendingResetAfterSendConfirm = true;
    openSendConfirmationModal({
      queuedCount,
      failedCount,
      faxIds,
      historyRecordedCount
    });
  } catch (error) {
    setMessage(sendMessage, error.message);
  } finally {
    sendFaxPrimaryBtn.disabled = false;
  }
});

refreshAllButton.addEventListener("click", async () => {
  try {
    await loadFaxes();
  } catch (error) {
    setMessage(sendMessage, error.message);
  }
});

historyTabSent.addEventListener("click", () => setHistoryFilter("sent"));
historyTabReceived.addEventListener("click", () => setHistoryFilter("received"));
settingsToggleBtn.addEventListener("click", () => {
  if (state.user?.role !== "admin") {
    state.adminSettingsOpen = false;
    applyAdminPanelVisibility();
    return;
  }
  state.adminSettingsOpen = !state.adminSettingsOpen;
  applyAdminPanelVisibility();
});
addressbookToggleBtn.addEventListener("click", () => {
  openAddressbookModal().catch(() => {});
});
addressbookCloseBtn.addEventListener("click", () => {
  closeAddressbookModal();
});
sendConfirmCloseBtn.addEventListener("click", () => {
  closeSendConfirmationModal();
});
sendConfirmOkBtn.addEventListener("click", () => {
  closeSendConfirmationModal();
  if (state.pendingResetAfterSendConfirm) {
    resetSendFormForNextFaxJob();
    state.pendingResetAfterSendConfirm = false;
  }
});
addressbookApplyBtn.addEventListener("click", () => {
  applyAddressbookSelection();
});
addressbookTabContacts.addEventListener("click", () => {
  setAddressbookTab("contacts");
});
addressbookTabBulk.addEventListener("click", () => {
  setAddressbookTab("bulk");
});
addressbookSearchInput.addEventListener("input", () => {
  renderAddressbookList();
});
toInput.addEventListener("input", () => {
  const rawValue = toInput.value || "";
  const parsed = setRecipientsFromInput(rawValue, { syncInput: false });
  if (!parsed.recipients.length || parsed.invalidTokens.length) {
    return;
  }

  const trailingSeparator = /[,\n;]\s*$/.test(rawValue);
  const parts = parseRecipientNumbers(rawValue);
  const lastPart = parts.length ? parts[parts.length - 1] : "";
  const shouldAppendComma = trailingSeparator || isCompletePhoneToken(lastPart);
  syncRecipientsInput({ trailingComma: shouldAppendComma });
});
recipientNameSearchInput.addEventListener("input", () => {
  renderRecipientSuggestions();
});
recipientNameSearchInput.addEventListener("blur", () => {
  setTimeout(() => {
    recipientSuggestions.classList.add("hidden");
  }, 120);
});
addressbookModal.addEventListener("click", (event) => {
  if (event.target === addressbookModal) {
    closeAddressbookModal();
  }
});
sendConfirmModal.addEventListener("click", (event) => {
  if (event.target === sendConfirmModal) {
    closeSendConfirmationModal();
  }
});
document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !addressbookModal.classList.contains("hidden")) {
    closeAddressbookModal();
  }
  if (event.key === "Escape" && !sendConfirmModal.classList.contains("hidden")) {
    closeSendConfirmationModal();
  }
});

contactForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(contactMessage, "");
  const formData = new FormData(contactForm);

  try {
    await api("/api/contacts", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        name: formData.get("name"),
        fax_number: formData.get("fax_number"),
        tags: parseTagsInput(formData.get("tags") || ""),
        email: formData.get("email"),
        notes: formData.get("notes")
      })
    });
    contactForm.reset();
    setMessage(contactMessage, "Contact added.");
    await Promise.all([loadContacts(), loadAllContactsForPicker(), loadContactTags()]);
  } catch (error) {
    setMessage(contactMessage, error.message);
  }
});

contactImportForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(contactImportMessage, "");

  const fileInput = document.getElementById("contact_import_file");
  const file = fileInput.files && fileInput.files[0] ? fileInput.files[0] : null;
  if (!file) {
    setMessage(contactImportMessage, "Choose a CSV file first.");
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  try {
    const summary = await api("/api/contacts/import", {
      method: "POST",
      body: formData
    });
    setMessage(
      contactImportMessage,
      `Imported. Created: ${summary.created}, Updated: ${summary.updated}, Skipped: ${summary.skipped}`
    );
    if (Array.isArray(summary.errors) && summary.errors.length) {
      setMessage(contactImportMessage, `${contactImportMessage.textContent}. ${summary.errors[0]}`);
    }
    contactImportForm.reset();
    await Promise.all([loadContacts(), loadAllContactsForPicker(), loadContactTags()]);
  } catch (error) {
    setMessage(contactImportMessage, error.message);
  }
});

contactRefreshBtn.addEventListener("click", async () => {
  try {
    await Promise.all([loadContacts(), loadAllContactsForPicker()]);
  } catch (error) {
    setMessage(contactMessage, error.message);
  }
});

contactSearchInput.addEventListener("input", async () => {
  try {
    await loadContacts();
  } catch (error) {
    setMessage(contactMessage, error.message);
  }
});

contactTagFilter.addEventListener("change", async () => {
  try {
    await loadContacts();
  } catch (error) {
    setMessage(contactMessage, error.message);
  }
});

bulkSendAllInput.addEventListener("change", () => {
  const disabled = bulkSendAllInput.checked;
  bulkTagModeSelect.disabled = disabled;
  bulkTagsList.classList.toggle("disabled", disabled);
});

bulkSendBtn.addEventListener("click", async () => {
  setMessage(bulkMessage, "");
  const mediaUrl = (bulkMediaUrlInput.value || "").trim();
  const selectedTags = selectedBulkTags();
  const sendAll = bulkSendAllInput.checked;

  if (!mediaUrl) {
    setMessage(bulkMessage, "Enter a media URL.");
    return;
  }
  if (!sendAll && !selectedTags.length) {
    setMessage(bulkMessage, "Select at least one tag, or enable send all contacts.");
    return;
  }

  bulkSendBtn.disabled = true;
  try {
    const job = await api("/api/faxes/bulk", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        media_url: mediaUrl,
        tag_filters: selectedTags,
        tag_mode: bulkTagModeSelect.value,
        send_all: sendAll
      })
    });
    await saveLastMediaUrl(mediaUrl);
    mediaUrlInput.value = mediaUrl;
    setMessage(bulkMessage, `Bulk job queued: ${job.id} (${job.totals.total} contacts).`);
    await Promise.all([loadBulkJobs(), loadFaxes()]);
  } catch (error) {
    setMessage(bulkMessage, error.message);
  } finally {
    bulkSendBtn.disabled = false;
  }
});

bulkRefreshBtn.addEventListener("click", async () => {
  try {
    await loadBulkJobs();
  } catch (error) {
    setMessage(bulkMessage, error.message);
  }
});

settingsForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(settingsMessage, "");
  const formData = new FormData(settingsForm);
  const payload = {
    telnyx_connection_id: formData.get("telnyx_connection_id"),
    telnyx_from_number: formData.get("telnyx_from_number"),
    telnyx_fax_application_id: formData.get("telnyx_fax_application_id"),
    outbound_copy_enabled: document.getElementById("setting_outbound_copy_enabled").checked,
    outbound_copy_email: formData.get("outbound_copy_email"),
    office_name: formData.get("office_name"),
    office_fax_number: formData.get("office_fax_number"),
    office_email: formData.get("office_email")
  };
  const apiKey = (formData.get("telnyx_api_key") || "").toString().trim();
  if (apiKey) {
    payload.telnyx_api_key = apiKey;
  }

  try {
    await api("/api/admin/settings", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    document.getElementById("setting_api_key").value = "";
    setMessage(settingsMessage, "Admin settings saved.");
    await Promise.all([loadAdminSettings(), loadAppSettings()]);
  } catch (error) {
    setMessage(settingsMessage, error.message);
  }
});

loadFaxAppBtn.addEventListener("click", async () => {
  setMessage(faxAppMessage, "");
  try {
    await loadFaxAppSettings();
    setMessage(faxAppMessage, "Loaded current Telnyx fax app settings.");
  } catch (error) {
    setMessage(faxAppMessage, error.message);
  }
});

faxAppForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(faxAppMessage, "");
  const formData = new FormData(faxAppForm);
  const payload = {};

  const email = (formData.get("fax_email_recipient") || "").toString().trim();
  const inbound = (formData.get("inbound_channel_limit") || "").toString().trim();
  const outbound = (formData.get("outbound_channel_limit") || "").toString().trim();

  if (email !== "") payload.fax_email_recipient = email;
  if (inbound !== "") payload.inbound_channel_limit = Number(inbound);
  if (outbound !== "") payload.outbound_channel_limit = Number(outbound);

  try {
    await api("/api/admin/telnyx/fax-application", {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    setMessage(faxAppMessage, "Fax application updated on Telnyx.");
    await loadFaxAppSettings();
  } catch (error) {
    setMessage(faxAppMessage, error.message);
  }
});

createUserForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  setMessage(usersMessage, "");
  const formData = new FormData(createUserForm);
  const provider = normalizeAuthProvider(formData.get("auth_provider") || "local");
  const usernameInput = (formData.get("username") || "").toString().trim().toLowerCase();
  const payload = {
    role: formData.get("role"),
    auth_provider: provider
  };

  if (provider === "google") {
    payload.google_email = (formData.get("google_email") || "").toString().trim().toLowerCase();
    if (usernameInput) {
      payload.username = usernameInput;
    }
  } else {
    payload.username = usernameInput;
    payload.password = formData.get("password");
  }

  try {
    const created = await api("/api/admin/users", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    createUserForm.reset();
    applyCreateUserProviderUI();
    const providerLabel = normalizeAuthProvider(created.auth_provider) === "google" ? "Google" : "local";
    setMessage(usersMessage, `User created (${providerLabel}). Login username: ${created.username}`);
    await loadUsers();
  } catch (error) {
    setMessage(usersMessage, error.message);
  }
});

if (newAuthProviderSelect) {
  newAuthProviderSelect.addEventListener("change", () => {
    applyCreateUserProviderUI();
  });
}

mediaUrlInput.addEventListener("blur", async () => {
  const urls = parseMediaUrls(mediaUrlInput.value || "");
  const value = urls[0] || "";
  if (!value || !state.user) return;
  try {
    await saveLastMediaUrl(value);
    if (!bulkMediaUrlInput.value.trim()) {
      bulkMediaUrlInput.value = value;
    }
  } catch (error) {
    // non-blocking
  }
});

sendFileInput.addEventListener("change", () => {
  const files = sendFileInput.files ? Array.from(sendFileInput.files) : [];
  if (!files.length) {
    return;
  }
  try {
    addFilesToSelection(files);
    setMessage(sendMessage, `Added ${files.length} file(s) to the fax.`);
  } catch (error) {
    setMessage(sendMessage, error.message || "Could not add files.");
  } finally {
    sendFileInput.value = "";
  }
});

async function bootstrap() {
  consumeAuthQueryState();
  applyCreateUserProviderUI();
  await loadGoogleAuthConfig({ silent: true });
  try {
    const me = await api("/api/auth/me");
    if (me.authenticated) {
      setAuthenticatedView(me.user);
      await initAfterLogin();
    } else {
      setAuthenticatedView(null);
    }
  } catch (error) {
    setAuthenticatedView(null);
  }
}

bootstrap();
setInterval(async () => {
  if (!state.user) return;
  try {
    await Promise.all([loadFaxes(), loadBulkJobs(), loadFrequentContacts()]);
  } catch (error) {
    if (error.status === 401) {
      setAuthenticatedView(null);
    }
  }
}, 15000);
