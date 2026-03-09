const signupModal = document.getElementById("signup-modal");
const signupForm = document.getElementById("signup-form");
const signupMessage = document.getElementById("signup-message");
const signupPlan = document.getElementById("signup_plan");
const signupSubmitBtn = document.getElementById("signup_submit_btn");
const signupGoogleBtn = document.getElementById("signup_google_btn");
const signupPlanSummary = document.getElementById("signup-plan-summary");
const signupBillingAck = document.getElementById("signup_billing_ack");
const appLinks = Array.from(document.querySelectorAll("[data-app-link]"));

const runtimeConfig = window.__FAX_MARKETING_CONFIG || {};
const apiBaseUrl = normalizeBaseUrl(runtimeConfig.apiBaseUrl || "");
const appBaseUrl = normalizeBaseUrl(runtimeConfig.appBaseUrl || apiBaseUrl || "");

const PLAN_SUMMARY = {
  starter: "Starter: 300 outbound + 300 inbound pages included. Overage is $0.021/page.",
  pro: "Pro: 1,800 outbound + 1,800 inbound pages included. Overage is $0.018/page.",
  enterprise: "Enterprise: 9,000 outbound + 9,000 inbound pages included. Overage is $0.015/page."
};

function setMessage(text) {
  signupMessage.textContent = text || "";
}

function normalizeBaseUrl(value) {
  const raw = (value || "").toString().trim();
  if (!raw) return "";
  try {
    const parsed = new URL(raw);
    if (parsed.protocol !== "https:" && parsed.protocol !== "http:") return "";
    return raw.replace(/\/+$/, "");
  } catch (error) {
    return "";
  }
}

function withBase(base, relativePath) {
  const path = (relativePath || "/").toString();
  if (!base) return path;
  return `${base}${path.startsWith("/") ? path : `/${path}`}`;
}

function isAbsoluteUrl(value) {
  return /^https?:\/\//i.test((value || "").toString());
}

function toAppUrl(pathOrUrl) {
  const target = (pathOrUrl || "/app").toString();
  if (isAbsoluteUrl(target)) {
    return target;
  }
  return withBase(appBaseUrl, target.startsWith("/") ? target : `/${target}`);
}

function toApiUrl(path) {
  return withBase(apiBaseUrl, path);
}

function applyAppLinks() {
  const appUrl = toAppUrl("/app");
  appLinks.forEach((node) => {
    node.setAttribute("href", appUrl);
  });
}

function normalizeTenantId(value) {
  const raw = (value || "").toString().trim().toLowerCase();
  if (!raw) return "";
  return /^[a-z0-9._-]{2,64}$/.test(raw) ? raw : "";
}

function consumeSignupQueryState() {
  const params = new URLSearchParams(window.location.search || "");
  const signupError = (params.get("signup_error") || "").toString().trim();
  if (signupError) {
    setMessage(signupError);
  }
  if (params.has("signup_error")) {
    params.delete("signup_error");
    const query = params.toString();
    const nextUrl = `${window.location.pathname}${query ? `?${query}` : ""}`;
    window.history.replaceState({}, document.title, nextUrl);
  }
}

function buildSignupPayload() {
  const formData = new FormData(signupForm);
  const tenantIdRaw = (formData.get("tenant_id") || "").toString().trim();
  const payload = {
    company_name: (formData.get("company_name") || "").toString().trim(),
    email: (formData.get("email") || "").toString().trim().toLowerCase(),
    username: (formData.get("username") || "").toString().trim().toLowerCase(),
    password: (formData.get("password") || "").toString(),
    plan: (formData.get("plan") || "starter").toString().trim().toLowerCase()
  };
  if (tenantIdRaw) {
    const normalizedTenantId = normalizeTenantId(tenantIdRaw);
    if (!normalizedTenantId) {
      throw new Error("Workspace ID must be 2-64 chars using letters, numbers, dot, underscore, or dash.");
    }
    payload.tenant_id = normalizedTenantId;
  }
  return payload;
}

function openSignup(plan = "starter") {
  if (signupPlan) {
    signupPlan.value = plan;
  }
  renderPlanSummary();
  setMessage("");
  signupModal.classList.remove("hidden");
}

function closeSignup() {
  signupModal.classList.add("hidden");
}

function bindOpenButtons() {
  ["open-signup-top", "open-signup-hero"].forEach((id) => {
    const node = document.getElementById(id);
    if (!node) return;
    node.addEventListener("click", () => openSignup("starter"));
  });

  document.querySelectorAll(".plan-select").forEach((node) => {
    node.addEventListener("click", () => {
      const plan = (node.dataset.plan || "starter").toLowerCase();
      openSignup(plan);
    });
  });
}

async function submitSignup(event) {
  event.preventDefault();
  setMessage("");
  signupSubmitBtn.disabled = true;
  if (signupGoogleBtn) {
    signupGoogleBtn.disabled = true;
  }
  try {
    const payload = buildSignupPayload();

    const response = await fetch(toApiUrl("/api/public/signup"), {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-Tenant-Id": "default" },
      body: JSON.stringify(payload)
    });
    const body = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(body.error || "Signup failed.");
    }

    if (body.checkout_url) {
      window.location.assign(body.checkout_url);
      return;
    }

    setMessage(`${body.message || "Signup created."} Redirecting to sign in...`);
    const loginUrl = toAppUrl(body.login_url || "/app");
    setTimeout(() => {
      window.location.assign(loginUrl);
    }, 1200);
  } catch (error) {
    setMessage(error.message || "Signup failed.");
  } finally {
    signupSubmitBtn.disabled = false;
    if (signupGoogleBtn) {
      signupGoogleBtn.disabled = false;
    }
  }
}

async function submitGoogleSignup() {
  setMessage("");
  if (signupGoogleBtn) {
    signupGoogleBtn.disabled = true;
  }
  if (signupSubmitBtn) {
    signupSubmitBtn.disabled = true;
  }
  try {
    const payload = buildSignupPayload();
    if (!payload.company_name || payload.company_name.length < 2) {
      throw new Error("Company name is required.");
    }
    if (signupBillingAck && !signupBillingAck.checked) {
      throw new Error("Please acknowledge billing terms before continuing.");
    }
    const params = new URLSearchParams();
    params.set("company_name", payload.company_name);
    params.set("plan", payload.plan);
    if (payload.tenant_id) {
      params.set("tenant_id", payload.tenant_id);
    }
    window.location.assign(toApiUrl(`/api/public/signup/google/start?${params.toString()}`));
  } catch (error) {
    setMessage(error.message || "Google signup failed.");
    if (signupGoogleBtn) {
      signupGoogleBtn.disabled = false;
    }
    if (signupSubmitBtn) {
      signupSubmitBtn.disabled = false;
    }
  }
}

function renderPlanSummary() {
  if (!signupPlanSummary || !signupPlan) return;
  const plan = (signupPlan.value || "starter").toString().trim().toLowerCase();
  signupPlanSummary.textContent =
    PLAN_SUMMARY[plan] || "You will continue to Stripe to enter payment details and activate your workspace.";
}

bindOpenButtons();
applyAppLinks();

const closeBtn = document.getElementById("close-signup");
if (closeBtn) {
  closeBtn.addEventListener("click", () => closeSignup());
}

signupModal.addEventListener("click", (event) => {
  if (event.target === signupModal) {
    closeSignup();
  }
});

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && !signupModal.classList.contains("hidden")) {
    closeSignup();
  }
});

signupForm.addEventListener("submit", submitSignup);
if (signupPlan) {
  signupPlan.addEventListener("change", renderPlanSummary);
  renderPlanSummary();
}
if (signupGoogleBtn) {
  signupGoogleBtn.addEventListener("click", submitGoogleSignup);
}
consumeSignupQueryState();
