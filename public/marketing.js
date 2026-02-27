const signupModal = document.getElementById("signup-modal");
const signupForm = document.getElementById("signup-form");
const signupMessage = document.getElementById("signup-message");
const signupPlan = document.getElementById("signup_plan");
const signupSubmitBtn = document.getElementById("signup_submit_btn");

function setMessage(text) {
  signupMessage.textContent = text || "";
}

function openSignup(plan = "starter") {
  if (signupPlan) {
    signupPlan.value = plan;
  }
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
  try {
    const formData = new FormData(signupForm);
    const payload = {
      company_name: (formData.get("company_name") || "").toString().trim(),
      email: (formData.get("email") || "").toString().trim().toLowerCase(),
      username: (formData.get("username") || "").toString().trim().toLowerCase(),
      password: (formData.get("password") || "").toString(),
      plan: (formData.get("plan") || "starter").toString().trim().toLowerCase()
    };

    const response = await fetch("/api/public/signup", {
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
    const loginUrl = body.login_url || "/app";
    setTimeout(() => {
      window.location.assign(loginUrl);
    }, 1200);
  } catch (error) {
    setMessage(error.message || "Signup failed.");
  } finally {
    signupSubmitBtn.disabled = false;
  }
}

bindOpenButtons();

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
