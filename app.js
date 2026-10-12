require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { Resend } = require("resend");
const { initializeApp, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore, FieldValue } = require("firebase-admin/firestore");
const { canClosePaidTable, statusAfterServing } = require("./orderLifecycle");
const { planMatchesCheckout, isSuccessfulSubscriptionCharge } = require("./subscriptionBilling");
const { canReadGuestCheck, guestSessionView, toWire } = require("./guestAccess");
const { summarizePayments, pendingTransferTotals } = require("./settlementLedger");
const { receiptsForSettlement, receiptHtml } = require("./receipts");
const { verifiedMenuItems } = require("./menuItems");

const emulatorMode = process.env.USE_FIREBASE_EMULATORS === "true";
if (emulatorMode) {
  if (!process.env.FIRESTORE_EMULATOR_HOST?.startsWith("127.0.0.1:") ||
      !process.env.FIREBASE_AUTH_EMULATOR_HOST?.startsWith("127.0.0.1:") ||
      !String(process.env.GCLOUD_PROJECT || "").startsWith("demo-")) {
    throw new Error("Emulator mode requires loopback Firestore/Auth hosts and a demo project ID.");
  }
  initializeApp({ projectId: process.env.GCLOUD_PROJECT });
  // Local tests cannot contact payment or image-deletion providers.
  process.env.PAYSTACK_SECRET_KEY = "";
  process.env.CLOUDINARY_API_SECRET = "";
} else {
  let serviceAccount;
  try { serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT || ""); }
  catch (_) { throw new Error("FIREBASE_SERVICE_ACCOUNT must contain valid service-account JSON."); }
  initializeApp({ credential: cert(serviceAccount) });
}
// Bound external calls and prevent demo sessions from touching real providers.
async function providerFetch(url, options = {}) {
  if (emulatorMode) throw new Error("External providers are disabled in emulator mode.");
  return fetch(url, { ...options, signal: AbortSignal.timeout(15_000) });
}
const firebaseAuth = getAuth();
const db = getFirestore();

const app = express();
const port = Number(process.env.PORT || 4000);
const resend = emulatorMode ? { emails: { send: async (payload) => {
  const ref = db.collection("emulatorEmails").doc();
  await ref.set({ ...payload, createdAt: FieldValue.serverTimestamp() });
  return { data: { id: ref.id } };
} } } : new Resend(process.env.RESEND_API_KEY);
// Sender for all transactional email. Set MAIL_FROM to your verified Resend domain,
// e.g. "Servrr <welcome@servrr.ng>". Falls back to the sandbox if unset (goes to spam).
const MAIL_FROM = process.env.MAIL_FROM || "Servrr <onboarding@resend.dev>";
const APP_URL = emulatorMode ? "http://127.0.0.1:5174" : process.env.APP_URL || "https://servrr.ng";

// Behind Render's proxy — needed for req.ip (rate limiting) to be the real client IP.
app.set("trust proxy", 1);

// ── CORS ───────────────────────────────────────────────────────────────────────
// Set ALLOWED_ORIGINS (comma-separated) in the environment to lock the API to your
// real frontend origins. If unset, falls back to permissive (logged) so nothing breaks.
// Origins are normalized (trailing slashes, stray quotes, case) so near-miss values still match.
const normalizeOrigin = (o) =>
  String(o || "")
    .trim()
    .replace(/^['"]|['"]$/g, "")
    .replace(/\/+$/, "")
    .toLowerCase();

const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "")
  .split(",")
  .map(normalizeOrigin)
  .filter(Boolean);

if (ALLOWED_ORIGINS.length === 0) {
  if (process.env.NODE_ENV === "production") throw new Error("ALLOWED_ORIGINS is required in production.");
  console.warn(
    "[cors] ALLOWED_ORIGINS not set — allowing all origins. Set it to lock down CORS in production.",
  );
} else {
  console.log(`[cors] allowed origins: ${ALLOWED_ORIGINS.join(", ")}`);
}

app.use(
  cors({
    exposedHeaders: ["X-Request-Id"],
    origin(origin, cb) {
      // Non-browser / same-origin requests (no Origin header) are always allowed.
      if (!origin) return cb(null, true);
      if (ALLOWED_ORIGINS.length === 0) return cb(null, true);
      if (ALLOWED_ORIGINS.includes(normalizeOrigin(origin))) return cb(null, true);
      console.warn(
        `[cors] rejected origin "${origin}" — allowed: ${ALLOWED_ORIGINS.join(", ")}`,
      );
      // Deny by omitting CORS headers (browser blocks) rather than erroring with a 500.
      return cb(null, false);
    },
  }),
);

app.use(express.json({
  limit: "256kb",
  verify: (req, _res, buffer) => {
    // Paystack signs the exact request bytes. Keep them before JSON parsing so
    // webhook verification is not affected by whitespace or key ordering.
    const requestPath = String(req.originalUrl || "").split("?")[0].replace(/\/+$/, "");
    if (requestPath === "/paystack-webhook") req.rawBody = buffer;
  },
}));
app.use(express.urlencoded({ limit: "256kb", extended: false }));

// Baseline security headers for API responses (the frontend's headers live in vercel.json).
app.use((req, res, next) => {
  req.requestId = /^[a-zA-Z0-9_-]{12,100}$/.test(req.headers["x-request-id"] || "")
    ? req.headers["x-request-id"] : crypto.randomUUID();
  res.setHeader("X-Request-Id", req.requestId);
  const started = Date.now();
  res.on("finish", () => {
    if (process.env.NODE_ENV === "production" || res.statusCode >= 500) console.log(JSON.stringify({
      event: "request", requestId: req.requestId, method: req.method, path: req.path,
      status: res.statusCode, durationMs: Date.now() - started,
    }));
  });
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  next();
});

// ── Rate limiting ──────────────────────────────────────────────────────────────
// Lightweight in-memory fixed-window limiter (sufficient for a single instance;
// use a shared store like Redis if the backend is ever horizontally scaled).
const rateBuckets = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [k, b] of rateBuckets) if (now > b.reset) rateBuckets.delete(k);
}, 60_000).unref?.();

const rateLimit = ({ windowMs, max }) => (req, res, next) => {
  const key = `${req.method} ${req.path}:${req.ip}`;
  const now = Date.now();
  let bucket = rateBuckets.get(key);
  if (!bucket || now > bucket.reset) {
    bucket = { count: 0, reset: now + windowMs };
    rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > max) {
    res.setHeader("Retry-After", String(Math.ceil((bucket.reset - now) / 1000)));
    return res
      .status(429)
      .json({ error: "Too many requests. Please slow down and try again shortly." });
  }
  return next();
};

const normalizePaymentMode = (mode) =>
  // Diner online payments are paused while SERVRR launches with cash, POS,
  // and bank transfer settlement.
  "at_table";

const slugify = (name) =>
  String(name || "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "-")
    .replace(/-+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 20);

const isExpiredTimestamp = (value) => {
  if (!value) return false;
  const expiry =
    typeof value.toDate === "function" ? value.toDate() : new Date(value);
  return Number.isFinite(expiry.getTime()) && new Date() > expiry;
};

const toMillis = (ts) => {
  if (!ts) return 0;
  if (typeof ts.toDate === "function") return ts.toDate().getTime();
  if (ts.seconds) return ts.seconds * 1000;
  const d = new Date(ts).getTime();
  return Number.isFinite(d) ? d : 0;
};

const LEGACY_CHECK_ID = "legacy";
const OPEN_TABLE_SESSION_STATUSES = ["open", "awaiting_payment", "transfer_reported"];
const GROUP_PAYMENT_SHARE_MS = 15 * 60 * 1000;
const validCheckId = (value) => /^c_[a-f0-9]{32}$/.test(String(value || ""));
const validCheckSecret = (value) => /^[a-f0-9]{64}$/.test(String(value || ""));
const hashCheckSecret = (value) => crypto.createHash("sha256").update(value).digest("hex");
const orderCheckId = (order) => order.checkId || LEGACY_CHECK_ID;
const checkState = (session, checkId) => session.checks?.[checkId] || {
  status: checkId === LEGACY_CHECK_ID && !session.checks?.[checkId] &&
    ["awaiting_payment", "transfer_reported", "paid"].includes(session.status)
    ? session.status : "open",
};
const hasValidSessionToken = (session, token) => Boolean(token) &&
  Array.isArray(session.accessTokens) && session.accessTokens.some(
    (entry) => entry.hash === hashSessionAccessToken(token) && Number(entry.expiresAt) > Date.now(),
  );
const hasCheckAccess = (session, checkId, secret) => {
  if (!validCheckId(checkId) || !validCheckSecret(secret)) return false;
  const state = session.checks?.[checkId];
  return !state || Boolean(state.secretHash && hashCheckSecret(secret) === state.secretHash);
};

const createSessionAccessToken = () => crypto.randomBytes(32).toString("hex");
const hashSessionAccessToken = (token) =>
  crypto.createHash("sha256").update(String(token || "")).digest("hex");
const SESSION_IDLE_MS = 4 * 60 * 60 * 1000;
const EMAIL_OTP_TTL_MS = 10 * 60 * 1000;
const EMAIL_OTP_MAX_ATTEMPTS = 5;

const normalizeEmail = (email) => String(email || "").trim().toLowerCase();
const hashValue = (value) =>
  crypto.createHash("sha256").update(String(value || "")).digest("hex");
const otpDocumentId = (purpose, email) => `${purpose}_${hashValue(normalizeEmail(email))}`;
const createOtp = () => String(crypto.randomInt(0, 1_000_000)).padStart(6, "0");

const DEFAULT_MONTHLY_FEES = {
  restaurant: 25000,
  lounge: 40000,
};

const SUBSCRIPTION_PRICING = {
  restaurant: { monthly: 25000, yearly: 250000 },
  lounge: { monthly: 40000, yearly: 400000 },
};

// A venue is operational only after a platform administrator activates it.
// Billing never expires a live venue automatically; suspension is explicit.
const isVenueActive = (profile) => {
  if (!profile) return false;
  return profile.suspended !== true;
};
const isVenueAcceptingOrders = (profile) => isVenueActive(profile) && profile.servicePaused !== true;

const requireFirebaseUser = async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: "Missing auth token" });

  try {
    req.firebaseUser = await firebaseAuth.verifyIdToken(token, true);
    if (await isSuperAdmin(req.firebaseUser.uid)) {
      const policy = await db.doc("platformSecurity/access").get();
      const requireMfa = process.env.REQUIRE_SUPERADMIN_MFA === "true" || policy.data()?.requireSuperAdminMfa === true;
      if (requireMfa && !req.firebaseUser.firebase?.sign_in_second_factor) {
        return res.status(403).json({ error: "Sign in with your platform administrator's second factor." });
      }
    }
    return next();
  } catch (err) {
    console.error("Auth token verification failed:", err);
    return res.status(401).json({ error: "Invalid auth token" });
  }
};

// Mirrors isSuperAdmin/ownsRestaurantProfile/hasRestaurantRole in Functions/firestore.rules —
// Admin SDK calls bypass rules, so staff-only routes re-check the same access model here.
const SUPER_ADMIN_UID = "vqjNAPsGMyUjVL7PMIg3cBNSQhS2";
const OPS_ROLES = ["owner", "manager", "admin", "staff", "kitchen", "bar", "waiter", "cashier"];
const MANAGE_ROLES = ["owner", "manager", "admin"];

const paymentRevenueField = (paidVia) =>
  ({
    cash: "cashRevenue",
    pos: "posRevenue",
    transfer: "transferRevenue",
    online: "onlineRevenue",
  })[paidVia] || "otherRevenue";

const queuePaidTableRelease = (tx, restaurantId, sessionId, tableRef, tableSnap) => {
  if (tableSnap.data()?.currentSessionId === sessionId) {
    tx.set(tableRef, { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
  }
  const dayKey = lagosDayKey();
  tx.set(db.doc(`restaurants/${restaurantId}/dailySummaries/${dayKey}`), {
    dateKey: dayKey,
    settledTables: FieldValue.increment(1),
    updatedAt: FieldValue.serverTimestamp(),
  }, { merge: true });
};

// Revenue is reported against the venue's operating day, not UTC. Servrr's
// current market is Nigeria, so the reconciliation key follows Lagos time.
const lagosDayKey = (value = new Date()) => {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Africa/Lagos",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date(value));
  const values = Object.fromEntries(
    parts.filter((part) => part.type !== "literal").map((part) => [part.type, part.value]),
  );
  return `${values.year}-${values.month}-${values.day}`;
};

// Escape user-supplied strings before interpolating into HTML emails.
const escapeHtml = (value) =>
  String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");

// Mirrors isSuperAdmin in firestore.rules — the hardcoded UID OR a users doc with role "superadmin".
const isSuperAdmin = async (uid) => {
  if (uid === SUPER_ADMIN_UID) return true;
  const snap = await db.doc(`users/${uid}`).get();
  return snap.exists && snap.data().role === "superadmin";
};

const hasRestaurantAccess = async (uid, restaurantId, roles) => {
  if (await isSuperAdmin(uid)) return true;

  const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
  if (!profileSnap.exists || profileSnap.data().suspended === true) return false;
  if (profileSnap.exists && profileSnap.data().ownerUid === uid) return true;

  const userSnap = await db.doc(`users/${uid}`).get();
  if (!userSnap.exists) return false;
  const userData = userSnap.data();
  return userData.restaurantId === restaurantId && roles.includes(userData.role);
};

// Any operational staff (mirrors canViewRestaurantOps).
const userCanOperate = (uid, restaurantId) =>
  hasRestaurantAccess(uid, restaurantId, OPS_ROLES);

// Management only (mirrors canManageRestaurant) — owner/manager/admin.
const userCanManage = (uid, restaurantId) =>
  hasRestaurantAccess(uid, restaurantId, MANAGE_ROLES);
const userCanCollect = (uid, restaurantId) =>
  hasRestaurantAccess(uid, restaurantId, [...MANAGE_ROLES, "cashier", "staff"]);

// Billing must remain available while a workspace is awaiting its first
// payment or recovering from a failed renewal. It therefore checks ownership
// and role without requiring the workspace itself to be active.
const userCanManageSubscription = async (uid, restaurantId) => {
  if (await isSuperAdmin(uid)) return true;
  const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
  if (!profileSnap.exists) return false;
  if (profileSnap.data().ownerUid === uid) return true;
  const userSnap = await db.doc(`users/${uid}`).get();
  if (!userSnap.exists) return false;
  const user = userSnap.data();
  return user.restaurantId === restaurantId && MANAGE_ROLES.includes(user.role);
};

const cloudinaryPublicIdFromUrl = (value) => {
  try {
    const url = new URL(String(value || ""));
    if (!url.hostname.endsWith("res.cloudinary.com")) return "";
    const parts = url.pathname.split("/").filter(Boolean);
    const uploadIndex = parts.indexOf("upload");
    if (uploadIndex < 0) return "";
    const assetParts = parts.slice(uploadIndex + 1);
    while (assetParts[0] && (/^v\d+$/.test(assetParts[0]) || assetParts[0].includes(","))) {
      assetParts.shift();
    }
    return assetParts.join("/").replace(/\.[a-z0-9]+$/i, "");
  } catch {
    return "";
  }
};

const destroyCloudinaryImage = async (publicId) => {
  const cloudName = process.env.CLOUDINARY_CLOUD_NAME;
  const apiKey = process.env.CLOUDINARY_API_KEY;
  const apiSecret = process.env.CLOUDINARY_API_SECRET;
  if (!cloudName || !apiKey || !apiSecret) {
    throw Object.assign(new Error("Cloudinary cleanup is not configured."), { statusCode: 503 });
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const signature = crypto
    .createHash("sha1")
    .update(`public_id=${publicId}&timestamp=${timestamp}${apiSecret}`)
    .digest("hex");
  const form = new URLSearchParams({
    public_id: publicId,
    timestamp: String(timestamp),
    api_key: apiKey,
    signature,
  });
  const response = await providerFetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/destroy`, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: form,
  });
  const result = await response.json().catch(() => ({}));
  if (!response.ok || (result.result !== "ok" && result.result !== "not found")) {
    throw new Error(result.error?.message || "Cloudinary asset cleanup failed.");
  }
};

app.post("/delete-restaurant-assets", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim().toLowerCase();
  if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
    return res.status(400).json({ error: "Invalid restaurant ID." });
  }
  if (!(await isSuperAdmin(req.firebaseUser.uid))) {
    return res.status(403).json({ error: "Only a super admin can delete restaurant assets." });
  }

  try {
    const [menuSnap, profileSnap, privateSnap] = await Promise.all([
      db.collection(`restaurants/${restaurantId}/menu`).get(),
      db.doc(`restaurants/${restaurantId}/profile/info`).get(),
      db.doc(`restaurants/${restaurantId}/profile/private`).get(),
    ]);
    const publicIds = new Set();
    for (const snapshot of [profileSnap, privateSnap, ...menuSnap.docs]) {
      if (!snapshot.exists) continue;
      const data = snapshot.data();
      if (data.imagePublicId) publicIds.add(String(data.imagePublicId));
      if (data.logoPublicId) publicIds.add(String(data.logoPublicId));
      const parsedImageId = cloudinaryPublicIdFromUrl(data.imageUrl);
      const parsedLogoId = cloudinaryPublicIdFromUrl(data.logoUrl);
      if (parsedImageId) publicIds.add(parsedImageId);
      if (parsedLogoId) publicIds.add(parsedLogoId);
    }
    for (const publicId of publicIds) await destroyCloudinaryImage(publicId);
    return res.json({ success: true, deleted: publicIds.size });
  } catch (err) {
    console.error("Restaurant asset cleanup error:", err);
    return res.status(err.statusCode || 502).json({
      error: err.message || "Restaurant assets could not be cleaned up.",
    });
  }
});

const validateOrderItems = (items) => {
  if (!Array.isArray(items) || items.length === 0 || items.length > 100) {
    return false;
  }
  return items.every((item) => {
    const price = Number(item.price);
    const qty = Number(item.qty);
    return (
      typeof item.name === "string" &&
      item.name.trim().length > 0 &&
      Number.isFinite(price) &&
      price >= 0 &&
      Number.isFinite(qty) &&
      Number.isInteger(qty) &&
      qty > 0 &&
      qty <= 100
    );
  });
};

const calculateItemsTotal = (items) => {
  const kobo = items.reduce((sum, item) => sum + Math.round(Number(item.price) * 100) * Number(item.qty), 0);
  if (!Number.isSafeInteger(kobo)) throw Object.assign(new Error("The order amount is outside the supported range."), { statusCode: 400 });
  return kobo / 100;
};

const verifyPaystackReference = async (reference) => {
  const paystackRes = await providerFetch(
    `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
    {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    },
  );
  const data = await paystackRes.json();
  if (!paystackRes.ok || data.data?.status !== "success") {
    const message = data.message || "Payment not successful";
    const error = new Error(message);
    error.statusCode = 400;
    throw error;
  }
  return data.data;
};

const normalizeSubscriptionType = (value) => value === "lounge" ? "lounge" : "restaurant";
const normalizeSubscriptionCycle = (value) => value === "yearly" ? "yearly" : "monthly";

const getSubscriptionPlanCode = (businessType, billingCycle) => {
  const operation = normalizeSubscriptionType(businessType) === "lounge" ? "LOUNGE" : "RESTAURANT";
  const cycle = normalizeSubscriptionCycle(billingCycle) === "yearly" ? "YEARLY" : "MONTHLY";
  return process.env[`PAYSTACK_${operation}_${cycle}_PLAN_CODE`] || "";
};

const getSubscriptionConfig = (businessType, billingCycle) => {
  const type = normalizeSubscriptionType(businessType);
  const cycle = normalizeSubscriptionCycle(billingCycle);
  return {
    businessType: type,
    billingCycle: cycle,
    planCode: getSubscriptionPlanCode(type, cycle),
    amountNaira: SUBSCRIPTION_PRICING[type][cycle],
  };
};

const planCodeFromPayload = (data) =>
  data?.plan?.plan_code ||
  data?.plan_object?.plan_code ||
  data?.subscription?.plan?.plan_code ||
  data?.metadata?.planCode ||
  "";

const subscriptionCodeFromPayload = (data) =>
  data?.subscription_code || data?.subscription?.subscription_code || "";

const customerCodeFromPayload = (data) =>
  data?.customer?.customer_code || data?.customer_code || "";

const subscriptionIntentId = (email, planCode) =>
  hashValue(`${normalizeEmail(email)}|${String(planCode || "")}`);

const customerPlanId = (customerCode, planCode) =>
  hashValue(`${String(customerCode || "")}|${String(planCode || "")}`);

const addSubscriptionPeriod = (value, cycle) => {
  const next = new Date(value);
  if (normalizeSubscriptionCycle(cycle) === "yearly") {
    next.setUTCFullYear(next.getUTCFullYear() + 1);
  } else {
    // Paystack renews subscriptions opened on the 29th–31st on the 28th.
    const originalDay = next.getUTCDate();
    next.setUTCDate(1);
    next.setUTCMonth(next.getUTCMonth() + 1);
    next.setUTCDate(Math.min(originalDay, 28));
  }
  return next;
};

// Generate a Firebase email-verification link. Tries to send the user back to the
// app's /login afterwards; falls back to the default handler if that domain isn't
// in Firebase's authorized domains yet.
const genVerifyLink = async (email) => {
  try {
    return await firebaseAuth.generateEmailVerificationLink(email, {
      url: `${APP_URL}/login`,
      handleCodeInApp: false,
    });
  } catch (_) {
    return firebaseAuth.generateEmailVerificationLink(email);
  }
};

// Branded welcome + email-verification message, sent via Resend from the verified domain.
const sendWelcomeEmail = async (email, name, verifyLink) => {
  const safeName = escapeHtml(name || "there");
  const html = `
    <div style="background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:40px 28px;">
      <p style="color:#fa5631;font-size:22px;font-weight:900;letter-spacing:-0.5px;margin:0 0 28px 0;">SERVRR</p>
      <h1 style="color:#fff;font-size:24px;font-weight:800;margin:0 0 12px 0;">Welcome, ${safeName} 👋</h1>
      <p style="color:#aaa;font-size:14px;line-height:1.6;margin:0 0 24px 0;">
        Your restaurant workspace is ready. One quick step to activate it — confirm your email address:
      </p>
      <a href="${verifyLink}" style="display:inline-block;background:#fa5631;color:#0a0a0a;font-size:14px;font-weight:800;text-decoration:none;padding:14px 32px;border-radius:10px;margin-bottom:28px;">
        Verify my email
      </a>
      <div style="background:#111;border:1px solid #222;border-radius:14px;padding:20px;margin:8px 0 24px 0;">
        <p style="color:#666;font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:700;margin:0 0 12px 0;">What's next</p>
        <p style="color:#ccc;font-size:13px;line-height:1.7;margin:0;">
          1. Verify your email (button above)<br/>
          2. Log in to your dashboard<br/>
          3. Add your menu &amp; generate table QR codes<br/>
          4. Start taking orders
        </p>
      </div>
      <p style="color:#555;font-size:11px;line-height:1.5;margin:0;word-break:break-all;">
        If the button doesn't work, paste this link into your browser:<br/>${verifyLink}
      </p>
      <p style="color:#333;font-size:11px;text-align:center;margin-top:32px;">© ${new Date().getFullYear()} SERVRR</p>
    </div>`;

  await resend.emails.send({
    from: MAIL_FROM,
    to: [email],
    subject: "Welcome to Servrr — verify your email",
    html,
  });
};

const sendOtpEmail = async ({ email, code, purpose }) => {
  const heading = purpose === "password_reset" ? "Reset your password" : "Verify your email";
  const detail = purpose === "password_reset"
    ? "Use this code to choose a new Servrr password."
    : "Use this code to continue setting up your Servrr workspace.";
  const html = `
    <div style="background:#fffaf5;font-family:Georgia,'Times New Roman',serif;max-width:480px;margin:0 auto;padding:40px 28px;color:#191511;">
      <p style="color:#f76b00;font-size:28px;font-weight:700;margin:0 0 32px;">Servrr</p>
      <h1 style="font-size:28px;line-height:1.15;margin:0 0 12px;">${heading}</h1>
      <p style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#685f57;font-size:14px;line-height:1.6;margin:0 0 24px;">${detail}</p>
      <div style="font-family:ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:10px;color:#191511;font-size:30px;font-weight:800;background:#fff;border:1px solid #f0ded0;border-radius:14px;padding:18px 20px;text-align:center;">${code}</div>
      <p style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#8a8179;font-size:12px;line-height:1.6;margin:24px 0 0;">This code expires in 10 minutes. If you did not request it, you can ignore this email.</p>
    </div>`;
  await resend.emails.send({
    from: MAIL_FROM,
    to: [email],
    subject: `${code} is your Servrr verification code`,
    html,
  });
};

// ── Public setup and email verification ──────────────────────────────────────
// Signup is intentionally verified before Firebase Auth creates an account. This
// avoids abandoned/unverified users and binds the verified email to the invite.
app.post("/setup-requests", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const name = String(req.body?.name || "").trim().slice(0, 120);
  const businessName = String(req.body?.businessName || "").trim().slice(0, 160);
  const email = normalizeEmail(req.body?.email);
  const phone = String(req.body?.phone || "").trim().slice(0, 40);
  const operatingMode = req.body?.operatingMode === "lounge" ? "lounge" : "restaurant";
  const planKind = req.body?.planKind === "custom" ? "custom" : "standard";
  const needs = String(req.body?.needs || "").trim().slice(0, 1500);
  if (!name || !businessName || !email || !phone) {
    return res.status(400).json({ error: "Name, business name, email, and phone are required." });
  }
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }

  try {
    const ref = await db.collection("setupRequests").add({
      name,
      businessName,
      email,
      phone,
      operatingMode,
      planKind,
      needs,
      status: "new",
      createdAt: FieldValue.serverTimestamp(),
      reviewedAt: null,
      reviewedByUid: null,
      inviteCodeId: null,
    });
    return res.status(201).json({ success: true, requestId: ref.id });
  } catch (err) {
    console.error("Setup request error:", err);
    return res.status(500).json({ error: "Could not submit your setup request." });
  }
});

app.post("/auth/request-otp", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const purpose = req.body?.purpose === "password_reset" ? "password_reset" : "signup";
  const inviteCode = String(req.body?.inviteCode || "").trim().toUpperCase();
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address." });
  }
  if (purpose === "signup" && !inviteCode) {
    return res.status(400).json({ error: "An invite code is required." });
  }

  try {
    if (purpose === "signup") {
      const inviteSnap = await db.collection("inviteCodes")
        .where("code", "==", inviteCode)
        .where("status", "==", "unused")
        .limit(1)
        .get();
      if (inviteSnap.empty || isExpiredTimestamp(inviteSnap.docs[0].data().expiresAt)) {
        return res.status(400).json({ error: "That invite code is invalid or has expired." });
      }
    } else {
      // Keep the response generic so this endpoint cannot be used to enumerate accounts.
      try {
        await firebaseAuth.getUserByEmail(email);
      } catch (_) {
        return res.json({ success: true, expiresInSeconds: EMAIL_OTP_TTL_MS / 1000 });
      }
    }

    const code = createOtp();
    const now = Date.now();
    const otpRef = db.doc(`emailOtps/${otpDocumentId(purpose, email)}`);
    await db.runTransaction(async (tx) => {
      const previous = await tx.get(otpRef);
      const record = previous.exists ? previous.data() : {};
      const sameWindow = now - toMillis(record.rateWindowStartedAt) < 15 * 60_000;
      if (sameWindow && (Number(record.requestCount || 0) >= 10 || Number(record.windowAttempts || 0) >= 20)) {
        throw Object.assign(new Error("Too many code requests or attempts. Please wait 15 minutes."), { statusCode: 429 });
      }
      tx.set(otpRef, {
      purpose,
      emailHash: hashValue(email),
      codeHash: hashValue(`${purpose}:${email}:${code}`),
      inviteCode: purpose === "signup" ? inviteCode : null,
      attempts: 0,
      expiresAt: new Date(now + EMAIL_OTP_TTL_MS),
      createdAt: FieldValue.serverTimestamp(),
      verifiedAt: null,
      verificationTokenHash: null,
      rateWindowStartedAt: sameWindow ? record.rateWindowStartedAt : new Date(now),
      requestCount: sameWindow ? Number(record.requestCount || 0) + 1 : 1,
      windowAttempts: sameWindow ? Number(record.windowAttempts || 0) : 0,
      });
    });
    await sendOtpEmail({ email, code, purpose });
    return res.json({ success: true, expiresInSeconds: EMAIL_OTP_TTL_MS / 1000 });
  } catch (err) {
    console.error("OTP request error:", err);
    return res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : "Could not send a verification code. Please try again." });
  }
});

app.post("/auth/verify-otp", rateLimit({ windowMs: 15 * 60_000, max: 20 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const purpose = req.body?.purpose === "password_reset" ? "password_reset" : "signup";
  const code = String(req.body?.code || "").replace(/\D/g, "");
  if (!/^\S+@\S+\.\S+$/.test(email) || code.length !== 6) {
    return res.status(400).json({ error: "Enter the six-digit code from your email." });
  }

  try {
    const otpRef = db.doc(`emailOtps/${otpDocumentId(purpose, email)}`);
    const verificationToken = crypto.randomBytes(32).toString("hex");
    const result = await db.runTransaction(async (tx) => {
      const snap = await tx.get(otpRef);
      const record = snap.exists ? snap.data() : null;
      if (!record || isExpiredTimestamp(record.expiresAt)) {
        throw Object.assign(new Error("That code has expired. Request a new one."), { statusCode: 400 });
      }
      if (Number(record.attempts || 0) >= EMAIL_OTP_MAX_ATTEMPTS || Number(record.windowAttempts || 0) >= 20) {
        throw Object.assign(new Error("Too many incorrect attempts. Request a new code."), { statusCode: 429 });
      }
      if (record.codeHash !== hashValue(`${purpose}:${email}:${code}`)) {
        tx.update(otpRef, { attempts: FieldValue.increment(1), windowAttempts: FieldValue.increment(1) });
        return { incorrect: true };
      }
      tx.update(otpRef, {
        codeHash: null,
        attempts: FieldValue.increment(1),
        windowAttempts: FieldValue.increment(1),
        verifiedAt: FieldValue.serverTimestamp(),
        verificationTokenHash: hashValue(verificationToken),
        verificationExpiresAt: new Date(Date.now() + EMAIL_OTP_TTL_MS),
      });
      return { incorrect: false };
    });
    if (result.incorrect) return res.status(400).json({ error: "That code is incorrect." });
    return res.json({ success: true, verificationToken });
  } catch (err) {
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not verify that code." });
  }
});

app.post("/auth/reset-password", rateLimit({ windowMs: 15 * 60_000, max: 10 }), async (req, res) => {
  const email = normalizeEmail(req.body?.email);
  const verificationToken = String(req.body?.verificationToken || "");
  const password = String(req.body?.password || "");
  if (!/^\S+@\S+\.\S+$/.test(email) || !verificationToken || password.length < 8) {
    return res.status(400).json({ error: "Use a verified code and a password with at least 8 characters." });
  }
  try {
    const otpRef = db.doc(`emailOtps/${otpDocumentId("password_reset", email)}`);
    await db.runTransaction(async (tx) => {
      const otpSnap = await tx.get(otpRef);
      const otp = otpSnap.exists ? otpSnap.data() : null;
      if (!otp || otp.verificationTokenHash !== hashValue(verificationToken) || isExpiredTimestamp(otp.verificationExpiresAt)) {
        throw Object.assign(new Error("Verify a new email code before resetting your password."), { statusCode: 403 });
      }
      tx.update(otpRef, { verificationTokenHash: null, usedAt: FieldValue.serverTimestamp() });
    });
    const user = await firebaseAuth.getUserByEmail(email);
    await firebaseAuth.updateUser(user.uid, { password });
    await firebaseAuth.revokeRefreshTokens(user.uid);
    await db.doc(`users/${user.uid}`).set({ authValidAfter: Math.floor(Date.now() / 1000) }, { merge: true });
    return res.json({ success: true });
  } catch (err) {
    console.error("Password reset error:", err);
    return res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : "Could not reset your password. Please try again." });
  }
});

app.post("/complete-signup", rateLimit({ windowMs: 15 * 60_000, max: 20 }), requireFirebaseUser, async (req, res) => {
  const {
    inviteCode,
    name,
    businessType,
    paymentMode,
    accentColor,
    tagline,
    description,
    logoUrl,
    logoPublicId,
    address,
    phone,
    contactEmail,
    instagram,
    twitter,
    verificationToken,
  } = req.body || {};

  const email = req.firebaseUser.email;
  const uid = req.firebaseUser.uid;
  const restaurantId = slugify(name);
  const selectedPaymentMode = normalizePaymentMode(paymentMode);
  const requestedBusinessType = businessType === "lounge" ? "lounge" : "restaurant";
  // Firestore rejects undefined values. Optional profile details are persisted as
  // empty strings until the venue adds them in Settings.
  const profileAddress = typeof address === "string" ? address.trim() : "";
  const profilePhone = typeof phone === "string" ? phone.trim() : "";
  const profileContactEmail = typeof contactEmail === "string" && contactEmail.trim()
    ? contactEmail.trim().toLowerCase()
    : email;
  const profileInstagram = typeof instagram === "string" ? instagram.trim() : "";
  const profileTwitter = typeof twitter === "string" ? twitter.trim() : "";
  const profileLogoUrl = typeof logoUrl === "string" ? logoUrl.trim() : "";
  const profileLogoPublicId = typeof logoPublicId === "string" ? logoPublicId.trim() : "";

  if (!inviteCode || !name || !restaurantId || !email) {
    return res
      .status(400)
      .json({ error: "Invite code, restaurant name, and email are required." });
  }
  try {
    const result = await db.runTransaction(async (tx) => {
      const userRef = db.doc(`users/${uid}`);
      const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
      const inviteQuery = db
        .collection("inviteCodes")
        .where("code", "==", String(inviteCode).trim().toUpperCase())
        .where("status", "==", "unused")
        .limit(1);

      const otpRef = db.doc(`emailOtps/${otpDocumentId("signup", email)}`);
      const [userSnap, profileSnap, inviteSnap, otpSnap] = await Promise.all([
        tx.get(userRef),
        tx.get(profileRef),
        tx.get(inviteQuery),
        tx.get(otpRef),
      ]);

      if (userSnap.exists) {
        const existing = userSnap.data();
        if (existing.restaurantId === restaurantId && profileSnap.data()?.ownerUid === uid &&
            (existing.emailVerifiedAt || req.firebaseUser.email_verified)) {
          return { restaurantId, alreadyCompleted: true };
        }
        throw Object.assign(
          new Error("This user already has a restaurant workspace."),
          { statusCode: 409 },
        );
      }
      if (profileSnap.exists) {
        throw Object.assign(
          new Error(
            "This restaurant URL is already taken. Please adjust the name.",
          ),
          { statusCode: 409 },
        );
      }
      if (inviteSnap.empty) {
        throw Object.assign(new Error("Invalid or already used invite code."), {
          statusCode: 400,
        });
      }

      const otp = otpSnap.exists ? otpSnap.data() : null;
      if (
        !verificationToken ||
        !otp ||
        otp.inviteCode !== String(inviteCode).trim().toUpperCase() ||
        otp.verificationTokenHash !== hashValue(verificationToken) ||
        isExpiredTimestamp(otp.verificationExpiresAt)
      ) {
        throw Object.assign(new Error("Verify your email before completing signup."), { statusCode: 403 });
      }

      const inviteDoc = inviteSnap.docs[0];
      const inviteData = inviteDoc.data();
      if (isExpiredTimestamp(inviteData.expiresAt)) {
        throw Object.assign(new Error("This invite code has expired."), {
          statusCode: 400,
        });
      }

      // Operational mode and commercial terms come from the approved invite,
      // not from browser-submitted signup data.
      const selectedBusinessType = inviteData.operatingMode === "lounge"
        ? "lounge"
        : requestedBusinessType;
      const planKind = inviteData.planKind === "custom" ? "custom" : "standard";
      const customMonthlyFee = Number(inviteData.monthlyFee);
      const monthlyFee = planKind === "custom" && Number.isFinite(customMonthlyFee) && customMonthlyFee > 0
        ? customMonthlyFee
        : DEFAULT_MONTHLY_FEES[selectedBusinessType];

      tx.set(userRef, {
        emailVerifiedAt: FieldValue.serverTimestamp(),
        restaurantId,
        email,
        role: "owner",
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.set(profileRef, {
        restaurantId,
        ownerUid: uid,
        name: String(name).trim(),
        email,
        businessType: selectedBusinessType,
        planKind,
        monthlyFee,
        accentColor: accentColor || "#fa5631",
        tagline: tagline || "",
        description: description || "",
        logoUrl: profileLogoUrl,
        logoPublicId: profileLogoPublicId,
        address: profileAddress,
        phone: profilePhone,
        contactEmail: profileContactEmail,
        instagram: profileInstagram,
        twitter: profileTwitter,
        paymentPreference: selectedPaymentMode,
        paymentMode: selectedPaymentMode,
        paymentModeUpdatedAt: FieldValue.serverTimestamp(),
        subscriptionStatus: "payment_pending",
        suspended: true,
        suspendedReason: "payment_pending",
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.update(inviteDoc.ref, {
        status: "used",
        usedBy: restaurantId,
        usedByUid: uid,
        usedAt: FieldValue.serverTimestamp(),
      });
      tx.update(otpRef, {
        verificationTokenHash: null,
        usedAt: FieldValue.serverTimestamp(),
      });

      return { restaurantId };
    });

    // The OTP proves control of this email, so mark the Firebase account verified.
    await firebaseAuth.updateUser(uid, { emailVerified: true });

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Complete signup error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Signup setup failed. Please try again.",
    });
  }
});

// POST /restore-restaurant-profile — recover the minimal profile document when
// a venue's parent/profile document was accidentally removed in Firestore.
// This intentionally does not recreate menu items, orders, or other deleted data.
app.post(
  "/restore-restaurant-profile",
  rateLimit({ windowMs: 15 * 60_000, max: 10 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "")
      .trim()
      .toLowerCase();
    const requestedName = String(req.body?.name || "").trim().slice(0, 100);

    if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
      return res.status(400).json({ error: "Enter a valid workspace ID." });
    }

    try {
      const uid = req.firebaseUser.uid;
      const superAdmin = await isSuperAdmin(uid);
      const result = await db.runTransaction(async (tx) => {
        const userRef = db.doc(`users/${uid}`);
        const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
        const restaurantRef = db.doc(`restaurants/${restaurantId}`);
        const [userSnap, profileSnap] = await Promise.all([
          tx.get(userRef),
          tx.get(profileRef),
        ]);

        if (!userSnap.exists) {
          throw Object.assign(new Error("Your owner account record could not be found."), {
            statusCode: 404,
          });
        }

        const userData = userSnap.data();
        const ownerCanRecover =
          userData.restaurantId === restaurantId &&
          (!userData.role || userData.role === "owner");
        if (!superAdmin && !ownerCanRecover) {
          throw Object.assign(
            new Error("Only the original owner can recover this workspace."),
            { statusCode: 403 },
          );
        }

        if (profileSnap.exists) {
          return { restored: false, restaurantId };
        }

        const name = requestedName || userData.restaurantName || restaurantId;
        const email = userData.email || req.firebaseUser.email || "";

        // Keep this profile deliberately minimal. Recovered workspaces remain active
        // unless a platform administrator explicitly suspends them.
        tx.set(profileRef, {
          restaurantId,
          ownerUid: uid,
          name,
          email,
          contactEmail: email,
          accentColor: "#fa5631",
          paymentMode: "at_table",
          paymentPreference: "at_table",
          suspended: false,
          recoveredAt: FieldValue.serverTimestamp(),
          recoveryVersion: 1,
        });
        tx.set(
          restaurantRef,
          {
            restoredParent: true,
            restoredAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );

        // Older owner records may not contain a role, which would otherwise
        // make Firestore rules reject every dashboard query after recovery.
        if (!userData.role) {
          tx.set(userRef, { role: "owner" }, { merge: true });
        }

        return { restored: true, restaurantId };
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      console.error("Restaurant profile recovery error:", err);
      return res.status(err.statusCode || 500).json({
        error: err.message || "The workspace profile could not be restored.",
      });
    }
  },
);

// POST /restore-legacy-workspace-data — copies the original single-tenant
// root collections into the current restaurant-scoped paths. The source data
// is intentionally retained and existing destination documents are skipped,
// making the operation safe to retry after a partial migration.
app.post(
  "/restore-legacy-workspace-data",
  rateLimit({ windowMs: 15 * 60_000, max: 5 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "")
      .trim()
      .toLowerCase();

    if (!/^[a-z0-9-]{2,80}$/.test(restaurantId)) {
      return res.status(400).json({ error: "Enter a valid workspace ID." });
    }

    try {
      const uid = req.firebaseUser.uid;
      const [superAdmin, userSnap, profileSnap] = await Promise.all([
        isSuperAdmin(uid),
        db.doc(`users/${uid}`).get(),
        db.doc(`restaurants/${restaurantId}/profile/info`).get(),
      ]);
      const userData = userSnap.exists ? userSnap.data() : {};
      const profileData = profileSnap.exists ? profileSnap.data() : {};
      const isOriginalOwner =
        userData.restaurantId === restaurantId &&
        (userData.role === "owner" || !userData.role) &&
        (!profileData.ownerUid || profileData.ownerUid === uid);

      if (!superAdmin && !isOriginalOwner) {
        return res.status(403).json({ error: "Only the workspace owner can recover this data." });
      }
      if (!profileSnap.exists) {
        return res.status(409).json({ error: "Restore the workspace profile before recovering its data." });
      }

      // Recovery is limited to explicitly owned source paths. Root records have
      // no tenant ownership and can only be migrated by a platform administrator.
      const relatedRestaurantIds = new Set([restaurantId]);
      const ownedProfiles = await db.collectionGroup("profile").where("ownerUid", "==", uid).get();
      for (const profile of ownedProfiles.docs) {
        const parts = profile.ref.path.split("/");
        if (parts[0] === "restaurants" && parts[2] === "profile" && parts[3] === "info") {
          relatedRestaurantIds.add(parts[1]);
        }
      }
      const sources = await Promise.all([...relatedRestaurantIds].map(async (sourceId) => {
        const [menu, orders] = await Promise.all([
          db.collection(`restaurants/${sourceId}/menu`).get(),
          db.collection(`restaurants/${sourceId}/orders`).get(),
        ]);
        return { menu, orders, sourceId };
      }));
      const [legacyMenu, legacyOrders] = superAdmin
        ? await Promise.all([db.collection("menu").get(), db.collection("orders").get()])
        : [{ docs: [] }, { docs: [] }];
      const current = sources.find((source) => source.sourceId === restaurantId);
      const currentMenu = current.menu;
      const currentOrders = current.orders;
      const legacyMenuRecords = [...legacyMenu.docs, ...sources.flatMap((source) => source.menu.docs)];
      const legacyOrderRecords = [...legacyOrders.docs, ...sources.flatMap((source) => source.orders.docs)];
      if (!legacyMenuRecords.length && !legacyOrderRecords.length) {
        return res.status(404).json({ error: "No owned historical records were found. Contact support for legacy migration." });
      }

      const currentMenuIds = new Set(currentMenu.docs.map((snapshot) => snapshot.id));
      const currentOrderIds = new Set(currentOrders.docs.map((snapshot) => snapshot.id));
      const pendingWrites = [];

      for (const snapshot of legacyMenuRecords) {
        if (currentMenuIds.has(snapshot.id)) continue;
        pendingWrites.push({
          ref: db.doc(`restaurants/${restaurantId}/menu/${snapshot.id}`),
          data: snapshot.data(),
          type: "menu",
        });
      }
      for (const snapshot of legacyOrderRecords) {
        if (currentOrderIds.has(snapshot.id)) continue;
        pendingWrites.push({
          ref: db.doc(`restaurants/${restaurantId}/orders/${snapshot.id}`),
          data: snapshot.data(),
          type: "orders",
        });
      }

      let menuCopied = 0;
      let ordersCopied = 0;
      for (let offset = 0; offset < pendingWrites.length; offset += 400) {
        const batch = db.batch();
        const chunk = pendingWrites.slice(offset, offset + 400);
        for (const write of chunk) {
          batch.set(write.ref, write.data);
          if (write.type === "menu") menuCopied += 1;
          if (write.type === "orders") ordersCopied += 1;
        }
        await batch.commit();
      }

      await db.doc(`restaurants/${restaurantId}/profile/info`).set(
        {
          legacyDataRecoveredAt: FieldValue.serverTimestamp(),
          legacyMenuRecovered: legacyMenuRecords.length,
          legacyOrdersRecovered: legacyOrderRecords.length,
        },
        { merge: true },
      );

      return res.json({
        success: true,
        restaurantId,
        menuCopied,
        ordersCopied,
        menuFound: legacyMenuRecords.length,
        ordersFound: legacyOrderRecords.length,
        menuAlreadyPresent: currentMenu.size,
        ordersAlreadyPresent: currentOrders.size,
      });
    } catch (err) {
      console.error("Legacy workspace data recovery error:", err);
      return res.status(500).json({
        error: "The existing menu and transactions could not be recovered right now.",
      });
    }
  },
);

// POST /resend-verification — re-send the branded verification email to the signed-in user.
app.post(
  "/resend-verification",
  rateLimit({ windowMs: 60_000, max: 5 }),
  requireFirebaseUser,
  async (req, res) => {
    const email = req.firebaseUser.email;
    if (!email) return res.status(400).json({ error: "No email on this account." });
    try {
      const verifyLink = await genVerifyLink(email);
      await sendWelcomeEmail(email, req.firebaseUser.name, verifyLink);
      return res.json({ success: true });
    } catch (err) {
      console.error("Resend verification failed:", err);
      return res.status(500).json({ error: "Could not resend verification email." });
    }
  },
);

// GET /banks — fetch supported Nigerian banks from Paystack (always up-to-date codes)
app.get("/banks", async (req, res) => {
  try {
    const r = await providerFetch(
      "https://api.paystack.co/bank?country=nigeria&type=nuban&currency=NGN&per_page=100",
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await r.json();
    if (data.status) {
      const banks = data.data.map((b) => ({ name: b.name, code: b.code }));
      return res.json(banks);
    }
    res.status(500).json({ error: "Failed to fetch banks" });
  } catch (err) {
    console.error("Banks fetch error:", err);
    res.status(500).json({ error: "Request failed" });
  }
});

// GET /resolve-account — verify a merchant's bank account number before creating subaccount (management only)
app.get("/resolve-account", rateLimit({ windowMs: 60_000, max: 30 }), requireFirebaseUser, async (req, res) => {
  const { account_number, bank_code, restaurantId } = req.query;
  const cleanedRestaurantId = String(restaurantId || "").trim();
  if (!account_number || !bank_code) {
    return res
      .status(400)
      .json({ error: "account_number and bank_code are required" });
  }
  if (!cleanedRestaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }
  if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const r = await providerFetch(
      `https://api.paystack.co/bank/resolve?account_number=${encodeURIComponent(account_number)}&bank_code=${encodeURIComponent(bank_code)}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await r.json();
    if (data.status) {
      return res.json({ accountName: data.data.account_name });
    }
    return res
      .status(400)
      .json({ error: data.message || "Could not resolve account" });
  } catch (err) {
    console.error("Resolve account error:", err);
    return res.status(500).json({ error: "Request failed" });
  }
});

// POST /create-subaccount — register merchant bank account as a Paystack subaccount (management only)
app.post("/create-subaccount", rateLimit({ windowMs: 60_000, max: 10 }), requireFirebaseUser, async (req, res) => {
  const { businessName, bankCode, accountNumber, restaurantId } = req.body;
  const cleanedRestaurantId = String(restaurantId || "").trim();
  if (!businessName || !bankCode || !accountNumber) {
    return res.status(400).json({
      error: "businessName, bankCode, and accountNumber are required",
    });
  }
  if (!cleanedRestaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }
  if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const r = await providerFetch("https://api.paystack.co/subaccount", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        business_name: businessName,
        settlement_bank: bankCode,
        account_number: accountNumber,
        percentage_charge: 0,
      }),
    });
    const data = await r.json();
    if (data.status) {
      return res.json({ subaccountCode: data.data.subaccount_code });
    }
    return res
      .status(400)
      .json({ error: data.message || "Subaccount creation failed" });
  } catch (err) {
    console.error("Create subaccount error:", err);
    return res.status(500).json({ error: "Request failed" });
  }
});

// POST /subscription-checkout — creates the first Paystack charge for a Servrr
// subscription. The attached Paystack plan creates subsequent automatic renewals.
app.post("/subscription-checkout", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const requestedCycle = normalizeSubscriptionCycle(req.body?.billingCycle);
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required." });
  try {
    if (!(await userCanManageSubscription(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant." });
    }
    const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
    const profileSnap = await profileRef.get();
    if (!profileSnap.exists) return res.status(404).json({ error: "Restaurant profile not found." });
    const profile = profileSnap.data();
    if (profile.planKind === "custom") {
      return res.status(409).json({ error: "Your Custom plan is activated by the Servrr team. Please contact support." });
    }
    if (profile.paystackSubscriptionCode && ["active", "non_renewing"].includes(profile.subscriptionStatus)) {
      return res.status(409).json({ error: "Automatic billing is already active. Use Manage billing to update or cancel it." });
    }
    const config = getSubscriptionConfig(profile.businessType, requestedCycle);
    if (!config.planCode) {
      return res.status(503).json({ error: "Subscription billing is not configured yet. Please contact support." });
    }
    if (!process.env.PAYSTACK_SECRET_KEY) {
      return res.status(503).json({ error: "Subscription billing is not configured yet. Please contact support." });
    }
    const planResponse = await providerFetch(`https://api.paystack.co/plan/${encodeURIComponent(config.planCode)}`, {
      headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
    });
    const planPayload = await planResponse.json();
    if (!planResponse.ok || !planPayload.status || !planMatchesCheckout(planPayload.data, config)) {
      return res.status(503).json({ error: "The billing plan does not match the displayed price. Please contact support." });
    }
    if (profile.pendingSubscriptionReference && profile.pendingSubscriptionCycle === requestedCycle) {
      const pendingSnap = await db.doc(`subscriptionCheckouts/${profile.pendingSubscriptionReference}`).get();
      const pending = pendingSnap.data();
      const ageMs = Date.now() - (pending?.createdAt?.toDate?.()?.getTime() || 0);
      if (pendingSnap.exists && pending?.status === "initialized" && pending?.authorizationUrl &&
          pending.planCode === config.planCode && pending.amountKobo === config.amountNaira * 100 &&
          ageMs >= 0 && ageMs < 15 * 60 * 1000) {
        return res.json({
          authorizationUrl: pending.authorizationUrl,
          reference: profile.pendingSubscriptionReference,
        });
      }
    }
    const billingEmail = normalizeEmail(req.firebaseUser.email || profile.email);
    if (!billingEmail) return res.status(400).json({ error: "A billing email is required." });
    const response = await providerFetch("https://api.paystack.co/transaction/initialize", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        email: billingEmail,
        amount: config.amountNaira * 100,
        plan: config.planCode,
        channels: ["card"],
        callback_url: `${APP_URL}/${encodeURIComponent(restaurantId)}/admin?subscription=complete`,
        metadata: {
          restaurantId,
          purpose: "servrr_subscription",
          businessType: config.businessType,
          billingCycle: config.billingCycle,
          planCode: config.planCode,
        },
      }),
    });
    const payload = await response.json();
    const checkoutReference = payload.data?.reference;
    if (!response.ok || !payload.status || !payload.data?.authorization_url || !checkoutReference) {
      return res.status(502).json({ error: payload.message || "Could not start subscription checkout." });
    }
    const checkout = {
      reference: checkoutReference,
      restaurantId,
      billingEmail,
      businessType: config.businessType,
      billingCycle: config.billingCycle,
      planCode: config.planCode,
      amountNaira: config.amountNaira,
      amountKobo: config.amountNaira * 100,
      authorizationUrl: payload.data.authorization_url,
      accessCode: payload.data.access_code || null,
      status: "initialized",
      createdAt: FieldValue.serverTimestamp(),
    };
    const batch = db.batch();
    batch.set(db.doc(`subscriptionCheckouts/${checkoutReference}`), checkout);
    batch.set(
      db.doc(`subscriptionIntents/${subscriptionIntentId(billingEmail, config.planCode)}`),
      checkout,
      { merge: true },
    );
    batch.set(profileRef, {
      pendingSubscriptionReference: checkoutReference,
      pendingSubscriptionCycle: config.billingCycle,
      pendingSubscriptionPlanCode: config.planCode,
      updatedAt: FieldValue.serverTimestamp(),
    }, { merge: true });
    await batch.commit();
    return res.json({
      authorizationUrl: payload.data.authorization_url,
      reference: checkoutReference,
    });
  } catch (err) {
    console.error("Subscription checkout error:", err);
    return res.status(500).json({ error: "Could not start subscription checkout." });
  }
});

app.post("/subscription-manage-link", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required." });
  try {
    if (!(await userCanManageSubscription(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant." });
    }
    const profileSnap = await db.doc(`restaurants/${restaurantId}/profile/info`).get();
    const subscriptionCode = profileSnap.data()?.paystackSubscriptionCode;
    if (!subscriptionCode) {
      return res.status(404).json({ error: "No automatic subscription is connected yet." });
    }
    const response = await providerFetch(
      `https://api.paystack.co/subscription/${encodeURIComponent(subscriptionCode)}/manage/link`,
      { headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` } },
    );
    const payload = await response.json();
    if (!response.ok || !payload.status || !payload.data?.link) {
      return res.status(502).json({ error: payload.message || "Could not open subscription management." });
    }
    return res.json({ url: payload.data.link });
  } catch (err) {
    console.error("Subscription management link error:", err);
    return res.status(500).json({ error: "Could not open subscription management." });
  }
});

app.post("/verify-payment", async (req, res) => {
  const { reference } = req.body;
  if (!reference || typeof reference !== "string") {
    return res.status(400).json({ success: false, error: "Invalid reference" });
  }
  try {
    const paystackRes = await providerFetch(
      `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    const data = await paystackRes.json();
    if (data.data?.status === "success") {
      return res.json({ success: true, amount: data.data.amount });
    }
    return res
      .status(400)
      .json({ success: false, error: "Payment not successful" });
  } catch (err) {
    console.error("Paystack verify error:", err);
    return res
      .status(500)
      .json({ success: false, error: "Verification request failed" });
  }
});

const resolveSubscriptionContext = async (data, reference, allowEmailFallback = false) => {
  const planCode = planCodeFromPayload(data);
  const subscriptionCode = subscriptionCodeFromPayload(data);
  const customerCode = customerCodeFromPayload(data);

  if (reference) {
    const checkoutSnap = await db.doc(`subscriptionCheckouts/${reference}`).get();
    if (checkoutSnap.exists) return { ...checkoutSnap.data(), subscriptionCode, customerCode };
  }
  if (subscriptionCode) {
    const subscriptionSnap = await db.doc(`paystackSubscriptions/${subscriptionCode}`).get();
    if (subscriptionSnap.exists) return { ...subscriptionSnap.data(), subscriptionCode, customerCode, planCode: planCode || subscriptionSnap.data().planCode };
  }
  if (customerCode && planCode) {
    const customerPlanSnap = await db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, planCode)}`).get();
    if (customerPlanSnap.exists) return { ...customerPlanSnap.data(), subscriptionCode, customerCode, planCode };
  }
  const customerEmail = normalizeEmail(data?.customer?.email);
  if (allowEmailFallback && customerEmail && planCode) {
    const intentSnap = await db.doc(`subscriptionIntents/${subscriptionIntentId(customerEmail, planCode)}`).get();
    if (intentSnap.exists) return { ...intentSnap.data(), subscriptionCode, customerCode, planCode };
  }
  return null;
};

const recordSuccessfulSubscriptionPayment = async (data, eventName) => {
  const transaction = data?.transaction && typeof data.transaction === "object"
    ? data.transaction
    : data;
  const reference = String(transaction?.reference || data?.reference || "").trim();
  if (!reference) return false;

  const context = await resolveSubscriptionContext(data, reference) ||
    await resolveSubscriptionContext(transaction, reference);
  if (!context?.restaurantId) {
    if (subscriptionCodeFromPayload(data) || data?.metadata?.purpose === "servrr_subscription") {
      throw new Error(`Subscription payment ${reference} has no workspace mapping.`);
    }
    return false;
  }

  const config = getSubscriptionConfig(context.businessType, context.billingCycle);
  const receivedPlanCode = planCodeFromPayload(data) || planCodeFromPayload(transaction) || context.planCode;
  const amountKobo = Number(transaction?.amount ?? data?.amount);
  const currency = String(transaction?.currency || data?.currency || "NGN").toUpperCase();
  if (!config.planCode || receivedPlanCode !== config.planCode) {
    throw new Error(`Subscription plan mismatch for ${context.restaurantId}.`);
  }
  if (currency !== "NGN" || amountKobo !== config.amountNaira * 100) {
    throw new Error(`Subscription amount mismatch for ${context.restaurantId}.`);
  }

  const profileRef = db.doc(`restaurants/${context.restaurantId}/profile/info`);
  const processedRef = db.doc(`subscriptionPayments/${hashValue(reference)}`);
  const billingRef = db.doc(`restaurants/${context.restaurantId}/billing/${hashValue(reference)}`);
  const subscriptionCode = subscriptionCodeFromPayload(data) || context.subscriptionCode || "";
  const customerCode = customerCodeFromPayload(data) || customerCodeFromPayload(transaction) || context.customerCode || "";
  const nextPaymentValue = data?.subscription?.next_payment_date || data?.next_payment_date;

  await db.runTransaction(async (tx) => {
    const [processedSnap, profileSnap] = await Promise.all([
      tx.get(processedRef),
      tx.get(profileRef),
    ]);
    if (processedSnap.exists) return;
    if (!profileSnap.exists) throw new Error(`Workspace ${context.restaurantId} not found.`);

    const profile = profileSnap.data();
    const now = new Date();
    const currentUntil = profile.subscriptionPaidUntil?.toDate?.() || null;
    const base = currentUntil && currentUntil > now ? currentUntil : now;
    const eventNextPayment = nextPaymentValue ? new Date(nextPaymentValue) : null;
    const paidUntil = eventNextPayment && Number.isFinite(eventNextPayment.getTime()) && eventNextPayment > now
      ? eventNextPayment
      : addSubscriptionPeriod(base, config.billingCycle);
    const clearsBillingSuspension = !profile.suspended || [
      "payment_pending",
      "subscription_failed",
      "subscription_lapsed",
    ].includes(profile.suspendedReason);

    tx.set(profileRef, {
      businessType: config.businessType,
      billingCycle: config.billingCycle,
      monthlyFee: SUBSCRIPTION_PRICING[config.businessType].monthly,
      billingAmountPaid: config.amountNaira,
      subscriptionStatus: "active",
      subscriptionPaidUntil: paidUntil,
      subscriptionAutoRenew: true,
      subscriptionPlanCode: config.planCode,
      paystackSubscriptionCode: subscriptionCode || profile.paystackSubscriptionCode || null,
      paystackCustomerCode: customerCode || profile.paystackCustomerCode || null,
      lastSubscriptionPaymentAt: FieldValue.serverTimestamp(),
      lastSubscriptionReference: reference,
      pendingSubscriptionReference: FieldValue.delete(),
      pendingSubscriptionCycle: FieldValue.delete(),
      pendingSubscriptionPlanCode: FieldValue.delete(),
      ...(clearsBillingSuspension ? { suspended: false, suspendedReason: null } : {}),
    }, { merge: true });
    tx.set(billingRef, {
      date: FieldValue.serverTimestamp(),
      type: config.businessType,
      planKind: profile.planKind || "standard",
      cycle: config.billingCycle,
      amount: config.amountNaira,
      status: "paid",
      reference,
      source: "paystack_subscription",
      event: eventName,
    });
    tx.set(processedRef, {
      reference,
      restaurantId: context.restaurantId,
      planCode: config.planCode,
      amountKobo,
      event: eventName,
      processedAt: FieldValue.serverTimestamp(),
    });
    if (subscriptionCode) {
      tx.set(db.doc(`paystackSubscriptions/${subscriptionCode}`), {
        restaurantId: context.restaurantId,
        businessType: config.businessType,
        billingCycle: config.billingCycle,
        planCode: config.planCode,
        customerCode: customerCode || null,
        subscriptionCode,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
    if (customerCode) {
      tx.set(db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, config.planCode)}`), {
        restaurantId: context.restaurantId,
        businessType: config.businessType,
        billingCycle: config.billingCycle,
        planCode: config.planCode,
        customerCode,
        subscriptionCode: subscriptionCode || null,
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
  });

  if (context.reference === reference) {
    await db.doc(`subscriptionCheckouts/${reference}`).set({
      status: "paid",
      paidAt: FieldValue.serverTimestamp(),
    }, { merge: true });
  }
  return true;
};

app.post("/paystack-webhook", async (req, res) => {
  const signature = String(req.headers["x-paystack-signature"] || "");
  const secret = process.env.PAYSTACK_SECRET_KEY || "";
  const hash = crypto.createHmac("sha512", secret).update(req.rawBody || Buffer.from("")).digest("hex");
  const signatureMatches = signature.length === hash.length &&
    crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(hash));
  if (!secret || !signatureMatches) return res.status(401).send("Invalid signature");

  const event = req.body || {};
  const data = event.data || {};
  const eventName = String(event.event || "");
  const transaction = data?.transaction && typeof data.transaction === "object" ? data.transaction : data;
  const reference = String(transaction?.reference || data?.reference || "").trim();

  try {
    if (isSuccessfulSubscriptionCharge(eventName, data)) {
      await recordSuccessfulSubscriptionPayment(data, eventName);
    }

    if (eventName === "subscription.create") {
      const context = await resolveSubscriptionContext(data, reference, true);
      const subscriptionCode = subscriptionCodeFromPayload(data);
      const planCode = planCodeFromPayload(data) || context?.planCode;
      const customerCode = customerCodeFromPayload(data) || context?.customerCode;
      if (context?.restaurantId && subscriptionCode && planCode === context.planCode) {
        const businessType = normalizeSubscriptionType(context.businessType);
        const billingCycle = normalizeSubscriptionCycle(context.billingCycle);
        const batch = db.batch();
        batch.set(db.doc(`paystackSubscriptions/${subscriptionCode}`), {
          restaurantId: context.restaurantId,
          businessType,
          billingCycle,
          subscriptionCode,
          planCode,
          customerCode: customerCode || null,
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
        batch.set(db.doc(`restaurants/${context.restaurantId}/profile/info`), {
          paystackSubscriptionCode: subscriptionCode,
          paystackCustomerCode: customerCode || null,
          subscriptionPlanCode: planCode,
          subscriptionNextPaymentAt: data.next_payment_date ? new Date(data.next_payment_date) : null,
        }, { merge: true });
        if (customerCode) {
          batch.set(db.doc(`paystackCustomerPlans/${customerPlanId(customerCode, planCode)}`), {
            restaurantId: context.restaurantId,
            businessType,
            billingCycle,
            subscriptionCode,
            planCode,
            customerCode,
            updatedAt: FieldValue.serverTimestamp(),
          }, { merge: true });
        }
        await batch.commit();
      }
    }

    if (["subscription.not_renew", "subscription.disable", "invoice.payment_failed"].includes(eventName)) {
      const context = await resolveSubscriptionContext(data, reference);
      if (context?.restaurantId) {
        const status = eventName === "invoice.payment_failed"
          ? "past_due"
          : eventName === "subscription.not_renew" ? "non_renewing"
            : data.status === "complete" ? "completed" : "cancelled";
        await db.doc(`restaurants/${context.restaurantId}/profile/info`).set({
          subscriptionStatus: status,
          ...(eventName !== "invoice.payment_failed" ? { subscriptionAutoRenew: false } : {}),
          subscriptionPaymentFailedAt: eventName === "invoice.payment_failed" ? FieldValue.serverTimestamp() : null,
          subscriptionUpdatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }
    }

    if (reference) {
      const metadata = transaction.metadata || data.metadata || {};
      await db.doc(`paymentReferences/${reference}`).set({
        reference,
        event: eventName || null,
        status: transaction.status || data.status || null,
        amount: Number(transaction.amount ?? data.amount ?? 0),
        currency: transaction.currency || data.currency || null,
        restaurantId: metadata.restaurantId || null,
        table: metadata.table || null,
        customerName: metadata.customerName || null,
        paidAt: transaction.paid_at ? new Date(transaction.paid_at) : null,
        raw: data,
        webhookReceivedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    }
  } catch (err) {
    console.error("Paystack webhook persistence error:", err);
    return res.sendStatus(500);
  }

  return res.sendStatus(200);
});

// GET /table-token — mint (or fetch) the permanent per-table QR secret (staff only)
app.get("/table-token", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const table = String(req.query.table || "").trim();
  if (!restaurantId || !table) {
    return res.status(400).json({ error: "restaurantId and table are required" });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const token = await db.runTransaction(async (tx) => {
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
      const tableSnap = await tx.get(tableRef);
      if (tableSnap.exists && tableSnap.data().token) {
        return tableSnap.data().token;
      }

      const newToken = crypto.randomBytes(16).toString("hex");
      tx.set(
        tableRef,
        {
          token: newToken,
          currentSessionId: tableSnap.exists ? tableSnap.data().currentSessionId ?? null : null,
          createdAt: tableSnap.exists ? tableSnap.data().createdAt : FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true },
      );
      return newToken;
    });

    return res.json({ token });
  } catch (err) {
    console.error("Table token error:", err);
    return res.status(500).json({ error: "Could not fetch table token." });
  }
});

// GET /table-tokens?restaurantId=&count= — mint/fetch tokens for tables 1..count in ONE
// request (the per-table route above does a round trip per table, which is painfully slow
// from high-latency connections). Staff only.
app.get("/table-tokens", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  const count = Math.min(100, Math.max(1, Number(req.query.count) || 0));
  if (!restaurantId || !count) {
    return res.status(400).json({ error: "restaurantId and count are required" });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const refs = Array.from({ length: count }, (_, index) => db.doc(`restaurants/${restaurantId}/tables/${index + 1}`));
    const tokens = await db.runTransaction(async (tx) => {
      const snaps = await Promise.all(refs.map((ref) => tx.get(ref)));
      const result = {};
      snaps.forEach((snap, index) => {
        const token = snap.data()?.token || crypto.randomBytes(16).toString("hex");
        result[index + 1] = token;
        if (!snap.data()?.token) tx.set(snap.ref, {
          token, currentSessionId: snap.data()?.currentSessionId || null,
          createdAt: snap.data()?.createdAt || FieldValue.serverTimestamp(), updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      });
      return result;
    });

    return res.json({ tokens });
  } catch (err) {
    console.error("Table tokens error:", err);
    return res.status(500).json({ error: "Could not fetch table tokens." });
  }
});

// POST /open-table-session — validate the permanent QR token and open/rejoin a session (public, QR scan)
app.post("/open-table-session", rateLimit({ windowMs: 60_000, max: 60 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const table = String(req.body?.table || "").trim();
  const token = String(req.body?.token || "").trim();
  if (!restaurantId || !table || !token) {
    return res.status(400).json({ error: "restaurantId, table, and token are required" });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const accessToken = createSessionAccessToken();
      const accessTokenHash = hashSessionAccessToken(accessToken);
      const accessTokenExpiresAt = Date.now() + 60 * 60 * 1000;
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
      const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
      const [tableSnap, profileSnap] = await Promise.all([
        tx.get(tableRef),
        tx.get(profileRef),
      ]);
      if (!tableSnap.exists || tableSnap.data().token !== token) {
        throw Object.assign(new Error("Invalid table QR code."), { statusCode: 403 });
      }

      // Block ordering at suspended or lapsed-subscription venues.
      if (!isVenueActive(profileSnap.data())) {
        throw Object.assign(
          new Error("This restaurant isn't accepting orders right now."),
          { statusCode: 403 },
        );
      }

      const currentSessionId = tableSnap.data().currentSessionId || null;
      if (currentSessionId) {
        const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${currentSessionId}`);
        const sessionSnap = await tx.get(sessionRef);
        if (sessionSnap.exists && OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
          const session = sessionSnap.data();
          const lastActivity = toMillis(session.updatedAt || session.openedAt);
          const orderSnaps = await Promise.all((session.orderIds || []).map((id) =>
            tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`))));
          // Missing financial history is never evidence that a visit is empty.
          const hasObligations = orderSnaps.some((snap) => !snap.exists ||
            (snap.data().status !== "cancelled" &&
             (snap.data().paymentStatus !== "paid" || !["served", "completed"].includes(snap.data().status))));
          const idle = lastActivity && Date.now() - lastActivity > SESSION_IDLE_MS;
          if (!idle || hasObligations) {
            const accessTokens = (session.accessTokens || []).filter((entry) => Number(entry.expiresAt) > Date.now());
            accessTokens.push({ hash: accessTokenHash, expiresAt: accessTokenExpiresAt });
            tx.update(sessionRef, { accessTokens: accessTokens.slice(-100) });
            return { sessionId: currentSessionId, accessToken };
          }
          tx.update(sessionRef, { status: "expired", expiredAt: FieldValue.serverTimestamp(), expiredReason: "empty_idle_visit", waiterCalledAt: null });
        }
      }

      if (profileSnap.data()?.servicePaused) throw Object.assign(new Error("This venue has paused new ordering. Ask staff for help."), { statusCode: 403 });
      const paymentMode = normalizePaymentMode(profileSnap.data()?.paymentMode);

      const newSessionRef = db
        .collection(`restaurants/${restaurantId}/tableSessions`)
        .doc();
      tx.set(newSessionRef, {
        table,
        status: "open",
        openedAt: FieldValue.serverTimestamp(),
        billRequestedAt: null,
        closedAt: null,
        totalBill: 0,
        orderIds: [],
        checks: {},
        accessTokens: [{ hash: accessTokenHash, expiresAt: accessTokenExpiresAt }],
        paymentMode,
        paidVia: null,
        closedByUid: null,
      });
      tx.set(
        tableRef,
        { currentSessionId: newSessionRef.id, updatedAt: FieldValue.serverTimestamp() },
        { merge: true },
      );
      return { sessionId: newSessionRef.id, accessToken };
    });

    return res.json(result);
  } catch (err) {
    console.error("Open table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not open table session.",
    });
  }
});

// POST /place-order — server-authoritative pay-at-table order creation.
// The client supplies the cart, but the server owns prices, totals, and the
// atomic append to the table session.
app.post("/guest-session", rateLimit({ windowMs: 60_000, max: 1200 }), async (req, res) => {
  const { restaurantId, sessionId, checkId, checkSecret, accessToken, orderId } = req.body || {};
  res.setHeader("Cache-Control", "no-store");
  if (!/^[a-z0-9-]{2,80}$/.test(String(restaurantId || "")) ||
      !/^[a-zA-Z0-9_-]{1,120}$/.test(String(sessionId || ""))) {
    return res.status(400).json({ error: "A valid visit is required." });
  }
  try {
    const sessionSnap = await db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).get();
    if (!sessionSnap.exists || !canReadGuestCheck(sessionSnap.data(), checkId, checkSecret, accessToken)) {
      return res.status(403).json({ error: "Open this bill in the browser you ordered from, or ask staff for help." });
    }
    const session = sessionSnap.data();
    const orderSnap = await db.collection(`restaurants/${restaurantId}/orders`)
      .where("sessionId", "==", sessionId).where("checkId", "==", checkId).get();
    const orders = orderSnap.docs.map((snap) => ({ id: snap.id, ...snap.data() }));
    const order = orderId ? orders.find((entry) => entry.id === orderId) : null;
    if (orderId && !order) return res.status(404).json({ error: "This order is not part of your bill." });
    const view = (currentSession, currentOrders) => toWire({
      session: guestSessionView(sessionId, currentSession, checkId, currentOrders),
      orders: currentOrders,
      order: orderId ? currentOrders.find((entry) => entry.id === orderId) : null,
      complete: ["paid", "closed"].includes(currentSession.status) && currentOrders.every((entry) =>
        entry.status === "cancelled" || (entry.paymentStatus === "paid" && ["served", "completed"].includes(entry.status))),
    });
    if (!String(req.headers.accept || "").includes("text/event-stream")) return res.json(view(session, orders));
    res.setHeader("Content-Type", "text/event-stream");
    res.setHeader("Cache-Control", "no-store, no-transform");
    res.setHeader("Connection", "keep-alive");
    res.flushHeaders();
    let currentSession = session;
    let currentOrders = orders;
    let stopped = false;
    const listeners = [];
    const heartbeat = setInterval(() => { if (!stopped) res.write(": keepalive\n\n"); }, 25000);
    const cleanup = () => { stopped = true; clearInterval(heartbeat); listeners.forEach((unsubscribe) => unsubscribe()); };
    res.on("close", cleanup);
    const fail = (message, status = 503) => {
      if (!stopped) { res.write(`data: ${JSON.stringify({ error: message, status })}\n\n`); res.end(); cleanup(); }
    };
    const send = () => {
      if (stopped) return;
      if (!canReadGuestCheck(currentSession, checkId, checkSecret, accessToken)) return fail("This bill is no longer available to this browser.", 403);
      if (orderId && !currentOrders.some((entry) => entry.id === orderId)) return fail("This order is no longer part of your bill.", 404);
      const payload = view(currentSession, currentOrders);
      res.write(`data: ${JSON.stringify(payload)}\n\n`);
      if (payload.complete) { res.end(); cleanup(); }
    };
    send();
    if (stopped) return undefined;
    listeners.push(db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).onSnapshot((snap) => {
      if (!snap.exists) return fail("This visit is no longer available.", 404);
      currentSession = snap.data(); send();
    }, () => fail("Updates are temporarily unavailable. Reconnecting…")));
    listeners.push(db.collection(`restaurants/${restaurantId}/orders`)
      .where("sessionId", "==", sessionId).where("checkId", "==", checkId).onSnapshot((snap) => {
        currentOrders = snap.docs.map((entry) => ({ id: entry.id, ...entry.data() })); send();
      }, () => fail("Updates are temporarily unavailable. Reconnecting…")));
    return undefined;
  } catch (err) {
    console.error("Guest visit read failed:", err);
    return res.status(500).json({ error: "Could not update your visit. Please try again." });
  }
});

app.post("/place-order", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const customerName = String(req.body?.customerName || "").trim().slice(0, 120);
  const email = String(req.body?.email || "").trim().slice(0, 160);
  const table = String(req.body?.table || "").trim();
  const allergies = String(req.body?.allergies || "").trim().slice(0, 500);
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  const requestId = String(req.body?.requestId || "").trim();
  const requestedCheckId = String(req.body?.checkId || "");
  const checkSecret = String(req.body?.checkSecret || "");

  if (!restaurantId || !sessionId || !accessToken || !customerName || !table ||
      !/^[a-zA-Z0-9_-]{12,120}$/.test(requestId) ||
      !validCheckId(requestedCheckId) || !validCheckSecret(checkSecret)) {
    return res.status(400).json({ error: "A valid table session, name, and table are required." });
  }
  if (!validateOrderItems(items)) {
    return res.status(400).json({ error: "Your order contains invalid items." });
  }

  try {
    const fingerprint = hashValue(JSON.stringify({ sessionId, checkId: requestedCheckId, customerName, email, table, allergies,
      items: items.map((item) => ({ id: item.id || null, name: item.name, qty: Number(item.qty) })) }));
    const result = await db.runTransaction(async (tx) => {
      const requestRef = db.doc(`restaurants/${restaurantId}/guestOrderRequests/${requestedCheckId}_${requestId}`);
      const existing = await tx.get(requestRef);
      if (existing.exists) {
        const prior = existing.data();
        if (prior.secretHash !== hashCheckSecret(checkSecret) || prior.sessionId !== sessionId) {
          throw Object.assign(new Error("This submission belongs to another visit."), { statusCode: 403 });
        }
        if (prior.fingerprint !== fingerprint) {
          throw Object.assign(new Error("The previous selection was already submitted. Check your bill before changing it."), { statusCode: 409 });
        }
        return { orderId: prior.orderId, total: prior.total, duplicate: true };
      }
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      const profileSnap = await tx.get(db.doc(`restaurants/${restaurantId}/profile/info`));
      if (!isVenueAcceptingOrders(profileSnap.data())) {
        throw Object.assign(new Error("This venue is not accepting orders right now."), { statusCode: 403 });
      }
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.table !== table) {
        throw Object.assign(new Error("Your table session has expired. Please scan the QR code again."), { statusCode: 403 });
      }
      if (session.status !== "open") {
        throw Object.assign(new Error("This table is no longer accepting orders."), { statusCode: 409 });
      }
      if (checkState(session, requestedCheckId).status !== "open") {
        throw Object.assign(new Error("This check has requested payment. Ask staff to reopen it or start a new visit."), { statusCode: 409 });
      }
      if (!hasCheckAccess(session, requestedCheckId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }

      const verifiedItems = await verifiedMenuItems(tx, db, restaurantId, items);
      const total = calculateItemsTotal(verifiedItems);
      const orderRef = db.collection(`restaurants/${restaurantId}/orders`).doc();
      tx.set(orderRef, {
        customerName,
        email,
        table,
        allergies,
        items: verifiedItems,
        total,
        status: "pending",
        createdAt: FieldValue.serverTimestamp(),
        sessionId,
        checkId: requestedCheckId,
      });
      tx.update(sessionRef, {
        orderIds: FieldValue.arrayUnion(orderRef.id),
        totalBill: FieldValue.increment(total),
        checks: { ...(session.checks || {}), [requestedCheckId]: { status: "open", secretHash: hashCheckSecret(checkSecret) } },
        updatedAt: FieldValue.serverTimestamp(),
      });
      tx.create(requestRef, { orderId: orderRef.id, sessionId, fingerprint, secretHash: hashCheckSecret(checkSecret), total, createdAt: FieldValue.serverTimestamp() });
      return { orderId: orderRef.id, total };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Place order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not place order." });
  }
});

// POST /staff-place-order — authenticated counter/waiter order entry for guests
// who are not ordering from their own phone. The server creates or reuses the
// table session, validates live menu prices, and records a private audit trail.
app.post(
  "/staff-place-order",
  rateLimit({ windowMs: 60_000, max: 40 }),
  requireFirebaseUser,
  async (req, res) => {
    const restaurantId = String(req.body?.restaurantId || "").trim();
    const table = String(req.body?.table || "").trim().slice(0, 40);
    const customerName = String(req.body?.customerName || "Walk-in guest")
      .trim()
      .slice(0, 120) || "Walk-in guest";
    const allergies = String(req.body?.allergies || "").trim().slice(0, 500);
    const requestId = String(req.body?.requestId || "").trim();
    const items = Array.isArray(req.body?.items) ? req.body.items : [];

    if (!restaurantId || !table || !/^[a-zA-Z0-9_-]{12,120}$/.test(requestId)) {
      return res.status(400).json({ error: "A table and valid order request are required." });
    }
    if (!validateOrderItems(items)) {
      return res.status(400).json({ error: "The order contains invalid items." });
    }

    try {
      const uid = req.firebaseUser.uid;
      if (!(await userCanOperate(uid, restaurantId))) {
        return res.status(403).json({ error: "You are not authorised to place orders here." });
      }

      const userSnap = await db.doc(`users/${uid}`).get();
      const userData = userSnap.exists ? userSnap.data() : {};
      const actorName = String(
        userData.name || userData.displayName || req.firebaseUser.name || req.firebaseUser.email || "Staff",
      ).slice(0, 120);

      const result = await db.runTransaction(async (tx) => {
        const requestRef = db.doc(
          `restaurants/${restaurantId}/staffOrderRequests/${requestId}`,
        );
        const profileRef = db.doc(`restaurants/${restaurantId}/profile/info`);
        const tableRef = db.doc(`restaurants/${restaurantId}/tables/${table}`);
        const [requestSnap, profileSnap, tableSnap] = await Promise.all([
          tx.get(requestRef),
          tx.get(profileRef),
          tx.get(tableRef),
        ]);

        if (requestSnap.exists) {
          return { ...requestSnap.data(), duplicate: true };
        }
        if (!profileSnap.exists || !isVenueAcceptingOrders(profileSnap.data())) {
          throw Object.assign(new Error("This restaurant is not accepting orders right now."), {
            statusCode: 403,
          });
        }

        let sessionRef = null;
        let createdSession = false;
        let existingSession = null;
        const currentSessionId = tableSnap.exists
          ? tableSnap.data().currentSessionId || null
          : null;
        if (currentSessionId) {
          const currentRef = db.doc(
            `restaurants/${restaurantId}/tableSessions/${currentSessionId}`,
          );
          const currentSnap = await tx.get(currentRef);
          if (currentSnap.exists) {
            const current = currentSnap.data();
            if (current.status === "open") {
              sessionRef = currentRef;
              existingSession = current;
            } else if (["awaiting_payment", "transfer_reported"].includes(current.status)) {
              throw Object.assign(
                new Error(`Table ${table} has an unsettled bill. Close it before starting another order.`),
                { statusCode: 409 },
              );
            }
          }
        }

        const verifiedItems = await verifiedMenuItems(tx, db, restaurantId, items);

        if (!sessionRef) {
          sessionRef = db.collection(`restaurants/${restaurantId}/tableSessions`).doc();
          createdSession = true;
          tx.set(
            tableRef,
            {
              currentSessionId: sessionRef.id,
              createdAt: tableSnap.exists
                ? tableSnap.data().createdAt || FieldValue.serverTimestamp()
                : FieldValue.serverTimestamp(),
              updatedAt: FieldValue.serverTimestamp(),
            },
            { merge: true },
          );
        }

        const total = calculateItemsTotal(verifiedItems);
        const orderRef = db.collection(`restaurants/${restaurantId}/orders`).doc();
        const staffCheckId = `c_${crypto.randomBytes(16).toString("hex")}`;
        const auditRef = db.doc(
          `restaurants/${restaurantId}/orderAudit/${orderRef.id}`,
        );
        tx.set(orderRef, {
          customerName,
          email: "",
          table,
          allergies,
          items: verifiedItems,
          total,
          status: "pending",
          createdAt: FieldValue.serverTimestamp(),
          sessionId: sessionRef.id,
          checkId: staffCheckId,
          orderSource: "staff",
          createdByName: actorName,
        });
        tx.set(auditRef, {
          action: "staff_order_created",
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          actorUid: uid,
          actorEmail: req.firebaseUser.email || "",
          actorName,
          requestId,
          createdAt: FieldValue.serverTimestamp(),
        });
        tx.set(requestRef, {
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          table,
          total,
          createdAt: FieldValue.serverTimestamp(),
        });
        if (createdSession) {
          tx.set(sessionRef, {
            table,
            status: "open",
            openedAt: FieldValue.serverTimestamp(),
            billRequestedAt: null,
            closedAt: null,
            totalBill: total,
            orderIds: [orderRef.id],
            checks: { [staffCheckId]: { status: "open" } },
            accessTokens: [],
            paymentMode: normalizePaymentMode(profileSnap.data()?.paymentMode),
            paidVia: null,
            closedByUid: null,
            updatedAt: FieldValue.serverTimestamp(),
          });
        } else {
          tx.update(sessionRef, {
            orderIds: FieldValue.arrayUnion(orderRef.id),
            totalBill: FieldValue.increment(total),
            checks: { ...(existingSession.checks || {}), [staffCheckId]: { status: "open" } },
            updatedAt: FieldValue.serverTimestamp(),
          });
        }

        return { orderId: orderRef.id, sessionId: sessionRef.id, table, total };
      });

      return res.json({ success: true, ...result });
    } catch (err) {
      console.error("Staff place order error:", err);
      return res.status(err.statusCode || 500).json({
        error: err.message || "The staff order could not be placed.",
      });
    }
  },
);

// POST /edit-order — recalculate a pending order and adjust the table atomically.
app.post("/edit-order", rateLimit({ windowMs: 60_000, max: 20 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const items = Array.isArray(req.body?.items) ? req.body.items : [];
  if (!restaurantId || !orderId || !sessionId || !accessToken || !validateOrderItems(items)) {
    return res.status(400).json({ error: "Invalid order update." });
  }
  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([
        tx.get(sessionRef),
        tx.get(orderRef),
      ]);
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = sessionSnap.exists && Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.status !== "open" || !orderSnap.exists) {
        throw Object.assign(new Error("This order can no longer be edited."), { statusCode: 409 });
      }
      const order = orderSnap.data();
      if (!hasCheckAccess(session, orderCheckId(order), checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (order.sessionId !== sessionId || order.status !== "pending" || order.paymentStatus === "paid" ||
          checkState(session, orderCheckId(order)).status !== "open") {
        throw Object.assign(new Error("This order can no longer be edited."), { statusCode: 409 });
      }
      const verifiedItems = await verifiedMenuItems(tx, db, restaurantId, items);
      const nextTotal = calculateItemsTotal(verifiedItems);
      tx.update(orderRef, { items: verifiedItems, total: nextTotal, updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        totalBill: FieldValue.increment(nextTotal - Number(order.total || 0)),
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { total: nextTotal };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Edit order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not edit order." });
  }
});

// POST /cancel-order — cancel a pending unpaid order and decrement the bill.
app.post("/cancel-order", rateLimit({ windowMs: 60_000, max: 10 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  if (!restaurantId || !orderId || !sessionId || !accessToken) {
    return res.status(400).json({ error: "Invalid cancellation request." });
  }
  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const tokenHash = hashSessionAccessToken(accessToken);
      const tokenValid = sessionSnap.exists && Array.isArray(session.accessTokens) && session.accessTokens.some(
        (entry) => entry.hash === tokenHash && Number(entry.expiresAt) > Date.now(),
      );
      if (!tokenValid || session.status !== "open" || !orderSnap.exists) {
        throw Object.assign(new Error("This order can no longer be cancelled."), { statusCode: 409 });
      }
      const order = orderSnap.data();
      if (!hasCheckAccess(session, orderCheckId(order), checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (order.sessionId !== sessionId || order.status !== "pending" || order.paymentStatus === "paid" ||
          checkState(session, orderCheckId(order)).status !== "open") {
        throw Object.assign(new Error("This order can no longer be cancelled."), { statusCode: 409 });
      }
      if (!session.orderIds?.includes(orderId)) {
        throw Object.assign(new Error("Order is not linked to this table."), { statusCode: 409 });
      }
      const orderSnaps = await Promise.all(session.orderIds.map((id) =>
        tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`)),
      ));
      if (orderSnaps.some((snap) => !snap.exists)) {
        throw Object.assign(new Error("Table order history is incomplete."), { statusCode: 409 });
      }
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      const remainingOrders = orderSnaps.map((snap) =>
        snap.id === orderId ? { ...snap.data(), status: "cancelled" } : snap.data(),
      );
      const tableClosed = canClosePaidTable(remainingOrders);
      const paidVia = [...new Set(remainingOrders.filter((item) => item.status !== "cancelled")
        .map((item) => item.paidVia).filter(Boolean))];
      tx.update(orderRef, { status: "cancelled", updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        totalBill: FieldValue.increment(-Number(order.total || 0)),
        ...(tableClosed ? {
          status: "paid", paidVia: paidVia.length > 1 ? "mixed" : paidVia[0] || (session.paymentMode === "pay_online" ? "online" : null),
          closedAt: FieldValue.serverTimestamp(), closedByUid: null,
          closeReason: "all_orders_served_and_paid", waiterCalledAt: null,
        } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (tableClosed) queuePaidTableRelease(tx, restaurantId, sessionId, tableRef, tableSnap);
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Cancel order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not cancel order." });
  }
});

// A diner may briefly expose their bill to other authenticated guests at the
// same table. Only a short label and the outstanding total are returned.
app.post("/group-payment-sharing", rateLimit({ windowMs: 60_000, max: 20 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const enabled = req.body?.enabled === true;
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const order = orderSnap.data();
      if (!session || !order || order.sessionId !== sessionId ||
          !hasValidSessionToken(session, accessToken)) {
        throw Object.assign(new Error("Order access has expired."), { statusCode: 403 });
      }
      if (session.status !== "open") {
        throw Object.assign(new Error("This table can no longer share bills."), { statusCode: 409 });
      }
      const checkId = orderCheckId(order);
      if (!validCheckId(checkId) || !hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This bill cannot be shared."), { statusCode: 403 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status !== "open" || order.status === "cancelled" || order.paymentStatus === "paid") {
        throw Object.assign(new Error("Only an open unpaid bill can be shared."), { statusCode: 409 });
      }
      const shareUntil = enabled ? new Date(Date.now() + GROUP_PAYMENT_SHARE_MS) : null;
      tx.update(sessionRef, {
        checks: {
          ...(session.checks || {}),
          [checkId]: {
            ...currentCheck,
            groupPaymentShareUntil: shareUntil,
            groupPaymentShareLabel: enabled
              ? String(order.customerName || "Guest").trim().split(/\s+/)[0].slice(0, 40)
              : null,
          },
        },
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { enabled, shareUntil: shareUntil?.toISOString() || null };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Group payment sharing error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not update bill sharing." });
  }
});

app.post("/shared-table-bills", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const [sessionSnap, orderSnap] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).get(),
      db.doc(`restaurants/${restaurantId}/orders/${orderId}`).get(),
    ]);
    const session = sessionSnap.data();
    const order = orderSnap.data();
    if (!session || !order || order.sessionId !== sessionId ||
        !hasValidSessionToken(session, accessToken)) {
      return res.status(403).json({ error: "Order access has expired." });
    }
    if (session.status !== "open") {
      return res.status(409).json({ error: "This table can no longer start a combined payment." });
    }
    const ownCheckId = orderCheckId(order);
    if (!hasCheckAccess(session, ownCheckId, checkSecret)) {
      return res.status(403).json({ error: "This bill belongs to another guest." });
    }
    const orderSnaps = await Promise.all((session.orderIds || []).map((id) =>
      db.doc(`restaurants/${restaurantId}/orders/${id}`).get(),
    ));
    const groups = new Map();
    orderSnaps.forEach((snap) => {
      if (!snap.exists) return;
      const item = snap.data();
      const checkId = orderCheckId(item);
      const state = checkState(session, checkId);
      if (checkId === ownCheckId || !validCheckId(checkId) || state.status !== "open" ||
          toMillis(state.groupPaymentShareUntil) <= Date.now() ||
          item.status === "cancelled" || item.paymentStatus === "paid") return;
      if (!groups.has(checkId)) {
        groups.set(checkId, {
          checkId,
          label: state.groupPaymentShareLabel || "Guest",
          total: 0,
          orderCount: 0,
          shareUntil: new Date(toMillis(state.groupPaymentShareUntil)).toISOString(),
        });
      }
      const group = groups.get(checkId);
      group.total += Number(item.total || 0);
      group.orderCount += 1;
    });
    return res.json({ bills: [...groups.values()] });
  } catch (err) {
    console.error("Shared table bills error:", err);
    return res.status(500).json({ error: "Could not load shared bills." });
  }
});

// POST /request-bill — customer-triggered soft lock, idempotent (public)
app.post("/request-bill", async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const includedCheckIds = [...new Set(
    Array.isArray(req.body?.includedCheckIds) ? req.body.includedCheckIds.map(String) : [],
  )];
  if (!restaurantId || !sessionId || !orderId || !accessToken ||
      includedCheckIds.some((id) => !validCheckId(id))) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      if (!sessionSnap.exists || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
          !hasValidSessionToken(sessionSnap.data(), accessToken)) {
        throw Object.assign(new Error("Order access has expired. Please ask a waiter for the bill."), { statusCode: 403 });
      }
      const session = sessionSnap.data();
      const checkId = orderCheckId(orderSnap.data());
      if (!hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      if (orderSnap.data().status === "cancelled" || orderSnap.data().paymentStatus === "paid") {
        throw Object.assign(new Error("This order has no outstanding bill."), { statusCode: 409 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status === "paid") return { status: "paid", checkId };
      if (currentCheck.status !== "open") return { status: currentCheck.status, checkId };
      if (session.status !== "open") {
        throw Object.assign(new Error("This table can no longer request a bill."), { statusCode: 409 });
      }
      const targetCheckIds = [...new Set([checkId, ...includedCheckIds.filter((id) => id !== checkId)])];
      const orderSnaps = await Promise.all((session.orderIds || []).map((id) =>
        tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`)),
      ));
      const targetOrders = orderSnaps.filter((snap) => snap.exists &&
        targetCheckIds.includes(orderCheckId(snap.data())) &&
        snap.data().status !== "cancelled" && snap.data().paymentStatus !== "paid");
      if (targetCheckIds.some((id) => !targetOrders.some((snap) => orderCheckId(snap.data()) === id))) {
        throw Object.assign(new Error("One of the selected bills is no longer available."), { statusCode: 409 });
      }
      for (const targetId of targetCheckIds) {
        const targetState = checkState(session, targetId);
        if (targetState.status !== "open" ||
            (targetId !== checkId && toMillis(targetState.groupPaymentShareUntil) <= Date.now())) {
          throw Object.assign(new Error("One of the selected bills is no longer shared or is already being paid."), { statusCode: 409 });
        }
      }
      const paymentGroupId = targetCheckIds.length > 1
        ? `pg_${crypto.randomBytes(16).toString("hex")}`
        : null;
      const checks = { ...(session.checks || {}) };
      targetCheckIds.forEach((targetId) => {
        checks[targetId] = {
          ...checkState(session, targetId),
          status: "awaiting_payment",
          billRequestedAt: new Date(),
          paymentGroupId,
          paymentGroupPayerCheckId: checkId,
          groupPaymentShareUntil: null,
        };
      });
      tx.update(sessionRef, {
        checks,
        updatedAt: FieldValue.serverTimestamp(),
      });
      return {
        status: "awaiting_payment",
        checkId,
        paymentGroupId,
        billCount: targetCheckIds.length,
        amount: targetOrders.reduce((sum, snap) => sum + Number(snap.data().total || 0), 0),
      };
    });

    return res.json(result);
  } catch (err) {
    console.error("Request bill error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not request bill.",
    });
  }
});

// POST /transfer-details — return bank details only for an active bill session.
// Full account numbers never live in the public restaurant profile.
app.post("/transfer-details", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  if (!restaurantId || !sessionId || !orderId || !accessToken) {
    return res.status(400).json({ error: "A valid order and table session are required." });
  }

  try {
    const [sessionSnap, orderSnap] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`).get(),
      db.doc(`restaurants/${restaurantId}/orders/${orderId}`).get(),
    ]);
    const session = sessionSnap.data();
    if (!session || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
        !hasValidSessionToken(session, accessToken) ||
        !hasCheckAccess(session, orderCheckId(orderSnap.data()), checkSecret) ||
        !["awaiting_payment", "transfer_reported"].includes(checkState(session, orderCheckId(orderSnap.data())).status)) {
      return res.status(409).json({ error: "Request the bill before viewing transfer details." });
    }
    const ownCheckId = orderCheckId(orderSnap.data());
    const ownCheck = checkState(session, ownCheckId);
    if (ownCheck.paymentGroupId && ownCheck.paymentGroupPayerCheckId !== ownCheckId) {
      return res.status(403).json({ error: "Another guest is handling this combined payment." });
    }
    const groupCheckIds = ownCheck.paymentGroupId
      ? Object.entries(session.checks || {})
          .filter(([, state]) => state.paymentGroupId === ownCheck.paymentGroupId)
          .map(([id]) => id)
      : [ownCheckId];
    const [privateSnap, ...orderSnaps] = await Promise.all([
      db.doc(`restaurants/${restaurantId}/profile/private`).get(),
      ...(session.orderIds || []).map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`).get()),
    ]);
    const bank = privateSnap.exists ? privateSnap.data() : {};
    if (!bank.bankName || !bank.accountName || !bank.accountNumber) {
      return res.status(404).json({ error: "Bank transfer is not configured for this restaurant." });
    }
    return res.json({
      bankName: String(bank.bankName),
      accountName: String(bank.accountName),
      accountNumber: String(bank.accountNumber),
      amount: orderSnaps.filter((snap) => snap.exists &&
        groupCheckIds.includes(orderCheckId(snap.data())) &&
        snap.data().status !== "cancelled" && snap.data().paymentStatus !== "paid")
        .reduce((sum, snap) => sum + Number(snap.data().total || 0), 0),
      billCount: groupCheckIds.length,
    });
  } catch (err) {
    console.error("Transfer details error:", err);
    return res.status(500).json({ error: "Could not load transfer details." });
  }
});

// POST /report-transfer — diner reports a transfer; staff still has to confirm it.
app.post("/report-transfer", rateLimit({ windowMs: 60_000, max: 5 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const accessToken = String(req.body?.accessToken || "").trim();
  const checkSecret = String(req.body?.checkSecret || "");
  const reference = String(req.body?.reference || "").trim().slice(0, 80);
  if (!restaurantId || !sessionId || !orderId || !accessToken || !reference) {
    return res.status(400).json({ error: "Order and transfer reference are required." });
  }

  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      if (!session || !orderSnap.exists || orderSnap.data().sessionId !== sessionId ||
          !hasValidSessionToken(session, accessToken)) {
        throw Object.assign(new Error("Order access has expired."), { statusCode: 403 });
      }
      const checkId = orderCheckId(orderSnap.data());
      if (!hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("This check belongs to another guest."), { statusCode: 403 });
      }
      const currentCheck = checkState(session, checkId);
      if (currentCheck.status !== "awaiting_payment") {
        throw Object.assign(new Error("This check is not awaiting payment."), { statusCode: 409 });
      }
      if (currentCheck.paymentGroupId && currentCheck.paymentGroupPayerCheckId !== checkId) {
        throw Object.assign(new Error("Another guest is handling this combined payment."), { statusCode: 403 });
      }
      const groupCheckIds = currentCheck.paymentGroupId
        ? Object.entries(session.checks || {})
            .filter(([, state]) => state.paymentGroupId === currentCheck.paymentGroupId)
            .map(([id]) => id)
        : [checkId];
      if (groupCheckIds.some((id) => checkState(session, id).status !== "awaiting_payment")) {
        throw Object.assign(new Error("One of these bills is no longer awaiting payment."), { statusCode: 409 });
      }
      const checks = { ...(session.checks || {}) };
      groupCheckIds.forEach((id) => {
        checks[id] = {
          ...checkState(session, id),
          status: "transfer_reported",
          transferReportedAt: new Date(),
          transferReference: reference,
        };
      });
      tx.update(sessionRef, {
        checks,
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true, status: "transfer_reported" });
  } catch (err) {
    console.error("Report transfer error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not report transfer." });
  }
});

// POST /call-waiter — diner-triggered, flags the session so staff get an alert (public)
app.post("/call-waiter", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "restaurantId and sessionId are required" });
  }

  try {
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists) {
        throw Object.assign(new Error("Table session not found."), { statusCode: 404 });
      }
      const session = sessionSnap.data();
      const { checkId, checkSecret, accessToken } = req.body || {};
      if (!hasValidSessionToken(session, accessToken) || !session.checks?.[checkId] || !hasCheckAccess(session, checkId, checkSecret)) {
        throw Object.assign(new Error("Valid guest access is required."), { statusCode: 403 });
      }
      if (!["open", "awaiting_payment"].includes(session.status)) {
        throw Object.assign(new Error("This table's session is closed."), { statusCode: 409 });
      }
      tx.update(sessionRef, { waiterCalledAt: FieldValue.serverTimestamp() });
    });

    return res.json({ success: true });
  } catch (err) {
    console.error("Call waiter error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not call the waiter.",
    });
  }
});

app.post("/delete-menu-category", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const categoryId = String(req.body?.categoryId || "").trim();
  if (!restaurantId || !categoryId) return res.status(400).json({ error: "Missing menu category." });
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Only management can delete categories." });
    await db.runTransaction(async (tx) => {
      const categoryRef = db.doc(`restaurants/${restaurantId}/menuCategories/${categoryId}`);
      const categorySnap = await tx.get(categoryRef);
      if (!categorySnap.exists) throw Object.assign(new Error("Category not found."), { statusCode: 404 });
      const menu = db.collection(`restaurants/${restaurantId}/menu`);
      const legacyName = categorySnap.data().legacyName || categorySnap.data().name;
      const [assigned, legacy] = await Promise.all([
        tx.get(menu.where("categoryId", "==", categoryId).limit(1)),
        tx.get(menu.where("category", "==", legacyName).limit(1)),
      ]);
      if (!assigned.empty || !legacy.empty) throw Object.assign(new Error("Move or delete this category's dishes first."), { statusCode: 409 });
      tx.delete(categoryRef);
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Delete menu category error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not delete category." });
  }
});

app.post("/accept-table-order", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const waiterId = req.body?.waiterId == null ? null : String(req.body.waiterId).trim();
  if (!restaurantId || !orderId || (waiterId !== null && !waiterId)) return res.status(400).json({ error: "Invalid order or waiter." });
  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Not authorised for this restaurant." });
    await db.runTransaction(async (tx) => {
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists || orderSnap.data().status !== "pending") throw Object.assign(new Error("This order is no longer pending."), { statusCode: 409 });
      const order = orderSnap.data();
      if (!order.sessionId) {
        tx.update(orderRef, { status: "in_progress" });
        return;
      }
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${order.sessionId}`);
      const waiterRef = waiterId ? db.doc(`restaurants/${restaurantId}/staff/${waiterId}`) : null;
      const [sessionSnap, waiterSnap] = await Promise.all([tx.get(sessionRef), waiterRef ? tx.get(waiterRef) : Promise.resolve(null)]);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status) || !sessionSnap.data().orderIds?.includes(orderId)) {
        throw Object.assign(new Error("This order is not in an open table session."), { statusCode: 409 });
      }
      if (waiterRef && (!waiterSnap.exists || !waiterSnap.data().name)) throw Object.assign(new Error("That waiter is no longer on the roster."), { statusCode: 409 });
      const assigned = sessionSnap.data().assignedWaiterId || sessionSnap.data().assignedWaiter;
      if (assigned && waiterId && assigned !== waiterId) throw Object.assign(new Error("This table already has a waiter. Refresh and try again."), { statusCode: 409 });
      if (!assigned && waiterId) tx.update(sessionRef, {
        assignedWaiterId: waiterId,
        assignedWaiter: String(waiterSnap.data().name).trim(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      tx.update(orderRef, { status: "in_progress" });
    });
    return res.json({ success: true, status: "in_progress" });
  } catch (err) {
    console.error("Accept order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not accept order." });
  }
});

app.post("/assign-table-waiter", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const waiterId = req.body?.waiterId == null ? null : String(req.body.waiterId).trim();
  if (!restaurantId || !sessionId) return res.status(400).json({ error: "Missing table session." });
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Only managers can reassign a waiter." });
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const waiterRef = waiterId ? db.doc(`restaurants/${restaurantId}/staff/${waiterId}`) : null;
      const [sessionSnap, waiterSnap] = await Promise.all([tx.get(sessionRef), waiterRef ? tx.get(waiterRef) : Promise.resolve(null)]);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) throw Object.assign(new Error("This table is no longer open."), { statusCode: 409 });
      if (waiterRef && (!waiterSnap.exists || !waiterSnap.data().name)) throw Object.assign(new Error("That waiter is no longer on the roster."), { statusCode: 409 });
      tx.update(sessionRef, {
        assignedWaiterId: waiterId,
        assignedWaiter: waiterSnap ? String(waiterSnap.data().name).trim() : null,
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Assign waiter error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not assign waiter." });
  }
});

app.post("/cancel-table-order", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  if (!restaurantId || !orderId) {
    return res.status(400).json({ error: "A restaurant and order are required." });
  }
  try {
    if (!(await userCanCollect(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const result = await db.runTransaction(async (tx) => {
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists) {
        throw Object.assign(new Error("Order not found."), { statusCode: 404 });
      }
      const order = orderSnap.data();
      if (order.status === "cancelled") return { tableClosed: false };
      if (!["pending", "in_progress", "ready"].includes(order.status) ||
          order.paymentStatus === "paid" || !order.sessionId) {
        throw Object.assign(new Error("This order cannot be cancelled after service or payment."), { statusCode: 409 });
      }
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${order.sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }
      const session = sessionSnap.data();
      if (!session.orderIds?.includes(orderId) || checkState(session, orderCheckId(order)).status !== "open") {
        throw Object.assign(new Error("Resolve this bill before cancelling the order."), { statusCode: 409 });
      }
      const orderSnaps = await Promise.all(session.orderIds.map((id) =>
        tx.get(db.doc(`restaurants/${restaurantId}/orders/${id}`)),
      ));
      if (orderSnaps.some((snap) => !snap.exists)) {
        throw Object.assign(new Error("Table order history is incomplete."), { statusCode: 409 });
      }
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      const remainingOrders = orderSnaps.map((snap) =>
        snap.id === orderId ? { ...snap.data(), status: "cancelled" } : snap.data(),
      );
      const tableClosed = canClosePaidTable(remainingOrders);
      const methods = [...new Set(remainingOrders.filter((item) => item.status !== "cancelled")
        .map((item) => item.paidVia).filter(Boolean))];
      tx.update(orderRef, { status: "cancelled", updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        totalBill: FieldValue.increment(-Number(order.total || 0)),
        ...(tableClosed ? {
          status: "paid", paidVia: methods.length > 1 ? "mixed" : methods[0] || (session.paymentMode === "pay_online" ? "online" : null),
          closedAt: FieldValue.serverTimestamp(), closedByUid: req.firebaseUser.uid,
          closeReason: "all_orders_served_and_paid", waiterCalledAt: null,
        } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (tableClosed) queuePaidTableRelease(tx, restaurantId, sessionRef.id, tableRef, tableSnap);
      return { tableClosed };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Cancel table order error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not cancel this order." });
  }
});

// Serving and payment can happen in either order. The last action closes the
// visit only after every non-cancelled order is both served and paid.
app.post("/mark-order-served", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  if (!restaurantId || !orderId) {
    return res.status(400).json({ error: "A restaurant and order are required." });
  }
  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const result = await db.runTransaction(async (tx) => {
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const orderSnap = await tx.get(orderRef);
      if (!orderSnap.exists) {
        throw Object.assign(new Error("Order not found."), { statusCode: 404 });
      }
      const order = orderSnap.data();
      if (["served", "completed"].includes(order.status)) {
        return { status: order.status, tableClosed: false };
      }
      if (order.status !== "ready" || !order.sessionId) {
        throw Object.assign(new Error("Only a ready order can be marked served."), { statusCode: 409 });
      }
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${order.sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }
      const session = sessionSnap.data();
      if (!session.orderIds?.includes(orderId)) {
        throw Object.assign(new Error("Order is not linked to this table."), { statusCode: 409 });
      }
      const orderRefs = session.orderIds.map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`));
      const orderSnaps = await Promise.all(orderRefs.map((ref) => tx.get(ref)));
      if (orderSnaps.some((snap) => !snap.exists)) {
        throw Object.assign(new Error("Table order history is incomplete."), { statusCode: 409 });
      }
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      const nextStatus = statusAfterServing(order);
      const nextOrders = orderSnaps.map((snap) =>
        snap.id === orderId ? { ...snap.data(), status: nextStatus } : snap.data(),
      );
      const tableClosed = canClosePaidTable(nextOrders);
      tx.update(orderRef, { status: nextStatus, servedAt: FieldValue.serverTimestamp() });
      if (tableClosed) {
        const methods = new Set(nextOrders.filter((item) => item.status !== "cancelled")
          .map((item) => item.paidVia).filter(Boolean));
        tx.update(sessionRef, {
          status: "paid",
          paidVia: methods.size > 1 ? "mixed" : [...methods][0] || session.paidVia || (session.paymentMode === "pay_online" ? "online" : null),
          closedAt: FieldValue.serverTimestamp(),
          closedByUid: req.firebaseUser.uid,
          closeReason: "all_orders_served_and_paid",
          waiterCalledAt: null,
          updatedAt: FieldValue.serverTimestamp(),
        });
        queuePaidTableRelease(tx, restaurantId, sessionRef.id, tableRef, tableSnap);
      }
      return { status: nextStatus, tableClosed };
    });
    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Mark order served error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not mark order served." });
  }
});

// Staff may collect one check or all outstanding checks together. Each order is
// marked paid exactly once. Service can finish before or after collection.
app.get("/pending-transfers", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  try {
    if (!restaurantId || !(await userCanManage(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const sessions = await db.collection(`restaurants/${restaurantId}/tableSessions`)
      .where("status", "in", OPEN_TABLE_SESSION_STATUSES).get();
    const totals = { count: 0, total: 0 };
    for (const snap of sessions.docs) {
      const session = snap.data();
      if (session.status !== "transfer_reported" && !Object.values(session.checks || {}).some((check) => check.status === "transfer_reported")) continue;
      const orders = await Promise.all((session.orderIds || []).map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`).get()));
      const pending = pendingTransferTotals(session, orders.filter((order) => order.exists).map((order) => order.data()));
      totals.count += pending.count;
      totals.total += pending.total;
    }
    return res.json(totals);
  } catch (err) {
    console.error("Pending transfer read failed:", err);
    return res.status(500).json({ error: "Could not load pending transfers." });
  }
});

app.post("/settle-checks", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderIds = [...new Set(Array.isArray(req.body?.orderIds) ? req.body.orderIds.map(String) : [])];
  const checkIds = [...new Set(Array.isArray(req.body?.checkIds) ? req.body.checkIds : [])];
  const paidVia = String(req.body?.paidVia || "");
  if (!restaurantId || !sessionId || (!orderIds.length && !checkIds.length) ||
      checkIds.some((id) => id !== LEGACY_CHECK_ID && !validCheckId(id)) ||
      !["cash", "pos", "transfer"].includes(paidVia)) {
    return res.status(400).json({ error: "Select a valid bill and payment method." });
  }
  try {
    if (!(await userCanCollect(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const settlementKey = hashValue(JSON.stringify([sessionId, paidVia, [...orderIds].sort(), [...checkIds].sort()]));
    const settlementRef = db.doc(`restaurants/${restaurantId}/settlements/s_${settlementKey}`);
    const paidAt = new Date();
    const receipt = await db.runTransaction(async (tx) => {
      const priorPayment = await tx.get(settlementRef);
      if (priorPayment.exists) return priorPayment.data().receipt;
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }
      const session = sessionSnap.data();
      const orderRefs = (session.orderIds || []).map((id) => db.doc(`restaurants/${restaurantId}/orders/${id}`));
      const [orderSnaps, profileSnap] = await Promise.all([
        Promise.all(orderRefs.map((ref) => tx.get(ref))),
        tx.get(db.doc(`restaurants/${restaurantId}/profile/info`)),
      ]);
      if (orderSnaps.some((snap) => !snap.exists)) {
        throw Object.assign(new Error("Table order history is incomplete."), { statusCode: 409 });
      }
      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      const active = orderSnaps.filter((snap) => snap.exists && snap.data().status !== "cancelled");
      const unpaid = active.filter((snap) => snap.data().paymentStatus !== "paid");
      const selected = orderIds.length
        ? unpaid.filter((snap) => orderIds.includes(snap.id))
        : unpaid.filter((snap) => checkIds.includes(orderCheckId(snap.data())));
      if (!selected.length ||
          (orderIds.length && orderIds.some((id) => !selected.some((snap) => snap.id === id))) ||
          (!orderIds.length && checkIds.some((id) => !selected.some((snap) => orderCheckId(snap.data()) === id)))) {
        throw Object.assign(new Error("This bill has no unpaid orders."), { statusCode: 409 });
      }
      const selectedCheckIds = [...new Set(selected.map((snap) => orderCheckId(snap.data())))];
      const selectedPaymentGroups = [...new Set(selectedCheckIds
        .map((id) => checkState(session, id).paymentGroupId)
        .filter(Boolean))];
      for (const paymentGroupId of selectedPaymentGroups) {
        const groupCheckIds = Object.entries(session.checks || {})
          .filter(([, state]) => state.paymentGroupId === paymentGroupId && state.status !== "paid")
          .map(([id]) => id);
        if (groupCheckIds.some((id) => !selectedCheckIds.includes(id))) {
          throw Object.assign(
            new Error("All bills in this combined payment must be confirmed together."),
            { statusCode: 409 },
          );
        }
      }
      // A guest report is an alert, not a prerequisite for a staff member who
      // has verified the transfer in the bank account. Combined requests still
      // have to settle every bill in their payment group above.
      const amount = selected.reduce((sum, snap) => sum + Number(snap.data().total || 0), 0);
      const selectedOrderIds = new Set(selected.map((snap) => snap.id));
      const allSettled = selected.length === unpaid.length;
      const tableClosed = allSettled && canClosePaidTable(orderSnaps.filter((snap) => snap.exists).map((snap) => ({
        ...snap.data(),
        ...(selectedOrderIds.has(snap.id) ? { paymentStatus: "paid" } : {}),
      })));
      const settlementMethods = new Set(active.map((snap) =>
        selectedOrderIds.has(snap.id) ? paidVia : snap.data().paidVia,
      ).filter(Boolean));
      const checks = { ...(session.checks || {}) };
      selectedCheckIds.forEach((id) => {
        const unpaidForCheck = unpaid.filter((snap) => orderCheckId(snap.data()) === id);
        const selectedForCheck = selected.filter((snap) => orderCheckId(snap.data()) === id);
        const checkAmount = selectedForCheck
          .reduce((sum, snap) => sum + Number(snap.data().total || 0), 0);
        const prior = checkState(session, id);
        const fullyPaid = selectedForCheck.length === unpaidForCheck.length;
        const methods = new Set([prior.paidVia, paidVia].filter(Boolean));
        checks[id] = { ...prior, ...(fullyPaid ? { status: "paid" } : {}),
          paidVia: methods.size > 1 ? "mixed" : paidVia, paidAt,
          amount: Number(prior.amount || 0) + checkAmount,
          settledOrders: Number(prior.settledOrders || 0) + selectedForCheck.length };
      });
      selected.forEach((snap) => tx.update(snap.ref, {
        paymentStatus: "paid", paidVia, paidAt: FieldValue.serverTimestamp(), settlementId: settlementRef.id,
        ...(snap.data().status === "served" ? { status: "completed" } : {}),
      }));
      tx.update(sessionRef, {
        checks,
        amountPaid: FieldValue.increment(amount),
        ...(tableClosed ? {
          status: "paid", closedAt: FieldValue.serverTimestamp(),
          paidVia: settlementMethods.size > 1 ? "mixed" : [...settlementMethods][0] || paidVia,
          closedByUid: req.firebaseUser.uid, closeReason: "all_orders_served_and_paid", waiterCalledAt: null,
        } : {}),
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (tableClosed) {
        if (tableSnap.data()?.currentSessionId === sessionId) {
          tx.set(tableRef, { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() }, { merge: true });
        }
      }
      const dayKey = lagosDayKey();
      tx.set(db.doc(`restaurants/${restaurantId}/dailySummaries/${dayKey}`), {
        dateKey: dayKey,
        totalRevenue: FieldValue.increment(amount),
        [paymentRevenueField(paidVia)]: FieldValue.increment(amount),
        settledOrders: FieldValue.increment(selected.length),
        ...(tableClosed ? { settledTables: FieldValue.increment(1) } : {}),
        lastSettlementAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      }, { merge: true });
      const receiptData = {
        settlementId: settlementRef.id,
        restaurantName: profileSnap.data()?.name || restaurantId,
        table: session.table,
        orders: selected.map((snap) => ({
          customerName: snap.data().customerName || "Guest",
          items: snap.data().items || [],
          total: Number(snap.data().total || 0),
        })),
        totalBill: amount,
        settledOrderIds: selected.map((snap) => snap.id),
        paidVia,
        tableClosed,
        closedAt: paidAt.toISOString(),
      };
      tx.create(settlementRef, {
        sessionId, table: session.table, orderIds: selected.map((snap) => snap.id),
        checkIds: selectedCheckIds, amount, paidVia, paidAt,
        dateKey: lagosDayKey(paidAt), actorUid: req.firebaseUser.uid, receipt: receiptData,
        recipients: [...new Set(selected.map((snap) => snap.data().email).filter(Boolean))],
        receiptOrders: selected.map((snap) => ({ customerName: snap.data().customerName || "Guest",
          email: snap.data().email || "", items: snap.data().items || [], total: Number(snap.data().total || 0) })),
      });
      return receiptData;
    });
    return res.json({ success: true, ...receipt });
  } catch (err) {
    console.error("Settle checks error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not settle checks." });
  }
});

// End an unused table visit without creating a payment or receipt. This route
// is intentionally limited to sessions where every linked order was cancelled.
app.post("/close-empty-table-session", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  if (!restaurantId || !sessionId) {
    return res.status(400).json({ error: "A restaurant and table session are required." });
  }

  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }

    const result = await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const sessionSnap = await tx.get(sessionRef);
      if (!sessionSnap.exists || !OPEN_TABLE_SESSION_STATUSES.includes(sessionSnap.data().status)) {
        throw Object.assign(new Error("This table is already closed."), { statusCode: 409 });
      }

      const session = sessionSnap.data();
      const orderRefs = (session.orderIds || []).map((id) =>
        db.doc(`restaurants/${restaurantId}/orders/${id}`),
      );
      const orderSnaps = await Promise.all(orderRefs.map((ref) => tx.get(ref)));
      const billableOrders = orderSnaps.filter(
        (snap) => snap.exists &&
          (snap.data().status !== "cancelled" || snap.data().paymentStatus === "paid"),
      );
      if (billableOrders.length > 0 || Number(session.amountPaid || 0) > 0) {
        throw Object.assign(
          new Error("This table has billable orders. Collect payment instead of closing it without charge."),
          { statusCode: 409 },
        );
      }

      const tableRef = db.doc(`restaurants/${restaurantId}/tables/${session.table}`);
      const tableSnap = await tx.get(tableRef);
      tx.update(sessionRef, {
        status: "closed",
        totalBill: 0,
        amountPaid: 0,
        paidVia: null,
        closeReason: "all_orders_cancelled",
        closedAt: FieldValue.serverTimestamp(),
        closedByUid: req.firebaseUser.uid,
        waiterCalledAt: null,
        updatedAt: FieldValue.serverTimestamp(),
      });
      if (tableSnap.exists && tableSnap.data()?.currentSessionId === sessionId) {
        tx.set(
          tableRef,
          { currentSessionId: null, updatedAt: FieldValue.serverTimestamp() },
          { merge: true },
        );
      }

      return { table: session.table };
    });

    return res.json({ success: true, table: result.table, receipt: null });
  } catch (err) {
    console.error("Close empty table session error:", err);
    return res.status(err.statusCode || 500).json({
      error: err.message || "Could not close this table.",
    });
  }
});

app.post("/move-order-check", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const sessionId = String(req.body?.sessionId || "").trim();
  const orderId = String(req.body?.orderId || "").trim();
  const targetCheckId = String(req.body?.targetCheckId || "").trim();
  if (!restaurantId || !sessionId || !orderId || !validCheckId(targetCheckId)) {
    return res.status(400).json({ error: "Select an order and an open check." });
  }
  try {
    if (!(await userCanOperate(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    await db.runTransaction(async (tx) => {
      const sessionRef = db.doc(`restaurants/${restaurantId}/tableSessions/${sessionId}`);
      const orderRef = db.doc(`restaurants/${restaurantId}/orders/${orderId}`);
      const [sessionSnap, orderSnap] = await Promise.all([tx.get(sessionRef), tx.get(orderRef)]);
      const session = sessionSnap.data();
      const order = orderSnap.data();
      if (!session || !order || session.status !== "open" || order.sessionId !== sessionId ||
          order.status === "cancelled" || order.paymentStatus === "paid" ||
          !session.orderIds?.includes(orderId) ||
          checkState(session, orderCheckId(order)).status !== "open" ||
          checkState(session, targetCheckId).status !== "open") {
        throw Object.assign(new Error("Only unpaid orders on open checks can be moved."), { statusCode: 409 });
      }
      const targetExists = Object.prototype.hasOwnProperty.call(session.checks || {}, targetCheckId);
      if (!targetExists) {
        throw Object.assign(new Error("Target check does not exist on this table."), { statusCode: 409 });
      }
      tx.update(orderRef, { checkId: targetCheckId, updatedAt: FieldValue.serverTimestamp() });
      tx.update(sessionRef, {
        checks: { ...(session.checks || {}), [targetCheckId]: { ...checkState(session, targetCheckId), status: "open" } },
        updatedAt: FieldValue.serverTimestamp(),
      });
    });
    return res.json({ success: true });
  } catch (err) {
    console.error("Move order check error:", err);
    return res.status(err.statusCode || 500).json({ error: err.message || "Could not move order." });
  }
});

// Retired in favor of check-level settlement. Do not accept client-supplied totals.
app.post("/close-table-session", requireFirebaseUser, (_req, res) => {
  return res.status(410).json({ error: "Use check-level settlement to close a table." });
});

// POST /rebuild-daily-summaries — management-only historical backfill. This is
// intentionally manual: the dashboard always reads tiny pre-aggregated docs,
// never every historical order/session.
app.post("/rebuild-daily-summaries", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const requestedDays = Number(req.body?.days || 7);
  const days = Math.max(1, Math.min(90, Number.isFinite(requestedDays) ? requestedDays : 7));

  if (!restaurantId) {
    return res.status(400).json({ error: "restaurantId is required" });
  }

  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }

    const endKey = lagosDayKey();
    const endDate = new Date(`${endKey}T12:00:00+01:00`);
    let summariesUpdated = 0;
    let lockedDaysSkipped = 0;
    for (let index = 0; index < days; index++) {
      const date = new Date(endDate.getTime() - index * 86400000);
      const key = lagosDayKey(date);
      const start = new Date(`${key}T00:00:00+01:00`);
      const end = new Date(start.getTime() + 86400000);
      const rebuilt = await db.runTransaction(async (tx) => {
        const summaryRef = db.doc(`restaurants/${restaurantId}/dailySummaries/${key}`);
        const summary = await tx.get(summaryRef);
        if (summary.data()?.reconciledAt) return false;
        // Reading the summary in this transaction serializes rebuild with any
        // settlement increment, so a concurrent collection cannot be overwritten.
        const [events, paidOrders, closedSessions] = await Promise.all([
          tx.get(db.collection(`restaurants/${restaurantId}/settlements`).where("paidAt", ">=", start).where("paidAt", "<", end)),
          tx.get(db.collection(`restaurants/${restaurantId}/orders`).where("paidAt", ">=", start).where("paidAt", "<", end)),
          tx.get(db.collection(`restaurants/${restaurantId}/tableSessions`).where("closedAt", ">=", start).where("closedAt", "<", end)),
        ]);
        const totals = summarizePayments(events.docs.map((snap) => snap.data()),
          paidOrders.docs.map((snap) => ({ id: snap.id, ...snap.data() })), closedSessions.docs.map((snap) => snap.data()));
        if (Number(summary.data()?.totalRevenue || 0) > totals.totalRevenue + 0.005) {
          throw Object.assign(new Error("Historical payment records are incomplete. Existing revenue was left unchanged; reconcile the missing records before rebuilding."), { statusCode: 409 });
        }
        tx.set(summaryRef, { dateKey: key, ...totals, rebuiltAt: FieldValue.serverTimestamp(), updatedAt: FieldValue.serverTimestamp() }, { merge: true });
        return true;
      });
      if (rebuilt) summariesUpdated++; else lockedDaysSkipped++;
    }
    return res.json({ success: true, days, summariesUpdated, lockedDaysSkipped });
  } catch (err) {
    console.error("Rebuild daily summaries error:", err);
    return res.status(err.statusCode || 500).json({ error: err.statusCode ? err.message : "Could not rebuild daily summaries." });
  }
});

app.post("/finalize-online-payment", rateLimit({ windowMs: 60_000, max: 30 }), async (req, res) => {
  return res.status(410).json({
    success: false,
    error: "Diner online payments are temporarily unavailable.",
  });

  const {
    reference,
    restaurantId,
    customerName,
    email,
    table,
    allergies,
    items,
    total,
    sessionId,
  } = req.body || {};

  const cleanedReference = String(reference || "").trim();
  const cleanedRestaurantId = String(restaurantId || "").trim();
  const cleanedTable = String(table || "").trim();
  const cleanedName = String(customerName || "").trim();
  const numericTotal = Number(total);
  const expectedAmount = Math.round(numericTotal * 100);
  const cleanedItems = Array.isArray(items)
    ? items.map((item) => ({
        name: String(item.name || "").trim(),
        price: Number(item.price),
        qty: Number(item.qty),
      }))
    : [];

  if (
    !cleanedReference ||
    !cleanedRestaurantId ||
    !cleanedTable ||
    !cleanedName
  ) {
    return res
      .status(400)
      .json({ success: false, error: "Missing payment or order details." });
  }
  if (
    !Number.isFinite(numericTotal) ||
    numericTotal <= 0 ||
    expectedAmount <= 0
  ) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid order total." });
  }
  if (!validateOrderItems(cleanedItems)) {
    return res
      .status(400)
      .json({ success: false, error: "Invalid order items." });
  }

  const calculatedTotal = calculateItemsTotal(cleanedItems);
  if (Math.round(calculatedTotal * 100) !== expectedAmount) {
    return res
      .status(400)
      .json({ success: false, error: "Order total does not match items." });
  }

  try {
    const transaction = await verifyPaystackReference(cleanedReference);
    const metadata = transaction.metadata || {};

    if (Number(transaction.amount) !== expectedAmount) {
      return res.status(400).json({
        success: false,
        error: "Payment amount does not match order total.",
      });
    }
    if (transaction.currency !== "NGN") {
      return res
        .status(400)
        .json({ success: false, error: "Unsupported payment currency." });
    }
    if (
      metadata.restaurantId &&
      metadata.restaurantId !== cleanedRestaurantId
    ) {
      return res
        .status(400)
        .json({ success: false, error: "Payment restaurant mismatch." });
    }
    if (metadata.table && String(metadata.table) !== cleanedTable) {
      return res
        .status(400)
        .json({ success: false, error: "Payment table mismatch." });
    }

    const result = await db.runTransaction(async (tx) => {
      const profileRef = db.doc(
        `restaurants/${cleanedRestaurantId}/profile/info`,
      );
      const paymentRef = db.doc(`paymentReferences/${cleanedReference}`);
      const profileSnap = await tx.get(profileRef);
      const paymentSnap = await tx.get(paymentRef);

      if (!profileSnap.exists) {
        throw Object.assign(new Error("Restaurant not found."), {
          statusCode: 404,
        });
      }

      const profile = profileSnap.data();
      if (normalizePaymentMode(profile.paymentMode) !== "pay_online") {
        throw Object.assign(
          new Error("Online payment is not enabled for this restaurant."),
          { statusCode: 403 },
        );
      }
      if (!profile.paystackSubaccountCode) {
        throw Object.assign(
          new Error("Online payment account is not connected."),
          { statusCode: 400 },
        );
      }

      const transactionSubaccount =
        transaction.subaccount?.subaccount_code ||
        transaction.subaccount_code ||
        null;
      if (
        transactionSubaccount &&
        transactionSubaccount !== profile.paystackSubaccountCode
      ) {
        throw Object.assign(new Error("Payment account mismatch."), {
          statusCode: 400,
        });
      }

      if (paymentSnap.exists && paymentSnap.data().orderId) {
        return {
          orderId: paymentSnap.data().orderId,
          sessionId: paymentSnap.data().sessionId || null,
          reused: true,
        };
      }

      const orderRef = db
        .collection(`restaurants/${cleanedRestaurantId}/orders`)
        .doc();
      let sessionRef;
      let isNewSession = false;
      let existingOrderIds = [];
      let nextTotalBill = numericTotal;

      if (sessionId) {
        sessionRef = db.doc(
          `restaurants/${cleanedRestaurantId}/tableSessions/${sessionId}`,
        );
        const sessionSnap = await tx.get(sessionRef);
        if (!sessionSnap.exists) {
          throw Object.assign(new Error("Table session not found."), {
            statusCode: 404,
          });
        }
        const session = sessionSnap.data();
        if (String(session.table) !== cleanedTable) {
          throw Object.assign(new Error("Table session mismatch."), {
            statusCode: 400,
          });
        }
        existingOrderIds = Array.isArray(session.orderIds)
          ? session.orderIds
          : [];
        nextTotalBill = Number(session.totalBill || 0) + numericTotal;
      } else {
        sessionRef = db
          .collection(`restaurants/${cleanedRestaurantId}/tableSessions`)
          .doc();
        isNewSession = true;
      }

      tx.set(orderRef, {
        customerName: cleanedName,
        email: String(email || "").trim(),
        table: cleanedTable,
        allergies: String(allergies || "").trim(),
        items: cleanedItems,
        total: numericTotal,
        status: "pending",
        paymentStatus: "paid",
        paymentRef: cleanedReference,
        sessionId: sessionRef.id,
        createdAt: FieldValue.serverTimestamp(),
      });

      // Paying online settles the ORDER, not the table: the session stays open
      // so the same party can keep ordering (each order prepaid) until staff
      // close the table. Closing terminally here broke follow-up orders.
      tx.set(
        sessionRef,
        {
          table: cleanedTable,
          ...(isNewSession
            ? {
                status: "open",
                openedAt: FieldValue.serverTimestamp(),
                billRequestedAt: null,
                closedAt: null,
                paidVia: null,
                closedByUid: null,
              }
            : {}),
          updatedAt: FieldValue.serverTimestamp(),
          totalBill: nextTotalBill,
          orderIds: [...existingOrderIds, orderRef.id],
          paymentMode: "pay_online",
          lastPaymentRef: cleanedReference,
        },
        { merge: true },
      );

      // Register a freshly-created session on the table so rescans rejoin it.
      if (isNewSession) {
        tx.set(
          db.doc(`restaurants/${cleanedRestaurantId}/tables/${cleanedTable}`),
          {
            currentSessionId: sessionRef.id,
            updatedAt: FieldValue.serverTimestamp(),
          },
          { merge: true },
        );
      }

      tx.set(
        paymentRef,
        {
          reference: cleanedReference,
          status: "success",
          amount: Number(transaction.amount),
          currency: transaction.currency,
          restaurantId: cleanedRestaurantId,
          table: cleanedTable,
          customerName: cleanedName,
          orderId: orderRef.id,
          sessionId: sessionRef.id,
          finalizedAt: FieldValue.serverTimestamp(),
          paystackData: transaction,
        },
        { merge: true },
      );

      return { orderId: orderRef.id, sessionId: sessionRef.id, reused: false };
    });

    return res.json({ success: true, ...result });
  } catch (err) {
    console.error("Finalize online payment error:", err);
    return res.status(err.statusCode || 500).json({
      success: false,
      error: err.message || "Could not finalize payment.",
    });
  }
});

// Named staff logins coexist with legacy shared screens during migration.
app.get("/staff-accounts", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Management access is required." });
    const users = await db.collection("users").where("restaurantId", "==", restaurantId).get();
    return res.json({ accounts: users.docs.filter((snap) => snap.data().accountType === "individual_staff")
      .map((snap) => ({ uid: snap.id, name: snap.data().displayName, email: snap.data().email, role: snap.data().role })) });
  } catch (_) { return res.status(500).json({ error: "Could not load staff access." }); }
});

app.post("/staff-accounts", rateLimit({ windowMs: 60000, max: 10 }), requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const name = String(req.body?.name || "").trim().slice(0, 80);
  const role = String(req.body?.role || "");
  if (!name || !["kitchen", "bar", "waiter", "cashier"].includes(role)) return res.status(400).json({ error: "Choose a staff name and a service role." });
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Management access is required." });
    const tempPassword = genTempPassword();
    const email = `${restaurantId}.${crypto.randomBytes(8).toString("hex")}@staff.servrr.ng`;
    const user = await firebaseAuth.createUser({ email, password: tempPassword, displayName: name, emailVerified: true });
    await db.doc(`users/${user.uid}`).set({ restaurantId, email, displayName: name, role, accountType: "individual_staff", createdAt: FieldValue.serverTimestamp() });
    return res.json({ success: true, uid: user.uid, email, tempPassword });
  } catch (_) { return res.status(500).json({ error: "Could not finish staff setup. Check the account list before retrying." }); }
});

const individualStaffTarget = async (restaurantId, uid) => {
  const snap = await db.doc(`users/${uid}`).get();
  return snap.exists && snap.data().restaurantId === restaurantId && snap.data().accountType === "individual_staff" ? snap.data() : null;
};
app.post("/reset-staff-account", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const uid = String(req.body?.uid || "").trim();
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Management access is required." });
    const target = await individualStaffTarget(restaurantId, uid);
    if (!target) return res.status(404).json({ error: "Staff account not found." });
    const tempPassword = genTempPassword();
    await firebaseAuth.updateUser(uid, { password: tempPassword });
    await firebaseAuth.revokeRefreshTokens(uid);
    await db.doc(`users/${uid}`).update({ authValidAfter: Math.floor(Date.now() / 1000) });
    return res.json({ success: true, email: target.email, tempPassword });
  } catch (_) { return res.status(500).json({ error: "Could not reset staff access." }); }
});
app.delete("/staff-account", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const uid = String(req.body?.uid || "").trim();
  try {
    if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) return res.status(403).json({ error: "Management access is required." });
    if (!(await individualStaffTarget(restaurantId, uid))) return res.status(404).json({ error: "Staff account not found." });
    // Remove authorization first. A failed Auth cleanup cannot leave venue access.
    await db.doc(`users/${uid}`).delete();
    await firebaseAuth.deleteUser(uid);
    return res.json({ success: true });
  } catch (_) { return res.status(500).json({ error: "Could not finish removing staff access. Please retry." }); }
});

// DELETE /delete-user — permanently delete a Firebase Auth account (super admin only)
app.delete("/delete-user", requireFirebaseUser, async (req, res) => {
  if (!(await isSuperAdmin(req.firebaseUser.uid))) {
    return res.status(403).json({ error: "Forbidden" });
  }
  const { uid } = req.body;
  if (!uid) return res.status(400).json({ error: "uid required" });
  try {
    await firebaseAuth.deleteUser(uid);
    res.json({ success: true });
  } catch (err) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: err.message });
  }
});

// ── Staff login (the single shared Orders+QR account for kitchen/cashier) ─────────
// Access collapses to two levels: owner (full) and "staff" (Orders + QR). Individual
// waiters are a name-only roster (restaurants/{id}/staff) — they don't log in.
const genTempPassword = () => {
  const raw = crypto.randomBytes(9).toString("base64").replace(/[^a-zA-Z0-9]/g, "");
  // Always satisfies Firebase's 6-char minimum and mixes letters + a digit.
  return `Srv${raw.slice(0, 8)}7`;
};

const findStaffLogin = async (restaurantId) => {
  const snap = await db
    .collection("users")
    .where("restaurantId", "==", restaurantId)
    .where("role", "==", "staff")
    .limit(1)
    .get();
  return snap.empty ? null : { uid: snap.docs[0].id, ...snap.docs[0].data() };
};

// GET /staff-login?restaurantId= — return the single staff login (without its password).
app.get("/staff-login", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.query.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    return res.json({ staff: staff ? { uid: staff.uid, email: staff.email || "" } : null });
  } catch (err) {
    console.error("Get staff login error:", err);
    return res.status(500).json({ error: "Could not load staff login." });
  }
});

// POST /create-staff — create the single staff login with a temporary password (shown once).
app.post(
  "/create-staff",
  rateLimit({ windowMs: 60_000, max: 20 }),
  requireFirebaseUser,
  async (req, res) => {
    const { restaurantId, email } = req.body || {};
    const cleanedRestaurantId = String(restaurantId || "").trim();
    const cleanedEmail = String(email || "").trim().toLowerCase();
    if (!cleanedRestaurantId || !cleanedEmail) {
      return res.status(400).json({ error: "restaurantId and email are required." });
    }
    if (!(await userCanManage(req.firebaseUser.uid, cleanedRestaurantId))) {
      return res.status(403).json({ error: "Not authorized for this restaurant" });
    }
    try {
      if (await findStaffLogin(cleanedRestaurantId)) {
        return res
          .status(409)
          .json({ error: "A staff login already exists. Reset or remove it instead." });
      }
      const tempPassword = genTempPassword();
      const userRecord = await firebaseAuth.createUser({
        email: cleanedEmail,
        password: tempPassword,
        emailVerified: true, // vouched for by the owner — no separate verification step
      });
      await db.doc(`users/${userRecord.uid}`).set({
        restaurantId: cleanedRestaurantId,
        email: cleanedEmail,
        role: "staff",
        createdAt: FieldValue.serverTimestamp(),
        createdBy: req.firebaseUser.uid,
      });
      return res.json({ success: true, uid: userRecord.uid, email: cleanedEmail, tempPassword });
    } catch (err) {
      if (err.code === "auth/email-already-exists") {
        return res.status(409).json({ error: "That email already has an account." });
      }
      if (err.code === "auth/invalid-email") {
        return res.status(400).json({ error: "That email address is invalid." });
      }
      console.error("Create staff error:", err);
      return res.status(500).json({ error: "Could not create staff login." });
    }
  },
);

// POST /reset-staff-password — issue a fresh temporary password for the staff login.
app.post("/reset-staff-password", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    if (!staff) return res.status(404).json({ error: "No staff login to reset." });
    const tempPassword = genTempPassword();
    await firebaseAuth.updateUser(staff.uid, { password: tempPassword });
    // Kill any live sessions too (e.g. a stolen tablet) — not just future logins.
    await firebaseAuth.revokeRefreshTokens(staff.uid);
    await db.doc(`users/${staff.uid}`).set({ authValidAfter: Math.floor(Date.now() / 1000) }, { merge: true });
    return res.json({ success: true, email: staff.email || "", tempPassword });
  } catch (err) {
    console.error("Reset staff password error:", err);
    return res.status(500).json({ error: "Could not reset password." });
  }
});

// DELETE /delete-staff — remove the staff login (auth account + user doc).
app.delete("/delete-staff", requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  if (!restaurantId) return res.status(400).json({ error: "restaurantId is required" });
  if (!(await userCanManage(req.firebaseUser.uid, restaurantId))) {
    return res.status(403).json({ error: "Not authorized for this restaurant" });
  }
  try {
    const staff = await findStaffLogin(restaurantId);
    if (!staff) return res.status(404).json({ error: "No staff login to remove." });
    await db.doc(`users/${staff.uid}`).delete();
    await firebaseAuth.deleteUser(staff.uid).catch(() => {});
    return res.json({ success: true });
  } catch (err) {
    console.error("Delete staff error:", err);
    return res.status(500).json({ error: "Could not remove staff login." });
  }
});

// POST /notify-login — new-device login alerts. Each browser sends a stable device ID
// after sign-in; the first-ever device registers silently, any later unknown device is
// registered AND triggers an alert email. Staff-login alerts go to the venue owner.
app.post(
  "/notify-login",
  rateLimit({ windowMs: 60_000, max: 10 }),
  requireFirebaseUser,
  async (req, res) => {
    const deviceId = String(req.body?.deviceId || "").trim().slice(0, 100);
    if (!deviceId) return res.status(400).json({ error: "deviceId required" });

    try {
      const userRef = db.doc(`users/${req.firebaseUser.uid}`);
      const snap = await userRef.get();
      if (!snap.exists) return res.json({ known: true }); // super admin — no user doc

      const userData = snap.data();
      const known = Array.isArray(userData.knownDevices) ? userData.knownDevices : [];
      if (known.includes(deviceId)) return res.json({ known: true });

      await userRef.update({ knownDevices: FieldValue.arrayUnion(deviceId) });

      // First device ever (incl. everyone's next login after this feature ships):
      // register quietly so we don't blast alerts for normal use.
      if (known.length === 0) return res.json({ known: false, first: true });

      // Staff logins alert the owner (they own the credential); others alert themselves.
      let to = req.firebaseUser.email || userData.email || "";
      const isStaff = ["staff", "kitchen", "bar", "waiter", "cashier"].includes(userData.role);
      if (isStaff && userData.restaurantId) {
        const profSnap = await db
          .doc(`restaurants/${userData.restaurantId}/profile/info`)
          .get();
        to = profSnap.data()?.email || to;
      }

      if (to) {
        const ua = String(req.headers["user-agent"] || "Unknown device").slice(0, 180);
        const when = new Date().toLocaleString("en-NG", {
          timeZone: "Africa/Lagos",
          dateStyle: "medium",
          timeStyle: "short",
        });
        const acct = isStaff
          ? `the STAFF login (${escapeHtml(userData.email || "")})`
          : "your Servrr account";
        const advice = isStaff
          ? "reset the staff password from your dashboard's Staff tab"
          : 'use "Forgot password" on the login page to reset it';
        await resend.emails.send({
          from: MAIL_FROM,
          to: [to],
          subject: "New sign-in to your Servrr account",
          html: `
            <div style="background:#0a0a0a;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;max-width:480px;margin:0 auto;padding:40px 28px;">
              <p style="color:#fa5631;font-size:22px;font-weight:900;letter-spacing:-0.5px;margin:0 0 28px 0;">SERVRR</p>
              <h1 style="color:#fff;font-size:22px;font-weight:800;margin:0 0 12px 0;">New sign-in detected</h1>
              <p style="color:#aaa;font-size:14px;line-height:1.7;margin:0 0 20px 0;">
                A device that hasn't been used before just signed in to ${acct}.
              </p>
              <div style="background:#111;border:1px solid #222;border-radius:14px;padding:18px;margin-bottom:24px;">
                <p style="color:#ccc;font-size:13px;line-height:1.8;margin:0;">
                  <strong style="color:#fff">When:</strong> ${escapeHtml(when)} (Lagos)<br/>
                  <strong style="color:#fff">Device:</strong> ${escapeHtml(ua)}<br/>
                  <strong style="color:#fff">IP:</strong> ${escapeHtml(String(req.ip || "unknown"))}
                </p>
              </div>
              <p style="color:#aaa;font-size:13px;line-height:1.7;margin:0;">
                If this was you or your team, no action is needed. If not, ${advice} immediately —
                that signs the device out.
              </p>
              <p style="color:#333;font-size:11px;text-align:center;margin-top:32px;">© ${new Date().getFullYear()} SERVRR</p>
            </div>`,
        });
      }

      return res.json({ known: false });
    } catch (err) {
      console.error("notify-login error:", err);
      return res.status(500).json({ error: "Could not record login." });
    }
  },
);

// Receipt contents and recipients come only from committed payment records.
app.post("/send-receipt", rateLimit({ windowMs: 60_000, max: 20 }), requireFirebaseUser, async (req, res) => {
  const restaurantId = String(req.body?.restaurantId || "").trim();
  const settlementId = String(req.body?.settlementId || "").trim();
  if (!restaurantId || !/^s_[a-f0-9]{64}$/.test(settlementId)) {
    return res.status(400).json({ error: "A recorded settlement is required." });
  }
  try {
    if (!(await userCanCollect(req.firebaseUser.uid, restaurantId))) {
      return res.status(403).json({ error: "Not authorised for this restaurant." });
    }
    const snapshot = await db.doc(`restaurants/${restaurantId}/settlements/${settlementId}`).get();
    if (!snapshot.exists) return res.status(404).json({ error: "Payment record not found." });
    const payment = snapshot.data();
    const receipts = receiptsForSettlement(payment);
    for (const receipt of receipts) {
      const result = await resend.emails.send({
        from: MAIL_FROM, to: [receipt.email],
        subject: `Your receipt from ${payment.receipt.restaurantName} — Table ${payment.table}`,
        html: receiptHtml(payment, receipt),
      }, { idempotencyKey: `${settlementId}-${hashValue(receipt.email)}` });
      if (result.error) throw new Error(result.error.message || "Email provider rejected the receipt.");
    }
    return res.json({ success: true, sent: receipts.length });
  } catch (err) {
    console.error("Receipt email error:", err);
    return res.status(500).json({ error: "Could not send the recorded receipt. Please retry." });
  }
});

// Lightweight health check (replaces the old unauthenticated email relay).
app.get("/", (req, res) => res.json({ status: "ok" }));
app.get("/ready", async (_req, res) => {
  try {
    await db.doc("platformHealth/readiness").get();
    return res.json({ status: "ready", database: "reachable" });
  } catch (_) { return res.status(503).json({ status: "unavailable" }); }
});

app.listen(port, () => {
  console.log(`Server listening at http://localhost:${port}`);
});
